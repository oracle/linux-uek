/*
 * Edit the "Build ID" note of an ELF file.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <byteswap.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#include <elf.h>

bool verbose;

#define pr_info(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while (0)

#define max(a, b) ((a) < (b) ? (b) : (a))

/*
 * libelf doesn't have support to do editing like this, so we need to roll our
 * own "generic elf" support.
 */
struct elfinfo {
	int endian;  /* ELFDATA2LSB or ELFDATA2MSB */
	int bits;    /* ELFCLASS64 or ELFCLASS32 */
};

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define platform_endian() ELFDATA2MSB
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define platform_endian() ELFDATA2LSB
#else
#error "Cannot determine platform endianness"
#endif

/*
 * Read a field from an ELF structure in a "generic" way. This only works for
 * fields that are actually the same size in Elf64 and Elf32.
 */
#define getfield(info, ptr_, typ, field, inttype, bswapmethod)			\
	({									\
		inttype _result;						\
		if (info->bits == ELFCLASS64) {				\
			Elf64_ ## typ *ptr = (Elf64_ ## typ *)ptr_;		\
			_result = ptr->field;					\
		} else if (info->bits == ELFCLASS32) {				\
			Elf32_ ## typ *ptr = (Elf32_ ## typ *)ptr_;		\
			_result = ptr->field;					\
		} else {							\
			fprintf(stderr, "Invalid ELF class: %d\n", info->bits); \
			exit(EXIT_FAILURE);					\
		}								\
		if (info->endian != platform_endian())				\
			_result = bswapmethod(_result);			\
		_result;							\
	})

#define getfield16(info, ptr, typ, field)		\
	getfield(info, ptr, typ, field, uint16_t, bswap_16)
#define getfield32(info, ptr, typ, field)		\
	getfield(info, ptr, typ, field, uint32_t, bswap_32)
#define getfield64(info, ptr, typ, field)		\
	getfield(info, ptr, typ, field, uint64_t, bswap_64)

/*
 * Read an ELF "offset" or "address" field whose type size depends on the ELF
 * class.
 */
#define getaddr(info, ptr_, typ, field)			\
	({									\
		uint64_t _result;						\
		uint32_t _result32;						\
		if (info->bits == ELFCLASS64) {				\
			Elf64_ ## typ *ptr = (Elf64_ ## typ *)ptr_;		\
			_result = ptr->field;					\
			if (info->endian != platform_endian())			\
				_result = bswap_64(_result);			\
		} else if (info->bits == ELFCLASS32) {				\
			Elf32_ ## typ *ptr = (Elf32_ ## typ *)ptr_;		\
			_result32 = ptr->field;				\
			if (info->endian != platform_endian())			\
				_result32 = bswap_32(_result32);		\
			_result = _result32;					\
		} else {							\
			fprintf(stderr, "Invalid ELF class: %d\n", info->bits); \
			exit(EXIT_FAILURE);					\
		}								\
		_result;							\
	})

static size_t pad4(size_t val)
{
	if (val & 3)
		return (val & (~(size_t)3)) + 4;
	return val;
}

static void *note_desc(void *nhdr, uint16_t namesz)
{
	return nhdr + sizeof(Elf64_Nhdr) + pad4(namesz);
}

static void *next_note(void *nhdr, uint16_t namesz, uint16_t descsz)
{
	return nhdr + sizeof(Elf64_Nhdr) + pad4(namesz) + pad4(descsz);
}

static bool end_notes(void *start, size_t len, void *ptr)
{
	return ((uintptr_t)ptr - (uintptr_t)start) >= len;
}

static inline char nibble_to_hex(uint8_t input)
{
	if (input >= 0 && input < 10)
		return '0' + input;
	else if (input >= 10 && input < 16)
		return 'a' + input - 10;
	assert(0);
}

static inline uint8_t hex_to_nibble(char input, bool *error)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	else if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	else if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	*error = true;
	return 0;
}

static char *to_hex(uint8_t *data, int size)
{
	int i;
	char *hex_data = calloc(1, size * 2 + 1);

	for (i = 0; i < size; i++) {
		char byte = data[i];

		hex_data[2 * i] = nibble_to_hex((byte & 0xF0) >> 4);
		hex_data[2 * i + 1] = nibble_to_hex((byte & 0xF));
	}
	return hex_data;
}

static uint8_t *from_hex(char *hex_data, int hex_size)
{
	uint8_t *data;
	int size, i;

	assert(hex_size % 2 == 0);
	size = hex_size / 2;
	data = calloc(1, size);
	for (i = 0; i < size; i++) {
		char byte = 0;
		bool error = false;

		byte |= hex_to_nibble(hex_data[2 * i], &error) << 4;
		byte |= hex_to_nibble(hex_data[2 * i + 1], &error);
		data[i] = byte;

		if (error) {
			free(data);
			return NULL;
		}
	}
	return data;
}

/*
 * There is no defined size for a build ID, just common ones: 20 bytes / 160
 * bits for a SHA-1 ID, and 16 bytes / 128 bits for MD5 or UUID based IDs.
 * This maximum is established merely as a reasonable upper bound for safety
 * checking our inputs: 512 bytes would be a really large build ID.
 */
#define MAX_BUILDID_SIZE 512

struct buildid_info {
	uint64_t data_offset;
	size_t bytes_size;
	char *hex;
};

static void *fetch_data(int fd, uint64_t offset, size_t len)
{
	int rv;
	void *data;

	if (lseek(fd, offset, SEEK_SET) == (loff_t) -1) {
		fprintf(stderr, "error seeking to notes location %"PRIu64"\n", offset);
		perror("lseek");
		return NULL;
	}

	data = calloc(len, 1);
	rv = read(fd, data, len);
	if (rv != len) {
		fprintf(stderr, "error: read notes data failed (%d)\n", rv);
		if (rv < 0)
			perror("read");
		free(data);
		return NULL;
	}
	return data;
}

static int find_buildid(int fd, struct elfinfo *info, uint64_t offset, size_t len,
			struct buildid_info *info_out)
{
	void *data = fetch_data(fd, offset, len);
	void *nhdr;

	if (!data)
		return -1;

	nhdr = data;
	while (!end_notes(data, len, nhdr)) {
		char *name = nhdr + sizeof(Elf64_Nhdr); /* Note: same structure size */
		uint32_t descsz = getfield32(info, nhdr, Nhdr, n_descsz);
		uint32_t namesz = getfield32(info, nhdr, Nhdr, n_namesz);
		uint32_t type = getfield32(info, nhdr, Nhdr, n_type);

		if ((strcmp("GNU", name) == 0) &&
		    (type == NT_GNU_BUILD_ID)) {
			size_t desc_offset_in_sect;

			/* This is just a sanity-check, it should never be hit */
			if (descsz > MAX_BUILDID_SIZE) {
				fprintf(stderr, "error: Found build ID of large size %"
					PRIu32", skipping\n", descsz);
				continue;
			}
			if (descsz != 20 && descsz != 16)
				pr_info("warning: non-standard build ID size %"
					PRIu32", continuing anyway\n", descsz);

			desc_offset_in_sect = (void *)note_desc(nhdr, namesz) - data;
			info_out->data_offset = offset + desc_offset_in_sect;
			info_out->bytes_size = (size_t) descsz;
			info_out->hex = to_hex(note_desc(nhdr, namesz), descsz);
			free(data);
			return 1;
		}
		nhdr = next_note(nhdr, namesz, descsz);
	}
	free(data);
	return 0;
}

static int find_notes_phdr(void *entries, struct elfinfo *info, int start,
			   uint16_t e_phnum, uint16_t e_phentsize,
			   uint64_t *offset_out, uint64_t *size_out)
{
	int i;

	for (i = start; i < e_phnum; i++) {
		/* Program header size may not match Elf64_Phdr, do it manually */
		void *phdr = entries + i * e_phentsize;
		uint32_t p_type = getfield32(info, phdr, Phdr, p_type);

		if (p_type != PT_NOTE)
			continue;

		*offset_out = getaddr(info, phdr, Phdr, p_offset);
		*size_out = getaddr(info, phdr, Phdr, p_filesz);
		return i;
	}
	return -1;
}

static int find_buildid_phdr(int fd, struct elfinfo *info, void *ehdr,
			     struct buildid_info *info_out)
{
	void *phdr;
	int start = 0;
	uint64_t offset, size;
	int rv;

	uint16_t e_phnum = getfield16(info, ehdr, Ehdr, e_phnum);
	uint64_t e_phoff = getaddr(info, ehdr, Ehdr, e_phoff);
	uint16_t e_phentsize = getfield16(info, ehdr, Ehdr, e_phentsize);

	if (!e_phnum) {
		pr_info("ELF file has no program header\n");
		return 0;
	}
	phdr = fetch_data(fd, e_phoff, e_phnum * e_phentsize);
	if (!phdr)
		return -1;

	while ((start = find_notes_phdr(phdr, info, start, e_phnum,
					e_phentsize, &offset, &size)) >= 0) {
		pr_info("Found NOTES section in program header index %d\n", start);
		rv = find_buildid(fd, info, offset, size, info_out);

		/*
		 * Continue searching on 0 (not found). Otherwise, either we
		 * found it, or had an error. Either way, we should return.
		 */
		if (rv != 0)
			goto out;

		pr_info("Build ID not present here, continuing...\n");
		start += 1; /* continue from next */
	}
	pr_info("Program header did not contain NOTES segment with Build ID note.\n");

out:
	free(phdr);
	return rv;
}

static int find_notes_shdr(void *entries, struct elfinfo *info, int start,
			   uint16_t e_shnum, uint16_t e_shentsize,
			   uint64_t *offset_out, uint64_t *size_out)
{
	int i;

	for (i = start; i < e_shnum; i++) {
		void *shdr = entries + i * e_shentsize;
		uint32_t sh_type = getfield32(info, shdr, Shdr, sh_type);

		if (sh_type != SHT_NOTE)
			continue;

		*offset_out = getaddr(info, shdr, Shdr, sh_offset);
		*size_out = getaddr(info, shdr, Shdr, sh_size);
		return i;
	}
	return -1;
}

static int find_buildid_shdr(int fd, struct elfinfo *info, void *ehdr,
			     struct buildid_info *info_out)
{
	void *shdr;
	int start = 0;
	uint64_t offset, size;
	int rv;

	uint16_t e_shnum = getfield16(info, ehdr, Ehdr, e_shnum);
	uint64_t e_shoff = getaddr(info, ehdr, Ehdr, e_shoff);
	uint16_t e_shentsize = getfield16(info, ehdr, Ehdr, e_shentsize);

	if (!e_shnum) {
		pr_info("ELF file has no section header\n");
		return 0;
	}
	shdr = fetch_data(fd, e_shoff, e_shnum * e_shentsize);
	if (!shdr)
		return -1;

	while ((start = find_notes_shdr(shdr, info, start, e_shnum,
					e_shentsize, &offset, &size)) >= 0) {
		pr_info("Found NOTES section in section header index %d\n", start);
		rv = find_buildid(fd, info, offset, size, info_out);

		/*
		 * Continue searching on 0 (not found). Otherwise, either we
		 * found it, or had an error. Either way, we should return.
		 */
		if (rv != 0)
			goto out;

		pr_info("Build ID not present here, continuing...\n");
		start += 1; /* continue from next */
	}
	pr_info("Section header did not contain NOTES segment with Build ID note.\n");

out:
	free(shdr);
	return rv;
}

static int find_build_id(int fd, struct buildid_info *info_out)
{
	int rv;
	char ehdrbuf[max(sizeof(Elf64_Ehdr), sizeof(Elf32_Ehdr))];
	Elf64_Ehdr *ehdr64 = (Elf64_Ehdr *)&ehdrbuf;
	struct elfinfo info;

	rv = read(fd, ehdrbuf, sizeof(ehdrbuf));
	if (rv != sizeof(ehdrbuf)) {
		fprintf(stderr, "read ELF header failed (%d)\n", rv);
		if (rv < 0)
			perror("read");
		return -1;
	}

	/*
	 * To simplify things, we can access the first few bytes using Elf64
	 * structure. The definitions are the same.
	 */
	if (!(ehdr64->e_ident[0] == ELFMAG0 && ehdr64->e_ident[1] == ELFMAG1 &&
	      ehdr64->e_ident[2] == ELFMAG2 && ehdr64->e_ident[3] == ELFMAG3)) {
		fprintf(stderr, "error: not an ELF file\n");
		return -1;
	}

	/*
	 * We can handle 32 and 64 bits, and big/little endian!
	 * But it's helpful to verify and log this information.
	 */
	info.bits = ehdr64->e_ident[EI_CLASS];
	if (info.bits == ELFCLASS32 || info.bits == ELFCLASS64) {
		pr_info("Input is a %d-bit ELF\n", info.bits == ELFCLASS32 ? 32 : 64);
	} else {
		fprintf(stderr, "Error: unsupported elf class: %d\n", info.bits);
		return -1;
	}
	info.endian = ehdr64->e_ident[EI_DATA];
	if (info.endian == ELFDATA2LSB || info.endian == ELFDATA2MSB) {
		pr_info("Input is %s-endian\n", info.endian == ELFDATA2LSB ? "little" : "big");
	} else {
		fprintf(stderr, "Error: unsupported elf data encoding: %d\n", info.endian);
		return -1;
	}

	/*
	 * Notes are legal to be declared in program headers or section headers.
	 * In manual tests, we have found NOTES declared in either place. So, we
	 * should support both.
	 */
	rv = find_buildid_phdr(fd, &info, (void *)ehdrbuf, info_out);
	if (rv != 0)
		return rv;

	return find_buildid_shdr(fd, &info, (void *)ehdrbuf, info_out);
}

static int write_new_buildid(int fd, size_t offset, uint8_t *data, size_t data_size)
{
	if (lseek(fd, offset, SEEK_SET) < 0) {
		fprintf(stderr, "error: seeking to build id bytes\n");
		perror("lseek");
		return -1;
	}

	if (write(fd, data, data_size) < 0)
		perror("write");

	return 0;
}

void help(void)
{
	puts(
		"usage: editbuildid [-n BUILD-ID] [-p] [-v] [-h] ELF-FILE\n"
		"\n"
		"Find the build ID of an ELF file and either print it (-p) and exit, or\n"
		"overwrite it with the given value (-n BUILD-ID). The -p and -n options\n"
		"are mutually exclusive and exactly one must be specified.\n"
		"\n"
		"Options:\n"
		"  -n, --new BUILD-ID   specify the new BUILD-ID value\n"
		"  -p, --print          print the current build ID value and exit\n"
		"  -v, --verbose        print informational messages\n"
		"  -h, --help           print this message and exit"
	);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	struct buildid_info info;
	char *newid_hex = NULL;
	char *elf_file = NULL;
	uint8_t *newid_bytes = NULL;
	size_t newid_len = 0;
	int elf_fd, opt, rv = 0;
	bool print = false;

	const char *shopt = "n:vhp";
	static struct option lopt[] = {
		{"--new",     required_argument, NULL, 'n'},
		{"--verbose", no_argument,       NULL, 'v'},
		{"--help",    no_argument,       NULL, 'h'},
		{"--print",   no_argument,       NULL, 'p'},
	};
	while ((opt = getopt_long(argc, argv, shopt, lopt, NULL)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
			help();
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			print = true;
			break;
		case 'n':
			newid_hex = optarg;
			break;
		}
	}
	argv += optind;
	argc -= optind;

	if (argc != 1) {
		fprintf(stderr, "error: require exactly one argument (ELF-FILE)\n");
		return 1;
	}
	if (print && newid_hex) {
		fprintf(stderr, "error: --print and --new are mutually exclusive\n");
		return 1;
	} else if (!(print || newid_hex)) {
		fprintf(stderr, "error: either --print or --new should be specified\n");
		return 1;
	}
	elf_file = argv[0];
	memset(&info, 0, sizeof(info));

	elf_fd = open(elf_file, O_RDWR, 0);
	if (elf_fd < 0) {
		fprintf(stderr, "failed to open %s to read\n", elf_file);
		perror("open");
		return 1;
	}
	rv = find_build_id(elf_fd, &info);
	if (rv < 0)
		goto out;
	if (rv == 0) {
		fprintf(stderr, "Sorry, couldn't find Build ID in that ELF file.\n");
		goto out;
	}
	rv = 0;
	if (print) {
		printf("%s\n", info.hex);
		goto out;
	}
	pr_info("Found old build ID: %s\n", info.hex);
	newid_len = strlen(newid_hex);
	if (newid_len % 2 == 0)
		newid_bytes = from_hex(newid_hex, newid_len);
	if (!newid_bytes) {
		fprintf(stderr, "error: invalid build ID \"%s\"\n", newid_hex);
		fprintf(stderr, "Expected even-length hex string\n");
		rv = 1;
		goto out;
	}
	if (newid_len / 2 != info.bytes_size) {
		fprintf(stderr, "error: the existing build ID has size %zu but the "
		        "new build ID has size %zu\n", info.bytes_size, newid_len / 2);
		fprintf(stderr, "This tool does not support changing the build ID size\n");
		rv = 1;
		goto out;
	}
	rv = write_new_buildid(elf_fd, info.data_offset, newid_bytes, info.bytes_size);
	if (rv < 0)
		goto out;
	pr_info("Wrote new build ID: %s\n", newid_hex);
out:
	free(newid_bytes);
	free(info.hex);
	close(elf_fd);
	return rv;
}
