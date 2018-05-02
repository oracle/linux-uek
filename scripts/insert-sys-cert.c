/* Write the contents of the <certfile> into kernel symbol system_extra_cert
 *
 * Copyright (C) IBM Corporation, 2015
 *
 * Author: Mehmet Kayaalp <mkayaalp@linux.vnet.ibm.com>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: insert-sys-cert [-s <System.map>] -b <vmlinux> -c <certfile>
 *                        [-s <System.map>] -z <bzImage> -c <certfile>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <linux/types.h>

#define CERT_SYM  "system_extra_cert"
#define USED_SYM  "system_extra_cert_used"
#define LSIZE_SYM "system_certificate_list_size"

#define info(format, args...) fprintf(stdout, "INFO:    " format, ## args)
#define warn(format, args...) fprintf(stdout, "WARNING: " format, ## args)
#define  err(format, args...) fprintf(stderr, "ERROR:   " format, ## args)

#if UINTPTR_MAX == 0xffffffff
#define CURRENT_ELFCLASS ELFCLASS32
#define Elf_Ehdr	Elf32_Ehdr
#define Elf_Shdr	Elf32_Shdr
#define Elf_Sym		Elf32_Sym
#else
#define CURRENT_ELFCLASS ELFCLASS64
#define Elf_Ehdr	Elf64_Ehdr
#define Elf_Shdr	Elf64_Shdr
#define Elf_Sym		Elf64_Sym
#endif

static unsigned char endianness(void)
{
	uint16_t two_byte = 0x00FF;
	uint8_t low_address = *((uint8_t *)&two_byte);

	if (low_address == 0)
		return ELFDATA2MSB;
	else
		return ELFDATA2LSB;
}

struct elf {
	unsigned char *base;
	int size;
	unsigned char eclass;
	unsigned char data;
	unsigned long shoff;
	unsigned long shnum;
	unsigned long shentsize;
	unsigned char *shstart;
	unsigned long shsize;
};

struct sym {
	char *name;
	unsigned long address;
	unsigned long offset;
	void *content;
	int size;
};

static int read_elf_data(struct elf *elf, char *base, int size)
{
	unsigned char *e_ident;
	Elf32_Ehdr *e32 = (Elf32_Ehdr *)base;
	Elf64_Ehdr *e64 = (Elf64_Ehdr *)base;

	elf->base = (unsigned char *)base;
	elf->size = size;

	if (size < EI_NIDENT) {
		err("Invalid file size for ELF format.\n");
		return -1;
	}
	e_ident = (unsigned char *)base;
	if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
	    e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
		err("Invalid ELF magic.\n");
		return -1;
	}
	elf->eclass = e_ident[EI_CLASS];
	if (elf->eclass != ELFCLASS32 && elf->eclass != ELFCLASS64) {
		err("Invalid ELF class.\n");
		return -1;
	}
	elf->data = e_ident[EI_DATA];
	if (elf->data != endianness()) {
		err("ELF endian mismatch.\n");
		return -1;
	}
	if (e_ident[EI_VERSION] != EV_CURRENT) {
		err("Invalid ELF file version.\n");
		return -1;
	}
	if (elf->eclass == ELFCLASS32) {
		elf->shoff = e32->e_shoff;
		elf->shnum = e32->e_shnum;
		elf->shentsize = e32->e_shentsize;
	} else {
		elf->shoff = e64->e_shoff;
		elf->shnum = e64->e_shnum;
		elf->shentsize = e64->e_shentsize;
	}
	if (elf->shoff == 0 || elf->shoff > size) {
		err("Could not find section header.\n");
		exit(EXIT_FAILURE);
	}
	elf->shstart = elf->base + elf->shoff;
	elf->shsize = elf->shnum * elf->shentsize;
	return 0;
}

static char *get_elf_string(struct elf *elf, unsigned long link,
			    unsigned long namendx)
{
	unsigned char *p = elf->shstart + link * elf->shentsize;
	Elf32_Shdr *s32 = (Elf32_Shdr *)p;
	Elf64_Shdr *s64 = (Elf64_Shdr *)p;

	if (elf->eclass == ELFCLASS32)
		return (char *)elf->base + s32->sh_offset + namendx;
	else
		return (char *)elf->base + s64->sh_offset + namendx;
}

static unsigned long get_offset_from_address(struct elf *elf,
					     unsigned long addr)
{
	unsigned long start, end, offset;
	unsigned char *p = elf->shstart;

	while (p < elf->shstart + elf->shsize) {
		Elf32_Shdr *s32 = (Elf32_Shdr *)p;
		Elf64_Shdr *s64 = (Elf64_Shdr *)p;

		if (elf->eclass == ELFCLASS32) {
			start = s32->sh_addr;
			end = start + s32->sh_size;
			offset = s32->sh_offset;
		} else {
			start = s64->sh_addr;
			end = start + s64->sh_size;
			offset = s64->sh_offset;
		}
		if (addr >= start && addr <= end)
			return addr - start + offset;
		p += elf->shentsize;
	}
	return 0;
}


#define LINE_SIZE 100

static void get_symbol_from_map(struct elf *elf, FILE *f, char *name,
				struct sym *s)
{
	char l[LINE_SIZE];
	char *w, *p, *n;

	s->size = 0;
	s->address = 0;
	s->offset = 0;
	if (fseek(f, 0, SEEK_SET) != 0) {
		perror("File seek failed");
		exit(EXIT_FAILURE);
	}
	while (fgets(l, LINE_SIZE, f)) {
		p = strchr(l, '\n');
		if (!p) {
			err("Missing line ending.\n");
			return;
		}
		n = strstr(l, name);
		if (n)
			break;
	}
	if (!n) {
		err("Unable to find symbol: %s\n", name);
		return;
	}
	w = strchr(l, ' ');
	if (!w)
		return;

	*w = '\0';
	s->address = strtoul(l, NULL, 16);
	if (s->address == 0)
		return;
	s->offset = get_offset_from_address(elf, s->address);
	s->name = name;
	s->content = elf->base + s->offset;
}

static void get_symbol_from_table(struct elf *elf, unsigned char *symtab,
				  char *name, struct sym *s)
{
	Elf32_Shdr *s32 = (Elf32_Shdr *)symtab;
	Elf64_Shdr *s64 = (Elf64_Shdr *)symtab;
	unsigned char *p;
	unsigned long address;
	unsigned long offset;
	unsigned long size;
	unsigned long entsize;
	unsigned long link;
	unsigned long shndx;
	char *symname;
	int found = 0;

	s->size = 0;
	s->address = 0;
	s->offset = 0;

	if (elf->eclass == ELFCLASS32) {
		offset = s32->sh_offset;
		size = s32->sh_size;
		entsize = s32->sh_entsize;
		link = s32->sh_link;
	} else {
		offset = s64->sh_offset;
		size = s64->sh_size;
		entsize = s64->sh_entsize;
		link = s64->sh_link;
	}

	p = elf->base + offset;
	while (p < elf->base + offset + size) {
		Elf32_Sym *sym32 = (Elf32_Sym *)p;
		Elf64_Sym *sym64 = (Elf64_Sym *)p;
		unsigned long namendx;

		if (elf->eclass == ELFCLASS32) {
			namendx = sym32->st_name;
			shndx = sym32->st_shndx;
		} else {
			namendx = sym64->st_name;
			shndx = sym64->st_shndx;
		}

		symname = get_elf_string(elf, link, namendx);
		if (strcmp(symname, name) == 0 && shndx) {
			found = 1;
			if (elf->eclass == ELFCLASS32) {
				s->size = sym32->st_size;
				s->address = sym32->st_value;
			} else {
				s->size = sym64->st_size;
				s->address = sym64->st_value;
			}
			break;
		}
		p += entsize;
	}

	if (!found)
		return;

	p = elf->shstart + shndx * elf->shentsize;
	s32 = (Elf32_Shdr *)p;
	s64 = (Elf64_Shdr *)p;

	if (elf->eclass == ELFCLASS32) {
		offset = s32->sh_offset;
		address = s32->sh_addr;
	} else {
		offset = s64->sh_offset;
		address = s64->sh_addr;
	}

	s->offset = s->address - address + offset;
	s->name = name;
	s->content = elf->base + s->offset;
}

static unsigned char *get_symbol_table(struct elf *elf)
{
	unsigned char *p = elf->shstart;

	while (p < elf->shstart + elf->shsize) {
		Elf32_Shdr *s32 = (Elf32_Shdr *)p;
		Elf64_Shdr *s64 = (Elf64_Shdr *)p;

		if (elf->eclass == ELFCLASS32) {
			if (s32->sh_type == SHT_SYMTAB)
				return p;
		} else {
			if (s64->sh_type == SHT_SYMTAB)
				return p;
		}
		p += elf->shentsize;
	}
	return NULL;
}

static void *map_file(char *file_name, int *size)
{
	struct stat st;
	void *map;
	int fd;

	fd = open(file_name, O_RDWR);
	if (fd < 0) {
		perror(file_name);
		return NULL;
	}
	if (fstat(fd, &st)) {
		perror("Could not determine file size");
		close(fd);
		return NULL;
	}
	*size = st.st_size;
	map = mmap(NULL, *size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("Mapping to memory failed");
		close(fd);
		return NULL;
	}
	close(fd);
	return map;
}

static char *read_file(char *file_name, int *size)
{
	struct stat st;
	char *buf;
	int fd;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		perror(file_name);
		return NULL;
	}
	if (fstat(fd, &st)) {
		perror("Could not determine file size");
		close(fd);
		return NULL;
	}
	*size = st.st_size;
	buf = malloc(*size);
	if (!buf) {
		perror("Allocating memory failed");
		close(fd);
		return NULL;
	}
	if (read(fd, buf, *size) != *size) {
		perror("File read failed");
		close(fd);
		return NULL;
	}
	close(fd);
	return buf;
}

#define BOOT_FLAG		0xAA55
#define MAGIC			0x53726448

#define BOOT_FLAG_O		0x1FE
#define MAGIC_O			0x202
#define VERSION_O		0x206
#define SETUP_SECTS_O		0x1F1
#define PAYLOAD_OFFSET_O	0x248
#define PAYLOAD_LENGTH_O	0x24C

static int image_supported(char *bzimage, int bzimage_size)
{
	uint16_t boot_flag;
	uint32_t magic;
	uint16_t version;

	if (bzimage_size < 1024) {
		err("Invalid bzImage: File is too small\n");
		return 0;
	}

	boot_flag = *((uint16_t *)&bzimage[BOOT_FLAG_O]);
	magic = *((uint32_t *)&bzimage[MAGIC_O]);
	version = *((uint16_t *)&bzimage[VERSION_O]);

	if (boot_flag != BOOT_FLAG || magic != MAGIC) {
		err("Invalid bzImage: Magic mismatch\n");
		return 0;
	}

	if (version < 0x208) {
		err("Invalid bzImage: Boot version <2.08 not supported\n");
		return 0;
	}

	return 1;
}

static void get_payload_info(char *bzimage, int *offset, int *size)
{
	unsigned int system_offset;
	unsigned char setup_sectors;

	setup_sectors = bzimage[SETUP_SECTS_O] + 1;
	system_offset = setup_sectors * 512;
	*offset = system_offset + *((int *)&bzimage[PAYLOAD_OFFSET_O]);
	*size = *((int *)&bzimage[PAYLOAD_LENGTH_O]);
}

static void update_payload_info(char *bzimage, int new_size)
{
	int offset, size;

	get_payload_info(bzimage, &offset, &size);
	*((int *)&bzimage[PAYLOAD_LENGTH_O]) = new_size;
	if (new_size < size)
		memset(bzimage + offset + new_size, 0, size - new_size);
}

struct zipper {
	unsigned char pattern[10];
	int length;
	char *command;
	char *compress;
};

struct zipper zippers[] = {
	{{0x7F, 'E', 'L', 'F'},
	 4, "cat", "cat"},
	{{0x1F, 0x8B},
	 2, "gunzip", "gzip -n -f -9"},
	{{0xFD, '7', 'z', 'X', 'Z', 0},
	 6, "unxz", "xz"},
	{{'B', 'Z', 'h'},
	 3, "bunzip2", "bzip2 -9"},
	{{0xFF, 'L', 'Z', 'M', 'A', 0},
	 6, "unlzma", "lzma -9"},
	{{0xD3, 'L', 'Z', 'O', 0, '\r', '\n', 0x20, '\n'},
	 9, "lzop -d", "lzop -9"}
};

static struct zipper *get_zipper(char *p)
{
	int i;

	for (i = 0; i < sizeof(zippers) / sizeof(struct zipper); i++) {
		if (memcmp(p, zippers[i].pattern, zippers[i].length) == 0)
			return &zippers[i];
	}
	return NULL;
}

static uint32_t crc32(uint32_t seed, const char *buffer, int size)
{
	int i, j;
	uint32_t byte, crc, mask;

	crc = seed;
	for (i = 0; i < size; i++) {
		byte = buffer[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
	}
	return crc;
}

/*
 * This only works for x86 bzImage
 */
static void extract_vmlinux(char *bzimage, int bzimage_size,
			    char **file, struct zipper **zipper)
{
	int r;
	char src[15] = "vmlinux-XXXXXX";
	char dest[15] = "vmlinux-XXXXXX";
	char cmd[100];
	int src_fd, dest_fd;
	int offset, size;
	struct zipper *z;

	if (!image_supported(bzimage, bzimage_size))
		return;

	get_payload_info(bzimage, &offset, &size);
	z = get_zipper(bzimage + offset);
	if (!z) {
		err("Unable to determine the compression of vmlinux\n");
		return;
	}

	src_fd = mkstemp(src);
	if (src_fd == -1) {
		perror("Could not create temp file");
		return;
	}

	r = write(src_fd, bzimage + offset, size);
	if (r != size) {
		perror("Could not write vmlinux");
		return;
	}
	dest_fd = mkstemp(dest);
	if (dest_fd == -1) {
		perror("Could not create temp file");
		return;
	}

	snprintf(cmd, sizeof(cmd), "%s <%s >%s", z->command, src, dest);
	info("Executing: %s\n", cmd);
	r = system(cmd);
	if (r != 0)
		warn("Possible errors when extracting\n");

	r = remove(src);
	if (r != 0)
		perror(src);

	*file = strdup(dest);
	*zipper = z;
}

static void repack_image(char *bzimage, int bzimage_size,
			 char *vmlinux_file, struct zipper *z)
{
	char tmp[15] = "vmlinux-XXXXXX";
	char cmd[100];
	int fd;
	struct stat st;
	int new_size;
	int r;
	int offset, size;
	uint32_t *crc;

	get_payload_info(bzimage, &offset, &size);

	fd = mkstemp(tmp);
	if (fd == -1) {
		perror("Could not create temp file");
		return;
	}
	snprintf(cmd, sizeof(cmd), "%s <%s >%s",
		 z->compress, vmlinux_file, tmp);

	info("Executing: %s\n", cmd);
	r = system(cmd);
	if (r != 0)
		warn("Possible errors when compressing\n");

	r = remove(vmlinux_file);
	if (r != 0)
		perror(vmlinux_file);

	if (fstat(fd, &st)) {
		perror("Could not determine file size");
		close(fd);
	}
	new_size = st.st_size;
	if (new_size > size) {
		err("Increase in compressed size is not supported.\n");
		err("Old size was %d, new size is %d\n", size, new_size);
		exit(EXIT_FAILURE);
	}

	r = read(fd, bzimage + offset, new_size);
	if (r != new_size)
		perror(tmp);

	r = remove(tmp);
	if (r != 0)
		perror(tmp);

	/* x86 specific patching of bzimage */
	update_payload_info(bzimage, new_size);

	/* update CRC */
	crc = (uint32_t *)(bzimage + bzimage_size - 4);
	*crc = crc32(~0, bzimage, bzimage_size);
}

static void print_sym(struct sym *s)
{
	info("sym:    %s\n", s->name);
	info("addr:   0x%lx\n", s->address);
	info("size:   %d\n", s->size);
	info("offset: 0x%lx\n", (unsigned long)s->offset);
}

static void print_usage(char *e)
{
	printf("Usage: %s [-s <System.map>] -b <vmlinux> -c <certfile>\n", e);
	printf("       %s [-s <System.map>] -z <bzImage> -c <certfile>\n", e);
}

int main(int argc, char **argv)
{
	char *system_map_file = NULL;
	char *vmlinux_file = NULL;
	char *bzimage_file = NULL;
	char *cert_file = NULL;
	int vmlinux_size;
	int bzimage_size;
	int cert_size;
	char *vmlinux;
	char *cert;
	char *bzimage = NULL;
	struct zipper *z = NULL;
	FILE *system_map;
	int *used;
	int opt;
	struct sym cert_sym, lsize_sym, used_sym;
	struct elf elf;
	unsigned char *symtab = NULL;

	while ((opt = getopt(argc, argv, "b:z:c:s:")) != -1) {
		switch (opt) {
		case 's':
			system_map_file = optarg;
			break;
		case 'b':
			vmlinux_file = optarg;
			break;
		case 'z':
			bzimage_file = optarg;
			break;
		case 'c':
			cert_file = optarg;
			break;
		default:
			break;
		}
	}

	if (!cert_file ||
	    (!vmlinux_file && !bzimage_file) ||
	    (vmlinux_file && bzimage_file)) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	cert = read_file(cert_file, &cert_size);
	if (!cert)
		exit(EXIT_FAILURE);

	if (bzimage_file) {
		bzimage = map_file(bzimage_file, &bzimage_size);
		if (!bzimage)
			exit(EXIT_FAILURE);

		extract_vmlinux(bzimage, bzimage_size, &vmlinux_file, &z);
		if (!vmlinux_file)
			exit(EXIT_FAILURE);
	}

	vmlinux = map_file(vmlinux_file, &vmlinux_size);
	if (!vmlinux)
		exit(EXIT_FAILURE);

	if (read_elf_data(&elf, vmlinux, vmlinux_size)) {
		err("Unable to read ELF file.\n");
		exit(EXIT_FAILURE);
	}

	symtab = get_symbol_table(&elf);
	if (!symtab) {
		warn("Could not find the symbol table.\n");
		if (!system_map_file) {
			err("Please provide a System.map file.\n");
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}

		system_map = fopen(system_map_file, "r");
		if (!system_map) {
			perror(system_map_file);
			exit(EXIT_FAILURE);
		}
		get_symbol_from_map(&elf, system_map, CERT_SYM, &cert_sym);
		get_symbol_from_map(&elf, system_map, USED_SYM, &used_sym);
		get_symbol_from_map(&elf, system_map, LSIZE_SYM, &lsize_sym);
		cert_sym.size = used_sym.address - cert_sym.address;
	} else {
		info("Symbol table found.\n");
		if (system_map_file)
			warn("System.map is ignored.\n");
		get_symbol_from_table(&elf, symtab, CERT_SYM, &cert_sym);
		get_symbol_from_table(&elf, symtab, USED_SYM, &used_sym);
		get_symbol_from_table(&elf, symtab, LSIZE_SYM, &lsize_sym);
	}

	if (!cert_sym.offset || !lsize_sym.offset || !used_sym.offset) {
		err("Unable to find symbols.\n");
		exit(EXIT_FAILURE);
	}

	print_sym(&cert_sym);
	print_sym(&used_sym);
	print_sym(&lsize_sym);

	used = (int *)used_sym.content;

	if (cert_sym.size < cert_size) {
		err("Certificate is larger than the reserved area!\n");
		exit(EXIT_FAILURE);
	}

	/* If the existing cert is the same, don't overwrite */
	if (cert_size > 0 && cert_size == *used &&
	    strncmp(cert_sym.content, cert, cert_size) == 0) {
		warn("Certificate was already inserted.\n");
		exit(EXIT_SUCCESS);
	}

	if (*used > 0)
		warn("Replacing previously inserted certificate.\n");

	memcpy(cert_sym.content, cert, cert_size);
	if (cert_size < cert_sym.size)
		memset(cert_sym.content + cert_size,
			0, cert_sym.size - cert_size);

	if (elf.eclass == ELFCLASS64) {
		uint64_t *lsize;

		lsize = (uint64_t *)lsize_sym.content;
		*lsize = *lsize + cert_size - *used;
	} else {
		uint32_t *lsize;

		lsize = (uint32_t *)lsize_sym.content;
		*lsize = *lsize + cert_size - *used;
	}
	*used = cert_size;
	info("Inserted the contents of %s into %lx.\n", cert_file,
						cert_sym.address);
	info("Used %d bytes out of %d bytes reserved.\n", *used,
						 cert_sym.size);
	if (munmap(vmlinux, vmlinux_size) == -1) {
		perror(vmlinux_file);
		exit(EXIT_FAILURE);
	}

	if (bzimage)
		repack_image(bzimage, bzimage_size, vmlinux_file, z);

	exit(EXIT_SUCCESS);
}
