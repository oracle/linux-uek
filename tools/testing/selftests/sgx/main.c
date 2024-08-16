// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <cpuid.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/auxv.h>
#include "defines.h"
#include "../kselftest_harness.h"
#include "main.h"

static const uint64_t MAGIC = 0x1122334455667788ULL;
static const uint64_t MAGIC2 = 0x8877665544332211ULL;
vdso_sgx_enter_enclave_t vdso_sgx_enter_enclave;

/*
 * Security Information (SECINFO) data structure needed by a few SGX
 * instructions (eg. ENCLU[EACCEPT] and ENCLU[EMODPE]) holds meta-data
 * about an enclave page. &enum sgx_secinfo_page_state specifies the
 * secinfo flags used for page state.
 */
enum sgx_secinfo_page_state {
	SGX_SECINFO_PENDING = (1 << 3),
	SGX_SECINFO_MODIFIED = (1 << 4),
	SGX_SECINFO_PR = (1 << 5),
};

struct vdso_symtab {
	Elf64_Sym *elf_symtab;
	const char *elf_symstrtab;
	Elf64_Word *elf_hashtab;
};

static Elf64_Dyn *vdso_get_dyntab(void *addr)
{
	Elf64_Ehdr *ehdr = addr;
	Elf64_Phdr *phdrtab = addr + ehdr->e_phoff;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdrtab[i].p_type == PT_DYNAMIC)
			return addr + phdrtab[i].p_offset;

	return NULL;
}

static void *vdso_get_dyn(void *addr, Elf64_Dyn *dyntab, Elf64_Sxword tag)
{
	int i;

	for (i = 0; dyntab[i].d_tag != DT_NULL; i++)
		if (dyntab[i].d_tag == tag)
			return addr + dyntab[i].d_un.d_ptr;

	return NULL;
}

static bool vdso_get_symtab(void *addr, struct vdso_symtab *symtab)
{
	Elf64_Dyn *dyntab = vdso_get_dyntab(addr);

	symtab->elf_symtab = vdso_get_dyn(addr, dyntab, DT_SYMTAB);
	if (!symtab->elf_symtab)
		return false;

	symtab->elf_symstrtab = vdso_get_dyn(addr, dyntab, DT_STRTAB);
	if (!symtab->elf_symstrtab)
		return false;

	symtab->elf_hashtab = vdso_get_dyn(addr, dyntab, DT_HASH);
	if (!symtab->elf_hashtab)
		return false;

	return true;
}

static unsigned long elf_sym_hash(const char *name)
{
	unsigned long h = 0, high;

	while (*name) {
		h = (h << 4) + *name++;
		high = h & 0xf0000000;

		if (high)
			h ^= high >> 24;

		h &= ~high;
	}

	return h;
}

static Elf64_Sym *vdso_symtab_get(struct vdso_symtab *symtab, const char *name)
{
	Elf64_Word bucketnum = symtab->elf_hashtab[0];
	Elf64_Word *buckettab = &symtab->elf_hashtab[2];
	Elf64_Word *chaintab = &symtab->elf_hashtab[2 + bucketnum];
	Elf64_Sym *sym;
	Elf64_Word i;

	for (i = buckettab[elf_sym_hash(name) % bucketnum]; i != STN_UNDEF;
	     i = chaintab[i]) {
		sym = &symtab->elf_symtab[i];
		if (!strcmp(name, &symtab->elf_symstrtab[sym->st_name]))
			return sym;
	}

	return NULL;
}

/*
 * Return the offset in the enclave where the data segment can be found.
 * The first RW segment loaded is the TCS, skip that to get info on the
 * data segment.
 */
static off_t encl_get_data_offset(struct encl *encl)
{
	int i;

	for (i = 1; i < encl->nr_segments; i++) {
		struct encl_segment *seg = &encl->segment_tbl[i];

		if (seg->prot == (PROT_READ | PROT_WRITE))
			return seg->offset;
	}

	return -1;
}

FIXTURE(enclave) {
	struct encl encl;
	struct sgx_enclave_run run;
};

static bool setup_test_encl(unsigned long heap_size, struct encl *encl,
			    struct __test_metadata *_metadata)
{
	Elf64_Sym *sgx_enter_enclave_sym = NULL;
	struct vdso_symtab symtab;
	struct encl_segment *seg;
	char maps_line[256];
	FILE *maps_file;
	unsigned int i;
	void *addr;

	if (!encl_load("test_encl.elf", encl, heap_size)) {
		encl_delete(encl);
		TH_LOG("Failed to load the test enclave.");
		return false;
	}

	if (!encl_measure(encl))
		goto err;

	if (!encl_build(encl))
		goto err;

	/*
	 * An enclave consumer only must do this.
	 */
	for (i = 0; i < encl->nr_segments; i++) {
		struct encl_segment *seg = &encl->segment_tbl[i];

		addr = mmap((void *)encl->encl_base + seg->offset, seg->size,
			    seg->prot, MAP_SHARED | MAP_FIXED, encl->fd, 0);
		EXPECT_NE(addr, MAP_FAILED);
		if (addr == MAP_FAILED)
			goto err;
	}

	/* Get vDSO base address */
	addr = (void *)getauxval(AT_SYSINFO_EHDR);
	if (!addr)
		goto err;

	if (!vdso_get_symtab(addr, &symtab))
		goto err;

	sgx_enter_enclave_sym = vdso_symtab_get(&symtab, "__vdso_sgx_enter_enclave");
	if (!sgx_enter_enclave_sym)
		goto err;

	vdso_sgx_enter_enclave = addr + sgx_enter_enclave_sym->st_value;

	return true;

err:
	for (i = 0; i < encl->nr_segments; i++) {
		seg = &encl->segment_tbl[i];

		TH_LOG("0x%016lx 0x%016lx 0x%02x", seg->offset, seg->size, seg->prot);
	}

	maps_file = fopen("/proc/self/maps", "r");
	if (maps_file != NULL)  {
		while (fgets(maps_line, sizeof(maps_line), maps_file) != NULL) {
			maps_line[strlen(maps_line) - 1] = '\0';

			if (strstr(maps_line, "/dev/sgx_enclave"))
				TH_LOG("%s", maps_line);
		}

		fclose(maps_file);
	}

	TH_LOG("Failed to initialize the test enclave.");

	encl_delete(encl);

	return false;
}

FIXTURE_SETUP(enclave)
{
}

FIXTURE_TEARDOWN(enclave)
{
	encl_delete(&self->encl);
}

#define ENCL_CALL(op, run, clobbered) \
	({ \
		int ret; \
		if ((clobbered)) \
			ret = vdso_sgx_enter_enclave((unsigned long)(op), 0, 0, \
						     EENTER, 0, 0, (run)); \
		else \
			ret = sgx_enter_enclave((void *)(op), NULL, 0, EENTER, NULL, NULL, \
						(run)); \
		ret; \
	})

#define EXPECT_EEXIT(run) \
	do { \
		EXPECT_EQ((run)->function, EEXIT); \
		if ((run)->function != EEXIT) \
			TH_LOG("0x%02x 0x%02x 0x%016llx", (run)->exception_vector, \
			       (run)->exception_error_code, (run)->exception_addr); \
	} while (0)

TEST_F(enclave, unclobbered_vdso)
{
	struct encl_op_get_from_buf get_op;
	struct encl_op_put_to_buf put_op;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	put_op.header.type = ENCL_OP_PUT_TO_BUFFER;
	put_op.value = MAGIC;

	EXPECT_EQ(ENCL_CALL(&put_op, &self->run, false), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);

	get_op.header.type = ENCL_OP_GET_FROM_BUFFER;
	get_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_op, &self->run, false), 0);

	EXPECT_EQ(get_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);
}

/*
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static unsigned long sgx_calc_section_metric(unsigned int low,
					     unsigned int high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

/*
 * Sum total available physical SGX memory across all EPC sections
 *
 * Return: total available physical SGX memory available on system
 */
static unsigned long get_total_epc_mem(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long total_size = 0;
	unsigned int type;
	int section = 0;

	while (true) {
		__cpuid_count(SGX_CPUID, section + SGX_CPUID_EPC, eax, ebx, ecx, edx);

		type = eax & SGX_CPUID_EPC_MASK;
		if (type == SGX_CPUID_EPC_INVALID)
			break;

		if (type != SGX_CPUID_EPC_SECTION)
			break;

		total_size += sgx_calc_section_metric(ecx, edx);

		section++;
	}

	return total_size;
}

TEST_F(enclave, unclobbered_vdso_oversubscribed)
{
	struct encl_op_get_from_buf get_op;
	struct encl_op_put_to_buf put_op;
	unsigned long total_mem;

	total_mem = get_total_epc_mem();
	ASSERT_NE(total_mem, 0);
	ASSERT_TRUE(setup_test_encl(total_mem, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	put_op.header.type = ENCL_OP_PUT_TO_BUFFER;
	put_op.value = MAGIC;

	EXPECT_EQ(ENCL_CALL(&put_op, &self->run, false), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);

	get_op.header.type = ENCL_OP_GET_FROM_BUFFER;
	get_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_op, &self->run, false), 0);

	EXPECT_EQ(get_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);

}

TEST_F(enclave, clobbered_vdso)
{
	struct encl_op_get_from_buf get_op;
	struct encl_op_put_to_buf put_op;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	put_op.header.type = ENCL_OP_PUT_TO_BUFFER;
	put_op.value = MAGIC;

	EXPECT_EQ(ENCL_CALL(&put_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);

	get_op.header.type = ENCL_OP_GET_FROM_BUFFER;
	get_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_op, &self->run, true), 0);

	EXPECT_EQ(get_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);
}

static int test_handler(long rdi, long rsi, long rdx, long ursp, long r8, long r9,
			struct sgx_enclave_run *run)
{
	run->user_data = 0;

	return 0;
}

TEST_F(enclave, clobbered_vdso_and_user_function)
{
	struct encl_op_get_from_buf get_op;
	struct encl_op_put_to_buf put_op;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	self->run.user_handler = (__u64)test_handler;
	self->run.user_data = 0xdeadbeef;

	put_op.header.type = ENCL_OP_PUT_TO_BUFFER;
	put_op.value = MAGIC;

	EXPECT_EQ(ENCL_CALL(&put_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);

	get_op.header.type = ENCL_OP_GET_FROM_BUFFER;
	get_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_op, &self->run, true), 0);

	EXPECT_EQ(get_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);
}

/*
 * Sanity check that it is possible to enter either of the two hardcoded TCS
 */
TEST_F(enclave, tcs_entry)
{
	struct encl_op_header op;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	op.type = ENCL_OP_NOP;

	EXPECT_EQ(ENCL_CALL(&op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/* Move to the next TCS. */
	self->run.tcs = self->encl.encl_base + PAGE_SIZE;

	EXPECT_EQ(ENCL_CALL(&op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);
}

/*
 * Second page of .data segment is used to test changing PTE permissions.
 * This spans the local encl_buffer within the test enclave.
 *
 * 1) Start with a sanity check: a value is written to the target page within
 *    the enclave and read back to ensure target page can be written to.
 * 2) Change PTE permissions (RW -> RO) of target page within enclave.
 * 3) Repeat (1) - this time expecting a regular #PF communicated via the
 *    vDSO.
 * 4) Change PTE permissions of target page within enclave back to be RW.
 * 5) Repeat (1) by resuming enclave, now expected to be possible to write to
 *    and read from target page within enclave.
 */
TEST_F(enclave, pte_permissions)
{
	struct encl_op_get_from_addr get_addr_op;
	struct encl_op_put_to_addr put_addr_op;
	unsigned long data_start;
	int ret;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	data_start = self->encl.encl_base +
		     encl_get_data_offset(&self->encl) +
		     PAGE_SIZE;

	/*
	 * Sanity check to ensure it is possible to write to page that will
	 * have its permissions manipulated.
	 */

	/* Write MAGIC to page */
	put_addr_op.value = MAGIC;
	put_addr_op.addr = data_start;
	put_addr_op.header.type = ENCL_OP_PUT_TO_ADDRESS;

	EXPECT_EQ(ENCL_CALL(&put_addr_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/*
	 * Read memory that was just written to, confirming that it is the
	 * value previously written (MAGIC).
	 */
	get_addr_op.value = 0;
	get_addr_op.addr = data_start;
	get_addr_op.header.type = ENCL_OP_GET_FROM_ADDRESS;

	EXPECT_EQ(ENCL_CALL(&get_addr_op, &self->run, true), 0);

	EXPECT_EQ(get_addr_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/* Change PTE permissions of target page within the enclave */
	ret = mprotect((void *)data_start, PAGE_SIZE, PROT_READ);
	if (ret)
		perror("mprotect");

	/*
	 * PTE permissions of target page changed to read-only, EPCM
	 * permissions unchanged (EPCM permissions are RW), attempt to
	 * write to the page, expecting a regular #PF.
	 */

	put_addr_op.value = MAGIC2;

	EXPECT_EQ(ENCL_CALL(&put_addr_op, &self->run, true), 0);

	EXPECT_EQ(self->run.exception_vector, 14);
	EXPECT_EQ(self->run.exception_error_code, 0x7);
	EXPECT_EQ(self->run.exception_addr, data_start);

	self->run.exception_vector = 0;
	self->run.exception_error_code = 0;
	self->run.exception_addr = 0;

	/*
	 * Change PTE permissions back to enable enclave to write to the
	 * target page and resume enclave - do not expect any exceptions this
	 * time.
	 */
	ret = mprotect((void *)data_start, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (ret)
		perror("mprotect");

	EXPECT_EQ(vdso_sgx_enter_enclave((unsigned long)&put_addr_op, 0,
					 0, ERESUME, 0, 0, &self->run),
		 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	get_addr_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_addr_op, &self->run, true), 0);

	EXPECT_EQ(get_addr_op.value, MAGIC2);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);
}

/*
 * Enclave page permission test.
 *
 * Modify and restore enclave page's EPCM (enclave) permissions from
 * outside enclave (ENCLS[EMODPR] via kernel) as well as from within
 * enclave (via ENCLU[EMODPE]). Check for page fault if
 * VMA allows access but EPCM permissions do not.
 */
TEST_F(enclave, epcm_permissions)
{
	struct sgx_enclave_restrict_permissions restrict_ioc;
	struct encl_op_get_from_addr get_addr_op;
	struct encl_op_put_to_addr put_addr_op;
	struct encl_op_eaccept eaccept_op;
	struct encl_op_emodpe emodpe_op;
	unsigned long data_start;
	int ret, errno_save;

	ASSERT_TRUE(setup_test_encl(ENCL_HEAP_SIZE_DEFAULT, &self->encl, _metadata));

	memset(&self->run, 0, sizeof(self->run));
	self->run.tcs = self->encl.encl_base;

	/*
	 * Ensure kernel supports needed ioctl() and system supports needed
	 * commands.
	 */
	memset(&restrict_ioc, 0, sizeof(restrict_ioc));

	ret = ioctl(self->encl.fd, SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS,
		    &restrict_ioc);
	errno_save = ret == -1 ? errno : 0;

	/*
	 * Invalid parameters were provided during sanity check,
	 * expect command to fail.
	 */
	ASSERT_EQ(ret, -1);

	/* ret == -1 */
	if (errno_save == ENOTTY)
		SKIP(return,
		     "Kernel does not support SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS ioctl()");
	else if (errno_save == ENODEV)
		SKIP(return, "System does not support SGX2");

	/*
	 * Page that will have its permissions changed is the second data
	 * page in the .data segment. This forms part of the local encl_buffer
	 * within the enclave.
	 *
	 * At start of test @data_start should have EPCM as well as PTE and
	 * VMA permissions of RW.
	 */

	data_start = self->encl.encl_base +
		     encl_get_data_offset(&self->encl) + PAGE_SIZE;

	/*
	 * Sanity check that page at @data_start is writable before making
	 * any changes to page permissions.
	 *
	 * Start by writing MAGIC to test page.
	 */
	put_addr_op.value = MAGIC;
	put_addr_op.addr = data_start;
	put_addr_op.header.type = ENCL_OP_PUT_TO_ADDRESS;

	EXPECT_EQ(ENCL_CALL(&put_addr_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/*
	 * Read memory that was just written to, confirming that
	 * page is writable.
	 */
	get_addr_op.value = 0;
	get_addr_op.addr = data_start;
	get_addr_op.header.type = ENCL_OP_GET_FROM_ADDRESS;

	EXPECT_EQ(ENCL_CALL(&get_addr_op, &self->run, true), 0);

	EXPECT_EQ(get_addr_op.value, MAGIC);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/*
	 * Change EPCM permissions to read-only. Kernel still considers
	 * the page writable.
	 */
	memset(&restrict_ioc, 0, sizeof(restrict_ioc));

	restrict_ioc.offset = encl_get_data_offset(&self->encl) + PAGE_SIZE;
	restrict_ioc.length = PAGE_SIZE;
	restrict_ioc.permissions = SGX_SECINFO_R;

	ret = ioctl(self->encl.fd, SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS,
		    &restrict_ioc);
	errno_save = ret == -1 ? errno : 0;

	EXPECT_EQ(ret, 0);
	EXPECT_EQ(errno_save, 0);
	EXPECT_EQ(restrict_ioc.result, 0);
	EXPECT_EQ(restrict_ioc.count, 4096);

	/*
	 * EPCM permissions changed from kernel, need to EACCEPT from enclave.
	 */
	eaccept_op.epc_addr = data_start;
	eaccept_op.flags = SGX_SECINFO_R | SGX_SECINFO_REG | SGX_SECINFO_PR;
	eaccept_op.ret = 0;
	eaccept_op.header.type = ENCL_OP_EACCEPT;

	EXPECT_EQ(ENCL_CALL(&eaccept_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);
	EXPECT_EQ(eaccept_op.ret, 0);

	/*
	 * EPCM permissions of page is now read-only, expect #PF
	 * on EPCM when attempting to write to page from within enclave.
	 */
	put_addr_op.value = MAGIC2;

	EXPECT_EQ(ENCL_CALL(&put_addr_op, &self->run, true), 0);

	EXPECT_EQ(self->run.function, ERESUME);
	EXPECT_EQ(self->run.exception_vector, 14);
	EXPECT_EQ(self->run.exception_error_code, 0x8007);
	EXPECT_EQ(self->run.exception_addr, data_start);

	self->run.exception_vector = 0;
	self->run.exception_error_code = 0;
	self->run.exception_addr = 0;

	/*
	 * Received AEX but cannot return to enclave at same entrypoint,
	 * need different TCS from where EPCM permission can be made writable
	 * again.
	 */
	self->run.tcs = self->encl.encl_base + PAGE_SIZE;

	/*
	 * Enter enclave at new TCS to change EPCM permissions to be
	 * writable again and thus fix the page fault that triggered the
	 * AEX.
	 */

	emodpe_op.epc_addr = data_start;
	emodpe_op.flags = SGX_SECINFO_R | SGX_SECINFO_W;
	emodpe_op.header.type = ENCL_OP_EMODPE;

	EXPECT_EQ(ENCL_CALL(&emodpe_op, &self->run, true), 0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	/*
	 * Attempt to return to main TCS to resume execution at faulting
	 * instruction, PTE should continue to allow writing to the page.
	 */
	self->run.tcs = self->encl.encl_base;

	/*
	 * Wrong page permissions that caused original fault has
	 * now been fixed via EPCM permissions.
	 * Resume execution in main TCS to re-attempt the memory access.
	 */
	self->run.tcs = self->encl.encl_base;

	EXPECT_EQ(vdso_sgx_enter_enclave((unsigned long)&put_addr_op, 0, 0,
					 ERESUME, 0, 0,
					 &self->run),
		  0);

	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);

	get_addr_op.value = 0;

	EXPECT_EQ(ENCL_CALL(&get_addr_op, &self->run, true), 0);

	EXPECT_EQ(get_addr_op.value, MAGIC2);
	EXPECT_EEXIT(&self->run);
	EXPECT_EQ(self->run.user_data, 0);
	EXPECT_EQ(self->run.exception_vector, 0);
	EXPECT_EQ(self->run.exception_error_code, 0);
	EXPECT_EQ(self->run.exception_addr, 0);
}

TEST_HARNESS_MAIN
