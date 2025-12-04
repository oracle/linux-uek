// SPDX-License-Identifier: GPL-2.0

/*
 * Test the userspace memory failure recovery (MFR) policy for HugeTLB
 * hugepage case:
 * 1. Create a memfd backed by HugeTLB and MFD_MF_KEEP_UE_MAPPED bit set.
 * 2. Allocate and map 4 hugepages.
 * 3. Create sub-threads to MADV_HWPOISON inner addresses of one hugepage.
 * 4. Check if each sub-thread get correct SIGBUS for the poisoned raw page.
 * 5. Check if all memory are still accessible and content still valid.
 *
 * Two ways to run the test:
 *   ./hugetlb-mfr 2M
 * or
 *   ./hugetlb-mfr 1G
 * assuming /sys/kernel/mm/hugepages/hugepages-${xxx}kB/nr_hugepages > 4
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <numaif.h>
#include <numa.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/magic.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/statfs.h>
#include <sys/types.h>

#include "../kselftest.h"
#include "vm_util.h"

#define EPREFIX			" !!! "
#define BYTE_LENTH_IN_1G	0x40000000UL
#define BYTE_LENTH_IN_2M	0x200000UL
#define HUGETLB_1GB_STR		"1G"
#define HUGETLB_2MB_STR		"2M"
#define HUGETLB_FILL		0xab

static const unsigned long offsets_1g[] = {0x200000, 0x400000, 0x800000};
static const unsigned long offsets_2m[] = {0x020000, 0x040000, 0x080000};

static void *sigbus_addr;
static int sigbus_addr_lsb;
static bool expecting_sigbus;
static bool got_sigbus;
static bool was_mceerr;

static int create_hugetlbfs_file(struct statfs *file_stat,
				 unsigned long hugepage_size)
{
	int fd;
	int flags = MFD_HUGETLB | MFD_MF_KEEP_UE_MAPPED;

	if (hugepage_size == BYTE_LENTH_IN_2M)
		flags |= MFD_HUGE_2MB;
	else
		flags |= MFD_HUGE_1GB;

	fd = memfd_create("hugetlb_tmp", flags);
	if (fd < 0)
		ksft_exit_fail_perror("Failed to memfd_create");

	memset(file_stat, 0, sizeof(*file_stat));
	if (fstatfs(fd, file_stat)) {
		close(fd);
		ksft_exit_fail_perror("Failed to fstatfs");
	}
	if (file_stat->f_type != HUGETLBFS_MAGIC) {
		close(fd);
		ksft_exit_fail_msg("Not hugetlbfs file");
	}

	ksft_print_msg("Created hugetlb_tmp file\n");
	ksft_print_msg("hugepagesize=%#lx\n", file_stat->f_bsize);
	if (file_stat->f_bsize != hugepage_size)
		ksft_exit_fail_msg("Hugepage size is not %#lx", hugepage_size);

	return fd;
}

/*
 * SIGBUS handler for "do_hwpoison" thread that mapped and MADV_HWPOISON
 */
static void sigbus_handler(int signo, siginfo_t *info, void *context)
{
	if (!expecting_sigbus)
		ksft_exit_fail_msg("unexpected sigbus with addr=%p",
				   info->si_addr);

	got_sigbus = true;
	was_mceerr = (info->si_code == BUS_MCEERR_AO ||
		      info->si_code == BUS_MCEERR_AR);
	sigbus_addr = info->si_addr;
	sigbus_addr_lsb = info->si_addr_lsb;
}

static void *do_hwpoison(void *hwpoison_addr)
{
	int hwpoison_size = getpagesize();

	ksft_print_msg("MADV_HWPOISON hwpoison_addr=%p, len=%d\n",
		       hwpoison_addr, hwpoison_size);
	if (madvise(hwpoison_addr, hwpoison_size, MADV_HWPOISON) < 0)
		ksft_exit_fail_perror("Failed to MADV_HWPOISON");

	pthread_exit(NULL);
}

static void test_hwpoison_multiple_pages(unsigned char *start_addr,
					 unsigned long hugepage_size)
{
	pthread_t pthread;
	int ret;
	unsigned char *hwpoison_addr;
	const unsigned long *offsets;
	size_t offsets_count;
	size_t i;

	if (hugepage_size == BYTE_LENTH_IN_2M) {
		offsets = offsets_2m;
		offsets_count = ARRAY_SIZE(offsets_2m);
	} else {
		offsets = offsets_1g;
		offsets_count = ARRAY_SIZE(offsets_1g);
	}

	for (i = 0; i < offsets_count; ++i) {
		sigbus_addr = (void *)0xBADBADBAD;
		sigbus_addr_lsb = 0;
		was_mceerr = false;
		got_sigbus = false;
		expecting_sigbus = true;
		hwpoison_addr = start_addr + offsets[i];

		ret = pthread_create(&pthread, NULL, &do_hwpoison, hwpoison_addr);
		if (ret)
			ksft_exit_fail_perror("Failed to create hwpoison thread");

		ksft_print_msg("Created thread to hwpoison and access hwpoison_addr=%p\n",
			       hwpoison_addr);

		pthread_join(pthread, NULL);

		if (!got_sigbus)
			ksft_test_result_fail("Didn't get a SIGBUS\n");
		if (!was_mceerr)
			ksft_test_result_fail("Didn't get a BUS_MCEERR_A(R|O)\n");
		if (sigbus_addr != hwpoison_addr)
			ksft_test_result_fail("Incorrect address: got=%p, expected=%p\n",
					      sigbus_addr, hwpoison_addr);
		if (sigbus_addr_lsb != pshift())
			ksft_test_result_fail("Incorrect address LSB: got=%d, expected=%d\n",
					      sigbus_addr_lsb, pshift());

		ksft_print_msg("Received expected and correct SIGBUS\n");
	}
}

static int read_nr_hugepages(unsigned long hugepage_size,
			     unsigned long *nr_hugepages)
{
	char buffer[256] = {0};
	char cmd[256] = {0};

	sprintf(cmd, "cat /sys/kernel/mm/hugepages/hugepages-%ldkB/nr_hugepages",
		hugepage_size);
	FILE *cmdfile = popen(cmd, "r");

	if (cmdfile == NULL) {
		ksft_perror(EPREFIX "failed to popen nr_hugepages");
		return -1;
	}

	if (!fgets(buffer, sizeof(buffer), cmdfile)) {
		ksft_perror(EPREFIX "failed to read nr_hugepages");
		pclose(cmdfile);
		return -1;
	}

	*nr_hugepages = atoll(buffer);
	pclose(cmdfile);
	return 0;
}

/*
 * Main thread that drives the test.
 */
static void test_main(int fd, unsigned long hugepage_size)
{
	unsigned char *map, *iter;
	struct sigaction new, old;
	const unsigned long hugepagesize_kb = hugepage_size / 1024;
	unsigned long nr_hugepages_before = 0;
	unsigned long nr_hugepages_after = 0;
	unsigned long nodemask = 1UL << 0;
	unsigned long len = hugepage_size * 4;
	int ret;

	if (read_nr_hugepages(hugepagesize_kb, &nr_hugepages_before) != 0) {
		close(fd);
		ksft_exit_fail_msg("Failed to read nr_hugepages\n");
	}
	ksft_print_msg("NR hugepages before MADV_HWPOISON is %ld\n", nr_hugepages_before);

	if (ftruncate(fd, len) < 0)
		ksft_exit_fail_perror("Failed to ftruncate");

	ksft_print_msg("Allocated %#lx bytes to HugeTLB file\n", len);

	map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		ksft_exit_fail_msg("Failed to mmap");

	ksft_print_msg("Created HugeTLB mapping: %p\n", map);

	ret = mbind(map, len, MPOL_BIND, &nodemask, sizeof(nodemask) * 8,
		    MPOL_MF_STRICT | MPOL_MF_MOVE);
	if (ret < 0) {
		perror("mbind");
		ksft_exit_fail_msg("Failed to bind to node\n");
	}

	memset(map, HUGETLB_FILL, len);
	ksft_print_msg("Memset every byte to 0xab\n");

	new.sa_sigaction = &sigbus_handler;
	new.sa_flags = SA_SIGINFO;
	if (sigaction(SIGBUS, &new, &old) < 0)
		ksft_exit_fail_msg("Failed to setup SIGBUS handler");

	ksft_print_msg("Setup SIGBUS handler successfully\n");

	test_hwpoison_multiple_pages(map, hugepage_size);

	/*
	 * Since MADV_HWPOISON doesn't corrupt the memory in hardware, and
	 * MFD_MF_KEEP_UE_MAPPED keeps the hugepage mapped, every byte should
	 * remain accessible and hold original data.
	 */
	expecting_sigbus = false;
	for (iter = map; iter < map + len; ++iter) {
		if (*iter != HUGETLB_FILL) {
			ksft_print_msg("At addr=%p: got=%#x, expected=%#x\n",
				       iter, *iter, HUGETLB_FILL);
			ksft_test_result_fail("Memory content corrupted\n");
			break;
		}
	}
	ksft_print_msg("Memory content all valid\n");

	if (read_nr_hugepages(hugepagesize_kb, &nr_hugepages_after) != 0) {
		close(fd);
		ksft_exit_fail_msg("Failed to read nr_hugepages\n");
	}

	/*
	 * After MADV_HWPOISON, hugepage should still be in HugeTLB pool.
	 */
	ksft_print_msg("NR hugepages after MADV_HWPOISON is %ld\n", nr_hugepages_after);
	if (nr_hugepages_before != nr_hugepages_after)
		ksft_test_result_fail("NR hugepages reduced by %ld after MADV_HWPOISON\n",
				      nr_hugepages_before - nr_hugepages_after);

	/* End of the lifetime of the created HugeTLB memfd. */
	if (ftruncate(fd, 0) < 0)
		ksft_exit_fail_perror("Failed to ftruncate to 0");
	munmap(map, len);
	close(fd);

	ksft_test_result_pass("All done\n");
}

static unsigned long parse_hugepage_size(char *argv)
{
	if (strncasecmp(argv, HUGETLB_1GB_STR, strlen(HUGETLB_1GB_STR)) == 0)
		return BYTE_LENTH_IN_1G;

	if (strncasecmp(argv, HUGETLB_2MB_STR, strlen(HUGETLB_2MB_STR)) == 0)
		return BYTE_LENTH_IN_2M;

	ksft_print_msg("Please provide valid hugepage_size: 1G or 2M\n");
	assert(false);
}

int main(int argc, char **argv)
{
	int fd;
	struct statfs file_stat;
	unsigned long hugepage_size;

	if (argc != 2) {
		ksft_print_msg("Usage: %s <hugepage_size=1G|2M>\n", argv[0]);
		return -EINVAL;
	}

	ksft_print_header();
	ksft_set_plan(1);

	hugepage_size = parse_hugepage_size(argv[1]);
	fd = create_hugetlbfs_file(&file_stat, hugepage_size);
	test_main(fd, hugepage_size);

	ksft_finished();
}
