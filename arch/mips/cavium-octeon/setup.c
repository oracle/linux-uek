/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2004-2007 Cavium Networks
 * Copyright (C) 2008, 2009 Wind River Systems
 *   written by Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/compiler.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/serial.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/string.h>	/* for memset */
#include <linux/tty.h>
#include <linux/time.h>
#include <linux/platform_device.h>
#include <linux/serial_core.h>
#include <linux/serial_8250.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/kexec.h>
#include <linux/initrd.h>

#include <linux/bootmem.h>
#include <linux/memblock.h>

#include <mmzone.h>

#include <asm/processor.h>
#include <asm/reboot.h>
#include <asm/smp-ops.h>
#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>
#include <asm/bootinfo.h>
#include <asm/sections.h>
#include <asm/fw/fw.h>
#include <asm/setup.h>
#include <asm/prom.h>
#include <asm/time.h>
#include <asm/perf_event.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/pci-octeon.h>
#include <asm/octeon/cvmx-rst-defs.h>
#include <asm/octeon/cvmx-sso-defs.h>
#include <asm/octeon/cvmx-qlm.h>
#include <asm/octeon/cvmx-debug.h>

#define SDK_VERSION "5.1.0-prerelease"

/*
 * TRUE for devices having registers with little-endian byte
 * order, FALSE for registers with native-endian byte order.
 * PCI mandates little-endian, USB and SATA are configuraable,
 * but we chose little-endian for these.
 */
const bool octeon_should_swizzle_table[256] = {
	[0x00] = true,	/* bootbus/CF */
	[0x1b] = true,	/* PCI mmio window */
	[0x1c] = true,	/* PCI mmio window */
	[0x1d] = true,	/* PCI mmio window */
	[0x1e] = true,	/* PCI mmio window */
	[0x68] = true,	/* OCTEON III USB */
	[0x69] = true,	/* OCTEON III USB */
	[0x6c] = true,	/* OCTEON III SATA */
	[0x6f] = true,	/* OCTEON II USB */
};
EXPORT_SYMBOL(octeon_should_swizzle_table);

static unsigned long long max_memory = ULLONG_MAX;
static const unsigned long MIN_MEM_32 = 256 << 20;
static unsigned long long reserve_low_mem;

/*
 * modified in hernel-entry-init.h, must have an initial value to keep
 * it from being clobbered when bss is zeroed.
 */
u32 octeon_cvmseg_lines = 2;

DEFINE_SEMAPHORE(octeon_bootbus_sem);
EXPORT_SYMBOL(octeon_bootbus_sem);

static struct octeon_boot_descriptor *octeon_boot_desc_ptr;

struct cvmx_bootinfo *octeon_bootinfo;
EXPORT_SYMBOL(octeon_bootinfo);

const char octeon_not_compatible[] =
	"ERROR: CONFIG_CAVIUM_OCTEON2 not compatible with this processor\r\n"
	"You must rebuild the kernel to be able to use it on this system.\r\n";

#ifdef CONFIG_KEXEC
#ifdef CONFIG_SMP
/*
 * Wait for relocation code is prepared and send
 * secondary CPUs to spin until kernel is relocated.
 */
static void octeon_kexec_smp_down(void *ignored)
{
	int cpu = smp_processor_id();

	local_irq_disable();
	set_cpu_online(cpu, false);
	while (!atomic_read(&kexec_ready_to_reboot))
		cpu_relax();

	asm volatile (
	"	sync\n"
	"	synci	($0)\n");

	kexec_reboot();
}
#endif

static int octeon_kexec_prepare(struct kimage *image)
{
	int i;
	char *bootloader = "kexec";

	octeon_boot_desc_ptr->argc = 0;
	for (i = 0; i < image->nr_segments; i++) {
		if (!strncmp(bootloader, (char *)image->segment[i].buf,
				strlen(bootloader))) {
			/*
			 * convert command line string to array
			 * of parameters (as bootloader does).
			 */
			int argc = 0, offt;
			char *str = (char *)image->segment[i].buf;
			char *ptr = strchr(str, ' ');
			while (ptr && (OCTEON_ARGV_MAX_ARGS > argc)) {
				*ptr = '\0';
				if (ptr[1] != ' ') {
					offt = (int)(ptr - str + 1);
					octeon_boot_desc_ptr->argv[argc] =
						image->segment[i].mem + offt;
					argc++;
				}
				ptr = strchr(ptr + 1, ' ');
			}
			octeon_boot_desc_ptr->argc = argc;
			break;
		}
	}
	return 0;
}

static void octeon_generic_shutdown(void)
{
#ifdef CONFIG_SMP
	int cpu;
	secondary_kexec_args[2] = 0UL; /* running on secondary cpu */
	secondary_kexec_args[3] = (unsigned long)octeon_boot_desc_ptr;
	/* disable watchdogs */
	for_each_online_cpu(cpu) {
		int node = cpu_to_node(cpu);
		unsigned int core = cpu_logical_map(cpu) & 0x3f;
		cvmx_write_csr_node(node, CVMX_CIU_WDOGX(core), 0);
	}
#else
	cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
#endif

	kexec_args[2] = 1UL; /* running on octeon_main_processor */
	kexec_args[3] = (unsigned long)octeon_boot_desc_ptr;
}

static void octeon_shutdown(void)
{
	octeon_generic_shutdown();
	octeon_error_tree_shutdown();
#ifdef CONFIG_SMP
	smp_call_function(octeon_kexec_smp_down, NULL, 0);
	smp_wmb();
	while (num_online_cpus() > 1) {
		cpu_relax();
		mdelay(1);
	}
#endif
}

static void octeon_crash_shutdown(struct pt_regs *regs)
{
	octeon_generic_shutdown();
	octeon_error_tree_shutdown();
	default_machine_crash_shutdown(regs);
}

#ifdef CONFIG_SMP
void octeon_crash_smp_send_stop(void)
{
	int cpu;

	/* disable watchdogs */
	for_each_online_cpu(cpu)
		cvmx_write_csr(CVMX_CIU_WDOGX(cpu_logical_map(cpu)), 0);
}
#endif

#endif /* CONFIG_KEXEC */

#ifndef CONFIG_CAVIUM_RESERVE32
#define	 CONFIG_CAVIUM_RESERVE32	0ULL
#endif

uint64_t octeon_reserve32_memory;
EXPORT_SYMBOL(octeon_reserve32_memory);

static int octeon_uart;

extern asmlinkage void handle_int(void);

/* If an initrd named block is specified, its name goes here. */
static char rd_name[64] __initdata;

/* Up to four blocks may be specified. */
static char __initdata named_memory_blocks[4][CVMX_BOOTMEM_NAME_LEN];

/**
 * Return non zero if we are currently running in the Octeon simulator
 *
 * Returns
 */
int octeon_is_simulation(void)
{
	return octeon_bootinfo->board_type == CVMX_BOARD_TYPE_SIM;
}
EXPORT_SYMBOL(octeon_is_simulation);

/**
 * Return true if Octeon is in PCI Host mode. This means
 * Linux can control the PCI bus.
 *
 * Returns Non zero if Octeon in host mode.
 */
int octeon_is_pci_host(void)
{
#ifdef CONFIG_PCI
	return octeon_bootinfo->config_flags & CVMX_BOOTINFO_CFG_FLAG_PCI_HOST;
#else
	return 0;
#endif
}

/**
 * Get the clock rate of Octeon
 *
 * Returns Clock rate in HZ
 */
uint64_t octeon_get_clock_rate(void)
{
	struct cvmx_sysinfo *sysinfo = cvmx_sysinfo_get();

	return sysinfo->cpu_clock_hz;
}
EXPORT_SYMBOL(octeon_get_clock_rate);

static u64 octeon_io_clock_rate;

u64 octeon_get_io_clock_rate(void)
{
	return octeon_io_clock_rate;
}
EXPORT_SYMBOL(octeon_get_io_clock_rate);


/**
 * Write to the LCD display connected to the bootbus. This display
 * exists on most Cavium evaluation boards. If it doesn't exist, then
 * this function doesn't do anything.
 *
 * @s:	    String to write
 */
static void octeon_write_lcd(const char *s)
{
	if (octeon_bootinfo->led_display_base_addr) {
		void __iomem *lcd_address =
			ioremap_nocache(octeon_bootinfo->led_display_base_addr,
					8);
		int i;
		for (i = 0; i < 8; i++, s++) {
			if (*s)
				iowrite8(*s, lcd_address + i);
			else
				iowrite8(' ', lcd_address + i);
		}
		iounmap(lcd_address);
	}
}

/**
 * Return the console uart passed by the bootloader
 *
 * Returns uart	  (0 or 1)
 */
static int octeon_get_boot_uart(void)
{
	return (octeon_boot_desc_ptr->flags & OCTEON_BL_FLAG_CONSOLE_UART1) ?
		1 : 0;
}

/**
 * Check the hardware BIST results for a CPU
 */
void octeon_check_cpu_bist(void)
{
	const int coreid = cvmx_get_core_num();
	unsigned long long mask;
	unsigned long long bist_val;

	/* Check BIST results for COP0 registers */
	mask = 0x1f00000000ull;
	bist_val = read_octeon_c0_icacheerr();
	if (bist_val & mask)
		pr_err("Core%d BIST Failure: CacheErr(icache) = 0x%llx\n",
		       coreid, bist_val);

	if (current_cpu_type() == CPU_CAVIUM_OCTEON3)
		bist_val = read_octeon_c0_errctl();
	else
		bist_val = read_octeon_c0_dcacheerr();
	if (bist_val & 1)
		pr_err("Core%d L1 Dcache parity error: CacheErr(dcache) = 0x%llx\n",
		       coreid, bist_val);

	mask = 0xfc00000000000000ull;
	bist_val = read_c0_cvmmemctl();
	if (bist_val & mask)
		pr_err("Core%d BIST Failure: COP0_CVM_MEM_CTL = 0x%llx\n",
		       coreid, bist_val);

	if (current_cpu_type() == CPU_CAVIUM_OCTEON3) {
		bist_val = read_octeon_c0_errctl();
		bist_val |= 1;
		write_octeon_c0_errctl(bist_val);
	} else
		write_octeon_c0_dcacheerr(0);
}

/**
 * Reboot Octeon
 *
 * @command: Command to pass to the bootloader. Currently ignored.
 */
static void octeon_restart(char *command)
{
	/* Disable all watchdogs before soft reset. They don't get cleared */
#ifdef CONFIG_SMP
	int cpu;
	for_each_online_cpu(cpu)
		cvmx_write_csr(CVMX_CIU_WDOGX(cpu_logical_map(cpu)), 0);
#else
	cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
#endif

	mb();
	while (1)
		if (OCTEON_IS_OCTEON3())
			cvmx_write_csr(CVMX_RST_SOFT_RST, 1);
		else
			cvmx_write_csr(CVMX_CIU_SOFT_RST, 1);
}


/**
 * Permanently stop a core.
 *
 * @arg: Ignored.
 */
static void octeon_kill_core(void *arg)
{
	if (octeon_is_simulation()) {
		/* The simulator needs the watchdog to stop for dead cores */
		cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
		/* A break instruction causes the simulator stop a core */
		asm volatile ("break" ::: "memory");
	}

	local_irq_disable();
	/* Disable watchdog on this core. */
	cvmx_write_csr(CVMX_CIU_WDOGX(cvmx_get_core_num()), 0);
	/* Spin in a low power mode. */
	while (true)
		asm volatile ("wait" ::: "memory");
}


/**
 * Halt the system
 */
static void octeon_halt(void)
{
	smp_call_function(octeon_kill_core, NULL, 0);

	switch (octeon_bootinfo->board_type) {
	case CVMX_BOARD_TYPE_NAC38:
		/* Driving a 1 to GPIO 12 shuts off this board */
		cvmx_write_csr(CVMX_GPIO_BIT_CFGX(12), 1);
		cvmx_write_csr(CVMX_GPIO_TX_SET, 0x1000);
		break;
	default:
		octeon_write_lcd("PowerOff");
		break;
	}

	octeon_kill_core(NULL);
}

static char __read_mostly octeon_system_type[80];

static void __init init_octeon_system_type(void)
{
	char const *board_type;

	board_type = cvmx_board_type_to_string(octeon_bootinfo->board_type);
	if (board_type == NULL) {
		struct device_node *root;
		int ret;

		root = of_find_node_by_path("/");
		ret = of_property_read_string(root, "model", &board_type);
		of_node_put(root);
		if (ret)
			board_type = "Unsupported Board";
	}

	snprintf(octeon_system_type, sizeof(octeon_system_type), "%s (%s)",
		 board_type, octeon_model_get_string(read_c0_prid()));
}

/**
 * Return a string representing the system type
 *
 * Returns
 */
const char *octeon_board_type_string(void)
{
	return octeon_system_type;
}

const char *get_system_type(void)
	__attribute__ ((alias("octeon_board_type_string")));

/* Try for a DIDTO of about 250 mS */
static unsigned int calc_didto(void)
{
	unsigned int bit = 0;
	u64 clk = octeon_get_clock_rate();

	clk >>= 2; /* cycles in 250mS */
	do {
		clk >>= 1;
		if (clk)
			bit++;
	} while (clk);

	if (bit > 31)
		return 0;

	if (OCTEON_IS_OCTEON1PLUS()) {
		switch (bit) {
		case 31:
			return 0;
		case 30:
			return 1;
		default:
			return 2;
		}
	} else {
		switch (bit) {
		case 31:
			return 0;
		case 30:
			return 1;
		case 29:
			return 2;
		case 28:
			return 4;
		case 27:
			return 5;
		case 26:
			return 6;
		default:
			return 7;
		}
	}
}

void octeon_user_io_init(void)
{
	unsigned int v;
	union octeon_cvmemctl cvmmemctl;

	/* Get the current settings for CP0_CVMMEMCTL_REG */
	cvmmemctl.u64 = read_c0_cvmmemctl();
	/* R/W If set, marked write-buffer entries time out the same
	 * as as other entries; if clear, marked write-buffer entries
	 * use the maximum timeout. */
	cvmmemctl.s.dismarkwblongto = 1;
	/* R/W If set, a merged store does not clear the write-buffer
	 * entry timeout state. */
	cvmmemctl.s.dismrgclrwbto = 0;
	/* R/W Two bits that are the MSBs of the resultant CVMSEG LM
	 * word location for an IOBDMA. The other 8 bits come from the
	 * SCRADDR field of the IOBDMA. */
	cvmmemctl.s.iobdmascrmsb = 0;
	/* R/W If set, SYNCWS and SYNCS only order marked stores; if
	 * clear, SYNCWS and SYNCS only order unmarked
	 * stores. SYNCWSMARKED has no effect when DISSYNCWS is
	 * set. */
	cvmmemctl.s.syncwsmarked = 0;
	/* R/W If set, SYNCWS acts as SYNCW and SYNCS acts as SYNC. */
	cvmmemctl.s.dissyncws = 0;
	/* R/W If set, no stall happens on write buffer full. */
	if (OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2))
		cvmmemctl.s.diswbfst = 1;
	else
		cvmmemctl.s.diswbfst = 0;
	/* R/W If set (and SX set), supervisor-level loads/stores can
	 * use XKPHYS addresses with <48>==0 */
	cvmmemctl.s.xkmemenas = 0;

	/* R/W If set (and UX set), user-level loads/stores can use
	 * XKPHYS addresses with VA<48>==0 */
#ifdef CONFIG_CAVIUM_OCTEON_USER_MEM
	cvmmemctl.s.xkmemenau = 1;
#else
	cvmmemctl.s.xkmemenau = 0;
#endif

	/* R/W If set (and SX set), supervisor-level loads/stores can
	 * use XKPHYS addresses with VA<48>==1 */
	cvmmemctl.s.xkioenas = 0;

	/* R/W If set (and UX set), user-level loads/stores can use
	 * XKPHYS addresses with VA<48>==1 */
#ifdef CONFIG_CAVIUM_OCTEON_USER_IO
	cvmmemctl.s.xkioenau = 1;
#else
	cvmmemctl.s.xkioenau = 0;
#endif

	/* R/W If set, all stores act as SYNCW (NOMERGE must be set
	 * when this is set) RW, reset to 0. */
	cvmmemctl.s.allsyncw = 0;

	/* R/W If set, no stores merge, and all stores reach the
	 * coherent bus in order. */
	cvmmemctl.s.nomerge = 0;
	/* R/W Selects the bit in the counter used for DID time-outs 0
	 * = 231, 1 = 230, 2 = 229, 3 = 214. Actual time-out is
	 * between 1x and 2x this interval. For example, with
	 * DIDTTO=3, expiration interval is between 16K and 32K. */
	v = calc_didto();
	cvmmemctl.s.didtto = v & 3;
	cvmmemctl.s.didtto2 = (v >> 2) & 1;
	/* R/W If set, the (mem) CSR clock never turns off. */
	cvmmemctl.s.csrckalwys = 0;
	/* R/W If set, mclk never turns off. */
	cvmmemctl.s.mclkalwys = 0;
	/* R/W Selects the bit in the counter used for write buffer
	 * flush time-outs (WBFLT+11) is the bit position in an
	 * internal counter used to determine expiration. The write
	 * buffer expires between 1x and 2x this interval. For
	 * example, with WBFLT = 0, a write buffer expires between 2K
	 * and 4K cycles after the write buffer entry is allocated. */
	cvmmemctl.s.wbfltime = 0;
	/* R/W If set, do not put Istream in the L2 cache. */
	cvmmemctl.s.istrnol2 = 0;

	/*
	 * R/W The write buffer threshold. As per erratum Core-14752
	 * for CN63XX, a sc/scd might fail if the write buffer is
	 * full.  Lowering WBTHRESH greatly lowers the chances of the
	 * write buffer ever being full and triggering the erratum.
	 */
	if (OCTEON_IS_MODEL(OCTEON_CN63XX_PASS1_X))
		cvmmemctl.s.wbthresh = 4;
	else
		cvmmemctl.s.wbthresh = 10;

	/* R/W If set, CVMSEG is available for loads/stores in
	 * kernel/debug mode. */
	cvmmemctl.s.cvmsegenak = 1;
	if (octeon_has_feature(OCTEON_FEATURE_PKO3)) {
		/* Enable LMTDMA */
		cvmmemctl.s.lmtena = 1;
		/* Scratch line to use for LMT operation */
		cvmmemctl.s.lmtline = 2;
	}
	/* R/W If set, CVMSEG is available for loads/stores in
	 * supervisor mode. */
	cvmmemctl.s.cvmsegenas = 0;
	/* R/W If set, CVMSEG is available for loads/stores in user
	 * mode. */
	cvmmemctl.s.cvmsegenau = 0;

	/* Enable TLB parity error reporting on OCTEON II */
	if (current_cpu_type() == CPU_CAVIUM_OCTEON2)
		cvmmemctl.s.tlbperrena = 1;
	else if (current_cpu_type() == CPU_CAVIUM_OCTEON3)
		cvmmemctl.s.tlbperrena = 0;

	write_c0_cvmmemctl(cvmmemctl.u64);

	/* Setup of CVMSEG is done in kernel-entry-init.h */
	if (smp_processor_id() == 0)
		pr_notice("CVMSEG size: %u cache lines (%u bytes)\n",
			  octeon_cvmseg_lines,
			  octeon_cvmseg_lines * 128);

	if (current_cpu_type() != CPU_CAVIUM_OCTEON3 ||
	    OCTEON_IS_MODEL(OCTEON_CN70XX)) {
		union cvmx_iob_fau_timeout fau_timeout;

		/* Set a default for the hardware timeouts */
		fau_timeout.u64 = 0;
		fau_timeout.s.tout_val = 0xfff;
		/* Disable tagwait FAU timeout */
		fau_timeout.s.tout_enb = 0;
		cvmx_write_csr(CVMX_IOB_FAU_TIMEOUT, fau_timeout.u64);
	}

	if (OCTEON_IS_MODEL(OCTEON_CN68XX) || octeon_has_feature(OCTEON_FEATURE_CIU3)) {
		union cvmx_sso_nw_tim nm_tim;

		nm_tim.u64 = 0;
		/* 4096 cycles */
		nm_tim.s.nw_tim = 3;
		cvmx_write_csr(CVMX_SSO_NW_TIM, nm_tim.u64);
	} else {
		union cvmx_pow_nw_tim nm_tim;

		nm_tim.u64 = 0;
		/* 4096 cycles */
		nm_tim.s.nw_tim = 3;
		cvmx_write_csr(CVMX_POW_NW_TIM, nm_tim.u64);
	}

	write_octeon_c0_icacheerr(0);
	write_c0_derraddr1(0);
}

static void octeon_soc_scache_init(void)
{
	struct cpuinfo_mips *c = &current_cpu_data;
	unsigned long scache_size = cvmx_l2c_get_cache_size_bytes();

	c->scache.sets = cvmx_l2c_get_num_sets();
	c->scache.ways = cvmx_l2c_get_num_assoc();
	c->scache.waybit = ffs(scache_size / c->scache.ways) - 1;
	c->scache.waysize = scache_size / c->scache.ways;
	c->scache.linesz = 128;
	c->scache.flags |= MIPS_CPU_PREFETCH;

	c->tcache.flags |= MIPS_CACHE_NOT_PRESENT;

	if (smp_processor_id() == 0)
		pr_notice("Secondary unified cache %ldkB, %d-way, %d sets, linesize %d bytes.\n",
			  scache_size >> 10, c->scache.ways,
			  c->scache.sets, c->scache.linesz);
}

/**
 * Early entry point for arch setup
 */
void __init prom_init(void)
{
	struct cvmx_sysinfo *sysinfo;
	const char *arg;
	char *p;
	int i;
	u64 t;
	int argc;

	octeon_scache_init = octeon_soc_scache_init;
	/*
	 * The bootloader passes a pointer to the boot descriptor in
	 * $a3, this is available as fw_arg3.
	 */
	octeon_boot_desc_ptr = (struct octeon_boot_descriptor *)fw_arg3;
	octeon_bootinfo = phys_to_virt(octeon_boot_desc_ptr->cvmx_desc_vaddr);
	cvmx_bootmem_init(octeon_bootinfo->phy_mem_desc_addr);

	sysinfo = cvmx_sysinfo_get();
	memset(sysinfo, 0, sizeof(*sysinfo));
	sysinfo->system_dram_size = octeon_bootinfo->dram_size << 20;
	sysinfo->phy_mem_desc_addr = (u64)phys_to_virt(octeon_bootinfo->phy_mem_desc_addr);

	if ((octeon_bootinfo->major_version > 1) ||
	    (octeon_bootinfo->major_version == 1 &&
	     octeon_bootinfo->minor_version >= 4))
		cvmx_coremask_copy(&sysinfo->core_mask,
				   &octeon_bootinfo->ext_core_mask);
	else
		cvmx_coremask_set64(&sysinfo->core_mask,
				    octeon_bootinfo->core_mask);

	/* Some broken u-boot pass garbage in upper bits, clear them out */
	if (!OCTEON_IS_MODEL(OCTEON_CN78XX))
		for (i = 512; i < 1024; i++)
			cvmx_coremask_clear_core(&sysinfo->core_mask, i);

	sysinfo->exception_base_addr = octeon_bootinfo->exception_base_addr;
	sysinfo->cpu_clock_hz = octeon_bootinfo->eclock_hz;
	sysinfo->dram_data_rate_hz = octeon_bootinfo->dclock_hz * 2;
	sysinfo->board_type = octeon_bootinfo->board_type;
	sysinfo->board_rev_major = octeon_bootinfo->board_rev_major;
	sysinfo->board_rev_minor = octeon_bootinfo->board_rev_minor;
	memcpy(sysinfo->mac_addr_base, octeon_bootinfo->mac_addr_base,
	       sizeof(sysinfo->mac_addr_base));
	sysinfo->mac_addr_count = octeon_bootinfo->mac_addr_count;
	memcpy(sysinfo->board_serial_number,
	       octeon_bootinfo->board_serial_number,
	       sizeof(sysinfo->board_serial_number));
	sysinfo->compact_flash_common_base_addr =
		octeon_bootinfo->compact_flash_common_base_addr;
	sysinfo->compact_flash_attribute_base_addr =
		octeon_bootinfo->compact_flash_attribute_base_addr;
	sysinfo->led_display_base_addr = octeon_bootinfo->led_display_base_addr;
	sysinfo->dfa_ref_clock_hz = octeon_bootinfo->dfa_ref_clock_hz;
	sysinfo->bootloader_config_flags = octeon_bootinfo->config_flags;

	if (current_cpu_type() == CPU_CAVIUM_OCTEON2) {
		/* I/O clock runs at a different rate than the CPU. */
		union cvmx_mio_rst_boot rst_boot;
		rst_boot.u64 = cvmx_read_csr(CVMX_MIO_RST_BOOT);
		octeon_io_clock_rate = 50000000 * rst_boot.s.pnr_mul;
	} else if (current_cpu_type() == CPU_CAVIUM_OCTEON3) {
		/* I/O clock runs at a different rate than the CPU. */
		union cvmx_rst_boot rst_boot;
		rst_boot.u64 = cvmx_read_csr(CVMX_RST_BOOT);
		octeon_io_clock_rate = 50000000 * rst_boot.s.pnr_mul;
	} else {
		octeon_io_clock_rate = sysinfo->cpu_clock_hz;
	}

	t = read_c0_cvmctl();
	if ((t & (1ull << 27)) == 0) {
		/*
		 * Setup the multiplier save/restore code if
		 * CvmCtl[NOMUL] clear.
		 */
		void *save;
		void *save_end;
		void *restore;
		void *restore_end;
		int save_len;
		int restore_len;
		int save_max = (char *)octeon_mult_save_end -
			(char *)octeon_mult_save;
		int restore_max = (char *)octeon_mult_restore_end -
			(char *)octeon_mult_restore;
		if (current_cpu_data.cputype == CPU_CAVIUM_OCTEON3) {
			save = octeon_mult_save3;
			save_end = octeon_mult_save3_end;
			restore = octeon_mult_restore3;
			restore_end = octeon_mult_restore3_end;
		} else {
			save = octeon_mult_save2;
			save_end = octeon_mult_save2_end;
			restore = octeon_mult_restore2;
			restore_end = octeon_mult_restore2_end;
		}
		save_len = (char *)save_end - (char *)save;
		restore_len = (char *)restore_end - (char *)restore;
		if (!WARN_ON(save_len > save_max ||
				restore_len > restore_max)) {
			memcpy(octeon_mult_save, save, save_len);
			memcpy(octeon_mult_restore, restore, restore_len);
		}
	}

	/* init octeon feature map */
	octeon_feature_init();

	/*
	 * Only enable the LED controller if we're running on a CN38XX, CN58XX,
	 * or CN56XX. The CN30XX and CN31XX don't have an LED controller.
	 */
	if (!octeon_is_simulation() &&
	    octeon_has_feature(OCTEON_FEATURE_LED_CONTROLLER)) {
		cvmx_write_csr(CVMX_LED_EN, 0);
		cvmx_write_csr(CVMX_LED_PRT, 0);
		cvmx_write_csr(CVMX_LED_DBG, 0);
		cvmx_write_csr(CVMX_LED_PRT_FMT, 0);
		cvmx_write_csr(CVMX_LED_UDD_CNTX(0), 32);
		cvmx_write_csr(CVMX_LED_UDD_CNTX(1), 32);
		cvmx_write_csr(CVMX_LED_UDD_DATX(0), 0);
		cvmx_write_csr(CVMX_LED_UDD_DATX(1), 0);
		cvmx_write_csr(CVMX_LED_EN, 1);
	}
	/*
	 * We need to temporarily allocate all memory in the reserve32
	 * region. This makes sure the kernel doesn't allocate this
	 * memory when it is getting memory from the
	 * bootloader. Later, after the memory allocations are
	 * complete, the reserve32 will be freed.
	 *
	 * Allocate memory for RESERVE32 aligned on 2MB boundary. This
	 * is in case we later use hugetlb entries with it.
	 */
	if (CONFIG_CAVIUM_RESERVE32 > 0) {
		int64_t addr = -1;
		addr = cvmx_bootmem_phy_named_block_alloc(
				CONFIG_CAVIUM_RESERVE32 << 20,
				0, 0, 2 << 20,
				"CAVIUM_RESERVE32", 0);
		if (addr < 0)
			pr_err("Failed to allocate CAVIUM_RESERVE32 memory area\n");
		else
			octeon_reserve32_memory = addr;
	}

	octeon_check_cpu_bist();

	octeon_uart = octeon_get_boot_uart();

#ifdef CONFIG_SMP
	octeon_write_lcd("LinuxSMP");
#else
	octeon_write_lcd("Linux");
#endif

	octeon_setup_delays();

	/*
	 * BIST should always be enabled when doing a soft reset. L2
	 * Cache locking for instance is not cleared unless BIST is
	 * enabled.  Unfortunately due to a chip errata G-200 for
	 * Cn38XX and CN31XX, BIST msut be disabled on these parts.
	 */
	if (OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2) ||
	    OCTEON_IS_MODEL(OCTEON_CN31XX))
		cvmx_write_csr(CVMX_CIU_SOFT_BIST, 0);
	else if (!octeon_has_feature(OCTEON_FEATURE_CIU3))
		cvmx_write_csr(CVMX_CIU_SOFT_BIST, 1);

	/* Default to 64MB in the simulator to speed things up */
	if (octeon_is_simulation())
		max_memory = 64ull << 20;

	arg = strstr(arcs_cmdline, "mem=");
	if (arg) {
		max_memory = memparse(arg + 4, &p);
		if (max_memory == 0)
			max_memory = 2ull << 49;
		if (*p == '@')
			reserve_low_mem = memparse(p + 1, &p);
	}

	arcs_cmdline[0] = 0;
	argc = octeon_boot_desc_ptr->argc;
	for (i = 0; i < argc; i++) {
		const char *arg = phys_to_virt(octeon_boot_desc_ptr->argv[i]);
		if (strncmp(arg, "mem=block:", 10) == 0) {
			const char *pos = arg + 10;
			int j;

			for (j = 0; pos[0] && j < ARRAY_SIZE(named_memory_blocks); j++) {
				int len;
				char *comma = strchr(pos, ',');
				if (comma)
					len = comma - pos;
				else
					len = max(strlen(pos), ARRAY_SIZE(named_memory_blocks[0]));
				strncpy(named_memory_blocks[j], pos, len);
				if (comma)
					pos = comma + 1;
				else
					break;
			}
			for (j = 0; j < ARRAY_SIZE(named_memory_blocks); j++)
				pr_err("Named Block[%d] = \"%s\"\n", j, named_memory_blocks[j]);
		} else if ((strncmp(arg, "MEM=", 4) == 0) ||
		    (strncmp(arg, "mem=", 4) == 0)) {
			max_memory = memparse(arg + 4, &p);
			if (max_memory == 0)
				max_memory = 2ull << 49;
			if (*p == '@')
				reserve_low_mem = memparse(p + 1, &p);
		} else if (strncmp(arg, "rd_name=", 8) == 0) {
			strncpy(rd_name, arg + 8, sizeof(rd_name));
			rd_name[sizeof(rd_name) - 1] = 0;
			goto append_arg;
		} else {
append_arg:
			if (strlen(arcs_cmdline) + strlen(arg) + 1 < sizeof(arcs_cmdline) - 1) {
				strcat(arcs_cmdline, " ");
				strcat(arcs_cmdline, arg);
			}
		}
	}

	if (strstr(arcs_cmdline, "console=pci"))
		octeon_pci_console_init(strstr(arcs_cmdline, "console=pci") + 8);

	if (strstr(arcs_cmdline, "console=") == NULL) {
		if (octeon_uart == 1)
			strcat(arcs_cmdline, " console=ttyS1,115200");
		else
			strcat(arcs_cmdline, " console=ttyS0,115200");
	}

	mips_hpt_frequency = octeon_get_clock_rate();

	octeon_init_cvmcount();

	_machine_restart = octeon_restart;
	_machine_halt = octeon_halt;

#ifdef CONFIG_KEXEC
	_machine_kexec_shutdown = octeon_shutdown;
	_machine_crash_shutdown = octeon_crash_shutdown;
	_machine_kexec_prepare = octeon_kexec_prepare;
#ifdef CONFIG_SMP
	_crash_smp_send_stop = octeon_crash_smp_send_stop;
#endif
#endif

	octeon_user_io_init();
	octeon_setup_numa();
	octeon_setup_smp();

#ifdef CONFIG_CAVIUM_GDB
	cvmx_debug_init();
#endif

#ifdef CONFIG_PCI
	if (octeon_has_feature(OCTEON_FEATURE_PCIE)) {
		if (octeon_has_feature(OCTEON_FEATURE_NPEI))
			octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_PCIE;
		else
			octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_PCIE2;
	} else {
		if (OCTEON_IS_MODEL(OCTEON_CN31XX) ||
		    OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2))
			octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_SMALL;
		else
			octeon_dma_bar_type = OCTEON_DMA_BAR_TYPE_BIG;
	}
#endif

	pr_info("Cavium Inc. SDK-" SDK_VERSION "\n");
}

#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2
static int __init octeon_l2_cache_lock(void)
{
	bool is_octeon = !(current_cpu_type() == CPU_CAVIUM_OCTEON2 ||
			   current_cpu_type() == CPU_CAVIUM_OCTEON3);

	if ((!is_octeon && (cvmx_read_csr(CVMX_MIO_FUS_DAT3) & (3ull << 32)))
	    || (is_octeon && (cvmx_read_csr(CVMX_L2D_FUS3) & (3ull << 34)))) {
		pr_info("Skipping L2 locking due to reduced L2 cache size\n");
	} else {
		u32 __maybe_unused my_ebase = read_c0_ebase() & 0x3ffff000;
		unsigned int __maybe_unused len = 0;
		unsigned int __maybe_unused len2 = 0;
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_TLB
		/* TLB refill */
		len = 0x100;
		pr_info("L2 lock: TLB refill %d bytes\n", len);
		cvmx_l2c_lock_mem_region(my_ebase, len);
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_EXCEPTION
		/* General exception */
		len = 0x80;
		pr_info("L2 lock: General exception %d bytes\n", len);
		cvmx_l2c_lock_mem_region(my_ebase + 0x180, len);
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_LOW_LEVEL_INTERRUPT
		/* Interrupt handler */
		len = 0x80;
		pr_info("L2 lock: low-level interrupt %d bytes\n", len);
		cvmx_l2c_lock_mem_region(my_ebase + 0x200, len);
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_INTERRUPT
		len = 0x100;
		len2 = 0x180;
		pr_info("L2 lock: interrupt %d bytes\n", len + len2);
		cvmx_l2c_lock_mem_region(__pa_symbol(handle_int), len);
		cvmx_l2c_lock_mem_region(__pa_symbol(plat_irq_dispatch), len2);
#endif
#ifdef CONFIG_CAVIUM_OCTEON_LOCK_L2_MEMCPY
		len = 0x480;
		pr_info("L2 lock: memcpy %d bytes\n", len);
		cvmx_l2c_lock_mem_region(__pa_symbol(memcpy), len);
#endif
	}
	return 0;
}
late_initcall(octeon_l2_cache_lock);
#endif

#ifdef CONFIG_HW_PERF_EVENTS
static int octeon_mipspmu_notifier(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	u64 cvmctl_orig = read_c0_cvmctl();
	u64 cvmctl_new = cvmctl_orig;
	u64 mask = (1ull << 15) | (1ull << 17);

	switch (action) {
	case MIPSPMU_ACTIVE:
		cvmctl_new = cvmctl_orig | mask;
		/*
		 * Set CvmCtl[DCICLK,DISCE] for more accurate profiling at
		 * the expense of power consumption.
		 */
		break;
	case MIPSPMU_INACTIVE:
		cvmctl_new = cvmctl_orig & ~mask;
		break;
	default:
		break;
	}
	if (cvmctl_new != cvmctl_orig)
		write_c0_cvmctl(cvmctl_new);
	return NOTIFY_OK;
}
static struct notifier_block octeon_mipspmu_nb = {
	.notifier_call = octeon_mipspmu_notifier
};

static int __init octeon_setup_mipspmu_notifiers(void)
{
	return mipspmu_notifier_register(&octeon_mipspmu_nb);
}
late_initcall(octeon_setup_mipspmu_notifiers);
#endif

/* Exclude a single page from the regions obtained in plat_mem_setup. */
static __init void memory_exclude_page(u64 addr, u64 *mem, u64 *size)
{
	if (addr > *mem && addr < *mem + *size) {
		u64 inc = addr - *mem;
		add_memory_region(*mem, inc, BOOT_MEM_RAM);
		*mem += inc;
		*size -= inc;
	}

	if (addr == *mem && *size > PAGE_SIZE) {
		*mem += PAGE_SIZE;
		*size -= PAGE_SIZE;
	}
}

void __init fw_init_cmdline(void)
{
	int i;

	octeon_boot_desc_ptr = (struct octeon_boot_descriptor *)fw_arg3;
	for (i = 0; i < octeon_boot_desc_ptr->argc; i++) {
		const char *arg =
			cvmx_phys_to_ptr(octeon_boot_desc_ptr->argv[i]);
		if (strlen(arcs_cmdline) + strlen(arg) + 1 <
			   sizeof(arcs_cmdline) - 1) {
			strcat(arcs_cmdline, " ");
			strcat(arcs_cmdline, arg);
		}
	}
}

void __init *plat_get_fdt(void)
{
	octeon_bootinfo =
		cvmx_phys_to_ptr(octeon_boot_desc_ptr->cvmx_desc_vaddr);
	return phys_to_virt(octeon_bootinfo->fdt_addr);
}

void __init plat_mem_setup(void)
{
	u64 mem_alloc_size = 4 << 20;
	u64 mem_32_size;
	u64 total = 0;
	s64 memory;
	u64 limit_max, limit_min;
	const struct cvmx_bootmem_named_block_desc *named_block;
	u64 system_limit = cvmx_bootmem_available_mem(mem_alloc_size);

#ifndef CONFIG_NUMA
	int last_core;
	struct cvmx_sysinfo *sysinfo = cvmx_sysinfo_get();

	last_core = cvmx_coremask_get_last_core(&sysinfo->core_mask);
	if (last_core >= CVMX_COREMASK_MAX_CORES_PER_NODE)
		panic("Must build kernel with CONFIG_NUMA for multi-node system.");
#endif

#ifdef CONFIG_BLK_DEV_INITRD
	if (rd_name[0]) {
		const struct cvmx_bootmem_named_block_desc *initrd_block;

		initrd_block = cvmx_bootmem_find_named_block(rd_name);
		if (initrd_block != NULL) {
			initrd_start = initrd_block->base_addr + PAGE_OFFSET;
			initrd_end = initrd_start + initrd_block->size;
			add_memory_region(initrd_block->base_addr, initrd_block->size,
					  BOOT_MEM_INIT_RAM);
			initrd_in_reserved = 1;
			total += initrd_block->size;
		}
	}
#endif

	if (named_memory_blocks[0][0]) {
		phys_addr_t kernel_begin, kernel_end;
		phys_addr_t block_begin, block_size;
		/* Memory from named blocks only */
		int i;

		kernel_begin = PFN_DOWN(__pa_symbol(&_text)) << PAGE_SHIFT;
		kernel_end = PFN_UP(__pa_symbol(&_end)) << PAGE_SHIFT;

		for (i = 0;
		     i < ARRAY_SIZE(named_memory_blocks) && named_memory_blocks[i][0];
		     i++) {
			named_block = cvmx_bootmem_find_named_block(named_memory_blocks[i]);
			if (!named_block) {
				pr_err("Error: Couldn't find cvmx_bootmem block \"%s\"",
				       named_memory_blocks[i]);
				return;
			}
			pr_info("Adding memory from \"%s\": %016lx @ %016lx\n",
				named_memory_blocks[i],
				(unsigned long)named_block->size,
				(unsigned long)named_block->base_addr);
		
			block_begin = named_block->base_addr;
			block_size = named_block->size;
			if (kernel_begin <= block_begin && kernel_end >= block_begin + block_size)
				continue;

			if (kernel_begin > block_begin && kernel_begin < block_begin + block_size) {
				u64 sz = kernel_begin - named_block->base_addr;
				add_memory_region(named_block->base_addr, sz, BOOT_MEM_RAM);
				total += sz;
				if (block_begin + block_size <= kernel_end)
					continue;
				block_size = block_begin + block_size - kernel_end;
				block_begin = kernel_end;
			}
			if (kernel_end > block_begin && kernel_end < block_begin + block_size) {
				block_size = block_begin + block_size - kernel_end;
				block_begin = kernel_end;
			}
			add_memory_region(block_begin, block_size, BOOT_MEM_RAM);
			total += block_size;
		}
		goto mem_alloc_done;
	}

	if (mem_alloc_size > max_memory)
		mem_alloc_size = max_memory;

	if (system_limit > max_memory)
		system_limit = max_memory;
	/* Try to get 512MB of 32-bit memory */
	mem_32_size = 512 * (1 << 20);

	cvmx_bootmem_lock();
	limit_max = 0xffffffffull;
	limit_min = 0;
	while (total < max_memory) {

		if (total >= mem_32_size)
			limit_max = ~0ull;		/* unlimitted */

		memory = cvmx_bootmem_phy_alloc(mem_alloc_size,
				limit_min, limit_max, 0x100000,
				CVMX_BOOTMEM_FLAG_NO_LOCKING);

		if (memory >= 0) {
			u64 size = mem_alloc_size;
			/*
			 * exclude a page at the beginning and end of
			 * the 256MB PCIe 'hole' so the kernel will not
			 * try to allocate multi-page buffers that
			 * span the discontinuity.
			 */
			memory_exclude_page(CVMX_PCIE_BAR1_PHYS_BASE,
					    &memory, &size);
			memory_exclude_page(CVMX_PCIE_BAR1_PHYS_BASE +
					    CVMX_PCIE_BAR1_PHYS_SIZE,
					    &memory, &size);

			/*
			 * This function automatically merges address
			 * regions next to each other if they are
			 * received in incrementing order.
			 */
			if (size)
				add_memory_region(memory, size, BOOT_MEM_RAM);
			total += mem_alloc_size;
		} else {
			if (limit_max < ~0ull)
				limit_max = ~0ull;		/* unlimitted */
			else
				break;
		}
	}
	cvmx_bootmem_unlock();

mem_alloc_done:

	/*
	 * Now that we've allocated the kernel memory it is safe to
	 * free the reserved region. We free it here so that builtin
	 * drivers can use the memory.
	 */
	if (octeon_reserve32_memory)
		cvmx_bootmem_free_named("CAVIUM_RESERVE32");

	if (total == 0)
		panic("Unable to allocate memory from cvmx_bootmem_phy_alloc\n");

	/* Initialize QLM and also apply any erratas */
	cvmx_qlm_init();
}

struct node_data __node_data[4];
EXPORT_SYMBOL(__node_data);

void __init mach_bootmem_init(void)
{
	int i;
	int node;

	min_low_pfn = ~0UL;
	max_low_pfn = 0;

	for (i = 0; i < boot_mem_map.nr_map; i++) {
		unsigned long start, end;
		struct node_data *nd;
		bool is_usable;

		switch (boot_mem_map.map[i].type) {
		case BOOT_MEM_RAM:
			is_usable = true;
			break;
		case BOOT_MEM_KERNEL:
		case BOOT_MEM_INIT_RAM:
			is_usable = false;
			break;
		default:
			/* Not usable memory */
			continue;
		}
		start = PFN_UP(boot_mem_map.map[i].addr);
		end = PFN_DOWN(boot_mem_map.map[i].addr
				+ boot_mem_map.map[i].size);
		node = pa_to_nid(boot_mem_map.map[i].addr);
		nd = __node_data + node;

		if (max_low_pfn < end)
			max_low_pfn = end;
		if (min_low_pfn > start)
			min_low_pfn = start;

		memblock_add_node(PFN_PHYS(start), PFN_PHYS(end - start), node);

		if (nd->endpfn == 0) {
			nd->startpfn = start;
			nd->endpfn = end;
		} else {
			if (nd->startpfn > start)
				nd->startpfn = start;
			if (nd->endpfn < end)
				nd->endpfn = end;
		}
		if (is_usable && (nd->startmempfn == 0 || start < nd->startmempfn))
			nd->startmempfn = start;
	}
	totalram_pages = 0;

	for_each_online_node(node) {
		unsigned long bootmap_size;
		struct node_data *nd = __node_data + node;
		if (nd->endpfn == 0)
			continue;
		NODE_DATA(node)->bdata = &bootmem_node_data[node];
		bootmap_size = init_bootmem_node(NODE_DATA(node), nd->startmempfn, nd->startpfn,  nd->endpfn);

		for (i = 0; i < boot_mem_map.nr_map; i++) {
			int map_nid;
			bool is_init;

			switch (boot_mem_map.map[i].type) {
			case BOOT_MEM_RAM:
				is_init = false;
				break;
			case BOOT_MEM_INIT_RAM:
				is_init = true;
				break;
			default:
				/* Not usable memory */
				continue;
			}
			map_nid = pa_to_nid(boot_mem_map.map[i].addr);
			if (map_nid != node)
				continue;
			memory_present(node,
				       PFN_DOWN(boot_mem_map.map[i].addr),
				       PFN_UP(boot_mem_map.map[i].addr + boot_mem_map.map[i].size));
			if (!is_init) {
				totalram_pages += PFN_DOWN(boot_mem_map.map[i].size);
				memblock_add_node(boot_mem_map.map[i].addr, boot_mem_map.map[i].size, node);
				free_bootmem_node(NODE_DATA(node), boot_mem_map.map[i].addr, boot_mem_map.map[i].size);
			}
		}
		reserve_bootmem(PFN_PHYS(nd->startmempfn), bootmap_size, BOOTMEM_DEFAULT);
	}
}

/*
 * Emit one character to the boot UART.	 Exported for use by the
 * watchdog timer.
 */
void prom_putchar(char c)
{
	uint64_t lsrval;

	/* Spin until there is room */
	do {
		lsrval = cvmx_read_csr(CVMX_MIO_UARTX_LSR(octeon_uart));
	} while ((lsrval & 0x20) == 0);

	/* Write the byte */
	cvmx_write_csr(CVMX_MIO_UARTX_THR(octeon_uart), c & 0xffull);
}
EXPORT_SYMBOL(prom_putchar);

void __init prom_free_prom_memory(void)
{
	if (CAVIUM_OCTEON_DCACHE_PREFETCH_WAR) {
		/* Check for presence of Core-14449 fix.  */
		u32 insn;
		u32 *foo;

		foo = &insn;

		asm volatile("# before" : : : "memory");
		prefetch(foo);
		asm volatile(
			".set push\n\t"
			".set noreorder\n\t"
			"bal 1f\n\t"
			"nop\n"
			"1:\tlw %0,-12($31)\n\t"
			".set pop\n\t"
			: "=r" (insn) : : "$31", "memory");

		if ((insn >> 26) != 0x33)
			panic("No PREF instruction at Core-14449 probe point.");

		if (((insn >> 16) & 0x1f) != 28)
			panic("OCTEON II DCache prefetch workaround not in place (%04x).\n"
			      "Please build kernel with proper options (CONFIG_CAVIUM_CN63XXP1).",
			      insn);
	}
}

void __init octeon_fill_mac_addresses(void);

void __init device_tree_init(void)
{
	const void *fdt;
	bool do_prune;
	bool fill_mac;

	if (fw_passed_dtb) {
		fdt = (void *)fw_passed_dtb;
		do_prune = false;
		fill_mac = true;
		pr_info("Using appended Device Tree.\n");
	} else if (octeon_bootinfo->minor_version >= 3 && octeon_bootinfo->fdt_addr) {
		fdt = phys_to_virt(octeon_bootinfo->fdt_addr);
		pr_info("Using passed Device Tree <%p>.\n", fdt);
		if (fdt_check_header(fdt))
			panic("Corrupt Device Tree passed to kernel.");
		do_prune = false;
		fill_mac = false;
		pr_info("Using passed Device Tree.\n");
	} else if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
		fdt = &__dtb_octeon_68xx_begin;
		do_prune = true;
		fill_mac = true;
	} else {
		fdt = &__dtb_octeon_3xxx_begin;
		do_prune = true;
		fill_mac = true;
	}

	initial_boot_params = (void *)fdt;

	if (do_prune) {
		octeon_prune_device_tree();
		pr_info("Using internal Device Tree.\n");
	}
	if (fill_mac)
		octeon_fill_mac_addresses();
	unflatten_and_copy_device_tree();
	init_octeon_system_type();
}

static int __initdata disable_octeon_edac_p;

static int __init disable_octeon_edac(char *str)
{
	disable_octeon_edac_p = 1;
	return 0;
}
early_param("disable_octeon_edac", disable_octeon_edac);

static char *edac_device_names[] = {
	"octeon_l2c_edac",
	"octeon_pc_edac",
};

static int __init edac_devinit(void)
{
	struct platform_device *dev;
	int i, err = 0;
	int num_lmc;
	char *name;

	if (disable_octeon_edac_p)
		return 0;

	for (i = 0; i < ARRAY_SIZE(edac_device_names); i++) {
		name = edac_device_names[i];
		dev = platform_device_register_simple(name, -1, NULL, 0);
		if (IS_ERR(dev)) {
			pr_err("Registration of %s failed!\n", name);
			err = PTR_ERR(dev);
		}
	}

	num_lmc = (OCTEON_IS_MODEL(OCTEON_CN68XX)
		   || OCTEON_IS_MODEL(OCTEON_CN78XX)) ? 4 :
		((OCTEON_IS_MODEL(OCTEON_CN56XX)
		  || OCTEON_IS_MODEL(OCTEON_CN73XX)
		  || OCTEON_IS_MODEL(OCTEON_CNF75XX)) ? 2 : 1);
	for (i = 0; i < num_lmc; i++) {
		dev = platform_device_register_simple("octeon_lmc_edac",
						      i, NULL, 0);
		if (IS_ERR(dev)) {
			pr_err("Registration of octeon_lmc_edac %d failed!\n", i);
			err = PTR_ERR(dev);
		}
	}

	return err;
}
device_initcall(edac_devinit);

static void __initdata *octeon_dummy_iospace;

static int __init octeon_no_pci_init(void)
{
	/*
	 * Initially assume there is no PCI. The PCI/PCIe platform code will
	 * later re-initialize these to correct values if they are present.
	 */
	octeon_dummy_iospace = vzalloc(IO_SPACE_LIMIT);
	set_io_port_base((unsigned long)octeon_dummy_iospace);
	ioport_resource.start = MAX_RESOURCE;
	ioport_resource.end = 0;
	return 0;
}
core_initcall(octeon_no_pci_init);

static int __init octeon_no_pci_release(void)
{
	/*
	 * Release the allocated memory if a real IO space is there.
	 */
	if ((unsigned long)octeon_dummy_iospace != mips_io_port_base)
		vfree(octeon_dummy_iospace);
	return 0;
}
late_initcall(octeon_no_pci_release);
