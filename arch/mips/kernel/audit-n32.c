#define __WANT_SYSCALL_NUMBERS _MIPS_SIM_NABI32

#include <linux/init.h>
#include <linux/types.h>
#include <linux/audit.h>
#include <asm/unistd.h>

static unsigned int dir_class_n32[] = {
#include <asm-generic/audit_dir_write.h>
~0U
};

static unsigned int read_class_n32[] = {
#include <asm-generic/audit_read.h>
0U
};

static unsigned int write_class_n32[] = {
#include <asm-generic/audit_write.h>
~0U
};

static unsigned int chattr_class_n32[] = {
#include <asm-generic/audit_change_attr.h>
~0U
};

static unsigned int signal_class_n32[] = {
#include <asm-generic/audit_signal.h>
~0U
};

int audit_classify_syscall_n32(int abi, unsigned int syscall)
{
	switch (syscall) {
	case __NR_open:
		return 2;
	case __NR_openat:
		return 3;
	case __NR_execve:
		return 5;
	default:
		return 0;
	}
}

static int __init audit_classes_n32_init(void)
{
	audit_register_class(AUDIT_CLASS_WRITE_N32, write_class_n32);
	audit_register_class(AUDIT_CLASS_READ_N32, read_class_n32);
	audit_register_class(AUDIT_CLASS_DIR_WRITE_N32, dir_class_n32);
	audit_register_class(AUDIT_CLASS_CHATTR_N32, chattr_class_n32);
	audit_register_class(AUDIT_CLASS_SIGNAL_N32, signal_class_n32);

	return 0;
}

arch_initcall(audit_classes_n32_init);

