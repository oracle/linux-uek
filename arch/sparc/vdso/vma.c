/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vdso.h>
#include <asm/vvar.h>
#include <asm/page.h>

#ifdef CONFIG_SPARC64
unsigned int __read_mostly vdso64_enabled = 1;
#endif

static struct page **vdso_pages, **vvar_page;
static struct vdso_image vdso_image_64;
static struct vm_special_mapping vvar_mapping = {
	.name = "[vvar]"
};
static struct vm_special_mapping vdso_mapping = {
	.name = "[vdso]"
};
struct vvar_data *vvar_data;

/*
 * Allocate pages for the vdso and vvar, and copy in the vdso text from the
 * kernel image.
 */
int __init init_vdso_image(struct vdso_image *image)
{
	int i;
	int npages = (image->size) / PAGE_SIZE;
	struct page *p;

	/*
	 * First, the vdso text.  This is initialied data, an integral number of
	 * pages long.
	 */
	BUG_ON(image->size % PAGE_SIZE != 0);

	vdso_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	vdso_mapping.pages = vdso_pages;

	if (!vdso_pages)
		goto oom;

	for (i = 0; i < npages; i++) {
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto oom;

		vdso_pages[i] = p;
		copy_page(page_address(p), image->data + i * PAGE_SIZE);
	}

	/*
	 * Now the vvar page.  This is uninitialized data.
	 */

	npages = (sizeof(struct vvar_data) / PAGE_SIZE) + 1;
	BUG_ON(npages != 1);
	vvar_page = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	vvar_mapping.pages = vvar_page;

	if (!vvar_page)
		goto oom;

	p = alloc_page(GFP_KERNEL);
	if (!p)
		goto oom;

	vvar_page[0] = p;
	vvar_data = page_address(p);
	memset(vvar_data, 0, PAGE_SIZE);

	return 0;
 oom:
	printk(KERN_WARNING "Cannot allocate vdso\n");
	vdso64_enabled = 0;
	return -ENOMEM;
}

#ifdef CONFIG_SPARC64
static int __init init_vdso(void)
{
	memcpy(&vdso_image_64, &vdso_image_64_builtin,
	       sizeof(struct vdso_image));
	return init_vdso_image(&vdso_image_64);
}
subsys_initcall(init_vdso);
#endif

struct linux_binprm;

/* Shuffle the vdso up a bit, randomly. */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned offset;

	/* This loses some more bits than a modulo, but is cheaper */
	offset = get_random_int() & (PTRS_PER_PTE - 1);
	return start + (offset << PAGE_SHIFT);
}

static int map_vdso(const struct vdso_image *image)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long text_start, addr = 0;
	int ret = 0;

	down_write(&mm->mmap_sem);

	/*
	 * First, get an unmapped region: then randomize it, and make sure that
	 * region is free.
	 */
	if (current->flags & PF_RANDOMIZE) {
		addr = get_unmapped_area(NULL, 0,
					 image->size - image->sym_vvar_start,
					 0, 0);
		if (IS_ERR_VALUE(addr)) {
			ret = addr;
			goto up_fail;
		}
		addr = vdso_addr(addr, image->size - image->sym_vvar_start);
	}
	addr = get_unmapped_area(NULL, addr,
				 image->size - image->sym_vvar_start, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	text_start = addr - image->sym_vvar_start;
	current->mm->context.vdso = (void __user *)text_start;

	/*
	 * MAYWRITE to allow gdb to COW and set breakpoints
	 */
	vma = _install_special_mapping(mm,
				       text_start,
				       image->size,
				       VM_READ|VM_EXEC|
				       VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				       &vdso_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	vma = _install_special_mapping(mm,
				       addr,
				       -image->sym_vvar_start,
				       VM_READ|VM_MAYREAD,
				       &vvar_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	if (ret)
		goto up_fail;

up_fail:
	if (ret)
		current->mm->context.vdso = NULL;

	up_write(&mm->mmap_sem);
	return ret;
}

#ifdef CONFIG_SPARC64
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	if (!vdso64_enabled)
		return 0;

	return map_vdso(&vdso_image_64);
}

static __init int vdso_setup(char *s)
{
	vdso64_enabled = simple_strtoul(s, NULL, 0);
	return 0;
}
__setup("vdso=", vdso_setup);
#endif

/*
 * SPARC doesn't need a gate area, since we have no (obsolete) vsyscall page nor
 * anything else at a similar fixed address.  However, kernels pre-3.17 assume
 * that anything with an AT_SYSINFO_EHDR also has a gate area (because
 * historically the gate area came first): we have to explicitly disable it.
 */

int in_gate_area_no_mm(unsigned long addr)
{
	return 0;
}

int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	return 0;
}

struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
	return NULL;
}
