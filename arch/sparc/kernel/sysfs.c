/* sysfs.c: Toplogy sysfs support code for sparc64.
 *
 * Copyright (C) 2007 David S. Miller <davem@davemloft.net>
 */
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/init.h>

#include <asm/cpudata.h>
#include <asm/hypervisor.h>
#include <asm/spitfire.h>

static DEFINE_PER_CPU(struct hv_mmu_statistics, mmu_stats) __attribute__((aligned(64)));

#define SHOW_MMUSTAT_ULONG(NAME) \
static ssize_t show_##NAME(struct device *dev, \
			struct device_attribute *attr, char *buf) \
{ \
	struct hv_mmu_statistics *p = &per_cpu(mmu_stats, dev->id); \
	return sprintf(buf, "%lu\n", p->NAME); \
} \
static DEVICE_ATTR(NAME, 0444, show_##NAME, NULL)

SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctx0_8k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctx0_8k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctx0_64k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctx0_64k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctx0_4mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctx0_4mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctx0_256mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctx0_256mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctxnon0_8k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctxnon0_8k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctxnon0_64k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctxnon0_64k_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctxnon0_4mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctxnon0_4mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_hits_ctxnon0_256mb_tte);
SHOW_MMUSTAT_ULONG(immu_tsb_ticks_ctxnon0_256mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctx0_8k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctx0_8k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctx0_64k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctx0_64k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctx0_4mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctx0_4mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctx0_256mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctx0_256mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctxnon0_8k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctxnon0_8k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctxnon0_64k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctxnon0_64k_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctxnon0_4mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctxnon0_4mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_hits_ctxnon0_256mb_tte);
SHOW_MMUSTAT_ULONG(dmmu_tsb_ticks_ctxnon0_256mb_tte);

static struct attribute *mmu_stat_attrs[] = {
	&dev_attr_immu_tsb_hits_ctx0_8k_tte.attr,
	&dev_attr_immu_tsb_ticks_ctx0_8k_tte.attr,
	&dev_attr_immu_tsb_hits_ctx0_64k_tte.attr,
	&dev_attr_immu_tsb_ticks_ctx0_64k_tte.attr,
	&dev_attr_immu_tsb_hits_ctx0_4mb_tte.attr,
	&dev_attr_immu_tsb_ticks_ctx0_4mb_tte.attr,
	&dev_attr_immu_tsb_hits_ctx0_256mb_tte.attr,
	&dev_attr_immu_tsb_ticks_ctx0_256mb_tte.attr,
	&dev_attr_immu_tsb_hits_ctxnon0_8k_tte.attr,
	&dev_attr_immu_tsb_ticks_ctxnon0_8k_tte.attr,
	&dev_attr_immu_tsb_hits_ctxnon0_64k_tte.attr,
	&dev_attr_immu_tsb_ticks_ctxnon0_64k_tte.attr,
	&dev_attr_immu_tsb_hits_ctxnon0_4mb_tte.attr,
	&dev_attr_immu_tsb_ticks_ctxnon0_4mb_tte.attr,
	&dev_attr_immu_tsb_hits_ctxnon0_256mb_tte.attr,
	&dev_attr_immu_tsb_ticks_ctxnon0_256mb_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctx0_8k_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctx0_8k_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctx0_64k_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctx0_64k_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctx0_4mb_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctx0_4mb_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctx0_256mb_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctx0_256mb_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctxnon0_8k_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctxnon0_8k_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctxnon0_64k_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctxnon0_64k_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctxnon0_4mb_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctxnon0_4mb_tte.attr,
	&dev_attr_dmmu_tsb_hits_ctxnon0_256mb_tte.attr,
	&dev_attr_dmmu_tsb_ticks_ctxnon0_256mb_tte.attr,
	NULL,
};

static struct attribute_group mmu_stat_group = {
	.attrs = mmu_stat_attrs,
	.name = "mmu_stats",
};

/* XXX convert to rusty's on_one_cpu */
static unsigned long run_on_cpu(unsigned long cpu,
			        unsigned long (*func)(unsigned long),
				unsigned long arg)
{
	cpumask_t old_affinity;
	unsigned long ret;

	cpumask_copy(&old_affinity, tsk_cpus_allowed(current));
	/* should return -EINVAL to userspace */
	if (set_cpus_allowed_ptr(current, cpumask_of(cpu)))
		return 0;

	ret = func(arg);

	set_cpus_allowed_ptr(current, &old_affinity);

	return ret;
}

static unsigned long read_mmustat_enable(unsigned long junk)
{
	unsigned long ra = 0;

	sun4v_mmustat_info(&ra);

	return ra != 0;
}

static unsigned long write_mmustat_enable(unsigned long val)
{
	unsigned long ra, orig_ra;

	if (val)
		ra = __pa(&per_cpu(mmu_stats, smp_processor_id()));
	else
		ra = 0UL;

	return sun4v_mmustat_conf(ra, &orig_ra);
}

static ssize_t show_mmustat_enable(struct device *s,
				struct device_attribute *attr, char *buf)
{
	unsigned long val = run_on_cpu(s->id, read_mmustat_enable, 0);
	return sprintf(buf, "%lx\n", val);
}

static ssize_t store_mmustat_enable(struct device *s,
			struct device_attribute *attr, const char *buf,
			size_t count)
{
	unsigned long val, err;
	int ret = sscanf(buf, "%lu", &val);

	if (ret != 1)
		return -EINVAL;

	err = run_on_cpu(s->id, write_mmustat_enable, val);
	if (err)
		return -EIO;

	return count;
}

static DEVICE_ATTR(mmustat_enable, 0644, show_mmustat_enable, store_mmustat_enable);

static int mmu_stats_supported;

static int register_mmu_stats(struct device *s)
{
	if (!mmu_stats_supported)
		return 0;
	device_create_file(s, &dev_attr_mmustat_enable);
	return sysfs_create_group(&s->kobj, &mmu_stat_group);
}

#ifdef CONFIG_HOTPLUG_CPU
static void unregister_mmu_stats(struct device *s)
{
	if (!mmu_stats_supported)
		return;
	sysfs_remove_group(&s->kobj, &mmu_stat_group);
	device_remove_file(s, &dev_attr_mmustat_enable);
}
#endif

#define SHOW_CPUDATA_ULONG_NAME(NAME, MEMBER) \
static ssize_t show_##NAME(struct device *dev, \
		struct device_attribute *attr, char *buf) \
{ \
	cpuinfo_sparc *c = &cpu_data(dev->id); \
	return sprintf(buf, "%lu\n", c->MEMBER); \
}

#define SHOW_CPUDATA_UINT_NAME(NAME, MEMBER) \
static ssize_t show_##NAME(struct device *dev, \
		struct device_attribute *attr, char *buf) \
{ \
	cpuinfo_sparc *c = &cpu_data(dev->id); \
	return sprintf(buf, "%u\n", c->MEMBER); \
}

SHOW_CPUDATA_ULONG_NAME(clock_tick, clock_tick);
SHOW_CPUDATA_UINT_NAME(l1_dcache_size, dcache_size);
SHOW_CPUDATA_UINT_NAME(l1_dcache_line_size, dcache_line_size);
SHOW_CPUDATA_UINT_NAME(l1_icache_size, icache_size);
SHOW_CPUDATA_UINT_NAME(l1_icache_line_size, icache_line_size);
SHOW_CPUDATA_UINT_NAME(l2_cache_size, ecache_size);
SHOW_CPUDATA_UINT_NAME(l2_cache_line_size, ecache_line_size);
SHOW_CPUDATA_UINT_NAME(l3_cache_size, l3_cache_size);
SHOW_CPUDATA_UINT_NAME(l3_cache_line_size, l3_cache_line_size);

static struct device_attribute cpu_core_attrs[] = {
	__ATTR(clock_tick,          0444, show_clock_tick, NULL),
	__ATTR(l1_dcache_size,      0444, show_l1_dcache_size, NULL),
	__ATTR(l1_dcache_line_size, 0444, show_l1_dcache_line_size, NULL),
	__ATTR(l1_icache_size,      0444, show_l1_icache_size, NULL),
	__ATTR(l1_icache_line_size, 0444, show_l1_icache_line_size, NULL),
	__ATTR(l2_cache_size,       0444, show_l2_cache_size, NULL),
	__ATTR(l2_cache_line_size,  0444, show_l2_cache_line_size, NULL),
	__ATTR(l3_cache_size,       0444, show_l3_cache_size, NULL),
	__ATTR(l3_cache_line_size,  0444, show_l3_cache_line_size, NULL),
};


#define to_object(k)    container_of(k, struct _index_kobject, kobj)
#define to_attr(a)      container_of(a, struct _cache_attr, attr)

struct _index_kobject {
        struct kobject kobj;
        unsigned int cpu;
        unsigned short index;
};

struct _cache_attr {
        struct attribute attr;
	ssize_t (*show)(struct _index_kobject *ca, char *buf);
	ssize_t (*store)(struct _index_kobject *ca, const char *buf, size_t cnt);
};


static ssize_t show_level(struct _index_kobject *iko, char *buf)
{
	return sprintf(buf, "%d\n", iko->index);
}

static ssize_t show_size(struct _index_kobject *iko, char *buf)
{
	int size = 0;
	cpuinfo_sparc *c = &cpu_data(iko->cpu);

	switch (iko->index) {
	case 0:
		size = c->dcache_size;
		break;
	case 1:
		size = c->icache_size;
		break;
	case 2:
		size = c->ecache_size;
		break;
	case 3:
		size = c->l3_cache_size;
		break;
	}

	return sprintf(buf, "%d\n", size);
}

static ssize_t show_line_size(struct _index_kobject *iko, char *buf)
{
	int size = 0;
	cpuinfo_sparc *c = &cpu_data(iko->cpu);

	switch (iko->index) {
	case 0:
		size = c->dcache_line_size;
		break;
	case 1:
		size = c->icache_line_size;
		break;
	case 2:
		size = c->ecache_line_size;
		break;
	case 3:
		size = c->l3_cache_line_size;
		break;
	}

	return sprintf(buf, "%d\n", size);
}

static ssize_t show_shared_cpu_map_func(struct _index_kobject *iko, int type,
				        char *buf)
{
	const struct cpumask *mask;
	cpumask_t cpu_map;


        ptrdiff_t len = PTR_ALIGN(buf + PAGE_SIZE - 1, PAGE_SIZE) - buf;
        int n = 0;

	if (len < 2)
		return 0;

	switch (iko->index) {
	case 2:
		mask = &cpu_core_map[iko->cpu];
		break;
	case 3:
		mask = &cpu_core_sib_map[iko->cpu];
		break;
	default:
		cpumask_clear(&cpu_map);
		cpumask_set_cpu(iko->cpu, &cpu_map);
		mask = &cpu_map;
		break;
	}

	n = type ?
		scnprintf(buf, len-2, "%*pbl", NR_CPUS, mask) :
		scnprintf(buf, len-2, "%*pb", NR_CPUS, mask);

	buf[n++] = '\n';
	buf[n] = '\0';
        return n;
}

static ssize_t show_shared_cpu_map(struct _index_kobject *iko, char *buf)
{
	return show_shared_cpu_map_func(iko, 0, buf);
}

static ssize_t show_shared_cpu_list(struct _index_kobject *iko, char *buf)
{
	return show_shared_cpu_map_func(iko, 1, buf);
}

static ssize_t show_type(struct _index_kobject *iko, char *buf)
{
	switch (iko->index) {
	case 0:
		return sprintf(buf, "DATA\n");
	case 1:
		return sprintf(buf, "Instruction\n");
	default:
		return sprintf(buf, "Unified\n");
	}
}

#define define_one_ro(_name) \
static struct _cache_attr _name = \
        __ATTR(_name, 0444, show_##_name, NULL)

static struct _cache_attr level = __ATTR(level, 0444, show_level, NULL);
static struct _cache_attr coherency_line_size = __ATTR(coherency_line_size, 0444, show_line_size, NULL);
static struct _cache_attr size = __ATTR(size, 0444, show_size, NULL);
static struct _cache_attr type = __ATTR(type, 0444, show_type, NULL);
static struct _cache_attr shared_cpu_map = __ATTR(shared_cpu_map, 0444, show_shared_cpu_map, NULL);
static struct _cache_attr shared_cpu_list = __ATTR(shared_cpu_list, 0444, show_shared_cpu_list, NULL);

static struct attribute *default_attrs[] = {
        &type.attr,
        &level.attr,
        &coherency_line_size.attr,
        &size.attr,
        &shared_cpu_map.attr,
        &shared_cpu_list.attr,
        NULL
};

static ssize_t show(struct kobject *kobj, struct attribute *attr, char *buf)
{
        struct _cache_attr *fattr = to_attr(attr);
        struct _index_kobject *this_leaf = to_object(kobj);
        ssize_t ret;

        ret = fattr->show ? fattr->show(this_leaf, buf) : 0;
        return ret;
}

static ssize_t store(struct kobject *kobj, struct attribute *attr,
                     const char *buf, size_t count)
{
        return 0;
}

static const struct sysfs_ops sysfs_ops = {
        .show   = show,
        .store  = store,
};

static struct kobj_type ktype_cache = {
        .sysfs_ops      = &sysfs_ops,
        .default_attrs  = default_attrs,
};

static struct kobj_type ktype_percpu_entry = {
        .sysfs_ops      = &sysfs_ops,
};

#define MAX_CACHE_LEVEL 4  /* max level plus one for both I and D */

static struct kobject *cache_kobjs[4096];
static struct _index_kobject *index_kobjs[4096];

static int init_kobjs(unsigned int cpu)
{
        /* Allocate all required memory */
        cache_kobjs[cpu] = kzalloc(sizeof(struct kobject), GFP_KERNEL);
        if (unlikely(cache_kobjs[cpu] == NULL))
                goto err_out;

        index_kobjs[cpu] = kzalloc(sizeof(struct _index_kobject) * MAX_CACHE_LEVEL, GFP_KERNEL);
        if (unlikely(index_kobjs[cpu] == NULL))
                goto err_out;

        return 0;

err_out:
        return -1;
}

#define INDEX_KOBJECT_PTR(x, y)         (&((index_kobjs[x])[y]))


static DEFINE_PER_CPU(struct cpu, cpu_devices);

static int register_cpu_online(unsigned int cpu)
{
	struct cpu *c = &per_cpu(cpu_devices, cpu);
	struct device *s = &c->dev;
	struct _index_kobject *this_object;
	int i, j;
	int retval;

	for (i = 0; i < ARRAY_SIZE(cpu_core_attrs); i++)
		device_create_file(s, &cpu_core_attrs[i]);

	register_mmu_stats(s);

	init_kobjs(cpu);

        retval = kobject_init_and_add(cache_kobjs[cpu], &ktype_percpu_entry,
                                      &s->kobj, "%s", "cache");

        for (i = 0; i < MAX_CACHE_LEVEL; i++) {
                this_object = INDEX_KOBJECT_PTR(cpu, i);
                this_object->cpu = cpu;
                this_object->index = i;

                ktype_cache.default_attrs = default_attrs;

                retval = kobject_init_and_add(&(this_object->kobj),
                                              &ktype_cache,
                                              cache_kobjs[cpu],
                                              "index%1d", i);
                if (unlikely(retval)) {
                        for (j = 0; j < i; j++)
                                kobject_put(&(INDEX_KOBJECT_PTR(cpu, j)->kobj));
                        kobject_put(cache_kobjs[cpu]);
                        return retval;
                }
                kobject_uevent(&(this_object->kobj), KOBJ_ADD);
        }

        kobject_uevent(cache_kobjs[cpu], KOBJ_ADD);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
static void unregister_cpu_online(unsigned int cpu)
{
	struct cpu *c = &per_cpu(cpu_devices, cpu);
	struct device *s = &c->dev;
	int i;

	BUG_ON(!c->hotpluggable);

	unregister_mmu_stats(s);
	for (i = 0; i < ARRAY_SIZE(cpu_core_attrs); i++)
		device_remove_file(s, &cpu_core_attrs[i]);

	for (i = 0; i < MAX_CACHE_LEVEL; i++)
		kobject_put(&(INDEX_KOBJECT_PTR(cpu, i)->kobj));
	kobject_put(cache_kobjs[cpu]);
}

void arch_unregister_cpu(int cpu)
{
	struct cpu *c = &per_cpu(cpu_devices, cpu);

	unregister_cpu(c);
}
#endif

static int sysfs_cpu_notify(struct notifier_block *self,
				      unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned int)(long)hcpu;

	switch (action) {
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		register_cpu_online(cpu);
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		unregister_cpu_online(cpu);
		break;
#endif
	}
	return NOTIFY_OK;
}

static struct notifier_block sysfs_cpu_nb = {
	.notifier_call	= sysfs_cpu_notify,
};

static void __init check_mmu_stats(void)
{
	unsigned long dummy1, err;

	if (tlb_type != hypervisor)
		return;

	err = sun4v_mmustat_info(&dummy1);
	if (!err)
		mmu_stats_supported = 1;
}

static void register_nodes(void)
{
#ifdef CONFIG_NUMA
	int i;

	for (i = 0; i < MAX_NUMNODES; i++)
		register_one_node(i);
#endif
}

/* This function should only be called from the cpu_maps_update_begin
 * or cpu_notifier_register_begin context.
 */
void arch_register_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct cpu *c = &per_cpu(cpu_devices, cpu);

	if (!node_online(node))
		panic("corresponding node [%d] for cpu [%d] is not online.\n",
		      node, cpu);

	c->hotpluggable = 1;
	register_cpu(c, cpu);
	if (cpu_online(cpu))
		register_cpu_online(cpu);
}

static int __init topology_init(void)
{
	int cpu;

	register_nodes();

	check_mmu_stats();

	cpu_notifier_register_begin();
	for_each_present_cpu(cpu) {
		arch_register_cpu(cpu);
	}
	__register_cpu_notifier(&sysfs_cpu_nb);

	cpu_notifier_register_done();

	return 0;
}

subsys_initcall(topology_init);
