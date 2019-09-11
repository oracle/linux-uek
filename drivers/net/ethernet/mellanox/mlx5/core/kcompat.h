/* Mellanox kcompat */


static inline int cpumask_set_cpu_local_first(int i, int numa_node, cpumask_t *dstp)
{
	set_bit(0, cpumask_bits(dstp));

	return 0;
}
	
	
