#ifndef MLX5_KCOMPAT_H
#define MLX5_KCOMPAT_H

/* Mellanox kcompat */


static inline int cpumask_set_cpu_local_first(int i, int numa_node, cpumask_t *dstp)
{
	set_bit(0, cpumask_bits(dstp));

	return 0;
}
	
	

/* We don't want this structure exposed to user space */
struct ifla_vf_stats {
        __u64 rx_packets;
        __u64 tx_packets;
        __u64 rx_bytes;
        __u64 tx_bytes;
        __u64 broadcast;
        __u64 multicast;
};
#endif
