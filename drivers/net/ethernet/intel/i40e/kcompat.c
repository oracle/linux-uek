
#include "kcompat.h"

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) )
#ifdef CONFIG_XPS
#if NR_CPUS < 64
#define _KC_MAX_XPS_CPUS	NR_CPUS
#else
#define _KC_MAX_XPS_CPUS	64
#endif

/*
 * netdev_queue sysfs structures and functions.
 */
struct _kc_netdev_queue_attribute {
	struct attribute attr;
	ssize_t (*show)(struct netdev_queue *queue,
	    struct _kc_netdev_queue_attribute *attr, char *buf);
	ssize_t (*store)(struct netdev_queue *queue,
	    struct _kc_netdev_queue_attribute *attr, const char *buf, size_t len);
};

#define to_kc_netdev_queue_attr(_attr) container_of(_attr,		\
    struct _kc_netdev_queue_attribute, attr)

int __kc_netif_set_xps_queue(struct net_device *dev, struct cpumask *mask,
			     u16 index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, index);
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) )
	/* Redhat requires some odd extended netdev structures */
	struct netdev_tx_queue_extended *txq_ext =
					netdev_extended(dev)->_tx_ext + index;
	struct kobj_type *ktype = txq_ext->kobj.ktype;
#else
	struct kobj_type *ktype = txq->kobj.ktype;
#endif
	struct _kc_netdev_queue_attribute *xps_attr;
	struct attribute *attr = NULL;
	int i, len, err;
#define _KC_XPS_BUFLEN	(DIV_ROUND_UP(_KC_MAX_XPS_CPUS, 32) * 9)
	char buf[_KC_XPS_BUFLEN];

	if (!ktype)
		return -ENOMEM;

	/* attempt to locate the XPS attribute in the Tx queue */
	for (i = 0; (attr = ktype->default_attrs[i]); i++) {
		if (!strcmp("xps_cpus", attr->name))
			break;
	}

	/* if we did not find it return an error */
	if (!attr)
		return -EINVAL;

	/* copy the mask into a string */
	len = bitmap_scnprintf(buf, _KC_XPS_BUFLEN,
			       cpumask_bits(mask), _KC_MAX_XPS_CPUS);
	if (!len)
		return -ENOMEM;

	xps_attr = to_kc_netdev_queue_attr(attr);

	/* Store the XPS value using the SYSFS store call */
	err = xps_attr->store(txq, xps_attr, buf, len);

	/* we only had an error on err < 0 */
	return (err < 0) ? err : 0;
}
#endif /* CONFIG_XPS */
#endif /* 3.9.0 */

