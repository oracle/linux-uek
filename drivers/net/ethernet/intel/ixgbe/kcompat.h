
#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

struct netdev_adjacent {
        struct net_device *dev;

        /* upper master flag, there can only be one master device per list */
        bool master;

        /* counter for the number of times this device was added to us */
        u16 ref_nr;

        /* private field for the users */
        void *private;

        struct list_head list;
        struct rcu_head rcu;
};

static struct net_device *netdev_next_upper_dev_rcu(struct net_device *dev,
						    struct list_head **iter)
{
	struct netdev_adjacent *upper;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_rtnl_is_held());

	upper = list_entry_rcu((*iter)->next, struct netdev_adjacent, list);

	if (&upper->list == &dev->adj_list.upper)
		return NULL;

	*iter = &upper->list;

	return upper->dev;
}

int netdev_walk_all_upper_dev_rcu(struct net_device *dev,
				  int (*fn)(struct net_device *dev,
					    void *data),
				  void *data)
{
	struct net_device *udev;
	struct list_head *iter;
	int ret;

	for (iter = &dev->adj_list.upper,
	     udev = netdev_next_upper_dev_rcu(dev, &iter);
	     udev;
	     udev = netdev_next_upper_dev_rcu(dev, &iter)) {
		/* first is the upper device itself */
		ret = fn(udev, data);
		if (ret)
			return ret;

		/* then look at all of its upper devices */
		ret = netdev_walk_all_upper_dev_rcu(udev, fn, data);
		if (ret)
			return ret;
	}

	return 0;
}
#endif
