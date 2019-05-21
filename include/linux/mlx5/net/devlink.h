#ifndef COMPAT_LINUX_DEVLINK_H
#define COMPAT_LINUX_DEVLINK_H

#include <linux/mlx5/compat/config.h>
#ifdef HAVE_DEVLINK_H
#include_next <net/devlink.h>
#else /* HAVE_DEVLINK_H */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

struct devlink {
	char priv[0] __aligned(NETDEV_ALIGN);
};

struct devlink_ops {
	int (*eswitch_mode_get)(struct devlink *devlink, u16 *p_mode);
	int (*eswitch_mode_set)(struct devlink *devlink, u16 mode);
	int (*eswitch_inline_mode_get)(struct devlink *devlink, u8 *p_inline_mode);
	int (*eswitch_inline_mode_set)(struct devlink *devlink, u8 inline_mode);
	int (*eswitch_encap_mode_get)(struct devlink *devlink, u8 *p_encap_mode);
	int (*eswitch_encap_mode_set)(struct devlink *devlink, u8 encap_mode);
};

static inline void *devlink_priv(struct devlink *devlink)
{
	BUG_ON(!devlink);
	return &devlink->priv;
}

static inline struct devlink *priv_to_devlink(void *priv)
{
	BUG_ON(!priv);
	return container_of(priv, struct devlink, priv);
}

static inline struct devlink *devlink_alloc(const struct devlink_ops *ops,
					    size_t priv_size)
{
	return kzalloc(sizeof(struct devlink) + priv_size, GFP_KERNEL);
}

static inline void devlink_free(struct devlink *devlink)
{
	kfree(devlink);
}

static inline int devlink_register(struct devlink *devlink, struct device *dev)
{
	return 0;
}

static inline void devlink_unregister(struct devlink *devlink)
{
}

#endif /* HAVE_DEVLINK_H */

#endif /* COMPAT_LINUX_DEVLINK_H */
