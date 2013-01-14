
#include <linux/mlx4/device.h>
#include "fmr_api.h"
#include "mlx4.h"

static struct mlx4_icm_slave	*icm_slave;
static u8			vpm_info_size;

static spinlock_t		vf_fmr_ctx_lock;
static void			*vf_fmr_ctx[MLX4_MAX_NUM_VF];
static int			reg_vf_num;


inline int mlx4_fmr_flow(struct mlx4_dev *dev, enum mlx4_mr_flags flags)
{
	return icm_slave && mlx4_is_mfunc(dev) && (flags & MLX4_MR_FLAG_FMR);
}

void mlx4_fmr_slave_init(void)
{
	 spin_lock_init(&vf_fmr_ctx_lock);
}

int mlx4_fmr_slave_context_init(struct mlx4_dev *dev)
{
	struct mlx4_cmd_mailbox		*outbox;
	struct mlx4_enable_fmr_mbox	*enable_fmr_mbox;
	int				err = 0;

	if (!icm_slave)
		return -EINVAL;

	if (mlx4_priv(dev)->fmr_ctx)
		return 0;

	outbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(outbox))
		return PTR_ERR(outbox);

	err = mlx4_cmd_box(dev, 0, outbox->dma, 0, 0, MLX4_CMD_ENABLE_FMR,
			   MLX4_CMD_TIME_CLASS_A, 0);
	if (err) {
		mlx4_dbg(dev, "MLX4_CMD_ENABLE_FMR failed, err %d\n", err);
		goto out_mailbox_free;
	}

	enable_fmr_mbox = (struct mlx4_enable_fmr_mbox *)outbox->buf;
	if (icm_slave->protocol != enable_fmr_mbox->protocol) {
		mlx4_dbg(dev, "Slave fmr protocol (%d) is different from master"
			 " protocol (%d)\n", icm_slave->protocol,
			 enable_fmr_mbox->protocol);
		err = -EINVAL;
		goto out_mailbox_free;
	}

/*
	Moved to query_slave_cap
	dev->caps.fmr_dmpt_base_idx =
			be32_to_cpu(enable_fmr_mbox->base_mpt_entry);
*/
	dev->caps.fmr_log_page_size = enable_fmr_mbox->log_page_size;
	if (dev->caps.fmr_log_page_size != PAGE_SHIFT) {
		mlx4_dbg(dev, "Slave fmr supports only the same "
			 "page size for master and slave\n");
		err = -EINVAL;
		goto out_mailbox_free;
	}

	err = icm_slave->init(dev->pdev, enable_fmr_mbox->vpm_info_size,
			      enable_fmr_mbox->fmr_info_size,
			      enable_fmr_mbox->fmr_info,
			      &mlx4_priv(dev)->fmr_ctx);
	if (err) {
		mlx4_dbg(dev, "Slave enable fmr failed, error %d\n", err);
		goto out_mailbox_free;
	}

	spin_lock_irq(&vf_fmr_ctx_lock);
	vf_fmr_ctx[reg_vf_num++] = mlx4_priv(dev)->fmr_ctx;
	spin_unlock_irq(&vf_fmr_ctx_lock);

	vpm_info_size = enable_fmr_mbox->vpm_info_size;

	mlx4_dbg(dev, "ICM SLAVE: module inited\n");

out_mailbox_free:
	mlx4_free_cmd_mailbox(dev, outbox);
	return err;
}

int mlx4_reg_icm_slave(struct mlx4_icm_slave *slave)
{
	icm_slave = slave;

	printk(KERN_INFO "ICM SLAVE: module registered\n");
	return 0;
}
EXPORT_SYMBOL_GPL(mlx4_reg_icm_slave);

int mlx4_unreg_icm_slave(struct mlx4_icm_slave *slave)
{
	int i;

	if (!icm_slave) {
		printk(KERN_ERR "ICM SLAVE: no module registered\n");
		return -EINVAL;
	}

	spin_lock_irq(&vf_fmr_ctx_lock);
	for (i = 0; i < reg_vf_num; ++i) {
		icm_slave->term(vf_fmr_ctx[i]);
		vf_fmr_ctx[i] = NULL;
	}
	reg_vf_num = 0;
	spin_unlock_irq(&vf_fmr_ctx_lock);

	printk(KERN_INFO "ICM SLAVE: module unregistered\n");
	return 0;
}
EXPORT_SYMBOL_GPL(mlx4_unreg_icm_slave);

void mlx4_fmr_slave_context_term(struct mlx4_dev *dev)
{
	int i;

	if (!icm_slave) {
		mlx4_dbg(dev, "ICM SLAVE: no module registered\n");
		return;
	}
	spin_lock_irq(&vf_fmr_ctx_lock);
	if (!mlx4_priv(dev)->fmr_ctx) {
		mlx4_dbg(dev, "ICM SLAVE: no fmr context\n");
		spin_unlock_irq(&vf_fmr_ctx_lock);
		return;
	}

	for (i = 0; i < reg_vf_num; ++i)
		if (vf_fmr_ctx[i] == mlx4_priv(dev)->fmr_ctx)
			break;

	if (i == reg_vf_num) {
		mlx4_dbg(dev, "ICM SLAVE: fmr context not registered\n");
		spin_unlock_irq(&vf_fmr_ctx_lock);
		return;
	}

	icm_slave->term(mlx4_priv(dev)->fmr_ctx);
	reg_vf_num -= 1;
	for (; i < reg_vf_num; ++i)
		vf_fmr_ctx[i] = vf_fmr_ctx[i + 1];
	vf_fmr_ctx[reg_vf_num] = NULL;
	mlx4_priv(dev)->fmr_ctx = NULL;

	spin_unlock_irq(&vf_fmr_ctx_lock);
}

int mlx4_fmr_slave_vpm_info_size(void)
{
	return vpm_info_size;
}

int mlx4_fmr_slave_share(struct mlx4_dev *dev, void *virt_addr,
			 struct vpm *vpm_page, void **vpm_ctx)
{
	if (!icm_slave) {
		mlx4_dbg(dev, "ICM SLAVE: no module registered\n");
		return -EINVAL;
	}

	return icm_slave->share(&mlx4_priv(dev)->fmr_ctx, virt_addr,
				vpm_page, vpm_ctx);
}

int mlx4_fmr_slave_unshare(void *vpm_ctx)
{
	return icm_slave->unshare(vpm_ctx);
}


