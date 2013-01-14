
#include <linux/slab.h>
#include <linux/mlx4/device.h>
#include "fmr_api.h"
#include "mlx4.h"


struct mlx4_pf_fmr_ctx {
	struct mlx4_dev	*dev;
	void		*ctx;
};

static struct mlx4_icm_master	*icm_master;

static spinlock_t               pf_fmr_ctx_lock;
static struct mlx4_pf_fmr_ctx	pf_fmr_ctx[MLX4_MAX_NUM_PF];
static int			reg_pf_num;

void mlx4_fmr_master_init(void)
{
	 spin_lock_init(&pf_fmr_ctx_lock);
}


static void fmr_master_delete_vpm_ctx(struct mlx4_dev *dev,
				      struct mlx4_fmr_vpm_ctx *vpm_ctx)
{
	int err;

	err = icm_master->dma_unmap(vpm_ctx->ctx);
	if (err)
		mlx4_dbg(dev, "ICM MASTER: delete vpm ctx "
			 "failed for addr 0x%llx with error %d\n",
			 (unsigned long long)vpm_ctx->va, err);

	kfree(vpm_ctx);
}


static int fmr_master_context_init(struct mlx4_dev *dev)
{
	int err;
	spin_lock_irq(&pf_fmr_ctx_lock);
	if (mlx4_priv(dev)->mfunc.master.fmr_ctx)
	{
		spin_unlock_irq(&pf_fmr_ctx_lock);
		return 0;
	}

	err = icm_master->init(dev->pdev,
			       &mlx4_priv(dev)->mfunc.master.fmr_ctx);
	if (err) {
		mlx4_dbg(dev, "ICM MASTER: init failed, error %d\n", err);
		spin_unlock_irq(&pf_fmr_ctx_lock);
		return err;
	}

	pf_fmr_ctx[reg_pf_num].ctx = mlx4_priv(dev)->mfunc.master.fmr_ctx;
	pf_fmr_ctx[reg_pf_num].dev = dev;
	reg_pf_num++;
	spin_unlock_irq(&pf_fmr_ctx_lock);

	mlx4_dbg(dev, "ICM MASTER: module inited\n");
	return 0;
}

#define DELETE_BATCH 16
void mlx4_fmr_master_delete_slave(struct mlx4_dev *dev, int slave)
{
	struct mlx4_slave_fmr_ctx *slave_fmr_ctx;
	struct mlx4_fmr_vpm_ctx *vpm_ctx[DELETE_BATCH];
	int num_vpm_ctx, i;

	mlx4_dbg(dev, "ICM MASTER: delete slave %d\n", slave);

	if (!icm_master) {
		mlx4_dbg(dev, "ICM MASTER: no module registered\n");
		return;
	}

	slave_fmr_ctx = &mlx4_priv(dev)->mfunc.master.slave_fmr_ctx[slave];

	spin_lock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
	if (!slave_fmr_ctx->vf_ctx) {
		mlx4_dbg(dev, "ICM MASTER: delete - no data for slave %d\n",
			  slave);
		spin_unlock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
		return;
	}

	do {
		num_vpm_ctx = radix_tree_gang_lookup(
					&slave_fmr_ctx->vpm_ctx_tree,
					(void **)vpm_ctx, 0, DELETE_BATCH);
		for (i = 0; i < num_vpm_ctx; ++i) {
			radix_tree_delete(&slave_fmr_ctx->vpm_ctx_tree,
					  vpm_ctx[i]->va);
			fmr_master_delete_vpm_ctx(dev, vpm_ctx[i]);
		}
	} while (num_vpm_ctx);

	icm_master->del_function(slave_fmr_ctx->vf_ctx);
	slave_fmr_ctx->vf_ctx = NULL;
	spin_unlock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
}

int mlx4_reg_icm_master(struct mlx4_icm_master *master)
{
	icm_master = master;

	printk(KERN_INFO "ICM MASTER: module registered\n");
	return 0;
}
EXPORT_SYMBOL_GPL(mlx4_reg_icm_master);

int mlx4_unreg_icm_master(struct mlx4_icm_master *master)
{
	int i, j;
	struct mlx4_dev *dev;

	if (icm_master != master)
		return -EINVAL;

	spin_lock_irq(&pf_fmr_ctx_lock);
	for (i = 0; i < reg_pf_num; ++i) {
		dev = pf_fmr_ctx[i].dev;
		for (j = 0 ; j < dev->num_slaves; j++)
			mlx4_fmr_master_delete_slave(dev, j);
		icm_master->term(pf_fmr_ctx[i].ctx);
	}
	reg_pf_num = 0;
	icm_master = NULL;

	spin_unlock_irq(&pf_fmr_ctx_lock);

	printk(KERN_INFO "ICM MASTER: module unregistered\n");

	return 0;
}
EXPORT_SYMBOL_GPL(mlx4_unreg_icm_master);

u8 mlx4_fmr_master_protocol(void)
{
	return icm_master->protocol;
}

u8 mlx4_fmr_master_vpm_info_size(void)
{
	return icm_master->vpm_info_size;
}

u8 mlx4_fmr_master_fmr_info_size(void)
{
	return icm_master->fmr_info_size;
}

u8 mlx4_fmr_master_fmr_log_page_size(void)
{
	return icm_master->log_page_size;
}

int mlx4_ENABLE_FMR_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	struct mlx4_enable_fmr_mbox *enable_fmr_mbox;
	struct mlx4_slave_fmr_ctx   *slave_fmr_ctx;
	int			    err;

	if (!icm_master) {
		mlx4_dbg(dev, "ICM MASTER: no module registered\n");
		return -EINVAL;
	}

	err = fmr_master_context_init(dev);
	if (err) {
		mlx4_dbg(dev, "ICM MASTER: module init failed\n");
		return err;
	}

	enable_fmr_mbox = outbox->buf;
	memset(enable_fmr_mbox, 0, sizeof *enable_fmr_mbox);

	slave_fmr_ctx = &mlx4_priv(dev)->mfunc.master.slave_fmr_ctx[slave];

	err = icm_master->add_function(mlx4_priv(dev)->mfunc.master.fmr_ctx,
				NULL, /* todo: replace with vf's pci_dev */
				NULL, /* todo: replace with fmr_info */
				&slave_fmr_ctx->vf_ctx);
	if (err) {
		mlx4_dbg(dev, "ICM MASTER: add function failed,"
			 " err %d\n", err);
		return err;
	}

	spin_lock_init(&slave_fmr_ctx->vpm_ctx_tree_lock);
	INIT_RADIX_TREE(&slave_fmr_ctx->vpm_ctx_tree, GFP_ATOMIC);

	if (!dev->caps.fmr_log_page_size)
		dev->caps.fmr_log_page_size = icm_master->log_page_size;

	enable_fmr_mbox->protocol	= icm_master->protocol;
	enable_fmr_mbox->fmr_info_size	= icm_master->fmr_info_size;
	enable_fmr_mbox->vpm_info_size	= icm_master->vpm_info_size;
	enable_fmr_mbox->log_page_size	= icm_master->log_page_size;
	enable_fmr_mbox->base_mpt_entry	=
			cpu_to_be32(dev->caps.fmr_dmpt_base_idx +
				    slave * dev->caps.fmr_num_mpts);

	/* add here protocol specific private info */

	return 0;
}

dma_addr_t mlx4_fmr_master_dma_map(struct mlx4_dev *dev, int slave,
				    struct vpm *vpm)
{
	struct mlx4_slave_fmr_ctx *slave_fmr_ctx;
	struct mlx4_fmr_vpm_ctx *vpm_ctx;
	dma_addr_t addr;
	int err;

	slave_fmr_ctx = &mlx4_priv(dev)->mfunc.master.slave_fmr_ctx[slave];
	if (!slave_fmr_ctx->vf_ctx) {
		mlx4_dbg(dev, "ICM MASTER: failed to map dma addr\n");
		return 0;
	}

	vpm_ctx = kzalloc(sizeof(vpm_ctx), GFP_KERNEL);
	if (!vpm_ctx) {
		mlx4_dbg(dev, "ICM MASTER: dma map has no mem left\n");
		return 0;
	}
	vpm_ctx->va = be64_to_cpu(vpm->va);
	addr = icm_master->dma_map(slave_fmr_ctx->vf_ctx, vpm, &vpm_ctx->ctx);
	if (addr) {
		spin_lock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
		err = radix_tree_insert(&slave_fmr_ctx->vpm_ctx_tree,
					vpm_ctx->va, vpm_ctx);
		spin_unlock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
		if (err) {
			mlx4_dbg(dev, "ICM MASTER: failed to save dma addr\n");
			goto out_free_vpm_ctx;
		}
	}

	return addr;

out_free_vpm_ctx:
	kfree(vpm_ctx);
	return 0;
}

void mlx4_fmr_master_dma_unmap(struct mlx4_dev *dev, int slave, u64 va)
{
	struct mlx4_slave_fmr_ctx *slave_fmr_ctx;
	struct mlx4_fmr_vpm_ctx *vpm_ctx;

	slave_fmr_ctx = &mlx4_priv(dev)->mfunc.master.slave_fmr_ctx[slave];
	if (!slave_fmr_ctx->vf_ctx) {
		mlx4_dbg(dev, "ICM MASTER: failed to unmap dma"
			 " for addr 0x%llx\n",
			 (unsigned long long)va);
		return;
	}
	spin_lock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
	vpm_ctx = radix_tree_delete(&slave_fmr_ctx->vpm_ctx_tree, va);
	spin_unlock_irq(&slave_fmr_ctx->vpm_ctx_tree_lock);
	if (!vpm_ctx) {
		mlx4_dbg(dev, "ICM MASTER: unmap dma failed to get"
			 " track data for addr 0x%llx\n",
			 (unsigned long long)va);
		return;
	}

	fmr_master_delete_vpm_ctx(dev, vpm_ctx);
}
