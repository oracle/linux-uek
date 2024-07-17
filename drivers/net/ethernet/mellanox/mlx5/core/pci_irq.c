// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include "mlx5_core.h"
#include "mlx5_irq.h"
#include "pci_irq.h"
#include "lib/sf.h"
#ifdef CONFIG_RFS_ACCEL
#include <linux/cpu_rmap.h>
#endif

#define MLX5_SFS_PER_CTRL_IRQ 64
#define MLX5_IRQ_CTRL_SF_MAX 8
/* min num of vectors for SFs to be enabled */
#define MLX5_IRQ_VEC_COMP_BASE_SF 2

#define MLX5_EQ_SHARE_IRQ_MAX_COMP (8)
#define MLX5_EQ_SHARE_IRQ_MAX_CTRL (UINT_MAX)
#define MLX5_EQ_SHARE_IRQ_MIN_COMP (1)
#define MLX5_EQ_SHARE_IRQ_MIN_CTRL (4)

struct mlx5_irq {
	struct atomic_notifier_head nh;
	cpumask_var_t mask;
	char name[MLX5_MAX_IRQ_NAME];
	struct mlx5_irq_pool *pool;
	int refcount;
	struct msi_map map;
};

struct mlx5_irq_table {
	struct mlx5_irq_pool *pf_pool;
	struct mlx5_irq_pool *sf_ctrl_pool;
	struct mlx5_irq_pool *sf_comp_pool;
};

/**
 * mlx5_get_default_msix_vec_count - Get the default number of MSI-X vectors
 *                                   to be ssigned to each VF.
 * @dev: PF to work on
 * @num_vfs: Number of enabled VFs
 */
int mlx5_get_default_msix_vec_count(struct mlx5_core_dev *dev, int num_vfs)
{
	int num_vf_msix, min_msix, max_msix;

	num_vf_msix = MLX5_CAP_GEN_MAX(dev, num_total_dynamic_vf_msix);
	if (!num_vf_msix)
		return 0;

	min_msix = MLX5_CAP_GEN(dev, min_dynamic_vf_msix_table_size);
	max_msix = MLX5_CAP_GEN(dev, max_dynamic_vf_msix_table_size);

	/* Limit maximum number of MSI-X vectors so the default configuration
	 * has some available in the pool. This will allow the user to increase
	 * the number of vectors in a VF without having to first size-down other
	 * VFs.
	 */
	return max(min(num_vf_msix / num_vfs, max_msix / 2), min_msix);
}

/**
 * mlx5_set_msix_vec_count - Set dynamically allocated MSI-X on the VF
 * @dev: PF to work on
 * @function_id: Internal PCI VF function IDd
 * @msix_vec_count: Number of MSI-X vectors to set
 */
int mlx5_set_msix_vec_count(struct mlx5_core_dev *dev, int function_id,
			    int msix_vec_count)
{
	int query_sz = MLX5_ST_SZ_BYTES(query_hca_cap_out);
	int set_sz = MLX5_ST_SZ_BYTES(set_hca_cap_in);
	void *hca_cap = NULL, *query_cap = NULL, *cap;
	int num_vf_msix, min_msix, max_msix;
	int ret;

	num_vf_msix = MLX5_CAP_GEN_MAX(dev, num_total_dynamic_vf_msix);
	if (!num_vf_msix)
		return 0;

	if (!MLX5_CAP_GEN(dev, vport_group_manager) || !mlx5_core_is_pf(dev))
		return -EOPNOTSUPP;

	min_msix = MLX5_CAP_GEN(dev, min_dynamic_vf_msix_table_size);
	max_msix = MLX5_CAP_GEN(dev, max_dynamic_vf_msix_table_size);

	if (msix_vec_count < min_msix)
		return -EINVAL;

	if (msix_vec_count > max_msix)
		return -EOVERFLOW;

	query_cap = kvzalloc(query_sz, GFP_KERNEL);
	hca_cap = kvzalloc(set_sz, GFP_KERNEL);
	if (!hca_cap || !query_cap) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_vport_get_other_func_general_cap(dev, function_id, query_cap);
	if (ret)
		goto out;

	cap = MLX5_ADDR_OF(set_hca_cap_in, hca_cap, capability);
	memcpy(cap, MLX5_ADDR_OF(query_hca_cap_out, query_cap, capability),
	       MLX5_UN_SZ_BYTES(hca_cap_union));
	MLX5_SET(cmd_hca_cap, cap, dynamic_msix_table_size, msix_vec_count);

	MLX5_SET(set_hca_cap_in, hca_cap, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	MLX5_SET(set_hca_cap_in, hca_cap, other_function, 1);
	MLX5_SET(set_hca_cap_in, hca_cap, function_id, function_id);

	MLX5_SET(set_hca_cap_in, hca_cap, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE << 1);
	ret = mlx5_cmd_exec_in(dev, set_hca_cap, hca_cap);
out:
	kvfree(hca_cap);
	kvfree(query_cap);
	return ret;
}

static void mlx5_system_free_irq(struct mlx5_irq *irq)
{
	/* free_irq requires that affinity and rmap will be cleared
	 * before calling it. This is why there is asymmetry with set_rmap
	 * which should be called after alloc_irq but before request_irq.
	 */
	irq_update_affinity_hint(irq->map.virq, NULL);
	free_irq(irq->map.virq, &irq->nh);
}

static void irq_release(struct mlx5_irq *irq)
{
	struct mlx5_irq_pool *pool = irq->pool;

	xa_erase(&pool->irqs, irq->map.index);
	mlx5_system_free_irq(irq);
	free_cpumask_var(irq->mask);
	kfree(irq);
}

int mlx5_irq_put(struct mlx5_irq *irq)
{
	struct mlx5_irq_pool *pool = irq->pool;
	int ret = 0;

	mutex_lock(&pool->lock);
	irq->refcount--;
	if (!irq->refcount) {
		irq_release(irq);
		ret = 1;
	}
	mutex_unlock(&pool->lock);
	return ret;
}

int mlx5_irq_read_locked(struct mlx5_irq *irq)
{
	lockdep_assert_held(&irq->pool->lock);
	return irq->refcount;
}

int mlx5_irq_get_locked(struct mlx5_irq *irq)
{
	lockdep_assert_held(&irq->pool->lock);
	if (WARN_ON_ONCE(!irq->refcount))
		return 0;
	irq->refcount++;
	return 1;
}

static int irq_get(struct mlx5_irq *irq)
{
	int err;

	mutex_lock(&irq->pool->lock);
	err = mlx5_irq_get_locked(irq);
	mutex_unlock(&irq->pool->lock);
	return err;
}

static irqreturn_t irq_int_handler(int irq, void *nh)
{
	atomic_notifier_call_chain(nh, 0, NULL);
	return IRQ_HANDLED;
}

static void irq_sf_set_name(struct mlx5_irq_pool *pool, char *name, int vecidx)
{
	snprintf(name, MLX5_MAX_IRQ_NAME, "%s%d", pool->name, vecidx);
}

static void irq_set_name(struct mlx5_irq_pool *pool, char *name, int vecidx)
{
	if (!pool->xa_num_irqs.max) {
		/* in case we only have a single irq for the device */
		snprintf(name, MLX5_MAX_IRQ_NAME, "mlx5_combined%d", vecidx);
		return;
	}

	if (vecidx == pool->xa_num_irqs.max) {
		snprintf(name, MLX5_MAX_IRQ_NAME, "mlx5_async%d", vecidx);
		return;
	}

	snprintf(name, MLX5_MAX_IRQ_NAME, "mlx5_comp%d", vecidx);
}

struct mlx5_irq *mlx5_irq_alloc(struct mlx5_irq_pool *pool, int i,
				const struct cpumask *affinity)
{
	struct mlx5_core_dev *dev = pool->dev;
	char name[MLX5_MAX_IRQ_NAME];
	struct mlx5_irq *irq;
	int err;

	irq = kzalloc(sizeof(*irq), GFP_KERNEL);
	if (!irq)
		return ERR_PTR(-ENOMEM);
	irq->map.virq = pci_irq_vector(dev->pdev, i);
	if (!mlx5_irq_pool_is_sf_pool(pool))
		irq_set_name(pool, name, i);
	else
		irq_sf_set_name(pool, name, i);
	ATOMIC_INIT_NOTIFIER_HEAD(&irq->nh);
	snprintf(irq->name, MLX5_MAX_IRQ_NAME,
		 "%s@pci:%s", name, pci_name(dev->pdev));
	err = request_irq(irq->map.virq, irq_int_handler, 0, irq->name,
			  &irq->nh);
	if (err) {
		mlx5_core_err(dev, "Failed to request irq. err = %d\n", err);
		goto err_req_irq;
	}
	if (!zalloc_cpumask_var(&irq->mask, GFP_KERNEL)) {
		mlx5_core_warn(dev, "zalloc_cpumask_var failed\n");
		err = -ENOMEM;
		goto err_cpumask;
	}
	if (affinity) {
		cpumask_copy(irq->mask, affinity);
		irq_set_affinity_and_hint(irq->map.virq, irq->mask);
	}
	irq->pool = pool;
	irq->refcount = 1;
	irq->map.index = i;
	err = xa_err(xa_store(&pool->irqs, irq->map.index, irq, GFP_KERNEL));
	if (err) {
		mlx5_core_err(dev, "Failed to alloc xa entry for irq(%u). err = %d\n",
			      irq->map.index, err);
		goto err_xa;
	}
	return irq;
err_xa:
	irq_update_affinity_hint(irq->map.virq, NULL);
	free_cpumask_var(irq->mask);
err_cpumask:
	free_irq(irq->map.virq, &irq->nh);
err_req_irq:
	kfree(irq);
	return ERR_PTR(err);
}

int mlx5_irq_attach_nb(struct mlx5_irq *irq, struct notifier_block *nb)
{
	int ret;

	ret = irq_get(irq);
	if (!ret)
		/* Something very bad happens here, we are enabling EQ
		 * on non-existing IRQ.
		 */
		return -ENOENT;
	ret = atomic_notifier_chain_register(&irq->nh, nb);
	if (ret)
		mlx5_irq_put(irq);
	return ret;
}

int mlx5_irq_detach_nb(struct mlx5_irq *irq, struct notifier_block *nb)
{
	int err = 0;

	err = atomic_notifier_chain_unregister(&irq->nh, nb);
	mlx5_irq_put(irq);
	return err;
}

struct cpumask *mlx5_irq_get_affinity_mask(struct mlx5_irq *irq)
{
	return irq->mask;
}

int mlx5_irq_get_index(struct mlx5_irq *irq)
{
	return irq->map.index;
}

/* irq_pool API */

/* requesting an irq from a given pool according to given index */
static struct mlx5_irq *
irq_pool_request_vector(struct mlx5_irq_pool *pool, int vecidx,
			struct cpumask *affinity)
{
	struct mlx5_irq *irq;

	mutex_lock(&pool->lock);
	irq = xa_load(&pool->irqs, vecidx);
	if (irq) {
		mlx5_irq_get_locked(irq);
		goto unlock;
	}
	irq = mlx5_irq_alloc(pool, vecidx, affinity);
unlock:
	mutex_unlock(&pool->lock);
	return irq;
}

static struct mlx5_irq_pool *sf_ctrl_irq_pool_get(struct mlx5_irq_table *irq_table)
{
	return irq_table->sf_ctrl_pool;
}

static struct mlx5_irq_pool *sf_irq_pool_get(struct mlx5_irq_table *irq_table)
{
	return irq_table->sf_comp_pool;
}

struct mlx5_irq_pool *mlx5_irq_pool_get(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *irq_table = mlx5_irq_table_get(dev);
	struct mlx5_irq_pool *pool = NULL;

	if (mlx5_core_is_sf(dev))
		pool = sf_irq_pool_get(irq_table);

	/* In some configs, there won't be a pool of SFs IRQs. Hence, returning
	 * the PF IRQs pool in case the SF pool doesn't exist.
	 */
	return pool ? pool : irq_table->pf_pool;
}

static struct mlx5_irq_pool *ctrl_irq_pool_get(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *irq_table = mlx5_irq_table_get(dev);
	struct mlx5_irq_pool *pool = NULL;

	if (mlx5_core_is_sf(dev))
		pool = sf_ctrl_irq_pool_get(irq_table);

	/* In some configs, there won't be a pool of SFs IRQs. Hence, returning
	 * the PF IRQs pool in case the SF pool doesn't exist.
	 */
	return pool ? pool : irq_table->pf_pool;
}

/**
 * mlx5_irqs_release - release one or more IRQs back to the system.
 * @irqs: IRQs to be released.
 * @nirqs: number of IRQs to be released.
 */
static void mlx5_irqs_release(struct mlx5_irq **irqs, int nirqs)
{
	int i;

	for (i = 0; i < nirqs; i++) {
		synchronize_irq(irqs[i]->map.virq);
		mlx5_irq_put(irqs[i]);
	}
}

/**
 * mlx5_ctrl_irq_release - release a ctrl IRQ back to the system.
 * @ctrl_irq: ctrl IRQ to be released.
 */
void mlx5_ctrl_irq_release(struct mlx5_irq *ctrl_irq)
{
	mlx5_irqs_release(&ctrl_irq, 1);
}

/**
 * mlx5_ctrl_irq_request - request a ctrl IRQ for mlx5 device.
 * @dev: mlx5 device that requesting the IRQ.
 *
 * This function returns a pointer to IRQ, or ERR_PTR in case of error.
 */
struct mlx5_irq *mlx5_ctrl_irq_request(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_pool *pool = ctrl_irq_pool_get(dev);
	cpumask_var_t req_mask;
	struct mlx5_irq *irq;

	if (!zalloc_cpumask_var(&req_mask, GFP_KERNEL))
		return ERR_PTR(-ENOMEM);
	cpumask_copy(req_mask, cpu_online_mask);
	if (!mlx5_irq_pool_is_sf_pool(pool)) {
		/* In case we are allocating a control IRQ from a pci device's pool.
		 * This can happen also for a SF if the SFs pool is empty.
		 */
		if (!pool->xa_num_irqs.max) {
			cpumask_clear(req_mask);
			/* In case we only have a single IRQ for PF/VF */
			cpumask_set_cpu(cpumask_first(cpu_online_mask), req_mask);
		}
		/* Allocate the IRQ in the last index of the pool */
		irq = irq_pool_request_vector(pool, pool->xa_num_irqs.max, req_mask);
	} else {
		irq = mlx5_irq_affinity_request(pool, req_mask);
	}

	free_cpumask_var(req_mask);
	return irq;
}

/**
 * mlx5_irq_request - request an IRQ for mlx5 PF/VF device.
 * @dev: mlx5 device that requesting the IRQ.
 * @vecidx: vector index of the IRQ. This argument is ignore if affinity is
 * provided.
 * @affinity: cpumask requested for this IRQ.
 *
 * This function returns a pointer to IRQ, or ERR_PTR in case of error.
 */
struct mlx5_irq *mlx5_irq_request(struct mlx5_core_dev *dev, u16 vecidx,
				  struct cpumask *affinity)
{
	struct mlx5_irq_table *irq_table = mlx5_irq_table_get(dev);
	struct mlx5_irq_pool *pool;
	struct mlx5_irq *irq;

	pool = irq_table->pf_pool;
	irq = irq_pool_request_vector(pool, vecidx, affinity);
	if (IS_ERR(irq))
		return irq;
	mlx5_core_dbg(dev, "irq %u mapped to cpu %*pbl, %u EQs on this irq\n",
		      irq->map.virq, cpumask_pr_args(affinity),
		      irq->refcount / MLX5_EQ_REFS_PER_IRQ);
	return irq;
}

/**
 * mlx5_irqs_release_vectors - release one or more IRQs back to the system.
 * @irqs: IRQs to be released.
 * @nirqs: number of IRQs to be released.
 */
void mlx5_irqs_release_vectors(struct mlx5_irq **irqs, int nirqs)
{
	mlx5_irqs_release(irqs, nirqs);
}

/**
 * mlx5_irqs_request_vectors - request one or more IRQs for mlx5 device.
 * @dev: mlx5 device that is requesting the IRQs.
 * @cpus: CPUs array for binding the IRQs
 * @nirqs: number of IRQs to request.
 * @irqs: an output array of IRQs pointers.
 *
 * Each IRQ is bound to at most 1 CPU.
 * This function is requests nirqs IRQs, starting from @vecidx.
 *
 * This function returns the number of IRQs requested, (which might be smaller than
 * @nirqs), if successful, or a negative error code in case of an error.
 */
int mlx5_irqs_request_vectors(struct mlx5_core_dev *dev, u16 *cpus, int nirqs,
			      struct mlx5_irq **irqs)
{
	cpumask_var_t req_mask;
	struct mlx5_irq *irq;
	int i;

	if (!zalloc_cpumask_var(&req_mask, GFP_KERNEL))
		return -ENOMEM;
	for (i = 0; i < nirqs; i++) {
		cpumask_set_cpu(cpus[i], req_mask);
		irq = mlx5_irq_request(dev, i, req_mask);
		if (IS_ERR(irq))
			break;
		cpumask_clear(req_mask);
		irqs[i] = irq;
	}

	free_cpumask_var(req_mask);
	return i ? i : PTR_ERR(irq);
}

static struct mlx5_irq_pool *
irq_pool_alloc(struct mlx5_core_dev *dev, int start, int size, char *name,
	       u32 min_threshold, u32 max_threshold)
{
	struct mlx5_irq_pool *pool = kvzalloc(sizeof(*pool), GFP_KERNEL);

	if (!pool)
		return ERR_PTR(-ENOMEM);
	pool->dev = dev;
	mutex_init(&pool->lock);
	xa_init_flags(&pool->irqs, XA_FLAGS_ALLOC);
	pool->xa_num_irqs.min = start;
	pool->xa_num_irqs.max = start + size - 1;
	if (name)
		snprintf(pool->name, MLX5_MAX_IRQ_NAME - MLX5_MAX_IRQ_IDX_CHARS,
			 "%s", name);
	pool->min_threshold = min_threshold * MLX5_EQ_REFS_PER_IRQ;
	pool->max_threshold = max_threshold * MLX5_EQ_REFS_PER_IRQ;
	mlx5_core_dbg(dev, "pool->name = %s, pool->size = %d, pool->start = %d",
		      name, size, start);
	return pool;
}

static void irq_pool_free(struct mlx5_irq_pool *pool)
{
	struct mlx5_irq *irq;
	unsigned long index;

	/* There are cases in which we are destrying the irq_table before
	 * freeing all the IRQs, fast teardown for example. Hence, free the irqs
	 * which might not have been freed.
	 */
	xa_for_each(&pool->irqs, index, irq)
		irq_release(irq);
	xa_destroy(&pool->irqs);
	mutex_destroy(&pool->lock);
	kfree(pool->irqs_per_cpu);
	kvfree(pool);
}

static int irq_pools_init(struct mlx5_core_dev *dev, int sf_vec, int pf_vec)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;
	int num_sf_ctrl_by_msix;
	int num_sf_ctrl_by_sfs;
	int num_sf_ctrl;
	int err;

	/* init pf_pool */
	table->pf_pool = irq_pool_alloc(dev, 0, pf_vec, NULL,
					MLX5_EQ_SHARE_IRQ_MIN_COMP,
					MLX5_EQ_SHARE_IRQ_MAX_COMP);
	if (IS_ERR(table->pf_pool))
		return PTR_ERR(table->pf_pool);
	if (!mlx5_sf_max_functions(dev))
		return 0;
	if (sf_vec < MLX5_IRQ_VEC_COMP_BASE_SF) {
		mlx5_core_dbg(dev, "Not enught IRQs for SFs. SF may run at lower performance\n");
		return 0;
	}

	/* init sf_ctrl_pool */
	num_sf_ctrl_by_msix = DIV_ROUND_UP(sf_vec, MLX5_COMP_EQS_PER_SF);
	num_sf_ctrl_by_sfs = DIV_ROUND_UP(mlx5_sf_max_functions(dev),
					  MLX5_SFS_PER_CTRL_IRQ);
	num_sf_ctrl = min_t(int, num_sf_ctrl_by_msix, num_sf_ctrl_by_sfs);
	num_sf_ctrl = min_t(int, MLX5_IRQ_CTRL_SF_MAX, num_sf_ctrl);
	table->sf_ctrl_pool = irq_pool_alloc(dev, pf_vec, num_sf_ctrl,
					     "mlx5_sf_ctrl",
					     MLX5_EQ_SHARE_IRQ_MIN_CTRL,
					     MLX5_EQ_SHARE_IRQ_MAX_CTRL);
	if (IS_ERR(table->sf_ctrl_pool)) {
		err = PTR_ERR(table->sf_ctrl_pool);
		goto err_pf;
	}
	/* init sf_comp_pool */
	table->sf_comp_pool = irq_pool_alloc(dev, pf_vec + num_sf_ctrl,
					     sf_vec - num_sf_ctrl, "mlx5_sf_comp",
					     MLX5_EQ_SHARE_IRQ_MIN_COMP,
					     MLX5_EQ_SHARE_IRQ_MAX_COMP);
	if (IS_ERR(table->sf_comp_pool)) {
		err = PTR_ERR(table->sf_comp_pool);
		goto err_sf_ctrl;
	}

	table->sf_comp_pool->irqs_per_cpu = kcalloc(nr_cpu_ids, sizeof(u16), GFP_KERNEL);
	if (!table->sf_comp_pool->irqs_per_cpu) {
		err = -ENOMEM;
		goto err_irqs_per_cpu;
	}

	return 0;

err_irqs_per_cpu:
	irq_pool_free(table->sf_comp_pool);
err_sf_ctrl:
	irq_pool_free(table->sf_ctrl_pool);
err_pf:
	irq_pool_free(table->pf_pool);
	return err;
}

static void irq_pools_destroy(struct mlx5_irq_table *table)
{
	if (table->sf_ctrl_pool) {
		irq_pool_free(table->sf_comp_pool);
		irq_pool_free(table->sf_ctrl_pool);
	}
	irq_pool_free(table->pf_pool);
}

static void mlx5_irq_pool_free_irqs(struct mlx5_irq_pool *pool)
{
	struct mlx5_irq *irq;
	unsigned long index;

	xa_for_each(&pool->irqs, index, irq)
		mlx5_system_free_irq(irq);
}

static void mlx5_irq_pools_free_irqs(struct mlx5_irq_table *table)
{
	if (table->sf_ctrl_pool) {
		mlx5_irq_pool_free_irqs(table->sf_comp_pool);
		mlx5_irq_pool_free_irqs(table->sf_ctrl_pool);
	}
	mlx5_irq_pool_free_irqs(table->pf_pool);
}

/* irq_table API */

int mlx5_irq_table_init(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *irq_table;

	if (mlx5_core_is_sf(dev))
		return 0;

	irq_table = kvzalloc_node(sizeof(*irq_table), GFP_KERNEL,
				  dev->priv.numa_node);
	if (!irq_table)
		return -ENOMEM;

	dev->priv.irq_table = irq_table;
	return 0;
}

void mlx5_irq_table_cleanup(struct mlx5_core_dev *dev)
{
	if (mlx5_core_is_sf(dev))
		return;

	kvfree(dev->priv.irq_table);
}

int mlx5_irq_table_get_num_comp(struct mlx5_irq_table *table)
{
	if (!table->pf_pool->xa_num_irqs.max)
		return 1;
	return table->pf_pool->xa_num_irqs.max - table->pf_pool->xa_num_irqs.min;
}

int mlx5_irq_table_create(struct mlx5_core_dev *dev)
{
	int num_eqs = MLX5_CAP_GEN(dev, max_num_eqs) ?
		      MLX5_CAP_GEN(dev, max_num_eqs) :
		      1 << MLX5_CAP_GEN(dev, log_max_eq);
	int total_vec;
	int pf_vec;
	int err;

	if (mlx5_core_is_sf(dev))
		return 0;

	pf_vec = MLX5_CAP_GEN(dev, num_ports) * num_possible_cpus() + 1;
	pf_vec = min_t(int, pf_vec, num_eqs);

	total_vec = pf_vec;
	if (mlx5_sf_max_functions(dev))
		total_vec += MLX5_IRQ_CTRL_SF_MAX +
			MLX5_COMP_EQS_PER_SF * mlx5_sf_max_functions(dev);

	total_vec = pci_alloc_irq_vectors(dev->pdev, 1, total_vec, PCI_IRQ_MSIX);
	if (total_vec < 0)
		return total_vec;
	pf_vec = min(pf_vec, total_vec);

	err = irq_pools_init(dev, total_vec - pf_vec, pf_vec);
	if (err)
		pci_free_irq_vectors(dev->pdev);

	return err;
}

void mlx5_irq_table_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;

	if (mlx5_core_is_sf(dev))
		return;

	/* There are cases where IRQs still will be in used when we reaching
	 * to here. Hence, making sure all the irqs are released.
	 */
	irq_pools_destroy(table);
	pci_free_irq_vectors(dev->pdev);
}

void mlx5_irq_table_free_irqs(struct mlx5_core_dev *dev)
{
	struct mlx5_irq_table *table = dev->priv.irq_table;

	if (mlx5_core_is_sf(dev))
		return;

	mlx5_irq_pools_free_irqs(table);
	pci_free_irq_vectors(dev->pdev);
}

int mlx5_irq_table_get_sfs_vec(struct mlx5_irq_table *table)
{
	if (table->sf_comp_pool)
		return min_t(int, num_online_cpus(),
			     table->sf_comp_pool->xa_num_irqs.max -
			     table->sf_comp_pool->xa_num_irqs.min + 1);
	else
		return mlx5_irq_table_get_num_comp(table);
}

struct mlx5_irq_table *mlx5_irq_table_get(struct mlx5_core_dev *dev)
{
#ifdef CONFIG_MLX5_SF
	if (mlx5_core_is_sf(dev))
		return dev->priv.parent_mdev->priv.irq_table;
#endif
	return dev->priv.irq_table;
}
