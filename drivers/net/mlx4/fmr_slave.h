#ifndef MLX4_FMR_SLAVE_H
#define MLX4_FMR_SLAVE_H

#include "fmr_api.h"

int mlx4_fmr_flow(struct mlx4_dev *dev, enum mlx4_mr_flags flags);
int mlx4_fmr_slave_init(void);
int mlx4_fmr_slave_context_init(struct mlx4_dev *dev);
void mlx4_fmr_slave_context_term(struct mlx4_dev *dev);

int mlx4_fmr_slave_vpm_info_size(void);
int mlx4_fmr_slave_share(struct mlx4_dev *dev, void *virt_addr,
			 struct vpm *vpm_page, void **vpm_ctx);
int mlx4_fmr_slave_unshare(void *vpm_ctx);

#endif /* MLX4_FMR_SLAVE_H */
