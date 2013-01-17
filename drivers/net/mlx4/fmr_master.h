#ifndef MLX4_FMR_MASTER_H
#define MLX4_FMR_MASTER_H

#include "fmr_api.h"

u8 mlx4_fmr_master_protocol(void);
u8 mlx4_fmr_master_vpm_info_size(void);
u8 mlx4_fmr_master_fmr_info_size(void);
u8 mlx4_fmr_master_fmr_log_page_size(void);

int mlx4_ENABLE_FMR_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd);

int mlx4_fmr_master_init(void);

void mlx4_fmr_master_delete_slave(struct mlx4_dev *dev, int slave);

dma_addr_t mlx4_fmr_master_dma_map(struct mlx4_dev *dev, int slave,
				    struct vpm *vpm_page);

void mlx4_fmr_master_dma_unmap(struct mlx4_dev *dev, int slave, u64 va);

#endif /* MLX4_FMR_MASTER_H */
