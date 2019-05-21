#ifndef MLX5_QP_EXP_H
#define MLX5_QP_EXP_H

#include <linux/mlx5/device.h>

void mlx5_init_dct_table(struct mlx5_core_dev *dev);
void mlx5_cleanup_dct_table(struct mlx5_core_dev *dev);

enum {
	MLX5_DCT_BIT_RRE		= 1 << 19,
	MLX5_DCT_BIT_RWE		= 1 << 18,
	MLX5_DCT_BIT_RAE		= 1 << 17,
};

struct mlx5_dct_context {
	u8			state;
	u8			rsvd0[7];
	__be32			cqn;
	__be32			flags;
	u8			rsvd1;
	u8			cs_res;
	u8			min_rnr;
	u8			rsvd2;
	__be32			srqn;
	__be32			pdn;
	__be32			tclass_flow_label;
	__be64			access_key;
	u8			mtu;
	u8			port;
	__be16			pkey_index;
	u8			rsvd4;
	u8			mgid_index;
	u8			rsvd5;
	u8			hop_limit;
	__be32			access_violations;
	u8			rsvd[12];
};
/*
int mlx5_core_dct_query(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct,
			u32 *out, int outlen);
*/
int mlx5_core_arm_dct(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct);

/*
void mlx5_core_create_dct(struct mlx5_core_dev *dev,
			 struct mlx5_core_dct *dct,
			 u32 *in);
int mlx5_core_destroy_dct(struct mlx5_core_dev *dev,
			  struct mlx5_core_dct *dct);
*/
int mlx5_debug_dct_add(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct);
void mlx5_debug_dct_remove(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct);
#endif
