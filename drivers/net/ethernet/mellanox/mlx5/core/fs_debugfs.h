#ifndef _MLX5_FS_DEBUGFS_
#define _MLX5_FS_DEBUGFS_

struct mlx5_core_dev;

struct fs_debugfs_match_misc_params {
	struct dentry *dir;
	struct dentry *src_port;
};

struct fs_debugfs_match_layer_2_4 {
	struct dentry *dir;
	struct dentry *dmac;
	struct dentry *smac;
	struct dentry *vid;
	struct dentry *src_ip;
	struct dentry *dst_ip;
	struct dentry *udp_sport;
	struct dentry *udp_dport;
	struct dentry *tcp_sport;
	struct dentry *tcp_dport;
	struct dentry *ethertype;
	struct dentry *ip_protocol;
};

struct fs_debugfs_match_header_ctx {
	struct fs_node *node;
	char	*addr;
	struct fs_debugfs_match_layer_2_4	header_files;
};

struct fs_debugfs_misc_params_ctx {
	struct fs_node *node;
	char	*addr;
	struct fs_debugfs_match_misc_params	misc_params;
};

struct fs_debugfs_match_criteria {
	struct dentry *dir;
	struct fs_debugfs_match_header_ctx		outer_headers_ctx;
	struct fs_debugfs_match_header_ctx		inner_headers_ctx;
	struct fs_debugfs_misc_params_ctx		misc_params_ctx;
};
struct fs_debugfs_mask {
	struct dentry				*match_criteria_enable;
	struct fs_debugfs_match_criteria	match_criteria;
};

struct fs_debugfs_fg {
	struct dentry				*start_index;
	struct dentry				*max_ftes;
	struct dentry				*num_ftes;
	struct dentry				*id;
	struct dentry				*ftes;
	struct fs_debugfs_mask			mask;
};

struct fs_debugfs_node {
	struct dentry		*dir;
	struct dentry		*type;
	struct dentry           *refcount;
};

struct fs_debugfs_prio {
	struct dentry		*prio;
	struct dentry		*ns;
	struct dentry		*fts;
};

struct fs_debugfs_dst {
	struct dentry *type;
	union {
		struct dentry *tir;
		struct dentry *ft;
	};
};

struct fs_debugfs_fte {
	struct dentry				*index;
	struct dentry				*action;
	struct dentry				*flow_tag;
	struct dentry				*dests_size;
	struct dentry				*dests;
	struct fs_debugfs_match_criteria	match_criteria;
};

struct fs_debugfs_ft {
	struct dentry		*max_fte;
	struct dentry		*level;
	struct dentry		*id;
	struct {
		struct dentry	*dir;
		struct dentry	*required_groups;
		struct dentry	*num_groups;
	} autogroup;
	struct dentry		*fgs;
};

struct fs_debugfs_ns {
	struct dentry		*prios;
};

/* debugfs API */
void fs_debugfs_remove(struct fs_node *node);
int fs_debugfs_add(struct fs_node *node);
void fs_debugfs_cleanup(struct mlx5_core_dev *dev);
int fs_debugfs_init(struct mlx5_core_dev *dev);

#endif
