#ifndef MLX4_FMR_API_H
#define MLX4_FMR_API_H

#include <linux/pci.h>

enum {
	FMR_PROTOCOL_KVM = 0,  /* default protocol */
	FMR_PROTOCOL_XEN = 1,
};

/*
 * Info that will be passed between FMR API module and mlx4_core driver
 * It is protocol specific, each protocol will add its private data.
 */
struct vpm {
	u64 va;
	u64 pa_logsz;
	u8 info[0];
};

/*
 * MASTER FMR API
 */

struct mlx4_icm_master {
	u8 protocol;		/* Xen/KVM/... */
	u8 vpm_info_size;	/* vpm size specific to current protocol */
	u8 fmr_info_size;	/* key size used by protocol during init */
	u8 log_page_size;	/* page size used by page allocation */

	/* Called by each HCA device on load */
	int (*init)(struct pci_dev *ppf, void **ppf_ctx);

	/* Called each time a new vf registers to ppf */
	int (*add_function)(void *ppf_ctx, struct pci_dev *vf, u8 *fmr_info,
			    void **vf_ctx);

	/* Called each time a vf unregisters from ppf */
	int (*del_function)(void *vf_ctx);

	/* Map pages using info from vpm and returns ctx handle */
	dma_addr_t (*dma_map)(void *vf_ctx, struct vpm *vpm,
			      void **vpm_ctx);

	/* Unmap pages based on ctx handle */
	int (*dma_unmap)(void *vpm_ctx);

	/* Called by each HCA before unload*/
	void (*term)(void *ppf_ctx);
};

/*
 * Master FMR API calls this method on load to register callbacks
 * Note: The mlx4_core is loaded but it is possible that probe pci
 *       was not yet called.
 */
int mlx4_reg_icm_master(struct mlx4_icm_master *master);

/*
 * Master FMR API calls this method before unload
 * Note: The module should keep a reference count and if
 *       is still in use the unload will not be allowed
 */
int mlx4_unreg_icm_master(struct mlx4_icm_master *master);

/*
 * SLAVE_FMR_API
 */

struct mlx4_icm_slave {
	u8 protocol;		/* Xen/KVM/... */

	/* Called by each FV on load */
	int (*init)(struct pci_dev *vf, u8 vpm_info_size, u8 fmr_info_size,
		     u8 *fmr_info, void **vf_ctx);

	/* Share pages using info from vpm and returns ctx handle */
	int (*share)(void *vf_ctx,  void *virt_addr, struct vpm *vpm_page,
		     void **vpm_ctx);

	/* Release pages based on ctx handle */
	int (*unshare)(void *vpm_ctx);

	/* Called by each VF before unload*/
	void (*term)(void *vf_ctx);
};

/*
 * Slave FMR API calls this method on load to register callbacks
 * Note: The mlx4_core is loaded but it is possible that probe pci
 *       was not yet called.
 */
int mlx4_reg_icm_slave(struct mlx4_icm_slave *slave);

/*
 * Slave FMR API calls this method before unload
 * Note: The module should keep a reference count and if
 *       is still in use the unload will not be allowed
 */
int mlx4_unreg_icm_slave(struct mlx4_icm_slave *slave);

#endif /* MLX4_FMR_API_H */
