#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 00))
#define NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#define enic_vlan_rx_add_vid(a, b, c) enic_vlan_rx_add_vid(a, c)
#define enic_vlan_rx_kill_vid(a, b, c) enic_vlan_rx_kill_vid(a, c)
#define __vlan_hwaccel_put_tag(a, b, c) __vlan_hwaccel_put_tag(a, c)
#endif /* kernel < 3.9 */

#ifndef CONFIG_NET_RX_BUSY_POLL
#define napi_hash_del(napi) do {} while(0)
#define napi_hash_add(napi) do {} while(0)
#define skb_mark_napi_id(skb, napi) do {} while(0)
#endif /*CONFIG_NET_RX_BUSY_POLL*/

#define NAPI_POLL_WEIGHT 64
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 00))
static inline void *pci_zalloc_consistent(struct pci_dev *hwdev, size_t size,
					  dma_addr_t *dma_handle)
{
	void *data;

	data = pci_alloc_consistent(hwdev, size, dma_handle);
	if (!data)
		return NULL;
	memset(data, 0, sizeof(struct vnic_devcmd_fw_info));

	return data;
}

#define skb_vlan_tag_present(skb) vlan_tx_tag_present(skb)
#define skb_vlan_tag_get(skb) vlan_tx_tag_get(skb)
#endif /* kernel < 3.18 */

#endif /* _KCOMPAT_H_ */
