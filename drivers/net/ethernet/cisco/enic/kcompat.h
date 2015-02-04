#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

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

#endif /* _KCOMPAT_H_ */
