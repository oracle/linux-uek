#ifndef _RDS_RDS_SINGLE_H
#define _RDS_RDS_SINGLE_H

#define	c_xmit_rm		c_path[0].cp_xmit_rm
#define	c_xmit_sg		c_path[0].cp_xmit_sg
#define	c_xmit_hdr_off		c_path[0].cp_xmit_hdr_off
#define	c_xmit_data_off		c_path[0].cp_xmit_data_off
#define	c_xmit_atomic_sent	c_path[0].cp_xmit_atomic_sent
#define	c_xmit_rdma_sent	c_path[0].cp_xmit_rdma_sent
#define	c_xmit_data_sent	c_path[0].cp_xmit_data_sent
#define	c_lock			c_path[0].cp_lock
#define c_next_tx_seq		c_path[0].cp_next_tx_seq
#define c_send_queue		c_path[0].cp_send_queue
#define c_retrans		c_path[0].cp_retrans
#define c_next_rx_seq		c_path[0].cp_next_rx_seq
#define c_transport_data	c_path[0].cp_transport_data
#define c_state			c_path[0].cp_state
#define c_send_gen		c_path[0].cp_send_gen
#define c_flags			c_path[0].cp_flags
#define c_reconnect_jiffies	c_path[0].cp_reconnect_jiffies
#define c_send_w		c_path[0].cp_send_w
#define c_recv_w		c_path[0].cp_recv_w
#define c_conn_w		c_path[0].cp_conn_w
#define c_down_w		c_path[0].cp_down_w
#define c_cm_lock		c_path[0].cp_cm_lock
#define c_waitq			c_path[0].cp_waitq
#define c_unacked_packets	c_path[0].cp_unacked_packets
#define c_unacked_bytes		c_path[0].cp_unacked_bytes
#define c_route			c_path[0].cp_route_resolved
#define c_drop_source		c_path[0].cp_drop_source
#define c_acl_init		c_path[0].cp_acl_init
#define c_connection_start	c_path[0].cp_connection_start
#define c_reconnect_racing	c_path[0].cp_reconnect_racing
#define c_to_index		c_path[0].cp_to_index
#define c_acl_en		c_path[0].cp_acl_en
#define c_reconnect_err		c_path[0].cp_reconnect_err

#endif /* _RDS_RDS_SINGLE_H */
