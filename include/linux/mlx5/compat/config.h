/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* if configfs_item_operations drop_link returns int */
#define CONFIGFS_DROP_LINK_RETURNS_INT 1

/* argument 3 of config_group_init_type_name should const */
/* #undef CONFIG_GROUP_INIT_TYPE_NAME_PARAM_3_IS_CONST */

/* __alloc_pages_node is defined */
/* #undef HAS_ALLOC_PAGES_NODE */

/* __GFP_DIRECT_RECLAIM is defined */
/* #undef HAS_GFP_DIRECT_RECLAIM */

/* __vlan_hwaccel_put_tag has 3 parameters */
#define HAVE_3_PARAMS_FOR_VLAN_HWACCEL_PUT_TAG 1

/* addrconf_addr_eui48 is defined */
/* #undef HAVE_ADDRCONF_ADDR_EUI48 */

/* addrconf_ifid_eui48 is defined */
/* #undef HAVE_ADDRCONF_IFID_EUI48 */

/* alloc_etherdev_mq is defined */
#define HAVE_ALLOC_ETHERDEV_MQ 1

/* alloc_netdev_mqs has 5 params */
/* #undef HAVE_ALLOC_NETDEV_MQS_5_PARAMS */

/* alloc_netdev_mq has 4 params */
/* #undef HAVE_ALLOC_NETDEV_MQ_4_PARAMS */

/* alloc_workqueue is defined */
#define HAVE_ALLOC_WORKQUEUE 1

/* atomic_fetch_add_unless is defined */
/* #undef HAVE_ATOMIC_FETCH_ADD_UNLESS */

/* attr_is_visible returns umode_t */
#define HAVE_ATTR_IS_VISIBLE_RET_UMODE_T 1

/* bdev_write_zeroes_sectors is defined */
/* #undef HAVE_BDEV_WRITE_ZEROES_SECTORS */

/* struct bio has member bi_disk */
/* #undef HAVE_BIO_BI_DISK */

/* linux/bio.h bio_endio has 1 parameter */
/* #undef HAVE_BIO_ENDIO_1_PARAM */

/* bio.h bio_init has 3 parameters */
/* #undef HAVE_BIO_INIT_3_PARAMS */

/* bio_integrity_payload has members bip_iter */
/* #undef HAVE_BIO_INTEGRITY_PYLD_BIP_ITER */

/* blist_flags_t is defined */
/* #undef HAVE_BLIST_FLAGS_T */

/* __blkdev_issue_zeroout exist */
/* #undef HAVE_BLKDEV_ISSUE_ZEROOUT */

/* REQ_TYPE_DRV_PRIV is defined */
#define HAVE_BLKDEV_REQ_TYPE_DRV_PRIV 1

/* blkdev.h blk_add_request_payload has 4 parameters */
#define HAVE_BLK_ADD_REQUEST_PAYLOAD_HAS_4_PARAMS 1

/* blk_alloc_queue_node has 3 args */
/* #undef HAVE_BLK_ALLOC_QUEUE_NODE_3_ARGS */

/* BLK_EH_DONE is defined */
/* #undef HAVE_BLK_EH_DONE */

/* blk_freeze_queue_start is defined */
/* #undef HAVE_BLK_FREEZE_QUEUE_START */

/* blk_init_request_from_bio is defined */
/* #undef HAVE_BLK_INIT_REQUEST_FROM_BIO */

/* BLK_INTEGRITY_DEVICE_CAPABLE is defined */
#define HAVE_BLK_INTEGRITY_DEVICE_CAPABLE 1

/* BLK_MAX_WRITE_HINTS is defined */
/* #undef HAVE_BLK_MAX_WRITE_HINTS */

/* linux/blk-mq.h blk_mq_alloc_request has 3 parameters */
/* #undef HAVE_BLK_MQ_ALLOC_REQUEST_HAS_3_PARAMS */

/* linux/blk-mq.h has blk_mq_alloc_request_hctx */
/* #undef HAVE_BLK_MQ_ALLOC_REQUEST_HCTX */

/* blk_mq_all_tag_busy_iter is defined */
#define HAVE_BLK_MQ_ALL_TAG_BUSY_ITER 1

/* linux/blk-mq.h blk_mq_complete_request has 2 parameters */
#define HAVE_BLK_MQ_COMPLETE_REQUEST_HAS_2_PARAMS 1

/* blk_mq_end_request accepts blk_status_t as second parameter */
#define HAVE_BLK_MQ_END_REQUEST_TAKES_BLK_STATUS_T 1

/* blk_mq_freeze_queue_wait is defined */
#define HAVE_BLK_MQ_FREEZE_QUEUE_WAIT 1

/* blk_mq_freeze_queue_wait_timeout is defined */
#define HAVE_BLK_MQ_FREEZE_QUEUE_WAIT_TIMEOUT 1

/* BLK_MQ_F_NO_SCHED is defined */
/* #undef HAVE_BLK_MQ_F_NO_SCHED */

/* blk_mq_map_queues is defined */
/* #undef HAVE_BLK_MQ_MAP_QUEUES */

/* linux/blk-mq.h blk_mq_ops exit_request has 3 parameters */
/* #undef HAVE_BLK_MQ_OPS_EXIT_REQUEST_HAS_3_PARAMS */

/* linux/blk-mq.h blk_mq_ops init_request has 4 parameters */
/* #undef HAVE_BLK_MQ_OPS_INIT_REQUEST_HAS_4_PARAMS */

/* struct blk_mq_ops has map_queue */
#define HAVE_BLK_MQ_OPS_MAP_QUEUE 1

/* struct blk_mq_ops has map_queues */
/* #undef HAVE_BLK_MQ_OPS_MAP_QUEUES */

/* struct blk_mq_ops has poll */
/* #undef HAVE_BLK_MQ_OPS_POLL */

/* include/linux/blk-mq-pci.h exists */
/* #undef HAVE_BLK_MQ_PCI_H */

/* blk_mq_pci_map_queues is defined */
/* #undef HAVE_BLK_MQ_PCI_MAP_QUEUES_3_ARGS */

/* blk_mq_poll exist */
/* #undef HAVE_BLK_MQ_POLL */

/* blk_mq_quiesce_queue exist */
/* #undef HAVE_BLK_MQ_QUIESCE_QUEUE */

/* blk-mq.h blk_mq_requeue_request has 2 parameters */
/* #undef HAVE_BLK_MQ_REQUEUE_REQUEST_2_PARAMS */

/* blk_mq_req_flags_t is defined */
/* #undef HAVE_BLK_MQ_REQ_FLAGS_T */

/* blk_mq_tagset_busy_iter is defined */
#define HAVE_BLK_MQ_TAGSET_BUSY_ITER 1

/* blk_mq_tag_set member ops is const */
#define HAVE_BLK_MQ_TAG_SET_HAS_CONST_POS 1

/* blk_mq_unique_tag exist */
#define HAVE_BLK_MQ_UNIQUE_TAG 1

/* blk_mq_unquiesce_queue is defined */
/* #undef HAVE_BLK_MQ_UNQUIESCE_QUEUE */

/* blk_mq_update_nr_hw_queues is defined */
#define HAVE_BLK_MQ_UPDATE_NR_HW_QUEUES 1

/* blk_path_error is defined */
/* #undef HAVE_BLK_PATH_ERROR */

/* blk_poll exist */
/* #undef HAVE_BLK_POLL */

/* blk_queue_flag_set is defined */
/* #undef HAVE_BLK_QUEUE_FLAG_SET */

/* blk_queue_max_write_zeroes_sectors is defined */
/* #undef HAVE_BLK_QUEUE_MAX_WRITE_ZEROES_SECTORS */

/* blk_queue_virt_boundary exist */
#define HAVE_BLK_QUEUE_VIRT_BOUNDARY 1

/* blkdev.h has blk_queue_write_cache */
#define HAVE_BLK_QUEUE_WRITE_CACHE 1

/* blk_rq_is_passthrough is defined */
/* #undef HAVE_BLK_RQ_IS_PASSTHROUGH */

/* blk_rq_nr_discard_segments is defined */
/* #undef HAVE_BLK_RQ_NR_DISCARD_SEGMENTS */

/* blk_rq_payload_bytes exist */
/* #undef HAVE_BLK_RQ_NR_PAYLOAD_BYTES */

/* blk_rq_nr_phys_segments exist */
/* #undef HAVE_BLK_RQ_NR_PHYS_SEGMENTS */

/* blk_status_t is defined */
#define HAVE_BLK_STATUS_T 1

/* REQ_DRV is defined */
/* #undef HAVE_BLK_TYPES_REQ_DRV */

/* REQ_INTEGRITY is defined */
#define HAVE_BLK_TYPES_REQ_INTEGRITY 1

/* REQ_OP_DISCARD is defined */
/* #undef HAVE_BLK_TYPES_REQ_OP_DISCARD */

/* REQ_OP_DRV_OUT is defined */
/* #undef HAVE_BLK_TYPES_REQ_OP_DRV_OUT */

/* REQ_OP_FLUSH is defined */
/* #undef HAVE_BLK_TYPES_REQ_OP_FLUSH */

/* include/net/bonding.h exists */
#define HAVE_BONDING_H 1

/* bpf_prog_aux has feild id */
/* #undef HAVE_BPF_PROG_AUX_FEILD_ID */

/* bpf_prog_inc is exported by the kernel */
/* #undef HAVE_BPF_PROG_INC_EXPORTED */

/* netdev_bpf has prog_attached */
/* #undef HAVE_BPF_PROG_PROG_ATTACHED */

/* bpf_prog_sub is defined */
/* #undef HAVE_BPF_PROG_SUB */

/* build_skb is defined */
#define HAVE_BUILD_SKB 1

/* linux/cdev.h has cdev_set_parent */
/* #undef HAVE_CDEV_SET_PARENT */

/* linux/cgroup_rdma exists */
/* #undef HAVE_CGROUP_RDMA_H */

/* class_attribute namespace is defined */
/* #undef HAVE_CLASS_ATTRIBUTE_NAMESPACE */

/* CLASS_ATTR_STRING is defined */
#define HAVE_CLASS_ATTR_STRING 1

/* class devnode gets umode_t */
#define HAVE_CLASS_DEVNODE_UMODE_T 1

/* linux/srcu.h cleanup_srcu_struct_quiesced is defined */
/* #undef HAVE_CLEANUP_SRCU_STRUCT_QUIESCED */

/* switch_to.h has clear_thread_tidr */
/* #undef HAVE_CLEAR_THREAD_TIDR */

/* cycle_t is defined in linux/clocksource.h */
#define HAVE_CLOCKSOURCE_CYCLE_T 1

/* default_groups is list_head */
/* #undef HAVE_CONFIGFS_DEFAULT_GROUPS_LIST */

/* const __read_once_size exist */
#define HAVE_CONST_READ_ONCE_SIZE 1

/* cyclecounter_cyc2ns has 4 parameters */
#define HAVE_CYCLECOUNTER_CYC2NS_4_PARAMS 1

/* struct dcbnl_rtnl_ops has dcbnl_get/set buffer */
/* #undef HAVE_DCBNL_GETBUFFER */

/* struct dcbnl_rtnl_ops_ext is defined */
/* #undef HAVE_DCBNL_RTNL_OPS_EXTENDED */

/* getnumtcs returns int */
#define HAVE_DCBNL_RTNL_OPS_GETNUMTCS_RET_INT 1

/* genhd.h has device_add_disk */
/* #undef HAVE_DEVICE_ADD_DISK */

/* struct device has dma_ops */
/* #undef HAVE_DEVICE_DMA_OPS */

/* device.h has device_remove_file_self */
#define HAVE_DEVICE_REMOVE_FILE_SELF 1

/* include/net/devlink.h exists */
/* #undef HAVE_DEVLINK_H */

/* eswitch_encap_mode_set/get is defined */
/* #undef HAVE_DEVLINK_HAS_ESWITCH_ENCAP_MODE_SET */

/* eswitch_inline_mode_get/set is defined */
/* #undef HAVE_DEVLINK_HAS_ESWITCH_INLINE_MODE_GET_SET */

/* eswitch_mode_get/set is defined */
/* #undef HAVE_DEVLINK_HAS_ESWITCH_MODE_GET_SET */

/* dev_alloc_page is defined */
#define HAVE_DEV_ALLOC_PAGE 1

/* dev_alloc_pages is defined */
#define HAVE_DEV_ALLOC_PAGES 1

/* dev_mc_add has 2 parameters */
#define HAVE_DEV_MC_ADD_2_PARAMS 1

/* dev_mc_del is defined */
#define HAVE_DEV_MC_DEL 1

/* set_latency_tolerance is defined */
#define HAVE_DEV_PM_INFO_SET_LATENCY_TOLERANCE 1

/* DEV_PM_QOS_LATENCY_TOLERANCE is defined */
#define HAVE_DEV_PM_QOS_LATENCY_TOLERANCE 1

/* DEV_PM_QOS_RESUME_LATENCY is defined */
#define HAVE_DEV_PM_QOS_RESUME_LATENCY 1

/* dev_uc_del is defined */
#define HAVE_DEV_UC_DEL 1

/* DMA_ATTR_NO_WARN is defined */
/* #undef HAVE_DMA_ATTR_NO_WARN */

/* dma_pool_zalloc is defined */
/* #undef HAVE_DMA_POOL_ZALLOC */

/* dma_alloc_attrs takes unsigned long attrs */
/* #undef HAVE_DMA_SET_ATTR_TAKES_UNSIGNED_LONG_ATTRS */

/* dst_get_neighbour is defined */
/* #undef HAVE_DST_GET_NEIGHBOUR */

/* dst_neigh_lookup is defined */
#define HAVE_DST_NEIGH_LOOKUP 1

/* elfcorehdr_addr is exported by the kernel */
#define HAVE_ELFCOREHDR_ADDR_EXPORTED 1

/* enum scsi_scan_mode is defined */
/* #undef HAVE_ENUM_SCSI_SCAN_MODE */

/* ether_addr_copy is defined */
#define HAVE_ETHER_ADDR_COPY 1

/* struct ethtool_flow_ext is defined */
#define HAVE_ETHTOOL_FLOW_EXT 1

/* ethtool_flow_ext has h_dest */
#define HAVE_ETHTOOL_FLOW_EXT_H_DEST 1

/* union ethtool_flow_union is defined */
#define HAVE_ETHTOOL_FLOW_UNION 1

/* struct ethtool_ops_ext is defined */
/* #undef HAVE_ETHTOOL_OPS_EXT */

/* ethtool_ops get_rxnfc gets u32 *rule_locs */
#define HAVE_ETHTOOL_OPS_GET_RXNFC_U32_RULE_LOCS 1

/* ETHTOOL_xLINKSETTINGS API is defined */
/* #undef HAVE_ETHTOOL_xLINKSETTINGS */

/* eth_get_headlen is defined */
#define HAVE_ETH_GET_HEADLEN 1

/* ETH_MIN_MTU exists */
/* #undef HAVE_ETH_MIN_MTU */

/* ETH_P_8021AD exists */
#define HAVE_ETH_P_8021AD 1

/* ETH_P_IBOE exists */
/* #undef HAVE_ETH_P_IBOE */

/* eth_random_addr is defined */
#define HAVE_ETH_RANDOM_ADDR 1

/* ETH_SS_RSS_HASH_FUNCS is defined */
#define HAVE_ETH_SS_RSS_HASH_FUNCS 1

/* fdget is defined */
#define HAVE_FDGET 1

/* fib_lookup has 4 params */
/* #undef HAVE_FIB_LOOKUP_4_PARAMS */

/* fib_lookup is exported by the kernel */
/* #undef HAVE_FIB_LOOKUP_EXPORTED */

/* fib_res_put */
/* #undef HAVE_FIB_RES_PUT */

/* flowi4, flowi6 is defined */
#define HAVE_FLOWI_AF_SPECIFIC_INSTANCES 1

/* FLOW_DISSECTOR_KEY_IP is defined */
/* #undef HAVE_FLOW_DISSECTOR_KEY_IP */

/* FLOW_DISSECTOR_KEY_TCP is defined */
/* #undef HAVE_FLOW_DISSECTOR_KEY_TCP */

/* FLOW_DISSECTOR_KEY_VLAN is defined */
/* #undef HAVE_FLOW_DISSECTOR_KEY_VLAN */

/* struct kiocb is defined in linux/fs.h */
#define HAVE_FS_HAS_KIOCB 1

/* HAVE_GET_MODULE_EEPROM is defined */
#define HAVE_GET_MODULE_EEPROM 1

/* HAVE_GET_MODULE_EEPROM_EXT is defined */
/* #undef HAVE_GET_MODULE_EEPROM_EXT */

/* get_pid_task is exported by the kernel */
#define HAVE_GET_PID_TASK_EXPORTED 1

/* get/set_channels is defined */
#define HAVE_GET_SET_CHANNELS 1

/* get/set_channels is defined in ethtool_ops_ext */
/* #undef HAVE_GET_SET_CHANNELS_EXT */

/* HAVE_GET_SET_DUMP is defined */
#define HAVE_GET_SET_DUMP 1

/* get/set_flags is defined */
/* #undef HAVE_GET_SET_FLAGS */

/* get/set_link_ksettings is defined */
/* #undef HAVE_GET_SET_LINK_KSETTINGS */

/* get/set_msglevel is defined */
#define HAVE_GET_SET_MSGLEVEL 1

/* get/set_priv_flags is defined */
#define HAVE_GET_SET_PRIV_FLAGS 1

/* get/set_rxfh is defined */
#define HAVE_GET_SET_RXFH 1

/* get/set_rxfh_indir is defined */
/* #undef HAVE_GET_SET_RXFH_INDIR */

/* get/set_rxfh_indir is defined */
/* #undef HAVE_GET_SET_RXFH_INDIR_EXT */

/* get/set_rx_csum is defined */
/* #undef HAVE_GET_SET_RX_CSUM */

/* get/set_sg is defined */
/* #undef HAVE_GET_SET_SG */

/* get/set_tso is defined */
/* #undef HAVE_GET_SET_TSO */

/* get/set_tunable is defined */
#define HAVE_GET_SET_TUNABLE 1

/* get/set_tx_csum is defined */
/* #undef HAVE_GET_SET_TX_CSUM */

/* get_task_comm is exported by the kernel */
#define HAVE_GET_TASK_COMM_EXPORTED 1

/* get_task_pid is exported by the kernel */
#define HAVE_GET_TASK_PID_EXPORTED 1

/* get_ts_info is defined */
#define HAVE_GET_TS_INFO 1

/* get_ts_info is defined in ethtool_ops_ext */
/* #undef HAVE_GET_TS_INFO_EXT */

/* GET_UNUSED_FD_FLAGS is defined */
#define HAVE_GET_UNUSED_FD_FLAGS 1

/* get_user_pages has 8 params */
#define HAVE_GET_USER_PAGES_8_PARAMS 1

/* get_user_pages uses gup_flags */
/* #undef HAVE_GET_USER_PAGES_GUP_FLAGS */

/* get_user_pages_longterm is defined */
/* #undef HAVE_GET_USER_PAGES_LONGTERM */

/* get_user_pages_remote is defined with 7 parameters */
/* #undef HAVE_GET_USER_PAGES_REMOTE_7_PARAMS */

/* get_user_pages_remote is defined with 8 parameters */
/* #undef HAVE_GET_USER_PAGES_REMOTE_8_PARAMS */

/* get_user_pages_remote is defined with 8 parameters with locked */
/* #undef HAVE_GET_USER_PAGES_REMOTE_8_PARAMS_W_LOCKED */

/* hex2bin return value exists */
#define HAVE_HEX2BIN_NOT_VOID 1

/* hlist_for_each_entry has 3 params */
#define HAVE_HLIST_FOR_EACH_ENTRY_3_PARAMS 1

/* HWTSTAMP_FILTER_NTP_ALL is defined */
/* #undef HAVE_HWTSTAMP_FILTER_NTP_ALL */

/* icmpv6_send has 4 parameters */
#define HAVE_ICMPV6_SEND_4_PARAMS 1

/* ida_is_empty is defined */
/* #undef HAVE_IDA_IS_EMPTY */

/* ida_simple_get is defined */
#define HAVE_IDA_SIMPLE_GET 1

/* idr_alloc is defined */
#define HAVE_IDR_ALLOC 1

/* idr_alloc_cyclic is defined */
#define HAVE_IDR_ALLOC_CYCLIC 1

/* idr_is_empty is defined */
#define HAVE_IDR_IS_EMPTY 1

/* ieee_getets/ieee_setets is defined and dcbnl defined */
#define HAVE_IEEE_DCBNL_ETS 1

/* ieee_getqcn is defined */
#define HAVE_IEEE_GETQCN 1

/* ieee_getmaxrate/ieee_setmaxrate is defined */
#define HAVE_IEEE_GET_SET_MAXRATE 1

/* trust is defined */
/* #undef HAVE_IFLA_VF_IB_NODE_PORT_GUID */

/* struct ifla_vf_info is defined */
#define HAVE_IFLA_VF_INFO 1

/* struct ifla_vf_stats is defined */
/* #undef HAVE_IFLA_VF_STATS */

/* if_list is defined */
#define HAVE_INET6_IF_LIST 1

/* inet_addr_is_any is defined */
/* #undef HAVE_INET_ADDR_IS_ANY */

/* inet_confirm_addr has 5 parameters */
#define HAVE_INET_CONFIRM_ADDR_5_PARAMS 1

/* inet_confirm_addr is exported by the kernel */
#define HAVE_INET_CONFIRM_ADDR_EXPORTED 1

/* inet_get_local_port_range has 3 parameters */
#define HAVE_INET_GET_LOCAL_PORT_RANGE_3_PARAMS 1

/* include/linux/inet_lro.h exists */
#define HAVE_INET_LRO_H 1

/* inet_pton_with_scope is defined */
/* #undef HAVE_INET_PTON_WITH_SCOPE */

/* include/linux/interval_tree_generic.h exists */
#define HAVE_INTERVAL_TREE_GENERIC_H 1

/* INTERVAL_TREE takes rb_root */
#define HAVE_INTERVAL_TREE_TAKES_RB_ROOT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* invalidate_page defined */
#define HAVE_INVALIDATE_PAGE 1

/* linux/io-64-nonatomic-lo-hi.h exists */
/* #undef HAVE_IO_64_NONATOMIC_LO_HI_H */

/* io_mapping_map_wc has 3 params */
/* #undef HAVE_IO_MAPPING_MAP_WC_3_PARAMS */

/* ip4_dst_hoplimit is defined */
#define HAVE_IP4_DST_HOPLIMIT 1

/* ip6_dst_hoplimit is exported by the kernel */
#define HAVE_IP6_DST_HOPLIMIT 1

/* ip6_rt_put is defined */
#define HAVE_IP6_RT_PUT 1

/* ipv6_addr_copy is defined */
/* #undef HAVE_IPV6_ADDR_COPY */

/* ipv6_chk_addr accepts a const second parameter */
#define HAVE_IPV6_CHK_ADDR_TAKES_CONST 1

/* ipv6_dst_lookup takes net */
/* #undef HAVE_IPV6_DST_LOOKUP_TAKES_NET */

/* ipv6_stub is defined */
#define HAVE_IPV6_STUB 1

/* struct ip_tunnel_info is defined */
/* #undef HAVE_IP_TUNNEL_INFO */

/* irq_calc_affinity_vectors is defined */
/* #undef HAVE_IRQ_CALC_AFFINITY_VECTORS_3_ARGS */

/* irq_data member affinity is defined */
#define HAVE_IRQ_DATA_AFFINITY 1

/* irq_desc_get_irq_data is defined */
#define HAVE_IRQ_DESC_GET_IRQ_DATA 1

/* include/linux/irq_poll.h exists */
/* #undef HAVE_IRQ_POLL_H */

/* irq_set_affinity_hint is defined */
#define HAVE_IRQ_SET_AFFINITY_HINT 1

/* irq_to_desc is exported by the kernel */
#define HAVE_IRQ_TO_DESC_EXPORTED 1

/* iscsit_find_cmd_from_itt is defined */
#define HAVE_ISCSIT_FIND_CMD_FROM_ITT 1

/* iscsit_transport has member iscsit_get_sup_prot_ops */
#define HAVE_ISCSIT_TRANSPORT_HAS_GET_SUP_PROT_OPS 1

/* iscsit_get_rx_pdu is defined */
/* #undef HAVE_ISCSIT_TRANSPORT_ISCSIT_GET_RX_PDU */

/* rdma_shutdown is defined */
/* #undef HAVE_ISCSIT_TRANSPORT_RDMA_SHUTDOWN */

/* attr_is_visible is defined */
#define HAVE_ISCSI_ATTR_IS_VISIBLE 1

/* iscsi_proto.h has structure iscsi_cmd */
/* #undef HAVE_ISCSI_CMD */

/* iscsi_conn has members local_sockaddr */
/* #undef HAVE_ISCSI_CONN_LOCAL_SOCKADDR */

/* iscsi_conn has member login_sockaddr */
/* #undef HAVE_ISCSI_CONN_LOGIN_SOCKADDR */

/* struct iscsi_session has discovery_sess */
#define HAVE_ISCSI_DISCOVERY_SESSION 1

/* iscsi_eh_cmd_timed_out is defined */
/* #undef HAVE_ISCSI_EH_CMD_TIMED_OUT */

/* get_ep_param is defined */
#define HAVE_ISCSI_GET_EP_PARAM 1

/* iscsi_target_core.h and iscsi_target_stat.h are under include/ */
#define HAVE_ISCSI_TARGET_CORE_ISCSI_TARGET_STAT_H 1

/* check_protection is defined */
#define HAVE_ISCSI_TRANSPORT_CHECK_PROTECTION 1

/* is_tcf_gact_shot is defined */
/* #undef HAVE_IS_TCF_GACT_SHOT */

/* is_tcf_mirred_egress_mirror is defined */
/* #undef HAVE_IS_TCF_MIRRED_EGRESS_MIRROR */

/* is_tcf_mirred_egress_redirect is defined */
/* #undef HAVE_IS_TCF_MIRRED_EGRESS_REDIRECT */

/* is_tcf_mirred_mirror is defined */
/* #undef HAVE_IS_TCF_MIRRED_MIRROR */

/* is_tcf_mirred_redirect is defined */
/* #undef HAVE_IS_TCF_MIRRED_REDIRECT */

/* is_tcf_skbedit_mark is defined */
/* #undef HAVE_IS_TCF_SKBEDIT_MARK */

/* is_tcf_vlan is defined */
/* #undef HAVE_IS_TCF_VLAN */

/* is_vlan_dev is defined */
#define HAVE_IS_VLAN_DEV 1

/* is_vlan_dev get const */
/* #undef HAVE_IS_VLAN_DEV_CONST */

/* kcalloc_node is defined */
/* #undef HAVE_KCALLOC_NODE */

/* kfree_const is defined */
#define HAVE_KFREE_CONST 1

/* kmalloc_array is defined */
#define HAVE_KMALLOC_ARRAY 1

/* kmalloc_array_node is defined */
/* #undef HAVE_KMALLOC_ARRAY_NODE */

/* highmem.h has kmap_atomic function with km_type */
/* #undef HAVE_KM_TYPE */

/* kobj_ns_grab_current is exported by the kernel */
/* #undef HAVE_KOBJ_NS_GRAB_CURRENT_EXPORTED */

/* kref_get_unless_zero is defined */
#define HAVE_KREF_GET_UNLESS_ZERO 1

/* kref_read is defined */
/* #undef HAVE_KREF_READ */

/* kstrtobool is defined */
/* #undef HAVE_KSTRTOBOOL */

/* kthread_queue_work is defined */
/* #undef HAVE_KTHREAD_QUEUE_WORK */

/* struct kthread_work is defined */
#define HAVE_KTHREAD_WORK 1

/* ktime_get_boot_ns is defined */
#define HAVE_KTIME_GET_BOOT_NS 1

/* ktime_get_ns defined */
/* #define HAVE_KTIME_GET_NS 1  */

/* ktime_get_real_ns is defined */
#define HAVE_KTIME_GET_REAL_NS 1

/* kvcalloc is defined */
/* #undef HAVE_KVCALLOC */

/* kvmalloc is defined */
#define HAVE_KVMALLOC 1

/* kvmalloc_array is defined */
/* #undef HAVE_KVMALLOC_ARRAY */

/* kvmalloc_node is defined */
#define HAVE_KVMALLOC_NODE 1

/* kvzalloc is defined */
#define HAVE_KVZALLOC 1

/* kvzalloc_node is defined */
#define HAVE_KVZALLOC_NODE 1

/* enum netdev_lag_tx_type is defined */
#define HAVE_LAG_TX_TYPE 1

/* linux/lightnvm.h exists */
/* #undef HAVE_LIGHTNVM_H */

/* linkstate is defined */
#define HAVE_LINKSTATE 1

/* uapi/bpf.h exists */
#define HAVE_LINUX_BPF_H 1

/* linux/bpf_trace exists */
/* #undef HAVE_LINUX_BPF_TRACE_H */

/* linux/hashtable.h exists */
#define HAVE_LINUX_HASHTABLE_H 1

/* linux/nvme-fc-driver.h exists */
/* #undef HAVE_LINUX_NVME_FC_DRIVER_H */

/* linux/overflow.h is defined */
/* #undef HAVE_LINUX_OVERFLOW_H */

/* linux/printk.h is defined */
#define HAVE_LINUX_PRINTK_H 1

/* linux/sed-opal.h exists */
/* #undef HAVE_LINUX_SED_OPAL_H */

/* linux/xz.h exists */
#define HAVE_LINUX_XZ_H 1

/* memalloc_noio_save is defined */
/* #undef HAVE_MEMALLOC_NOIO_SAVE */

/* memchr_inv is defined */
#define HAVE_MEMCHR_INV 1

/* memcpy_and_pad is defined */
/* #undef HAVE_MEMCPY_AND_PAD */

/* memdup_user_nul is defined */
/* #undef HAVE_MEMDUP_USER_NUL */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* mm_context_add_copro is defined */
/* #undef HAVE_MM_CONTEXT_ADD_COPRO */

/* struct page has _count */
#define HAVE_MM_PAGE__COUNT 1

/* mm_types.h struct mm_struct has free_area_cache */
/* #undef HAVE_MM_STRUCT_FREE_AREA_CACHE */

/* moduleparam.h has kernel_param_ops */
#define HAVE_MODULEPARAM_KERNEL_PARAM_OPS 1

/* napi_alloc_skb is defined */
#define HAVE_NAPI_ALLOC_SKB 1

/* napi_complete_done is defined */
#define HAVE_NAPI_COMPLETE_DONE 1

/* napi_consume_skb is defined */
/* #undef HAVE_NAPI_CONSUME_SKB */

/* napi_schedule_irqoff is defined */
#define HAVE_NAPI_SCHEDULE_IRQOFF 1

/* NAPI_STATE_MISSED is defined */
/* #undef HAVE_NAPI_STATE_MISSED */

/* ndo_add_slave is defined */
#define HAVE_NDO_ADD_SLAVE 1

/* ndo_add_vxlan_port is defined */
#define HAVE_NDO_ADD_VXLAN_PORT 1

/* ndo_busy_poll is defined */
#define HAVE_NDO_BUSY_POLL 1

/* extended ndo_change_mtu is defined */
/* #undef HAVE_NDO_CHANGE_MTU_EXTENDED */

/* extended ndo_change_mtu_rh74 is defined */
/* #undef HAVE_NDO_CHANGE_MTU_RH74 */

/* ndo_fix_features is defined */
#define HAVE_NDO_FIX_FEATURES 1

/* ndo_get_iflink is defined */
#define HAVE_NDO_GET_IFLINK 1

/* ndo_get_offload_stats is defined */
/* #undef HAVE_NDO_GET_OFFLOAD_STATS */

/* extended ndo_get_offload_stats is defined */
/* #undef HAVE_NDO_GET_OFFLOAD_STATS_EXTENDED */

/* ndo_get_phys_port_name is defined */
#define HAVE_NDO_GET_PHYS_PORT_NAME 1

/* is defined */
/* #undef HAVE_NDO_GET_PHYS_PORT_NAME_EXTENDED */

/* ndo_get_stats64 is defined */
#define HAVE_NDO_GET_STATS64 1

/* ndo_get_stats64 is defined and returns void */
/* #undef HAVE_NDO_GET_STATS64_RET_VOID */

/* ndo_get_vf_stats is defined */
/* #undef HAVE_NDO_GET_VF_STATS */

/* ndo_gso_check is defined */
/* #undef HAVE_NDO_GSO_CHECK */

/* ndo_has_offload_stats gets net_device */
/* #undef HAVE_NDO_HAS_OFFLOAD_STATS_EXTENDED */

/* ndo_vlan_rx_add_vid has 2 parameters and returns int */
/* #undef HAVE_NDO_RX_ADD_VID_HAS_2_PARAMS_RET_INT */

/* ndo_vlan_rx_add_vid has 3 parameters */
#define HAVE_NDO_RX_ADD_VID_HAS_3_PARAMS 1

/* ndo_rx_flow_steer is defined */
#define HAVE_NDO_RX_FLOW_STEER 1

/* ndo_setup_tc is defined */
#define HAVE_NDO_SETUP_TC 1

/* ndo_setup_tc takes 4 parameters */
/* #undef HAVE_NDO_SETUP_TC_4_PARAMS */

/* ndo_setup_tc_rh is defined */
/* #undef HAVE_NDO_SETUP_TC_RH_EXTENDED */

/* ndo_setup_tc takes chain_index */
/* #undef HAVE_NDO_SETUP_TC_TAKES_CHAIN_INDEX */

/* ndo_setup_tc takes tc_setup_type */
/* #undef HAVE_NDO_SETUP_TC_TAKES_TC_SETUP_TYPE */

/* ndo_set_features is defined */
#define HAVE_NDO_SET_FEATURES 1

/* ndo_set_tx_maxrate is defined */
#define HAVE_NDO_SET_TX_MAXRATE 1

/* extended ndo_set_tx_maxrate is defined */
/* #undef HAVE_NDO_SET_TX_MAXRATE_EXTENDED */

/* ndo_set_vf_guid is defined */
/* #undef HAVE_NDO_SET_VF_GUID */

/* ndo_set_vf_mac is defined */
#define HAVE_NDO_SET_VF_MAC 1

/* ndo_set_vf_vlan is defined in net_device_ops */
#define HAVE_NDO_SET_VF_VLAN 1

/* ndo_set_vf_vlan is defined in net_device_ops_extended */
/* #undef HAVE_NDO_SET_VF_VLAN_EXTENDED */

/* ndo_add_vxlan_port is defined */
/* #undef HAVE_NDO_UDP_TUNNEL_ADD */

/* extended ndo_add_vxlan_port is defined */
/* #undef HAVE_NDO_UDP_TUNNEL_ADD_EXTENDED */

/* extended ndo_xdp is defined */
/* #undef HAVE_NDO_XDP_EXTENDED */

/* netdev_bonding_info is defined */
#define HAVE_NETDEV_BONDING_INFO 1

/* struct netdev_bpf is defined */
/* #undef HAVE_NETDEV_BPF */

/* is defined */
/* #undef HAVE_NETDEV_EXTENDED_DEV_PORT */

/* is defined */
/* #undef HAVE_NETDEV_EXTENDED_HW_FEATURES */

/* is defined */
/* #undef HAVE_NETDEV_EXTENDED_NDO_BUSY_POLL */

/* is defined */
/* #undef HAVE_NETDEV_EXTENDED_WANTED_FEATURES */

/* ndo_get_phys_port_id is defined */
/* #undef HAVE_NETDEV_EXT_NDO_GET_PHYS_PORT_ID */

/* netdev_features_t is defined */
#define HAVE_NETDEV_FEATURES_T 1

/* netdev_master_upper_dev_get_rcu is defined */
#define HAVE_NETDEV_FOR_EACH_ALL_UPPER_DEV_RCU 1

/* netdev_for_each_mc_addr is defined */
#define HAVE_NETDEV_FOR_EACH_MC_ADDR 1

/* netdev_get_num_tc is defined */
#define HAVE_NETDEV_GET_NUM_TC 1

/* netdev_get_tx_queue is defined */
#define HAVE_NETDEV_GET_TX_QUEUE 1

/* netdev_has_upper_dev_all_rcu is defined */
/* #undef HAVE_NETDEV_HAS_UPPER_DEV_ALL_RCU */

/* hw_enc_features is defined */
#define HAVE_NETDEV_HW_ENC_FEATURES 1

/* hw_features is defined */
#define HAVE_NETDEV_HW_FEATURES 1

/* IFF_LIVE_ADDR_CHANGE is defined */
#define HAVE_NETDEV_IFF_LIVE_ADDR_CHANGE 1

/* IFF_UNICAST_FLT is defined */
#define HAVE_NETDEV_IFF_UNICAST_FLT 1

/* netdev_master_upper_dev_get is defined */
#define HAVE_NETDEV_MASTER_UPPER_DEV_GET 1

/* netdev_master_upper_dev_get_rcu is defined */
#define HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU 1

/* is defined */
/* #undef HAVE_NETDEV_NDO_GET_PHYS_PORT_ID */

/* netdev_notifier_changeupper_info is defined */
#define HAVE_NETDEV_NOTIFIER_CHANGEUPPER_INFO 1

/* struct netdev_notifier_changeupper_info has upper_info */
#define HAVE_NETDEV_NOTIFIER_CHANGEUPPER_INFO_UPPER_INFO 1

/* struct netdev_notifier_info is defined */
#define HAVE_NETDEV_NOTIFIER_INFO 1

/* netdev_notifier_info_to_dev is defined */
#define HAVE_NETDEV_NOTIFIER_INFO_TO_DEV 1

/* ndo_fix_features is defined in net_device_ops_ext */
/* #undef HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES */

/* ndo_set_features is defined in net_device_ops_ext */
/* #undef HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES */

/* ndo_set_vf_link_state is defined */
/* #undef HAVE_NETDEV_OPS_EXT_NDO_SET_VF_LINK_STATE */

/* ndo_set_vf_spoofchk is defined in net_device_ops_ext */
/* #undef HAVE_NETDEV_OPS_EXT_NDO_SET_VF_SPOOFCHK */

/* ndo_set_vf_link_state is defined in net_device_ops */
#define HAVE_NETDEV_OPS_NDO_SET_VF_LINK_STATE 1

/* ndo_set_vf_spoofchk is defined in net_device_ops */
#define HAVE_NETDEV_OPS_NDO_SET_VF_SPOOFCHK 1

/* ndo_set_vf_trust is defined in net_device_ops */
/* #undef HAVE_NETDEV_OPS_NDO_SET_VF_TRUST */

/* extended ndo_set_vf_trust is defined */
/* #undef HAVE_NETDEV_OPS_NDO_SET_VF_TRUST_EXTENDED */

/* netdev_phys_item_id is defined */
#define HAVE_NETDEV_PHYS_ITEM_ID 1

/* netdev_reg_state is defined */
#define HAVE_NETDEV_REG_STATE 1

/* netdev_reset_tc is defined */
#define HAVE_NETDEV_RESET_TC 1

/* netdev_rss_key_fill is defined */
#define HAVE_NETDEV_RSS_KEY_FILL 1

/* rx_cpu_rmap is defined */
#define HAVE_NETDEV_RX_CPU_RMAP 1

/* netdev_rx_handler_register is defined */
#define HAVE_NETDEV_RX_HANDLER_REGISTER 1

/* netdev_set_num_tc is defined */
#define HAVE_NETDEV_SET_NUM_TC 1

/* netdev_set_tc_queue is defined */
#define HAVE_NETDEV_SET_TC_QUEUE 1

/* netdev_stats_to_stats64 is defined */
#define HAVE_NETDEV_STATS_TO_STATS64 1

/* netdev_txq_bql_complete_prefetchw is defined */
#define HAVE_NETDEV_TXQ_BQL_PREFETCHW 1

/* is defined */
#define HAVE_NETDEV_UPDATE_FEATURES 1

/* netdev_walk_all_upper_dev_rcu is defined */
/* #undef HAVE_NETDEV_WALK_ALL_UPPER_DEV_RCU */

/* wanted_features is defined */
#define HAVE_NETDEV_WANTED_FEATURES 1

/* struct netdev_xdp is defined */
/* #undef HAVE_NETDEV_XDP */

/* netif_dev_get_by_index_rcu is defined */
#define HAVE_NETIF_DEV_GET_BY_INDEX_RCU 1

/* NETIF_F_GSO_GRE_CSUM is defined in netdev_features.h */
#define HAVE_NETIF_F_GSO_GRE_CSUM 1

/* NETIF_F_GSO_PARTIAL is defined in netdev_features.h */
/* #undef HAVE_NETIF_F_GSO_PARTIAL */

/* NETIF_F_GSO_UDP_TUNNEL is defined in netdev_features.h */
#define HAVE_NETIF_F_GSO_UDP_TUNNEL 1

/* NETIF_F_GSO_UDP_TUNNEL_CSUM is defined in netdev_features.h */
#define HAVE_NETIF_F_GSO_UDP_TUNNEL_CSUM 1

/* NETIF_F_HW_VLAN_STAG_RX is defined in netdev_features.h */
#define HAVE_NETIF_F_HW_VLAN_STAG_RX 1

/* NETIF_F_RXALL is defined in netdev_features.h */
#define HAVE_NETIF_F_RXALL 1

/* NETIF_F_RXFCS is defined in netdev_features.h */
#define HAVE_NETIF_F_RXFCS 1

/* NETIF_F_RXHASH is defined in netdev_features.h */
#define HAVE_NETIF_F_RXHASH 1

/* NETIF_IS_BOND_MASTER is defined in netdev_features.h */
#define HAVE_NETIF_IS_BOND_MASTER 1

/* NETIF_IS_LAG_MASTER is defined in netdevice.h */
/* #undef HAVE_NETIF_IS_LAG_MASTER */

/* NETIF_IS_LAG_PORT is defined in netdevice.h */
/* #undef HAVE_NETIF_IS_LAG_PORT */

/* netif_is_rxfh_configured is defined */
/* #undef HAVE_NETIF_IS_RXFH_CONFIGURED */

/* netif_keep_dst is defined */
#define HAVE_NETIF_KEEP_DST 1

/* netif_set_real_num_rx_queues is defined */
#define HAVE_NETIF_SET_REAL_NUM_RX_QUEUES 1

/* netif_set_real_num_tx_queues is defined */
#define HAVE_NETIF_SET_REAL_NUM_TX_QUEUES 1

/* netif_set_real_num_tx_queues return value exists */
#define HAVE_NETIF_SET_REAL_NUM_TX_QUEUES_NOT_VOID 1

/* is defined */
#define HAVE_NETIF_SET_XPS_QUEUE 1

/* netif_trans_update is defined */
/* #undef HAVE_NETIF_TRANS_UPDATE */

/* netif_tx_napi_add is defined */
/* #undef HAVE_NETIF_TX_NAPI_ADD */

/* netif_tx_queue_stopped is defined */
#define HAVE_NETIF_TX_QUEUE_STOPPED 1

/* netif_xmit_stopped is defined */
#define HAVE_NETIF_XMIT_STOPPED 1

/* netlink_capable is defined */
#define HAVE_NETLINK_CAPABLE 1

/* netlink_dump_control dump is defined */
#define HAVE_NETLINK_DUMP_CONTROL_DUMP 1

/* netlink_dump_start has 5 parameters */
/* #undef HAVE_NETLINK_DUMP_START_5P */

/* struct netlink_ext_ack is defined */
/* #undef HAVE_NETLINK_EXT_ACK */

/* netlink_kernel_cfg input is defined */
#define HAVE_NETLINK_KERNEL_CFG_INPUT 1

/* netlink_kernel_create has 3 params */
#define HAVE_NETLINK_KERNEL_CREATE_3_PARAMS 1

/* struct netlink_skb_parms has portid */
#define HAVE_NETLINK_SKB_PARMS_PORTID 1

/* netlink_skb_params has sk */
#define HAVE_NETLINK_SKB_PARMS_SK 1

/* dev_port is defined */
#define HAVE_NET_DEVICE_DEV_PORT 1

/* is defined */
/* #undef HAVE_NET_DEVICE_EXTENDED_TX_EXT */

/* net_device min/max is defined */
/* #undef HAVE_NET_DEVICE_MIN_MAX_MTU */

/* extended min/max_mtu is defined */
/* #undef HAVE_NET_DEVICE_MIN_MAX_MTU_EXTENDED */

/* net_device needs_free_netdev is defined */
/* #undef HAVE_NET_DEVICE_NEEDS_FREE_NETDEV */

/* neigh_priv_len is defined */
#define HAVE_NET_DEVICE_NEIGH_PRIV_LEN 1

/* struct net_device_ops_ext is defined */
/* #undef HAVE_NET_DEVICE_OPS_EXT */

/* struct net_device_ops_extended is defined */
/* #undef HAVE_NET_DEVICE_OPS_EXTENDED */

/* net_device real_num_rx_queues is defined */
#define HAVE_NET_DEVICE_REAL_NUM_RX_QUEUES 1

/* net/flow_keys.h exists */
#define HAVE_NET_FLOW_KEYS_H 1

/* net/page_pool.h is defined */
/* #undef HAVE_NET_PAGE_POOL_H */

/* net/tc_act/tc_mirred.h exists */
#define HAVE_NET_TC_ACT_TC_MIRRED_H 1

/* net/tc_act/tc_tunnel_key.h exists */
/* #undef HAVE_NET_TC_ACT_TC_TUNNEL_KEY_H */

/* net/xdp.h is defined */
/* #undef HAVE_NET_XDP_H */

/* alloc_etherdev_mqs, alloc_etherdev_mqs, num_tc is defined */
#define HAVE_NEW_TX_RING_SCHEME 1

/* nla_parse takes 6 parameters */
/* #undef HAVE_NLA_PARSE_6_PARAMS */

/* nla_put_u64_64bit is defined */
/* #undef HAVE_NLA_PUT_U64_64BIT */

/* NLA_S32 is defined */
#define HAVE_NLA_S32 1

/* numa_mem_id is defined */
#define HAVE_NUMA_MEM_ID 1

/* nvm_alloc_dev is exported by the kernel */
/* #undef HAVE_NVM_ALLOC_DEV_EXPORTED */

/* struct nvm_user_vio is defined */
/* #undef HAVE_NVM_USER_VIO */

/* N_MEMORY is defined */
#define HAVE_N_MEMORY 1

/* include/linux/once.h exists */
/* #undef HAVE_ONCE_H */

/* page_is_pfmemalloc is defined */
#define HAVE_PAGE_IS_PFMEMALLOC 1

/* page_ref_count/add/sub/inc defined */
/* #undef HAVE_PAGE_REF_COUNT_ADD_SUB_INC */

/* param_ops_ullong is defined */
#define HAVE_PARAM_OPS_ULLONG 1

/* pat.h has pat_enabled as a function */
/* #undef HAVE_PAT_ENABLED_AS_FUNCTION */

/* pcie_get_minimum_link is defined */
#define HAVE_PCIE_GET_MINIMUM_LINK 1

/* pcie_link_width is defined */
#define HAVE_PCIE_LINK_WIDTH 1

/* pcie_print_link_status is defined */
/* #undef HAVE_PCIE_PRINT_LINK_STATUS */

/* pci_bus_addr_t is defined */
#define HAVE_PCI_BUS_ADDR_T 1

/* pci_bus_speed is defined */
#define HAVE_PCI_BUS_SPEED 1

/* PCI_CLASS_STORAGE_EXPRESS is defined */
/* #undef HAVE_PCI_CLASS_STORAGE_EXPRESS */

/* PCI_DEV_FLAGS_ASSIGNED is defined */
#define HAVE_PCI_DEV_FLAGS_ASSIGNED 1

/* pcie_mpss is defined */
#define HAVE_PCI_DEV_PCIE_MPSS 1

/* pci_driver sriov_configure is defined */
#define HAVE_PCI_DRIVER_SRIOV_CONFIGURE 1

/* pci_enable_atomic_ops_to_root is defined */
/* #undef HAVE_PCI_ENABLE_ATOMIC_OPS_TO_ROOT */

/* pci_enable_msix_range is defined */
#define HAVE_PCI_ENABLE_MSIX_RANGE 1

/* pci.h struct pci_error_handlers has reset_done */
/* #undef HAVE_PCI_ERROR_HANDLERS_RESET_DONE */

/* pci.h struct pci_error_handlers has reset_notify */
#define HAVE_PCI_ERROR_HANDLERS_RESET_NOTIFY 1

/* pci.h struct pci_error_handlers has reset_prepare */
/* #undef HAVE_PCI_ERROR_HANDLERS_RESET_PREPARE */

/* linux/pci.h has pci_free_irq */
/* #undef HAVE_PCI_FREE_IRQ */

/* linux/pci.h has pci_irq_vector, pci_free_irq_vectors, pci_alloc_irq_vectors
   */
/* #undef HAVE_PCI_IRQ_API */

/* pci_irq_get_affinity is defined */
/* #undef HAVE_PCI_IRQ_GET_AFFINITY */

/* pci_irq_get_node is defined */
/* #undef HAVE_PCI_IRQ_GET_NODE */

/* pci_num_vf is defined */
#define HAVE_PCI_NUM_VF 1

/* pci_physfn is defined */
#define HAVE_PCI_PHYSFN 1

/* pci_pool_zalloc is defined */
/* #undef HAVE_PCI_POOL_ZALLOC */

/* pci_release_mem_regions is defined */
/* #undef HAVE_PCI_RELEASE_MEM_REGIONS */

/* pci_request_mem_regions is defined */
/* #undef HAVE_PCI_REQUEST_MEM_REGIONS */

/* pci_sriov_get_totalvfs is defined */
#define HAVE_PCI_SRIOV_GET_TOTALVFS 1

/* pci_upstream_bridge is defined */
#define HAVE_PCI_UPSTREAM_BRIDGE 1

/* pci_vfs_assigned is defined */
#define HAVE_PCI_VFS_ASSIGNED 1

/* PDE_DATA is defined */
#define HAVE_PDE_DATA 1

/* pernet_operations_id is defined */
#define HAVE_PERENT_OPERATIONS_ID 1

/* struct pernet_operations has id, size is defined */
#define HAVE_PERNET_OPERATIONS_ID_AND_SIZE 1

/* pinned_vm is defined */
#define HAVE_PINNED_VM 1

/* PM_QOS_LATENCY_TOLERANCE_NO_CONSTRAINT is defined */
#define HAVE_PM_QOS_LATENCY_TOLERANCE_NO_CONSTRAINT 1

/* dev_pm_qos_update_user_latency_tolerance is exported by the kernel */
/* #undef HAVE_PM_QOS_UPDATE_USER_LATENCY_TOLERANCE_EXPORTED */

/* pnv-pci.h has pnv_pci_enable_tunnel */
/* #undef HAVE_PNV_PCI_AS_NOTIFY */

/* pnv-pci.h has pnv_pci_set_p2p */
/* #undef HAVE_PNV_PCI_SET_P2P */

/* prandom_u32 is defined */
#define HAVE_PRANDOM_U32 1

/* print_hex_dump_debug is defined */
#define HAVE_PRINT_HEX_DUMP_DEBUG 1

/* pr_debug_ratelimited is defined */
#define HAVE_PR_DEBUG_RATELIMITED 1

/* linux/pr.h exists */
#define HAVE_PR_H 1

/* ptp_clock_info is defined */
#define HAVE_PTP_CLOCK_INFO 1

/* gettime 32bit is defined */
/* #undef HAVE_PTP_CLOCK_INFO_GETTIME_32BIT */

/* n_pins is defined */
#define HAVE_PTP_CLOCK_INFO_N_PINS 1

/* ptp_clock_register has 2 params is defined */
#define HAVE_PTP_CLOCK_REGISTER_2_PARAMS 1

/* __put_task_struct is exported by the kernel */
#define HAVE_PUT_TASK_STRUCT_EXPORTED 1

/* QUEUE_FLAG_WC_FUA is defined */
#define HAVE_QUEUE_FLAG_WC_FUA 1

/* rb_first_postorder is defined */
#define HAVE_RB_FIRST_POSTORDER 1

/* struct rb_root_cached is defined */
/* #undef HAVE_RB_ROOT_CACHED */

/* reciprocal_scale is defined */
#define HAVE_RECIPROCAL_SCALE 1

/* refcount.h exists */
#define HAVE_REFCOUNT 1

/* linux/security.h has register_lsm_notifier */
/* #undef HAVE_REGISTER_LSM_NOTIFIER */

/* register_netdevice_notifier_rh is defined */
/* #undef HAVE_REGISTER_NETDEVICE_NOTIFIER_RH */

/* register_net_sysctl is defined */
#define HAVE_REGISTER_NET_SYSCTL 1

/* request_firmware_direct is defined */
#define HAVE_REQUEST_FIRMWARE_DIRECT 1

/* struct request_queue has q_usage_counter */
#define HAVE_REQUEST_QUEUE_Q_USAGE_COUNTER 1

/* struct request_queue has request_fn_active */
#define HAVE_REQUEST_QUEUE_REQUEST_FN_ACTIVE 1

/* blkdev.h struct request has rq_flags */
/* #undef HAVE_REQUEST_RQ_FLAGS */

/* blk_types.h has REQ_IDLE */
/* #undef HAVE_REQ_IDLE */

/* req_op exist */
/* #undef HAVE_REQ_OP */

/* struct bio_aux is defined */
/* #undef HAVE_RH7_STRUCT_BIO_AUX */

/* struct rhltable is defined */
/* #undef HAVE_RHLTABLE */

/* rt6_lookup takes 6 params */
/* #undef HAVE_RT6_LOOKUP_TAKES_6_PARAMS */

/* linux/rtnetlink.h has net_rwsem */
/* #undef HAVE_RTNETLINK_NET_RWSEM */

/* dellink has 2 paramters */
#define HAVE_RTNL_LINK_OPS_DELLINK_2_PARAMS 1

/* newlink has 4 paramters */
#define HAVE_RTNL_LINK_OPS_NEWLINK_4_PARAMS 1

/* newlink has 5 paramters */
/* #undef HAVE_RTNL_LINK_OPS_NEWLINK_5_PARAMS */

/* rtnl_link_stats64 is defined */
#define HAVE_RTNL_LINK_STATS64 1

/* rtble has direct dst */
#define HAVE_RT_DIRECT_DST 1

/* rt_uses_gateway is defined */
#define HAVE_RT_USES_GATEWAY 1

/* get_rxfh_indir_size is defined */
#define HAVE_RXFH_INDIR_SIZE 1

/* get_rxfh_indir_size is defined in ethtool_ops_ext */
/* #undef HAVE_RXFH_INDIR_SIZE_EXT */

/* linux/sched/mm.h exists */
/* #undef HAVE_SCHED_MM_H */

/* linux/sched/signal.h exists */
/* #undef HAVE_SCHED_SIGNAL_H */

/* linux/sched/task.h exists */
/* #undef HAVE_SCHED_TASK_H */

/* scsi_change_queue_depth exist */
#define HAVE_SCSI_CHANGE_QUEUE_DEPTH 1

/* scsi_cmnd has members prot_flags */
#define HAVE_SCSI_CMND_PROT_FLAGS 1

/* scsi_device.h has function scsi_internal_device_block */
/* #undef HAVE_SCSI_DEVICE_SCSI_INTERNAL_DEVICE_BLOCK */

/* scsi_device.h struct scsi_device has member state_mutex */
/* #undef HAVE_SCSI_DEVICE_STATE_MUTEX */

/* scsi_device.h struct scsi_device has u64 lun */
#define HAVE_SCSI_DEVICE_U64_LUN 1

/* Scsi_Host has members nr_hw_queues */
#define HAVE_SCSI_HOST_NR_HW_QUEUES 1

/* scsi_host_template has members change_queue_type */
/* #undef HAVE_SCSI_HOST_TEMPLATE_CHANGE_QUEUE_TYPE */

/* scsi_host_template has members lockless */
/* #undef HAVE_SCSI_HOST_TEMPLATE_LOCKLESS */

/* scsi_host_template has members track_queue_depth */
#define HAVE_SCSI_HOST_TEMPLATE_TRACK_QUEUE_DEPTH 1

/* scsi_host_template has members use_blk_tags */
#define HAVE_SCSI_HOST_TEMPLATE_USE_BLK_TAGS 1

/* scsi_host_template has members use_host_wide_tags */
/* #undef HAVE_SCSI_HOST_TEMPLATE_USE_HOST_WIDE_TAGS */

/* SCSI_MAX_SG_SEGMENTS is defined */
#define HAVE_SCSI_MAX_SG_SEGMENTS 1

/* SCSI_SCAN_INITIAL is defined */
/* #undef HAVE_SCSI_SCAN_INITIAL */

/* scsi_tcq.h has function scsi_change_queue_type */
/* #undef HAVE_SCSI_TCQ_SCSI_CHANGE_QUEUE_TYPE */

/* scsi_transfer_length is defined */
#define HAVE_SCSI_TRANSFER_LENGTH 1

/* select_queue_fallback_t is defined */
#define HAVE_SELECT_QUEUE_FALLBACK_T 1

/* select_queue_fallback_t has third parameter */
/* #undef HAVE_SELECT_QUEUE_FALLBACK_T_3_PARAMS */

/* ndo_select_queue has a second net_device parameter */
/* #undef HAVE_SELECT_QUEUE_NET_DEVICE */

/* is defined */
/* #undef HAVE_SET_NETDEV_HW_FEATURES */

/* set_phys_id is defined */
#define HAVE_SET_PHYS_ID 1

/* set_phys_id is defined in ethtool_ops_ext */
/* #undef HAVE_SET_PHYS_ID_EXT */

/* struct se_cmd has member prot_checks */
#define HAVE_SE_CMD_HAS_PROT_CHECKS 1

/* target_core_base.h se_cmd transport_complete_callback has three params */
/* #undef HAVE_SE_CMD_TRANSPORT_COMPLETE_CALLBACK_HAS_THREE_PARAM */

/* sgl_alloc is defined */
/* #undef HAVE_SGL_ALLOC */

/* sgl_free is defined */
/* #undef HAVE_SGL_FREE */

/* sg_alloc_table_chained has 3 parameters */
/* #undef HAVE_SG_ALLOC_TABLE_CHAINED_3_PARAMS */

/* sg_alloc_table_chained has 4 parameters */
/* #undef HAVE_SG_ALLOC_TABLE_CHAINED_4_PARAMS */

/* SG_MAX_SEGMENTS is defined */
/* #undef HAVE_SG_MAX_SEGMENTS */

/* sg_zero_buffer is defined */
/* #undef HAVE_SG_ZERO_BUFFER */

/* SIOCGHWTSTAMP is defined */
#define HAVE_SIOCGHWTSTAMP 1

/* include/linux/sizes.h exists */
#define HAVE_SIZES_H 1

/* skb_add_rx_frag has 5 params */
/* #undef HAVE_SKB_ADD_RX_FRAG_5_PARAMS */

/* skb_clear_hash is defined */
#define HAVE_SKB_CLEAR_HASH 1

/* skb_dst_update_pmtu is defined */
/* #undef HAVE_SKB_DST_UPDATE_PMTU */

/* skb_flow_dissect_flow_keys has 3 parameters */
/* #undef HAVE_SKB_FLOW_DISSECT_FLOW_KEYS_HAS_3_PARAMS */

/* skb_inner_network_header is defined */
#define HAVE_SKB_INNER_NETWORK_HEADER 1

/* skb_inner_transport_header is defined */
#define HAVE_SKB_INNER_TRANSPORT_HEADER 1

/* skb_inner_transport_offset is defined */
/* #undef HAVE_SKB_INNER_TRANSPORT_OFFSET */

/* sk_buff has member l4_rxhash */
/* #undef HAVE_SKB_L4_RXHASH */

/* skb_pull_inline is defined */
#define HAVE_SKB_PULL_INLINE 1

/* skb_put_zero is defined */
/* #undef HAVE_SKB_PUT_ZERO */

/* sk_buff has member rxhash */
/* #undef HAVE_SKB_RXHASH */

/* skb_set_hash is defined */
#define HAVE_SKB_SET_HASH 1

/* skb_shared_info has union tx_flags */
/* #undef HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS */

/* sk_buff has member sw_hash */
#define HAVE_SKB_SWHASH 1

/* skb_transport_header_was_set is defined */
#define HAVE_SKB_TRANSPORT_HEADER_WAS_SET 1

/* skb_transport_offset is defined */
#define HAVE_SKB_TRANSPORT_OFFSET 1

/* skb_vlan_pop is defined */
#define HAVE_SKB_VLAN_POP 1

/* skwq_has_sleeper is defined */
/* #undef HAVE_SKWQ_HAS_SLEEPER */

/* csum_level is defined */
#define HAVE_SK_BUFF_CSUM_LEVEL 1

/* encapsulation is defined */
#define HAVE_SK_BUFF_ENCAPSULATION 1

/* xmit_more is defined */
#define HAVE_SK_BUFF_XMIT_MORE 1

/* sk_clone_lock is defined */
#define HAVE_SK_CLONE_LOCK 1

/* sk_wait_data has 3 params */
/* #undef HAVE_SK_WAIT_DATA_3_PARAMS */

/* smp_load_acquire is defined */
#define HAVE_SMP_LOAD_ACQUIRE 1

/* sock_create_kern has 5 params is defined */
#define HAVE_SOCK_CREATE_KERN_5_PARAMS 1

/* split_page is exported by the kernel */
#define HAVE_SPLIT_PAGE_EXPORTED 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* strnicmp is defined */
/* #undef HAVE_STRNICMP */

/* struct bio has member bi_error */
/* #undef HAVE_STRUCT_BIO_BI_ERROR */

/* struct bio has member bi_iter */
#define HAVE_STRUCT_BIO_BI_ITER 1

/* struct bio has member bi_opf */
/* #undef HAVE_STRUCT_BIO_BI_OPF */

/* struct dma_attrs is defined */
#define HAVE_STRUCT_DMA_ATTRS 1

/* ieee_pfc is defined */
#define HAVE_STRUCT_IEEE_PFC 1

/* ieee_qcn is defined */
#define HAVE_STRUCT_IEEE_QCN 1

/* struct ifla_vf_stats has memebers rx_dropped and tx_dropped */
/* #undef HAVE_STRUCT_IFLA_VF_STATS_RX_TX_DROPPED */

/* struct ifla_vf_stats has member tx_broadcast */
/* #undef HAVE_STRUCT_IFLA_VF_STATS_TX_BROADCAST */

/* linux/bio.h submit_bio has 1 parameter */
/* #undef HAVE_SUBMIT_BIO_1_PARAM */

/* SWITCHDEV_ATTR_ID_PORT_PARENT_ID is defined */
/* #undef HAVE_SWITCHDEV_ATTR_ID_PORT_PARENT_ID */

/* include/net/switchdev.h exists */
#define HAVE_SWITCHDEV_H 1

/* HAVE_SWITCHDEV_OPS is defined */
/* #undef HAVE_SWITCHDEV_OPS */

/* switchdev_port_same_parent_id is defined */
/* #undef HAVE_SWITCHDEV_PORT_SAME_PARENT_ID */

/* sysfs_create_file_ns is supported */
#define HAVE_SYSFS_CREATE_FILE_NS 1

/* sysfs_get_dirent gets 2 parameters */
#define HAVE_SYSFS_GET_DIRENT_2_PARAMS 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* linux/t10-pi.h exists */
#define HAVE_T10_PI_H 1

/* t10_pi_ref_tag() exists */
/* #undef HAVE_T10_PI_REF_TAG */

/* target_core_fabric.h has target_reverse_dma_direction function */
#define HAVE_TARGET_FABRIC_HAS_TARGET_REVERSE_DMA_DIRECTION 1

/* target_put_sess_cmd in target_core_fabric.h has 1 parameter */
#define HAVE_TARGET_PUT_SESS_CMD_HAS_1_PARAM 1

/* target_core_base.h se_cmd supports compare_and_write */
#define HAVE_TARGET_SUPPORT_COMPARE_AND_WRITE 1

/* TCA_CSUM_UPDATE_FLAG_IPV4HDR is defined */
/* #undef HAVE_TCA_CSUM_UPDATE_FLAG_IPV4HDR */

/* tc_action_stats_update is defined */
/* #undef HAVE_TCF_ACTION_STATS_UPDATE */

/* tcf_block_cb_register has fifth parameter */
/* #undef HAVE_TCF_BLOCK_CB_REGISTER_EXTACK */

/* tcf_exts_get_dev is defined */
/* #undef HAVE_TCF_EXTS_GET_DEV */

/* tcf_exts_has_actions is defined */
/* #undef HAVE_TCF_EXTS_HAS_ACTIONS */

/* tcf_exts_init is defined */
#define HAVE_TCF_EXTS_INIT 1

/* tcf_exts_stats_update is defined */
/* #undef HAVE_TCF_EXTS_STATS_UPDATE */

/* tcf_exts_to_list is defined */
/* #undef HAVE_TCF_EXTS_TO_LIST */

/* tcf_mirred_dev is defined */
/* #undef HAVE_TCF_MIRRED_DEV */

/* tcf_mirred_ifindex is defined */
/* #undef HAVE_TCF_MIRRED_IFINDEX */

/* tcf_pedit_nkeys is defined */
/* #undef HAVE_TCF_PEDIT_NKEYS */

/* struct tcf_pedit has member tcfp_keys_ex */
/* #undef HAVE_TCF_PEDIT_TCFP_KEYS_EX */

/* tcf_queue_work is defined */
/* #undef HAVE_TCF_QUEUE_WORK */

/* tcf_tunnel_info is defined */
/* #undef HAVE_TCF_TUNNEL_INFO */

/* tcf_vlan_push_prio is defined */
/* #undef HAVE_TCF_VLAN_PUSH_PRIO */

/* struct tc_block_offload is defined */
/* #undef HAVE_TC_BLOCK_OFFLOAD */

/* HAVE_TC_CLSFLOWER_STATS is defined */
/* #undef HAVE_TC_CLSFLOWER_STATS */

/* tc_cls_can_offload_and_chain0 is defined */
/* #undef HAVE_TC_CLS_CAN_OFFLOAD_AND_CHAIN0 */

/* struct tc_cls_flower_offload has egress_dev */
/* #undef HAVE_TC_CLS_FLOWER_OFFLOAD_EGRESS_DEV */

/* struct tc_cls_flower_offload is defined */
/* #undef HAVE_TC_FLOWER_OFFLOAD */

/* tc_gact.h exists */
#define HAVE_TC_GACT_H 1

/* tc_setup_cb_egdev_register is defined */
/* #undef HAVE_TC_SETUP_CB_EGDEV_REGISTER */

/* TC_SETUP_QDISC_MQPRIO is defined */
/* #undef HAVE_TC_SETUP_QDISC_MQPRIO */

/* struct tc_to_netdev has egress_dev */
/* #undef HAVE_TC_TO_NETDEV_EGRESS_DEV */

/* struct tc_to_netdev has tc */
/* #undef HAVE_TC_TO_NETDEV_TC */

/* timecounter_adjtime is defined */
#define HAVE_TIMECOUNTER_ADJTIME 1

/* linux/timecounter.h exists */
#define HAVE_TIMECOUNTER_H 1

/* timer_setup is defined */
/* #undef HAVE_TIMER_SETUP */

/* trace_seq_buffer_ptr is defined */
#define HAVE_TRACE_SEQ_BUFFER_PTR 1

/* trace_xdp_exception is defined */
/* #undef HAVE_TRACE_XDP_EXCEPTION */

/* type cycle_t is defined in linux/types.h */
#define HAVE_TYPE_CYCLE_T 1

/* type __poll_t is defined */
/* #undef HAVE_TYPE___POLL_T */

/* uapi/linux/if_bonding.h exists */
#define HAVE_UAPI_IF_BONDING_H 1

/* uapi/linux/if_ether.h exist */
#define HAVE_UAPI_LINUX_IF_ETHER_H 1

/* uapi/linux/netlink.h exists */
#define HAVE_UAPI_LINUX_NETLINK_H 1

/* uapi/linux/nvme_ioctl.h exists */
#define HAVE_UAPI_LINUX_NVME_IOCTL_H 1

/* uapi/linux/nvme_ioctl.h has NVME_IOCTL_RESCAN */
#define HAVE_UAPI_LINUX_NVME_IOCTL_RESCAN 1

/* uapi/linux/tls.h exists */
/* #undef HAVE_UAPI_LINUX_TLS_H */

/* udp4_hwcsum is exported by the kernel */
#define HAVE_UDP4_HWCSUM 1

/* ib_umem_notifier_invalidate_range_start has parameter blockable */
/* #undef HAVE_UMEM_NOTIFIER_PARAM_BLOCKABLE */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* unregister_netdevice_queue is defined */
#define HAVE_UNREGISTER_NETDEVICE_QUEUE 1

/* update_pmtu has 4 paramters */
#define HAVE_UPDATE_PMTU_4_PARAMS 1

/* include/generated/utsrelease.h exists */
#define HAVE_UTSRELEASE_H 1

/* uuid_be_to_bin is defined */
/* #undef HAVE_UUID_BE_TO_BIN */

/* uuid_equal is defined */
/* #undef HAVE_UUID_EQUAL */

/* uuid_gen is defined */
/* #undef HAVE_UUID_GEN */

/* uuid_is_null is defined */
/* #undef HAVE_UUID_IS_NULL */

/* va_format is defined */
#define HAVE_VA_FORMAT 1

/* spoofchk is defined */
#define HAVE_VF_INFO_SPOOFCHK 1

/* trust is defined */
/* #undef HAVE_VF_INFO_TRUST */

/* tx_rate is defined */
/* #undef HAVE_VF_TX_RATE */

/* min_tx_rate is defined */
#define HAVE_VF_TX_RATE_LIMITS 1

/* vlan_proto is defined */
/* #undef HAVE_VF_VLAN_PROTO */

/* vlan_dev_get_egress_qos_mask is defined */
#define HAVE_VLAN_DEV_GET_EGRESS_QOS_MASK 1

/* vlan_features_check is defined */
#define HAVE_VLAN_FEATURES_CHECK 1

/* __vlan_get_protocol defined */
#define HAVE_VLAN_GET_PROTOCOL 1

/* vlan_gro_frags is defined in if_vlan.h */
/* #undef HAVE_VLAN_GRO_FRAGS */

/* vlan_gro_receive is defined in if_vlan.h */
/* #undef HAVE_VLAN_GRO_RECEIVE */

/* vlan_hwaccel_do_receive have *skb in if_vlan.h */
/* #undef HAVE_VLAN_HWACCEL_DO_RECEIVE_SKB_PTR */

/* vlan_hwaccel_rx is defined in if_vlan.h */
/* #undef HAVE_VLAN_HWACCEL_RX */

/* vxlan_features_check is defined */
#define HAVE_VXLAN_FEATURES_CHECK 1

/* vxlan_gso_check is defined */
/* #undef HAVE_VXLAN_GSO_CHECK */

/* vxlan_vni_field is defined */
/* #undef HAVE_VXLAN_VNI_FIELD */

/* WQ_HIGHPRI is defined */
#define HAVE_WQ_HIGHPRI 1

/* WQ_MEM_RECLAIM is defined */
#define HAVE_WQ_MEM_RECLAIM 1

/* WQ_NON_REENTRANT is defined */
/* #undef HAVE_WQ_NON_REENTRANT */

/* WQ_SYSFS is defined */
#define HAVE_WQ_SYSFS 1

/* WQ_UNBOUND is defined */
#define HAVE_WQ_UNBOUND 1

/* WQ_UNBOUND_MAX_ACTIVE is defined */
#define HAVE_WQ_UNBOUND_MAX_ACTIVE 1

/* struct xfrmdev_ops has member xdo_dev_state_advance_esn */
/* #undef HAVE_XDO_DEV_STATE_ADVANCE_ESN */

/* xdp is defined */
/* #undef HAVE_XDP_BUFF */

/* xdp_buff data_hard_start is defined */
/* #undef HAVE_XDP_BUFF_DATA_HARD_START */

/* XDP_REDIRECT is defined */
/* #undef HAVE_XDP_REDIRECT */

/* net/xdp.h has xdp_rxq_info_reg_mem_model */
/* #undef HAVE_XDP_RXQ_INFO_REG_MEM_MODEL */

/* xdp_set_data_meta_invalid is defined */
/* #undef HAVE_XDP_SET_DATA_META_INVALID */

/* struct xps_map is defined */
#define HAVE_XPS_MAP 1

/* __atomic_add_unless is defined */
#define HAVE___ATOMIC_ADD_UNLESS 1

/* __blkdev_issue_discard is defined */
/* #undef HAVE___BLKDEV_ISSUE_DISCARD */

/* __cancel_delayed_work is defined */
/* #undef HAVE___CANCEL_DELAYED_WORK */

/* __ethtool_get_link_ksettings is defined */
/* #undef HAVE___ETHTOOL_GET_LINK_KSETTINGS */

/* __get_task_comm is exported by the kernel */
/* #undef HAVE___GET_TASK_COMM_EXPORTED */

/* napi_gro_flush has 2 parameters */
#define NAPI_GRO_FLUSH_2_PARAMS 1

/* ndo_add_slave has 3 parameters */
/* #undef NDO_ADD_SLAVE_3_PARAMS */

/* if getapp returns int */
#define NDO_GETAPP_RETURNS_INT 1

/* if getnumtcs returns int */
#define NDO_GETNUMTCS_RETURNS_INT 1

/* ndo_has_offload_stats gets net_device */
/* #undef NDO_HAS_OFFLOAD_STATS_GETS_NET_DEVICE */

/* ndo_select_queue has accel_priv */
/* #undef NDO_SELECT_QUEUE_HAS_ACCEL_PRIV */

/* if setapp returns int */
#define NDO_SETAPP_RETURNS_INT 1

/* netdev_master_upper_dev_link gets 4 parameters */
/* #undef NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS */

/* netdev_master_upper_dev_link gets 5 parameters */
/* #undef NETDEV_MASTER_UPPER_DEV_LINK_5_PARAMS */

/* Name of package */

/* Define to the address where bug reports for this package should be sent. */

/* Define to the full name of this package. */

/* Define to the full name and version of this package. */

/* Define to the one symbol short name of this package. */

/* Define to the home page for this package. */

/* Define to the version of this package. */

/* The size of `unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */

/* vfs_getattr has 4 params */
/* #undef VFS_GETATTR_HAS_4_PARAMS */

/* Make sure LINUX_BACKPORT macro is defined for all external users */
#ifndef LINUX_BACKPORT
#define LINUX_BACKPORT(__sym) backport_ ##__sym
#endif

/* use compat ib_verbs */
/* #define IB_VERBS_H 1 */

