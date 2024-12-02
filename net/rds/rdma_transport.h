#ifndef _RDMA_TRANSPORT_H
#define _RDMA_TRANSPORT_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "rds.h"

extern struct mutex		cm_id_map_lock;
extern struct idr		cm_id_map;

int rds_rdma_conn_connect(struct rds_connection *conn);
int rds_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event);
int rds6_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			       struct rdma_cm_event *event);

/* from rdma_transport.c */
int rds_rdma_init(void);
void rds_rdma_exit(void);

/* from ib.c */
extern struct rds_transport rds_ib_transport;
int rds_ib_init(void);
void rds_ib_exit(void);

#endif
