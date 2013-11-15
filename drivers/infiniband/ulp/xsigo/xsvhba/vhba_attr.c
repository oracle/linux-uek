/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	 Redistribution and use in source and binary forms, with or
 *	 without modification, are permitted provided that the following
 *	 conditions are met:
 *
 *	  - Redistributions of source code must retain the above
 *		copyright notice, this list of conditions and the following
 *		disclaimer.
 *
 *	  - Redistributions in binary form must reproduce the above
 *		copyright notice, this list of conditions and the following
 *		disclaimer in the documentation and/or other materials
 *		provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <scsi/scsi_transport_fc.h>
#include "vhba_xsmp.h"

static void vhba_get_host_port_id(struct Scsi_Host *shost)
{
	return;
}

static void vhba_get_host_speed(struct Scsi_Host *shost)
{
	struct virtual_hba *vhba =
	    vhba_get_context_by_idr((u32) *shost->hostdata);
	u32 speed = FC_PORTSPEED_4GBIT;

	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Could not find vhba\n");
		return;
	}

	/* Hard coded for now, but we need this info
	 * sent from the I/O card to us.
	 switch (vhba->speed) {
	 case OFC_SPEED_1GBIT:
	 speed = FC_PORTSPEED_1GBIT;
	 break;
	 case OFC_SPEED_2GBIT:
	 speed = FC_PORTSPEED_2GBIT;
	 break;
	 case OFC_SPEED_4GBIT:
	 speed = FC_PORTSPEED_4GBIT;
	 break;
	 default:
	 speed = FC_PORTSPEED_UNKNOWN;
	 break;
	 }*/
	fc_host_speed(shost) = speed;
	DEC_REF_CNT(vhba);
}

static void vhba_get_host_port_type(struct Scsi_Host *shost)
{
	fc_host_port_type(shost) = FC_PORTTYPE_NPORT;
	return;
}

static void vhba_get_host_port_state(struct Scsi_Host *shost)
{
	struct virtual_hba *vhba;
	int link_state;

	vhba = vhba_get_context_by_idr((u32) *(shost->hostdata));
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Could not find vhba\n");
		return;
	}

	link_state = atomic_read(&vhba->ha->link_state);
	switch (link_state) {
	case 0:
		fc_host_port_state(shost) = FC_PORTSTATE_LINKDOWN;
		break;
	case 1:
		fc_host_port_state(shost) = FC_PORTSTATE_ONLINE;
		break;
	case 2:
		fc_host_port_state(shost) = FC_PORTSTATE_OFFLINE;
		break;
	default:
		fc_host_port_state(shost) = FC_PORTSTATE_UNKNOWN;
		break;
	}
	DEC_REF_CNT(vhba);
}

static void vhba_get_host_symbolic_name(struct Scsi_Host *shost)
{
	struct virtual_hba *vhba;

	vhba = vhba_get_context_by_idr((u32) *(shost->hostdata));
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Could not find vhba\n");
		return;
	}
	DEC_REF_CNT(vhba);
}

static void vhba_get_host_fabric_name(struct Scsi_Host *shost)
{
	struct virtual_hba *vhba;
	u64 node_name;

	vhba = vhba_get_context_by_idr((u32) *(shost->hostdata));
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Could not find vhba\n");
		return;
	}
	node_name = vhba->cfg->wwn;
	fc_host_fabric_name(shost) = node_name;
	DEC_REF_CNT(vhba);
}

static void vhba_get_starget_node_name(struct scsi_target *target)
{

	struct Scsi_Host *host = dev_to_shost(target->dev.parent);
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;
	struct fc_port *fc;

	vhba = vhba_get_context_by_idr((u32) *(host->hostdata));
	if (vhba == NULL) {
		pr_err("Error: Could not find vhba for this command\n");
		return;
	}
	ha = vhba->ha;

	list_for_each_entry(fc, &ha->disc_ports, list) {
		if (fc->os_target_id == target->id) {
			fc_starget_node_name(target) =
			    __be64_to_cpu(*(uint64_t *) fc->node_name);
			DEC_REF_CNT(vhba);
			return;
		}
	}
	fc_starget_node_name(target) = -1;
	DEC_REF_CNT(vhba);
	return;
}

static void vhba_get_starget_port_name(struct scsi_target *target)
{
	struct Scsi_Host *host = dev_to_shost(target->dev.parent);
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	struct fc_port *fc;
	vhba = vhba_get_context_by_idr((u32) *(host->hostdata));
	if (vhba == NULL) {
		pr_err("Error: Could not find vhba for this command\n");
		return;
	}
	ha = vhba->ha;

	list_for_each_entry(fc, &ha->disc_ports, list) {
		if (fc->os_target_id == target->id) {
			fc_starget_port_name(target) =
			    __be64_to_cpu(*(uint64_t *) fc->port_name);
			DEC_REF_CNT(vhba);
			return;
		}
	}
	fc_starget_port_name(target) = -1;
	DEC_REF_CNT(vhba);
	return;
}

static void vhba_get_starget_port_id(struct scsi_target *target)
{
	struct Scsi_Host *host = dev_to_shost(target->dev.parent);
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	struct fc_port *fc;
	vhba = vhba_get_context_by_idr((u32) *(host->hostdata));
	if (vhba == NULL) {
		pr_err("Error: Could not find vhba for this command\n");
		return;
	}
	ha = vhba->ha;

	list_for_each_entry(fc, &ha->disc_ports, list) {
		if (fc->os_target_id == target->id) {
			fc_starget_port_id(target) = fc->d_id.b.domain << 16 |
			    fc->d_id.b.area << 8 | fc->d_id.b.al_pa;
			DEC_REF_CNT(vhba);
			return;
		}
	}
	fc_starget_port_id(target) = -1;
	DEC_REF_CNT(vhba);
	return;
}

static void vhba_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout + 5;
	else
		rport->dev_loss_tmo = 30;	/* Default value XXX revisit */

}

struct fc_host_statistics *vhba_get_fc_host_stats(struct Scsi_Host *shp)
{
	return NULL;
}

struct fc_function_template vhba_transport_functions = {

	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_active_fc4s = 1,

	.get_host_port_id = vhba_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = vhba_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = vhba_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_port_state = vhba_get_host_port_state,
	.show_host_port_state = 1,
	.get_host_symbolic_name = vhba_get_host_symbolic_name,
	.show_host_symbolic_name = 1,

	.dd_fcrport_size = sizeof(struct os_tgt),
	.show_rport_supported_classes = 1,

	.get_host_fabric_name = vhba_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_starget_node_name = vhba_get_starget_node_name,
	.show_starget_node_name = 1,
	.get_starget_port_name = vhba_get_starget_port_name,
	.show_starget_port_name = 1,
	.get_starget_port_id = vhba_get_starget_port_id,
	.show_starget_port_id = 1,
	.set_rport_dev_loss_tmo = vhba_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,
	.get_fc_host_stats = vhba_get_fc_host_stats,

};
