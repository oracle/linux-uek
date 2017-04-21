/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"

static atomic_t has_flow_ctl  = ATOMIC_INIT(0);
static atomic_t response_count = ATOMIC_INIT(0);

static int dax_has_flow_ctl_one_node(void)
{
	struct ccb_extract *ccb;
	struct ccb_completion_area *ca;
	char *mem, *dax_input, *dax_output;
	unsigned long submitted_ccb_buf_len, status_data, hv_rv, ra, va;
	long timeout;
	int ret = 0;

	mem = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (mem == NULL)
		return -ENOMEM;

	va = ALIGN((unsigned long)mem, 128);
	ccb = (struct ccb_extract *) va;
	ca = (struct ccb_completion_area *)ALIGN(va + sizeof(*ccb),
						 sizeof(*ca));
	dax_input = (char *)ca + sizeof(*ca);
	dax_output = (char *)dax_input + (DAX_INPUT_ELEMS * DAX_INPUT_ELEM_SZ);

	ccb->control.hdr.opcode  = CCB_QUERY_OPCODE_EXTRACT;

	/* I/O formats and sizes */
	ccb->control.src0_fmt = CCB_QUERY_IFMT_FIX_BYTE;
	ccb->control.src0_sz = 0; /* 1 byte */
	ccb->control.output_sz = DAX_OUTPUT_ELEM_SZ - 1;
	ccb->control.output_fmt = CCB_QUERY_OFMT_BYTE_ALIGN;

	/* addresses */
	*(u64 *)&ccb->src0 = (u64) dax_input;
	*(u64 *)&ccb->output = (u64) dax_output;
	*(u64 *)&ccb->completion = (u64) ca;

	/* address types */
	ccb->control.hdr.at_src0 = CCB_AT_VA;
	ccb->control.hdr.at_dst  = CCB_AT_VA;
	ccb->control.hdr.at_cmpl = CCB_AT_VA;

	/* input sizes and output flow control limit */
	ccb->data_acc_ctl.input_len_fmt = CCB_QUERY_ILF_BYTE;
	ccb->data_acc_ctl.input_cnt = (DAX_INPUT_ELEMS * DAX_INPUT_ELEM_SZ) - 1;
	/* try to overflow; 0 means 64B output limit */
	ccb->data_acc_ctl.output_buf_sz = DAX_FLOW_LIMIT / 64 - 1;
	ccb->data_acc_ctl.flow_ctl = DAX_BUF_LIMIT_FLOW_CTL;

	ra = virt_to_phys(ccb);

	hv_rv = sun4v_dax_ccb_submit((void *) ra, 64, HV_DAX_CCB_VA_PRIVILEGED | HV_DAX_QUERY_CMD, 0,
				     &submitted_ccb_buf_len, &status_data);
	if (hv_rv != HV_EOK) {
		dax_info("failed dax submit, ret=0x%lx", hv_rv);
		if (dax_debug & DAX_DBG_FLG_BASIC)
			dax_prt_ccbs((union ccb *)ccb, 64);
		goto done;
	}

	timeout = 10LL * 1000LL * 1000LL; /* 10ms in ns */
	while (timeout > 0) {
		unsigned long status;
		unsigned long mwait_time = 8192;

		/* monitored load */
		__asm__ __volatile__("lduba [%1] 0x84, %0\n\t"
				     : "=r" (status) : "r" (&ca->cmd_status));
		if (status == CCB_CMD_STAT_NOT_COMPLETED)
			__asm__ __volatile__("wr %0, %%asr28\n\t" /* mwait */
					     : : "r" (mwait_time));
		else
			break;
		timeout = timeout - mwait_time;
	}
	if (timeout <= 0) {
		int kill_ret;
		u16 kill_res;

		dax_alert("dax flow control test timed out, killing ccb");
		ra = virt_to_phys(ca);
		kill_ret = dax_ccb_kill(ra, &kill_res);
		dax_alert("kill returned %d, kill_res %d", kill_ret, kill_res);
		ret = -EIO;
		goto done;
	}

	if (ca->output_sz != DAX_FLOW_LIMIT) {
		dax_dbg("0x%x bytes output, differs from flow limit 0x%lx",
			ca->output_sz, DAX_FLOW_LIMIT);
		dax_dbg("mem=%p, va=0x%lx, ccb=%p, ca=%p, out=%p",
			mem, va, ccb, ca, dax_output);
		goto done;
	}

	ret = 1;
done:
	kfree(mem);
	return ret;
}

static void dax_has_flow_ctl_client(void *info)
{
	int cpu = smp_processor_id();
	int node = cpu_to_node(cpu);
	int ret = dax_has_flow_ctl_one_node();

	if (ret > 0) {
		dax_dbg("DAX on cpu %d node %d has flow control",
		       cpu, node);
		atomic_set(&has_flow_ctl, 1);
	} else if (ret == 0) {
		dax_dbg("DAX on cpu %d node %d has no flow control",
		       cpu, node);
	} else {
		return;
	}
	atomic_inc(&response_count);
}

bool dax_has_flow_ctl_numa(void)
{
	unsigned int node;
	int cnt = 10000;
	int nr_nodes = 0;
	cpumask_t numa_cpu_mask;

	cpumask_clear(&numa_cpu_mask);
	atomic_set(&has_flow_ctl, 0);
	atomic_set(&response_count, 0);

	/*
	 * For M7 platforms with multi socket, processors on each socket may be
	 * of different version, thus different DAX version. So it is
	 * necessary to detect the flow control on all the DAXs in the
	 * platform. Select first cpu from each numa node and run the
	 * flow control detection code on those cpus. This makes sure
	 * that the detection code runs on all the DAXs in the platform.
	 */
	for_each_node_with_cpus(node) {
		int dst_cpu = cpumask_first(&numa_cpumask_lookup_table[node]);

		cpumask_set_cpu(dst_cpu, &numa_cpu_mask);
		nr_nodes++;
	}

	smp_call_function_many(&numa_cpu_mask,
			       dax_has_flow_ctl_client, NULL, 1);
	while ((atomic_read(&response_count) != nr_nodes) && --cnt)
		udelay(100);

	if (cnt == 0) {
		dax_err("Could not synchronize DAX flow control detector");
		return false;
	}

	return !!atomic_read(&has_flow_ctl);
}

bool dax_has_ra_pgsz(void)
{
	struct ccb_extract *ccb;
	struct ccb_completion_area *ca;
	char *mem, *dax_input, *dax_output;
	unsigned long submitted_ccb_buf_len, status_data, hv_rv, ra, va;
	long timeout;
	bool ret = false;
	int i;

	/* allocate 3 pages so we are guaranteed a 16k aligned chunk inside it */
	mem = kzalloc(3*PAGE_SIZE, GFP_KERNEL);

	if (mem == NULL)
		return false;

	va = ALIGN((unsigned long)mem, 2*PAGE_SIZE);
	ccb = (struct ccb_extract *) va;
	ca = (struct ccb_completion_area *)ALIGN(va + sizeof(*ccb),
						 sizeof(*ca));
	dax_input = (char *)ca + sizeof(*ca);
	/* position output address 16 bytes before the end of the page */
	dax_output = (char *) ALIGN((u64)dax_input, PAGE_SIZE) - 16;

	ccb->control.hdr.opcode  = CCB_QUERY_OPCODE_EXTRACT;

	/* I/O formats and sizes */
	ccb->control.src0_fmt = CCB_QUERY_IFMT_FIX_BYTE;
	ccb->control.src0_sz = DAX_INPUT_ELEM_SZ - 1; /* 1 byte */
	ccb->control.output_sz = DAX_OUTPUT_ELEM_SZ - 1; /* 1 byte */
	ccb->control.output_fmt = CCB_QUERY_OFMT_BYTE_ALIGN;

	/* addresses */
	*(u64 *)&ccb->src0 = (u64) dax_input;
	*(u64 *)&ccb->output = (u64) virt_to_phys(dax_output);
	*(u64 *)&ccb->completion = (u64) ca;

	/* address types */
	ccb->control.hdr.at_src0 = CCB_AT_VA;
	ccb->control.hdr.at_dst  = CCB_AT_RA;
	ccb->control.hdr.at_cmpl = CCB_AT_VA;

	/* input sizes */
	ccb->data_acc_ctl.input_len_fmt = CCB_QUERY_ILF_BYTE;
	ccb->data_acc_ctl.input_cnt = (DAX_INPUT_ELEMS * DAX_INPUT_ELEM_SZ) - 1;

	/* no flow control, we are testing for page limit */
	ccb->data_acc_ctl.flow_ctl = 0;

	memset(dax_input, 0x99, DAX_INPUT_ELEMS * DAX_INPUT_ELEM_SZ);
	memset(dax_output, 0x77, DAX_OUTPUT_ELEMS * DAX_OUTPUT_ELEM_SZ);

	ra = virt_to_phys(ccb);

	hv_rv = sun4v_dax_ccb_submit((void *) ra, 64, HV_DAX_CCB_VA_PRIVILEGED | HV_DAX_QUERY_CMD, 0,
				     &submitted_ccb_buf_len, &status_data);
	if (hv_rv != HV_EOK) {
		dax_info("failed dax submit, ret=0x%lx", hv_rv);
		if (dax_debug & DAX_DBG_FLG_BASIC)
			dax_prt_ccbs((union ccb *)ccb, 64);
		goto done;
	}

	timeout = 10LL * 1000LL * 1000LL; /* 10ms in ns */
	while (timeout > 0) {
		unsigned long status;
		unsigned long mwait_time = 8192;

		/* monitored load */
		__asm__ __volatile__("lduba [%1] 0x84, %0\n\t"
				     : "=r" (status) : "r" (&ca->cmd_status));
		if (status == CCB_CMD_STAT_NOT_COMPLETED)
			__asm__ __volatile__("wr %0, %%asr28\n\t" /* mwait */
					     : : "r" (mwait_time));
		else
			break;
		timeout = timeout - mwait_time;
	}
	if (timeout <= 0) {
		int kill_ret;
		u16 kill_res;

		dax_alert("dax ra_pgsz test timed out, killing ccb");
		ra = virt_to_phys(ca);
		kill_ret = dax_ccb_kill(ra, &kill_res);
		dax_alert("kill returned %d, kill_res %d", kill_ret, kill_res);
		goto done;
	}

	if (ca->cmd_status == CCB_CMD_STAT_FAILED &&
	    ca->err_mask == CCB_CMD_ERR_POF) {
		ret = true;
		dax_dbg("dax ra_pgsz test succeeded: feature is available");
	}
	else {
		dax_dbg("dax ra_pgsz test failed: feature not available");
	}

	dax_dbg("page overflow test, output_sz=%d", ca->output_sz);
	dax_dbg("mem=%p, va=0x%lx, ccb=%p, ca=%p, out=%p",
		mem, va, ccb, ca, dax_output);
	dax_dbg("cmd_status=%d, err_mask=0x%x",
		ca->cmd_status, ca->err_mask);
	dax_prt_ccbs((union ccb *)ccb, 64);
	for (i=0; i<64; i=i+8) {
		dax_dbg("%08lx/ %08lx", (unsigned long) dax_output+i, *(unsigned long *)(dax_output+i));
	}

done:
	kfree(mem);
	return ret;
}

void dax_overflow_check(struct dax_ctx *ctx, int idx)
{
	unsigned long virtp, page_size = PAGE_SIZE;
	struct ccb_hdr *hdr;
	union ccb     *ccb;
	struct vm_area_struct *vma;
	struct ccb_completion_area *ca = &ctx->ca_buf[idx];

	if (dax_debug == 0)
		return;

	if (ca->cmd_status != CCB_CMD_STAT_FAILED)
		return;

	if (ca->err_mask != CCB_CMD_ERR_POF)
		return;

	ccb = &ctx->ccb_buf[idx];
	hdr = CCB_HDR(ccb);

	dax_dbg("*************************");
	dax_dbg("*DAX Page Overflow Report:");
	dax_dbg("*  Output size produced = 0x%x", ca->output_sz);
	dax_dbg("*  Input size processed = 0x%x", ca->n_processed);
	dax_dbg("*  Address analysis:");

	virtp = ccb->dwords[QUERY_DWORD_OUTPUT];

	if (hdr->at_dst == CCB_AT_RA) {
		page_size = DAX_SYN_LARGE_PAGE_SIZE;
	} else if (hdr->at_dst == CCB_AT_VA_ALT) {
		if (current->mm == NULL)
			return;

		vma = find_vma(current->mm, virtp);
		if (vma == NULL) {
			dax_dbg("*   Output address = 0x%lx but is demapped, which precludes analysis",
				virtp);
			goto done;
		} else {
			page_size = vma_kernel_pagesize(vma);
		}
	} 

	dax_dbg("*   Output size produced (0x%x) is %s the page bounds 0x%lx..0x%lx",
		ca->output_sz,
		(virtp + ca->output_sz > ALIGN(virtp + 1, page_size)) ?
					 "OUTSIDE" : "WITHIN",
			virtp, ALIGN(virtp + 1, page_size));

done:
	dax_dbg("*************************");
}
