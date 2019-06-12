/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012 Cavium, Inc.
 *
 * Copyright (C) 2009 Wind River Systems,
 *   written by Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/edac.h>

#include <asm/octeon/cvmx.h>
#include <asm/octeon/octeon.h>

#include "edac_module.h"

#define EDAC_MOD_STR "octeon-l2c"

struct octeon_edac_l2c_pvt_info {
	int num_tads;
	int num_nodes;
};

static void octeon_l2c_poll_oct1(struct edac_device_ctl_info *l2c)
{
	union cvmx_l2t_err l2t_err, l2t_err_reset;
	union cvmx_l2d_err l2d_err, l2d_err_reset;

	l2t_err_reset.u64 = 0;
	l2t_err.u64 = cvmx_read_csr(CVMX_L2T_ERR);
	if (l2t_err.s.sec_err) {
		edac_device_handle_ce(l2c, 0, 0,
				      "Tag Single bit error (corrected)");
		l2t_err_reset.s.sec_err = 1;
	}
	if (l2t_err.s.ded_err) {
		edac_device_handle_ue(l2c, 0, 0,
				      "Tag Double bit error (detected)");
		l2t_err_reset.s.ded_err = 1;
	}
	if (l2t_err_reset.u64)
		cvmx_write_csr(CVMX_L2T_ERR, l2t_err_reset.u64);

	l2d_err_reset.u64 = 0;
	l2d_err.u64 = cvmx_read_csr(CVMX_L2D_ERR);
	if (l2d_err.s.sec_err) {
		edac_device_handle_ce(l2c, 0, 1,
				      "Data Single bit error (corrected)");
		l2d_err_reset.s.sec_err = 1;
	}
	if (l2d_err.s.ded_err) {
		edac_device_handle_ue(l2c, 0, 1,
				      "Data Double bit error (detected)");
		l2d_err_reset.s.ded_err = 1;
	}
	if (l2d_err_reset.u64)
		cvmx_write_csr(CVMX_L2D_ERR, l2d_err_reset.u64);

}

static void _octeon_l2c_poll_oct2(struct edac_device_ctl_info *l2c, int tad)
{
	union cvmx_l2c_err_tdtx err_tdtx, err_tdtx_reset;
	union cvmx_l2c_err_ttgx err_ttgx, err_ttgx_reset;
	union cvmx_l2c_int_reg l2c_int_reg;
	bool invalidate_cache_line_tdtx = false;
	bool l2c_clear = false;
	char buf1[64];
	char buf2[80];

	/* Poll for L2C bigrd/bigwr/holewr/holerd */
	l2c_int_reg.u64 = cvmx_read_csr(CVMX_L2C_INT_REG);
	if (l2c_int_reg.s.bigrd) {
		snprintf(buf1, sizeof(buf1),
			"Read reference past L2C_BIG_CTL[MAXDRAM] occurred:");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.bigwr) {
		snprintf(buf1, sizeof(buf1),
			"Write reference past L2C_BIG_CTL[MAXDRAM] occurred:");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.vrtpe) {
		snprintf(buf1, sizeof(buf1),
			"L2C_VRT_MEM read found a parity error");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.vrtadrng) {
		snprintf(buf1, sizeof(buf1),
			"Address outside of virtualization range");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.vrtidrng) {
		snprintf(buf1, sizeof(buf1),
			"Virtualization ID out of range");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.vrtwr) {
		snprintf(buf1, sizeof(buf1),
			"Virtualization ID prevented a write");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.holewr) {
		snprintf(buf1, sizeof(buf1),
			"Write reference to 256MB hole occurred:");
		l2c_clear = true;
	}
	if (l2c_int_reg.s.holerd) {
		snprintf(buf1, sizeof(buf1),
			"Read reference to 256MB hole occurred:");
		l2c_clear = true;
	}
	if (l2c_clear) {
		edac_device_handle_ce(l2c, tad, 1, buf1);
		cvmx_write_csr(CVMX_L2C_INT_REG, l2c_int_reg.u64);
	}

	err_tdtx_reset.u64 = 0;
	err_tdtx.u64 = cvmx_read_csr(CVMX_L2C_ERR_TDTX(tad));
	if (err_tdtx.s.dbe || err_tdtx.s.sbe) {
		snprintf(buf1, sizeof(buf1),
			 "type:%d, syn:0x%x, way:%d",
			 err_tdtx.s.type, err_tdtx.s.syn, err_tdtx.s.wayidx);
		invalidate_cache_line_tdtx = true;
	}

	if (err_tdtx.s.vdbe || err_tdtx.s.vsbe) {
		union cvmx_l2c_err_vbfx err_vbfx;
		err_vbfx.u64 = cvmx_read_csr(CVMX_L2C_ERR_VBFX(tad));
		snprintf(buf1, sizeof(buf1),
			 "type:%d, syn:0x%x, way:%d, VBF error syndrome: 0x%x",
			 err_tdtx.s.type, err_tdtx.s.syn, err_tdtx.s.wayidx,
			 err_vbfx.s.vsyn);
		invalidate_cache_line_tdtx = true;
	}

	if (err_tdtx.s.dbe) {
		snprintf(buf2, sizeof(buf2),
			 "L2D Double bit error (detected):%s", buf1);
		err_tdtx_reset.s.dbe = 1;
		edac_device_handle_ue(l2c, tad, 1, buf2);
		panic("Uncorrectable L2 cache error detected!\n");
	}

	if (err_tdtx.s.sbe) {
		snprintf(buf2, sizeof(buf2),
			 "L2D Single bit error (corrected):%s", buf1);
		err_tdtx_reset.s.sbe = 1;
		edac_device_handle_ce(l2c, tad, 1, buf2);
	}
	if (err_tdtx.s.vdbe) {
		snprintf(buf2, sizeof(buf2),
			 "VBF Double bit error (detected):%s", buf1);
		err_tdtx_reset.s.vdbe = 1;
		edac_device_handle_ue(l2c, tad, 1, buf2);
		panic("Uncorrectable L2 cache error detected!\n");
	}
	if (err_tdtx.s.vsbe) {
		snprintf(buf2, sizeof(buf2),
			 "VBF Single bit error (corrected):%s", buf1);
		err_tdtx_reset.s.vsbe = 1;
		edac_device_handle_ce(l2c, tad, 1, buf2);
	}
	if (err_tdtx_reset.u64) {
		if (invalidate_cache_line_tdtx) {
			/* Write back and invalidate the cache line */
			CVMX_SYNCW;
			CVMX_CACHE_WBIL2I((err_tdtx.s.wayidx) | (1ULL << 63), 0);
		}
		cvmx_write_csr(CVMX_L2C_ERR_TDTX(tad), err_tdtx_reset.u64);
	}

	err_ttgx_reset.u64 = 0;
	err_ttgx.u64 = cvmx_read_csr(CVMX_L2C_ERR_TTGX(tad));

	if (err_ttgx.s.dbe || err_ttgx.s.sbe)
		snprintf(buf1, sizeof(buf1),
			 "type:%d, syn:0x%x, way:%d",
			 err_ttgx.s.type, err_ttgx.s.syn, err_ttgx.s.wayidx);

	if (err_ttgx.s.dbe) {
		snprintf(buf2, sizeof(buf2),
			 "Tag Double bit error (detected):%s", buf1);
		edac_device_handle_ue(l2c, tad, 0, buf2);
	}
	if (err_ttgx.s.sbe) {
		snprintf(buf2, sizeof(buf2),
			 "Tag Single bit error (corrected):%s", buf1);
		err_ttgx_reset.s.sbe = 1;
		edac_device_handle_ce(l2c, tad, 0, buf2);
		/* Write back and invalidate the cache line */
		CVMX_SYNCW;
		CVMX_CACHE_WBIL2I((err_tdtx.s.wayidx) | (1ULL << 63), 0);
	}
	if (err_ttgx_reset.u64)
		cvmx_write_csr(CVMX_L2C_ERR_TTGX(tad), err_ttgx_reset.u64);
}

static void octeon_l2c_poll_oct2(struct edac_device_ctl_info *l2c)
{
	int i;
	for (i = 0; i < l2c->nr_instances; i++)
		_octeon_l2c_poll_oct2(l2c, i);
}

/**
 * When a L2 cache single-bit ECC error occurs in the data this function
 * calculates the proper cache index and flushes and invalidates the cache
 * line.
 *
 * @param	node	node where L2 ECC error occurred
 * @param	tad	tad number where L2 ECC error occurred
 * @return	cache index flushed
 */
static u64 octeon_flush_l2c_l2d_ecc_error(int node, int tad)
{
	u64 cindex;

	cindex = cvmx_l2c_tqdl2d_to_index_7xxx(node, tad);
	cindex = CVMX_ADD_IO_SEG(cindex);
	/* Write back and invalidate the cache line */
	CVMX_SYNCW;
	CVMX_CACHE_WBIL2I(cindex, 0);
	return cindex;
}

/**
 * Processes and fixes (single bit) L2 data cache errors
 *
 * @param	l2c	edac device
 * @param	node	Octeon CPU node
 * @param	tad	TAD number
 */
static void octeon3_l2c_process_l2d_ecc_error(struct edac_device_ctl_info *l2c,
					      int node, int tad)
{
	union cvmx_l2c_tqdx_err tqdx_err;
	union cvmx_l2c_ecc_ctl ecc_ctl;
	union cvmx_l2c_tadx_int l2c_reset;
	u64 cindex;
	char msg[256];
	bool dbe = false;

	/* Check for artificial L2C ECC errors */
	ecc_ctl.u64 = cvmx_read_csr_node(node, CVMX_L2C_ECC_CTL);
	switch (ecc_ctl.s.l2dflip) {
	case 0:
		break;
	case 1:
		/* Single-bit L2C ECC error generated artificially on ECC[0] */
		dev_info(l2c->dev,
			 "Detected artificially generated single-bit L2C error on ECC[0]\n");
		break;
	case 2:
		/* Single-bit L2C ECC error generated artificially on ECC[1] */
		dev_info(l2c->dev,
			 "Detected artificially generated single-bit L2C error on ECC[1]\n");
		break;
	case 3:
		/* Double-bit L2C ECC error generated artificially */
		dev_info(l2c->dev,
			 "Detected artificially generated double-bit L2C error\n");
		break;
	}
	/* Clear artificially generated errors */
	if (ecc_ctl.s.l2dflip) {
		ecc_ctl.s.l2dflip = 0;
		cvmx_write_csr_node(node, CVMX_L2C_ECC_CTL, ecc_ctl.u64);
	}

	tqdx_err.u64 = cvmx_read_csr_node(node, CVMX_L2C_TQDX_ERR(tad));
	/* FBF = fill buffer
	 * SBF = store buffer
	 * VBF = victim buffer
	 * LFB + VAB = in-flight address buffers
	 */
	if (tqdx_err.s.l2ddbe) {
		dbe = true;
	} else if (!tqdx_err.s.l2dsbe) {
		/* Unknown L2 cache error detected */
		panic("Unknown l2c error occurred: l2c_tqd%d_err: 0x%llx\n",
		      tad, tqdx_err.u64);
	}

	cindex = octeon_flush_l2c_l2d_ecc_error(node, tad);
	snprintf(msg, sizeof(msg),
		 "%s: tad: %d, l2idx: 0x%x, qdhalf: %d, qdnum: 0x%x, syndrome: 0x%x",
		 l2c->ctl_name, tad, tqdx_err.s.l2didx, tqdx_err.s.qdhlf,
		 tqdx_err.s.qdnum, tqdx_err.s.syn);
	if (!dbe) {
		edac_device_handle_ce(l2c, tad, 1, msg);
		l2c_reset.u64 = 0;
		l2c_reset.s.l2dsbe = 1;
		cvmx_write_csr_node(node, CVMX_L2C_TADX_INT(tad),
				    l2c_reset.u64);
	} else {
		edac_device_handle_ue(l2c, tad, 1, msg);
		panic("Uncorrectable L2 cache error detected!\n");
	}
}

static void octeon3_l2c_process_tag_ecc_error(struct edac_device_ctl_info *l2c,
					      int node, int tad, bool remote)
{
	union cvmx_l2c_ttgx_err ttgx_err;
	union cvmx_l2c_rtgx_err rtgx_err;
	union cvmx_l2c_ecc_ctl ecc_ctl;
	u64 cindex;
	char msg[128];
	int way;
	int index;
	int syn;

	if (remote && OCTEON_IS_MODEL(OCTEON_CN78XX_PASS1_X)) {
		edac_device_handle_ue(l2c, tad, 0,
				      "Remote TAG L2C errors not supported by CN78XX pass 1.X");
		return;
	}

	ecc_ctl.u64 = cvmx_read_csr_node(node, CVMX_L2C_ECC_CTL);
	switch (ecc_ctl.s.l2tflip) {
	case 0:
		break;
	case 1:
	case 2:
	case 3:
		/* We could print a message since this is an artificially
		 * generated error.
		 */
		cvmx_write_csr_node(node, CVMX_L2C_ECC_CTL, 0);
	}
	if (remote)
		rtgx_err.u64 = cvmx_read_csr_node(node, CVMX_L2C_RTGX_ERR(tad));
	else
		rtgx_err.u64 = cvmx_read_csr_node(node, CVMX_L2C_TTGX_ERR(tad));

	if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		if (remote) {
			way = rtgx_err.s.way;
			index = rtgx_err.s.l2idx;
			syn = rtgx_err.s.syn;
		} else {
			way = ttgx_err.cn78xx.way;
			index = ttgx_err.cn78xx.l2idx;
			syn = ttgx_err.cn78xx.syn;
		}
	} else if (OCTEON_IS_MODEL(OCTEON_CN70XX)) {
		way = ttgx_err.cn70xx.way;
		index = ttgx_err.cn70xx.l2idx;
		syn = ttgx_err.cn70xx.syn;
	} else {
		way = ttgx_err.cn73xx.way;
		index = ttgx_err.cn73xx.l2idx;
		syn = ttgx_err.cn73xx.syn;
	}

	snprintf(msg, sizeof(msg),
		 "L2D: %stag way: 0x%x, index: 0x%x, syn: 0x%x",
		 remote ? "remote " : "", way, index, syn);

	if ((remote && rtgx_err.s.rtgdbe) || (!remote && ttgx_err.s.tagdbe)) {
		edac_device_handle_ue(l2c, tad, 1, msg);
	} else if (!remote && ttgx_err.s.noway) {
		edac_device_handle_ue(l2c, tad, 1, "L2D: no way!");
	} else {
		edac_device_handle_ce(l2c, tad, 1, msg);
		cindex = cvmx_l2c_ttgx_to_index_7xxx(node, tad, remote);
		cindex = CVMX_ADD_IO_SEG(cindex);
		CVMX_SYNCW;
		CVMX_CACHE_WBIL2I(cindex, 0);
		CVMX_SYNC;
	}
}

static void _octeon_l2c_poll_oct3(struct edac_device_ctl_info *l2c,
				  int node, int tad)
{
	char buf1[64];
	char buf2[80];
	union cvmx_l2c_tqdx_err tqdx_err;
	union cvmx_l2c_ttgx_err ttgx_err;
	union cvmx_l2c_rtgx_err rtgx_err;
	union cvmx_l2c_tadx_err l2c_err;
	union cvmx_l2c_tadx_int l2c_reset;
	int way, l2idx;

	tqdx_err.u64 = cvmx_read_csr_node(node, CVMX_L2C_TQDX_ERR(tad));
	ttgx_err.u64 = cvmx_read_csr(CVMX_L2C_TTGX_ERR(tad));
	rtgx_err.u64 = OCTEON_IS_MODEL(OCTEON_CN78XX) ?
		cvmx_read_csr_node(node, CVMX_L2C_RTGX_ERR(tad)) : 0;

	/* The most likely case is that there is no error so bail out. */
	if (likely(!tqdx_err.s.fbfsbe && !tqdx_err.s.sbfsbe &&
		   !tqdx_err.s.l2dsbe && !tqdx_err.s.fbfdbe &&
		   !tqdx_err.s.sbfdbe && !tqdx_err.s.l2ddbe &&
		   !ttgx_err.s.tagsbe && !ttgx_err.s.tagdbe &&
		   !ttgx_err.s.noway && !rtgx_err.s.rtgsbe &&
		   !rtgx_err.s.rtgdbe))
		return;

	if (tqdx_err.s.l2dsbe || tqdx_err.s.l2ddbe) {
		octeon3_l2c_process_l2d_ecc_error(l2c, node, tad);
		return;
	}

	if (tqdx_err.s.sbfsbe || tqdx_err.s.fbfsbe)
		/* Hardware automatically handles this so ignore it */
		return;

	l2c_reset.u64 = 0;

	if (tqdx_err.s.sbfdbe || tqdx_err.s.sbfsbe ||
	    tqdx_err.s.fbfdbe || tqdx_err.s.fbfsbe)
		snprintf(buf1, sizeof(buf1),
			 "L2D: syn:0x%x, quad:%d, index:%d",
			 tqdx_err.s.syn, tqdx_err.s.qdnum, tqdx_err.s.l2didx);

	if (tqdx_err.s.sbfdbe) {
		snprintf(buf2, sizeof(buf2),
			 "SBF Double bit error (detected):%s", buf1);
		l2c_reset.cn70xx.sbfdbe = 1;
		edac_device_handle_ue(l2c, tad, 1, buf2);
	}
	if (tqdx_err.s.sbfsbe) {
		snprintf(buf2, sizeof(buf2),
			 "SBF Single bit error (corrected):%s", buf1);
		l2c_reset.cn70xx.sbfsbe = 1;
		edac_device_handle_ce(l2c, tad, 1, buf2);
	}
	if (tqdx_err.s.fbfdbe) {
		snprintf(buf2, sizeof(buf2),
			 "FBF Double bit error (detected):%s", buf1);
		l2c_reset.cn70xx.fbfdbe = 1;
		edac_device_handle_ue(l2c, tad, 1, buf2);
	}
	if (tqdx_err.s.fbfsbe) {
		snprintf(buf2, sizeof(buf2),
			 "FBF Single bit error (corrected):%s", buf1);
		l2c_reset.cn70xx.fbfsbe = 1;
		edac_device_handle_ce(l2c, tad, 1, buf2);
	}

	if (OCTEON_IS_MODEL(OCTEON_CN70XX)) {
		way = ttgx_err.cn70xx.way;
		l2idx = ttgx_err.cn70xx.l2idx;
	} else if (OCTEON_IS_MODEL(OCTEON_CN78XX)) {
		way = ttgx_err.cn78xx.way;
		l2idx = ttgx_err.cn78xx.l2idx;
	} else {
		way = ttgx_err.cn73xx.way;
		l2idx = ttgx_err.cn73xx.l2idx;
	}

	if (ttgx_err.s.tagdbe || ttgx_err.s.tagsbe) {
		/* Handle tag errors */
		octeon3_l2c_process_tag_ecc_error(l2c, node, tad, false);
		return;
	}

	/* handle remote tag errors */
	if (rtgx_err.s.rtgsbe || rtgx_err.s.rtgdbe) {
		octeon3_l2c_process_tag_ecc_error(l2c, node, tad, true);
		return;
	}

	l2c_err.u64 = cvmx_read_csr(CVMX_L2C_TADX_ERR(tad));
	if (l2c_err.s.bigrd) {
		snprintf(buf1, sizeof(buf1),
			"Read reference past L2C_BIG_CTL[MAXDRAM] occurred:");
		l2c_reset.cn70xx.bigrd = true;
		edac_device_handle_ue(l2c, tad, 0, buf1);
	}
	if (l2c_err.s.bigwr) {
		snprintf(buf1, sizeof(buf1),
			"Write reference past L2C_BIG_CTL[MAXDRAM] occurred:");
		l2c_reset.cn70xx.bigwr = true;
		edac_device_handle_ue(l2c, tad, 0, buf1);
	}

	if (l2c_reset.u64)
		cvmx_write_csr(CVMX_L2C_TADX_INT(tad), l2c_reset.u64);
}

static void octeon_l2c_poll_oct3(struct edac_device_ctl_info *l2c)
{
	struct octeon_edac_l2c_pvt_info *l2c_pvt = l2c->pvt_info;
	int i;

	for (i = 0; i < l2c->nr_instances; i++)
		_octeon_l2c_poll_oct3(l2c, i / l2c_pvt->num_tads,
				      i % l2c_pvt->num_tads);
}

static int octeon_l2c_probe(struct platform_device *pdev)
{
	struct edac_device_ctl_info *l2c;
	int num_tads;
	struct octeon_edac_l2c_data *l2c_data;
	struct octeon_edac_l2c_pvt_info *l2c_priv;

	if (OCTEON_IS_MODEL(OCTEON_CN78XX))
		num_tads = 8;
	else if ((!OCTEON_IS_MODEL(OCTEON_CN70XX) && OCTEON_IS_OCTEON3())
		 || OCTEON_IS_MODEL(OCTEON_CN68XX))
		num_tads = 4;
	else
		num_tads = 1;

	/* This function gets called multiple times, first globally then again
	 * for all of the TADs.  We don't need to do anything in the latter
	 * cases.
	 */
	l2c_data = dev_get_platdata(&pdev->dev);
	if (!l2c_data) {
		l2c = edac_device_alloc_ctl_info(sizeof(*l2c_priv), "l2ctad",
						 num_tads * num_online_nodes(),
						 "l2c", 2, 0, NULL, 0,
						 edac_device_alloc_index());
		if (!l2c)
			return -ENOMEM;

		l2c->dev = &pdev->dev;
		platform_set_drvdata(pdev, l2c);

		l2c->dev_name = dev_name(&pdev->dev);
		l2c->mod_name = "octeon-l2c";
		l2c->ctl_name = "octeon_l2c_err";
		l2c->panic_on_ue = true;
		l2c_priv = l2c->pvt_info;
		l2c_priv->num_tads = num_tads;
		l2c_priv->num_nodes = num_online_nodes();

		if (OCTEON_IS_OCTEON1PLUS()) {
			union cvmx_l2t_err l2t_err;
			union cvmx_l2d_err l2d_err;

			l2t_err.u64 = cvmx_read_csr(CVMX_L2T_ERR);
			l2t_err.s.sec_intena = 0;	/* We poll */
			l2t_err.s.ded_intena = 0;
			cvmx_write_csr(CVMX_L2T_ERR, l2t_err.u64);

			l2d_err.u64 = cvmx_read_csr(CVMX_L2D_ERR);
			l2d_err.s.sec_intena = 0;	/* We poll */
			l2d_err.s.ded_intena = 0;
			cvmx_write_csr(CVMX_L2T_ERR, l2d_err.u64);

			l2c->edac_check = octeon_l2c_poll_oct1;
		} else if (current_cpu_type() == CPU_CAVIUM_OCTEON2) {
			/* OCTEON II */
			l2c->edac_check = octeon_l2c_poll_oct2;
		} else {
			/* OCTEON III */
			l2c->edac_check = octeon_l2c_poll_oct3;
		}

		if (edac_device_add_device(l2c) > 0) {
			dev_err(&pdev->dev,
				"%s: edac_device_add_device() failed\n",
				__func__);
			goto err;
		}
	}

	return 0;

err:
	edac_device_free_ctl_info(l2c);

	return -ENXIO;
}

static int octeon_l2c_remove(struct platform_device *pdev)
{
	struct edac_device_ctl_info *l2c = platform_get_drvdata(pdev);

	edac_device_del_device(&pdev->dev);
	if (l2c)
		edac_device_free_ctl_info(l2c);

	return 0;
}

static struct platform_driver octeon_l2c_driver = {
	.probe = octeon_l2c_probe,
	.remove = octeon_l2c_remove,
	.driver = {
		   .name = "octeon_l2c_edac",
	}
};
module_platform_driver(octeon_l2c_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ralf Baechle <ralf@linux-mips.org>");
