/*
 * Copyright (C) Marvell International Ltd. and its affiliates
 *
 * This software file (the "File") is owned and distributed by Marvell
 * International Ltd. and/or its affiliates ("Marvell") under the following
 * alternative licensing terms.  Once you have made an election to distribute
 * the file under one of the following license alternatives, please (i) delete
 * this introductory statement regarding license alternatives, (ii) delete the
 * two license alternatives that you have not elected to use and (iii) preserve
 * the Marvell copyright notice above.
 *
 *******************************************************************************
 * Marvell GPL License Option

 * If you received this File from Marvell, you may opt to use, redistribute
 * and/or modify this File in accordance with the terms and conditions of the
 * General Public License Version 2, June 1991 (the "GPL License"), a copy of
 * which is available along with the File in the license.txt file or by writing
 * to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE
 * EXPRESSLY DISCLAIMED.  The GPL License provides additional details about this
 * warranty disclaimer.
*/

/*
 * @file mvcpss_main.c
 *
 * @brief Marvell's CPSS utilities kernel module
 *
 * @author Yuval Shaia <yshaia@marvell.com>
 *
 */

#include <linux/module.h>

/*
 * Added by Oracle in order to compile in kernel source tree
 */
#define CONFIG_KM_MVPCI
#define CONFIG_KM_MVDMA2
#define CONFIG_KM_MVINT
#define CONFIG_KM_MVMBUS
#define CONFIG_KM_MVETH
#define CPSS_STREAM_NAME_CNS "CPSS_4.3.14_015"

#define MODULE_NAME "mvcpss"

#ifdef CONFIG_KM_MVPCI
extern int mvpci_init(void);
extern void mvpci_exit(void);
static unsigned int en_func_pci = 1;
module_param(en_func_pci, uint, 0644);
MODULE_PARM_DESC(en_func_pci, "Enable PCI function 0/1");
#endif

#ifdef CONFIG_KM_MVDMA2
extern int mvdma2_init(void);
extern void mvdma2_exit(void);
static unsigned int en_func_dma2 = 1;
module_param(en_func_dma2, uint, 0644);
MODULE_PARM_DESC(en_func_dma2, "Enable DMA2 function 0/1");
#endif

#ifdef CONFIG_KM_MVDMA
extern int mvdmadrv_init(void);
extern void mvdmadrv_exit(void);
static unsigned int en_func_dma = 1;
module_param(en_func_dma, uint, 0644);
MODULE_PARM_DESC(en_func_dma, "Enable DMA function 0/1");
#endif

#ifdef CONFIG_KM_MVINT
extern int mvintdrv_init(void);
extern void mvintdrv_exit(void);
static unsigned int en_func_int = 1;
module_param(en_func_int, uint, 0644);
MODULE_PARM_DESC(en_func_int, "Enable INT function 0/1");
#endif

#ifdef CONFIG_KM_MVMBUS
extern int mvmbusdrv_init(void);
extern void mvmbusdrv_exit(void);
static unsigned int en_func_mbus = 1;
module_param(en_func_mbus, uint, 0644);
MODULE_PARM_DESC(en_func_mbus, "Enable MBUS function 0/1");
#endif

#ifdef CONFIG_KM_MVETH
extern int mvppnd_init(void);
extern void mvppnd_exit(void);
static unsigned int en_func_eth = 1;
module_param(en_func_eth, uint, 0644);
MODULE_PARM_DESC(en_func_eth, "Enable ETH function 0/1");
#endif

#if defined(CONFIG_KM_MVDMA) && defined(CONFIG_KM_MVDMA2)
#warning "Invalid combination DMA=y and DMA2=y"
#endif

#if defined(CONFIG_KM_MVINT) && !defined(CONFIG_KM_MVPCI) && !defined(CONFIG_KM_MVMBUS) && !defined(CONFIG_KM_MVETH)
#warning "Invalid combination INT=y PCI=n, MBUS=n and ETH=n"
#endif

static inline void mvcpss_init_module(int (*module_init_func)(void),
				      const char *func_name, int *enable)
{
	int rc;

	if (!*enable)
		return;

	rc = module_init_func();
	if (rc) {
		pr_err("%s: Fail to initialize %s function\n", MODULE_NAME,
		       func_name);
		*enable = 0; /* So module_exit will not get called */
	} else {
		pr_info("%s: Function %s loaded\n", MODULE_NAME,
			func_name);
	}
}

static inline void mvcpss_exit_module(void (*module_exit_func)(void),
				      const char *func_name, int enable)
{
	if (!enable)
		return;

	module_exit_func();

	pr_info("%s: Function %s unloaded\n", MODULE_NAME, func_name);
}

static int mvcpss_init(void)
{
#if defined(CONFIG_KM_MVINT) || defined(CONFIG_KM_MVPCI) || defined(CONFIG_KM_MVETH)
	bool pci = false;
#endif
#if defined(CONFIG_KM_MVINT) || defined(CONFIG_KM_MVMBUS)
	bool mbus = false;
#endif

#ifdef CONFIG_KM_MVPCI
	mvcpss_init_module(mvpci_init, "PCI", &en_func_pci);
	pci = en_func_pci;
#endif

#ifdef CONFIG_KM_MVDMA2
#ifdef CONFIG_KM_MVDMA
	if (en_func_dma && en_func_dma2)
		pr_warn("%s: Both DMA and DMA2 selected\n", MODULE_NAME);
#endif
	mvcpss_init_module(mvdma2_init, "DMA2", &en_func_dma2);
#endif

#ifdef CONFIG_KM_MVDMA
#ifdef CONFIG_KM_MVDMA2
	if (en_func_dma && en_func_dma2)
		pr_warn("%s: Both DMA and DMA2 selected\n", MODULE_NAME);
#endif
	mvcpss_init_module(mvdmadrv_init, "DMA", &en_func_dma);
#endif

#ifdef CONFIG_KM_MVMBUS
	mvcpss_init_module(mvmbusdrv_init, "MBUS", &en_func_mbus);
	mbus = en_func_mbus;
#endif

#ifdef CONFIG_KM_MVETH
	mvcpss_init_module(mvppnd_init, "ETH", &en_func_eth);
	pci |= en_func_eth;
#endif

#ifdef CONFIG_KM_MVINT
	if (!pci && !mbus)
		pr_warn("%s: INT driver with no PCI or MBUS\n", MODULE_NAME);

	mvcpss_init_module(mvintdrv_init, "INT", &en_func_int);
#endif

	/* We are okay regarless of the status of the above */
	return 0;
}

static void mvcpss_exit(void)
{
#ifdef CONFIG_KM_MVINT
	mvcpss_exit_module(mvintdrv_exit, "INT", en_func_int);
#endif

#ifdef CONFIG_KM_MVETH
	mvcpss_exit_module(mvppnd_exit, "ETH", en_func_eth);
#endif

#ifdef CONFIG_KM_MVMBUS
	mvcpss_exit_module(mvmbusdrv_exit, "MBUS", en_func_mbus);
#endif

#ifdef CONFIG_KM_MVDMA
	mvcpss_exit_module(mvdmadrv_exit, "DMA", en_func_dma);
#endif

#ifdef CONFIG_KM_MVDMA2
	mvcpss_exit_module(mvdma2_exit, "DMA2", en_func_dma2);
#endif

#ifdef CONFIG_KM_MVPCI
	mvcpss_exit_module(mvpci_exit, "PCI", en_func_pci);
#endif
}

module_init(mvcpss_init);
module_exit(mvcpss_exit);

MODULE_AUTHOR("Yuval Shaia <yshaia@marvell.com>");
MODULE_DESCRIPTION("Marvell's CPSS kernel module");
MODULE_VERSION(CPSS_STREAM_NAME_CNS);
MODULE_LICENSE("Dual BSD/GPL");
