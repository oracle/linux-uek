/* priq_sun4v.c: SUN4V Hardware Priority Interrupt Queues - PRIQ support.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/hash.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <asm/irq.h>
#include <asm/mdesc.h>
#include <asm/hypervisor.h>
#include "priq_sun4v.h"
#include "pci_impl.h"

static unsigned long priqs_eq_sizes, priqs_per_cpu, priqs_per_pcibus;
static unsigned long priq_eq_max_num_entries;
static bool priq_configured;
static bool priq_debug;

#define PRIQ_LABEL "[priq] "
#define priqdbg(fmt, args...) \
do {    if (priq_debug) \
		pr_info(PRIQ_LABEL fmt, ## args); \
} while (0)

/* priq_eq_sizes is a bit map of supported EQ sizes.
 *     If bit n is set, EQ size in bytes of 2^(13 + 3n) is supported.
 *     If bit n is set, #entries of 2^(7 + 3n) is supported.
 *     Note: Each EQ entry is 64 bytes.
 *
 *     bit 0 = 128 entries/8KB buffer size is supported
 *     bit 1 = 1k entries/64KB buffer size is supported
 *     bit 2 = 8k entries/512KB buffer size is supported
 *     bit 3 = 64k entries/4MB buffer size is supported
 */
static void __init priq_max_eq_size(unsigned long priq_eq_sizes)
{
	unsigned int n;

	n = fls64(priq_eq_sizes) - 1UL;
	priq_eq_max_num_entries = 1UL << (7 + 3 * n);
}

static int __init priq_get_properties(void)
{
	struct mdesc_handle *hp = mdesc_grab();
	int rc = -ENODEV;
	u64 pn, *mdp;

	pn = mdesc_node_by_name(hp, MDESC_NODE_NULL, "platform");

	mdp = (u64 *)mdesc_get_property(hp, pn, "priq-eq-sizes", NULL);
	if (!mdp)
		goto out;

	priqs_eq_sizes = *mdp;
	priq_max_eq_size(priqs_eq_sizes);

	mdp = (u64 *)mdesc_get_property(hp, pn, "#priqs-per-cpu", NULL);
	if (mdp)
		priqs_per_cpu = *mdp;
	else
		priqs_per_cpu = 1;

	mdp = (u64 *)mdesc_get_property(hp, pn, "#priqs-per-pcibus", NULL);
	if (mdp)
		priqs_per_pcibus = *mdp;
	else
		priqs_per_pcibus = 1;

	rc = 0;
	pr_info("PRIQ: priqs_eq_sizes=%ld priqs_per_cpu=%ld priqs_per_pcibus=%ld\n",
		priqs_eq_sizes, priqs_per_cpu, priqs_per_pcibus);

out:
	mdesc_release(hp);
	return rc;
}

/* bus, device and function. */
#define BDF(b, d, f)	(((b) << 8) | ((d) << 3) | (f))
#define RID(bdf) ((bdf) & 0xffff)

/* bus, device and function for intx is PEX req_id (0x0000).*/
#define	BDF_INTX	BDF(0, 0, 0)

/* INTX priq record for msidata. */
#define	PRIQ_INTA	0UL
#define	PRIQ_INTB	1UL
#define	PRIQ_INTC	2UL
#define	PRIQ_INTD	3UL

static char *BDF2str(char *buf, int size, unsigned int bdf)
{
	snprintf(buf, size, "%04x:%02x:%02x.%d", (bdf >> 16) & 0xffff,
		 (bdf >> 8) & 0xff, (bdf & 0xff) >> 3, bdf & 0x03);
	return buf;
}

static unsigned long priq_irq_to_intx(struct priq_irq *priq_irq)
{
	return priq_irq->msidata & PRIQ_INTD;
}

static bool priq_irq_is_intx(struct priq_irq *priq_irq)
{
	return priq_irq->bdf == BDF_INTX;
}

#define PRIQ_INTX_DEBUG 0
#if PRIQ_INTX_DEBUG
static void priq_intx_debug(struct priq_irq *priq_irq, const char *message)
{
	unsigned long intx = priq_irq_to_intx(priq_irq);
	char buf[16];

	pr_info("PRIQ: %s intx=%ld devhandle=0x%x irq=%d bdf=%s msidata=%u\n",
		message, intx, priq_irq->devhandle, priq_irq->irq,
		BDF2str(buf, 16, priq_irq->bdf), priq_irq->msidata);
}
#else
static void priq_intx_debug(struct priq_irq *priq_irq, const char *message) {}
#endif

static const unsigned int priq_hash_node_nr =
				PAGE_SIZE / sizeof(struct list_head);

static const unsigned int priq_hash_mask =
				(PAGE_SIZE / sizeof(struct list_head)) - 1;

/* TODO should not be hardcoded but should be the order of priq_hash_mode_nr */
#define	PRIQ_HASH_BITS		9

/* The numa affined piece is replicated percpu for each node's strands. */
static struct list_head *priq_hash[MAX_NUMNODES];

/* Should this be spotted hot then it can be done per node.
 * It should only be used during MSI/IRQ hash list addition and removal.
 */
static DEFINE_SPINLOCK(priq_hash_node_lock);

#define	PRIQ_EQ_SIZE_SHIFT	6
#define	PRIQ_EQ_SIZE		BIT(PRIQ_EQ_SIZE_SHIFT)

struct priq {
	unsigned long id;
	unsigned long c_raddr;	/* complex raddr (raddr|order) */
	unsigned long head;
	unsigned long tail;
	struct list_head *hash;
};

static void raddr_order_to_priq(struct priq *priq, unsigned long raddr,
				unsigned int order)
{
	priq->c_raddr = raddr | order;
}

static unsigned long priq_to_raddr(struct priq *priq)
{
	return priq->c_raddr & PAGE_MASK;
}

static unsigned int priq_to_order(struct priq *priq)
{
	return priq->c_raddr & ~PAGE_MASK;
}

static unsigned  long priq_size_mask(struct priq *priq)
{
	return  ~((1UL << (PAGE_SHIFT + (priq_to_order(priq)))) - 1UL);
}

static bool priq_active(struct priq *priq)
{
	return priq->hash;
}

static DEFINE_PER_CPU(struct priq, current_priq) = {
		      .id = 0UL, .c_raddr = 0UL, .head = 0UL, .tail = 0UL,
		      .hash = NULL};

/* online CPUs with configured PRIQs */
static cpumask_t priq_cpu_mask;

static void cpumask_set_cpu_priq(int cpu)
{
	cpumask_set_cpu(cpu, &priq_cpu_mask);
}

static void cpumask_clear_cpu_priq(int cpu)
{
	cpumask_clear_cpu(cpu, &priq_cpu_mask);
}

static int priq_mask_to_strand(int hint_strand, const struct cpumask *mask)
{
	cpumask_t tmp_mask;
	int strand;

	if (hint_strand)
		hint_strand--;

	cpumask_and(&tmp_mask, &priq_cpu_mask, mask);

	if (cpumask_empty(&tmp_mask)) {
		strand = cpumask_next(hint_strand, &priq_cpu_mask);

		if (strand >= nr_cpu_ids)
			strand = cpumask_first(&priq_cpu_mask);
	} else {
		strand = cpumask_next(hint_strand, &tmp_mask);

		if (strand >= nr_cpu_ids)
			strand = cpumask_first(&tmp_mask);
	}

	return strand;
}

static int priq_irq_bind_eqcb(struct priq_irq *priq_irq,
			      const struct cpumask *mask)
{
	bool is_intx = priq_irq_is_intx(priq_irq);
	int strand = priq_irq->strand;
	unsigned long hverror, id;
	struct priq *priq;
	char buf[16];

	strand = priq_mask_to_strand(strand, mask);

	if (strand >= nr_cpu_ids) {
		priqdbg("priq_affine failed. strand: %d\n", strand);
		return -ENODEV;
	}

	priq = &per_cpu(current_priq, strand);
	id = priq->id;

	if (is_intx) {
		unsigned long intx = priq_irq_to_intx(priq_irq);

		priq_intx_debug(priq_irq, __func__);
		hverror = pci_priq_intx_bind(priq_irq->devhandle, intx, id);
		if (hverror) {
			priqdbg("bind_eqcb(intx) h: %lu intx: %ld RC: 0x%04x\n",
				hverror, intx, priq_irq->devhandle);
			return -ENODEV;
		}

		priqdbg("bind_eqcb(intx) success. intx: %ld RC: 0x%04x\n",
			intx, priq_irq->devhandle);
	} else {
		hverror = pci_priq_msi_bind(priq_irq->devhandle,
					    priq_irq->msidata,
					    RID(priq_irq->bdf), id);
		if (hverror) {
			priqdbg("bind_eqcb(msi). hv: %lu msi: %d PCI: %s\n",
				hverror, priq_irq->msidata,
				BDF2str(buf, 16, priq_irq->bdf));
			return -ENODEV;
		}
	}

	priq_irq->strand = strand;
	return 0;
}

/* We may want to limit the number of priq per socket. For now it will 128
 * entries PRIQ and one per strand, which is 1U << (7 + 6) = 8Kb. This could
 * encounter issue with nr_cpus=1, such as EQ overflow, and with unevenly
 * distributed irq placement. To mitigate both of these the choices are
 * larger priq EQ size and/or limit strand per core coverage.
 *
 * Another issue is NUMA affining priq_msi. Should a node cpu be put offline,
 * then the numa affined priq_msi needs to be move from one hash to
 * another. It becomes a tangled and ugly. Let's attempt to not permit this.
 */
static int priq_msi_set_affinity(struct irq_data *data,
				 const struct cpumask *mask, bool force)
{
	struct priq_irq *priq_msi = irq_data_get_irq_handler_data(data);
	int err = priq_irq_bind_eqcb(priq_msi, mask);

	if (err) {
		char buf[16];

		pr_warn("PRIQ: Set affinity failed. IRQ: %d, MSI %d, PCI: %s\n",
			priq_msi->irq, priq_msi->msidata,
			BDF2str(buf, 16, priq_msi->bdf));
	}

	return err;
}

static void priq_msi_enable(struct irq_data *data)
{
	struct priq_irq *priq_msi = irq_data_get_irq_handler_data(data);
	unsigned long hverror;
	char buf[16];

	hverror = priq_irq_bind_eqcb(priq_msi, data->affinity);
	if (hverror)
		goto out;

	hverror = pci_priq_msi_enable(priq_msi->devhandle, priq_msi->msidata,
				      RID(priq_msi->bdf));
	if (hverror) {
		priqdbg("MSI enable failed. err: %ld\n", hverror);
		goto out;
	}

	hverror = pci_priq_msi_setstate(priq_msi->devhandle, priq_msi->msidata,
					RID(priq_msi->bdf), HV_MSISTATE_IDLE);
	if (hverror) {
		priqdbg("Set MSI to idle failed. err: %ld\n", hverror);
		goto out;
	}

	unmask_msi_irq(data);
	return;

out:
	pr_err("PRIQ: Could not enable MSI: %d - RC: 0x%04x - PCI: %s\n",
	       priq_msi->msidata, priq_msi->devhandle,
	       BDF2str(buf, 16, priq_msi->bdf));
}

static void priq_msi_disable(struct irq_data *data)
{
	struct priq_irq *priq_msi = irq_data_get_irq_handler_data(data);
	unsigned long hverror;

	hverror = pci_priq_msi_disable(priq_msi->devhandle, priq_msi->msidata,
				       RID(priq_msi->bdf));
	if (hverror)
		priqdbg("MSI disable failed. err: %ld\n", hverror);

	mask_msi_irq(data);
}

static struct irq_chip priq_msi_chip = {
	.name			= "PCI-MSI",
	.irq_mask		= mask_msi_irq,
	.irq_unmask		= unmask_msi_irq,
	.irq_enable		= priq_msi_enable,
	.irq_disable		= priq_msi_disable,
	.irq_set_affinity	= priq_msi_set_affinity,
};

static int priq_intx_set_affinity(struct irq_data *data,
				  const struct cpumask *mask, bool force)
{
	struct priq_irq *priq_irq = irq_data_get_irq_handler_data(data);
	int err = priq_irq_bind_eqcb(priq_irq, mask);

	if (err) {
		unsigned long intx = priq_irq_to_intx(priq_irq);

		pr_warn("PRIQ: Could not set affinity. INTx %lu - RC: 0x%04x\n",
			intx, priq_irq->devhandle);
	}

	return err;
}

static void priq_intx_enable(struct irq_data *data)
{
	struct priq_irq *priq_irq = irq_data_get_irq_handler_data(data);
	unsigned long intx = priq_irq_to_intx(priq_irq);
	unsigned long hverror;

	hverror = priq_irq_bind_eqcb(priq_irq, data->affinity);
	if (hverror)
		goto out;

	hverror = pci_priq_intx_enable(priq_irq->devhandle, intx);
	if (hverror) {
		priqdbg("intx enable failed: %ld, rc: 0x%03x, intx: %lu\n",
			hverror, priq_irq->devhandle, intx);
		goto out;
	}

	hverror = pci_priq_intx_setstate(priq_irq->devhandle, intx,
					 HV_PCI_INTX_CLEAR);
	if (hverror) {
		priqdbg("clear intx failed: %ld, rc: 0x%03x, intx: %lu\n",
			hverror, priq_irq->devhandle, intx);
		goto out;
	}

	return;

out:
	priq_intx_debug(priq_irq, __func__);
	pr_err("PRIQ: Could not enable INTx %lu - RC: 0x%04x\n", intx,
	       priq_irq->devhandle);
}

static void priq_intx_disable(struct irq_data *data)
{
	struct priq_irq *priq_irq = irq_data_get_irq_handler_data(data);
	unsigned long intx = priq_irq_to_intx(priq_irq);
	unsigned long hverror;

	hverror = pci_priq_intx_disable(priq_irq->devhandle, intx);
	if (hverror)
		priqdbg("intx(%lu) disable failed: %lu 0x%04x\n", intx, hverror,
			priq_irq->devhandle);

	priq_intx_debug(priq_irq, __func__);
}

static struct irq_chip priq_intx_chip = {
	.name			= "PCI-INTX",
	.irq_enable		= priq_intx_enable,
	.irq_disable		= priq_intx_disable,
	.irq_set_affinity	= priq_intx_set_affinity,
};

static void priq_hash_node_init(struct list_head *head)
{
	unsigned int index;

	for (index = 0U; index != priq_hash_node_nr; index++, head++)
		INIT_LIST_HEAD(head);
}

static void priq_hash_nodes_free(void)
{
	int node;

	for_each_online_node(node) {
		if (priq_hash[node]) {
			struct list_head *head = priq_hash[node];

			free_pages((unsigned long)head, 0U);
		}
	}
}

static int priq_hash_nodes_init(void)
{
	int node;

	for_each_online_node(node) {
		struct list_head *head;
		struct page *page;

		page = alloc_pages_exact_node(node, GFP_ATOMIC, 0U);
		if (!page) {
			priqdbg("Failed to allocate priq hash list.\n");
			goto out;
		}

		head = page_address(page);
		priq_hash[node] = head;
		priq_hash_node_init(head);
	}
	return 0;

out:
	priq_hash_nodes_free();
	return -ENOMEM;
}

#define MAX_PBMS_BITS 7
#define MAX_PBMS (1 << (MAX_PBMS_BITS))
#define MAX_PBMS_MASK ((MAX_PBMS) - 1)

static struct pci_pbm_info *pbms[MAX_PBMS];

static DEFINE_SPINLOCK(priq_pbm_tbl_lock);

static struct pci_pbm_info *priq_dhndl_to_pbm(unsigned int dhndl)
{
	int idx = dhndl & MAX_PBMS_MASK;
	unsigned long flags;
	int j = 0;

	spin_lock_irqsave(&priq_pbm_tbl_lock, flags);
	while (unlikely(pbms[idx]->devhandle != dhndl)) {
		idx = (idx + 1) & MAX_PBMS_MASK;

		if (unlikely(j++ >= MAX_PBMS)) {
			priqdbg("Can't find pbm\n");
			spin_unlock_irqrestore(&priq_pbm_tbl_lock, flags);
			return NULL;
		}
	}
	spin_unlock_irqrestore(&priq_pbm_tbl_lock, flags);

	return pbms[idx];
}

static int priq_add_pbm_tbl(struct pci_pbm_info *pbm)
{
	int idx = pbm->devhandle & MAX_PBMS_MASK;
	unsigned long flags;
	int j = 0;

	spin_lock_irqsave(&priq_pbm_tbl_lock, flags);
	while (pbms[idx]) {
		if (j == 0)
			pr_warn("PRIQ: PBM Hash Collision\n");

		idx = (idx + 1) & MAX_PBMS_MASK;

		if (j++ >= MAX_PBMS) {
			pr_err("PRIQ: Too many root Complexes\n");
			spin_unlock_irqrestore(&priq_pbm_tbl_lock, flags);
			return -ENODEV;
		}
	}

	pbms[idx] = pbm;

	spin_unlock_irqrestore(&priq_pbm_tbl_lock, flags);
	return 0;
}

static unsigned int priq_hash_value(unsigned int devhandle, unsigned int bdf,
				    unsigned int msidata)
{
	unsigned long bits = ((unsigned long)devhandle << 44) |
			     ((unsigned long)msidata << 16) | RID(bdf);
	unsigned int hash_value = hash_64(bits, PRIQ_HASH_BITS);

	return hash_value;
}

static void priq_hash_add(struct priq_irq *priq_irq, int node)
{
	if (priq_irq->bdf != BDF_INTX) {
		struct pci_pbm_info *pbm;

		pbm = priq_dhndl_to_pbm(priq_irq->devhandle);
		if (!pbm) {
			priqdbg("Cannot add priq_irq to tbl\n");
			return;
		}

		pbm->msi_priq[priq_irq->msidata - pbm->msi_first] = priq_irq;

	} else {
		unsigned int hash_value;
		struct list_head *head;
		unsigned long flags;

		hash_value = priq_hash_value(priq_irq->devhandle, priq_irq->bdf,
					     priq_irq->msidata);

		head = &priq_hash[0][hash_value];

		spin_lock_irqsave(&priq_hash_node_lock, flags);
		list_add_rcu(&priq_irq->list, head);
		spin_unlock_irqrestore(&priq_hash_node_lock, flags);
	}
}

static void priq_hash_del(struct priq_irq *priq_irq)
{
	if (priq_irq->bdf != BDF_INTX) {
		struct pci_pbm_info *pbm;

		pbm = priq_dhndl_to_pbm(priq_irq->devhandle);
		if (!pbm) {
			priqdbg("Cannot rm priq_irq from tbl\n");
			return;
		}

		pbm->msi_priq[priq_irq->msidata - pbm->msi_first] = 0;

	} else {
		unsigned long flags;

		spin_lock_irqsave(&priq_hash_node_lock, flags);
		list_del_rcu(&priq_irq->list);
		spin_unlock_irqrestore(&priq_hash_node_lock, flags);
	}
}

static unsigned int priq_bdf(struct pci_dev *pdev)
{
	unsigned int device = PCI_SLOT(pdev->devfn);
	unsigned int func = PCI_FUNC(pdev->devfn);
	struct pci_bus *bus_dev = pdev->bus;
	unsigned int bus = bus_dev->number;

	return (pci_domain_nr(bus_dev) << 16) | BDF(bus, device, func);
}

static int priq_irq_get_strand(int node)
{
	cpumask_t *nodemask = cpumask_of_node(node);
	static int last_strand;
	cpumask_t tmp;

	cpumask_and(&tmp, nodemask, &priq_cpu_mask);

	if (cpumask_empty(&tmp)) {
		last_strand = cpumask_first(&priq_cpu_mask);
	} else {
		last_strand = cpumask_next(last_strand, &tmp);
		if (last_strand >= nr_cpu_ids)
			last_strand = cpumask_first(&tmp);
	}

	return last_strand;
}

static int priq_msi_setup(unsigned int *irqp, struct pci_dev *pdev,
			  struct msi_desc *entry)
{
	struct pci_pbm_info *pbm = get_pbm(pdev);
	struct priq_irq *priq_msi;
	struct msi_msg msg;
	int msi, irq;
	int strand;
	int node;

	node = pbm->numa_node;
	strand = priq_irq_get_strand(node);

	if (unlikely(strand >= nr_cpu_ids))
		goto out;

	/* if node was -1, it is now >= 0 or if all strands in original are
	 * offline and a different node gets chosen, it will come back correct.
	 */
	node = cpu_to_node(strand);

	irq = irq_alloc_descs(-1, 1, 1, node);
	if (irq <= 0)
		goto out;

	priq_msi = kzalloc_node(sizeof(*priq_msi), GFP_ATOMIC, node);
	if (!priq_msi)
		goto out_free_irq;

	msi = sparc64_pbm_alloc_msi(pbm);
	if (msi < 0)
		goto out_free_mem;

	priq_msi->strand = strand;
	priq_msi->devhandle = pbm->devhandle;
	priq_msi->msidata = msi;
	priq_msi->irq = irq;
	priq_msi->bdf = priq_bdf(pdev);

	/* Some of this is duplicated from pci_msi.c and should be unified. */
	if (entry->msi_attrib.is_64) {
		msg.address_hi = pbm->msi64_start >> 32;
		msg.address_lo = pbm->msi64_start & 0xffffffff;
	} else {
		msg.address_hi = 0;
		msg.address_lo = pbm->msi32_start;
	}
	msg.data = msi;

	irq_set_msi_desc(irq, entry);
	write_msi_msg(irq, &msg);

	/* Now set up chip handler name and chip handler data. */
	irq_set_chip_and_handler_name(irq, &priq_msi_chip, handle_simple_irq,
				      "PRIQ");
	irq_set_handler_data(irq, priq_msi);

	/* The MSI is not bound to a priq yet.  */
	priq_hash_add(priq_msi, node);

	return 0;

out_free_mem:
	kfree(priq_msi);
out_free_irq:
	irq_free(irq);
out:
	return -ENOMEM;
}

static void priq_msi_teardown(unsigned int irq, struct pci_dev *pdev)
{
	struct pci_pbm_info *pbm = get_pbm(pdev);
	struct priq_irq *priq_msi = irq_get_handler_data(irq);
	unsigned long hverror;
	char buf[16];

	hverror = pci_priq_msi_unbind(pbm->devhandle, priq_msi->msidata,
				      RID(priq_msi->bdf));
	if (hverror && hverror != HV_EUNBOUND)
		priqdbg("msi_unbind failed: %ld, dh: 0x%03x, pci: %s, 0x%x\n",
			hverror, pbm->devhandle,
			BDF2str(buf, 16, priq_msi->bdf), priq_msi->msidata);

	priq_hash_del(priq_msi);
	synchronize_rcu();

	sparc64_pbm_free_msi(pbm, priq_msi->msidata);
	irq_set_chip(irq, NULL);
	irq_set_handler_data(irq, NULL);
	irq_free_desc(irq);
	kfree(priq_msi);
}

/* priq msi record root complex(rc) devhandle.*/
static unsigned int priq_pci_record_dhndl(unsigned long word4)
{
	static const unsigned long rc_mask = 0xffffffff00000000UL;
	static const unsigned int rc_shift = 32U;
	unsigned int rc;

	rc = (word4 & rc_mask) >> rc_shift;
	return rc;
}

/* priq msi record pci msidata (msi).*/
static unsigned int priq_pci_record_msidata(unsigned long word6)
{
	static const unsigned int msidata_mask = 0xffffffffU;
	unsigned int msidata = word6 & msidata_mask;

	return msidata;
}

/* priq msi record pci bdf(rid).*/
static unsigned int priq_pci_record_bdf(unsigned long word4)
{
	unsigned int bdf = word4 & 0xffffU;

	return bdf;
}

static void priq_msi_dump_record(const char *reason, void *entry)
{
	if (priq_debug) {
		unsigned long *word = entry;

		pr_err("%s: %s\n", __func__, reason);
		pr_err("word0=0x%.16lx word1=0x%.16lx word2=0x%.16lx word3=0x%.16lx\n",
		       word[0], word[1], word[2], word[3]);
		pr_err("word4=0x%.16lx word5=0x%.16lx word6=0x%.16lx word7=0x%.16lx\n",
		       word[4], word[5], word[6], word[7]);
	}
}

static void priq_msi_idle(struct priq_irq *priq_msi)
{
	unsigned long hverror;
	char buf[16];

	hverror = pci_priq_msi_setstate(priq_msi->devhandle, priq_msi->msidata,
					RID(priq_msi->bdf), HV_MSISTATE_IDLE);
	if (hverror)
		priqdbg("Failed to set msi to idle. err: %ldi, pci: %s, 0x%x\n",
			hverror, BDF2str(buf, 16, priq_msi->bdf),
			priq_msi->msidata);
}

#define PRIQ_TYPE_MASK		0xffUL
#define	PRIQ_TYPE_MESSAGE	0x01UL
#define	PRIQ_TYPE_MSI32		0x02UL
#define	PRIQ_TYPE_MSI64		0x03UL
#define	PRIQ_TYPE_INTX		0x08UL
#define PRIQ_TYPE_ERROR		0x0fUL

static void process_priq_record(void *entry, int type,
				struct priq_irq *priq_irq)
{
	unsigned long hverror;
	unsigned long intx;

	switch (type) {
	case PRIQ_TYPE_MSI32:
	case PRIQ_TYPE_MSI64:
		priq_msi_idle(priq_irq);
		generic_handle_irq(priq_irq->irq);
		break;

	case PRIQ_TYPE_INTX:
		intx = priq_irq_to_intx(priq_irq);

		hverror = pci_priq_intx_setstate(priq_irq->devhandle, intx,
						 HV_PCI_INTX_CLEAR);
		if (hverror)
			priqdbg("intx_setstate failed. err: %ld, intx: %lu dh: 0x%03x\n",
				hverror, intx, priq_irq->devhandle);

		generic_handle_irq(priq_irq->irq);
		break;
	}
}

static void priq_msi_consume(struct priq *priq, void *entry)
{
	/* PRIQ PCI record.*/
	struct priq_pci_msi_record {
		unsigned long word0;	/* reserved | type */
		unsigned long word1;
		unsigned long word2;
		unsigned long word3;
		unsigned long word4;	/* devhandle | reserved | rid	*/
		unsigned long word5;
		unsigned long word6;	/* msidata			*/
		unsigned long word7;
	} *rec = entry;

	unsigned int msidata = priq_pci_record_msidata(rec->word6);
	unsigned int bdf     = priq_pci_record_bdf(rec->word4);
	unsigned int dhndl   = priq_pci_record_dhndl(rec->word4);
	unsigned long type   = rec->word0 & PRIQ_TYPE_MASK;

	struct priq_irq *priq_irq;


	if (likely(type == PRIQ_TYPE_MSI64 || type == PRIQ_TYPE_MSI32)) {
		struct pci_pbm_info *pbm;

		pbm = priq_dhndl_to_pbm(dhndl);
		if (likely(pbm)) {
			priq_irq = pbm->msi_priq[msidata - pbm->msi_first];
			process_priq_record(entry, type, priq_irq);
		}

		return;

	} else if (type == PRIQ_TYPE_INTX) {
		unsigned int hash_value = msidata;
		struct list_head *head;
		bool found = false;

		head = &priq->hash[hash_value];

		rcu_read_lock();
		list_for_each_entry_rcu(priq_irq, head, list) {
			if (priq_irq->devhandle == dhndl &&
			    RID(priq_irq->bdf) == bdf &&
			    priq_irq->msidata == msidata) {
				found = true;
				break;
			}
		}
		rcu_read_unlock();

		if (found)
			process_priq_record(entry, type, priq_irq);
		else
			priq_msi_dump_record("No PRIQ MSI Record.", entry);

	} else {
		priq_msi_dump_record("Type not supported yet", entry);
	}
}

static unsigned long priq_disable_ie(void)
{
	unsigned long pstate;

	__asm__ __volatile__("rdpr %%pstate,%0\n\t"
			     "wrpr %0, %1, %%pstate\n\t"
			     : "=&r" (pstate)
			     : "i" (PSTATE_IE));

	return pstate;
}

static void priq_enable_ie(unsigned long pstate)
{
	__asm__ __volatile__("wrpr %0, 0, %%pstate\n\t"
			     : /* no outputs */
			     : "r" (pstate));
}

static unsigned long eq_distance(struct priq *priq, unsigned long head,
				 unsigned long tail)
{
	unsigned long distance;

	if (head > tail) {
		unsigned long eq_mask = ~priq_size_mask(priq);
		unsigned long eq_size = eq_mask + 1UL;

		distance = eq_size - head + tail;
	} else {
		distance = tail - head;
	}

	return distance;
}

static unsigned long eq_distance_percpu(struct priq *priq)
{
	unsigned long distance = eq_distance(priq, priq->head, priq->tail);

	return distance;
}

static void handle_priq(struct priq *priq)
{
	unsigned long head, tail, hverror, pstate;
	unsigned long raddr = priq_to_raddr(priq);
	unsigned long mask = priq_size_mask(priq);
	bool nested;

	hverror = priq_get_head_tail(priq->id, &head, &tail);
	if (unlikely(hverror)) {
		priqdbg("failed priq_get_head_tail(%ld).\n", hverror);
		return;
	}

	/* this function is currently called for every interrupt, many not
	 * PRIQ related
	 */
	if (head == tail)
		return;

	pstate = priq_disable_ie();

	/* when we are done processing prior interrupts, these should be equal
	 * in which case we are NOT nested.
	 */
	if (likely(priq->head == priq->tail)) {
		nested = false;
		priq->tail = tail;

	} else {
		nested = true;

		/* see if number of records to process has increased */
		if (eq_distance(priq, head, tail) > eq_distance_percpu(priq))
			priq->tail = tail;
	}

	priq_enable_ie(pstate);

	if (unlikely(nested)) {
		priqdbg("Bailed on nested interrupt\n");
		return;
	}

	while (1) {
		while (likely(head != tail)) {
			void *entry = __va(raddr + head);

			priq_msi_consume(priq, entry);
			head = (head + PRIQ_EQ_SIZE) & ~mask;
		}

		pstate = priq_disable_ie();

		/* have we taken a new nested interrupt increasing the amount
		 * of work. if so, lets keep going
		 */
		if (likely(tail == priq->tail))
			break;

		tail = priq->tail;
		priq_enable_ie(pstate);
	}

	hverror = priq_set_head(priq->id, head);
	priq->head = head;

	BUG_ON(priq->head != priq->tail);
	priq_enable_ie(pstate);

	if (unlikely(hverror))
		priqdbg("Failed priq_set_head: %ld\n", hverror);
}

/* We have at most one priq per cpu for now.*/
void cpu_handle_priqs(void)
{
	struct priq *priq = &get_cpu_var(current_priq);

	if (priq_active(priq))
		handle_priq(priq);

	put_cpu_var(current_priq);
}

static unsigned int priq_coarse_mask;
static bool priq_enabled = true;

static void __init early_priq_coarse(void)
{
	static const unsigned int strands_per_core_shift = 3U;

	priq_coarse_mask = ~((1U << strands_per_core_shift) - 1U);
}

static bool can_cpu_have_priq(int cpu)
{
	int weight;

	if (priq_coarse_mask) {
		weight = num_online_cpus();
		if ((weight > 1) && (cpu & ~priq_coarse_mask))
			return false;
	}

	return true;
}

/* For now leave size at a PAGE_SIZE which is 1UL << (13-6) eq entries.
 * For nr_cpu small a large size might be desirable when MR supports,
 * which MR does.
 */
static bool priq_eq_max;
static size_t compute_cpu_priq_size(int cpu)
{
	size_t size;

	if ((nr_cpu_ids == 1) || !pci_msi_enabled() || priq_eq_max)
		size = priq_eq_max_num_entries << PRIQ_EQ_SIZE_SHIFT;
	else
		size = PAGE_SIZE;

	return size;
}

static int __init early_priq(char *p)
{
	while (p) {
		char *k = strchr(p, ',');

		if (k)
			*k++ = 0;

		if (*p) {
			if (!strcmp(p, "max"))
				priq_eq_max = true;
			else if (!strcmp(p, "coarse"))
				early_priq_coarse();
			else if (!strcmp(p, "off"))
				priq_enabled = false;
			else if (!strcmp(p, "dbg")) {
				priq_debug = true;
				priqdbg("PRIQ: debugging enabled.\n");
			}
		}

		p = k;
	}
	return 0;
}

early_param("priq", early_priq);

/* Here we can decide whether a cpu will have a priq.*/
static size_t priq_size_for_cpu(int cpu)
{
	int cpu_priq_possible = can_cpu_have_priq(cpu);
	size_t priq_size = 0UL;

	if (cpu_priq_possible)
		priq_size = compute_cpu_priq_size(cpu);
	return priq_size;
}

/* The priq will be numa affined and the EQ entries will be too. Should
 * there be failure then the cpu will not be considered a member of priq
 * online strands(cpus).
 */
void priq_percpu_setup(int cpu)
{
	struct priq *priq = &per_cpu(current_priq, cpu);
	unsigned long raddr, hverror, id, nentries;
	int node = cpu_to_node(cpu);
	unsigned int order;
	struct page *pages;
	size_t size;

	if (!priq_configured)
		goto out;

	size = priq_size_for_cpu(cpu);
	if (!size)
		goto out;

	order = get_order(size);
	nentries = size >> PRIQ_EQ_SIZE_SHIFT;

	pages = alloc_pages_exact_node(node, GFP_ATOMIC, order);
	if (!pages)
		goto out1;

	raddr = page_to_phys(pages);

	id = priq_conf(PRIQ_CPU, cpu, raddr, nentries);
	if ((long)id < 0) {
		long hverror = -id;

		priqdbg("priq_conf failed: %ld, cpu(%d)\n", hverror, cpu);
		goto out2;
	}

	hverror = priq_bind(id, cpu, PIL_DEVICE_IRQ);
	if (hverror) {
		priqdbg("priq_bind(id=%lx) failed: %ld, cpu(%d)\n", id, hverror,
			cpu);
		goto out3;
	}

	raddr_order_to_priq(priq, raddr, order);
	priq->id = id;

	/* The initialization order is important because hash is true active.*/
	priq->hash = priq_hash[node];

	/* Mark the cpu and its associated priq online. Now binding can occur
	 * for PRIQ MSI.
	 */
	cpumask_set_cpu_priq(cpu);
	goto out;

out3:
	hverror = priq_unconf(id);
	if (hverror)
		priqdbg("priq_unconf(%ld) failed: %ld\n", id, hverror);
out2:
	free_pages((unsigned long)__va(raddr), order);
out1:
	priqdbg("Failed to allocate priq for cpu(%d)\n", cpu);
out:
	return;
}


static void unbind_all_msi_on_priq(int cpu, struct priq *priq)
{
	struct irq_desc *desc;
	int irq;

	for_each_irq_desc(irq, desc) {
		struct irq_chip *chip = irq_desc_get_chip(desc);
		struct priq_irq *priq_irq;

		if (chip != &priq_msi_chip && chip != &priq_intx_chip)
			continue;

		priq_irq = irq_desc_get_handler_data(desc);
		if (priq_irq->strand != cpu)
			continue;

		priq_irq_bind_eqcb(priq_irq, &priq_cpu_mask);
	}
}

void priq_percpu_destroy(int cpu)
{
	struct priq *priq = &per_cpu(current_priq, cpu);
	unsigned long hverror;
	unsigned long raddr;
	unsigned int order;

	if (!priq_active(priq))
		return;

	cpumask_clear_cpu_priq(cpu);

	unbind_all_msi_on_priq(cpu, priq);

	hverror = priq_unbind(priq->id);
	if (hverror) {
		priqdbg("priq_unbind failed. err: %ld, id: %lu\n", hverror,
			priq->id);
		return;
	}

	hverror = priq_unconf(priq->id);
	if (hverror) {
		priqdbg("priq_unconf failed. err: %ld, cpu=%d, id: %lu\n",
			hverror, cpu, priq->id);
		return;
	}

	raddr = priq_to_raddr(priq);
	order = priq_to_order(priq);

	free_pages((unsigned long)__va(raddr), order);
	priq->c_raddr = 0UL;
	priq->hash = NULL;
}

static int cpu_notify_callback(struct notifier_block *nfb, unsigned long action,
			       void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;

	switch (action) {
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		if (!cpumask_test_cpu(cpu, &priq_cpu_mask))
			priq_percpu_setup(cpu);
		break;

	case CPU_DOWN_PREPARE:
	case CPU_DOWN_PREPARE_FROZEN:
		if (cpumask_test_cpu(cpu, &priq_cpu_mask))
			priq_percpu_destroy(cpu);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block priq_cpu_notifier = {
	.notifier_call = cpu_notify_callback,
};

void __init sun4v_priq(void)
{
	int cpu = raw_smp_processor_id();
	unsigned long major = 1UL;
	unsigned long minor = 1UL;
	int group_rc, rc;

	if (tlb_type != hypervisor)
		return;

	if (!priq_enabled) {
		pr_info("PRIQ: Available but disabled by priq=off\n");
		return;
	}

	rc = priq_get_properties();
	if (rc)
		return;

	/* Register the HV groups.*/
	group_rc = sun4v_hvapi_register(HV_GRP_PRIQ, major, &minor);
	if (group_rc) {
		priqdbg("Failed to register HV_GRP_PRIQ(%d)\n", group_rc);
		return;
	}

	minor = 1UL;
	group_rc = sun4v_hvapi_register(HV_GRP_PRIQ_PCI, major, &minor);
	if (group_rc) {
		priqdbg("Failed to register HV_GRP_PRIQ_PCI(%d).\n", group_rc);
		return;
	}

	if (priq_hash_nodes_init())
		return;

	priq_configured = true;
	priq_percpu_setup(cpu);

	register_cpu_notifier(&priq_cpu_notifier);
}

int pci_sun4v_priq_msi_init(struct pci_pbm_info *pbm)
{
	int err;

	if (!priq_configured)
		return -ENODEV;

	err = priq_add_pbm_tbl(pbm);
	if (err)
		return err;

	pci_priq_msi_init(pbm);

	pbm->setup_msi_irq = priq_msi_setup;
	pbm->teardown_msi_irq = priq_msi_teardown;

	pr_info("PRIQ: Enabled Root Complex = 0x%03x node=%d.\n",
		pbm->devhandle, pbm->numa_node);
	return 0;
}

static int intx_shared(unsigned int rc, unsigned int msidata, int node)
{
	unsigned short bdf = BDF_INTX;
	unsigned int hash_value = priq_hash_value(rc, bdf, msidata);
	struct list_head *head = &priq_hash[node][hash_value];
	struct priq_irq *priq_irq;
	int irq = -1;

	list_for_each_entry_rcu(priq_irq, head, list) {
		if (priq_irq->devhandle == rc && priq_irq->bdf == bdf &&
			priq_irq->msidata == msidata) {
			irq = priq_irq->irq;
			break;
		}
	}

	return irq;
}

static int setup_priq_intx_irq(unsigned int devhandle, unsigned int devino,
			       int node)
{
	unsigned int intx = devino - 1U;
	unsigned short bdf = BDF_INTX;
	unsigned int msidata = intx;
	struct priq_irq *priq_irq;
	int strand;
	int irq;

	strand = priq_irq_get_strand(node);

	/* strand may not be on requested node or node might have been -1 */
	node = cpu_to_node(strand);

	irq = intx_shared(devhandle, msidata, node);
	if (irq > 0)
		return irq;

	irq = irq_alloc_descs(-1, 1, 1, node);
	if (irq <= 0)
		return irq;

	priq_irq = kzalloc_node(sizeof(*priq_irq), GFP_ATOMIC, node);
	if (!priq_irq) {
		priqdbg("Failed to allocate legacy priq_irq\n");
		irq_free(irq);
		return -1;
	}

	priq_irq->strand = strand;

	priq_irq->devhandle = devhandle;
	priq_irq->msidata = msidata;
	priq_irq->irq = irq;
	priq_irq->bdf = bdf;

	irq_set_chip_and_handler_name(irq, &priq_intx_chip, handle_simple_irq,
				      "PRIQ");
	irq_set_handler_data(irq, priq_irq);

	priq_hash_add(priq_irq, cpu_to_node(priq_irq->strand));

	pr_info("PRIQ: %s: devhandle=0x%x devino=0x%x node=%d irq=%d.\n",
		__func__, devhandle, devino, node, irq);

	return irq;
}

/* We will drop 0x3f (IOS_PEU_ERR_DEVINO) and 0x3e (IOS_DMU_ERR_DEVINO).
 */
int pci_priq_build_irq(unsigned int devhandle, unsigned int devino)
{
	int irq = -1;
	int node;

	if (!priq_configured)
		return 0;

	if (!(1 <= devino && devino <= 4))
		return irq;

	/* These INT-A ... INT-D are shared line interrupts for which the
	 * performance ramifications greatly exceed the advantages of exact node
	 * placement. As this function is called prior to PCI root complex
	 * structure creation, exact node calculations are ugly.
	 */
	node = -1;

	irq = setup_priq_intx_irq(devhandle, devino, node);

	return irq;
}

void dump_priq_info(void)
{
	char buf[256];
	int cpu, weight;

	scnprintf(buf, sizeof(buf), "%pb", &priq_cpu_mask);
	weight = cpumask_weight(&priq_cpu_mask);

	pr_info("%s: strand priq active(%d), %s\n", __func__, weight, buf);

	for_each_online_cpu(cpu) {
		struct priq *priq = &per_cpu(current_priq, cpu);
		unsigned long raddr = priq_to_raddr(priq);
		unsigned long mask = priq_size_mask(priq);

		pr_info("cpu=%d priq id=0x%lx raddr=0x%lx mask=0x%lx hash=%p\n",
			cpu, priq->id, raddr, mask, priq->hash);
	}
}
