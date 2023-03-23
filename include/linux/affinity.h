/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _IRQ_AFFINITY_H
#define _IRQ_AFFINITY_H

/* Forward declaration */
struct irq_affinity_desc;

int irq_build_affinity_masks(unsigned int startvec, unsigned int numvecs,
                             unsigned int firstvec,
                             struct irq_affinity_desc *masks);

#endif /* _IRQ_AFFINITY_H */
