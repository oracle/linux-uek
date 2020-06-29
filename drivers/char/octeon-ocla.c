/*************************************************************************
 *
 * Author: Cavium Inc.
 *
 * Contact: support@cavium.com
 * This file is part of the OCTEON SDK
 *
 * Copyright (c) 2010 - 2014 Cavium, Inc.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, Version 2, as
 * published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but
 * AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
 * NONINFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 * or visit http://www.gnu.org/licenses/.
 *
 * This file may also be available under a different license from Cavium.
 * Contact Cavium, Inc. for more information
 *************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/semaphore.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-ocla.h>
#include <asm/octeon/cvmx-oclax-defs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Carlos Munoz <cmunoz@caviumnetworks.com>");
MODULE_DESCRIPTION("Octeon On Chip Logig Analizer driver");
MODULE_SUPPORTED_DEVICE("cn70xx/cn78xx");


/* Dynamic allocation of the major device number */
#define OCLA_MAJOR		0

#define DEVICE_NAME		"octeon-ocla"
#define MAX_OCLA_IRQS		3
#define MAX_CAP_BUF_SIZE	(1024 * 1024 * 100)


/* Ocla comlex states */
enum {
	COMPLEX_INVALID,
	COMPLEX_FREE,
	COMPLEX_IN_USE
};

/*
 * irq_info:			Contains the information needed to handle irqs.
 *
 *  irq:			Virtual irq number.
 *  en:				Irq state: 1=enabled, 0=disabled.
 */
struct irq_info {
	int			irq;
	int			en;
};

/*
 * ocla_complex:		Information needed to manage each ocla complex.
 *
 *  node:			Node the ocla complex is on.
 *  ix:				Ocla complex index.
 *  state:			Current ocla complex state.
 *  data_avail:			Indicates capture data is available. Set to 1 by
 *				the interrupt handler. Set to 0 by the read
 *				method when all entries have been read.
 *  waitq:			Wait queue to support blocking io.
 *  pdev:			Pointer to platform device structure for this
 *				ocla complex.
 *  lock:			Spin lock.
 *  irqs:			IRQs used by this ocla complex.
 *  vbuf:			Virtual address of capture buffer.
 *  pbuf:			Physical address of capture buffer (cache line
 *				aligned)
 *  rd_line:			Capture buffer address of next cache line to
 *				read.
 *  wr_line:			DDR capture buffer address of next cache line to
 *				be written by ocla hardware.
 *  line_cnt:			Number of capture buffer cache lines processed.
 *  cur_entry:			Next entry within cache line to be processed.
 *  buf_size:			Size of capture buffer.
 */
struct ocla_complex {
	int			node;
	int			ix;
	int			state;
	int			data_avail;
	wait_queue_head_t	waitq;
	struct platform_device	*pdev;
	spinlock_t		lock;
	struct irq_info		irqs[MAX_OCLA_IRQS];
	void			*vbuf;
	uint64_t		pbuf;
	void			*rd_line;
	void			*wr_line;
	int			line_cnt;
	int			cur_entry;
	uint			buf_size;
};

/*
 * ddr_line:			Format of the cache line worth of entries.
 *
 *  timestamp:			Time at which the entry was written.
 *  rsvd:			Not used.
 *  entry0..25:			The 26 entries.
 */
struct ddr_line {
#ifdef __BIG_ENDIAN_BITFIELD
	uint64_t		entry25:38;
	uint64_t		entry24:38;
	uint64_t		entry23:38;
	uint64_t		entry22:38;
	uint64_t		entry21:38;
	uint64_t		entry20:38;
	uint64_t		entry19:38;
	uint64_t		entry18:38;
	uint64_t		entry17:38;
	uint64_t		entry16:38;
	uint64_t		entry15:38;
	uint64_t		entry14:38;
	uint64_t		entry13:38;
	uint64_t		entry12:38;
	uint64_t		entry11:38;
	uint64_t		entry10:38;
	uint64_t		entry9:38;
	uint64_t		entry8:38;
	uint64_t		entry7:38;
	uint64_t		entry6:38;
	uint64_t		entry5:38;
	uint64_t		entry4:38;
	uint64_t		entry3:38;
	uint64_t		entry2:38;
	uint64_t		entry1:38;
	uint64_t		entry0:38;
	uint64_t		rsvd:4;
	uint64_t		timestamp:32;
#else
	uint64_t		timestamp:32;
	uint64_t		rsvd:4;
	uint64_t		entry0:38;
	uint64_t		entry1:38;
	uint64_t		entry2:38;
	uint64_t		entry3:38;
	uint64_t		entry4:38;
	uint64_t		entry5:38;
	uint64_t		entry6:38;
	uint64_t		entry7:38;
	uint64_t		entry8:38;
	uint64_t		entry9:38;
	uint64_t		entry10:38;
	uint64_t		entry11:38;
	uint64_t		entry12:38;
	uint64_t		entry13:38;
	uint64_t		entry14:38;
	uint64_t		entry15:38;
	uint64_t		entry16:38;
	uint64_t		entry17:38;
	uint64_t		entry18:38;
	uint64_t		entry19:38;
	uint64_t		entry20:38;
	uint64_t		entry21:38;
	uint64_t		entry22:38;
	uint64_t		entry23:38;
	uint64_t		entry24:38;
	uint64_t		entry25:38;
#endif
} __packed __aligned(128);


static int ocla_major = OCLA_MAJOR;
static DEFINE_SEMAPHORE(complexes_sem);
static struct ocla_complex ocla_complexes[CVMX_MAX_NODES][MAX_COMPLEXES] = {
	{ {.state = COMPLEX_INVALID}, {.state = COMPLEX_INVALID},
	  {.state = COMPLEX_INVALID}, {.state = COMPLEX_INVALID},
	  {.state = COMPLEX_INVALID} },
	{ {.state = COMPLEX_INVALID}, {.state = COMPLEX_INVALID},
	  {.state = COMPLEX_INVALID}, {.state = COMPLEX_INVALID},
	  {.state = COMPLEX_INVALID} }
};

/*
 * Process ocla interrutps.
 * This handler is called either when the stop trigger occurs or when the
 * capture buffer fills. It disables the interrupt and wakes up any blocked
 * readers.
 *
 *  irq:			Interrupt to process.
 *  dev_id:			Pointer to ocla complex.
 *
 *  returns:			Indication interrupt was handled.
 */
static irqreturn_t  ocla_irq_handler(int	irq,
				     void	*dev_id)
{
	struct ocla_complex	*complex = dev_id;
	unsigned long		flags;
	int			i;

	/* Clear the interrupts */
	cvmx_ocla_clear_interrupts(complex->node, complex->ix);

	/* Disable the irq */
	spin_lock_irqsave(&complex->lock, flags);
	disable_irq_nosync(irq);
	for (i = 0; i < MAX_OCLA_IRQS; i++) {
		if (irq == complex->irqs[i].irq) {
			complex->irqs[i].en = 0;
			break;
		}
	}
	complex->data_avail = 1;
	spin_unlock_irqrestore(&complex->lock, flags);

	wake_up_interruptible(&complex->waitq);

	return IRQ_HANDLED;
}

/*
 * Read an entry from the ddr buffer.
 *
 *  complex:			Ocla complex.
 *  data:			Updated with entry read.
 *
 *  returns:			Entry.
 */
static uint64_t get_entry_from_line(struct ddr_line	*line,
				    int			entry_ix)
{
	uint64_t	data;

	switch (entry_ix) {
	case 0:
		data = line->entry0;
		break;
	case 1:
		data = line->entry1;
		break;
	case 2:
		data = line->entry2;
		break;
	case 3:
		data = line->entry3;
		break;
	case 4:
		data = line->entry4;
		break;
	case 5:
		data = line->entry5;
		break;
	case 6:
		data = line->entry6;
		break;
	case 7:
		data = line->entry7;
		break;
	case 8:
		data = line->entry8;
		break;
	case 9:
		data = line->entry9;
		break;
	case 10:
		data = line->entry10;
		break;
	case 11:
		data = line->entry11;
		break;
	case 12:
		data = line->entry12;
		break;
	case 13:
		data = line->entry13;
		break;
	case 14:
		data = line->entry14;
		break;
	case 15:
		data = line->entry15;
		break;
	case 16:
		data = line->entry16;
		break;
	case 17:
		data = line->entry17;
		break;
	case 18:
		data = line->entry18;
		break;
	case 19:
		data = line->entry19;
		break;
	case 20:
		data = line->entry20;
		break;
	case 21:
		data = line->entry21;
		break;
	case 22:
		data = line->entry22;
		break;
	case 23:
		data = line->entry23;
		break;
	case 24:
		data = line->entry24;
		break;
	case 25:
		data = line->entry25;
		break;
	default:
		data = -1;
		break;
	}

	return data;
}

/*
 * Swap a ddr line worth of entries to match the format expected by
 * 'struct ddr_line'.
 *
 *  line:			Pointer to ddr line to swap.
 *
 *  returns:			Zero on success, error otherwise.
 */
static int swap_ddr_line(void	*line)
{
	uint64_t	*ptr;
	uint64_t	tmp;
	int		num_elem;
	int		end_ix;
	int		i;

	num_elem = CVMX_CACHE_LINE_SIZE / sizeof(uint64_t);
	end_ix = num_elem - 1;
	ptr = (uint64_t *)line;

	for (i = 0; i < num_elem / 2; i++, end_ix--) {
		tmp = ptr[i];
		ptr[i] = ptr[end_ix];
		ptr[end_ix] = tmp;
	}

	return 0;
}

/*
 * Get the next entry from the ddr capture buffer.
 *
 *  complex:			Ocla complex.
 *  data:			Updated with entry read.
 *
 *  returns:			Zero on success, error otherwise.
 */
static int get_ddr_buf_entry(struct ocla_complex	*complex,
			     uint64_t			*data)
{
	int	node;
	int	ix;
	void	*ptr;
	int	rc = 0;

	node = complex->node;
	ix = complex->ix;

	/* Check if the buffer has been completetly read */
	if (complex->rd_line == complex->wr_line) {
		/* Read any entries not flushed to the ddr buffer */
		rc = cvmx_ocla_get_packet(node, ix, data);
	} else {
		*data = get_entry_from_line((struct ddr_line *)complex->rd_line,
					    complex->cur_entry);

		complex->cur_entry++;
		if (complex->cur_entry == 26) {
			complex->cur_entry = 0;
			complex->line_cnt++;
			complex->rd_line += CVMX_CACHE_LINE_SIZE;

			ptr = cvmx_phys_to_ptr(complex->pbuf);
			if (complex->rd_line >= ptr + complex->buf_size)
				complex->rd_line = ptr;

			swap_ddr_line(complex->rd_line);
		}
	}

	return rc;
}

/*
 * Read the capture fifo or ddr buffer.
 *
 *  complex:			Ocla complex.
 *  buf:			Buffer to fill with the captured entries.
 *  count:			Size of buf.
 *
 *  returns:			Number of bytes read, or error.
 */
static ssize_t ocla_read_fifo(struct ocla_complex	*complex,
			      char __user		*buf,
			      size_t			count)
{
	ssize_t		read_cnt = 0;
	int		node;
	int		ix;
	uint64_t	data;

	node = complex->node;
	ix = complex->ix;

	/* If a ddr buffer is in used, initialize variables */
	if (complex->vbuf && complex->buf_size && complex->line_cnt == 0) {
		cvmx_oclax_stack_base_t	base;
		cvmx_oclax_stack_cur_t	cur;
		cvmx_oclax_stack_wrap_t	wrap;
		void			*ptr;

		base.u64 = cvmx_read_csr_node(node, CVMX_OCLAX_STACK_BASE(ix));
		cur.u64 = cvmx_read_csr_node(node, CVMX_OCLAX_STACK_CUR(ix));
		wrap.u64 = cvmx_read_csr_node(node, CVMX_OCLAX_STACK_WRAP(ix));

		/* Get the address of the ddr buffer */
		ptr = cvmx_phys_to_ptr(complex->pbuf);

		complex->wr_line = ptr + (cur.u64 - base.u64);
		if (complex->wr_line >= ptr + complex->buf_size) {
			complex->wr_line = ptr + complex->buf_size -
				CVMX_CACHE_LINE_SIZE;
		}

		if (wrap.s.wraps) {
			complex->rd_line = complex->wr_line +
				CVMX_CACHE_LINE_SIZE;
			if (complex->rd_line >= ptr + complex->buf_size)
				complex->rd_line = ptr;
		} else
			complex->rd_line = ptr;

		complex->cur_entry = 0;
		complex->line_cnt = 1;
		swap_ddr_line(complex->rd_line);
	}

	/* Try to read as many entries as possible */
	while (read_cnt <= count - 8) {
		if (complex->vbuf && complex->buf_size) {
			if (get_ddr_buf_entry(complex, &data) < 0)
				break;
		} else {
			if (cvmx_ocla_get_packet(node, ix, &data) < 0)
				break;
		}

		if (copy_to_user(buf + read_cnt, (char *)&data, 8))
			return -EFAULT;
		read_cnt += 8;
	}

	return read_cnt;
}

/*
 * Read captured entries.
 * To keep ocla from interfering with the test, the reader blocks until capture
 * is complete. Once capture completes, the reader is woken up and the captured
 * entries read.
 *
 * Capture is deemed complete when the capture fifo/buffer fills or when the
 * user stops the capture via CTRl_C.
 *
 *  file:			Pointer to file structure.
 *  buf:			Buffer to fill with the captured entries.
 *  count:			Size of buf.
 *  off:			File offset. Updated with amount of data read.
 *
 *  returns:			Number of bytes read, or error.
 */
static ssize_t ocla_read(struct file *file, char __user *buf, size_t count,
			 loff_t *off)
{
	struct ocla_complex	*complex;
	ssize_t			read_cnt = 0;
	unsigned long		flags;
	int			node;
	int			ix;
	int			i;

	complex = (struct ocla_complex *)file->private_data;

	if (count < 8)
		return -EINVAL;

	if (complex == NULL) {
		printk(KERN_ERR "OCLA: Capture is not enabled\n");
		return -EPERM;
	}

	node = complex->node;
	ix = complex->ix;

	/* Block if no data is available */
	if (!complex->data_avail) {
		/* No data available, enable interrupts and wait */
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		spin_lock_irqsave(&complex->lock, flags);
		for (i = 0; i < MAX_OCLA_IRQS; i++) {
			if (!complex->irqs[i].en) {
				enable_irq(complex->irqs[i].irq);
				complex->irqs[i].en = 1;
			}
		}
		spin_unlock_irqrestore(&complex->lock, flags);

		if (wait_event_interruptible(complex->waitq,
					     complex->data_avail == 1)) {
			/*
			 * Interrupted. Disable interrutps and read the entries
			 * captured.
			 */
			spin_lock_irqsave(&complex->lock, flags);
			for (i = 0; i < MAX_OCLA_IRQS; i++) {
				if (!complex->irqs[i].en) {
					disable_irq(complex->irqs[i].irq);
					complex->irqs[i].en = 0;
				}
			}
			spin_unlock_irqrestore(&complex->lock, flags);
			complex->data_avail = 1;
			return -ERESTARTSYS;
		}
	}

	/* Read the fifo/buffer */
	read_cnt = ocla_read_fifo(complex, buf, count);

	/* Indicate no more data is available */
	if (!read_cnt)
		complex->data_avail = 0;

	*off += read_cnt;

	return read_cnt;
}

/*
 * Process a capture request.
 *
 *  file:			Pointer to file structure.
 *  req:			Capture request.
 *
 *  returns:			0 on success, error otherwise.
 */
static long ioctl_cap_req(struct file		*file,
			  struct cap_req	*req)
{
	struct ocla_complex	*complex;

	/* Verify arguments */
	if (req->node >= CVMX_MAX_NODES || req->ix >= MAX_COMPLEXES)
		return -EINVAL;

	if (file->private_data == NULL)
		complex = &ocla_complexes[req->node][req->ix];
	else
		complex = file->private_data;

	/* Make sure complex is available */
	if (complex->state != COMPLEX_FREE)
		return -EBUSY;

	complex->state = COMPLEX_IN_USE;

	if (file->private_data == NULL)
		file->private_data = complex;

	return 0;
}

/*
 * Process a ddr buffer request. Allocate a kernel buffer and return its
 * physical address to the application.
 *
 *  file:			Pointer to file structure.
 *  req:			Capture buffer request.
 *
 *  returns:			0 on success, error otherwise.
 */
static long ioctl_ddr_buf_req(struct file		*file,
			      struct ddr_buf_req	*req)
{
	struct ocla_complex	*complex;
	uint64_t		ptr;

	/* Verify arguments */
	if (req->node >= CVMX_MAX_NODES || req->ix >= MAX_COMPLEXES ||
	    req->size > MAX_CAP_BUF_SIZE ||
	    req->size & (CVMX_CACHE_LINE_SIZE - 1))
		return -EINVAL;

	if (file->private_data == NULL)
		complex = &ocla_complexes[req->node][req->ix];
	else
		complex = file->private_data;

	/* Make sure complex is available */
	if (complex->state != COMPLEX_FREE)
		return -EBUSY;

	/*
	 * Allocate the caputure buffer, if not already. Must be cache line
	 * aligned.
	 */
	if (complex->vbuf == NULL) {
		complex->vbuf = kzalloc_node(req->size + CVMX_CACHE_LINE_SIZE,
					     GFP_ATOMIC, complex->node);
		ptr = (((uint64_t)complex->vbuf + CVMX_CACHE_LINE_SIZE - 1) &
		       ~(CVMX_CACHE_LINE_SIZE - 1));
		complex->pbuf = cvmx_ptr_to_phys((void *)ptr);
		complex->buf_size = req->size;
	}
	req->pbuf = complex->pbuf;

	if (file->private_data == NULL)
		file->private_data = complex;

	return 0;
}

/*
 * Process ioctl commands.
 *
 *  file:			Pointer to file structure.
 *  cmd:			Ioctl command.
 *  arg:			Ioctl command argument.
 *
 *  returns:			0 on success, error otherwise.
 */
static long ocla_ioctl(struct file	*file,
		       unsigned int 	cmd,
		       unsigned long	arg)
{
	struct cap_req		req;
	struct ddr_buf_req	breq;
	long			rc = 0;

	switch (cmd) {
	case OCLA_CAP_REQ:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		rc = ioctl_cap_req(file, &req);
		break;

	case OCLA_DDR_BUF_REQ:
		if (copy_from_user(&breq, (void __user *)arg, sizeof(breq)))
			return -EFAULT;

		rc = ioctl_ddr_buf_req(file, &breq);

		if (copy_to_user((void __user *)arg, &breq, sizeof(breq)))
			rc = -EFAULT;
		break;

	default:
		pr_err("OCLA: Invalid ioctl cmd [%d]\n", _IOC_NR(cmd));
		rc = -EINVAL;
		break;
	}

	return rc;
}

/*
 * Open file request.
 *
 *  inode:			Pointer to inode structure.
 *  file:			Pointer to file structure.
 *
 *  returns:			0 on success, error otherwise.
 */
static int ocla_open(struct inode	*inode,
		     struct file	*file)
{
	/* No ocla complex currently in use */
	file->private_data = NULL;

	return 0;
}

/*
 * Close file request.
 *
 *  inode:			Pointer to inode structure.
 *  file:			Pointer to file structure.
 *
 *  returns:			0 on success, error otherwise.
 */
static int ocla_release(struct inode *inode, struct file *file)
{
	struct ocla_complex	*complex;
	unsigned long		flags;

	complex = (struct ocla_complex *)file->private_data;

	if (complex) {
		int	i;

		/* Disable the interrupts */
		spin_lock_irqsave(&complex->lock, flags);
		for (i = 0; i < MAX_OCLA_IRQS; i++) {
			if (complex->irqs[i].en) {
				disable_irq(complex->irqs[i].irq);
				complex->irqs[i].en = 0;
			}
		}
		complex->data_avail = 0;
		spin_unlock_irqrestore(&complex->lock, flags);

		/* Free the capture buffer if available */
		if (complex->vbuf) {
			kfree(complex->vbuf);
			complex->vbuf = NULL;
			complex->pbuf = 0;
			complex->line_cnt = 0;
			complex->buf_size = 0;
		}

		complex->state = COMPLEX_FREE;
	}

	return 0;
}

/*
 * Probe the ocla complex specified in pdev.
 *
 *  pdev:			Pointer to platform_device structure.
 *
 *  returns:			0 on success, error otherwise.
 */
static int ocla_probe(struct platform_device *pdev)
{
	struct ocla_complex	*complex;
	const __be32		*zero_addr;
	const u32		*reg;
	u64			base_addr;
	int			node;
	int			ix;
	struct resource		*res;
	int			irq;
	unsigned long		flags;
	int			i;
	int			j;
	int			rc = -1;

	/* Get the node this complex is on */
	zero_addr = of_get_address(pdev->dev.of_node, 0, NULL, NULL);
	base_addr = of_translate_address(pdev->dev.of_node, zero_addr);
	base_addr = (u64)phys_to_virt(base_addr);
	node = (base_addr >> 36) & 3;

	/* Get the index of the ocla complex being initialized */
	reg = of_get_property(pdev->dev.of_node, "reg", NULL);
	if (!reg) {
		printk(KERN_ERR "ocla: No 'reg' property, aborting\n");
		return -ENODEV;
	}
	ix = (reg[1] >> 24) & 7;

	/* Initialize the ocla complex information */
	complex = &ocla_complexes[node][ix];
	platform_set_drvdata(pdev, complex);
	complex->node = node;
	complex->ix = ix;
	complex->state = COMPLEX_FREE;
	complex->data_avail = 0;
	init_waitqueue_head(&complex->waitq);
	complex->pdev = pdev;
	spin_lock_init(&complex->lock);
	complex->vbuf = NULL;
	complex->pbuf = 0;
	complex->line_cnt = 0;
	complex->buf_size = 0;

	/* Register the interrupt handlers */
	for (i = 0; i < pdev->num_resources; i++) {
		if ((res = platform_get_resource(pdev, IORESOURCE_IRQ, i))) {
			irq = irq_of_parse_and_map(pdev->dev.of_node, i);
			if (irq) {
				if ((rc = request_irq(irq, ocla_irq_handler, 0,
						      DEVICE_NAME, complex))) {
					printk(KERN_ERR "ocla: failed to "
					       "request irq\n");
					for (j = 0; j < i; j++)
						free_irq(complex->irqs[j].irq,
							 complex);
					return rc;
				}
				complex->irqs[i].irq = irq;

				/*
				 * Interrupts are disabled until we have a
				 * reader. The reader will enable interrupts
				 * before blocking.
				 */
				spin_lock_irqsave(&complex->lock, flags);
				disable_irq(irq);
				complex->irqs[i].en = 0;
				spin_unlock_irqrestore(&complex->lock, flags);
			}
		}
	}

	return 0;
}

/*
 * Remove ocla complex specified in pdev.
 *
 *  pdev:			Pointer to platform_device structure.
 *
 *  returns:			0 on success, error otherwise.
 */
static int ocla_remove(struct platform_device *pdev)
{
	struct ocla_complex	*complex;
	int			i;

	complex = platform_get_drvdata(pdev);
	for (i = 0; i < MAX_OCLA_IRQS; i++)
		free_irq(complex->irqs[i].irq, complex);

	return 0;
}

static const struct file_operations ocla_fops = {
	.open		= ocla_open,
	.unlocked_ioctl = ocla_ioctl,
	.read		= ocla_read,
	.release	= ocla_release,
};

static const struct of_device_id ocla_of_match_table[] = {
        { .compatible = "cavium,octeon-7130-ocla", },
        {}
};

static struct platform_driver ocla_driver = {
        .probe          = ocla_probe,
        .remove         = ocla_remove,
        .driver         = {
                .owner  = THIS_MODULE,
                .name   = "ocla",
                .of_match_table = ocla_of_match_table,
        },
};

static int __init ocla_init(void)
{
	int	rc;

	/* Register the platform driver */
	if ((rc = platform_driver_register(&ocla_driver))) {
		printk(KERN_ERR "ocla: failed to register platform driver\n");
		return rc;
	}

	/* Register the character device */
	if ((rc = register_chrdev(ocla_major, DEVICE_NAME, &ocla_fops)) < 0) {
		printk(KERN_ERR "ocla: can't register major %d\n", ocla_major);
		platform_driver_unregister(&ocla_driver);
		return rc;
	}
	if (!ocla_major)
		ocla_major = rc;

        return 0;
}

static void __exit ocla_exit(void)
{
        platform_driver_unregister(&ocla_driver);
	unregister_chrdev(ocla_major, DEVICE_NAME);
}

module_init(ocla_init);
module_exit(ocla_exit);
