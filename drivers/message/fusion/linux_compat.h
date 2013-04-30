/*
 *  linux/drivers/message/fusion/linux_compat.h
 *      For use with LSI PCI chip/adapter(s)
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2010 LSI Corporation
 *  (mailto:DL-MPTFusionLinux@lsi.com)
 */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    NO WARRANTY
    THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
    LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
    MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
    solely responsible for determining the appropriateness of using and
    distributing the Program and assumes all risks associated with its
    exercise of rights under this Agreement, including but not limited to
    the risks and costs of program errors, damage to or loss of data,
    programs or equipment, and unavailability or interruption of operations.

    DISCLAIMER OF LIABILITY
    NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
    TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
    HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* drivers/message/fusion/linux_compat.h */
#ifndef FUSION_LINUX_COMPAT_H
#define FUSION_LINUX_COMPAT_H

#include <linux/version.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi.h>
#include <scsi/scsi_transport_sas.h>
#include <linux/blkdev.h>

#ifndef PCI_VENDOR_ID_ATTO
#define PCI_VENDOR_ID_ATTO	0x117c
#endif

#ifndef PCI_VENDOR_ID_BROCADE
#define PCI_VENDOR_ID_BROCADE	0x1657
#endif

/*
 * TODO Need to change 'shost_private' back to 'shost_priv' when suppying patchs
 * upstream.  Since Red Hat decided to backport this to rhel5.2 (2.6.18-92.el5)
 * from the 2.6.23 kernel, it will make it difficult for us to add the proper
 * glue in our driver.
 */
static inline void *shost_private(struct Scsi_Host *shost)
{
        return (void *)shost->hostdata;
}

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(bit_dma) DMA_##bit_dma##BIT_MASK
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18))
static inline unsigned int blk_rq_bytes(const struct request *rq)
{
	return rq->data_len;
}
#endif

#ifndef spi_dv_pending
#define spi_dv_pending(x) (((struct spi_transport_attrs *)&(x)->starget_data)->dv_pending)
#endif
#ifndef	upper_32_bits
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#endif
#ifndef	lower_32_bits
#define lower_32_bits(n) ((u32)(n))
#endif
/**
 * mpt_scsilun_to_int: convert a scsi_lun to an int
 * @scsilun:    struct scsi_lun to be converted.
 *
 * Description:
 *     Convert @scsilun from a struct scsi_lun to a four byte host byte-ordered
 *     integer, and return the result. The caller must check for
 *     truncation before using this function.
 *
 * Notes:
 *     The struct scsi_lun is assumed to be four levels, with each level
 *     effectively containing a SCSI byte-ordered (big endian) short; the
 *     addressing bits of each level are ignored (the highest two bits).
 *     For a description of the LUN format, post SCSI-3 see the SCSI
 *     Architecture Model, for SCSI-3 see the SCSI Controller Commands.
 *
 *     Given a struct scsi_lun of: 0a 04 0b 03 00 00 00 00, this function returns
 *     the integer: 0x0b030a04
 **/
static inline int mpt_scsilun_to_int(struct scsi_lun *scsilun)
{
        int i;
        unsigned int lun;

        lun = 0;
        for (i = 0; i < sizeof(lun); i += 2)
                lun = lun | (((scsilun->scsi_lun[i] << 8) |
                              scsilun->scsi_lun[i + 1]) << (i * 8));
        return lun;
}
#if (defined(CONFIG_SUSE_KERNEL) && !defined(scsi_is_sas_phy_local))
#define SUSE_KERNEL_BASE	1
#endif

#ifndef DID_TRANSPORT_DISRUPTED
#define DID_TRANSPORT_DISRUPTED DID_BUS_BUSY
#endif

/*}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#endif /* _LINUX_COMPAT_H */
