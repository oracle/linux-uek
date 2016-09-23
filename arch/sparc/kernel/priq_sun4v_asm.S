#include <linux/linkage.h>
#include <asm/hypervisor.h>

	/* %o0:	id
	 *
	 * returns %o0: status
	 */
ENTRY(priq_unconf)
	or	%g0, HV_FAST_PRIQ_UNCONF, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(priq_unconf)

	/* %o0:	id
	 * %o1:	cpuid
	 * %o2:	pil
	 *
	 * returns: %o0: status
	 */
ENTRY(priq_bind)
	or	%g0, HV_FAST_PRIQ_BIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(priq_bind)

	/* %o0:	id
	 *
	 * returns %o0: status
	 *	   %o1: cpuid
	 *	   %o2: pil
	 */
ENTRY(priq_bind_info)
	or	%o1, 0, %g1
	or	%o2, 0, %g2
	or	%g0, HV_FAST_PRIQ_BIND_INFO, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + 0x00]
	stx	%o2, [%g2 + 0x00]
	retl
	nop
	/*
ENDPROC(priq_bind_info);

	/* %o0: id
	 *
	 * returns %o0: status
	 */
ENTRY(priq_unbind)
	or	%g0, HV_FAST_PRIQ_UNBIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(priq_unbind)

	/* %o0: id
	 *
	 * returns %o0: status
	 *	   %o1: head
	 *	   %o2: tail
	 */
ENTRY(priq_get_head_tail)
	or	%g0, %o1, %g1
	or	%g0, %o2, %g2
	or	%g0, HV_FAST_PRIQ_GET_HEAD_TAIL, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + 0x00]
	stx	%o2, [%g2 + 0x00]
	retl
	nop
ENDPROC(priq_get_head_tail)

	/* %o0: id
	 * %o1: head
	 *
	 * returns %o0: status
	 */
ENTRY(priq_set_head)
	or	%g0, HV_FAST_PRIQ_SET_HEAD, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(priq_set_head)

	/* %o0: id
	 *
	 * returns %o0: status
	 */
ENTRY(priq_status)
	or	%g0, HV_FAST_PRIQ_STATUS, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, 1f
	 sub	%g0, %o0, %o0
	or	%o1, %g0, %o0
1:	retl
	nop
ENDPROC(priq_status)

	/* %o0: type
	 * %o1: arg
	 * %o2: raddr
	 * %o3: nentries
	 *
	 * returns %o0: status
	 */
ENTRY(priq_conf)
	or	%g0, HV_FAST_PRIQ_CONF, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, 1f
	 sub	%g0, %o0, %o0
	or	%o1, %g0, %o0
1:	retl
	nop
ENDPROC(priq_conf)

	/* %o0: id
	 *
	 * returns %o0: status
	 * 	   %o1: type
	 *	   %o2: arg
	 *	   %o3: raddr
	 *	   %o4: nentries
	 */
ENTRY(priq_info)
	or	%o1, %g0, %g1
	or	%g0, HV_FAST_PRIQ_INFO, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, 1f
	stx	%o1, [%g1 + HV_PRIQ_INFO_TYPE_OFFSET]
	stx	%o2, [%g1 + HV_PRIQ_INFO_ARG_OFFSET]
	stx	%o3, [%g1 + HV_PRIQ_INFO_RADDR_OFFSET]
	stx	%o4, [%g1 + HV_PRIQ_INFO_NENTRIES_OFFSET]
1:	retl
	nop
ENDPROC(priq_info)

	/* %o0: devhandle
	 * %o1: errtype
	 * %o2: priq_id
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_err_bind)
	or	%g0, HV_FAST_PCI_PRIQ_ERR_BIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_err_bind)

	/* %o0: devhandle
	 * %o1: errtype
	 *
	 * returns %o0: status
	 *	   %o1: priq_id
	 *	   %o2: enabled
	 */
ENTRY(pci_priq_err_info)
	or	%o2, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_ERR_INFO, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + HV_PCI_PRIQ_ERR_INFO_PRIQ_ID_OFFSET]
	stx	%o2, [%g1 + HV_PCI_PRIQ_ERR_INFO_ENABLED_OFFSET]
	retl
	nop
ENDPROC(pci_priq_err_info)

	/* %o0: devhandle
	 * %o1: errtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_err_unbind)
	or	%g0, HV_FAST_PCI_PRIQ_ERR_UNBIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_err_unbind)

	/* %o0: devhandle
	 * %o1: errtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_err_enable)
	or	%g0, HV_FAST_PCI_PRIQ_ERR_ENABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_err_enable)

	/* %o0: devhandle
	 * %o1: errtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_err_disable)
	or	%g0, HV_FAST_PCI_PRIQ_ERR_DISABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_err_disable)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 * %o3: priq_id
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msi_bind)
	or	%g0, HV_FAST_PCI_PRIQ_MSI_BIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msi_bind)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 *
	 * returns %o0: status
	 *	   %o1: priq_id
	 *	   %o2: enabled
	 */
ENTRY(pci_priq_msi_info)
	or	%o3, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_MSI_INFO, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + HV_PCI_MSI_INFO_PRIQ_ID_OFFSET]
	stx	%o2, [%g1 + HV_PCI_MSI_INFO_PRIQ_ENABLE_OFFSET]
	retl
	nop
ENDPROC(pci_priq_msi_info)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msi_unbind)
	or	%g0, HV_FAST_PCI_PRIQ_MSI_UNBIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msi_unbind)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msi_enable)
	or	%g0, HV_FAST_PCI_PRIQ_MSI_ENABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msi_enable)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msi_disable)
	or	%g0, HV_FAST_PCI_PRIQ_MSI_DISABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msi_disable)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 *
	 * returns %o0: status
	 *	   %o1: msistate
	 */
ENTRY(pci_priq_msi_getstate)
	or	%o1, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_MSI_GETSTATE, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + 0x00]
	retl
	nop
ENDPROC(pci_priq_msi_getstate)

	/* %o0: devhandle
	 * %o1: msinum
	 * %o2: rid
	 * %o3: msistate
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msi_setstate)
	or	%g0, HV_FAST_PCI_PRIQ_MSI_SETSTATE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msi_setstate)

	/* %o0: devhandle
	 * %o1: msgtype
	 * %o2: priq_id
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msg_bind)
	or	%g0, HV_FAST_PCI_PRIQ_MSG_BIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msg_bind)

	/* %o0: devhandle
	 * %o1: msgtype
	 *
	 * returns: %o0: status
	 *	    %o1: priq_id
	 *	    %o2: enabled
	 */
ENTRY(pci_priq_msg_info)
	or	%o1, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_MSG_INFO, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + HV_PCI_PRIQ_MSG_INFO_PRIQ_ID_OFFSET]
	stx	%o2, [%g1 + HV_PCI_PRIQ_MSG_INFO_ENABLED_OFFSET]
	retl
	nop
ENDPROC(pci_priq_msg_info)

	/* %o0: devhandle
	 * %o1: msgtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msg_unbind)
	or	%g0, HV_FAST_PCI_PRIQ_MSG_UNBIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msg_unbind)

	/* %o0: devhandle
	 * %o1: msgtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msg_enable)
	or	%g0, HV_FAST_PCI_PRIQ_MSG_ENABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msg_enable)

	/* %o0: devhandle
	 * %o1: msgtype
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_msg_disable)
	or	%g0, HV_FAST_PCI_PRIQ_MSG_DISABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_msg_disable)

	/* %o0: devhandle
	 * %o1: intx
	 * %o2: priq_id
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_intx_bind)
	or	%g0, HV_FAST_PCI_PRIQ_INTX_BIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_intx_bind)

	/* %o0: devhandle
	 * %o1: intx
	 *
	 * returns %o0: status
	 *	   %o1: priq_id
	 *	   %o2: enabled
	 */
ENTRY(pci_priq_intx_info)
	or	%o2, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_INTX_INFO, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + HV_PCI_PRIQ_INTX_INFO_PRIQ_ID_OFFSET]
	stx	%o2, [%g1 + HV_PCI_PRIQ_INTX_INFO_ENABLED_OFFSET]
	retl
	nop
ENDPROC(pci_priq_intx_info)

	/* %o0: devhandle
	 * %o1: intx
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_intx_unbind)
	or	%g0, HV_FAST_PCI_PRIQ_INTX_UNBIND, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_intx_unbind)

	/* %o0: devhandle
	 * %o1: intx
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_intx_enable)
	or	%g0, HV_FAST_PCI_PRIQ_INTX_ENABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_intx_enable)

	/* %o0: devhandle
	 * %o1: intx
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_intx_disable)
	or	%g0, HV_FAST_PCI_PRIQ_INTX_DISABLE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_intx_disable)

	/* %o0: devhandle
	 * %o1: intx
	 *
	 * returns %o0: status
	 *	   %o1: intxstate
	 */
ENTRY(pci_priq_intx_getstate)
	or	%o1, %g0, %g1
	or	%g0, HV_FAST_PCI_PRIQ_INTX_GETSTATE, %o5
	ta	HV_FAST_TRAP
	stx	%o1, [%g1 + 0x00]
	retl
	nop
ENDPROC(pci_priq_intx_getstate)

	/* %o0: devhandle
	 * %o1: intx
	 * %o2: intxstate
	 *
	 * returns %o0: status
	 */
ENTRY(pci_priq_intx_setstate)
	or	%g0, HV_FAST_PCI_PRIQ_INTX_SETSTATE, %o5
	ta	HV_FAST_TRAP
	retl
	nop
ENDPROC(pci_priq_intx_setstate)
