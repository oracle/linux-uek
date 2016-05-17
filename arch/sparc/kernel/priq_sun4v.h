/* sun4v priq interfaces. Introduced in CoreS4.*/
#ifndef	__PRIQ_SUN4V_H__
#define __PRIQ_SUN4V_H__

unsigned long priq_unconf(unsigned long id);
unsigned long priq_bind(unsigned long id,
			unsigned long cpuid,
			unsigned long pil);
unsigned long priq_bind_info(unsigned long id,
			     unsigned long *cpuid,
			     unsigned long *pil);
unsigned long priq_unbind(unsigned long id);
unsigned long priq_get_head_tail(unsigned long id,
				 unsigned long *head,
				 unsigned long *tail);
unsigned long priq_set_head(unsigned long id,
			    unsigned long head);
unsigned long priq_status(unsigned long id,
			  unsigned long *priq_status);
unsigned long priq_conf(unsigned long type,
			unsigned long arg,
			unsigned long raddr,
			unsigned long nentries);
unsigned long priq_info(unsigned long id,
			struct hv_priq_info *hv_priq_info);
unsigned long pci_priq_err_bind(unsigned long devhandle,
				unsigned long errtype,
				unsigned long priq_id);
unsigned long pci_pirq__err_info(unsigned long handle,
				 unsigned long errtype,
				 struct hv_pci_priq_err_info *err_info);
unsigned long pci_priq_err_unbind(unsigned long devhandle,
				  unsigned long errtype);
unsigned long pci_priq_err_enable(unsigned long devhandle,
				  unsigned long errtype);
unsigned long pci_err_disable(unsigned long devhandle,
			      unsigned long errtype);
unsigned long pci_priq_msi_bind(unsigned long devhandle,
				unsigned long msinum,
				unsigned long rid,
				unsigned long priq_id);
unsigned long pci_priq_msi_info(unsigned long devhandle,
				unsigned long msinum,
				unsigned long rid,
				struct hv_pci_msi_info *msi_info);
unsigned long pci_priq_msi_unbind(unsigned long devhandle,
				  unsigned long msinum,
				  unsigned long rid);
unsigned long pci_priq_msi_enable(unsigned long devhandle,
				  unsigned long msinum,
				  unsigned long rid);
unsigned long pci_priq_msi_disable(unsigned long devhandle,
				   unsigned long msinum,
				   unsigned long rid);
unsigned long pci_priq_msi_getstate(unsigned long devhandle,
				    unsigned long msinum,
				    unsigned long rid,
				    unsigned long *msistate);
unsigned long pci_priq_msi_setstate(unsigned long devhandle,
				    unsigned long msinum,
				    unsigned long rid,
				    unsigned long msistate);
unsigned long pci_priq_msg_bind(unsigned long devhandle,
				unsigned long msgtype,
				unsigned long priq_id);
unsigned long pci_priq_msg_info(unsigned long devhandle,
				unsigned long msgtype,
				struct hv_pci_priq_msg_info *msg_info);
unsigned long pci_priq_msg_unbind(unsigned long devhandle,
				  unsigned long msgtype);
unsigned long pci_priq_msg_enable(unsigned long devhandle,
				  unsigned long msgtype);
unsigned long pci_priq_msg_disable(unsigned long devhandle,
				   unsigned long msgtype);
unsigned long pci_priq_intx_bind(unsigned long devhandle,
				 unsigned long intx,
				 unsigned long priq_id);
unsigned long pci_priq_intx_info(unsigned long devhandle,
				 unsigned intx,
				 struct hv_pci_priq_intx_info *intx_info);
unsigned long pci_priq_intx_unbind(unsigned long devhandle,
				   unsigned long intx);
unsigned long pci_priq_intx_enable(unsigned long devhandle,
				   unsigned long intx);
unsigned long pci_priq_intx_disable(unsigned long devhandle,
				    unsigned long intx);
unsigned long pci_priq_intx_getstate(unsigned long intx,
				     unsigned long *intxstate);
unsigned long pci_priq_intx_setstate(unsigned long devhandle,
				     unsigned long intx,
				     unsigned long intxstate);

void priq_percpu_setup(int cpu);
void cpu_handle_priqs(void);
void sun4v_priq(void);
struct pci_pbm_info;
int pci_sun4v_priq_msi_init(struct pci_pbm_info *pbm);
void priq_percpu_destroy(int cpu);
struct device_node;
int pci_priq_build_irq(unsigned int devhandle, unsigned int devino);
#endif	/* !__PRIQ_SUN4V_H__*/
