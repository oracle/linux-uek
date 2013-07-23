# mpt2sas makefile
EXTRA_CFLAGS := -DCPQ_CIM

# comment out this line so driver can compile for kernels not having mpt2sas
#obj-$(CONFIG_SCSI_MPT2SAS) += mpt2sas.o
obj-m += mpt2sas.o
mpt2sas-y +=  mpt2sas_base.o     \
		mpt2sas_config.o \
		mpt2sas_scsih.o      \
		mpt2sas_transport.o     \
		mpt2sas_ctl.o  \
		mpt2sas_trigger_diag.o
