/* Misc driver release info */

#include "version.h"

struct sif_version sif_version = {
.git_repo = "sifdrv [origin/master]",
.last_commit = "titan_1.0.0.1-4-g3865298 eq: increase cq_eq_max to 46",
.git_status = """?? drivers/\n"
"?? drv/sif_epsc.c~\n"
,
.build_git_time = "Fri, 15 Jul 2016 07:58:00 +0000",
.build_user = "komang",

.git_psifapi_repo = "psifapi [origin/master]",
.last_psifapi_commit = "titan_1.0.0.1-3-g7496ad1 EPSC_API_VERSION(2,6) - Adding retrieval of SMP and vlink connect modes",
.git_psifapi_status = "",
};
