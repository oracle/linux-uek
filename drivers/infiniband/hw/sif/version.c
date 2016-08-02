/* Misc driver release info */

#include "version.h"

struct sif_version sif_version = {
.git_repo = "sifdrv [origin/master]",
.last_commit = "titan_1.0.0.2 pqp: Be less aggressive in invoking cond_resched()",
.git_status = """?? drivers/\n"
,
.build_git_time = "Tue, 26 Jul 2016 15:46:06 +0000",
.build_user = "komang",

.git_psifapi_repo = "psifapi [origin/master]",
.last_psifapi_commit = "titan_1.0.0.2 EPSC_API_VERSION(2,8) - New EPSC_QUERY_ON_CHIP_TEMP",
.git_psifapi_status = "",
};
