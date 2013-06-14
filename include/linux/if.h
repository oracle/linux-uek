#ifndef __EXTEND_LINUX_IF_H_TO_3_6__
#define __EXTEND_LINUX_IF_H_TO_3_6__

#include <linux/version.h>
#include_next <linux/if.h>

#define IFF_EIPOIB_PIF  0x100000       /* IPoIB PIF intf(eg ib0, ib1 etc.)*/
#define IFF_EIPOIB_VIF  0x200000       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.)*/

#endif /* __EXTEND_LINUX_IF_H_TO_3_6__ */
