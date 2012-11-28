#ifndef __EXTEND_LINUX_IF_H_TO_3_6__
#define __EXTEND_LINUX_IF_H_TO_3_6__

#include <linux/version.h>
#include_next <linux/if.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))

#define IFF_EIPOIB_PIF  0x100000       /* IPoIB PIF intf(eg ib0, ib1 etc.)*/
#define IFF_EIPOIB_VIF  0x200000       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.)*/

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) */

#endif /* __EXTEND_LINUX_IF_H_TO_3_6__ */
