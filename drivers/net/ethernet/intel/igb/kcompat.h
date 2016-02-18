#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/of_net.h>
#include <linux/pci.h>

#endif


#ifdef __KERNEL__

unsigned char * __weak arch_get_platform_mac_address(void)
{
        return NULL;
}

int eth_platform_get_mac_address(struct device *dev, u8 *mac_addr)
{
        const unsigned char *addr;
        struct device_node *dp;

        if (dev_is_pci(dev))
                dp = pci_device_to_OF_node(to_pci_dev(dev));
        else
                dp = dev->of_node;

        addr = NULL;
        if (dp)
                addr = of_get_mac_address(dp);
        if (!addr)
                addr = arch_get_platform_mac_address();

        if (!addr)
                return -ENODEV;

        ether_addr_copy(mac_addr, addr);
        return 0;
}
EXPORT_SYMBOL(eth_platform_get_mac_address);

#endif
