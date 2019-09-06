#!/bin/bash
set -e

. /etc/os-release

kernelver=$1 && shift
rootfs=$1 && shift
variant=$1 && shift

output="${rootfs}/lib/modules/${kernelver}/bls.conf"
date=$(date -u +%Y%m%d%H%M%S)

if [ "${variant:-5}" = "debug" ]; then
    debugname=" with debugging"
    debugid="-debug"
else
    debugname=""
    debugid=""
fi

cat >${output} <<EOF
title ${NAME} (${kernelver}) ${VERSION}${debugname}
version ${kernelver}${debugid}
linux ${bootprefix}/vmlinuz-${kernelver}
initrd ${bootprefix}/initramfs-${kernelver}.img
options \$kernelopts
id ${ID}-${date}-${kernelver}${debugid}
grub_users \$grub_users
grub_arg --unrestricted
grub_class kernel${variant}
EOF
