#! /bin/bash
#
# Called as filter-modules.sh <core-listfile> <all-modules-listfile>

# This script filters the modules into the kernel-uek-core and kernel-uek-modules
# subpackages. It uses core.list file to create list file for kernel-uek-modules rpm.

corelist=$1
modlist=$2

cat $modlist | while read mod
do
        grep -q -e "$mod" $corelist
        if [ $? -eq 0 ]
        then
		# .ko is present in -core list. Remove it in -modules list.
                grep -v -e "$mod" $modlist > ${modlist}.tmp
                mv ${modlist}.tmp $modlist
        else
		# Remove the .ko files.  It will be restored later.
                rm -f "$mod"
        fi
done
