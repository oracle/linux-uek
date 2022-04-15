#! /bin/bash
#
# Called as filter-modules.sh <core-listfile> <all-modules-listfile>

# This script filters the modules into the kernel-uek-core and kernel-uek-modules
# subpackages. It uses core.list file to create list file for kernel-uek-modules rpm.

corelist=$1
modlist=$2
> ${modlist}.tmp

cat $modlist | while read mod
do
        grep -q -e "$mod" $corelist
        if [ $? -ne 0 ]
        then
		# Remove the .ko file.  It will be restored later.
                rm -f "$mod"

		# Add the .ko to -modules rpm list.
		echo "$mod" >> ${modlist}.tmp
        fi
done

# Make sure all modules listed in core.list is currently built.
cat $corelist | while read mod
do
        grep -q -e "$mod" $modlist
        if [ $? -ne 0 ]
        then
                echo "$mod is not built."
        fi
done

# Verify all the modules are added either in core or in modules rpm.
# If the count don't match, fail the build.
ALL=$(wc -l $modlist | awk '{print $1}')
CORE=$(wc -l $corelist | awk '{print $1}')
MOD=$(wc -l ${modlist}.tmp | awk '{print $1}')
SUM=$((CORE + MOD))

if [[ $ALL -ne $SUM ]]
then
	echo "Not all modules are included in core and modules list"
	exit 1
fi

mv ${modlist}.tmp ${modlist}
exit 0
