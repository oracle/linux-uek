Mmcoops oops/panic logger
=========================

Introduction
------------

Mmcoops is an oops/panic logger that write its logs to MMC before the system crashes.
Introduction and concept are similar to other oops loggers.
(Refer to Documentation/admin-guide/ramoops.rst)

Setting the parameters
----------------------

The mmcoops uses module parameters for variables that can be configured.
Currently there are 3 customizable parameters:

* ``mmcdev``: specifies on which mmcdev the dump will be stored.
* ``start-offset``: block-offset for start. Default 14680064 (7GB = 14680064 * 512).
* ``size``: the number of block to write oopses and panics. Default 20 (20 * 512B = 10KiB).

Only ``mmcdev`` is mandatory and has to be specified via bootargs. Wrong or
missing value will not activate mmc_oops dumper. Setting start_offset and
record_size parameters are optional if not set default values will be used.

Example::


        mmc_oops.mmcdev=mmc0 mmc_oops.start-offset=2097152 mmc_oops.size=30

or minimum example with default start-offset and size::

        mmc_oops.mmcdev=mmc1


Dump format
-----------

The data dump begins with a header, currently defined as ``====``, the dump then
continues with the actual data. It is written in raw ASCI format.

Reading the data
----------------

After reboot, the last log can be gathered with bellow command::

 #dd if=/dev/mmcblk0 of=/tmp/dump.log skip=14680064 count=20; cat /tmp/dump.log

- skip is the ``start-offset`` specify by module parameter
- count is the ``size`` specify by module parameter


Choosing mmcblk used for dumps via sysfs
----------------------------------------

In order to bind different mmc device to mmc_oops the mmcX:000Y can be unbind
and then bind to mmc_oops::

 # ls -al /sys/bus/mmc/drivers/mmcblk
 drwxr-xr-x 2 root root    0 Mar 10 23:05 .
 drwxr-xr-x 4 root root    0 Mar 10 23:05 ..
 --w------- 1 root root 4096 Mar 10 23:05 bind
 lrwxrwxrwx 1 root root    0 Mar 10 23:05 mmc0:0001 -> ../../../../devices/platform/ap807/ap807:config-space@f0000000/f06e0000.sdhci/mmc_host/mmc0/mmc0:0001
 lrwxrwxrwx 1 root root    0 Mar 10 23:05 mmc2:0007 -> ../../../../devices/platform/cp2/cp2:config-space/f6780000.sdhci/mmc_host/mmc2/mmc2:0007
 --w------- 1 root root 4096 Mar 10 23:05 uevent
 --w------- 1 root root 4096 Mar 10 23:05 unbin

 # echo mmc2:0007 > /sys/bus/mmc/drivers/mmcblk/unbind
 # echo mmc2:0007 > /sys/bus/mmc/drivers/mmc_oops/bind
 [  165.860185] mmc2: mmc_oops_card_set
 #
