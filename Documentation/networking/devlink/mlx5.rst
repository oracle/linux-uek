.. SPDX-License-Identifier: GPL-2.0

====================
mlx5 devlink support
====================

This document describes the devlink features implemented by the ``mlx5``
device driver.

Parameters
==========

.. list-table:: Generic parameters implemented

   * - Name
     - Mode
     - Validation
   * - ``enable_roce``
     - driverinit
     - Type: Boolean
   * - ``io_eq_size``
     - driverinit
     - The range is between 64 and 4096.
   * - ``event_eq_size``
     - driverinit
     - The range is between 64 and 4096.
   * - ``max_macs``
     - driverinit
     - The range is between 1 and 2^31. Only power of 2 values are supported.

The ``mlx5`` driver also implements the following driver-specific
parameters.

.. list-table:: Driver-specific parameters implemented
   :widths: 5 5 5 85

   * - Name
     - Type
     - Mode
     - Description
   * - ``flow_steering_mode``
     - string
     - runtime
     - Controls the flow steering mode of the driver

       * ``dmfs`` Device managed flow steering. In DMFS mode, the HW
         steering entities are created and managed through firmware.
       * ``smfs`` Software managed flow steering. In SMFS mode, the HW
         steering entities are created and manage through the driver without
         firmware intervention.
   * - ``fdb_large_groups``
     - u32
     - driverinit
     - Control the number of large groups (size > 1) in the FDB table.

       * The default value is 15, and the range is between 1 and 1024.
   * - ``esw_multiport``
     - Boolean
     - runtime
     - Control MultiPort E-Switch shared fdb mode.

       An experimental mode where a single E-Switch is used and all the vports
       and physical ports on the NIC are connected to it.

       An example is to send traffic from a VF that is created on PF0 to an
       uplink that is natively associated with the uplink of PF1

       Note: Future devices, ConnectX-8 and onward, will eventually have this
       as the default to allow forwarding between all NIC ports in a single
       E-switch environment and the dual E-switch mode will likely get
       deprecated.

       Default: disabled

   * - ``hairpin_num_queues``
     - u32
     - driverinit
     - We refer to a TC NIC rule that involves forwarding as "hairpin".
       Hairpin queues are mlx5 hardware specific implementation for hardware
       forwarding of such packets.

       Control the number of hairpin queues.
   * - ``hairpin_queue_size``
     - u32
     - driverinit
     - Control the size (in packets) of the hairpin queues.

The ``mlx5`` driver supports reloading via ``DEVLINK_CMD_RELOAD``

Info versions
=============

The ``mlx5`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``fw.psid``
     - fixed
     - Used to represent the board id of the device.
   * - ``fw.version``
     - stored, running
     - Three digit major.minor.subminor firmware version number.
