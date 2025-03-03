UEK-next: Oracle's Next Unbreakable Enterprise Kernel Development Release
=========================================================================

The Next Unbreakable Enterprise Kernel Developer Release (UEK-next) is the
next generation of the UEK kernel based upon the upstream Linux `v6.13` tag.

The UEK-next developer release allows Oracle Linux users to try out the latest
developments from upstream Linux combined with Oracle UEK-specific features.

To read more about Linux kernel development at Oracle, see:

- https://blogs.oracle.com/linuxkernel

The original README for the Linux kernel along with a other useful documentation
can be found at Documentation/admin-guide/README.rst

## Support

UEK-next is not supported for production use, however we will provide limited
test and development support for these kernels to help validate applications and
workloads.

## How it is formed

The UEK-next release is built by applying UEK specific fixes on top of the
latest Linux mainline release tag.

UEK-next developer releases are upstream Linux kernels with Oracle Linux patches
for use to evaluate new features in upstream Linux and enable developers to
experiment with the latest hardware support, and to validate application
compatibility with the latest kernels.

Every UEK-next release is based on a major upstream release (e.g.: 6.10 based,
6.13 based, etc.)

## Noteworthy Changes

- Packaging changes

  The UEK kernel has so many modules which are rarely used by server class
  deployments in the `kernel-ueknext-modules` and `kernel-ueknext-modules-extra`
  RPMs.

  Some of the examples include:

  - Desktop related modules

    - Graphics drivers
    - Touchscreen drivers
    - Tablet drivers
    - Joystick drivers
    - Laptop drivers
    - HID (Human Interface Device) drivers -- HID is a type of
      computer device that interacts directly with and takes input
      from humans.
    - Industrial I/O drivers -- Industrial I/O drivers are typically
      things like accelerometers and orientation sensors used in
      phones, tablets and laptops
    - Media drivers
    - Video and DVB drivers
    - Webcam drivers
    - MMC drivers(Multimedia card)
    - Bluetooth drivers
    
  - Sound drivers

  - Wireless drivers

  - Other varied USB drivers

  - Some modules are not hardware drivers but provide software functionality such as:

    - Network protocols
    - Network schedulers
    - Network filtering

  With that in mind, we are testing out the idea of an extended set of
  packages:

  - `kernel-ueknext-modules-core`
    - Essentials for booting Exadata, OCI VMs, etc.

  - `kernel-ueknext-modules`
    - Various modules that are expected to be commonly used

  - `kernel-ueknext-modules-extra` 
    - Modules that are NOT expected to be commonly used

  - `kernel-ueknext-modules-desktop`
    - Modules for desktop-type hardware (HID, touchscreens, etc.)

  - `kernel-ueknext-modules-usb`
    - Optional USB drivers

  - `kernel-ueknext-modules-wireless`
    - Wireless drivers

  - `kernel-ueknext-modules-extra-netfilter` 
    - Rarely used netfilter modules

  - `kernel-ueknext-modules-deprecated` 
    - Modules that we plan to remove in future releases

  The exact set of packages and how modules are distributed among them is a
  balancing act of shrinking the default set of installed modules while still
  allowing users to install modules they need in special circumstances.

  You may find that on upgrade to UEK-next, that some functionality is
  missing, but it may be provided in a different package.

  You may be able to find which package by looking at the file:

  ```

    grep "<modname>" /lib/moduiles/$(uname -r)/modules.packages

  ```

  and then installing those packages with `dnf install`.

  Please do let us know your experiences on this by logging issues, UEK-next
  is a good way to try out new scenarios like this.

- UEK-next as default kernel post-install

  Because UEK-next is not a production kernel, it was decided not autoselect it as the
  default kernel on installation. Should you prefer it to be the default kernel, you
  may do so by either:

  - Prior to installation, if not already done, setting the default
    kernel in `/etc/sysconfig/kernel` using the line:

    ```
	DEFAULTKERNEL=kernel-ueknext-core
	```

  - Post installation, set it as the default using `grubby` as:

    ```
	sudo grubby --set-default=/boot/vmlinuz-6.13.0-1.el9ueknext.$(name -p)
	```

## Known Problems

- Some NVME devices exhibit what appears to be a corruption of the metadata

  Due to inconsistencies between the firmware and the kernel, the kernel
  believes that the device supports WRITE ZEROES, when it does not.

  This can be resolved by ensuring that the NVME firmware is updated to the
  latest version.

# Reporting Issues

Issues found while using this release that are not present in upstream Linux may
be reported using Github Issues at:

- https://github.com/oracle/linux-uek/issues

If you have kernel patches, please contribute to upstream Linux first! Patches
accepted by upstream will be part of the next UEK-next build a few weeks after
that kernel is released.

# Recent Blog posts

- https://elufasys.com/investigating-the-kernel-configuration-of-uek-next/

- https://blogs.oracle.com/linux/post/uek-next

- https://blogs.oracle.com/linux/post/exploring-ueknexts-kernel-configuration

- https://blogs.oracle.com/linux/post/virtioblk-using-iothread-vq-mapping
