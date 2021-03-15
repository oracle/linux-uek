.. SPDX-License-Identifier: GPL-2.0-or-later

Configfs GPIO Simulator
=======================

The configfs GPIO Simulator (gpio-sim) provides a way to create simulated GPIO
chips for testing purposes. The lines exposed by these chips can be accessed
using the standard GPIO character device interface as well as manipulated
using sysfs attributes.

Creating simulated chips
------------------------

The gpio-sim module registers a configfs subsystem called 'gpio-sim'. It's a
subsystem with committable items which means two subdirectories are created in
the filesystem: pending and live. For more information on configfs and
committable items, please refer to Documentation/filesystems/configfs.rst.

In order to instantiate a new simulated chip, the user needs to mkdir() a new
directory in pending/. Inside each new directory, there's a set of attributes
that can be used to configure the new chip. Once the configuration is complete,
the user needs to use rename() to move the chip to the live/ directory. This
creates and registers the new device.

In order to destroy a simulated chip, it has to be moved back to pending first
and then removed using rmdir().

Currently supported configuration attributes are:

  num_lines - an unsigned integer value defining the number of GPIO lines to
              export

  label - a string defining the label for the GPIO chip

  line_names - a list of GPIO line names in the form of quoted strings
               separated by commas, e.g.: '"foo", "bar", "", "foobar"'. The
               number of strings doesn't have to be equal to the value set in
               the num_lines attribute. If it's lower than the number of lines,
               the remaining lines are unnamed. If it's larger, the superfluous
               lines are ignored. A name of the form: '""' means the line
               should be unnamed.

Additionally two read-only attributes named 'chip_name' and 'dev_name' are
exposed in order to provide users with a mapping from configfs directories to
the actual devices created in the kernel. The former returns the name of the
GPIO device as assigned by gpiolib (i.e. "gpiochip0", "gpiochip1", etc.). The
latter returns the parent device name as defined by the gpio-sim driver (i.e.
"gpio-sim.0", "gpio-sim.1", etc.). This allows user-space to map the configfs
items both to the correct character device file as well as the associated entry
in sysfs.

Simulated GPIO chips can also be defined in device-tree. The compatible string
must be: "gpio-simulator". Supported properties are:

  "gpio-sim,label" - chip label

  "gpio-sim,nr-gpios" - number of lines

Other standard GPIO properties (like "gpio-line-names" and gpio-hog) are also
supported.

Manipulating simulated lines
----------------------------

Each simulated GPIO chip creates a sysfs attribute group under its device
directory called 'line-ctrl'. Inside each group, there's a separate attribute
for each GPIO line. The name of the attribute is of the form 'gpioX' where X
is the line's offset in the chip.

Reading from a line attribute returns the current value. Writing to it (0 or 1)
changes the configuration of the simulated pull-up/pull-down resistor
(1 - pull-up, 0 - pull-down).
