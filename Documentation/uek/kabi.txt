UEK kABI
========

This file documents the kABI tool in the file uek-rpm/tools/kabi, along with a
brief introduction to kABI in general.


Introduction to genksyms & module loading
-----------------------------------------

When the kernel loads a module, it is quite important that it avoid loading one
which is incompatible with the current kernel -- that is a sure path to a nasty
bug. One way to do this is to check the exact kernel version string which the
module was built for. However, this completely eliminates the possibility of
reusing a pre-compiled module on multiple kernels, condemning module
distributors to recompiling for every kernel release. So, genksyms was created
to offer an alternative.

Modules may only interact with the core kernel via certain symbols which are
"exported". That is, they can only directly access static variables which are
exported, and they may only call exported functions. Genksyms is a compile-time
tool which reads the pre-processed source code of a compilation unit, and
outputs a hash of the "full declaration" of every exported symbol. This hash is
called the "symver" - symbol version.

This "full declaration" recursively contains the declaration of every type (e.g.
structs, enums) which is referenced in the original symbol's declaration. So, if
a function takes an argument of type "struct foo", and foo contains a pointer to
"struct bar", then the "full declaration" will include the declarations of both
structs as well. The full declaration gets hashed to a 32-bit integer because
these declarations can become quite large (tens to hundreds of KiB!).

At compile-time for the kernel, genksyms computes the symver for every exported
symbol, and stores this info into a table within the kernel. It also installs
this data in the "kernel-devel" packages.

At compile-time for kernel modules, the build system determines every exported
symbol which the module accesses. The build system looks up the symbol version
corresponding to the target kernel headers. It inserts a table into the module's
ELF file, which enumerates these symbols, and symvers.

The module loader reads this table, compares it to the symbol versions built-in
to the kernel, and ensures they match before loading the module. This protects
the kernel from loading modules compiled for a substantially different kernel
version. It is quite effective, and has served the kernel well.


Introduction to kABI
--------------------

An ABI (application binary interface) describes the interface that compiled code
modules use to interact, for example the calling conventions, as well as
data structure sizes and layouts. So long as an ABI does not change, modules can
be updated independently without risk of breaking each other. The genksyms tool
and module loading mechanisms described in the previous section are intended to
avoid ABI mismatches between the kernel and the modules it loads.

If we want to provide a stable kernel ABI, we would need to avoid changing any
exported symbol's symver, during the entire lifetime of a kernel release.
However, the set of all exported symbols is quite large, and making a change
without altering the version of at least one symver is nearly impossible. So we
cannot pledge to do that.

Instead, the stable kernel ABI (or kABI) which we provide is for a limited
subset of exported symbols. We pledge to not break the symvers for any symbol in
this subset (the "locked list"). If a module uses only symbols from this list,
it is guaranteed to load on any kernel from the same release.


kABI Files
----------

There are several files which are used as part of maintaining the kABI:

kabi_lockedlist

    The kabi_lockedlist file defines a set of symbols (mostly functions) whose
    declarations and ABI may not change for the duration of a release. It is
    maintained in version control.

Module.symvers

    This file is generated at build time by genksyms. It contains a line for
    each exported symbol, with columns that define:
    1) The symver, computed as described above
    2) The name of the symbol
    3) The object defining the symbol (vmlinux or a module)
    4) The license by which a symbol is exported
    The Module.symvers file from a particular kernel build is installed to at
    least one of the following locations, depending on the release:
    /boot/symvers-$(uname -r).gz
    /lib/modules/$(uname -r)/symvers.gz
    /lib/modules/$(uname -r)/build/Module.symvers

Module.kabi

    This file contains a subset of the lines of Module.symvers, one for each
    symbol contained in the lockedlist. It is generated when the kABI is
    defined, and kept in version control.

By comparing the relevant lines of a newly built kernel's Module.symvers to
those in Module.kabi, we can check whether the kABI has been broken. The tool
"check-kabi" is designed to do exactly that. However, if the kABI has been
broken, all we will know is the list of symbols which have changed. Since a
symbol's kABI hash takes into account every type it references (recursively), it
can be difficult to pin down the exact modifications which resulted in the ABI
breakage.

To assist in this process, we maintain some additional information which
contains all type definitions as genksyms saw them, and encodes the type
dependencies of each symbol. These files are referred to as Symtypes files.

*.symtypes

    For each compilation unit, if the KBUILD_SYMTYPES=y option is given to make,
    then KBuild will generate a corresponding file containing type definitions
    as it saw them.

Symtypes.build

    To reduce redundancy, the above files can be collected into a single file
    for the entire build. The command "uek-rpm/tools/kabi collect" can be used
    to create these files. The size of the files varies, but is typically a few
    MiB before compression.  The format is similar to the the .symtypes files,
    but with some additional metadata. Both formats are described below.

    The Symtypes.build file from a particular kernel build is included in
    debuginfo packages, and installed to:
    /usr/lib/debug/lib/modules/$(uname -r)/Symtypes.build.gz

Symtypes.kabi

    Given a list of symbols which are part of a kABI definition, the
    Symtypes.build file can be further minimized so that it only contains types
    and symbols which are used in the kABI. This file is maintained in version
    control alongside the Module.kabi file.

When a kABI breakage is detected, we can compare the Symtypes.kabi file against
the newly built Symtypes.build file, and highlight specific type definitions
which have changed.


Use of the "kabi" tool
----------------------

The tool uek-rpm/tools/kabi is designed to complement the check-kabi script
which verifies kABI compatibility for a newly built kernel. Its purpose is to
manage the Symtypes data created by a kernel build, and allow for comparisons
between the Symtypes data of two different kernel builds. When the check-kabi
command reports a breakage, "uek-rpm/tools/kabi" can be used to give more
information on the cause of the breakage.

Below are some important kabi commands. Their exact arguments can be discovered
with the "-h" option (e.g. "kabi collect -h"). The full list of sub-commands is
given by "kabi -h".

kabi collect

    Given a build directory (with KBUILD_SYMTYPES=y), this sub-command can
    collect all .symtypes files and combine them into a single Symtypes.build
    file. It can also perform the steps of "kabi consolidate" if you want.

kabi consolidate

    Given a Symtypes.build file, along with a list of symbols from a kABI
    definition (e.g. the locked list or the Module.symvers), this sub-command
    will filter the contents of the file so that it retains only those which are
    related to the kABI symbols.

kabi compare

    This sub-command allows directly comparing the exported symbols which are in
    common between two symtypes files. For example, to check whether the file
    mm/slub.c contains any deviations from the kABI, one could do a full build
    and wait for the check-kabi output. However, it would be much quicker to do:

    make KBUILD_SYMTYPES=y mm/slub.o
    uek-rpm/ol8/kabi compare uek-rpm/ol8/Symtypes.kabi mm/slub.symtypes


The genksyms .symtypes format
-----------------------------

Symtypes files generated by genksyms (*.symtypes) consist of lines which contain
definitions of items -- either types or symbols. The first whitespace delimited
token at the beginning of the line is the name of the item being defined, and
the subsequent whitespace delimited tokens are the item's definition. Since
different types of items (structs, functions, etc) may have different
namespaces, genksyms prefixes some names with a single-character code, plus a
pound sign (#). Here are some examples of type or symbol names, followed by
their genksyms name and explanation:

    struct task_struct    s#task_struct       struct prefix: s
    enum system_states    e#system_states     enum type prefix: e
    SYSTEM_BOOTING        E#SYSTEM_BOOTING    enumerator prefix: E
    __u8                  t#u8                typedef prefix: t
    schedule()            schedule            function: no prefix
    current_task          current_task        global var: no prefix

Symbols which can be exported (i.e. functions or globals) have no prefix, as
shown above. Type names have prefixes both to separate namespaces, and also to
distinguish from exported symbols.

At the beginning of a .symtypes file are types or symbols which depend on
nothing but pure C types (or possibly themselves). Subsequent lines may refer to
the prior definitions. As a simple example:

    s#list_head struct list_head { s#list_head * next , * prev ; }
    t#sigset_t typedef struct { unsigned long sig [ ( 64 / 64 ) ] ; } sigset_t
    s#sigpending struct sigpending { s#list_head list ; t#sigset_t signal ; }

At the end of a .symtypes file are the exported symbols definitions. If
necessary, they will refer to type definitions above. Here is an example of a
made-up function using the above types:

    do_something extern void do_something( s#sigpending * arg )

A .symtypes file will contain only exported symbol definitions, and will only
contain the type definitions necessary to define those exported symbols. This is
all simply intermediate information. The final output of genksyms is to
construct a full definition for each exported symbol and create the CRC32 for
it. We can re-construct this definition and hash simply by replacing each type
reference with its definition recursively.

A .symtypes file contains only information from a single compilation unit. To
create it, genksyms takes the pre-processed C source code for that compilation
unit and parses it, storing the declarations as above and finally creating
hashes for exported symbols. You can create a .symtypes file by invoking
genksyms with the -T option.


The Symtypes format
-------------------

For a full kernel build, potentially thousands of compilation units exist, and
thus hundreds of .symtypes files exist, each in the hundreds of KiB. Thus, the
collection of symtypes data is quite large. Most of this data is duplicated type
definitions. For example, almost every .symtypes file will contain a line
defining s#list_head. So, it makes sense that one could create a large combined
symtypes file, which contains the definition of all exported symbols, each
sharing their type definitions.

However, this naive approach encounters an issue with duplicate types. Since
genksyms reads each pre-processed source file separately, it may see different
definitions for the same type in different compilation units. There are a few
possible cases where this will happen:

1. A compilation unit contains a forward declaration of a struct, with no full
   definition. In this .symtypes file, the definition of the struct would be
   "s#struct_name { UNKNOWN }". For compilation units which see the full
   definition, a complete definition exist with the exact same name.

2. A struct with the same name is defined in two completely different contexts.

If we simply combined and deduplicated the lines of each .symtypes file, we
would find that we cannot construct a complete type definition for many symbols,
because they use types which have different definitions in different compilation
units. Since, in the context of one large file, we don't know where these
symbols are defined, nor which versions of each type they see, we have no way of
reproducing the original definition. As a concrete example, consider two
compilation units:

    // file1.c
    struct task_struct { /* full definition */ };
    void do_operation(struct task_struct *arg);
    EXPORT_SYMBOL(do_operation);

    // file2.c
    struct task_struct;
    void do_other(struct task_struct *arg);
    EXPORT_SYMBOL(do_other);

When it comes to the final symtypes file, we would have the following contents
(among other things):

    s#task_struct { UNDEFINED }
    s#task_struct { /* full definition */ }
    do_operation extern void do_operation ( s#task_struct * arg )
    do_other extern void do_other ( s#task_struct * arg )

Without additional context, we can't reproduce the original declarations. To
solve this problem, we introduce two changes to the format which are seen in
Symtypes files, but not .symtypes:

1) Any type name which is duplicated will have a CRC32 hash of its declaration
   line appended to its name. So, for the example above, we would instead have:

    s#task_struct@1b9c735e struct task_struct { UNKNOWN }
    s#task_struct@ef30a39b struct task_struct { /* long, full definition */ }

   Thus, each name is unique within the file, which allows us to refer to any
   version of a type which has been seen before.

2) To know which version of a type should be used when resolving the definition
   of an exported symbol, we need context: (a) what was the compilation unit
   that defined a symbol, and (b) what were the type versions visible in that
   compilation unit? We can encode this context in a single line for each
   compilation unit. This line will contain a filename, followed by the list of
   exported symbols and type versions in this file.

Applying these two rules, we can create the combined Symtypes for the example
scenario above:

    s#task_struct@1b9c735e struct task_struct { UNKNOWN }
    s#task_struct@ef30a39b struct task_struct { /* long, full definition */ }
    do_operation extern void do_operation ( s#task_struct * arg )
    do_other extern void do_other ( s#task_struct * arg )
    F#file1.symtypes do_operation s#task_struct@ef30a39b
    F#file2.symtypes do_other s#task_struct@1b9c735e

This file has no ambiguity: given a symbol name, we will know exactly where it
was defined and which type versions were used in its definition.


Creating or updating the kABI
-----------------------------

At the beginning of a release, and periodically throughout, it may be necessary
to create a kABI, or add symbols to it. Each time this happens, the
kabi_lockedlist, Module.kabi, and Symtypes.kabi must be modified accordingly.
The simplest way to do this is to build the kernel RPM without kABI checking.
Then, grab the Module.symvers and Symtypes.build from the kernel package.

Use the kabi_lockedlist to filter the contents of Module.symvers so that it only
contains kABI symbols. If you're adding a symbol to kABI, it is simpler to just
insert the relevant line to the Module.kabi as necessary.

Finally, use the kabi tool to create a new minimal Symtypes.kabi file based on
your new kabi_lockedlist. You can use the "kabi consolidate" command for this:

    kabi consolidate -i Symtypes.build -k kabi_lockedlist -o Symtypes.kabi


Debugging kABI Breakages Locally
--------------------------------

While the check-kabi script and kabi tool are run automatically to detect and
report breakages, developers can also run them manually to verify kABI locally.
There are two main ways to do this.

1) Single compilation unit

To compare just the symbols exported by a single CU, compile that file (being
sure to include KBUILD_SYMTYPES=y):

    make KBUILD_SYMTYPES=y mm/slub.o

Then, use "kabi compare" to compare those symbols against the desired kABI. If
any changes are detected, the structure differences will be highlighted as well.

    uek-rpm/tools/kabi compare mm/slub.o uek-rpm/ol8/Symtypes.kabi_x86_64

2) Full build

To check the output of a full build, first clean the source tree and then build
with KBUILD_SYMTYPES=y on the make command line. Then, use "kabi debug" to
compare the full build results against the desired kABI. The following assumes
that the kernel build directory was ".":

    uek-rpm/tools/kabi debug . uek-rpm/ol8/Symtypes.kabi_x86_64

This is roughly equivalent to the following steps:

    uek-rpm/tools/kabi collect . -o Symtypes.build \
        --minimize-kabi uek-rpm/ol8/kabi_lockedlist_x86_64
    uek-rpm/tools/kabi compare --print-missing Symtypes.build \
        uek-rpm/ol8/Symtypes.kabi_x86_64
