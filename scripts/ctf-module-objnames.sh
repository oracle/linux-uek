#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
# Produce a file mapping module names to object file names for all built-in
# modules in the kernel.  Used by ctfarchive.

set -e

# Translate e.g. ./lib/zstd/common/entropy_common.o into
# ./lib/zstd/common/.entropy_common.o.cmd, and extract the module name from
# that.

sed 's,^\(.*/\)\(.*\)$,\1.\2.cmd,g' .tmp_objects.builtin |\
    xargs grep -o -- '-DKBUILD_MODNAME=[^ ]*' | \
    # Translate e.g. ./lib/zstd/common/.entropy_common.o.cmd:
    # -KDBUILD_MODNAME='"zstd_common"' into zstd_common
    # ./lib/zstd/common/entropy_common.o, and sort the result so the same module
    # always occupies consecutive lines.
    sed 's,^\([^:]*/\)\.\([^:]*\).cmd.*-DKBUILD_MODNAME=."\([^"]*\)".*$,\3 \1\2,' | sort -k1 | \
    # Accumulate filename portions for the same module into one line.
    awk -F ' ' 'BEGIN { mod=""; objs="";}
                $1 != mod { printf ("%s %s\n", mod, objs); mod=$1; objs=""; }
                { objs=objs $2 " "; }
                END { printf ("%s %s\n", mod, objs); }' > .tmp_possible_modobjs

# Filter out the maybe-module names from this list, and sort them.
sed 's, .*,,' < .tmp_possible_modobjs | sort -u -k 1b,1 > .tmp_possible_modules

# Filter the list of possible modules by the list of modules actually in the
# kernel, then use that to exclude non-modules from the list we computed
# earlier.  Trim off trailing spaces, to help the iterator in
# modules_builtin.c.  Complicated a bit by the need to trim off the leading
# kernel/ from modules.builtin.
sed 's,^.*/\([^/]*\)\.ko$,\1,' modules.builtin | sort -u -k 1b,1 | \
    comm - .tmp_possible_modules -12 | join -j 1 - .tmp_possible_modobjs | \
    sed 's, *$,,'> $1
