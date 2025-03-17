#! /usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Build script for the UEK 8 FIPS 140 cryptographic module.
#
# Copyright © 2025, Oracle and/or its affiliates.
#

import argparse
import glob
import os
import subprocess
import sys
import tempfile

import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--key', default="Sphinx of black quartz, judge my vow")
parser.add_argument('--kernel-dir', '-C')
parser.add_argument('--make-args', default=[], nargs=argparse.REMAINDER)

args = parser.parse_args()

with open('sources.yaml') as f:
    sources = yaml.safe_load(f)

source_kos = set(os.path.basename(path) for path in sources.keys())

kmodsrc = os.path.join(os.getcwd(), 'kmodsrc')

#
# Build kmodsrc/crypto/*.ko
#
subprocess.check_call([
    'make',
    '-C', args.kernel_dir,
    f'M={kmodsrc}',
    'FIPS140_BUILD_CRYPTO=1',
    'KBUILD_MODPOST_WARN=1',
    'modname-prefix=fips_',
] + args.make_args)

#
# strip BTF and record dependencies
#

built_kos = set()
path_by_modname = {}
deps_by_modname = {}
for ko_path in glob.glob(os.path.join(os.path.dirname(__file__), 'kmodsrc/crypto/*.ko')):
    basename = os.path.basename(ko_path)
    built_kos.add(basename)

    modname, _ = os.path.splitext(basename)

    # strip debuginfo/BTF
    # TODO: do we want to keep this in a separate debuginfo RPM?
    # TODO: do we want to use temporary files for this?
    subprocess.check_call(['strip', '--strip-debug', '--remove-section=.BTF', ko_path])

    path_by_modname[modname] = ko_path

    deps = subprocess.check_output(['modinfo', '-F', 'depends', ko_path], text=True).rstrip('\n')
    deps_by_modname[modname] = deps.split(',') if deps else []

#
# check that we built what we expected to build
#

extra_kos = built_kos - source_kos
if extra_kos:
    print(f"error: the following modules were built but not specified in sources.yaml: {extra_kos}", file=sys.stderr)
    sys.exit(1)

missing_kos = source_kos - built_kos
if missing_kos:
    print(f"warning: the following modules were not built: {missing_kos}", file=sys.stderr)

#
# depth-first path traversal so the modules are added to
# the archive in the order they need to be loaded
#

# skip tcrypt as we'll do that last
done = set(['tcrypt'])
paths = []

def add_module(modname):
    if modname in done:
        return

    for dep in deps_by_modname[modname]:
        add_module(dep)

    paths.append(path_by_modname[modname])
    done.add(modname)

priority_modnames = [
    'cryptomgr', # needs to be first?
    'sha3_generic', # needed by jitterentropy_rng
    'jitterentropy_rng', # must be loaded before drbg
]

for modname in priority_modnames + list(path_by_modname):
    add_module(modname)

done.remove('tcrypt')
add_module('tcrypt')

#
# create archive and object files
#

fips140_archive_a = 'kmodsrc/fips140-archive.a'

try:
    # take care to remove this first as 'ar' doesn't always create the
    # archive from scratch if the file already exists
    os.remove(fips140_archive_a)
except FileNotFoundError:
    pass

subprocess.check_call(['ar', 'rcS', fips140_archive_a] + paths)

#
# Build kmodsrc/fips140.ko
#
subprocess.check_call([
    'make',
    '-C', args.kernel_dir,
    f'M={kmodsrc}',
    'FIPS140_BUILD_MODULE=1',
    f'FIPS140_INTEG_HMAC_KEY={args.key}',
    'KBUILD_MODPOST_WARN=1',
] + args.make_args)

#
# Create object files
#

fips140_ko = 'fips140.ko'
fips140_hmac = 'fips140.hmac'

subprocess.check_call(['openssl', 'dgst', '-sha256', '-hmac', args.key, '-binary', '-out', fips140_hmac, fips140_ko], cwd='kmodsrc')
