#! /usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Initialize the repository with Linux kernel source files from a given
# directory.
#
# Copyright © 2025, Oracle and/or its affiliates.
#

import argparse
import errno
import os
import subprocess
import sys

import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--all', '-a', action='store_true')
parser.add_argument('--dry-run', '-n', action='store_true')
parser.add_argument('kernel_dir')
parser.add_argument('paths', metavar='path', default=[], nargs='*')

args = parser.parse_args()

with open('sources.yaml') as f:
    sources = yaml.safe_load(f)

all_source_paths = set()
for ko_path, source_paths in sources.items():
    all_source_paths.update(source_paths)

todo = set()

if args.all:
    todo = all_source_paths

not_in_sources = set(args.paths) - all_source_paths
if not_in_sources:
    print(f"error: paths not in sources.yaml: {not_in_sources}", file=sys.stderr)
    sys.exit(1)

todo.update(args.paths)

kmodsrc = 'kmodsrc/crypto/'

if not args.dry_run:
    try:
        os.makedirs(kmodsrc)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass

for source_path in sorted(todo):
    src = os.path.join(args.kernel_dir, source_path)
    dest = os.path.join(kmodsrc, os.path.basename(source_path))

    print(f"Copy {src} to {dest}")
    if not args.dry_run:
        #shutil.copy(os.path.join(args.kernel_dir, source_path), kmodsrc)
        try:
            os.unlink(dest)
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass

        if not os.path.exists(src):
            print(f"error: path does not exist: {src}", file=sys.stderr)
            sys.exit(1)

        os.symlink(os.path.relpath(src, os.path.dirname(dest)), dest)
