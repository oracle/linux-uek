#! /usr/bin/env python3

import argparse
import os
import subprocess
import sys

import yaml

# parse all-numeric module names as strings
yaml.SafeLoader.add_constructor('tag:yaml.org,2002:int',
                                lambda loader, node: str(node.value))

parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True,
    help="kernel version (as it appears under /lib/modules/)")
parser.add_argument('--ko-suffix', default='',
    help="kernel module suffix (e.g. .xz)")
parser.add_argument('--output', required=True,
    help="where to place generated .list files")
parser.add_argument('-D', metavar='macro', default=[], action='append',
    help="preprocessor defines (e.g. Flavour_debug)")
parser.add_argument('path',
    help="path to module list (e.g. modules.yaml.S)")
parser.add_argument('denylist_path',
    help="path to denylist (e.g. denylist.txt.S)")

args = parser.parse_args()

error = False

#
# Scan --tree for directories and kernel modules
#

all_dirs = []
all_modules = []

for root, dirs, files in os.walk(f'lib/modules/{args.version}/kernel'):
    for dir in dirs:
        all_dirs.append(os.path.join(root, dir))

    for file in files:
        modname, ext = os.path.splitext(file)
        if ext not in ['.ko']:
            continue

        path = os.path.join(root, file)
        all_modules.append((path, modname))

path_by_module = {}
for path, modname in all_modules:
    path_by_module[modname] = path

print(f"filter-modules.py: {len(all_dirs)} dirs {len(all_modules)} modules")

#
# Read YAML module lists
#

modules_by_subpackage = {}

cpp = subprocess.run(['cpp'] + [f'-D{arg}' for arg in args.D] +
                     ['-P', args.path],
                     stdout=subprocess.PIPE, universal_newlines=True)
data = yaml.safe_load(cpp.stdout)

for subpackage, modnames in data.items():
    modules_by_subpackage.setdefault(subpackage, set()).update(modnames)

#
# Read denylists
#

cpp = subprocess.run(['cpp'] + [f'-D{arg}' for arg in args.D] +
                     ['-P', args.denylist_path],
                     stdout=subprocess.PIPE, universal_newlines=True)
denylist = set(cpp.stdout.splitlines())

#
# Write out modules.packages
#

with open(f"lib/modules/{args.version}/modules.packages", 'w') as f:
    for subpackage, modnames in modules_by_subpackage.items():
        for modname in sorted(modnames):
            rpm_name = f"{os.path.basename(args.output)}-{subpackage}-{args.version}"
            print(f"{modname} {rpm_name}", file=f)

#
# Write out .list files (for use with %files -f)
#

DENYLIST_TEMPLATE="""\
# This kernel module can be automatically loaded by non-root users. To
# enhance system security, the module is denylisted by default to ensure
# system administrators make the module available for use as needed.
# See https://access.redhat.com/articles/3760101 for more details.
#
# Remove the denylist entry by adding a comment # at the start of the line.
blacklist {modname}
"""

paths_seen = set()

for subpackage, modnames in modules_by_subpackage.items():
    lines = []
    for modname in modnames:
        path = path_by_module.get(modname)
        if not path:
            print(f"error: Module {modname} was not built?", file=sys.stderr)
            error = True
            continue

        paths_seen.add(path)
        lines.append((path + args.ko_suffix, ''))

        if modname in denylist:
            denylist_path = f'etc/modprobe.d/{args.version}-{modname}-denylist.conf'

            with open(denylist_path, 'w') as f:
                f.write(DENYLIST_TEMPLATE.format(modname=modname))

            print(f"Wrote {os.path.abspath(denylist_path)}")

            lines.append((denylist_path, '%config(noreplace)'))

    # modules-core is special and includes _all_ the modules directories
    # as well (but not their contents)
    if subpackage == 'modules-core':
        for path in all_dirs:
            lines.append((path, '%dir '))

    filename = f'{args.output}-{subpackage}.list'

    with open(filename, 'w') as f:
        for path, directive in sorted(lines):
            print(f'{directive}/{path}', file=f)

    print(f"Wrote {os.path.abspath(filename)}")

for path in set(path_by_module.values()) - paths_seen:
    print(f"error: {path} built but not specified by any subpackage", file=sys.stderr)
    error = True

