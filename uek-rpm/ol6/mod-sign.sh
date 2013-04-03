#! /bin/bash

# The modules_sign target checks for corresponding .o files for every .ko that
# is signed. This doesn't work for package builds which re-use the same build
# directory for every flavour, and the .config may change between flavours.
# So instead of using this script to just sign lib/modules/$KernelVer/extra,
# sign all .ko in the buildroot.

# This essentially duplicates the 'modules_sign' Kbuild target and runs the
# same commands for those modules.

moddir=$1

modules=`find $moddir -name *.ko`

MODSECKEY="./signing_key.priv"
MODPUBKEY="./signing_key.x509"

for mod in $modules
do
    dir=`dirname $mod`
    file=`basename $mod`

    ./scripts/sign-file sha256 ${MODSECKEY} ${MODPUBKEY} ${dir}/${file} \
       ${dir}/${file}.signed
    mv ${dir}/${file}.signed ${dir}/${file}
    rm -f ${dir}/${file}.{sig,dig}
done
