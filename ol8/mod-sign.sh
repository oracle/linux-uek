#! /bin/bash

# The modules_sign target checks for corresponding .o files for every .ko that
# is signed. This doesn't work for package builds which re-use the same build
# directory for every flavour, and the .config may change between flavours.
# So instead of using this script to just sign lib/modules/$KernelVer/extra,
# sign all .ko in the buildroot.

# This essentially duplicates the 'modules_sign' Kbuild target and runs the
# same commands for those modules.

parallel=1
internal=
while [[ $# -gt 0 ]]; do
    case $1 in
        -j) parallel=$2
            shift;;
        -j*) parallel="$(echo $1 | sed 's,-j,,')";;
        --single-file) # One job from a parallel multitude.
                    internal=t;;
        *) break;;
    esac
    shift
done

moddir=$1
dgst=$2

MODSECKEY="./certs/signing_key.pem"
MODPUBKEY="./certs/signing_key.x509"

if [[ -n $internal ]]; then
    dir=`dirname $1`
    file=`basename $1`

    ./scripts/sign-file ${dgst} ${MODSECKEY} ${MODPUBKEY} ${dir}/${file} \
       ${dir}/${file}.signed
    mv ${dir}/${file}.signed ${dir}/${file}
    rm -f ${dir}/${file}.{sig,dig}
    exit 0
fi

# Parallel case.

find $moddir -name "*.ko*" -print0 | xargs -0r -P $parallel -n 1 -I'{}' $0 --single-file '{}' $dgst
