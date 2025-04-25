#!/bin/bash
set -o nounset
set -o errexit
set -o pipefail

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Part 1:
#
#  Provisioning Input
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# We assume the existance of the following files in the same directory as the
# script:
#
#   mle-prov.dat
#   mle-prov-pl.dat
#   securelaunch.pubkey
#   securelaunch-pl.pubkey
#
# We also assume that both the SL and PL kernels will use the same PCRs to
# seal their secrets.

# Script Input #1: MLE Sealing PCRs List
#
# The list of PCRs to use to seal values against in both the SL and PL MLEs.
# The script will extract the relevent entries from the PCR values files.

# Script Input #2: LUKS key file
#
# A file wit the key used to LUKS encrypt the partitions which will be sealed
# to the PCR values in locality 2.

# NOTE: This will be done booted to a non-MLE environment in locality 0
# with the Linux TPM2 tools. The safest approach would be to live boot and only
# use tmpfs storage.

# A safe place to write things
test -w /run

SAFE_SPACE=/run/_tpm_prov
rm -rf "${SAFE_SPACE}"
mkdir -p "${SAFE_SPACE}"

_cleanup() {
  rm -rf "${SAFE_SPACE}"
}

trap _cleanup EXIT

OWNER_AUTH=$(tpm2_getrandom -T device --hex 32 2>/dev/null)
test -n "${OWNER_AUTH}"
# Why is this exported?
export OWNER_AUTH="hex:${OWNER_AUTH}"

usage()
{
    echo "Usage: rover-tpm-prov.sh <seal-pcrs>"
    echo "                         <luks-key-file>"
    echo ""
    echo "  This script assumes the the following files exist:"
    echo "    mle-prov.dat"
    echo "    mle-prov-pl.dat"
    echo "    securelaunch.pubkey"
    echo "    securelaunch-pl.pubkey"
    exit 1
}

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Part 2:
#
#  Generic TPM Provisioning
#n
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
tpm_take_ownership()
{
    tpm2_changeauth -T device -c o ${OWNER_AUTH}
    echo "Changed owner auth"
}

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Provision NVRAM Index with Policy Key Hash
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
tpm_provision_policy_pubkey()
{
    local pubkey_file=$1
    local policy_index=$2

    sha256sum $pubkey_file | cut -d ' ' -f 1 | xxd -r -p > "${SAFE_SPACE}/pubkey.hash"

    tpm2_nvdefine -T device -C o -P ${OWNER_AUTH} -s 256 -a "authread|ownerread|policywrite|ownerwrite" $policy_index

    tpm2_nvwrite -T device -C o -P ${OWNER_AUTH} -i "${SAFE_SPACE}/pubkey.hash" $policy_index

    rm -f "${SAFE_SPACE}/pubkey.hash"

    echo "Stored Rover key hash at NV index $policy_index"
}

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Seal LUKS key into a persistent TPM object
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
tpm_seal_secrets()
{
    local pcrs_list=$1
    local pcrs_full_file=$2
    local secrets_file=$3
    local persist_handle=$4
    local pcrs_file="${SAFE_SPACE}/mle-pcrs.dat"

    rm -f "${pcrs_file}"
    OLD_IFS=$IFS
    IFS=','
    read -a pcrs_array <<< "$pcrs_list"
    for pcr in "${pcrs_array[@]}"; do
        dd if=${pcrs_full_file} skip=$pcr bs=32 count=1 >> "${pcrs_file}"
    done
    IFS=$OLD_IFS

    # Create a root key as parent for sealing context
    tpm2_createprimary -T device -C o -P ${OWNER_AUTH} -g sha256 -G rsa -c "${SAFE_SPACE}/sealing-key.ctx"

    # Create the policy object
    tpm2_startauthsession -T device -S "${SAFE_SPACE}/trial-session.dat"

    tpm2_policypcr -T device -S "${SAFE_SPACE}/trial-session.dat" -l "sha256:${pcrs_list}" -f "${pcrs_file}" -L "${SAFE_SPACE}/mle-policy.dat"

    # Now "${SAFE_SPACE}/mle-policy.dat" is our policy object

    tpm2_flushcontext -T device "${SAFE_SPACE}/trial-session.dat"

    echo "Created sealing auth policy: "${SAFE_SPACE}/mle-policy.dat""

    # Seal PL data into a persistent TPM object

    cat "${secrets_file}" | tpm2_create -T device -C "${SAFE_SPACE}/sealing-key.ctx" -u "${SAFE_SPACE}/sealing-key.pub" -r "${SAFE_SPACE}/sealing-key.priv" -L "${SAFE_SPACE}/mle-policy.dat" -i-

    tpm2_load -T device -C "${SAFE_SPACE}/sealing-key.ctx" -u "${SAFE_SPACE}/sealing-key.pub" -r "${SAFE_SPACE}/sealing-key.priv" -n "${SAFE_SPACE}/sealing.name" -c "${SAFE_SPACE}/sealing.ctx"

    PL_EVICT_RESULT=$(tpm2_evictcontrol -T device -C o -P $OWNER_AUTH -c "${SAFE_SPACE}/sealing.ctx" "${persist_handle}")

    rm -f "${SAFE_SPACE}/mle-policy.dat" "${SAFE_SPACE}/trial-session.dat"
    rm -f "${SAFE_SPACE}/sealing.ctx" "${SAFE_SPACE}/sealing-key.ctx" "${SAFE_SPACE}/sealing-key.priv" "${SAFE_SPACE}/sealing-key.pub" "${SAFE_SPACE}/sealing.name"

    # Return value should be requested persistent-handle: 0x8100000x
    if [ ! -z "$(echo $PL_EVICT_RESULT | grep ${persist_handle})" ]; then
        echo "Provisioning successful. Sealed data to PCRs: ${pcrs_list}"
    else
        echo "Provisioning failed persisting sealing context, invalid handle"
        exit 1
    fi
}

if [ $# -ne 2 ]; then
    usage
fi

PL_PUBKEY_FILE=securelaunch-pl.pubkey
PL_PCRS_FILE=mle-prov-pl.dat
PL_SEAL_PCRS=$1
SL_PUBKEY_FILE=securelaunch.pubkey
SL_PCRS_FILE=mle-prov.dat
SL_SEAL_PCRS=$1
LUKS_KEY_FILE=$2

PL_POLICY_INDEX=0x01800182
PL_KEY_PERSIST_HANDLE=0x81000002
PL_AUTH_PERSIST_HANDLE=0x81000004
SL_POLICY_INDEX=0x01800180
SL_PERSIST_HANDLE=0x81000000

# sanity check
test -s "${PL_PUBKEY_FILE}"
test -s "${PL_PCRS_FILE}"
test -n "${PL_SEAL_PCRS}"
test -s "${SL_PUBKEY_FILE}"
test -s "${SL_PCRS_FILE}"
test -n "${SL_SEAL_PCRS}"
test -s "${LUKS_KEY_FILE}"

# Take ownership with random hex owner auth value
tpm_take_ownership

# Provision PL NVRAM index with policy key hash
tpm_provision_policy_pubkey "${PL_PUBKEY_FILE}" "${PL_POLICY_INDEX}"
echo "Provisioned PL policy NVRAM index"

# Sealing PL key secret
tpm_seal_secrets ${PL_SEAL_PCRS} "${PL_PCRS_FILE}" "${LUKS_KEY_FILE}" "${PL_KEY_PERSIST_HANDLE}"
echo "Sealed PL LUKS key secret"

# Sealing PL owner auth secret
echo ${OWNER_AUTH} | cut -c 5- | xxd -r -p > ${SAFE_SPACE}/pl-tmp.bin
tpm_seal_secrets ${PL_SEAL_PCRS} "${PL_PCRS_FILE}" "${SAFE_SPACE}/pl-tmp.bin" "${PL_AUTH_PERSIST_HANDLE}"
echo "Sealed PL owner auth secret"

# Provision SL NVRAM index with policy key hash
tpm_provision_policy_pubkey "${SL_PUBKEY_FILE}" "${SL_POLICY_INDEX}"
echo "Provisioned SL policy NVRAM index"

# Sealing SL key secret
tpm_seal_secrets ${SL_SEAL_PCRS} "${SL_PCRS_FILE}" "${LUKS_KEY_FILE}" "${SL_PERSIST_HANDLE}"
echo "Sealed SL LUKS key secret"

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Provisioning is complete. Cleanup.
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

_cleanup
