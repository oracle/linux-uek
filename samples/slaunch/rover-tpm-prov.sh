#!/bin/bash

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Provisioning Input
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Script Input #1: Management Policy RSA Public Key
#
# A 4096 bit RSA key pair must be generated. This will be used to sign
# the management policy files. The public key is input to this script.

# Script Input #2: Security Policy RSA Public Key
#
# A 4096 bit RSA key pair must be generated. This will be used to sign
# the security policy files. The public key is input to this script.

# Script Input #3: Management MLE PCR Values
#
# The management MLE must run once first, read PCRs 17 and 18 and write them to
# a file. This needs to be the same format as
#
# tpm2_pcrread sha256:17,18 -o mle-pcr-values.dat
#
# u-root already has the wrapper function readPCR20() that can do this. This
# can be done on every boot to make it simple.

# Script Input #4: Runtime MLE PCR Values
#
# The runtime MLE must run once first, read PCRs 17 and 18 and write them to
# a file.

# Script Input #5: LUKS key
#
# The key used to LUKS encrypt the partitions which will be sealed to the
# PCR values in locality 2.

# NOTE: This will be done booted to a non-MLE environment in locality 0
# with the Linux TPM2 tools. The safest approach would be to live boot and only
# use tmpfs storage.

export OWNER_AUTH=hex:`tpm2_getrandom -T device --hex 32 2>/dev/null`

usage()
{
    echo "Usage: rover-tpm-prov.sh <mgmt-pubkey-file> <rt-pubkey-file>"
    echo "                         <mgmt-pcrs-file> <rt-pcrs-file>"
    echo "                         <luks-key-file>"
    exit 1
}

tpm_take_ownership()
{
    tpm2_changeauth -T device -c o $OWNER_AUTH

    # ***TODO*** DONT DO THIS IN PROD, JUST POINTING OUT IT NEEDS TO BE DONE. BOTH
    # OWNER AUTH VALUE AND LUKS KEY NEED TO BE ESCROWED. THE MANAGEMENT DATA FILE
    # COULD BE USED FOR THIS.
    echo $OWNER_AUTH > owner-auth.txt

    echo "Changed owner auth"
}

tpm_provision_policy_pubkey()
{
    local pubkey_file=$1
    local policy_index=$2

    sha256sum $pubkey_file | cut -d ' ' -f 1 | xxd -r -p > pubkey.hash

    tpm2_nvdefine -T device -C o -P $OWNER_AUTH -s 256 -a "authread|ownerread|policywrite|ownerwrite" $policy_index

    tpm2_nvwrite -T device -C o -P $OWNER_AUTH -i pubkey.hash $policy_index

    rm -f pubkey.hash

    echo "Stored Rover key hash at NV index $policy_index"
}

tpm_seal_secrets()
{
    local pcrs_file=$1
    local secrets_file=$2
    local persist_handle=$3

    # Create a root key as parent for sealing context
    tpm2_createprimary -T device -C o -P $OWNER_AUTH -g sha256 -G rsa -c sealing-key.ctx

    # Create the policy object
    tpm2_startauthsession -T device -S trial-session.dat

    tpm2_policypcr -T device -S trial-session.dat -l "sha256:17,18" -f $pcrs_file -L mle-policy.dat

    # Now mle-policy.dat is our policy object

    tpm2_flushcontext -T device trial-session.dat

    echo "Created sealing auth policy: mle-policy.dat"

    # Seal managemet data into a persistent TPM object

    cat $secrets_file | tpm2_create -T device -C sealing-key.ctx -u sealing-key.pub -r sealing-key.priv -L mle-policy.dat -i-

    tpm2_load -T device -C sealing-key.ctx -u sealing-key.pub -r sealing-key.priv -n sealing.name -c sealing.ctx

    MGMT_EVICT_RESULT=`tpm2_evictcontrol -T device -C o -P $OWNER_AUTH -c sealing.ctx $persist_handle`

    rm -f mle-policy.dat trial-session.dat
    rm -f sealing.ctx sealing-key.ctx sealing-key.priv sealing-key.pub sealing.name

    # Return value should be requested persistent-handle: 0x8100000x
    if [ ! -z "`echo $MGMT_EVICT_RESULT | grep $persist_handle`" ]; then
        echo "Sealed data to PCRs 17 and 18 in the TPM, provisioning successful"
    else
        echo "Provisioning failed persisting sealing context, invalid handle"
        exit 1
    fi
}

MGMT_PUBKEY_FILE=$1
RT_PUBKEY_FILE=$2
MGMT_PCRS_FILE=$3
RT_PCRS_FILE=$4
LUKS_KEY=$5

MGMT_POLICY_INDEX=0x01800182
MGMT_KEY_PERSIST_HANDLE=0x81000002
MGMT_AUTH_PERSIST_HANDLE=0x81000004
RT_POLICY_INDEX=0x01800180
RT_PERSIST_HANDLE=0x81000000

if [ $# -ne 5 ]; then
	usage
fi

# Take ownership with random hex owner auth value
tpm_take_ownership

# Provision management NVRAM index with policy key hash
tpm_provision_policy_pubkey "$MGMT_PUBKEY_FILE" "$MGMT_POLICY_INDEX"
echo "Provisioned management policy NVRAM index"

# Sealing management key secret
tpm_seal_secrets "$MGMT_PCRS_FILE" "$LUKS_KEY" "$MGMT_KEY_PERSIST_HANDLE"
echo "Sealed management LUKS key secret"

# Sealing management owner auth secret
echo $OWNER_AUTH | cut -c 5- | xxd -r -p > mgmt-tmp.bin
tpm_seal_secrets "$MGMT_PCRS_FILE" "mgmt-tmp.bin" "$MGMT_AUTH_PERSIST_HANDLE"
rm -f mgmt-tmp.bin
echo "Sealed management owner auth secret"

# Provision runtime NVRAM index with policy key hash
tpm_provision_policy_pubkey "$RT_PUBKEY_FILE" "$RT_POLICY_INDEX"
echo "Provisioned runtime policy NVRAM index"

# Sealing runtime key secret
tpm_seal_secrets "$RT_PCRS_FILE" "$LUKS_KEY" "$RT_PERSIST_HANDLE"
echo "Sealed runtime LUKS key secret"
