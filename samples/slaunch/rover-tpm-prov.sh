#!/bin/bash

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Part 1:
#
#  Pre-provisioning Stage
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Script Input #1: RSA Public Key
#
# A 4096 bit RSA key pair must be generated. This will be used to sign
# the policy files. The public key is input to this script.

# Script Input #2: MLE PCR Values
#
# The real MLE must run once first, read PCRs 17 and 18 and write them to
# a file. This needs to be the same format as
#
# tpm2_pcrread sha256:17,18 -o mle-pcr-values.dat
#
# u-root already has the wrapper function readPCR20() that can do this. This
# can be done on every boot to make it simple.

# Script Input #3: LUKS key
#
# The key used to LUKS encrypt the partitions which will be sealed to the
# PCR values in locality 2.

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Part 2:
#
#  Generic TPM Provisioning
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# This will be done booted to a non-MLE environment in locality 0
# with the Linux TPM2 tools.

if [ $# -ne 3 ]; then
    echo "Usage: rover-tpm-prov.sh <pubkey-file> <mle-pcr-file> <luks-key-file>"
    exit 1
fi

PUBKEY_FILE=$1
PCR_FILE=$2
LUKS_KEY=$3

# Take ownership
export OWNER_AUTH=hex:`tpm2_getrandom -T device --hex 32 2>/dev/null`

tpm2_changeauth -T device -c o $OWNER_AUTH

# ***TODO*** DONT DO THIS IN PROD, JUST POINTING OUT IT NEEDS TO BE DONE
echo $OWNER_AUTH > owner-auth.txt

echo "Changed owner auth"

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Provision NVRAM Index with Policy Key Hash
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

POLICY_HASH=`sha256sum $PUBKEY_FILE | cut -d ' ' -f 1 | xxd -r -p`
POLICY_INDEX=0x01800180

tpm2_nvdefine -T device -C o -P $OWNER_AUTH -s 256 -a "authread|ownerread|policywrite|ownerwrite" $POLICY_INDEX

tpm2_nvwrite -T device -C o -P $OWNER_AUTH -i- $POLICY_INDEX <<< $POLICY_HASH

echo "Stored Rover public key hash at NV index $POLICY_INDEX"

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Prepare the policy object for sealing
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#
# Create a key we can use for sealing
#
tpm2_createprimary -T device -C o -P $OWNER_AUTH -g sha256 -G rsa -c sealing-key.ctx

#
# Create the policy object
#
tpm2_startauthsession -T device -S trial-session.dat

tpm2_policypcr -T device -S trial-session.dat -l "sha256:17,18" -f $PCR_FILE -L mle-policy.dat

# Now mle-policy.dat is our policy object

tpm2_flushcontext -T device trial-session.dat

echo "Created sealing auth policy: mle-policy.dat"

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Seal LUKS key into a persistent TPM object
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PERSIST_HANDLE=0x81000000

cat $LUKS_KEY | tpm2_create -T device -C sealing-key.ctx -u sealing-key.pub -r sealing-key.priv -L mle-policy.dat -i-

tpm2_load -T device -C sealing-key.ctx -u sealing-key.pub -r sealing-key.priv -n sealing.name -c sealing.ctx

EVICT_RESULT=`tpm2_evictcontrol -T device -C o -P $OWNER_AUTH -c sealing.ctx $PERSIST_HANDLE`

# Return value should be requested persistent-handle: 0x81000000
if [ ! -z "`echo $EVICT_RESULT | grep $PERSIST_HANDLE`" ]; then
    echo "Sealed LUKS key to PCRs 17 and 18 in the TPM, provisioning successful"
else
    echo "Provisioning failed persisting sealing context, invalid handle"
fi

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Provisioning is complete. Cleanup.
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

rm -f mle-policy.dat trial-session.dat
rm -f sealing.ctx sealing-key.ctx sealing-key.priv sealing-key.pub sealing.name

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#  Part 3:
#
#  MLE Runtime Operations
#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# This is the TPM2 tools equivalent of the wrapper that is needed
# in the u-root tpm/tss code. The calls in the TPM library that
# will be needed in the wrapper are:
# StartAuthSession(), PolicyPCR(), UnsealWithSession(), FlushContext()

#tpm2_startauthsession --policy-session -S unseal-session.dat

#tpm2_policypcr -S unseal-session.dat -l "sha256:17,18" -L unseal-policy.dat

#tpm2_unseal -p session:unseal-session.dat -c 0x81000000 > luks-key-out.bin

#tpm2_flushcontext unseal-session.dat

# After the LUKS key is unsealed, PCRs 17 and 18 need to be capped off. This
# is basically 2 extendPCR20() calls with the hashes set to all bits set
# (i.e. ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff).
#
# This prevents the unseal from being able to happen outside the MLE/locality 2.
