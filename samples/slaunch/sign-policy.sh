#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: sign-policy <rsa-privkey> <rsa-pubkey> <policy-file>"
    exit 1
fi

PRIVKEY=$1
PUBKEY=$2
POLICY=$3
SIGFILE=`echo $POLICY | cut -f 1 -d '.'`.sig

openssl dgst -sha256 -sign $PRIVKEY -out $SIGFILE $POLICY

echo "Signed $POLICY -- signature file $SIGFILE"

openssl dgst -sha256 -verify $PUBKEY -signature $SIGFILE $POLICY
