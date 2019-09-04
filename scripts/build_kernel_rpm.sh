#!/bin/bash

# Specify a specific commit to build. Can leave empty to use most recent commit.

export COMMIT=

# Update the VERSION below to match version specified in buildrpm/ol7/edk2.spec

export VERSION=4.14.35

if [ -z ${COMMIT:+x} ]; then
        export COMMIT=`git log --oneline | head -1 | awk '{print $1}'`;
fi

echo Commit to build=${COMMIT}

export HOME=`pwd`

echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

rm -rf ~/rpmbuild/
rpmdev-setuptree

# create the archive
git archive --format=tar --prefix=linux-${VERSION}/ ${COMMIT} | bzip2 > ~/rpmbuild/SOURCES/linux-${VERSION}.tar.bz2

# copy over patches
cp uek-rpm/ol7/* ~/rpmbuild/SOURCES

# build it (using securelaunch flag)
rpmbuild -ba --with securelaunch uek-rpm/ol7/kernel-uek.spec
