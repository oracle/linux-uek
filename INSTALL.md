# Installation

Installation of the UEK-next Developer Release can be achieved in 2 ways:

- Creation of a DNF repository file (preferred mechanism)
- Direct installation of the RPMs

But the first step should be to install the Development GPG Key that is used for verifying the Oracle-built UEK-next RPMs

## Requirements

Some additional packages should be updated before installation

- libdnf updates, which consists of

  - libdnf-0.69.0-6.0.2
  - python3-libdnf-0.69.0-6.0.2
  - python3-hawkey-0.69.0-6.0.2

## Install the Development GPG Key

The RPM provided for installation are GPG signed using a Developer GPG Key, not
the usual Oracle Linux GPG signing key. To validate RPMs, it is advisable to
install this key on the system that you intend to install UEK-next on.

The simplest way to install this GPG Key is using the command:

```
$ sudo rpm --import https://yum.oracle.com/RPM-GPG-KEY-oracle-development
```

Further details on these signing keys can be found at:

- [Development GPG Signing Keys](https://linux.oracle.com/security/gpg/index.html)

## DNF Repo-based Installation

### Repository Configuration

Create a file in `/etc/yum.repos.d` such as `/etc/yum.repos.d/uek-next-developer-ol9.repo`, with the following content:


```
[ol9_developer_UEKnext]
name=UEK-next Developer Release
baseurl=https://yum$ociregion.$ocidomain/repo/OracleLinux/OL9/developer/UEKnext/$basearch/
gpgkey=https://yum.oracle.com/RPM-GPG-KEY-oracle-development
gpgcheck=1
enabled=1
```
### Install
```
sudo dnf install \
   kernel-ueknext \
   kernel-ueknext-core \
   kernel-ueknext-modules-core \
   kernel-ueknext-modules
```


### DNF Direct Installation

The minimum set of files that are required for installation are:

```
kernel-ueknext-VERSION.el9ueknext.ARCH.rpm
kernel-ueknext-core-VERSION.el9ueknext.ARCH.rpm
kernel-ueknext-modules-core-VERSION.el9ueknext.ARCH.rpm
kernel-ueknext-modules-VERSION.el9ueknext.ARCH.rpm
```

These can be downloaded from an architecture specific directory, such as one of:

- x86_64

  - https://yum.oracle.com/repo/OracleLinux/OL9/developer/UEKnext/x86_64/

- aarch64

  - https://yum.oracle.com/repo/OracleLinux/OL9/developer/UEKnext/aarch64/

Once downloaded, you may want to verify the signature on the RPMs using the `rpm -K` command:

```
$ rpm -K *.rpm
```

Installation can then be done using the dnf install command as follows:

```
VERSION="v6.11.0-1"
ARCH="$(uname -p)"

sudo dnf install \
    "./kernel-ueknext-${VERSION}.el9ueknext.${ARCH}.rpm" \
    "./kernel-ueknext-core-${VERSION}.el9ueknext.${ARCH}.rpm" \
    "./kernel-ueknext-headers-${VERSION}.el9ueknext.${ARCH}.rpm" \
    "./kernel-ueknext-modules-core-${VERSION}.el9ueknext.${ARCH}.rpm" \
    "./kernel-ueknext-modules-${VERSION}.el9ueknext.${ARCH}.rpm"
```
