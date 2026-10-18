#!/bin/sh
# Install flex, c-ares, and c-ares-devel with dnf.
# On a subscribed RHEL 9 host those packages are in BaseOS and AppStream.
# The public UBI 9 content set does not include them, so if that install
# finds no match this uses the Rocky Linux 9 el9 repositories for these
# packages only and then removes that repo file.
set -eu

if dnf -y install flex c-ares c-ares-devel; then
    rpm -q flex c-ares c-ares-devel
    exit 0
fi

curl -fsSL -o /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9 \
    https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9
cat > /etc/yum.repos.d/rocky9-flex-cares.repo <<'EOF'
[rocky9-baseos]
name=Rocky Linux 9 BaseOS
baseurl=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1

[rocky9-appstream]
name=Rocky Linux 9 AppStream
baseurl=https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1
EOF

dnf -y install flex c-ares c-ares-devel
rm -f /etc/yum.repos.d/rocky9-flex-cares.repo
rpm -q flex c-ares c-ares-devel
