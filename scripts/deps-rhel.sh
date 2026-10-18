#!/bin/sh
# RHEL 8 / RHEL 9 (and AlmaLinux, Rocky, CentOS Stream) build dependencies.
# Adapted from the dbshark deps-rhel.sh in the attached sqlshark zip.
# PostgreSQL is omitted. CodeReady Builder / CRB / PowerTools is enabled for
# speexdsp-devel and libmaxminddb-devel. The library build turns the GUI
# and sharkd off, so those two are not required for libwireshark.
set -eu
MODE=${1:-all}
. /etc/os-release
RHEL=$(rpm -E %rhel)
case "$RHEL" in
    8|9) ;;
    *) echo "error: this script targets RHEL 8 or 9 (rpm -E %rhel = $RHEL)" >&2; exit 1 ;;
esac
DNF=dnf
command -v dnf >/dev/null 2>&1 || DNF=yum
case "$ID" in
    rhel)
        if command -v subscription-manager >/dev/null 2>&1; then
            subscription-manager repos --enable "codeready-builder-for-rhel-$RHEL-$(arch)-rpms" || true
        fi
        $DNF -y config-manager --set-enabled "codeready-builder-for-rhel-$RHEL-$(arch)-rpms" 2>/dev/null || true
        ;;
    almalinux|rocky|centos)
        if [ "$RHEL" = 8 ]; then
            $DNF -y config-manager --set-enabled powertools 2>/dev/null || true
        else
            $DNF -y config-manager --set-enabled crb 2>/dev/null || true
        fi
        ;;
esac
$DNF -y install dnf-plugins-core >/dev/null 2>&1 || true
BUILD="gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config flex bison python3
    glib2-devel libgcrypt-devel libgpg-error-devel libpcap-devel pcre2-devel c-ares-devel
    zlib-devel gnutls-devel libxml2-devel lz4-devel libzstd-devel
    libnghttp2-devel brotli-devel krb5-devel libssh-devel
    speexdsp-devel libmaxminddb-devel libcurl-devel xz tar"
RUNTIME="glib2 libgcrypt libgpg-error libpcap pcre2 c-ares zlib gnutls libxml2 lz4-libs
    libzstd libnghttp2 brotli krb5-libs libssh speexdsp libmaxminddb libcap libcurl"
TEST="python3 procps-ng iproute hostname libcap"
if [ "$RHEL" = 8 ]; then
    TEST="$TEST python3.11"
fi
case "$MODE" in
    build) $DNF -y install $BUILD ;;
    runtime) $DNF -y install $RUNTIME ;;
    test) $DNF -y install $RUNTIME $TEST ;;
    all) $DNF -y install $BUILD $RUNTIME $TEST ;;
    *) echo "usage: $0 [all|build|runtime|test]" >&2; exit 1 ;;
esac
echo "deps-rhel: installed $MODE on $PRETTY_NAME"
