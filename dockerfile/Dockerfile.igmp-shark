# UBI 9 image. libwireshark 4.6.9 is compiled from
# third_party/wireshark-4.6.9.tar.xz, which is part of this tree, so the
# build does not download Wireshark. UBI 9 does not ship that library.
# flex, c-ares, and c-ares-devel come from dnf
# (scripts/install-flex-c-ares.sh).
# No kubeconfig or credentials are copied into the image.

FROM registry.access.redhat.com/ubi9/ubi:9.8 AS build

# curl-minimal is already installed and conflicts with the curl package.
RUN dnf -y install \
        gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config python3 \
        m4 file \
        glib2-devel libgcrypt-devel libgpg-error-devel libpcap-devel pcre2-devel \
        zlib-devel libxml2-devel lz4-devel libzstd-devel \
        libnghttp2-devel brotli-devel krb5-devel libssh-devel libcurl-devel \
        xz tar gzip ca-certificates diffutils findutils \
    && dnf clean all

WORKDIR /src
COPY . /src
RUN chmod +x scripts/install-flex-c-ares.sh \
    && ./scripts/install-flex-c-ares.sh

RUN chmod +x scripts/build-wireshark-4.6.9.sh \
    && NATIVE=0 ./scripts/build-wireshark-4.6.9.sh /opt/wireshark-4.6.9 \
    && WS=/opt/wireshark-4.6.9 ./scripts/build.sh \
    && mkdir -p /opt/igmpshark/lib \
    && cp -a build/run/igmpshark /opt/igmpshark/igmpshark \
    && cp -a /opt/wireshark-4.6.9/build/run/libwireshark.so* /opt/igmpshark/lib/ \
    && cp -a /opt/wireshark-4.6.9/build/run/libwiretap.so* /opt/igmpshark/lib/ \
    && cp -a /opt/wireshark-4.6.9/build/run/libwsutil.so* /opt/igmpshark/lib/ \
    && cp -a /usr/lib64/libcares.so.2* /opt/igmpshark/lib/

FROM registry.access.redhat.com/ubi9/ubi:9.8
# libcurl-minimal is already installed and provides libcurl.so.4. The libcurl
# package conflicts with it.
RUN dnf -y install \
        glib2 libgcrypt libgpg-error libpcap pcre pcre2 zlib libxml2 libicu lz4-libs libzstd \
        libnghttp2 brotli krb5-libs libssh libstdc++ xz-libs ca-certificates \
    && dnf clean all
COPY --from=build /opt/igmpshark/igmpshark /usr/local/bin/igmpshark
COPY --from=build /opt/igmpshark/lib/ /usr/local/lib/igmpshark/
ENV LD_LIBRARY_PATH=/usr/local/lib/igmpshark
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/igmpshark"]
CMD ["--help"]
