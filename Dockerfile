# UBI 9 image. libwireshark 4.2.6 is compiled here because UBI 9 does not
# ship that library. flex, c-ares, and c-ares-devel come from dnf
# (scripts/install-flex-c-ares.sh). The Wireshark tarball is fetched during
# the build unless third_party/wireshark-4.2.6.tar.xz is in the context.
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

ARG WS_TARBALL=third_party/wireshark-4.2.6.tar.xz
RUN if [ -f "$WS_TARBALL" ]; then \
        mkdir -p /opt/wireshark-4.2.6 && tar -xJf "$WS_TARBALL" --strip-components=1 -C /opt/wireshark-4.2.6; \
    fi
RUN NATIVE=0 \
        sh -c 'if [ -f /opt/wireshark-4.2.6/CMakeLists.txt ]; then mkdir -p "$HOME" && rm -rf "$HOME/wireshark-4.2.6" && mv /opt/wireshark-4.2.6 "$HOME/wireshark-4.2.6"; fi; \
               ./scripts/build-wireshark-4.2.6.sh "$HOME/wireshark-4.2.6"' \
    && WS="$HOME/wireshark-4.2.6" ./scripts/build.sh \
    && mkdir -p /opt/igmpshark/lib \
    && cp build/run/igmpshark /opt/igmpshark/igmpshark \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwireshark.so* /opt/igmpshark/lib/ \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwiretap.so* /opt/igmpshark/lib/ \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwsutil.so* /opt/igmpshark/lib/ \
    && cp -a /usr/lib64/libcares.so.2* /opt/igmpshark/lib/

FROM registry.access.redhat.com/ubi9/ubi:9.8
RUN dnf -y install \
        glib2 libgcrypt libgpg-error libpcap pcre pcre2 zlib libxml2 lz4-libs libzstd \
        libnghttp2 brotli krb5-libs libssh xz-libs ca-certificates \
    && dnf clean all
COPY --from=build /opt/igmpshark/igmpshark /usr/local/bin/igmpshark
COPY --from=build /opt/igmpshark/lib/ /usr/local/lib/igmpshark/
ENV LD_LIBRARY_PATH=/usr/local/lib/igmpshark
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/igmpshark"]
CMD ["--help"]
