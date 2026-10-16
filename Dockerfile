# Multi-stage build. The Wireshark 4.2.6 tarball is fetched during the build
# unless third_party/wireshark-4.2.6.tar.xz is present in the context.
# No kubeconfig or credentials are copied into the image.

FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make cmake ninja-build pkg-config flex bison python3 \
        libglib2.0-dev libgcrypt20-dev libpcap-dev libpcre2-dev libc-ares-dev \
        zlib1g-dev libgnutls28-dev libxml2-dev liblz4-dev libzstd-dev \
        libnghttp2-dev libbrotli-dev libkrb5-dev libssh-dev libspeexdsp-dev \
        libmaxminddb-dev libcurl4-openssl-dev curl xz-utils tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
ARG WS_TARBALL=third_party/wireshark-4.2.6.tar.xz
RUN if [ -f "$WS_TARBALL" ]; then \
        mkdir -p /opt/wireshark-4.2.6 && tar -xJf "$WS_TARBALL" --strip-components=1 -C /opt/wireshark-4.2.6; \
    fi
RUN WS_SOURCE=tarball NATIVE=0 JOBS=2 \
        sh -c 'if [ -f /opt/wireshark-4.2.6/CMakeLists.txt ]; then mkdir -p "$HOME" && rm -rf "$HOME/wireshark-4.2.6" && mv /opt/wireshark-4.2.6 "$HOME/wireshark-4.2.6"; fi; \
               ./scripts/build-wireshark-4.2.6.sh "$HOME/wireshark-4.2.6"' \
    && WS=$HOME/wireshark-4.2.6 ./scripts/build.sh \
    && mkdir -p /opt/igmpshark/lib \
    && cp build/run/igmpshark /opt/igmpshark/igmpshark \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwireshark.so* /opt/igmpshark/lib/ \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwiretap.so* /opt/igmpshark/lib/ \
    && cp "$HOME/wireshark-4.2.6/build/run"/libwsutil.so* /opt/igmpshark/lib/

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libgcrypt20 libpcap0.8 libpcre2-8-0 libc-ares2 \
        zlib1g libgnutls30 libxml2 liblz4-1 libzstd1 libnghttp2-14 \
        libbrotli1 libkrb5-3 libssh-4 libspeexdsp1 libmaxminddb0 \
        libcurl4 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/igmpshark/igmpshark /usr/local/bin/igmpshark
COPY --from=build /opt/igmpshark/lib/ /usr/local/lib/igmpshark/
ENV LD_LIBRARY_PATH=/usr/local/lib/igmpshark
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/igmpshark"]
CMD ["--help"]
