#define _DEFAULT_SOURCE
#include <sys/types.h>
#include "igmp_types.h"
#include "ws_capture.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", msg);
        failures++;
    }
}

static int link_of(int dlt) {
    if (dlt == DLT_EN10MB)
        return IGMP_LINK_ETHERNET;
    if (dlt == DLT_LINUX_SLL)
        return IGMP_LINK_SLL;
#ifdef DLT_LINUX_SLL2
    if (dlt == DLT_LINUX_SLL2)
        return IGMP_LINK_SLL2;
#endif
    return IGMP_LINK_RAW;
}

static int wtap_of(int dlt) {
    if (dlt == DLT_EN10MB)
        return 1;
    if (dlt == DLT_LINUX_SLL)
        return 25;
#ifdef DLT_LINUX_SLL2
    if (dlt == DLT_LINUX_SLL2)
        return 210;
#endif
    return 7;
}

static int replay(const char *path) {
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, err);
    if (!p) {
        fprintf(stderr, "open %s: %s\n", path, err);
        return -1;
    }
    int dlt = pcap_datalink(p);
    int hits = 0, parsed = 0, rejected = 0, ws_miss = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;
    while ((rc = pcap_next_ex(p, &hdr, &data)) == 1) {
        int ws = ws_capture_frame_is_igmp(data, hdr->caplen, hdr->len, wtap_of(dlt));
        igmp_message msg;
        int pr = igmp_parse_ipv4(data, hdr->caplen, link_of(dlt), &msg);
        if (ws < 0) {
            fprintf(stderr, "dissector failed\n");
            pcap_close(p);
            return -1;
        }
        if (ws == 1)
            hits++;
        else
            ws_miss++;
        if (pr == 0 && msg.ok && msg.checksum_ok)
            parsed++;
        else
            rejected++;
        if (ws == 1)
            expect(pr == 0 && msg.checksum_ok, "wireshark igmp frame parses");
    }
    pcap_close(p);
    expect(hits >= 3, "v2 report, v3 report, and query dissected");
    expect(parsed >= 3, "parser accepted the same valid frames");
    expect(rejected >= 1, "truncated or non-igmp frame rejected by parser");
    expect(ws_miss >= 1, "tcp frame is not igmp");
    printf("%s hits=%d parsed=%d rejected=%d other=%d\n", path, hits, parsed, rejected, ws_miss);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: test_ws file.pcap [file.pcapng]\n");
        return 2;
    }
    int major = 0, minor = 0, micro = 0;
    if (ws_capture_init() != 0)
        return 1;
    ws_capture_version(&major, &minor, &micro);
    expect(major == 4 && minor == 6 && micro == 9, "libwireshark 4.6.9");
    for (int i = 1; i < argc; i++) {
        if (replay(argv[i]) != 0)
            failures++;
    }
    ws_capture_shutdown();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
