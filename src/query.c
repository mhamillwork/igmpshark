#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "query.h"

#include <netinet/in.h>

#include "igmp_types.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int igmp_query_build(uint8_t *out, size_t cap, uint32_t group_host, int max_resp_ms, int version) {
    if (!out || cap < 8)
        return -1;
    memset(out, 0, cap < 12 ? cap : 12);
    int deciseconds = max_resp_ms / 100;
    if (deciseconds < 0)
        deciseconds = 0;
    if (deciseconds > 255)
        deciseconds = 255;
    out[0] = 0x11;
    out[1] = (uint8_t)deciseconds;
    uint32_t g = htonl(group_host);
    memcpy(out + 4, &g, 4);
    size_t len = 8;
    if (version >= 3) {
        if (cap < 12)
            return -1;
        len = 12;
    }
    uint16_t c = igmp_checksum(out, len);
    out[2] = (uint8_t)(c >> 8);
    out[3] = (uint8_t)c;
    return (int)len;
}

int igmp_query_send(const char *ifname, uint32_t group_host, int max_resp_ms, int version) {
    uint8_t pkt[16];
    int n = igmp_query_build(pkt, sizeof pkt, group_host, max_resp_ms, version);
    if (n < 0)
        return -1;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (fd < 0)
        return -1;
    if (ifname && ifname[0]) {
        unsigned idx = if_nametoindex(ifname);
        if (idx == 0) {
            close(fd);
            return -1;
        }
        struct ip_mreqn mreq;
        memset(&mreq, 0, sizeof mreq);
        mreq.imr_ifindex = (int)idx;
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof mreq) != 0) {
            close(fd);
            return -1;
        }
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    uint32_t dest = group_host ? group_host : 0xe0000001u;
    dst.sin_addr.s_addr = htonl(dest);
    int rc = sendto(fd, pkt, (size_t)n, 0, (struct sockaddr *)&dst, sizeof dst) == n ? 0 : -1;
    close(fd);
    return rc;
}
