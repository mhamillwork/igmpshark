#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "query.h"

#include <netinet/in.h>

#include "igmp_types.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
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

static int pod_facing(const char *name) {
    if (!name)
        return 0;
    if (strncmp(name, "lxc", 3) == 0)
        return 1;
    return strcmp(name, "cilium_host") == 0;
}

/* IP header is included so the source stays self_ip on the way out of lxc*.
 * The kernel overwrites tot_len and the IP checksum. */
static int send_on(int fd, unsigned ifindex, uint32_t src_host, uint32_t dest_host,
                   const uint8_t *igmp, int igmp_len) {
    uint8_t buf[64];
    int len = 20 + igmp_len;
    if (len > (int)sizeof buf)
        return -1;
    memset(buf, 0, (size_t)len);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(len >> 8);
    buf[3] = (uint8_t)len;
    buf[8] = 1;
    buf[9] = IPPROTO_IGMP;
    uint32_t src = htonl(src_host);
    uint32_t dst = htonl(dest_host);
    memcpy(buf + 12, &src, 4);
    memcpy(buf + 16, &dst, 4);
    memcpy(buf + 20, igmp, (size_t)igmp_len);

    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = dst;

    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = (size_t)len;
    char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &to;
    msg.msg_namelen = sizeof to;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (ifindex) {
        memset(cbuf, 0, sizeof cbuf);
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof cbuf;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_IP;
        cm->cmsg_type = IP_PKTINFO;
        cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
        memset(pi, 0, sizeof *pi);
        pi->ipi_ifindex = (int)ifindex;
    }
    return sendmsg(fd, &msg, 0) == len ? 0 : -1;
}

static int send_pod_facing(int fd, uint32_t src_host, uint32_t dest_host, const uint8_t *igmp,
                           int igmp_len) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return -1;
    char seen[1024][IF_NAMESIZE];
    int nseen = 0;
    int ok = 0;
    for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!pod_facing(ifa->ifa_name) || !(ifa->ifa_flags & IFF_UP))
            continue;
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            if (strcmp(seen[i], ifa->ifa_name) == 0)
                dup = 1;
        if (dup)
            continue;
        if (nseen < 1024)
            snprintf(seen[nseen++], IF_NAMESIZE, "%s", ifa->ifa_name);
        unsigned idx = if_nametoindex(ifa->ifa_name);
        if (idx && send_on(fd, idx, src_host, dest_host, igmp, igmp_len) == 0)
            ok = 1;
    }
    freeifaddrs(list);
    return ok ? 0 : -1;
}

int igmp_query_send(const char *ifname, uint32_t src_host, uint32_t group_host, int max_resp_ms,
                    int version) {
    uint8_t pkt[16];
    int n = igmp_query_build(pkt, sizeof pkt, group_host, max_resp_ms, version);
    if (n < 0)
        return -1;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (fd < 0)
        return -1;
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }
    uint32_t dest = group_host ? group_host : 0xe0000001u;
    int rc;
    if (ifname && strcmp(ifname, "any") == 0)
        rc = send_pod_facing(fd, src_host, dest, pkt, n);
    else if (ifname && ifname[0]) {
        unsigned idx = if_nametoindex(ifname);
        rc = idx ? send_on(fd, idx, src_host, dest, pkt, n) : -1;
    } else
        rc = send_on(fd, 0, src_host, dest, pkt, n);
    close(fd);
    return rc;
}
