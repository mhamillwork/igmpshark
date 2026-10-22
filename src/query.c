#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "query.h"

#include <netinet/in.h>

#include "igmp_types.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

int igmp_v3_toex_build(uint8_t *out, size_t cap, uint32_t group_host) {
    if (!out || cap < 16)
        return -1;
    memset(out, 0, 16);
    out[0] = 0x22;
    out[7] = 1;
    out[8] = IGMP_REC_TO_EXCLUDE;
    uint32_t g = htonl(group_host);
    memcpy(out + 12, &g, 4);
    uint16_t c = igmp_checksum(out, 16);
    out[2] = (uint8_t)(c >> 8);
    out[3] = (uint8_t)c;
    return 16;
}

static int line_has_token(const char *s, size_t len, const char *tok) {
    size_t n = strlen(tok);
    for (size_t i = 0; i + n <= len; i++) {
        if (memcmp(s + i, tok, n) != 0)
            continue;
        if (i > 0) {
            unsigned char prev = (unsigned char)s[i - 1];
            if (isdigit(prev) || prev == '.')
                continue;
        }
        if (i + n < len) {
            unsigned char next = (unsigned char)s[i + n];
            if (isdigit(next) || next == '.')
                continue;
        }
        return 1;
    }
    return 0;
}

static int line_blank(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (s[i] != ' ' && s[i] != '\t' && s[i] != '\r')
            return 0;
    return 1;
}

/* The leaf line is `| -- 10.42.5.149` with the flags on the next line.
 * A prefix such as `+-- 10.42.5.0/24` also contains an address token, and
 * the next leaf's `/32 host LOCAL` is not that prefix. */
static int leaf_line(const char *s, size_t len) {
    return memmem(s, len, "/", 1) == NULL;
}

int igmp_fib_trie_has_local(const char *text, uint32_t ip) {
    if (!text || ip == 0)
        return 0;
    char want[32];
    igmp_ip_fmt(ip, want, sizeof want);
    int in_local = 0;
    const char *leaf = NULL;
    size_t leaf_len = 0;
    int pending = 0;
    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        int header = 0;
        if (len >= 5 && strncmp(p, "Local", 5) == 0 && (len == 5 || p[5] == ':')) {
            in_local = 1;
            pending = 0;
            header = 1;
        } else if (len >= 4 && strncmp(p, "Main", 4) == 0 && (len == 4 || p[4] == ':')) {
            in_local = 0;
            pending = 0;
            header = 1;
        }
        if (!header && in_local && !line_blank(p, len)) {
            if (line_has_token(p, len, want) && memmem(p, len, "/32 host LOCAL", 14))
                return 1;
            if (pending && line_has_token(leaf, leaf_len, want) && leaf_line(leaf, leaf_len) &&
                memmem(p, len, "/32 host LOCAL", 14))
                return 1;
            leaf = p;
            leaf_len = len;
            pending = 1;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return 0;
}

static int read_trie(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r < 0) {
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        n += (size_t)r;
    }
    close(fd);
    buf[n] = 0;
    return 0;
}

int igmp_netns_for_local_ip(uint32_t ip, char *out, size_t cap) {
    if (!out || cap < 16 || ip == 0)
        return -1;
    static uint32_t cached_ip;
    static char cached[64];
    if (cached_ip == ip && cached[0]) {
        char pidbuf[32];
        /* /proc/<pid>/ns/net -> trie at /proc/<pid>/net/fib_trie */
        {
            const char *ns = strstr(cached, "/ns/net");
            if (ns && (size_t)(ns - cached) < sizeof pidbuf) {
                memcpy(pidbuf, cached, (size_t)(ns - cached));
                pidbuf[ns - cached] = 0;
                char trie[96];
                snprintf(trie, sizeof trie, "%s/net/fib_trie", pidbuf);
                /* A busy node's Local section does not fit in a small stack
                 * buffer. Truncating it made a neighbor's leaf look local. */
                char *body = malloc(1 << 20);
                int hit = body && read_trie(trie, body, 1 << 20) == 0 &&
                          igmp_fib_trie_has_local(body, ip);
                free(body);
                if (hit) {
                    snprintf(out, cap, "%s", cached);
                    return 0;
                }
            }
        }
        cached_ip = 0;
        cached[0] = 0;
    }
    struct stat selfns;
    if (stat("/proc/self/ns/net", &selfns) != 0)
        return -1;
    DIR *d = opendir("/proc");
    if (!d)
        return -1;
    ino_t seen[2048];
    int nseen = 0;
    struct dirent *de;
    int found = 0;
    while (!found && (de = readdir(d)) != NULL) {
        char pid[16];
        size_t pi = 0;
        for (; de->d_name[pi] && pi + 1 < sizeof pid; pi++) {
            if (de->d_name[pi] < '0' || de->d_name[pi] > '9')
                break;
            pid[pi] = de->d_name[pi];
        }
        if (pi == 0 || de->d_name[pi] != 0)
            continue;
        pid[pi] = 0;
        char nspath[64];
        snprintf(nspath, sizeof nspath, "/proc/%s/ns/net", pid);
        struct stat st;
        if (stat(nspath, &st) != 0 || st.st_ino == selfns.st_ino)
            continue;
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            if (seen[i] == st.st_ino)
                dup = 1;
        if (dup)
            continue;
        if (nseen < 2048)
            seen[nseen++] = st.st_ino;
        char trie[80];
        snprintf(trie, sizeof trie, "/proc/%s/net/fib_trie", pid);
        char *body = malloc(1 << 20);
        if (!body)
            continue;
        int hit = read_trie(trie, body, 1 << 20) == 0 && igmp_fib_trie_has_local(body, ip);
        free(body);
        if (!hit)
            continue;
        snprintf(out, cap, "%s", nspath);
        snprintf(cached, sizeof cached, "%s", nspath);
        cached_ip = ip;
        found = 1;
    }
    closedir(d);
    return found ? 0 : -1;
}

int igmp_v3_toex_send(const char *netns_path, uint32_t src_host, uint32_t group_host) {
    if (!netns_path || !netns_path[0] || src_host == 0 || group_host == 0)
        return -1;
    uint8_t pkt[16];
    if (igmp_v3_toex_build(pkt, sizeof pkt, group_host) != 16)
        return -1;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int ns = open(netns_path, O_RDONLY);
        if (ns < 0)
            _exit(1);
        if (setns(ns, CLONE_NEWNET) != 0)
            _exit(1);
        close(ns);
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
        if (fd < 0)
            _exit(1);
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) != 0)
            _exit(1);
        unsigned idx = if_nametoindex("eth0");
        int rc = idx ? send_on(fd, idx, src_host, 0xe0000016u, pkt, 16) : -1;
        close(fd);
        _exit(rc == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}
