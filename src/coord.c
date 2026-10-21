#include "coord.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* A peer clock a little ahead of ours is still a live snapshot. */
enum { IGMP_SNAP_FUTURE_SKEW_MS = 30000 };

int64_t igmp_coord_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int igmp_coord_ensure(const char *dir) {
    if (!dir || !dir[0])
        return -1;
    if (mkdir(dir, 0755) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int same_name(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

int igmp_coord_parse(const char *text, igmp_peer *peer, igmp_snap_mem *mem, int mem_cap,
                     int *nmem) {
    if (peer)
        memset(peer, 0, sizeof *peer);
    if (nmem)
        *nmem = 0;
    if (!text)
        return -1;
    int count = 0;
    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[512];
        if (len >= sizeof line)
            len = sizeof line - 1;
        memcpy(line, p, len);
        line[len] = 0;
        if (strncmp(line, "NODE ", 5) == 0 && peer) {
            char ipb[64];
            unsigned long long ts = 0;
            int active = 0;
            if (sscanf(line + 5, "%63s %63s %d %llu", peer->name, ipb, &active, &ts) >= 2) {
                igmp_ip_parse(ipb, &peer->ip);
                peer->active = active;
                peer->ts_ms = (int64_t)ts;
            }
        } else if (strncmp(line, "MEM ", 4) == 0 && mem && nmem && count < mem_cap) {
            char gb[64], sb[64], uid[IGMP_UID_LEN];
            unsigned ifindex = 0, ifgen = 0, joined = 0;
            uid[0] = 0;
            if (sscanf(line + 4, "%63s %63s %u %u %u %95s", gb, sb, &joined, &ifindex, &ifgen,
                       uid) >= 3) {
                igmp_snap_mem *m = &mem[count];
                memset(m, 0, sizeof *m);
                if (igmp_ip_parse(gb, &m->group) == 0 && igmp_ip_parse(sb, &m->subscriber) == 0) {
                    m->joined = joined ? 1 : 0;
                    m->ifindex = ifindex;
                    m->ifgen = ifgen;
                    if (uid[0] && strcmp(uid, "-") != 0)
                        snprintf(m->pod_uid, sizeof m->pod_uid, "%s", uid);
                    count++;
                }
            }
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    if (nmem)
        *nmem = count;
    return 0;
}

static int read_file(const char *path, char *buf, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    size_t n = fread(buf, 1, cap - 1, fp);
    int bad = ferror(fp);
    fclose(fp);
    if (bad)
        return -1;
    buf[n] = 0;
    return (int)n;
}

int igmp_coord_write(const char *dir, const char *node, uint32_t node_ip, int active,
                     int64_t now_ms, const igmp_snap_mem *members, int nmem) {
    if (!dir || !dir[0] || !node || !node[0])
        return -1;
    if (igmp_coord_ensure(dir) != 0)
        return -1;
    char path[768], tmp[800];
    snprintf(path, sizeof path, "%s/%s.snap", dir, node);
    snprintf(tmp, sizeof tmp, "%s/%s.snap.tmp", dir, node);
    FILE *fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    char ip[32];
    igmp_ip_fmt(node_ip, ip, sizeof ip);
    fprintf(fp, "NODE %s %s %d %lld\n", node, ip, active ? 1 : 0, (long long)now_ms);
    for (int i = 0; i < nmem; i++) {
        if (!members[i].joined)
            continue;
        char g[32], s[32];
        igmp_ip_fmt(members[i].group, g, sizeof g);
        igmp_ip_fmt(members[i].subscriber, s, sizeof s);
        fprintf(fp, "MEM %s %s %d %u %u %s\n", g, s, 1, members[i].ifindex, members[i].ifgen,
                members[i].pod_uid[0] ? members[i].pod_uid : "-");
    }
    if (fclose(fp) != 0)
        return -1;
    if (rename(tmp, path) != 0)
        return -1;
    return 0;
}

static int load_named(const char *dir, const char *name, char *buf, size_t cap) {
    char path[768];
    snprintf(path, sizeof path, "%s/%s.snap", dir, name);
    return read_file(path, buf, cap);
}

int igmp_coord_peers(const char *dir, const char *self_node, int64_t now_ms, int64_t max_age_ms,
                     igmp_peer *out, int cap) {
    DIR *d = opendir(dir ? dir : "");
    if (!d)
        return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < cap) {
        size_t len = strlen(de->d_name);
        if (len < 6 || strcmp(de->d_name + len - 5, ".snap") != 0)
            continue;
        char node[IGMP_NODE_LEN];
        size_t nlen = len - 5;
        if (nlen >= sizeof node)
            continue;
        memcpy(node, de->d_name, nlen);
        node[nlen] = 0;
        if (same_name(node, self_node))
            continue;
        char buf[1 << 16];
        if (load_named(dir, node, buf, sizeof buf) < 0)
            continue;
        igmp_peer peer;
        if (igmp_coord_parse(buf, &peer, NULL, 0, NULL) != 0 || !peer.name[0])
            continue;
        int64_t age = now_ms - peer.ts_ms;
        peer.fresh = max_age_ms <= 0 || (age >= -IGMP_SNAP_FUTURE_SKEW_MS && age <= max_age_ms);
        out[n++] = peer;
    }
    closedir(d);
    return n;
}

int igmp_coord_load_remote(const char *dir, const char *self_node, int64_t now_ms,
                           int64_t max_age_ms, igmp_remote_sub *out, int cap,
                           uint32_t *stale_ips, int stale_cap, int *nstale) {
    if (nstale)
        *nstale = 0;
    igmp_peer peers[128];
    int np = igmp_coord_peers(dir, self_node, now_ms, max_age_ms, peers, 128);
    if (np < 0)
        return -1;
    int n = 0;
    int ns = 0;
    for (int i = 0; i < np; i++) {
        if (!peers[i].fresh) {
            if (stale_ips && ns < stale_cap && peers[i].ip)
                stale_ips[ns++] = peers[i].ip;
            continue;
        }
        char *buf = malloc(1 << 20);
        igmp_snap_mem *mem = calloc(1024, sizeof *mem);
        if (!buf || !mem) {
            free(buf);
            free(mem);
            continue;
        }
        if (load_named(dir, peers[i].name, buf, 1 << 20) < 0) {
            free(buf);
            free(mem);
            continue;
        }
        int nm = 0;
        igmp_peer peer;
        igmp_coord_parse(buf, &peer, mem, 1024, &nm);
        free(buf);
        for (int m = 0; m < nm; m++) {
            if (!mem[m].joined || peer.ip == 0)
                continue;
            int found = 0;
            for (int r = 0; r < n; r++) {
                if (out[r].node_ip == peer.ip && out[r].group == mem[m].group) {
                    out[r].joined_count++;
                    found = 1;
                    break;
                }
            }
            if (!found && n < cap) {
                out[n].node_ip = peer.ip;
                out[n].group = mem[m].group;
                out[n].joined_count = 1;
                n++;
            }
        }
        free(mem);
    }
    if (nstale)
        *nstale = ns;
    return n;
}

int igmp_coord_load_self(const char *dir, const char *self_node, igmp_snap_mem *out, int cap) {
    char *buf = malloc(1 << 20);
    if (!buf)
        return -1;
    if (load_named(dir, self_node, buf, 1 << 20) < 0) {
        free(buf);
        return 0;
    }
    int n = 0;
    igmp_coord_parse(buf, NULL, out, cap, &n);
    free(buf);
    return n;
}
