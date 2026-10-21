#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "coord.h"
#include "kube.h"
#include "query.h"
#include "runtime.h"
#include "ws_capture.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_IFACES 8

typedef struct {
    pcap_t *pcap;
    int fd;
    int dlt;
    char name[IF_NAMESIZE];
} cap_if;

static igmp_runtime *rt;
static cap_if caps[MAX_IFACES];
static int ncaps;
static int http_fd = -1;
static int ctrl_fd = -1;
static int ctrl_client = -1;
static int no_capture;
static int no_ws;
static int manual_time;
static int64_t reconcile_ms = 5000;
static int64_t next_reconcile;
static char iface_names[MAX_IFACES][IF_NAMESIZE];
static int niface;
static char cilium_bin[256] = "cilium-dbg";
static uint32_t host_ip_cfg;
static uint32_t cilium_host_addr;
static int identity_ok = -1;
static int identity_disagree_logged;
static uint32_t identity_logged;
static kube_client *kube;
static int kube_coord;
static char http_host[64] = "0.0.0.0";
static int http_port = 9080;

/* /healthz must answer while reconcile is inside curl or cilium-dbg.
 * The HTTP thread only reads this cache; it never touches rt. */
typedef struct {
    pthread_mutex_t mu;
    int ready_code;
    char ready_body[32];
    char metrics[8192];
} http_cache;

static http_cache hcache;

static void http_cache_refresh(void) {
    if (!rt)
        return;
    char metrics[sizeof hcache.metrics];
    igmp_metrics_render(rt, metrics, sizeof metrics);
    /* Capture up means the process can do its job. A Kubernetes watch
     * blip is igmpshark_k8s_watch_healthy, not a reason to fail the probe. */
    int ready = no_capture || ncaps > 0;
    const char *body = rt->eng->querier_degraded ? "degraded\n" : "ready\n";
    pthread_mutex_lock(&hcache.mu);
    hcache.ready_code = ready ? 200 : 503;
    snprintf(hcache.ready_body, sizeof hcache.ready_body, "%s", body);
    snprintf(hcache.metrics, sizeof hcache.metrics, "%s", metrics);
    pthread_mutex_unlock(&hcache.mu);
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void log_msg(const char *level, const char *msg) {
    fprintf(stderr, "{\"level\":\"%s\",\"msg\":\"%s\",\"node\":\"%s\"}\n", level, msg,
            rt && rt->node_name[0] ? rt->node_name : "");
}

/* First IPv4 on an interface. cilium_host can also hold a stale router address,
 * so this is logged and not used as the VXLAN identity. */
static int iface_ipv4(const char *name, char *out, size_t cap) {
    struct ifaddrs *list = NULL;
    if (!name || !name[0] || getifaddrs(&list) != 0)
        return -1;
    int rc = -1;
    for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, name) != 0)
            continue;
        const struct sockaddr_in *in = (const struct sockaddr_in *)ifa->ifa_addr;
        if (!inet_ntop(AF_INET, &in->sin_addr, out, (socklen_t)cap))
            continue;
        rc = 0;
        break;
    }
    freeifaddrs(list);
    return rc;
}

static int link_of_dlt(int dlt) {
    if (dlt == DLT_EN10MB)
        return IGMP_LINK_ETHERNET;
    if (dlt == DLT_LINUX_SLL)
        return IGMP_LINK_SLL;
#ifdef DLT_LINUX_SLL2
    if (dlt == DLT_LINUX_SLL2)
        return IGMP_LINK_SLL2;
#endif
    if (dlt == DLT_RAW || dlt == DLT_IPV4)
        return IGMP_LINK_RAW;
    return 0;
}

static int wtap_of_dlt(int dlt) {
    if (dlt == DLT_EN10MB)
        return 1; /* WTAP_ENCAP_ETHERNET */
    if (dlt == DLT_LINUX_SLL)
        return 25; /* WTAP_ENCAP_SLL */
#ifdef DLT_LINUX_SLL2
    if (dlt == DLT_LINUX_SLL2)
        return 210; /* WTAP_ENCAP_SLL2 */
#endif
    if (dlt == DLT_RAW)
        return 7; /* WTAP_ENCAP_RAW_IP */
    if (dlt == DLT_IPV4)
        return 129; /* WTAP_ENCAP_RAW_IP4 */
    return 1;
}

static void handle_frame(const uint8_t *data, uint32_t len, int dlt, uint32_t ifindex) {
    int link = link_of_dlt(dlt);
    if (!link) {
        rt->capture_drops++;
        return;
    }
    uint32_t gen = 1;
    for (int i = 0; i < ncaps; i++) {
        if (caps[i].pcap && if_nametoindex(caps[i].name) == ifindex)
            gen = igmp_runtime_observe_iface(rt, ifindex, caps[i].name, 1);
    }
    if (ifindex == 0)
        gen = 1;
    if (!no_ws) {
        int hit = ws_capture_frame_is_igmp(data, len, len, wtap_of_dlt(dlt));
        if (hit == 0)
            return;
    }
    if (igmp_runtime_enqueue(rt, data, len, link, ifindex, gen) != 0)
        log_msg("warn", "capture-queue-full");
}

static int open_live(const char *name) {
    if (ncaps >= MAX_IFACES)
        return -1;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(name, err);
    if (!p) {
        fprintf(stderr, "pcap_create %s: %s\n", name, err);
        return -1;
    }
    pcap_set_snaplen(p, IGMP_FRAME_MAX);
    pcap_set_promisc(p, 1);
    pcap_set_timeout(p, 200);
    pcap_set_immediate_mode(p, 1);
    if (pcap_activate(p) != 0) {
        fprintf(stderr, "pcap_activate %s: %s\n", name, pcap_geterr(p));
        pcap_close(p);
        return -1;
    }
    struct bpf_program fp;
    if (pcap_compile(p, &fp, "igmp", 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(p, &fp) != 0) {
        fprintf(stderr, "igmp filter failed on %s: %s\n", name, pcap_geterr(p));
        pcap_close(p);
        return -1;
    }
    pcap_freecode(&fp);
    pcap_setnonblock(p, 1, err);
    caps[ncaps].pcap = p;
    caps[ncaps].fd = pcap_get_selectable_fd(p);
    caps[ncaps].dlt = pcap_datalink(p);
    snprintf(caps[ncaps].name, sizeof caps[ncaps].name, "%s", name);
    unsigned idx = if_nametoindex(name);
    if (idx)
        igmp_runtime_observe_iface(rt, idx, name, 1);
    ncaps++;
    return 0;
}

static int replay_file(const char *path) {
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, err);
    if (!p) {
        fprintf(stderr, "pcap_open_offline %s: %s\n", path, err);
        return -1;
    }
    struct bpf_program fp;
    if (pcap_compile(p, &fp, "igmp", 1, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(p, &fp);
    pcap_freecode(&fp);
    int dlt = pcap_datalink(p);
    struct pcap_pkthdr *hdr;
    const u_char *data;
    while (pcap_next_ex(p, &hdr, &data) == 1) {
        uint32_t n = hdr->caplen;
        if (n > IGMP_FRAME_MAX)
            n = IGMP_FRAME_MAX;
        handle_frame(data, n, dlt, 0);
        igmp_runtime_drain(rt, 64);
    }
    pcap_close(p);
    return 0;
}

static int listen_tcp(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void http_reply(int fd, int code, const char *type, const char *body) {
    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     code, code == 200 ? "OK" : "Unavailable", type, strlen(body));
    send(fd, hdr, (size_t)n, MSG_NOSIGNAL);
    send(fd, body, strlen(body), MSG_NOSIGNAL);
}

static void http_client(int fd) {
    char req[1024];
    size_t got = 0;
    while (got < sizeof req - 1) {
        ssize_t n = recv(fd, req + got, sizeof req - 1 - got, 0);
        if (n <= 0)
            break;
        got += (size_t)n;
        req[got] = 0;
        if (strstr(req, "\n") != NULL)
            break;
    }
    if (got == 0) {
        close(fd);
        return;
    }
    if (strncmp(req, "GET /metrics", 12) == 0) {
        char metrics[sizeof hcache.metrics];
        pthread_mutex_lock(&hcache.mu);
        snprintf(metrics, sizeof metrics, "%s", hcache.metrics);
        pthread_mutex_unlock(&hcache.mu);
        http_reply(fd, 200, "text/plain; version=0.0.4", metrics);
    } else if (strncmp(req, "GET /healthz", 12) == 0) {
        http_reply(fd, 200, "text/plain", "ok\n");
    } else if (strncmp(req, "GET /readyz", 11) == 0) {
        int code;
        char body[32];
        pthread_mutex_lock(&hcache.mu);
        code = hcache.ready_code;
        snprintf(body, sizeof body, "%s", hcache.ready_body);
        pthread_mutex_unlock(&hcache.mu);
        http_reply(fd, code, "text/plain", body);
    } else {
        http_reply(fd, 404, "text/plain", "not found\n");
    }
    close(fd);
}

static void *http_thread(void *arg) {
    (void)arg;
    for (;;) {
        int c = accept(http_fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            usleep(10000);
            continue;
        }
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        http_client(c);
    }
    return NULL;
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void ctrl_reply(int fd, const char *line) {
    char buf[512];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    send(fd, buf, (size_t)n, MSG_NOSIGNAL);
}

static void ctrl_line(int fd, char *line) {
    char cmd[64];
    if (sscanf(line, "%63s", cmd) != 1)
        return;
    if (strcmp(cmd, "NOW") == 0) {
        long long t = 0;
        sscanf(line, "%*s %lld", &t);
        if (!manual_time)
            rt->eng->started_ms = t;
        rt->now_ms = t;
        manual_time = 1;
        ctrl_reply(fd, "OK");
    } else if (strcmp(cmd, "TICK") == 0) {
        igmp_runtime_tick(rt);
        ctrl_reply(fd, "OK");
    } else if (strcmp(cmd, "FRAME") == 0) {
        unsigned ifindex = 0, ifgen = 0;
        char hex[4096];
        if (sscanf(line, "%*s %u %u %4095s", &ifindex, &ifgen, hex) != 3) {
            ctrl_reply(fd, "ERR frame");
            return;
        }
        uint8_t raw[2048];
        size_t n = 0;
        for (size_t i = 0; hex[i] && hex[i + 1] && n < sizeof raw; i += 2) {
            int hi = hex_nibble(hex[i]), lo = hex_nibble(hex[i + 1]);
            if (hi < 0 || lo < 0)
                break;
            raw[n++] = (uint8_t)((hi << 4) | lo);
        }
        int rc = igmp_runtime_on_frame(rt, raw, n, IGMP_LINK_ETHERNET, ifindex, ifgen);
        char out[64];
        snprintf(out, sizeof out, "OK %d", rc);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "POD") == 0) {
        char uid[96], name[64], node[64], ipb[64];
        int restarts = 0;
        if (sscanf(line, "%*s %95s %63s %63s %63s %d", uid, name, node, ipb, &restarts) < 4) {
            ctrl_reply(fd, "ERR pod");
            return;
        }
        uint32_t ip = 0;
        igmp_ip_parse(ipb, &ip);
        igmp_runtime_pod_upsert(rt, uid, name, node, ip, restarts, 0, 0);
        ctrl_reply(fd, "OK");
    } else if (strcmp(cmd, "GONE") == 0) {
        char uid[96];
        sscanf(line, "%*s %95s", uid);
        int n = igmp_runtime_pod_delete(rt, uid);
        char out[64];
        snprintf(out, sizeof out, "OK %d", n);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "LISTBEGIN") == 0) {
        igmp_runtime_pods_begin(rt);
        ctrl_reply(fd, "OK");
    } else if (strcmp(cmd, "LISTEND") == 0) {
        int n = igmp_runtime_pods_end(rt);
        char out[64];
        snprintf(out, sizeof out, "OK %d", n);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "API") == 0) {
        int up = 1;
        sscanf(line, "%*s %d", &up);
        igmp_runtime_set_api(rt, up);
        ctrl_reply(fd, "OK");
    } else if (strcmp(cmd, "IFACE") == 0) {
        unsigned idx = 0, present = 0;
        char name[32];
        sscanf(line, "%*s %u %31s %u", &idx, name, &present);
        unsigned gen = igmp_runtime_observe_iface(rt, idx, name, present);
        char out[64];
        snprintf(out, sizeof out, "OK %u", gen);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "RECONCILE") == 0) {
        int n = igmp_runtime_reconcile(rt);
        char out[64];
        snprintf(out, sizeof out, "OK %d", n);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "SNAPSHOT") == 0) {
        int n = igmp_runtime_write_snapshot(rt);
        char out[64];
        snprintf(out, sizeof out, "OK %d", n);
        ctrl_reply(fd, out);
    } else if (strcmp(cmd, "DUMP") == 0) {
        for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
            igmp_member *m = &rt->eng->members[i];
            if (!m->used || !m->joined)
                continue;
            char g[32], s[32], lineout[256];
            igmp_ip_fmt(m->group, g, sizeof g);
            igmp_ip_fmt(m->subscriber, s, sizeof s);
            snprintf(lineout, sizeof lineout, "MEMBER %s %s %s %u %u", g, s,
                     m->pod_uid[0] ? m->pod_uid : "-", m->ifindex, m->ifgen);
            ctrl_reply(fd, lineout);
        }
        char ops[64];
        snprintf(ops, sizeof ops, "MUTATIONS %llu", (unsigned long long)rt->mutations);
        ctrl_reply(fd, ops);
        ctrl_reply(fd, "END");
    } else if (strcmp(cmd, "QUIT") == 0) {
        ctrl_reply(fd, "OK");
        exit(0);
    } else {
        ctrl_reply(fd, "ERR unknown");
    }
}

static int cilium_name_is(const char *listed, const char *want) {
    if (!listed || !want || !want[0])
        return 0;
    if (strcmp(listed, want) == 0)
        return 1;
    size_t ll = strlen(listed);
    size_t wl = strlen(want);
    return ll > wl && listed[ll - wl - 1] == '/' && strcmp(listed + (ll - wl), want) == 0;
}

static int same_node(const char *a, const char *b) {
    return cilium_name_is(a, b) || cilium_name_is(b, a);
}

static uint32_t annotated_ip(const kube_node_ip *ann, int nann, const char *name) {
    for (int i = 0; i < nann; i++) {
        if (!ann[i].name[0] || ann[i].ip == 0)
            continue;
        if (same_node(ann[i].name, name))
            return ann[i].ip;
    }
    return 0;
}

static int rewrite_has(const igmp_ip_rewrite *rw, int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (same_node(rw[i].name, name))
            return 1;
    return 0;
}

/* CiliumInternalIP is the node annotation network.cilium.io/ipv4-cilium-host.
 * `cilium-dbg node list` is only the fallback: its secondary list has no
 * address type, so the first in-CIDR address can be the health endpoint.
 * Neither source is status.hostIP or the first address on cilium_host. A
 * failed lookup leaves the last good identity in place. */
static int refresh_cilium_identity(void) {
    kube_node_ip ann[128];
    int ann_rc = kube_load_cilium_host_ips(ann, 128);
    int nann = ann_rc < 0 ? 0 : ann_rc;
    char *buf = malloc(1 << 20);
    igmp_cilium_node nodes[128];
    int nnodes = 0;
    int list_ok = 0;
    if (buf && igmp_cilium_node_list(cilium_bin, buf, 1 << 20, 3000) == 0) {
        nnodes = igmp_parse_cilium_nodes(buf, nodes, 128);
        if (nnodes < 0)
            nnodes = 0;
        list_ok = 1;
    }
    free(buf);
    /* A blip must not replace the annotation address with the node-list
     * fallback. That fallback is what installed the health IP. */
    if (ann_rc < 0 && identity_ok == 1)
        return 0;
    if (!list_ok && nann == 0) {
        if (identity_ok != 0) {
            identity_ok = 0;
            log_msg("warn", "cilium-identity-failed");
        }
        return -1;
    }
    igmp_ip_rewrite rw[128];
    int nr = 0;
    uint32_t self = 0;
    int self_from_ann = 0;
    uint32_t self_list = 0;
    for (int i = 0; i < nnodes && nr < 128; i++) {
        if (!nodes[i].name[0])
            continue;
        uint32_t from_ann = annotated_ip(ann, nann, nodes[i].name);
        uint32_t ip = from_ann ? from_ann : nodes[i].internal;
        if (!ip)
            continue;
        snprintf(rw[nr].name, sizeof rw[nr].name, "%s", nodes[i].name);
        rw[nr].ip = ip;
        if (same_node(nodes[i].name, rt->node_name)) {
            self = ip;
            self_from_ann = from_ann != 0;
            self_list = nodes[i].internal;
        }
        nr++;
    }
    for (int i = 0; i < nann && nr < 128; i++) {
        if (!ann[i].name[0] || ann[i].ip == 0)
            continue;
        if (rewrite_has(rw, nr, ann[i].name))
            continue;
        snprintf(rw[nr].name, sizeof rw[nr].name, "%s", ann[i].name);
        rw[nr].ip = ann[i].ip;
        if (same_node(ann[i].name, rt->node_name)) {
            self = ann[i].ip;
            self_from_ann = 1;
        }
        nr++;
    }
    if (nann > 0 && !identity_disagree_logged) {
        for (int i = 0; i < nnodes; i++) {
            uint32_t from_ann = annotated_ip(ann, nann, nodes[i].name);
            if (!from_ann || !nodes[i].internal || from_ann == nodes[i].internal)
                continue;
            char a[32], b[32];
            igmp_ip_fmt(from_ann, a, sizeof a);
            igmp_ip_fmt(nodes[i].internal, b, sizeof b);
            fprintf(stderr,
                    "{\"level\":\"warn\",\"msg\":\"cilium-identity-disagree\","
                    "\"annotation\":\"%s\",\"node-list\":\"%s\",\"name\":\"%s\","
                    "\"node\":\"%s\"}\n",
                    a, b, nodes[i].name, rt->node_name);
        }
        identity_disagree_logged = 1;
    }
    if (nr == 0) {
        if (identity_ok != 0) {
            identity_ok = 0;
            log_msg("warn", "cilium-identity-empty");
        }
        return -1;
    }
    igmp_runtime_set_identities(rt, rw, nr);
    if (self == 0) {
        if (identity_ok != 0) {
            identity_ok = 0;
            log_msg("warn", "cilium-identity-missing");
        }
        return -1;
    }
    rt->node_ip = self;
    rt->eng->cfg.self_ip = self;
    if (identity_ok != 1 || identity_logged != self) {
        identity_ok = 1;
        identity_logged = self;
        char ip[32], host[32], face[32], listed[32];
        igmp_ip_fmt(self, ip, sizeof ip);
        igmp_ip_fmt(host_ip_cfg, host, sizeof host);
        igmp_ip_fmt(cilium_host_addr, face, sizeof face);
        igmp_ip_fmt(self_list, listed, sizeof listed);
        const char *source = self_from_ann ? "annotation" : "cilium-internal";
        if (self_list && self_list != self)
            fprintf(stderr,
                    "{\"level\":\"info\",\"msg\":\"node-ip\",\"ip\":\"%s\","
                    "\"source\":\"%s\",\"node-list-ip\":\"%s\",\"host-ip\":\"%s\","
                    "\"cilium-host-ip\":\"%s\",\"node\":\"%s\"}\n",
                    ip, source, listed, host, face, rt->node_name);
        else
            fprintf(stderr,
                    "{\"level\":\"info\",\"msg\":\"node-ip\",\"ip\":\"%s\","
                    "\"source\":\"%s\",\"host-ip\":\"%s\","
                    "\"cilium-host-ip\":\"%s\",\"node\":\"%s\"}\n",
                    ip, source, host, face, rt->node_name);
    }
    return 0;
}

static void send_pending_joins(void) {
    igmp_local_join js[32];
    int n = igmp_runtime_take_joins(rt, js, 32);
    if (n <= 0 || rt->dry_run || no_capture)
        return;
    int sent = 0;
    int failed = 0;
    for (int i = 0; i < n; i++) {
        char ns[64];
        if (igmp_netns_for_local_ip(js[i].subscriber, ns, sizeof ns) != 0 ||
            igmp_v3_toex_send(ns, js[i].subscriber, js[i].group) != 0)
            failed++;
        else
            sent++;
    }
    if (sent || failed)
        fprintf(stderr,
                "{\"level\":\"info\",\"msg\":\"local-join\",\"sent\":%d,\"failed\":%d,"
                "\"node\":\"%s\"}\n",
                sent, failed, rt->node_name);
}

static void send_pending_queries(void) {
    igmp_query_out qs[32];
    int n = 0;
    igmp_engine_take_queries(rt->eng, qs, &n, 32);
    if (rt->dry_run || no_capture)
        return;
    uint32_t src = rt->eng->cfg.self_ip ? rt->eng->cfg.self_ip : rt->node_ip;
    for (int i = 0; i < n; i++) {
        const char *ifn = niface ? iface_names[0] : NULL;
        if (igmp_query_send(ifn, src, qs[i].group, qs[i].max_resp_ms, qs[i].version) != 0)
            log_msg("warn", "query-send-failed");
    }
}

static void scan_ifaces(void) {
    DIR *d = opendir("/sys/class/net");
    if (!d)
        return;
    int seen[64];
    memset(seen, 0, sizeof seen);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        unsigned idx = if_nametoindex(de->d_name);
        if (!idx)
            continue;
        igmp_runtime_observe_iface(rt, idx, de->d_name, 1);
    }
    closedir(d);
    (void)seen;
}

static void usage(void) {
    fprintf(stderr,
            "usage: igmpshark [options]\n"
            "  --iface NAME            capture interface (repeatable, default any)\n"
            "  --pcap FILE             replay pcap or pcapng and exit\n"
            "  --backend file|cilium   state backend (default file)\n"
            "  --state PATH            file-backend map (default /var/lib/igmpshark/state.tsv)\n"
            "  --ledger PATH           ownership ledger for the cilium backend\n"
            "  --cilium-dbg PATH       cilium-dbg binary (default cilium-dbg)\n"
            "  --coord-dir PATH        per-node membership snapshots\n"
            "  --node-name NAME        this node\n"
            "  --node-ip ADDR          Kubernetes node IP, logged only on the cilium backend\n"
            "  --cilium-host-iface IF  logged only; not the remote subscriber (default cilium_host)\n"
            "  --self-ip ADDR          querier election address\n"
            "  --listen HOST:PORT      health and metrics (default 0.0.0.0:9080)\n"
            "  --control HOST:PORT     line protocol for tests\n"
            "  --dry-run               compute changes without applying them\n"
            "  --active-querier        originate queries when elected\n"
            "  --immediate-leave       leave immediately on a single-subscriber port\n"
            "  --kube                  watch pods\n"
            "  --kube-coord            publish snapshots as ConfigMaps\n"
            "  --no-capture            do not open interfaces\n"
            "  --no-ws                 skip libwireshark confirmation\n"
            "  --query-interval-ms N   default 125000\n"
            "  --query-response-ms N   default 10000\n"
            "  --robustness N          default 2\n"
            "  --lmqi-ms N             last-member query interval, default 1000\n"
            "  --startup-grace-ms N    additions only until this elapses, default 15000\n"
            "  --reconcile-ms N        default 5000\n"
            "  --max-members N\n");
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    igmp_config cfg;
    igmp_config_defaults(&cfg);
    const char *backend_kind = "file";
    const char *state_path = "/var/lib/igmpshark/state.tsv";
    const char *ledger = "/var/lib/igmpshark/ledger.tsv";
    const char *cilium = "cilium-dbg";
    const char *pcap_path = NULL;
    char coord[512] = "";
    char node[64] = "";
    char node_ip[64] = "";
    char self_ip[64] = "";
    char cilium_host_iface[32] = "cilium_host";
    char control[64] = "";
    int dry = 0, active = 0, immediate = 0, use_kube = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define NEED()                                                                                     \
    do {                                                                                           \
        if (!v) {                                                                                  \
            usage();                                                                               \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
        if (strcmp(a, "--help") == 0) {
            usage();
            return 0;
        } else if (strcmp(a, "--iface") == 0) {
            NEED();
            if (niface < MAX_IFACES)
                snprintf(iface_names[niface++], IF_NAMESIZE, "%s", v);
            i++;
        } else if (strcmp(a, "--pcap") == 0) {
            NEED();
            pcap_path = v;
            i++;
        } else if (strcmp(a, "--backend") == 0) {
            NEED();
            backend_kind = v;
            i++;
        } else if (strcmp(a, "--state") == 0) {
            NEED();
            state_path = v;
            i++;
        } else if (strcmp(a, "--ledger") == 0) {
            NEED();
            ledger = v;
            i++;
        } else if (strcmp(a, "--cilium-dbg") == 0) {
            NEED();
            cilium = v;
            i++;
        } else if (strcmp(a, "--coord-dir") == 0) {
            NEED();
            snprintf(coord, sizeof coord, "%s", v);
            i++;
        } else if (strcmp(a, "--node-name") == 0) {
            NEED();
            snprintf(node, sizeof node, "%s", v);
            i++;
        } else if (strcmp(a, "--node-ip") == 0) {
            NEED();
            snprintf(node_ip, sizeof node_ip, "%s", v);
            i++;
        } else if (strcmp(a, "--cilium-host-iface") == 0) {
            NEED();
            snprintf(cilium_host_iface, sizeof cilium_host_iface, "%s", v);
            i++;
        } else if (strcmp(a, "--self-ip") == 0) {
            NEED();
            snprintf(self_ip, sizeof self_ip, "%s", v);
            i++;
        } else if (strcmp(a, "--listen") == 0) {
            NEED();
            char host[64];
            unsigned port = 0;
            if (sscanf(v, "%63[^:]:%u", host, &port) == 2) {
                snprintf(http_host, sizeof http_host, "%s", host);
                http_port = (int)port;
            }
            i++;
        } else if (strcmp(a, "--control") == 0) {
            NEED();
            snprintf(control, sizeof control, "%s", v);
            i++;
        } else if (strcmp(a, "--dry-run") == 0) {
            dry = 1;
        } else if (strcmp(a, "--active-querier") == 0) {
            active = 1;
        } else if (strcmp(a, "--immediate-leave") == 0) {
            immediate = 1;
        } else if (strcmp(a, "--kube") == 0) {
            use_kube = 1;
        } else if (strcmp(a, "--kube-coord") == 0) {
            kube_coord = 1;
        } else if (strcmp(a, "--no-capture") == 0) {
            no_capture = 1;
        } else if (strcmp(a, "--no-ws") == 0) {
            no_ws = 1;
        } else if (strcmp(a, "--query-interval-ms") == 0) {
            NEED();
            cfg.query_interval_ms = atoll(v);
            i++;
        } else if (strcmp(a, "--query-response-ms") == 0) {
            NEED();
            cfg.query_response_ms = atoll(v);
            i++;
        } else if (strcmp(a, "--robustness") == 0) {
            NEED();
            cfg.robustness = atoi(v);
            i++;
        } else if (strcmp(a, "--lmqi-ms") == 0) {
            NEED();
            cfg.last_member_query_ms = atoll(v);
            i++;
        } else if (strcmp(a, "--startup-grace-ms") == 0) {
            NEED();
            cfg.startup_grace_ms = atoll(v);
            i++;
        } else if (strcmp(a, "--reconcile-ms") == 0) {
            NEED();
            reconcile_ms = atoll(v);
            i++;
        } else if (strcmp(a, "--max-members") == 0) {
            NEED();
            cfg.max_members = atoi(v);
            i++;
        } else {
            usage();
            return 2;
        }
#undef NEED
    }
    cfg.active_querier = active;
    cfg.immediate_leave = immediate;
    snprintf(cilium_bin, sizeof cilium_bin, "%s", cilium);
    if (self_ip[0])
        igmp_ip_parse(self_ip, &cfg.self_ip);
    else if (node_ip[0])
        igmp_ip_parse(node_ip, &cfg.self_ip);
    /* The chart passes status.hostIP as both. That address is not the overlay
     * identity, and using it as the querier address makes our own queries look
     * foreign once the real identity is installed. */
    if (strcmp(backend_kind, "cilium") == 0)
        cfg.self_ip = 0;
    int64_t now = mono_ms();
    rt = igmp_runtime_new(&cfg, now);
    if (!rt)
        return 1;
    rt->dry_run = dry;
    rt->use_kube = use_kube;
    snprintf(rt->node_name, sizeof rt->node_name, "%s", node);
    snprintf(rt->coord_dir, sizeof rt->coord_dir, "%s", coord);
    if (coord[0] && igmp_coord_ensure(coord) != 0)
        fprintf(stderr, "{\"level\":\"warn\",\"msg\":\"coord-dir-create-failed\",\"node\":\"%s\"}\n",
                node);
    if (node_ip[0])
        igmp_ip_parse(node_ip, &host_ip_cfg);
    if (strcmp(backend_kind, "cilium") == 0) {
        rt->node_ip = 0;
        char face[64];
        if (iface_ipv4(cilium_host_iface, face, sizeof face) == 0)
            igmp_ip_parse(face, &cilium_host_addr);
    } else {
        rt->node_ip = host_ip_cfg;
    }
    if (strcmp(backend_kind, "cilium") == 0) {
        snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s", ledger);
        rt->mark_from_ledger = 1;
    }
    igmp_backend *be = calloc(1, sizeof *be);
    if (!be)
        return 1;
    if (strcmp(backend_kind, "cilium") == 0) {
        if (backend_cli_open(be, cilium, ledger, dry, 10000) != 0)
            return 1;
    } else {
        if (backend_file_open(be, state_path, dry) != 0)
            return 1;
    }
    rt->backend = be;
    if (!no_ws) {
        if (ws_capture_init() != 0)
            return 1;
    }
    igmp_runtime_restore(rt);
    if (!no_capture && !pcap_path) {
        if (niface == 0)
            snprintf(iface_names[niface++], IF_NAMESIZE, "%s", "any");
        for (int i = 0; i < niface; i++) {
            if (open_live(iface_names[i]) != 0)
                return 1;
        }
    }
    if (pcap_path) {
        if (replay_file(pcap_path) != 0)
            return 1;
        if (strcmp(backend_kind, "cilium") == 0)
            refresh_cilium_identity();
        igmp_runtime_reconcile(rt);
        igmp_runtime_write_snapshot(rt);
        if (!no_ws)
            ws_capture_shutdown();
        return 0;
    }
    pthread_mutex_init(&hcache.mu, NULL);
    hcache.ready_code = 200;
    snprintf(hcache.ready_body, sizeof hcache.ready_body, "%s", "ready\n");
    http_fd = listen_tcp(http_host, http_port);
    if (http_fd < 0) {
        perror("listen");
        return 1;
    }
    http_cache_refresh();
    pthread_t http_thr;
    if (pthread_create(&http_thr, NULL, http_thread, NULL) != 0) {
        perror("http");
        return 1;
    }
    pthread_detach(http_thr);
    if (control[0]) {
        char host[64];
        unsigned port = 0;
        if (sscanf(control, "%63[^:]:%u", host, &port) != 2)
            return 2;
        ctrl_fd = listen_tcp(host, (int)port);
        if (ctrl_fd < 0) {
            perror("control");
            return 1;
        }
    }
    if (use_kube) {
        if (kube_client_start(&kube) != 0)
            log_msg("warn", "kube-watch-not-started");
    }
    next_reconcile = now;
    char ctrlbuf[8192];
    size_t ctrl_len = 0;
    if (strcmp(backend_kind, "cilium") == 0)
        refresh_cilium_identity();
    else {
        char ipb[32];
        igmp_ip_fmt(rt->node_ip, ipb, sizeof ipb);
        fprintf(stderr,
                "{\"level\":\"info\",\"msg\":\"node-ip\",\"ip\":\"%s\",\"source\":\"node-ip\","
                "\"node\":\"%s\"}\n",
                ipb, rt->node_name);
    }
    log_msg("info", "started");
    for (;;) {
        if (!manual_time)
            rt->now_ms = mono_ms();
        if (kube) {
            kube_event ev;
            while (kube_client_poll(kube, &ev)) {
                if (ev.kind == KUBE_EV_API_DOWN)
                    igmp_runtime_set_api(rt, 0);
                else if (ev.kind == KUBE_EV_API_UP)
                    igmp_runtime_set_api(rt, 1);
                else if (ev.kind == KUBE_EV_BEGIN)
                    igmp_runtime_pods_begin(rt);
                else if (ev.kind == KUBE_EV_END)
                    igmp_runtime_pods_end(rt);
                else if (ev.kind == KUBE_EV_UPSERT)
                    igmp_runtime_pod_upsert(rt, ev.uid, ev.name, ev.node, ev.ip, ev.restart,
                                            ev.deleting, 1);
                else if (ev.kind == KUBE_EV_DELETE)
                    igmp_runtime_pod_delete(rt, ev.uid);
            }
            rt->queue_drops += kube_client_drops(kube);
        }
        http_cache_refresh();
        struct pollfd pfds[16];
        int np = 0;
        int ctrl_slot = -1, client_slot = -1;
        if (ctrl_fd >= 0 && ctrl_client < 0) {
            ctrl_slot = np;
            pfds[np].fd = ctrl_fd;
            pfds[np].events = POLLIN;
            np++;
        }
        if (ctrl_client >= 0) {
            client_slot = np;
            pfds[np].fd = ctrl_client;
            pfds[np].events = POLLIN;
            np++;
        }
        int cap_base = np;
        for (int i = 0; i < ncaps; i++) {
            pfds[np].fd = caps[i].fd;
            pfds[np].events = POLLIN;
            np++;
        }
        int pr = poll(pfds, (nfds_t)np, 200);
        (void)pr;
        if (ctrl_slot >= 0 && (pfds[ctrl_slot].revents & POLLIN)) {
            ctrl_client = accept(ctrl_fd, NULL, NULL);
            if (ctrl_client >= 0)
                ctrl_reply(ctrl_client, "READY");
        }
        if (client_slot >= 0 && (pfds[client_slot].revents & POLLIN)) {
            ssize_t n = recv(ctrl_client, ctrlbuf + ctrl_len, sizeof ctrlbuf - ctrl_len - 1, 0);
            if (n <= 0) {
                close(ctrl_client);
                ctrl_client = -1;
                ctrl_len = 0;
            } else {
                ctrl_len += (size_t)n;
                ctrlbuf[ctrl_len] = 0;
                char *start = ctrlbuf;
                char *nl;
                while ((nl = strchr(start, '\n')) != NULL) {
                    *nl = 0;
                    if (nl > start && nl[-1] == '\r')
                        nl[-1] = 0;
                    ctrl_line(ctrl_client, start);
                    start = nl + 1;
                }
                size_t left = strlen(start);
                memmove(ctrlbuf, start, left);
                ctrl_len = left;
            }
        }
        for (int i = 0; i < ncaps; i++) {
            if (!(pfds[cap_base + i].revents & POLLIN))
                continue;
            struct pcap_pkthdr *hdr;
            const u_char *data;
            while (pcap_next_ex(caps[i].pcap, &hdr, &data) == 1) {
                uint32_t n = hdr->caplen > IGMP_FRAME_MAX ? IGMP_FRAME_MAX : hdr->caplen;
                unsigned idx = if_nametoindex(caps[i].name);
                handle_frame(data, n, caps[i].dlt, idx);
                /* A shutdown sends one report per group back to back. Draining
                 * only after the burst filled the 64-slot queue dropped the
                 * rest, and those memberships never left. */
                if (rt->queue_depth > rt->queue_cap / 2)
                    igmp_runtime_drain(rt, rt->queue_cap);
            }
            struct pcap_stat st;
            if (pcap_stats(caps[i].pcap, &st) == 0)
                rt->capture_drops = st.ps_drop;
        }
        igmp_runtime_drain(rt, 64);
        if (!manual_time) {
            igmp_runtime_tick(rt);
            if (rt->now_ms >= next_reconcile) {
                scan_ifaces();
                if (kube_coord && coord[0]) {
                    static long fetch_status = -1;
                    int fetched = kube_fetch_snapshots(coord);
                    long st = fetched < 0 ? kube_last_status() : 200;
                    if (st != fetch_status) {
                        fetch_status = st;
                        if (fetched < 0)
                            fprintf(stderr,
                                    "{\"level\":\"warn\",\"msg\":\"snapshot-fetch-failed\",\"http\":%ld,"
                                    "\"node\":\"%s\"}\n",
                                    st, rt->node_name);
                    }
                }
                if (strcmp(backend_kind, "cilium") == 0)
                    refresh_cilium_identity();
                igmp_runtime_write_snapshot(rt);
                if (kube_coord && coord[0] && node[0]) {
                    char path[768];
                    snprintf(path, sizeof path, "%s/%s.snap", coord, node);
                    FILE *sf = fopen(path, "r");
                    if (sf) {
                        char text[1 << 16];
                        size_t n = fread(text, 1, sizeof text - 1, sf);
                        text[n] = 0;
                        fclose(sf);
                        static long publish_status = -1;
                        int prc = kube_publish_snapshot(node, text);
                        long st = prc == 0 ? 200 : kube_last_status();
                        if (st != publish_status) {
                            publish_status = st;
                            if (prc != 0)
                                fprintf(stderr,
                                        "{\"level\":\"warn\",\"msg\":\"snapshot-publish-failed\",\"http\":%ld,"
                                        "\"node\":\"%s\"}\n",
                                        st, rt->node_name);
                        }
                    }
                }
                igmp_runtime_reconcile(rt);
                next_reconcile = rt->now_ms + reconcile_ms;
            }
            /* After reconcile, so a solicit lands once the group map exists.
             * Cilium records a local subscriber only from a report that
             * arrives while that map is already there. */
            send_pending_joins();
            send_pending_queries();
        }
    }
}
