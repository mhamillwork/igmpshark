#include "runtime.h"

#include "coord.h"
#include "query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct igmp_qframe {
    uint8_t data[IGMP_FRAME_MAX];
    uint32_t len;
    int link;
    uint32_t ifindex;
    uint32_t ifgen;
} igmp_qframe;

typedef struct igmp_iface {
    int used;
    int present;
    uint32_t ifindex;
    uint32_t gen;
    char name[32];
} igmp_iface;

enum { IGMP_HELD_MAX = 8, IGMP_HELD_MS = 30000 };

/* One report per source, kept until that pod IP is learned or it ages out.
 * A restarted pod sends its join before the watch publishes the new address. */
typedef struct igmp_held {
    int used;
    uint32_t src;
    int64_t at_ms;
    uint32_t len;
    int link;
    uint32_t ifindex;
    uint32_t ifgen;
    uint8_t data[IGMP_FRAME_MAX];
} igmp_held;

typedef struct igmp_rt_extra {
    igmp_qframe *q;
    int qh;
    int qn;
    igmp_op *retry;
    int n_retry;
    int retry_cap;
    uint64_t retry_gen;
    int solicit_at;
    int join_at;
    int njoins;
    igmp_local_join joins[32];
    igmp_ip_rewrite ids[128];
    int nids;
    uint64_t remote_sig;
    igmp_iface ifaces[64];
    igmp_held held[IGMP_HELD_MAX];
    uint32_t local_seen[128];
    int nlocal_seen;
} igmp_rt_extra;

static int (*pod_local_fn)(uint32_t ip);

void igmp_runtime_set_pod_local_fn(int (*fn)(uint32_t ip)) {
    pod_local_fn = fn;
}

static igmp_rt_extra *extra(igmp_runtime *rt) {
    return (igmp_rt_extra *)(rt + 1);
}

void igmp_runtime_set_identities(igmp_runtime *rt, const igmp_ip_rewrite *rows, int n) {
    igmp_rt_extra *x = extra(rt);
    igmp_ip_rewrite next[128];
    int nn = 0;
    if (rows && n > 0) {
        if (n > 128)
            n = 128;
        for (int i = 0; i < n; i++) {
            if (!rows[i].name[0] || rows[i].ip == 0)
                continue;
            next[nn++] = rows[i];
        }
    }
    int changed = nn != x->nids;
    for (int i = 0; !changed && i < nn; i++)
        if (strcmp(next[i].name, x->ids[i].name) != 0 || next[i].ip != x->ids[i].ip)
            changed = 1;
    if (changed)
        x->n_retry = 0;
    x->nids = nn;
    if (nn > 0)
        memcpy(x->ids, next, (size_t)nn * sizeof *next);
}

int igmp_runtime_take_joins(igmp_runtime *rt, igmp_local_join *out, int cap) {
    igmp_rt_extra *x = extra(rt);
    int n = x->njoins;
    if (n > cap)
        n = cap;
    if (n < 0)
        n = 0;
    if (out && n > 0)
        memcpy(out, x->joins, (size_t)n * sizeof *out);
    x->njoins = 0;
    return n;
}

static void logj(const igmp_runtime *rt, const char *level, const char *msg) {
    if (!rt->log_json)
        return;
    fprintf(stderr, "{\"level\":\"%s\",\"msg\":\"%s\",\"node\":\"%s\"}\n", level, msg,
            rt->node_name);
}

static void log_member(igmp_runtime *rt, const char *msg, const char *reason, uint32_t ip,
                       int count) {
    if (msg && strcmp(msg, "member-deleted") == 0)
        snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "%s", reason ? reason : "");
    if (!rt->log_json || count <= 0)
        return;
    char ipb[32];
    if (ip)
        igmp_ip_fmt(ip, ipb, sizeof ipb);
    else
        snprintf(ipb, sizeof ipb, "%s", "-");
    fprintf(stderr,
            "{\"level\":\"info\",\"msg\":\"%s\",\"reason\":\"%s\",\"ip\":\"%s\",\"count\":%d,"
            "\"node\":\"%s\"}\n",
            msg, reason ? reason : "", ipb, count, rt->node_name);
}

/* Each cilium-dbg call can take the full command timeout. A full pass over
 * every membership blocks the capture loop long enough for kubelet to time
 * out /healthz. Finish the rest on the next reconcile. */
enum { IGMP_APPLY_PER_PASS = 8 };

static void log_backend(const igmp_runtime *rt, const char *msg) {
    if (!rt->log_json)
        return;
    char detail[180];
    const char *src = (rt->backend && rt->backend->err[0]) ? rt->backend->err : "";
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < sizeof detail; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            detail[j++] = '\\';
            detail[j++] = (char)c;
        } else if (c < 0x20) {
            detail[j++] = ' ';
        } else {
            detail[j++] = (char)c;
        }
    }
    detail[j] = 0;
    fprintf(stderr,
            "{\"level\":\"warn\",\"msg\":\"%s\",\"detail\":\"%s\",\"node\":\"%s\"}\n", msg, detail,
            rt->node_name);
}

igmp_runtime *igmp_runtime_new(const igmp_config *cfg, int64_t now_ms) {
    igmp_runtime *rt = calloc(1, sizeof(igmp_runtime) + sizeof(igmp_rt_extra));
    if (!rt)
        return NULL;
    rt->eng = calloc(1, sizeof(igmp_engine));
    extra(rt)->q = calloc(64, sizeof(igmp_qframe));
    extra(rt)->retry = calloc(256, sizeof(igmp_op));
    extra(rt)->retry_cap = 256;
    if (!rt->eng || !extra(rt)->q || !extra(rt)->retry) {
        igmp_runtime_free(rt);
        return NULL;
    }
    igmp_engine_init(rt->eng, cfg, now_ms);
    igmp_pods_init(&rt->pods);
    rt->now_ms = now_ms;
    rt->queue_cap = 64;
    rt->snap_max_age_ms = igmp_membership_interval_ms(cfg) * 2;
    rt->coord_ok = 1;
    rt->log_json = 1;
    return rt;
}

void igmp_runtime_free(igmp_runtime *rt) {
    if (!rt)
        return;
    if (rt->eng)
        free(rt->eng);
    if (extra(rt)->q)
        free(extra(rt)->q);
    if (extra(rt)->retry)
        free(extra(rt)->retry);
    free(rt);
}

static const igmp_pod *pod_for_src(igmp_runtime *rt, uint32_t ip) {
    const igmp_pod *pod = igmp_pods_by_ip(&rt->pods, ip);
    if (!pod)
        return NULL;
    if (rt->node_name[0] && pod->node[0] && strcmp(pod->node, rt->node_name) != 0)
        return NULL;
    return pod;
}

static void remember_local(igmp_runtime *rt, uint32_t group, uint32_t sub) {
    if (rt->ledger_path[0])
        igmp_ledger_add(rt->ledger_path, group, sub, 0);
}

static int pod_on_this_node(const igmp_runtime *rt, const char *node) {
    if (!rt->node_name[0] || !node || !node[0])
        return 1;
    return strcmp(node, rt->node_name) == 0;
}

static int seen_local(const igmp_runtime *rt, uint32_t ip) {
    const igmp_rt_extra *x = extra((igmp_runtime *)rt);
    if (ip == 0)
        return 0;
    for (int i = 0; i < x->nlocal_seen; i++)
        if (x->local_seen[i] == ip)
            return 1;
    return 0;
}

static void note_local(igmp_runtime *rt, uint32_t ip) {
    igmp_rt_extra *x = extra(rt);
    if (ip == 0 || seen_local(rt, ip))
        return;
    if (x->nlocal_seen >= (int)(sizeof x->local_seen / sizeof x->local_seen[0]))
        return;
    x->local_seen[x->nlocal_seen++] = ip;
}

static void forget_local(igmp_runtime *rt, uint32_t ip) {
    igmp_rt_extra *x = extra(rt);
    for (int i = 0; i < x->nlocal_seen; i++) {
        if (x->local_seen[i] != ip)
            continue;
        x->local_seen[i] = x->local_seen[x->nlocal_seen - 1];
        x->nlocal_seen--;
        return;
    }
}

static int pod_namespace_live(uint32_t ip) {
    if (pod_local_fn)
        return pod_local_fn(ip);
    char ns[64];
    return igmp_netns_for_local_ip(ip, ns, sizeof ns) == 0;
}

/* The pod list is one snapshot behind a restart. An address is still current
 * when the API has it, or when a pod network namespace on this node owns it. */
static int subscriber_live(igmp_runtime *rt, uint32_t ip) {
    if (pod_for_src(rt, ip))
        return 1;
    if (seen_local(rt, ip))
        return 1;
    if (pod_namespace_live(ip)) {
        note_local(rt, ip);
        return 1;
    }
    return 0;
}

static void refresh_local_seen(igmp_runtime *rt) {
    igmp_rt_extra *x = extra(rt);
    for (int i = 0; i < x->nlocal_seen;) {
        uint32_t ip = x->local_seen[i];
        /* A table hit is not enough. The note means a pod namespace owns
         * this address, and that has to be checked again after a restart. */
        if (pod_namespace_live(ip)) {
            i++;
            continue;
        }
        x->local_seen[i] = x->local_seen[x->nlocal_seen - 1];
        x->nlocal_seen--;
    }
}

static int drop_subscriber(igmp_runtime *rt, uint32_t ip, const char *reason) {
    int n = igmp_engine_subscriber_gone(rt->eng, ip, rt->now_ms);
    if (n <= 0)
        return 0;
    rt->cleanups += (uint64_t)n;
    log_member(rt, "member-deleted", reason, ip, n);
    rt->gen++;
    forget_local(rt, ip);
    return n;
}

/* uid is leaving the pod table. Memberships whose address is still a running
 * pod stay; that is the new IP from a restart the list has not published. */
static int drop_uid(igmp_runtime *rt, const char *uid, const char *reason) {
    uint32_t subs[16];
    int nsubs = 0;
    int total = 0;
    if (!uid || !uid[0])
        return 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &rt->eng->members[i];
        int seen = 0;
        if (!m->used || strcmp(m->pod_uid, uid) != 0 || m->subscriber == 0)
            continue;
        for (int s = 0; s < nsubs; s++)
            if (subs[s] == m->subscriber)
                seen = 1;
        if (seen || nsubs >= (int)(sizeof subs / sizeof subs[0]))
            continue;
        subs[nsubs++] = m->subscriber;
    }
    for (int s = 0; s < nsubs; s++) {
        if (subscriber_live(rt, subs[s])) {
            int n = igmp_engine_keep_subscriber(rt->eng, subs[s]);
            if (n > 0)
                log_member(rt, "member-kept", "pod-local", subs[s], n);
            continue;
        }
        total += drop_subscriber(rt, subs[s], reason);
    }
    return total;
}

static void sweep_missing_pods(igmp_runtime *rt) {
    uint32_t subs[64];
    int nsubs = 0;
    if (!rt->use_kube || !rt->pods.full_list_ok)
        return;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &rt->eng->members[i];
        int seen = 0;
        if (!m->used || m->subscriber == 0)
            continue;
        if (m->pod_uid[0] && igmp_pods_by_uid(&rt->pods, m->pod_uid))
            continue;
        for (int s = 0; s < nsubs; s++)
            if (subs[s] == m->subscriber)
                seen = 1;
        if (seen || nsubs >= (int)(sizeof subs / sizeof subs[0]))
            continue;
        subs[nsubs++] = m->subscriber;
    }
    for (int s = 0; s < nsubs; s++) {
        if (subscriber_live(rt, subs[s]))
            continue;
        drop_subscriber(rt, subs[s], "pod-list-absent");
    }
}

static void hold_unbound(igmp_runtime *rt, uint32_t src, const uint8_t *frame, size_t len, int link,
                         uint32_t ifindex, uint32_t ifgen) {
    igmp_rt_extra *x = extra(rt);
    igmp_held *slot = NULL;
    int fresh = 1;
    if (src == 0 || !frame || len == 0 || len > IGMP_FRAME_MAX)
        return;
    for (int i = 0; i < IGMP_HELD_MAX; i++) {
        if (x->held[i].used && x->held[i].src == src) {
            slot = &x->held[i];
            fresh = 0;
            break;
        }
    }
    if (!slot) {
        int oldest = 0;
        for (int i = 0; i < IGMP_HELD_MAX; i++) {
            if (!x->held[i].used) {
                slot = &x->held[i];
                break;
            }
            if (x->held[i].at_ms < x->held[oldest].at_ms)
                oldest = i;
        }
        if (!slot)
            slot = &x->held[oldest];
    }
    slot->used = 1;
    slot->src = src;
    slot->at_ms = rt->now_ms;
    slot->len = (uint32_t)len;
    slot->link = link;
    slot->ifindex = ifindex;
    slot->ifgen = ifgen;
    memcpy(slot->data, frame, len);
    if (fresh && rt->log_json) {
        char ip[32];
        igmp_ip_fmt(src, ip, sizeof ip);
        fprintf(stderr,
                "{\"level\":\"warn\",\"msg\":\"ignored-unbound\",\"src\":\"%s\",\"node\":\"%s\"}\n",
                ip, rt->node_name);
    }
}

int igmp_runtime_on_frame(igmp_runtime *rt, const uint8_t *frame, size_t len, int link,
                          uint32_t ifindex, uint32_t ifgen) {
    igmp_message msg;
    if (igmp_parse_ipv4(frame, len, link, &msg) != 0) {
        rt->eng->malformed++;
        return -1;
    }
    int is_report = msg.kind == IGMP_KIND_V1_REPORT || msg.kind == IGMP_KIND_V2_REPORT ||
                    msg.kind == IGMP_KIND_V3_REPORT;
    const igmp_pod *pod = NULL;
    if (is_report)
        pod = pod_for_src(rt, msg.src);
    if (is_report && rt->use_kube && rt->pods.full_list_ok && !pod) {
        /* The watch can miss a restarted pod's address. A fib LOCAL route in
         * some other network namespace is that pod running on this node. */
        if (pod_namespace_live(msg.src)) {
            int seen = seen_local(rt, msg.src);
            note_local(rt, msg.src);
            if (!seen && rt->log_json) {
                char ip[32];
                igmp_ip_fmt(msg.src, ip, sizeof ip);
                fprintf(stderr,
                        "{\"level\":\"info\",\"msg\":\"pod-local\",\"ip\":\"%s\",\"node\":\"%s\"}\n",
                        ip, rt->node_name);
            }
        } else {
            rt->ignored_unbound++;
            rt->eng->ignored++;
            hold_unbound(rt, msg.src, frame, len, link, ifindex, ifgen);
            return -1;
        }
    }
    int before = igmp_engine_joined_count(rt->eng);
    int rc = igmp_engine_on_message(rt->eng, &msg, ifindex, ifgen, rt->now_ms, frame, len);
    if (rc == 0 && pod)
        igmp_engine_bind_pod(rt->eng, msg.src, pod->uid, pod->node);
    if (rc == 0 && is_report && rt->ledger_path[0]) {
        for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
            igmp_member *m = &rt->eng->members[i];
            if (m->used && m->joined && m->subscriber == msg.src)
                remember_local(rt, m->group, m->subscriber);
        }
    }
    if (rc == 0 && igmp_engine_joined_count(rt->eng) != before)
        rt->gen++;
    else if (rc == 0 && msg.kind == IGMP_KIND_V2_LEAVE)
        rt->gen++;
    return rc;
}

static void replay_held(igmp_runtime *rt, uint32_t ip) {
    igmp_rt_extra *x = extra(rt);
    int n = 0;
    if (!ip || !pod_for_src(rt, ip))
        return;
    for (int i = 0; i < IGMP_HELD_MAX; i++) {
        igmp_held copy;
        if (!x->held[i].used || x->held[i].src != ip)
            continue;
        copy = x->held[i];
        x->held[i].used = 0;
        igmp_runtime_on_frame(rt, copy.data, copy.len, copy.link, copy.ifindex, copy.ifgen);
        n++;
    }
    if (n > 0 && rt->log_json) {
        char ipb[32];
        igmp_ip_fmt(ip, ipb, sizeof ipb);
        fprintf(stderr,
                "{\"level\":\"info\",\"msg\":\"pod-report-replay\",\"ip\":\"%s\",\"count\":%d,"
                "\"node\":\"%s\"}\n",
                ipb, n, rt->node_name);
    }
}

static void expire_held(igmp_runtime *rt) {
    igmp_rt_extra *x = extra(rt);
    for (int i = 0; i < IGMP_HELD_MAX; i++) {
        if (!x->held[i].used)
            continue;
        if (rt->now_ms - x->held[i].at_ms > IGMP_HELD_MS)
            x->held[i].used = 0;
    }
}

int igmp_runtime_enqueue(igmp_runtime *rt, const uint8_t *frame, size_t len, int link,
                         uint32_t ifindex, uint32_t ifgen) {
    igmp_rt_extra *x = extra(rt);
    if (!frame || len == 0 || len > IGMP_FRAME_MAX || x->qn >= rt->queue_cap) {
        rt->queue_drops++;
        rt->capture_drops++;
        rt->queue_depth = x->qn;
        return -1;
    }
    igmp_qframe *slot = &x->q[(x->qh + x->qn) % rt->queue_cap];
    memcpy(slot->data, frame, len);
    slot->len = (uint32_t)len;
    slot->link = link;
    slot->ifindex = ifindex;
    slot->ifgen = ifgen;
    x->qn++;
    rt->queue_depth = x->qn;
    return 0;
}

int igmp_runtime_drain(igmp_runtime *rt, int maxn) {
    igmp_rt_extra *x = extra(rt);
    int n = 0;
    while (x->qn > 0 && n < maxn) {
        igmp_qframe *slot = &x->q[x->qh];
        igmp_runtime_on_frame(rt, slot->data, slot->len, slot->link, slot->ifindex, slot->ifgen);
        x->qh = (x->qh + 1) % rt->queue_cap;
        x->qn--;
        n++;
    }
    rt->queue_depth = x->qn;
    return n;
}

static void note_peers(igmp_runtime *rt) {
    if (!rt->coord_dir[0] || !rt->eng->cfg.active_querier)
        return;
    igmp_peer peers[64];
    int n = igmp_coord_peers(rt->coord_dir, rt->node_name, igmp_coord_now_ms(), rt->snap_max_age_ms,
                             peers, 64);
    if (n < 0)
        return;
    for (int i = 0; i < n; i++) {
        if (peers[i].fresh && peers[i].active && peers[i].ip && peers[i].ip < rt->eng->cfg.self_ip)
            igmp_engine_note_cluster_querier(rt->eng, peers[i].ip, rt->now_ms);
    }
}

void igmp_runtime_tick(igmp_runtime *rt) {
    expire_held(rt);
    note_peers(rt);
    int before = igmp_engine_joined_count(rt->eng);
    igmp_engine_tick(rt->eng, rt->now_ms);
    int after = igmp_engine_joined_count(rt->eng);
    if (after < before) {
        rt->cleanups += (uint64_t)(before - after);
        log_member(rt, "member-deleted", "timer", 0, before - after);
        rt->gen++;
    }
}

int igmp_runtime_pod_upsert(igmp_runtime *rt, const char *uid, const char *name, const char *node,
                            uint32_t ip, int restart_count, int deleting, int from_list) {
    const igmp_pod *prev = igmp_pods_by_uid(&rt->pods, uid);
    int prev_restart = prev ? prev->restart_count : -1;
    uint32_t old_ip = prev ? prev->ip : 0;
    if (igmp_pods_upsert(&rt->pods, uid, name, node, ip, restart_count, deleting, from_list) != 0)
        return -1;
    if (prev_restart >= 0 && restart_count > prev_restart)
        rt->restarts_ignored++;
    if (ip && !deleting)
        igmp_engine_bind_pod(rt->eng, ip, uid, node);
    /* Same pod object, new address. The previous address is the inactive one.
     * Groups learned from the new address stay bound above. */
    if (old_ip && ip && old_ip != ip && !igmp_pods_by_ip(&rt->pods, old_ip))
        drop_subscriber(rt, old_ip, "pod-ip-changed");
    if (ip && !deleting && pod_on_this_node(rt, node)) {
        if (ip != old_ip && rt->log_json) {
            char ipb[32];
            igmp_ip_fmt(ip, ipb, sizeof ipb);
            fprintf(stderr,
                    "{\"level\":\"info\",\"msg\":\"pod-ip\",\"ip\":\"%s\",\"pod\":\"%s\","
                    "\"node\":\"%s\"}\n",
                    ipb, name ? name : "", rt->node_name);
        }
        replay_held(rt, ip);
    }
    return 0;
}

int igmp_runtime_pod_delete(igmp_runtime *rt, const char *uid) {
    if (!igmp_pods_delete(&rt->pods, uid))
        return 0;
    refresh_local_seen(rt);
    return drop_uid(rt, uid, "pod-deleted");
}

void igmp_runtime_pods_begin(igmp_runtime *rt) {
    igmp_pods_begin_list(&rt->pods);
}

static void end_cb(void *user, const char *uid) {
    igmp_runtime *rt = user;
    drop_uid(rt, uid, "pod-list-absent");
}

int igmp_runtime_pods_end(igmp_runtime *rt) {
    refresh_local_seen(rt);
    int n = igmp_pods_end_list(&rt->pods, end_cb, rt);
    if (n < 0)
        logj(rt, "warn", "pod-list-skipped-api-down");
    else
        sweep_missing_pods(rt);
    return n;
}

void igmp_runtime_set_api(igmp_runtime *rt, int healthy) {
    rt->pods.api_healthy = healthy ? 1 : 0;
}

uint32_t igmp_runtime_observe_iface(igmp_runtime *rt, uint32_t ifindex, const char *name,
                                    int present) {
    igmp_iface *slot = NULL;
    igmp_rt_extra *x = extra(rt);
    for (int i = 0; i < 64; i++) {
        if (x->ifaces[i].used && x->ifaces[i].ifindex == ifindex) {
            slot = &x->ifaces[i];
            break;
        }
    }
    if (!present) {
        if (slot && slot->present) {
            uint32_t old = slot->gen;
            slot->present = 0;
            slot->gen++;
            int n = igmp_engine_retire_ifgen(rt->eng, ifindex, old);
            if (n > 0) {
                rt->cleanups += (uint64_t)n;
                log_member(rt, "member-deleted", "iface-down", 0, n);
                rt->gen++;
            }
        }
        return slot ? slot->gen : 0;
    }
    if (!slot) {
        for (int i = 0; i < 64; i++) {
            if (!x->ifaces[i].used) {
                slot = &x->ifaces[i];
                memset(slot, 0, sizeof *slot);
                slot->used = 1;
                slot->ifindex = ifindex;
                slot->gen = 1;
                break;
            }
        }
    }
    if (!slot)
        return 0;
    if (slot->name[0] && name && strcmp(slot->name, name) != 0) {
        uint32_t old = slot->gen;
        slot->gen++;
        int n = igmp_engine_retire_ifgen(rt->eng, ifindex, old);
        if (n > 0) {
            rt->cleanups += (uint64_t)n;
            log_member(rt, "member-deleted", "ifindex-reuse", 0, n);
            rt->gen++;
        }
    }
    slot->present = 1;
    if (name)
        snprintf(slot->name, sizeof slot->name, "%s", name);
    return slot->gen;
}

static int collect_snaps(igmp_runtime *rt, igmp_snap_mem *mem, int cap) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS && n < cap; i++) {
        igmp_member *m = &rt->eng->members[i];
        if (!m->used || !m->joined || m->lmq_left > 0)
            continue;
        mem[n].group = m->group;
        mem[n].subscriber = m->subscriber;
        mem[n].ifindex = m->ifindex;
        mem[n].ifgen = m->ifgen;
        mem[n].joined = 1;
        snprintf(mem[n].pod_uid, sizeof mem[n].pod_uid, "%s", m->pod_uid);
        n++;
    }
    return n;
}

int igmp_runtime_write_snapshot(igmp_runtime *rt) {
    if (!rt->coord_dir[0])
        return 0;
    igmp_snap_mem *mem = calloc(IGMP_MAX_MEMBERS, sizeof *mem);
    if (!mem)
        return -1;
    int n = collect_snaps(rt, mem, IGMP_MAX_MEMBERS);
    int rc = igmp_coord_write(rt->coord_dir, rt->node_name, rt->node_ip, rt->eng->cfg.active_querier,
                              igmp_coord_now_ms(), mem, n);
    free(mem);
    return rc;
}

int igmp_runtime_restore(igmp_runtime *rt) {
    if (!rt->coord_dir[0] || !rt->node_name[0])
        return 0;
    igmp_snap_mem *mem = calloc(IGMP_MAX_MEMBERS, sizeof *mem);
    if (!mem)
        return -1;
    int n = igmp_coord_load_self(rt->coord_dir, rt->node_name, mem, IGMP_MAX_MEMBERS);
    int restored = 0;
    for (int i = 0; i < n; i++) {
        if (!mem[i].joined)
            continue;
        if (igmp_engine_restore(rt->eng, mem[i].group, mem[i].subscriber, mem[i].ifindex,
                                mem[i].ifgen, mem[i].pod_uid, rt->node_name, rt->now_ms) == 0) {
            remember_local(rt, mem[i].group, mem[i].subscriber);
            restored++;
        }
    }
    free(mem);
    return restored;
}

static int fill_local(igmp_runtime *rt, igmp_local_sub *local, int cap) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS && n < cap; i++) {
        igmp_member *m = &rt->eng->members[i];
        if (!m->used)
            continue;
        local[n].group = m->group;
        local[n].subscriber = m->subscriber;
        /* Last-member wait still holds the slot so a late report can rejoin,
         * but the pod has left. Publishing it makes every other node keep a
         * remote subscriber, and injecting TO_EX puts the Cilium row back. */
        local[n].joined = m->joined && m->lmq_left == 0;
        n++;
    }
    return n;
}

static void apply_ledger_marks(igmp_runtime *rt, igmp_actual *rows, int n) {
    if (!rt->mark_from_ledger || !rt->ledger_path[0])
        return;
    for (int i = 0; i < n; i++) {
        if (igmp_ledger_has(rt->ledger_path, rows[i].group, rows[i].addr, rows[i].remote))
            rows[i].managed = 1;
        if (!rows[i].remote && igmp_engine_find(rt->eng, rows[i].group, rows[i].addr, 0, NULL))
            rows[i].managed = 1;
        /* The datapath never inserts a remote row. subscriber add is the only
         * writer, and a pod restart drops the emptyDir ledger, so an address
         * left from the previous process has to stay owned or it can never
         * be removed and it blocks group delete. */
        if (rows[i].remote && rows[i].addr != 0)
            rows[i].managed = 1;
    }
}

/* A Local Endpoint whose address is not a current pod on this node was left
 * by a restart that never sent a leave. Owning it lets reconcile delete that
 * address without adopting it as a membership. A still-running pod is left
 * unmanaged unless the engine already learned its report. */
static void claim_departed_locals(igmp_runtime *rt, igmp_actual *rows, int n) {
    uint32_t ips[64];
    int counts[64];
    int nips = 0;
    if (!rt->use_kube || !rt->pods.full_list_ok)
        return;
    refresh_local_seen(rt);
    for (int i = 0; i < n; i++) {
        int slot = -1;
        if (rows[i].remote || rows[i].addr == 0 || rows[i].managed)
            continue;
        if (subscriber_live(rt, rows[i].addr))
            continue;
        rows[i].managed = 1;
        for (int k = 0; k < nips; k++)
            if (ips[k] == rows[i].addr)
                slot = k;
        if (slot >= 0) {
            counts[slot]++;
            continue;
        }
        if (nips >= (int)(sizeof ips / sizeof ips[0]))
            continue;
        ips[nips] = rows[i].addr;
        counts[nips] = 1;
        nips++;
    }
    for (int k = 0; k < nips; k++)
        log_member(rt, "member-deleted", "departed-local", ips[k], counts[k]);
}

static int actual_has_local(const igmp_actual *actual, int n, uint32_t group, uint32_t addr) {
    for (int i = 0; i < n; i++)
        if (actual[i].group == group && !actual[i].remote && actual[i].addr == addr)
            return 1;
    return 0;
}

static int actual_has_group(const igmp_actual *actual, int n, uint32_t group) {
    for (int i = 0; i < n; i++)
        if (actual[i].group == group)
            return 1;
    return 0;
}

/* Lowest joined version on this group. v2 hosts ignore a v3 query, and a v3
 * host answers a v2 query. only_missing limits the choice to members that
 * Cilium has not yet recorded as local subscribers. Returns 0 when none. */
static int solicit_version(const igmp_engine *e, uint32_t group, int only_missing,
                           const igmp_actual *actual, int nactual) {
    int version = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        const igmp_member *m = &e->members[i];
        if (!m->used || !m->joined || m->lmq_left > 0 || m->group != group)
            continue;
        if (only_missing && actual_has_local(actual, nactual, group, m->subscriber))
            continue;
        int v = m->version >= 3 ? 3 : 2;
        if (version == 0 || v < version)
            version = v;
    }
    return version;
}

static int solicit_group(igmp_runtime *rt, uint32_t group, int version) {
    if (version <= 0)
        return 0;
    int rc = igmp_engine_solicit(rt->eng, group, 0, version);
    return rc > 0 ? 1 : rc;
}

/* Groups already in the map but missing the pod address. One query per group,
 * continuing from the previous pass so a full queue cannot starve the tail. */
static int solicit_missing_locals(igmp_runtime *rt, const igmp_actual *actual, int nactual) {
    if (!rt->eng->cfg.solicit_reports || nactual <= 0)
        return 0;
    igmp_rt_extra *x = extra(rt);
    int start = x->solicit_at;
    if (start < 0 || start >= IGMP_MAX_MEMBERS)
        start = 0;
    int queued = 0;
    for (int n = 0; n < IGMP_MAX_MEMBERS; n++) {
        int i = (start + n) % IGMP_MAX_MEMBERS;
        const igmp_member *m = &rt->eng->members[i];
        if (!m->used || !m->joined || m->lmq_left > 0 || !actual_has_group(actual, nactual, m->group))
            continue;
        if (actual_has_local(actual, nactual, m->group, m->subscriber))
            continue;
        int rc = solicit_group(rt, m->group, solicit_version(rt->eng, m->group, 1, actual, nactual));
        if (rc < 0) {
            x->solicit_at = i;
            return queued;
        }
        queued += rc;
    }
    x->solicit_at = 0;
    return queued;
}

static int queue_join(igmp_rt_extra *x, uint32_t group, uint32_t sub) {
    if (!group || !sub)
        return 0;
    for (int i = 0; i < x->njoins; i++)
        if (x->joins[i].group == group && x->joins[i].subscriber == sub)
            return 0;
    if (x->njoins >= 32)
        return -1;
    x->joins[x->njoins].group = group;
    x->joins[x->njoins].subscriber = sub;
    x->njoins++;
    return 1;
}

/* Cilium inserts a local subscriber from CHANGE_TO_EXCLUDE, which is what the
 * pod sent before the group map existed. Queue one injection per missing pod. */
static void queue_joins_for_group(igmp_runtime *rt, uint32_t group, const igmp_actual *actual,
                                  int nactual) {
    igmp_rt_extra *x = extra(rt);
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        const igmp_member *m = &rt->eng->members[i];
        if (!m->used || !m->joined || m->lmq_left > 0 || m->group != group)
            continue;
        if (actual_has_local(actual, nactual, group, m->subscriber))
            continue;
        if (queue_join(x, group, m->subscriber) < 0)
            return;
    }
}

static void queue_missing_joins(igmp_runtime *rt, const igmp_actual *actual, int nactual) {
    igmp_rt_extra *x = extra(rt);
    int start = x->join_at;
    if (start < 0 || start >= IGMP_MAX_MEMBERS)
        start = 0;
    for (int n = 0; n < IGMP_MAX_MEMBERS; n++) {
        int i = (start + n) % IGMP_MAX_MEMBERS;
        const igmp_member *m = &rt->eng->members[i];
        if (!m->used || !m->joined || m->lmq_left > 0)
            continue;
        if (!actual_has_group(actual, nactual, m->group))
            continue;
        if (actual_has_local(actual, nactual, m->group, m->subscriber))
            continue;
        if (queue_join(x, m->group, m->subscriber) < 0) {
            x->join_at = i;
            return;
        }
    }
    x->join_at = 0;
}

static void ledger_after_op(igmp_runtime *rt, const igmp_op *op) {
    if (!rt->ledger_path[0])
        return;
    int remote = (op->op == IGMP_OP_REMOTE_ADD || op->op == IGMP_OP_REMOTE_DEL);
    (void)remote;
    if (op->op == IGMP_OP_GROUP_ADD)
        igmp_ledger_add(rt->ledger_path, op->group, 0, 1);
    else if (op->op == IGMP_OP_REMOTE_ADD)
        igmp_ledger_add(rt->ledger_path, op->group, op->addr, 1);
    else if (op->op == IGMP_OP_REMOTE_DEL || op->op == IGMP_OP_LOCAL_DEL)
        igmp_ledger_del(rt->ledger_path, op->group, op->addr, remote || op->op == IGMP_OP_REMOTE_DEL);
    else if (op->op == IGMP_OP_GROUP_DEL)
        igmp_ledger_del(rt->ledger_path, op->group, 0, 1);
}

int igmp_runtime_reconcile(igmp_runtime *rt) {
    if (!rt->backend || !rt->backend->load || !rt->backend->apply)
        return -1;
    igmp_rt_extra *x = extra(rt);
    x->njoins = 0;
    igmp_actual *actual = calloc(4096, sizeof *actual);
    igmp_local_sub *local = calloc(4096, sizeof *local);
    igmp_remote_sub *remote = calloc(2048, sizeof *remote);
    igmp_op *ops = calloc(8192, sizeof *ops);
    if (!actual || !local || !remote || !ops) {
        free(actual);
        free(local);
        free(remote);
        free(ops);
        return -1;
    }
    int continue_plan = x->n_retry > 0 && x->retry_gen == rt->gen;
    int nactual = 0;
    int loaded = 0;
    if (!continue_plan) {
        nactual = rt->backend->load(rt->backend, actual, 4096);
        if (nactual < 0) {
            rt->reconcile_failures++;
            log_backend(rt, "backend-load-failed");
            free(actual);
            free(local);
            free(remote);
            free(ops);
            return -1;
        }
        apply_ledger_marks(rt, actual, nactual);
        claim_departed_locals(rt, actual, nactual);
        loaded = 1;
    }
    int nlocal = fill_local(rt, local, 4096);
    int nremote = 0;
    uint32_t stale[128];
    int nstale = 0;
    int allow_remote = 1;
    if (rt->coord_dir[0]) {
        nremote = igmp_coord_load_remote(rt->coord_dir, rt->node_name, igmp_coord_now_ms(),
                                         rt->snap_max_age_ms, remote, 2048, stale, 128, &nstale,
                                         x->ids, x->nids);
        if (nremote < 0) {
            nremote = 0;
            allow_remote = 0;
            rt->coord_ok = 0;
        } else {
            rt->coord_ok = 1;
        }
        if (rt->log_json && nremote != rt->remote_subscribers) {
            fprintf(stderr,
                    "{\"level\":\"info\",\"msg\":\"remote-subscribers\",\"count\":%d,\"node\":\"%s\"}\n",
                    nremote, rt->node_name);
        }
        rt->remote_subscribers = nremote;
    }
    uint64_t remote_sig = (uint64_t)nremote << 32;
    for (int i = 0; i < nremote; i++) {
        uint64_t h = remote[i].group;
        h = h * 131u + remote[i].node_ip;
        h = h * 131u + (uint64_t)remote[i].joined_count;
        remote_sig ^= h;
    }
    /* A leave on another node does not bump the local generation. Finishing
     * an old add plan would reinstall groups the peer has already dropped. */
    if (continue_plan && remote_sig != x->remote_sig) {
        continue_plan = 0;
        x->n_retry = 0;
        rt->stale_dropped++;
    }
    x->remote_sig = remote_sig;
    if (!continue_plan && !loaded) {
        nactual = rt->backend->load(rt->backend, actual, 4096);
        if (nactual < 0) {
            rt->reconcile_failures++;
            log_backend(rt, "backend-load-failed");
            free(actual);
            free(local);
            free(remote);
            free(ops);
            return -1;
        }
        apply_ledger_marks(rt, actual, nactual);
        claim_departed_locals(rt, actual, nactual);
    }
    int allow_delete = rt->now_ms >= rt->eng->started_ms + rt->eng->cfg.startup_grace_ms;
    if (rt->use_kube && !rt->pods.full_list_ok)
        allow_delete = 0;
    int nop = 0;
    int from_retry = 0;
    if (continue_plan) {
        nop = x->n_retry;
        memcpy(ops, x->retry, (size_t)nop * sizeof *ops);
        from_retry = 1;
        rt->reconcile_retries++;
    } else {
        if (x->n_retry > 0 && x->retry_gen != rt->gen) {
            x->n_retry = 0;
            rt->stale_dropped++;
        }
        nop = igmp_reconcile(local, nlocal, remote, nremote, actual, nactual, rt->node_ip,
                             allow_delete, allow_delete && allow_remote, stale, nstale, ops, 8192);
    }
    if (nop < 0) {
        rt->reconcile_failures++;
        free(actual);
        free(local);
        free(remote);
        free(ops);
        return -1;
    }
    rt->last_op_count = nop < 128 ? nop : 128;
    if (rt->last_op_count > 0)
        memcpy(rt->last_ops, ops, (size_t)rt->last_op_count * sizeof(igmp_op));
    if (rt->dry_run || rt->backend->dry_run) {
        x->n_retry = 0;
        rt->reconcile_ok++;
        free(actual);
        free(local);
        free(remote);
        free(ops);
        return nop;
    }
    int applied = 0;
    int deferred = 0;
    int failed = 0;
    int solicited = 0;
    for (int i = 0; i < nop; i++) {
        if (applied >= IGMP_APPLY_PER_PASS) {
            int left = nop - i;
            if (left > x->retry_cap)
                left = x->retry_cap;
            memcpy(x->retry, &ops[i], (size_t)left * sizeof(igmp_op));
            x->n_retry = left;
            x->retry_gen = rt->gen;
            deferred = left;
            break;
        }
        if (rt->backend->apply(rt->backend, &ops[i]) != 0) {
            int left = nop - i;
            if (left > x->retry_cap)
                left = x->retry_cap;
            memcpy(x->retry, &ops[i], (size_t)left * sizeof(igmp_op));
            x->n_retry = left;
            x->retry_gen = rt->gen;
            failed = 1;
            break;
        }
        applied++;
        rt->mutations++;
        ledger_after_op(rt, &ops[i]);
        /* The group map exists only after this add. A remote-only group has
         * no local member here, so it is not solicited. */
        if (ops[i].op == IGMP_OP_GROUP_ADD) {
            int rc = solicit_group(rt, ops[i].group,
                                   solicit_version(rt->eng, ops[i].group, 0, NULL, 0));
            if (rc > 0)
                solicited += rc;
            queue_joins_for_group(rt, ops[i].group, actual, nactual);
        }
    }
    if (!failed && !continue_plan) {
        solicited += solicit_missing_locals(rt, actual, nactual);
        queue_missing_joins(rt, actual, nactual);
    }
    if (rt->log_json && solicited > 0) {
        fprintf(stderr,
                "{\"level\":\"info\",\"msg\":\"local-solicit\",\"count\":%d,\"node\":\"%s\"}\n",
                solicited, rt->node_name);
    }
    if (deferred > 0 && rt->log_json) {
        fprintf(stderr,
                "{\"level\":\"info\",\"msg\":\"reconcile-deferred\",\"remaining\":%d,"
                "\"node\":\"%s\"}\n",
                deferred, rt->node_name);
    }
    free(actual);
    free(local);
    free(remote);
    free(ops);
    (void)from_retry;
    if (failed) {
        rt->reconcile_failures++;
        log_backend(rt, "backend-apply-failed");
        return -1;
    }
    if (deferred > 0)
        return applied;
    x->n_retry = 0;
    rt->reconcile_ok++;
    return nop;
}

int igmp_metrics_render(const igmp_runtime *rt, char *buf, size_t len) {
    const igmp_engine *e = rt->eng;
    int n = snprintf(
        buf, len,
        "# HELP igmpshark_joins_total Memberships created\n"
        "# TYPE igmpshark_joins_total counter\n"
        "igmpshark_joins_total %llu\n"
        "# TYPE igmpshark_leaves_total counter\n"
        "igmpshark_leaves_total %llu\n"
        "# TYPE igmpshark_memberships gauge\n"
        "igmpshark_memberships %d\n"
        "# TYPE igmpshark_refreshes_total counter\n"
        "igmpshark_refreshes_total %llu\n"
        "# TYPE igmpshark_expires_total counter\n"
        "igmpshark_expires_total %llu\n"
        "# TYPE igmpshark_malformed_total counter\n"
        "igmpshark_malformed_total %llu\n"
        "# TYPE igmpshark_dedup_drops_total counter\n"
        "igmpshark_dedup_drops_total %llu\n"
        "# TYPE igmpshark_limit_drops_total counter\n"
        "igmpshark_limit_drops_total %llu\n"
        "# TYPE igmpshark_capture_drops_total counter\n"
        "igmpshark_capture_drops_total %llu\n"
        "# TYPE igmpshark_queue_drops_total counter\n"
        "igmpshark_queue_drops_total %llu\n"
        "# TYPE igmpshark_queue_depth gauge\n"
        "igmpshark_queue_depth %d\n"
        "# TYPE igmpshark_reconcile_failures_total counter\n"
        "igmpshark_reconcile_failures_total %llu\n"
        "# TYPE igmpshark_reconcile_retries_total counter\n"
        "igmpshark_reconcile_retries_total %llu\n"
        "# TYPE igmpshark_reconcile_ok_total counter\n"
        "igmpshark_reconcile_ok_total %llu\n"
        "# TYPE igmpshark_mutations_total counter\n"
        "igmpshark_mutations_total %llu\n"
        "# TYPE igmpshark_cleanups_total counter\n"
        "igmpshark_cleanups_total %llu\n"
        "# TYPE igmpshark_ignored_unbound_total counter\n"
        "igmpshark_ignored_unbound_total %llu\n"
        "# TYPE igmpshark_restarts_ignored_total counter\n"
        "igmpshark_restarts_ignored_total %llu\n"
        "# TYPE igmpshark_stale_work_dropped_total counter\n"
        "igmpshark_stale_work_dropped_total %llu\n"
        "# TYPE igmpshark_k8s_watch_healthy gauge\n"
        "igmpshark_k8s_watch_healthy %d\n"
        "# TYPE igmpshark_querier_degraded gauge\n"
        "igmpshark_querier_degraded %d\n"
        "# TYPE igmpshark_we_are_querier gauge\n"
        "igmpshark_we_are_querier %d\n"
        "# TYPE igmpshark_queries_seen_total counter\n"
        "igmpshark_queries_seen_total %llu\n"
        "# TYPE igmpshark_queries_sent_total counter\n"
        "igmpshark_queries_sent_total %llu\n"
        "# TYPE igmpshark_coord_ok gauge\n"
        "igmpshark_coord_ok %d\n"
        "# TYPE igmpshark_remote_subscribers gauge\n"
        "igmpshark_remote_subscribers %d\n",
        (unsigned long long)e->joins, (unsigned long long)e->leaves, igmp_engine_joined_count(e),
        (unsigned long long)e->refreshes, (unsigned long long)e->expires,
        (unsigned long long)e->malformed, (unsigned long long)e->dedup_drops,
        (unsigned long long)e->limit_drops, (unsigned long long)rt->capture_drops,
        (unsigned long long)rt->queue_drops, rt->queue_depth,
        (unsigned long long)rt->reconcile_failures, (unsigned long long)rt->reconcile_retries,
        (unsigned long long)rt->reconcile_ok, (unsigned long long)rt->mutations,
        (unsigned long long)rt->cleanups, (unsigned long long)rt->ignored_unbound,
        (unsigned long long)rt->restarts_ignored, (unsigned long long)rt->stale_dropped,
        rt->pods.api_healthy, e->querier_degraded, e->we_are_querier,
        (unsigned long long)e->queries_seen, (unsigned long long)e->queries_sent, rt->coord_ok,
        rt->remote_subscribers);
    return n;
}
