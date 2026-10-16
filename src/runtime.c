#include "runtime.h"

#include "coord.h"

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

typedef struct igmp_rt_extra {
    igmp_qframe *q;
    int qh;
    int qn;
    igmp_op *retry;
    int n_retry;
    int retry_cap;
    uint64_t retry_gen;
    igmp_iface ifaces[64];
} igmp_rt_extra;

static igmp_rt_extra *extra(igmp_runtime *rt) {
    return (igmp_rt_extra *)(rt + 1);
}

static void logj(const igmp_runtime *rt, const char *level, const char *msg) {
    if (!rt->log_json)
        return;
    fprintf(stderr, "{\"level\":\"%s\",\"msg\":\"%s\",\"node\":\"%s\"}\n", level, msg,
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
        rt->ignored_unbound++;
        rt->eng->ignored++;
        return -1;
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
    int n = igmp_coord_peers(rt->coord_dir, rt->node_name, rt->now_ms, rt->snap_max_age_ms, peers, 64);
    if (n < 0)
        return;
    for (int i = 0; i < n; i++) {
        if (peers[i].fresh && peers[i].active && peers[i].ip && peers[i].ip < rt->eng->cfg.self_ip)
            igmp_engine_note_cluster_querier(rt->eng, peers[i].ip, rt->now_ms);
    }
}

void igmp_runtime_tick(igmp_runtime *rt) {
    note_peers(rt);
    int before = igmp_engine_joined_count(rt->eng);
    igmp_engine_tick(rt->eng, rt->now_ms);
    int after = igmp_engine_joined_count(rt->eng);
    if (after < before) {
        rt->cleanups += (uint64_t)(before - after);
        snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "timer");
        rt->gen++;
    }
}

int igmp_runtime_pod_upsert(igmp_runtime *rt, const char *uid, const char *name, const char *node,
                            uint32_t ip, int restart_count, int deleting, int from_list) {
    const igmp_pod *prev = igmp_pods_by_uid(&rt->pods, uid);
    int prev_restart = prev ? prev->restart_count : -1;
    if (igmp_pods_upsert(&rt->pods, uid, name, node, ip, restart_count, deleting, from_list) != 0)
        return -1;
    if (prev_restart >= 0 && restart_count > prev_restart)
        rt->restarts_ignored++;
    if (ip && !deleting)
        igmp_engine_bind_pod(rt->eng, ip, uid, node);
    return 0;
}

int igmp_runtime_pod_delete(igmp_runtime *rt, const char *uid) {
    if (!igmp_pods_delete(&rt->pods, uid))
        return 0;
    int n = igmp_engine_pod_gone(rt->eng, uid, rt->now_ms);
    if (n > 0) {
        rt->cleanups += (uint64_t)n;
        snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "pod-deleted");
        rt->gen++;
        logj(rt, "info", "pod-deleted");
    }
    return n;
}

void igmp_runtime_pods_begin(igmp_runtime *rt) {
    igmp_pods_begin_list(&rt->pods);
}

static void end_cb(void *user, const char *uid) {
    igmp_runtime *rt = user;
    int n = igmp_engine_pod_gone(rt->eng, uid, rt->now_ms);
    if (n > 0) {
        rt->cleanups += (uint64_t)n;
        snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "pod-list-absent");
        rt->gen++;
    }
}

int igmp_runtime_pods_end(igmp_runtime *rt) {
    int n = igmp_pods_end_list(&rt->pods, end_cb, rt);
    if (n < 0)
        logj(rt, "warn", "pod-list-skipped-api-down");
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
                snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "iface-down");
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
            snprintf(rt->cleanup_reason, sizeof rt->cleanup_reason, "ifindex-reuse");
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
        if (!m->used || !m->joined)
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
                              rt->now_ms, mem, n);
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
        local[n].joined = m->joined;
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
    }
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
    int nactual = rt->backend->load(rt->backend, actual, 4096);
    if (nactual < 0) {
        rt->reconcile_failures++;
        logj(rt, "warn", "backend-load-failed");
        free(actual);
        free(local);
        free(remote);
        free(ops);
        return -1;
    }
    apply_ledger_marks(rt, actual, nactual);
    int nlocal = fill_local(rt, local, 4096);
    int nremote = 0;
    uint32_t stale[128];
    int nstale = 0;
    int allow_remote = 1;
    if (rt->coord_dir[0]) {
        nremote = igmp_coord_load_remote(rt->coord_dir, rt->node_name, rt->now_ms, rt->snap_max_age_ms,
                                         remote, 2048, stale, 128, &nstale);
        if (nremote < 0) {
            nremote = 0;
            allow_remote = 0;
            rt->coord_ok = 0;
        } else {
            rt->coord_ok = 1;
        }
    }
    int allow_delete = rt->now_ms >= rt->eng->started_ms + rt->eng->cfg.startup_grace_ms;
    if (rt->use_kube && !rt->pods.full_list_ok)
        allow_delete = 0;
    int nop = 0;
    int from_retry = 0;
    if (x->n_retry > 0 && x->retry_gen == rt->gen) {
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
    for (int i = 0; i < nop; i++) {
        if (rt->backend->apply(rt->backend, &ops[i]) != 0) {
            int left = nop - i;
            if (left > x->retry_cap)
                left = x->retry_cap;
            memcpy(x->retry, &ops[i], (size_t)left * sizeof(igmp_op));
            x->n_retry = left;
            x->retry_gen = rt->gen;
            rt->reconcile_failures++;
            logj(rt, "warn", "backend-apply-failed");
            free(actual);
            free(local);
            free(remote);
            free(ops);
            (void)from_retry;
            return -1;
        }
        rt->mutations++;
        ledger_after_op(rt, &ops[i]);
    }
    x->n_retry = 0;
    rt->reconcile_ok++;
    free(actual);
    free(local);
    free(remote);
    free(ops);
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
        "igmpshark_coord_ok %d\n",
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
        (unsigned long long)e->queries_seen, (unsigned long long)e->queries_sent, rt->coord_ok);
    return n;
}
