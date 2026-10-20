#include "engine.h"

#include <stdio.h>
#include <string.h>

void igmp_config_defaults(igmp_config *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->query_interval_ms = 125000;
    cfg->query_response_ms = 10000;
    cfg->robustness = 2;
    cfg->last_member_query_ms = 1000;
    cfg->immediate_leave = 0;
    cfg->active_querier = 0;
    cfg->max_members = 1024;
    cfg->max_sources = IGMP_MAX_SOURCES;
    cfg->dedup_window_ms = 50;
    cfg->startup_grace_ms = 15000;
    cfg->solicit_reports = 1;
}

int64_t igmp_membership_interval_ms(const igmp_config *cfg) {
    return (int64_t)cfg->robustness * cfg->query_interval_ms + cfg->query_response_ms;
}

int64_t igmp_other_querier_ms(const igmp_config *cfg) {
    return (int64_t)cfg->robustness * cfg->query_interval_ms + cfg->query_response_ms / 2;
}

void igmp_engine_init(igmp_engine *e, const igmp_config *cfg, int64_t now_ms) {
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    if (e->cfg.max_members < 1 || e->cfg.max_members > IGMP_MAX_MEMBERS)
        e->cfg.max_members = IGMP_MAX_MEMBERS;
    if (e->cfg.max_sources < 1 || e->cfg.max_sources > IGMP_MAX_SOURCES)
        e->cfg.max_sources = IGMP_MAX_SOURCES;
    if (e->cfg.robustness < 1)
        e->cfg.robustness = 1;
    e->started_ms = now_ms;
    e->next_query_ms = now_ms;
    e->querier_degraded = cfg->active_querier ? 0 : 1;
    e->we_are_querier = cfg->active_querier ? 1 : 0;
    e->querier_ip = cfg->active_querier ? cfg->self_ip : 0;
}

static int source_has(const igmp_member *m, uint32_t src) {
    for (int i = 0; i < m->n_sources; i++)
        if (m->sources[i] == src)
            return 1;
    return 0;
}

static void source_add(igmp_member *m, uint32_t src, int max_sources) {
    if (source_has(m, src))
        return;
    if (m->n_sources >= max_sources) {
        m->n_sources = max_sources;
        return;
    }
    m->sources[m->n_sources++] = src;
}

static void source_del(igmp_member *m, uint32_t src) {
    int w = 0;
    for (int i = 0; i < m->n_sources; i++)
        if (m->sources[i] != src)
            m->sources[w++] = m->sources[i];
    m->n_sources = w;
}

static igmp_member *find_slot(igmp_engine *e, uint32_t group, uint32_t sub,
                              uint32_t ifindex, uint32_t ifgen) {
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (m->used && m->group == group && m->subscriber == sub &&
            m->ifindex == ifindex && m->ifgen == ifgen)
            return m;
    }
    return NULL;
}

static int count_on_attachment(const igmp_engine *e, uint32_t group,
                               uint32_t ifindex, uint32_t ifgen) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        const igmp_member *m = &e->members[i];
        if (m->used && m->joined && m->group == group &&
            m->ifindex == ifindex && m->ifgen == ifgen)
            n++;
    }
    return n;
}

static igmp_member *alloc_slot(igmp_engine *e) {
    if (e->n_used >= e->cfg.max_members) {
        e->limit_drops++;
        return NULL;
    }
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        if (!e->members[i].used) {
            memset(&e->members[i], 0, sizeof e->members[i]);
            e->members[i].used = 1;
            e->n_used++;
            return &e->members[i];
        }
    }
    e->limit_drops++;
    return NULL;
}

static void free_slot(igmp_engine *e, igmp_member *m) {
    if (!m->used)
        return;
    m->used = 0;
    e->n_used--;
    e->leaves++;
}

static void refresh_attachment(igmp_engine *e, uint32_t group, uint32_t ifindex,
                               uint32_t ifgen, int64_t now_ms) {
    int64_t deadline = now_ms + igmp_membership_interval_ms(&e->cfg);
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (!m->used || !m->joined || m->group != group)
            continue;
        if (m->ifindex != ifindex || m->ifgen != ifgen)
            continue;
        m->last_report_ms = now_ms;
        m->deadline_ms = deadline;
        m->lmq_left = 0;
    }
}

static void queue_query(igmp_engine *e, uint32_t group, uint32_t ifindex, int version) {
    if (e->n_pending_q >= (int)(sizeof e->pending_q / sizeof e->pending_q[0]))
        return;
    igmp_query_out *q = &e->pending_q[e->n_pending_q++];
    q->group = group;
    q->ifindex = ifindex;
    q->version = version;
    q->max_resp_ms = group ? (int)e->cfg.last_member_query_ms : (int)e->cfg.query_response_ms;
    e->queries_sent++;
}

static void arm_leave(igmp_engine *e, igmp_member *m, uint32_t ifindex, int64_t now_ms) {
    int others = count_on_attachment(e, m->group, m->ifindex, m->ifgen);
    if (e->cfg.immediate_leave && others <= 1) {
        free_slot(e, m);
        return;
    }
    m->lmq_left = e->cfg.robustness;
    m->lmq_deadline_ms = now_ms + e->cfg.last_member_query_ms;
    if (e->we_are_querier)
        queue_query(e, m->group, ifindex, m->version >= 3 ? 3 : 2);
}

static igmp_member *ensure_member(igmp_engine *e, uint32_t group, uint32_t sub,
                                  uint32_t ifindex, uint32_t ifgen, int *created) {
    igmp_member *m = find_slot(e, group, sub, ifindex, ifgen);
    *created = 0;
    if (m)
        return m;
    m = alloc_slot(e);
    if (!m)
        return NULL;
    m->group = group;
    m->subscriber = sub;
    m->ifindex = ifindex;
    m->ifgen = ifgen;
    *created = 1;
    e->joins++;
    return m;
}

static void mark_joined(igmp_engine *e, igmp_member *m, int version, int64_t now_ms,
                        int created, uint32_t ifindex) {
    int was = m->joined;
    m->joined = 1;
    m->version = version;
    m->last_report_ms = now_ms;
    m->deadline_ms = now_ms + igmp_membership_interval_ms(&e->cfg);
    m->lmq_left = 0;
    if (created && e->cfg.solicit_reports && e->we_are_querier)
        queue_query(e, m->group, ifindex, version >= 3 ? 3 : 2);
    if (!created && was)
        e->refreshes++;
    refresh_attachment(e, m->group, m->ifindex, m->ifgen, now_ms);
}

static int apply_v3_record(igmp_engine *e, const igmp_record *rec, uint32_t src,
                           uint32_t ifindex, uint32_t ifgen, int64_t now_ms) {
    if (!igmp_group_routable(rec->group) || rec->type < 1 || rec->type > 6) {
        e->ignored++;
        return -1;
    }
    int created = 0;
    igmp_member *m = find_slot(e, rec->group, src, ifindex, ifgen);
    if (!m && (rec->type == IGMP_REC_IS_INCLUDE || rec->type == IGMP_REC_TO_INCLUDE) &&
        rec->n_sources == 0) {
        e->ignored++;
        return 0;
    }
    if (!m) {
        m = ensure_member(e, rec->group, src, ifindex, ifgen, &created);
        if (!m)
            return -1;
        m->filter_mode = IGMP_FILTER_INCLUDE;
    }
    int max_src = e->cfg.max_sources;
    switch (rec->type) {
    case IGMP_REC_IS_INCLUDE:
    case IGMP_REC_TO_INCLUDE:
        m->filter_mode = IGMP_FILTER_INCLUDE;
        m->n_sources = 0;
        for (int i = 0; i < rec->n_sources && i < max_src; i++)
            source_add(m, rec->sources[i], max_src);
        if (m->n_sources == 0)
            arm_leave(e, m, ifindex, now_ms);
        else
            mark_joined(e, m, 3, now_ms, created, ifindex);
        break;
    case IGMP_REC_IS_EXCLUDE:
    case IGMP_REC_TO_EXCLUDE:
        m->filter_mode = IGMP_FILTER_EXCLUDE;
        m->n_sources = 0;
        for (int i = 0; i < rec->n_sources && i < max_src; i++)
            source_add(m, rec->sources[i], max_src);
        mark_joined(e, m, 3, now_ms, created, ifindex);
        break;
    case IGMP_REC_ALLOW:
        if (m->filter_mode == IGMP_FILTER_INCLUDE) {
            for (int i = 0; i < rec->n_sources; i++)
                source_add(m, rec->sources[i], max_src);
        } else {
            for (int i = 0; i < rec->n_sources; i++)
                source_del(m, rec->sources[i]);
        }
        if (m->filter_mode == IGMP_FILTER_INCLUDE && m->n_sources == 0)
            arm_leave(e, m, ifindex, now_ms);
        else
            mark_joined(e, m, 3, now_ms, 0, ifindex);
        break;
    case IGMP_REC_BLOCK:
        if (m->filter_mode == IGMP_FILTER_INCLUDE) {
            for (int i = 0; i < rec->n_sources; i++)
                source_del(m, rec->sources[i]);
            if (m->n_sources == 0)
                arm_leave(e, m, ifindex, now_ms);
            else
                mark_joined(e, m, 3, now_ms, 0, ifindex);
        } else {
            for (int i = 0; i < rec->n_sources; i++)
                source_add(m, rec->sources[i], max_src);
            mark_joined(e, m, 3, now_ms, 0, ifindex);
        }
        break;
    default:
        e->ignored++;
        if (created)
            free_slot(e, m);
        return -1;
    }
    return 0;
}

static int dedup_hit(igmp_engine *e, uint32_t src, const uint8_t *dedup, size_t dedup_len,
                     int64_t now_ms) {
    if (!dedup || dedup_len == 0 || e->cfg.dedup_window_ms <= 0)
        return 0;
    unsigned h = 2166136261u;
    for (size_t i = 0; i < dedup_len; i++)
        h = (h ^ dedup[i]) * 16777619u;
    h ^= src;
    unsigned slot = h % IGMP_DEDUP_SLOTS;
    if (e->dedup_src[slot] == src && e->dedup_hash[slot] == (uint8_t)h &&
        now_ms >= e->dedup_time[slot] &&
        now_ms - e->dedup_time[slot] <= e->cfg.dedup_window_ms) {
        e->dedup_drops++;
        return 1;
    }
    e->dedup_src[slot] = src;
    e->dedup_hash[slot] = (uint8_t)h;
    e->dedup_time[slot] = now_ms;
    return 0;
}

int igmp_engine_restore(igmp_engine *e, uint32_t group, uint32_t subscriber,
                          uint32_t ifindex, uint32_t ifgen, const char *pod_uid,
                          const char *node_name, int64_t now_ms) {
    int created = 0;
    igmp_member *m = ensure_member(e, group, subscriber, ifindex, ifgen, &created);
    if (!m)
        return -1;
    if (created)
        e->joins--;
    m->joined = 1;
    m->version = 2;
    m->filter_mode = IGMP_FILTER_EXCLUDE;
    m->last_report_ms = now_ms;
    m->deadline_ms = now_ms + igmp_membership_interval_ms(&e->cfg);
    m->lmq_left = 0;
    snprintf(m->pod_uid, sizeof m->pod_uid, "%s", pod_uid ? pod_uid : "");
    snprintf(m->node_name, sizeof m->node_name, "%s", node_name ? node_name : "");
    return 0;
}

static void elect_querier(igmp_engine *e, uint32_t ip, int64_t now_ms) {
    e->querier_degraded = 0;
    if (!e->cfg.active_querier || e->cfg.self_ip == 0) {
        e->querier_ip = ip;
        e->we_are_querier = 0;
        e->querier_deadline_ms = now_ms + igmp_other_querier_ms(&e->cfg);
        return;
    }
    /* A still-valid lower querier is not displaced by a higher address. */
    if (e->querier_ip != 0 && e->querier_ip < e->cfg.self_ip && e->querier_ip < ip &&
        now_ms < e->querier_deadline_ms) {
        e->we_are_querier = 0;
        return;
    }
    if (e->cfg.self_ip < ip) {
        e->we_are_querier = 1;
        e->querier_ip = e->cfg.self_ip;
    } else {
        e->querier_ip = ip;
        e->we_are_querier = (ip == e->cfg.self_ip);
    }
    e->querier_deadline_ms = now_ms + igmp_other_querier_ms(&e->cfg);
}

static void note_querier(igmp_engine *e, uint32_t ip, int64_t now_ms) {
    e->queries_seen++;
    elect_querier(e, ip, now_ms);
}

void igmp_engine_note_cluster_querier(igmp_engine *e, uint32_t ip, int64_t now_ms) {
    if (!e->cfg.active_querier || ip == 0 || ip == e->cfg.self_ip)
        return;
    elect_querier(e, ip, now_ms);
}

int igmp_engine_on_message(igmp_engine *e, const igmp_message *msg,
                           uint32_t ifindex, uint32_t ifgen, int64_t now_ms,
                           const uint8_t *dedup, size_t dedup_len) {
    if (!msg || !msg->ok || msg->malformed || !msg->checksum_ok) {
        e->malformed++;
        return -1;
    }
    if (dedup_hit(e, msg->src, dedup, dedup_len, now_ms))
        return 1;
    if (msg->kind == IGMP_KIND_QUERY) {
        note_querier(e, msg->src, now_ms);
        if (msg->group != 0) {
            /* Group-specific query continues last-member wait; it does not
             * expire subscribers who have not sent a leave. */
            for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
                igmp_member *m = &e->members[i];
                if (m->used && m->group == msg->group && m->lmq_left > 0)
                    m->lmq_deadline_ms = now_ms + (msg->max_resp_ms > 0 ? msg->max_resp_ms
                                                                        : e->cfg.last_member_query_ms);
            }
        }
        return 0;
    }
    if (msg->kind == IGMP_KIND_V3_REPORT) {
        for (int i = 0; i < msg->n_records; i++)
            apply_v3_record(e, &msg->records[i], msg->src, ifindex, ifgen, now_ms);
        if (msg->too_many_records)
            e->limit_drops++;
        return 0;
    }
    if (!igmp_group_routable(msg->group)) {
        e->ignored++;
        return -1;
    }
    if (msg->kind == IGMP_KIND_V2_LEAVE) {
        igmp_member *m = find_slot(e, msg->group, msg->src, ifindex, ifgen);
        if (!m || !m->joined) {
            e->ignored++;
            return 0;
        }
        arm_leave(e, m, ifindex, now_ms);
        return 0;
    }
    if (msg->kind == IGMP_KIND_V1_REPORT || msg->kind == IGMP_KIND_V2_REPORT) {
        int created = 0;
        igmp_member *m = ensure_member(e, msg->group, msg->src, ifindex, ifgen, &created);
        if (!m)
            return -1;
        m->filter_mode = IGMP_FILTER_EXCLUDE;
        m->n_sources = 0;
        mark_joined(e, m, msg->version, now_ms, created, ifindex);
        return 0;
    }
    e->ignored++;
    return -1;
}

int igmp_engine_on_frame(igmp_engine *e, const uint8_t *frame, size_t len,
                         int link, uint32_t ifindex, uint32_t ifgen, int64_t now_ms) {
    igmp_message msg;
    if (igmp_parse_ipv4(frame, len, link, &msg) != 0) {
        e->malformed++;
        return -1;
    }
    return igmp_engine_on_message(e, &msg, ifindex, ifgen, now_ms, frame, len);
}

void igmp_engine_tick(igmp_engine *e, int64_t now_ms) {
    int querier_alive = e->querier_ip != 0 && now_ms < e->querier_deadline_ms;
    if (e->cfg.active_querier && !querier_alive) {
        e->we_are_querier = 1;
        e->querier_ip = e->cfg.self_ip;
        e->querier_deadline_ms = now_ms + igmp_other_querier_ms(&e->cfg);
        e->querier_degraded = 0;
        querier_alive = 1;
    }
    if (!e->cfg.active_querier && !querier_alive)
        e->querier_degraded = 1;
    else if (querier_alive)
        e->querier_degraded = 0;

    if (e->we_are_querier && now_ms >= e->next_query_ms) {
        queue_query(e, 0, 0, 2);
        e->next_query_ms = now_ms + e->cfg.query_interval_ms;
    }

    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (!m->used)
            continue;
        if (m->lmq_left > 0 && now_ms >= m->lmq_deadline_ms) {
            m->lmq_left--;
            if (m->lmq_left <= 0) {
                free_slot(e, m);
                e->expires++;
                continue;
            }
            m->lmq_deadline_ms = now_ms + e->cfg.last_member_query_ms;
            if (e->we_are_querier)
                queue_query(e, m->group, m->ifindex, m->version >= 3 ? 3 : 2);
            continue;
        }
        /* Silence alone does not expire a subscriber unless a querier is
         * present to have solicited a refresh. */
        if (m->joined && querier_alive && m->deadline_ms > 0 && now_ms >= m->deadline_ms) {
            free_slot(e, m);
            e->expires++;
        }
    }
}

int igmp_engine_bind_pod(igmp_engine *e, uint32_t subscriber, const char *pod_uid,
                         const char *node_name) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (!m->used || m->subscriber != subscriber)
            continue;
        snprintf(m->pod_uid, sizeof m->pod_uid, "%s", pod_uid ? pod_uid : "");
        if (node_name)
            snprintf(m->node_name, sizeof m->node_name, "%s", node_name);
        n++;
    }
    return n;
}

int igmp_engine_pod_gone(igmp_engine *e, const char *pod_uid, int64_t now_ms) {
    (void)now_ms;
    if (!pod_uid || !pod_uid[0])
        return 0;
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (!m->used)
            continue;
        if (strcmp(m->pod_uid, pod_uid) == 0) {
            free_slot(e, m);
            n++;
        }
    }
    return n;
}

int igmp_engine_retire_ifgen(igmp_engine *e, uint32_t ifindex, uint32_t old_gen) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        igmp_member *m = &e->members[i];
        if (m->used && m->ifindex == ifindex && m->ifgen == old_gen) {
            free_slot(e, m);
            n++;
        }
    }
    return n;
}

int igmp_engine_joined_count(const igmp_engine *e) {
    int n = 0;
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++)
        if (e->members[i].used && e->members[i].joined)
            n++;
    return n;
}

int igmp_engine_find(const igmp_engine *e, uint32_t group, uint32_t subscriber,
                     uint32_t ifindex, const igmp_member **out) {
    for (int i = 0; i < IGMP_MAX_MEMBERS; i++) {
        const igmp_member *m = &e->members[i];
        if (m->used && m->group == group && m->subscriber == subscriber &&
            (ifindex == 0 || m->ifindex == ifindex)) {
            if (out)
                *out = m;
            return 1;
        }
    }
    return 0;
}

void igmp_engine_take_queries(igmp_engine *e, igmp_query_out *out, int *n, int cap) {
    int c = e->n_pending_q < cap ? e->n_pending_q : cap;
    if (out && c > 0)
        memcpy(out, e->pending_q, (size_t)c * sizeof *out);
    *n = c;
    e->n_pending_q = 0;
}
