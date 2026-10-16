#ifndef IGMPSHARK_ENGINE_H
#define IGMPSHARK_ENGINE_H

#include "igmp_types.h"

#define IGMP_MAX_MEMBERS 4096
#define IGMP_DEDUP_SLOTS 128

typedef struct igmp_config {
    int64_t query_interval_ms;
    int64_t query_response_ms;
    int robustness;
    int64_t last_member_query_ms;
    int immediate_leave;
    int active_querier;
    uint32_t self_ip;
    int max_members;
    int max_sources;
    int64_t dedup_window_ms;
    int64_t startup_grace_ms;
    int solicit_reports;
} igmp_config;

typedef struct igmp_member {
    uint32_t group;
    uint32_t subscriber;
    char pod_uid[IGMP_UID_LEN];
    char node_name[IGMP_NODE_LEN];
    uint32_t ifindex;
    uint32_t ifgen;
    int version;
    int filter_mode;
    int n_sources;
    uint32_t sources[IGMP_MAX_SOURCES];
    int joined;
    int64_t last_report_ms;
    int64_t deadline_ms;
    int lmq_left;
    int64_t lmq_deadline_ms;
    int used;
} igmp_member;

typedef struct igmp_query_out {
    uint32_t group; /* 0 = general */
    uint32_t ifindex;
    int version;
    int max_resp_ms;
} igmp_query_out;

typedef struct igmp_engine {
    igmp_config cfg;
    igmp_member members[IGMP_MAX_MEMBERS];
    int n_used;
    uint32_t querier_ip;
    int64_t querier_deadline_ms;
    int we_are_querier;
    int querier_degraded;
    int64_t next_query_ms;
    int64_t started_ms;
    uint64_t joins;
    uint64_t leaves;
    uint64_t refreshes;
    uint64_t expires;
    uint64_t malformed;
    uint64_t ignored;
    uint64_t dedup_drops;
    uint64_t limit_drops;
    uint64_t queries_sent;
    uint64_t queries_seen;
    uint8_t dedup_hash[IGMP_DEDUP_SLOTS];
    int64_t dedup_time[IGMP_DEDUP_SLOTS];
    uint32_t dedup_src[IGMP_DEDUP_SLOTS];
    igmp_query_out pending_q[32];
    int n_pending_q;
} igmp_engine;

void igmp_config_defaults(igmp_config *cfg);
void igmp_engine_init(igmp_engine *e, const igmp_config *cfg, int64_t now_ms);

/* Recovery of a previously joined subscriber. Does not count as a new join. */
int igmp_engine_restore(igmp_engine *e, uint32_t group, uint32_t subscriber,
                        uint32_t ifindex, uint32_t ifgen, const char *pod_uid,
                        const char *node_name, int64_t now_ms);

/* Another DaemonSet instance won querier election. Does not count as a query. */
void igmp_engine_note_cluster_querier(igmp_engine *e, uint32_t ip, int64_t now_ms);

int64_t igmp_membership_interval_ms(const igmp_config *cfg);
int64_t igmp_other_querier_ms(const igmp_config *cfg);

/* Returns 0 if applied, 1 if deduped, -1 if ignored or malformed. */
int igmp_engine_on_frame(igmp_engine *e, const uint8_t *frame, size_t len,
                         int link, uint32_t ifindex, uint32_t ifgen, int64_t now_ms);

int igmp_engine_on_message(igmp_engine *e, const igmp_message *msg,
                           uint32_t ifindex, uint32_t ifgen, int64_t now_ms,
                           const uint8_t *dedup, size_t dedup_len);

void igmp_engine_tick(igmp_engine *e, int64_t now_ms);

int igmp_engine_bind_pod(igmp_engine *e, uint32_t subscriber, const char *pod_uid,
                         const char *node_name);
int igmp_engine_pod_gone(igmp_engine *e, const char *pod_uid, int64_t now_ms);
int igmp_engine_retire_ifgen(igmp_engine *e, uint32_t ifindex, uint32_t old_gen);

int igmp_engine_joined_count(const igmp_engine *e);
int igmp_engine_find(const igmp_engine *e, uint32_t group, uint32_t subscriber,
                     uint32_t ifindex, const igmp_member **out);
void igmp_engine_take_queries(igmp_engine *e, igmp_query_out *out, int *n, int cap);

#endif
