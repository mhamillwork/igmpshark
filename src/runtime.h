#ifndef IGMPSHARK_RUNTIME_H
#define IGMPSHARK_RUNTIME_H

#include "backend.h"
#include "engine.h"
#include "pods.h"

#define IGMP_FRAME_MAX 2048

typedef struct igmp_runtime igmp_runtime;

struct igmp_runtime {
    igmp_engine *eng;
    igmp_pods pods;
    igmp_backend *backend;
    char node_name[IGMP_NODE_LEN];
    uint32_t node_ip;
    char coord_dir[512];
    char ledger_path[512];
    int use_kube;
    int mark_from_ledger;
    int dry_run;
    int log_json;
    int64_t now_ms;
    int64_t snap_max_age_ms;
    uint64_t gen;
    uint64_t capture_drops;
    uint64_t queue_drops;
    uint64_t reconcile_failures;
    uint64_t reconcile_retries;
    uint64_t reconcile_ok;
    uint64_t cleanups;
    uint64_t mutations;
    uint64_t stale_dropped;
    uint64_t ignored_unbound;
    uint64_t restarts_ignored;
    int queue_depth;
    int queue_cap;
    int coord_ok;
    int remote_subscribers;
    int last_op_count;
    igmp_op last_ops[128];
    char cleanup_reason[64];
};

igmp_runtime *igmp_runtime_new(const igmp_config *cfg, int64_t now_ms);
void igmp_runtime_free(igmp_runtime *rt);

int igmp_runtime_on_frame(igmp_runtime *rt, const uint8_t *frame, size_t len, int link,
                          uint32_t ifindex, uint32_t ifgen);
int igmp_runtime_enqueue(igmp_runtime *rt, const uint8_t *frame, size_t len, int link,
                         uint32_t ifindex, uint32_t ifgen);
int igmp_runtime_drain(igmp_runtime *rt, int maxn);

void igmp_runtime_tick(igmp_runtime *rt);
int igmp_runtime_reconcile(igmp_runtime *rt);
int igmp_runtime_write_snapshot(igmp_runtime *rt);
int igmp_runtime_restore(igmp_runtime *rt);

int igmp_runtime_pod_upsert(igmp_runtime *rt, const char *uid, const char *name,
                            const char *node, uint32_t ip, int restart_count, int deleting,
                            int from_list);
int igmp_runtime_pod_delete(igmp_runtime *rt, const char *uid);
void igmp_runtime_pods_begin(igmp_runtime *rt);
int igmp_runtime_pods_end(igmp_runtime *rt);
void igmp_runtime_set_api(igmp_runtime *rt, int healthy);

uint32_t igmp_runtime_observe_iface(igmp_runtime *rt, uint32_t ifindex, const char *name,
                                    int present);

int igmp_metrics_render(const igmp_runtime *rt, char *buf, size_t len);

#endif
