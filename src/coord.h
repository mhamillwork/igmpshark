#ifndef IGMPSHARK_COORD_H
#define IGMPSHARK_COORD_H

#include "igmp_types.h"
#include "reconcile.h"

typedef struct igmp_snap_mem {
    uint32_t group;
    uint32_t subscriber;
    uint32_t ifindex;
    uint32_t ifgen;
    char pod_uid[IGMP_UID_LEN];
    int joined;
} igmp_snap_mem;

typedef struct igmp_peer {
    char name[IGMP_NODE_LEN];
    uint32_t ip;
    int active;
    int64_t ts_ms;
    int fresh;
} igmp_peer;

/* Atomic snapshot. members may be NULL when nmem is 0. */
int igmp_coord_write(const char *dir, const char *node, uint32_t node_ip, int active,
                     int64_t now_ms, const igmp_snap_mem *members, int nmem);

int igmp_coord_peers(const char *dir, const char *self_node, int64_t now_ms,
                     int64_t max_age_ms, igmp_peer *out, int cap);

int igmp_coord_load_remote(const char *dir, const char *self_node, int64_t now_ms,
                           int64_t max_age_ms, igmp_remote_sub *out, int cap,
                           uint32_t *stale_ips, int stale_cap, int *nstale);

int igmp_coord_load_self(const char *dir, const char *self_node, igmp_snap_mem *out, int cap);

int igmp_coord_parse(const char *text, igmp_peer *peer, igmp_snap_mem *mem, int mem_cap,
                     int *nmem);

#endif
