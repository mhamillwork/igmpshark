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

/* Overlay address for a node, from Cilium rather than from the snapshot.
 * name may be the Kubernetes name or cluster/name. */
typedef struct igmp_ip_rewrite {
    char name[IGMP_NODE_LEN];
    uint32_t ip;
} igmp_ip_rewrite;

/* Realtime milliseconds. Snapshot NODE timestamps use this so another node
 * can age them. Protocol timers stay on the monotonic clock. */
int64_t igmp_coord_now_ms(void);

/* Create the snapshot directory. The state volume is the parent; this
 * subdirectory is not created by the mount. */
int igmp_coord_ensure(const char *dir);

/* Atomic snapshot. members may be NULL when nmem is 0. */
int igmp_coord_write(const char *dir, const char *node, uint32_t node_ip, int active,
                     int64_t now_ms, const igmp_snap_mem *members, int nmem);

int igmp_coord_peers(const char *dir, const char *self_node, int64_t now_ms,
                     int64_t max_age_ms, igmp_peer *out, int cap);

/* rewrite replaces a peer's published address by node name. When nrewrite is
 * greater than zero, a peer that is not in the table is skipped: the address
 * in its snapshot is not installed. nrewrite zero keeps the snapshot address. */
int igmp_coord_load_remote(const char *dir, const char *self_node, int64_t now_ms,
                           int64_t max_age_ms, igmp_remote_sub *out, int cap,
                           uint32_t *stale_ips, int stale_cap, int *nstale,
                           const igmp_ip_rewrite *rewrite, int nrewrite);

int igmp_coord_load_self(const char *dir, const char *self_node, igmp_snap_mem *out, int cap);

int igmp_coord_parse(const char *text, igmp_peer *peer, igmp_snap_mem *mem, int mem_cap,
                     int *nmem);

#endif
