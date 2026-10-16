#ifndef IGMPSHARK_RECONCILE_H
#define IGMPSHARK_RECONCILE_H

#include "igmp_types.h"

enum {
    IGMP_OP_GROUP_ADD = 1,
    IGMP_OP_GROUP_DEL = 2,
    IGMP_OP_REMOTE_ADD = 3,
    IGMP_OP_REMOTE_DEL = 4,
    IGMP_OP_LOCAL_DEL = 5
};

typedef struct igmp_op {
    int op;
    uint32_t group;
    uint32_t addr;
} igmp_op;

typedef struct igmp_actual {
    uint32_t group;
    uint32_t addr;
    int remote; /* 1 = CiliumNode internal IP, 0 = local pod source */
    int managed;
} igmp_actual;

typedef struct igmp_local_sub {
    uint32_t group;
    uint32_t subscriber;
    int joined;
} igmp_local_sub;

typedef struct igmp_remote_sub {
    uint32_t node_ip;
    uint32_t group;
    int joined_count;
} igmp_remote_sub;

/* allow_delete=0 is startup grace: additions only.
 * allow_remote_delete=0 keeps every remote-node row (coord outage).
 * keep_remote lists node IPs whose snapshots are stale: their existing
 * remote rows are preserved and the group is not deleted out from under them.
 * self_node_ip is never installed as a remote subscriber.
 * addr 0 is a group-present marker, not a subscriber.
 * Unmanaged actual rows are left in place. Group delete is not emitted
 * while any unmanaged or preserved subscriber remains, because Cilium's
 * group delete wipes the inner map.
 * Local subscriber additions are not emitted: Cilium's datapath inserts
 * those from IGMP, and the CLI insert marks the entry remote. */
int igmp_reconcile(const igmp_local_sub *local, int nlocal,
                   const igmp_remote_sub *remote, int nremote,
                   const igmp_actual *actual, int nactual,
                   uint32_t self_node_ip, int allow_delete, int allow_remote_delete,
                   const uint32_t *keep_remote, int nkeep,
                   igmp_op *out, int cap);

#endif
