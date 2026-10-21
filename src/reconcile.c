#include "reconcile.h"

static int emit(igmp_op *out, int *n, int cap, int op, uint32_t group, uint32_t addr) {
    if (*n >= cap)
        return -1;
    out[*n].op = op;
    out[*n].group = group;
    out[*n].addr = addr;
    (*n)++;
    return 0;
}

static int actual_has(const igmp_actual *actual, int n, uint32_t group, uint32_t addr, int remote) {
    for (int i = 0; i < n; i++)
        if (actual[i].group == group && actual[i].addr == addr && actual[i].remote == remote)
            return 1;
    return 0;
}

static int local_joined(const igmp_local_sub *local, int n, uint32_t group, uint32_t addr) {
    for (int i = 0; i < n; i++)
        if (local[i].joined && local[i].group == group && local[i].subscriber == addr)
            return 1;
    return 0;
}

static int group_wanted(const igmp_local_sub *local, int nlocal,
                        const igmp_remote_sub *remote, int nremote, uint32_t group) {
    for (int i = 0; i < nlocal; i++)
        if (local[i].joined && local[i].group == group)
            return 1;
    for (int i = 0; i < nremote; i++)
        if (remote[i].joined_count > 0 && remote[i].group == group)
            return 1;
    return 0;
}

static int group_present(const igmp_actual *actual, int n, uint32_t group) {
    for (int i = 0; i < n; i++)
        if (actual[i].group == group)
            return 1;
    return 0;
}

static int kept_remote(const uint32_t *keep, int nkeep, uint32_t ip) {
    for (int i = 0; i < nkeep; i++)
        if (keep[i] == ip)
            return 1;
    return 0;
}

static int group_blocked(const igmp_actual *actual, int n, uint32_t group,
                         int allow_remote_delete, const uint32_t *keep, int nkeep) {
    for (int i = 0; i < n; i++) {
        if (actual[i].group != group)
            continue;
        /* A group-list marker has no subscriber. It must not keep the group
         * alive after every real subscriber is gone. */
        if (actual[i].addr == 0)
            continue;
        if (!actual[i].managed)
            return 1;
        if (actual[i].remote && actual[i].addr != 0 &&
            (!allow_remote_delete || kept_remote(keep, nkeep, actual[i].addr)))
            return 1;
    }
    return 0;
}

int igmp_reconcile(const igmp_local_sub *local, int nlocal,
                   const igmp_remote_sub *remote, int nremote,
                   const igmp_actual *actual, int nactual,
                   uint32_t self_node_ip, int allow_delete, int allow_remote_delete,
                   const uint32_t *keep_remote, int nkeep,
                   igmp_op *out, int cap) {
    int n = 0;
    for (int i = 0; i < nlocal; i++) {
        if (!local[i].joined)
            continue;
        if (!group_present(actual, nactual, local[i].group)) {
            int already = 0;
            for (int k = 0; k < n; k++)
                if (out[k].op == IGMP_OP_GROUP_ADD && out[k].group == local[i].group)
                    already = 1;
            if (!already && emit(out, &n, cap, IGMP_OP_GROUP_ADD, local[i].group, 0) != 0)
                return -1;
        }
    }
    for (int i = 0; i < nremote; i++) {
        if (remote[i].joined_count <= 0 || remote[i].node_ip == 0)
            continue;
        if (remote[i].node_ip == self_node_ip)
            continue;
        if (!group_present(actual, nactual, remote[i].group)) {
            int already = 0;
            for (int k = 0; k < n; k++)
                if (out[k].op == IGMP_OP_GROUP_ADD && out[k].group == remote[i].group)
                    already = 1;
            if (!already && emit(out, &n, cap, IGMP_OP_GROUP_ADD, remote[i].group, 0) != 0)
                return -1;
        }
        if (!actual_has(actual, nactual, remote[i].group, remote[i].node_ip, 1)) {
            if (emit(out, &n, cap, IGMP_OP_REMOTE_ADD, remote[i].group, remote[i].node_ip) != 0)
                return -1;
        }
    }
    if (!allow_delete)
        return n;
    for (int i = 0; i < nactual; i++) {
        if (!actual[i].managed)
            continue;
        if (actual[i].remote) {
            if (actual[i].addr == 0)
                continue;
            if (!allow_remote_delete || kept_remote(keep_remote, nkeep, actual[i].addr))
                continue;
            int keep = 0;
            for (int r = 0; r < nremote; r++) {
                if (remote[r].group == actual[i].group && remote[r].node_ip == actual[i].addr &&
                    remote[r].joined_count > 0 && remote[r].node_ip != self_node_ip)
                    keep = 1;
            }
            if (!keep && emit(out, &n, cap, IGMP_OP_REMOTE_DEL, actual[i].group, actual[i].addr) != 0)
                return -1;
        } else if (!local_joined(local, nlocal, actual[i].group, actual[i].addr)) {
            if (emit(out, &n, cap, IGMP_OP_LOCAL_DEL, actual[i].group, actual[i].addr) != 0)
                return -1;
        }
    }
    for (int i = 0; i < nactual; i++) {
        if (!actual[i].managed)
            continue;
        if (group_wanted(local, nlocal, remote, nremote, actual[i].group))
            continue;
        if (group_blocked(actual, nactual, actual[i].group, allow_remote_delete, keep_remote, nkeep))
            continue;
        int already = 0;
        for (int k = 0; k < n; k++)
            if (out[k].op == IGMP_OP_GROUP_DEL && out[k].group == actual[i].group)
                already = 1;
        if (!already && emit(out, &n, cap, IGMP_OP_GROUP_DEL, actual[i].group, 0) != 0)
            return -1;
    }
    return n;
}
