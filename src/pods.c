#include "pods.h"

#include <stdio.h>
#include <string.h>

void igmp_pods_init(igmp_pods *p) {
    memset(p, 0, sizeof *p);
    p->api_healthy = 1;
}

static igmp_pod *find_uid(igmp_pods *p, const char *uid) {
    for (int i = 0; i < IGMP_POD_MAX; i++)
        if (p->items[i].used && strcmp(p->items[i].uid, uid) == 0)
            return &p->items[i];
    return NULL;
}

int igmp_pods_upsert(igmp_pods *p, const char *uid, const char *name, const char *node,
                     uint32_t ip, int restart_count, int deleting, int from_list) {
    if (!uid || !uid[0])
        return -1;
    igmp_pod *slot = find_uid(p, uid);
    if (!slot) {
        for (int i = 0; i < IGMP_POD_MAX; i++) {
            if (!p->items[i].used) {
                slot = &p->items[i];
                memset(slot, 0, sizeof *slot);
                slot->used = 1;
                break;
            }
        }
    }
    if (!slot)
        return -1;
    snprintf(slot->uid, sizeof slot->uid, "%s", uid);
    snprintf(slot->name, sizeof slot->name, "%s", name ? name : "");
    snprintf(slot->node, sizeof slot->node, "%s", node ? node : "");
    slot->ip = ip;
    slot->restart_count = restart_count;
    slot->deleting = deleting;
    if (from_list)
        slot->seen_gen = p->list_gen;
    return 0;
}

int igmp_pods_delete(igmp_pods *p, const char *uid) {
    igmp_pod *slot = uid ? find_uid(p, uid) : NULL;
    if (!slot)
        return 0;
    slot->used = 0;
    return 1;
}

void igmp_pods_begin_list(igmp_pods *p) {
    p->list_gen++;
    if (p->list_gen <= 0)
        p->list_gen = 1;
}

int igmp_pods_end_list(igmp_pods *p, void (*cb)(void *user, const char *uid), void *user) {
    if (!p->api_healthy)
        return -1;
    int n = 0;
    for (int i = 0; i < IGMP_POD_MAX; i++) {
        igmp_pod *slot = &p->items[i];
        if (!slot->used || slot->seen_gen == p->list_gen)
            continue;
        char uid[IGMP_UID_LEN];
        snprintf(uid, sizeof uid, "%s", slot->uid);
        slot->used = 0;
        n++;
        if (cb)
            cb(user, uid);
    }
    p->full_list_ok = 1;
    return n;
}

const igmp_pod *igmp_pods_by_uid(const igmp_pods *p, const char *uid) {
    for (int i = 0; i < IGMP_POD_MAX; i++)
        if (p->items[i].used && strcmp(p->items[i].uid, uid) == 0)
            return &p->items[i];
    return NULL;
}

const igmp_pod *igmp_pods_by_ip(const igmp_pods *p, uint32_t ip) {
    const igmp_pod *found = NULL;
    if (ip == 0)
        return NULL;
    for (int i = 0; i < IGMP_POD_MAX; i++) {
        const igmp_pod *slot = &p->items[i];
        if (slot->used && !slot->deleting && slot->ip == ip)
            found = slot;
    }
    return found;
}
