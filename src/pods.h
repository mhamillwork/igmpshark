#ifndef IGMPSHARK_PODS_H
#define IGMPSHARK_PODS_H

#include "igmp_types.h"

#define IGMP_POD_MAX 2048

typedef struct igmp_pod {
    int used;
    char uid[IGMP_UID_LEN];
    char name[64];
    char node[IGMP_NODE_LEN];
    uint32_t ip;
    int restart_count;
    int seen_gen;
    int deleting;
} igmp_pod;

typedef struct igmp_pods {
    igmp_pod items[IGMP_POD_MAX];
    int list_gen;
    int api_healthy;
    int full_list_ok;
} igmp_pods;

void igmp_pods_init(igmp_pods *p);
int igmp_pods_upsert(igmp_pods *p, const char *uid, const char *name, const char *node,
                     uint32_t ip, int restart_count, int deleting, int from_list);
int igmp_pods_delete(igmp_pods *p, const char *uid);
void igmp_pods_begin_list(igmp_pods *p);
/* Calls cb for each pod absent from the completed list. Returns the count,
 * or -1 when the API is unhealthy (no pods are removed). */
int igmp_pods_end_list(igmp_pods *p, void (*cb)(void *user, const char *uid), void *user);
const igmp_pod *igmp_pods_by_uid(const igmp_pods *p, const char *uid);
const igmp_pod *igmp_pods_by_ip(const igmp_pods *p, uint32_t ip);

#endif
