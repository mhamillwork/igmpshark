#ifndef IGMPSHARK_KUBE_H
#define IGMPSHARK_KUBE_H

#include <stdint.h>

typedef struct kube_client kube_client;

enum {
    KUBE_EV_API_DOWN = 1,
    KUBE_EV_API_UP = 2,
    KUBE_EV_BEGIN = 3,
    KUBE_EV_END = 4,
    KUBE_EV_UPSERT = 5,
    KUBE_EV_DELETE = 6
};

typedef struct kube_event {
    int kind;
    char uid[96];
    char name[64];
    char node[64];
    uint32_t ip;
    int restart;
    int deleting;
} kube_event;

int kube_client_start(kube_client **out);
void kube_client_stop(kube_client *k);
int kube_client_poll(kube_client *k, kube_event *ev);
uint64_t kube_client_drops(const kube_client *k);

/* Publish and fetch DaemonSet snapshots through labeled ConfigMaps.
 * text is the snapshot body. Returns 0 on success. */
int kube_publish_snapshot(const char *node, const char *text);
int kube_fetch_snapshots(const char *dir);

#endif
