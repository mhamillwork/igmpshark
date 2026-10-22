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

/* node_name limits the list and watch to spec.nodeName. Empty lists every pod. */
int kube_client_start(kube_client **out, const char *node_name);
void kube_client_stop(kube_client *k);
int kube_client_poll(kube_client *k, kube_event *ev);
uint64_t kube_client_drops(const kube_client *k);

/* Publish and fetch DaemonSet snapshots through labeled ConfigMaps.
 * text is the snapshot body. Returns 0 on success. */
int kube_publish_snapshot(const char *node, const char *text);
int kube_fetch_snapshots(const char *dir);
/* HTTP status from the last publish or fetch. 0 when the call did not run. */
long kube_last_status(void);

/* Kubernetes node metadata.name and the Cilium router annotation
 * network.cilium.io/ipv4-cilium-host. That address is CiliumInternalIP. */
typedef struct kube_node_ip {
    char name[64];
    uint32_t ip;
} kube_node_ip;

/* GET /api/v1/nodes and parse the router annotation. Returns the number of
 * nodes that have one, or -1 when the apiserver cannot be read. Does not
 * use the health annotation. */
int kube_load_cilium_host_ips(kube_node_ip *out, int cap);

#endif
