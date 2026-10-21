#ifndef IGMPSHARK_KUBE_PARSE_H
#define IGMPSHARK_KUBE_PARSE_H

#include "kube.h"

/* PodList items from the apiserver omit kind and apiVersion. Walk the items
 * array itself. Calls cb once per pod. cb returning non-zero stops the walk.
 * Returns the number of pods delivered. */
int kube_parse_pod_list(const char *json, int (*cb)(void *user, const kube_event *ev), void *user);

/* One watch line: {"type":"ADDED|MODIFIED|DELETED","object":{...}}.
 * Returns 1 when ev was filled. */
int kube_parse_watch_line(const char *line, kube_event *ev);

/* Each ConfigMap data.snapshot string in a list body. The value starts after
 * the colon; pointing the string parser at the colon skips every snapshot.
 * cb returning non-zero stops the walk. Returns how many values were delivered. */
int kube_each_snapshot(const char *json, int (*cb)(void *user, const char *b64), void *user);

/* NodeList (or one Node). ip is network.cilium.io/ipv4-cilium-host, or the
 * io.cilium.network.ipv4-cilium-host alias when the canonical key is absent.
 * The health annotation is ignored. Returns how many nodes were stored. */
int kube_parse_cilium_host_ips(const char *json, kube_node_ip *out, int cap);

#endif
