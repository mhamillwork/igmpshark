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

#endif
