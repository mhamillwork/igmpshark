#ifndef IGMPSHARK_QUERY_H
#define IGMPSHARK_QUERY_H

#include <stddef.h>
#include <stdint.h>

/* IGMPv2 or v3 query payload, checksum included. Returns length or -1. */
int igmp_query_build(uint8_t *out, size_t cap, uint32_t group_host, int max_resp_ms, int version);

/* Raw IPPROTO_IGMP send. src_host is the IP source when non-zero so a capture
 * of our own query can be ignored. ifname "any" is not a device: the query is
 * injected on each up lxc* interface and on cilium_host, which is how a pod
 * receives it before it is a multicast subscriber. A real ifname sends once
 * on that device. NULL uses the routing table. Returns 0 if at least one
 * send succeeded, otherwise -1. */
int igmp_query_send(const char *ifname, uint32_t src_host, uint32_t group_host, int max_resp_ms,
                    int version);

#endif
