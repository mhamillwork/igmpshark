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

/* IGMPv3 report, one CHANGE_TO_EXCLUDE record, zero sources. Cilium 1.19
 * records a local subscriber from this record type. A query response
 * (MODE_IS_EXCLUDE) is ignored by that datapath. Returns 16 or -1. */
int igmp_v3_toex_build(uint8_t *out, size_t cap, uint32_t group_host);

/* 1 when text is a fib_trie whose Local section lists ip as its own
 * /32 host LOCAL leaf. A covering prefix, a neighbor's leaf, and a
 * Main-section /32 host UNICAST route do not match. */
int igmp_fib_trie_has_local(const char *text, uint32_t ip);

/* Path of a network namespace whose Local fib trie owns ip, such as
 * /proc/<pid>/ns/net. The host namespace is not searched. */
int igmp_netns_for_local_ip(uint32_t ip, char *out, size_t cap);

/* Fork, enter netns_path, send a TO_EX report sourced from src_host to
 * 224.0.0.22, and exit the child. The caller stays in its own netns. */
int igmp_v3_toex_send(const char *netns_path, uint32_t src_host, uint32_t group_host);

#endif
