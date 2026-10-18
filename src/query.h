#ifndef IGMPSHARK_QUERY_H
#define IGMPSHARK_QUERY_H

#include <stddef.h>
#include <stdint.h>

/* IGMPv2 or v3 query payload, checksum included. Returns length or -1. */
int igmp_query_build(uint8_t *out, size_t cap, uint32_t group_host, int max_resp_ms, int version);

/* Raw IPPROTO_IGMP send. ifname NULL uses the routing table. Returns 0 or -1. */
int igmp_query_send(const char *ifname, uint32_t group_host, int max_resp_ms, int version);

#endif
