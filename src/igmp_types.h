#ifndef IGMPSHARK_TYPES_H
#define IGMPSHARK_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define IGMP_MAX_SOURCES 16
#define IGMP_MAX_RECORDS 32
#define IGMP_UID_LEN 96
#define IGMP_NODE_LEN 64

enum {
    IGMP_FILTER_INCLUDE = 1,
    IGMP_FILTER_EXCLUDE = 2
};

enum {
    IGMP_KIND_QUERY = 1,
    IGMP_KIND_V1_REPORT = 2,
    IGMP_KIND_V2_REPORT = 3,
    IGMP_KIND_V2_LEAVE = 4,
    IGMP_KIND_V3_REPORT = 5
};

enum {
    IGMP_REC_IS_INCLUDE = 1,
    IGMP_REC_IS_EXCLUDE = 2,
    IGMP_REC_TO_INCLUDE = 3,
    IGMP_REC_TO_EXCLUDE = 4,
    IGMP_REC_ALLOW = 5,
    IGMP_REC_BLOCK = 6
};

typedef struct igmp_record {
    int type;
    uint32_t group; /* host order */
    int n_sources;
    uint32_t sources[IGMP_MAX_SOURCES];
    int truncated_sources;
} igmp_record;

typedef struct igmp_message {
    int ok;
    int malformed;
    int checksum_ok;
    int version; /* 1, 2, or 3; 0 if unknown */
    int kind;
    uint32_t src;          /* IPv4 source, host order */
    uint32_t group;        /* v1/v2/query group; 0 = general query */
    int max_resp_ms;
    int n_records;
    igmp_record records[IGMP_MAX_RECORDS];
    int too_many_records;
} igmp_message;

enum igmp_link {
    IGMP_LINK_ETHERNET = 1,
    IGMP_LINK_SLL = 2,
    IGMP_LINK_SLL2 = 3,
    IGMP_LINK_RAW = 4
};

int igmp_parse_ipv4(const uint8_t *frame, size_t len, int link, igmp_message *out);
uint16_t igmp_checksum(const uint8_t *data, size_t len);
int igmp_group_routable(uint32_t group_host);

char *igmp_ip_fmt(uint32_t host_order, char *buf, size_t buflen);
int igmp_ip_parse(const char *text, uint32_t *host_order);

#endif
