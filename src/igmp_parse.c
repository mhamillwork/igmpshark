#include "igmp_types.h"

#include <stdio.h>
#include <string.h>

uint16_t igmp_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    if (len & 1)
        sum += (uint32_t)data[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

int igmp_group_routable(uint32_t group_host) {
    /* 224.0.0.0/4, excluding 224.0.0.0/24 link-local control. */
    if ((group_host & 0xf0000000u) != 0xe0000000u)
        return 0;
    if ((group_host & 0xffffff00u) == 0xe0000000u)
        return 0;
    return 1;
}

char *igmp_ip_fmt(uint32_t host_order, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%u.%u.%u.%u",
             (host_order >> 24) & 255u, (host_order >> 16) & 255u,
             (host_order >> 8) & 255u, host_order & 255u);
    return buf;
}

int igmp_ip_parse(const char *text, uint32_t *host_order) {
    unsigned a, b, c, d;
    char tail;
    if (!text || sscanf(text, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
        return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return -1;
    *host_order = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int max_resp_ms(uint8_t code, int v3) {
    if (!v3 || code < 128)
        return (int)code * 100;
    int mant = code & 0x0f;
    int exp = (code >> 4) & 0x07;
    return ((mant | 0x10) << (exp + 3)) * 100;
}

static int find_igmp(const uint8_t *frame, size_t len, int link,
                     const uint8_t **igmp, size_t *igmp_len, uint32_t *src) {
    size_t l2 = 0;
    if (link == IGMP_LINK_ETHERNET) {
        if (len < 14)
            return -1;
        uint16_t eth = ((uint16_t)frame[12] << 8) | frame[13];
        l2 = 14;
        if (eth == 0x8100) {
            if (len < 18)
                return -1;
            eth = ((uint16_t)frame[16] << 8) | frame[17];
            l2 = 18;
        }
        if (eth != 0x0800)
            return -1;
    } else if (link == IGMP_LINK_SLL) {
        if (len < 16)
            return -1;
        uint16_t proto = ((uint16_t)frame[14] << 8) | frame[15];
        if (proto != 0x0800)
            return -1;
        l2 = 16;
    } else if (link == IGMP_LINK_SLL2) {
        if (len < 20)
            return -1;
        uint16_t proto = ((uint16_t)frame[0] << 8) | frame[1];
        if (proto != 0x0800)
            return -1;
        l2 = 20;
    } else if (link == IGMP_LINK_RAW) {
        l2 = 0;
    } else {
        return -1;
    }
    if (len < l2 + 20)
        return -1;
    const uint8_t *ip = frame + l2;
    unsigned ihl = (ip[0] & 0x0f) * 4u;
    unsigned ver = ip[0] >> 4;
    if (ver != 4 || ihl < 20 || len < l2 + ihl + 8)
        return -1;
    if (ip[9] != 2)
        return -1;
    *src = rd32(ip + 12);
    *igmp = ip + ihl;
    *igmp_len = len - l2 - ihl;
    return 0;
}

static int push_source(igmp_record *rec, uint32_t src) {
    if (rec->n_sources >= IGMP_MAX_SOURCES) {
        rec->truncated_sources = 1;
        return -1;
    }
    rec->sources[rec->n_sources++] = src;
    return 0;
}

int igmp_parse_ipv4(const uint8_t *frame, size_t len, int link, igmp_message *out) {
    const uint8_t *msg;
    size_t msg_len;
    memset(out, 0, sizeof *out);
    if (find_igmp(frame, len, link, &msg, &msg_len, &out->src) != 0) {
        out->malformed = 1;
        return -1;
    }
    if (msg_len < 8) {
        out->malformed = 1;
        return -1;
    }
    uint16_t sum = igmp_checksum(msg, msg_len);
    out->checksum_ok = (sum == 0 || sum == 0xffff);
    uint8_t type = msg[0];
    out->group = rd32(msg + 4);
    if (type == 0x12) {
        out->kind = IGMP_KIND_V1_REPORT;
        out->version = 1;
    } else if (type == 0x16) {
        out->kind = IGMP_KIND_V2_REPORT;
        out->version = 2;
    } else if (type == 0x17) {
        out->kind = IGMP_KIND_V2_LEAVE;
        out->version = 2;
    } else if (type == 0x11) {
        out->kind = IGMP_KIND_QUERY;
        out->version = msg_len == 8 ? (msg[1] == 0 ? 1 : 2) : 3;
        out->max_resp_ms = max_resp_ms(msg[1], out->version == 3);
        if (out->version == 3 && msg_len >= 12) {
            unsigned nsrc = ((unsigned)msg[10] << 8) | msg[11];
            if (msg_len < 12u + nsrc * 4u) {
                out->malformed = 1;
                return -1;
            }
        }
    } else if (type == 0x22) {
        out->kind = IGMP_KIND_V3_REPORT;
        out->version = 3;
        if (msg_len < 8) {
            out->malformed = 1;
            return -1;
        }
        unsigned nrec = ((unsigned)msg[6] << 8) | msg[7];
        size_t off = 8;
        for (unsigned r = 0; r < nrec; r++) {
            if (off + 8 > msg_len) {
                out->malformed = 1;
                return -1;
            }
            unsigned rec_type = msg[off];
            unsigned aux_words = msg[off + 1];
            unsigned nsrc = ((unsigned)msg[off + 2] << 8) | msg[off + 3];
            size_t need = 8u + nsrc * 4u + aux_words * 4u;
            if (off + need > msg_len) {
                out->malformed = 1;
                return -1;
            }
            if (out->n_records >= IGMP_MAX_RECORDS) {
                out->too_many_records = 1;
            } else {
                igmp_record *rec = &out->records[out->n_records++];
                rec->type = (int)rec_type;
                rec->group = rd32(msg + off + 4);
                for (unsigned s = 0; s < nsrc; s++)
                    push_source(rec, rd32(msg + off + 8 + s * 4));
            }
            off += need;
        }
    } else {
        out->malformed = 1;
        return -1;
    }
    out->ok = 1;
    return 0;
}
