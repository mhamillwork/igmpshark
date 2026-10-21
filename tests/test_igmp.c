#include "engine.h"
#include "reconcile.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", msg);
        failures++;
    }
}

static void put16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void finish_igmp(uint8_t *igmp, size_t len) {
    igmp[2] = 0;
    igmp[3] = 0;
    uint16_t c = igmp_checksum(igmp, len);
    igmp[2] = (uint8_t)(c >> 8);
    igmp[3] = (uint8_t)c;
}

/* Ethernet + IPv4 + payload. src/dst host order. */
static size_t build_frame(uint8_t *out, uint32_t src, uint32_t dst,
                          const uint8_t *igmp, size_t igmp_len) {
    memset(out, 0, 14);
    out[12] = 0x08;
    out[13] = 0x00;
    uint8_t *ip = out + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put16(ip + 2, (unsigned)(20 + igmp_len));
    ip[8] = 1;
    ip[9] = 2;
    put32(ip + 12, src);
    put32(ip + 16, dst);
    uint16_t c = igmp_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    memcpy(ip + 20, igmp, igmp_len);
    return 14 + 20 + igmp_len;
}

static size_t v2_report(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x16;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group, igmp, 8);
}

static size_t v2_leave(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x17;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group, igmp, 8);
}

static size_t v1_report(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x12;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group, igmp, 8);
}

static size_t v2_query(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x11;
    igmp[1] = 100;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group ? group : 0xe0000001u, igmp, 8);
}

static size_t v3_report(uint8_t *frame, uint32_t src, const igmp_record *recs, int nrec) {
    uint8_t igmp[512];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x22;
    put16(igmp + 6, (unsigned)nrec);
    size_t off = 8;
    for (int r = 0; r < nrec; r++) {
        igmp[off] = (uint8_t)recs[r].type;
        put16(igmp + off + 2, (unsigned)recs[r].n_sources);
        put32(igmp + off + 4, recs[r].group);
        for (int s = 0; s < recs[r].n_sources; s++)
            put32(igmp + off + 8 + (size_t)s * 4, recs[r].sources[s]);
        off += 8 + (size_t)recs[r].n_sources * 4;
    }
    finish_igmp(igmp, off);
    return build_frame(frame, src, 0xe0000016u, igmp, off);
}

static uint32_t ip4(const char *s) {
    uint32_t v = 0;
    igmp_ip_parse(s, &v);
    return v;
}

static igmp_engine E;
static uint8_t frame[512];

static void setup(int active) {
    igmp_config cfg;
    igmp_config_defaults(&cfg);
    cfg.query_interval_ms = 1000;
    cfg.query_response_ms = 100;
    cfg.robustness = 2;
    cfg.last_member_query_ms = 100;
    cfg.active_querier = active;
    cfg.self_ip = ip4("10.0.0.1");
    cfg.solicit_reports = 0;
    igmp_engine_init(&E, &cfg, 0);
}

static void test_parse_and_join(void) {
    setup(0);
    uint32_t g = ip4("239.1.1.1");
    uint32_t s = ip4("10.1.0.5");
    size_t n = v2_report(frame, s, g);
    igmp_message msg;
    expect(igmp_parse_ipv4(frame, n, IGMP_LINK_ETHERNET, &msg) == 0, "parse v2");
    expect(msg.checksum_ok && msg.kind == IGMP_KIND_V2_REPORT, "v2 kind");
    expect(msg.group == g && msg.src == s, "v2 addrs");
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 3, 1, 1000) == 0, "join");
    expect(igmp_engine_joined_count(&E) == 1, "one member");
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 3, 1, 1100) == 0, "refresh");
    expect(igmp_engine_joined_count(&E) == 1, "refresh does not duplicate");
    const igmp_member *m = NULL;
    expect(igmp_engine_find(&E, g, s, 3, &m) == 1 && m->joined, "found");
}

static void test_v1_and_leave(void) {
    setup(1);
    uint32_t g = ip4("239.2.2.2");
    uint32_t a = ip4("10.1.0.8");
    uint32_t b = ip4("10.1.0.9");
    size_t n = v1_report(frame, a, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 0);
    n = v2_report(frame, b, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 10);
    expect(igmp_engine_joined_count(&E) == 2, "two subscribers");
    n = v2_leave(frame, b, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 20);
    expect(igmp_engine_find(&E, g, a, 1, NULL) == 1, "a remains during lmq");
    expect(igmp_engine_find(&E, g, b, 1, NULL) == 1, "b pending lmq");
    igmp_engine_tick(&E, 20 + 100);
    igmp_engine_tick(&E, 20 + 200);
    expect(igmp_engine_find(&E, g, b, 1, NULL) == 0, "b expired after lmq");
    expect(igmp_engine_find(&E, g, a, 1, NULL) == 1, "a preserved");
}

static void test_leave_on_other_ifindex(void) {
    setup(0);
    uint32_t g = ip4("239.2.9.9");
    uint32_t s = ip4("10.42.7.178");
    size_t n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 5, 1, 0);
    n = v2_leave(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 9, 1, 20);
    const igmp_member *m = NULL;
    expect(igmp_engine_find(&E, g, s, 5, &m) == 1 && m && m->lmq_left > 0,
           "leave on another interface starts last-member wait");
    setup(0);
    n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 5, 1, 0);
    igmp_record rec;
    memset(&rec, 0, sizeof rec);
    rec.type = IGMP_REC_TO_INCLUDE;
    rec.group = g;
    n = v3_report(frame, s, &rec, 1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 8, 1, 30);
    m = NULL;
    expect(igmp_engine_find(&E, g, s, 5, &m) == 1 && m && m->lmq_left > 0,
           "to_in on another interface starts last-member wait");
}

static void test_immediate_leave_single(void) {
    setup(0);
    E.cfg.immediate_leave = 1;
    uint32_t g = ip4("239.3.3.3");
    uint32_t s = ip4("10.2.0.2");
    size_t n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 7, 1, 0);
    n = v2_leave(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 7, 1, 5);
    expect(igmp_engine_joined_count(&E) == 0, "immediate leave");
}

static void test_shared_suppression(void) {
    setup(1);
    uint32_t g = ip4("239.4.4.4");
    uint32_t a = ip4("10.3.0.1");
    uint32_t b = ip4("10.3.0.2");
    size_t n = v2_report(frame, a, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 4, 1, 0);
    n = v2_report(frame, b, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 4, 1, 10);
    /* Only A refreshes; B is suppressed but shares the attachment. */
    n = v2_report(frame, a, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 4, 1, 500);
    igmp_engine_tick(&E, 1500);
    expect(igmp_engine_find(&E, g, b, 4, NULL) == 1, "suppressed subscriber kept");
    expect(igmp_engine_find(&E, g, a, 4, NULL) == 1, "reporter kept");
}

static void test_no_expire_without_querier(void) {
    setup(0);
    uint32_t g = ip4("239.5.5.5");
    uint32_t s = ip4("10.4.0.1");
    size_t n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 0);
    igmp_engine_tick(&E, 1000000);
    expect(igmp_engine_joined_count(&E) == 1, "no querier keeps member");
    expect(E.querier_degraded == 1, "degraded without querier");
    n = v2_query(frame, ip4("10.0.0.9"), 0);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 1000);
    expect(E.querier_degraded == 0, "query clears degraded");
    expect(igmp_engine_joined_count(&E) == 1, "query does not drop quiet member");
    igmp_engine_tick(&E, 2500);
    expect(igmp_engine_joined_count(&E) == 0, "expires after solicited silence");
}

static void test_v3_records(void) {
    setup(1);
    uint32_t g = ip4("239.6.6.6");
    uint32_t s = ip4("10.5.0.5");
    uint32_t src1 = ip4("192.0.2.10");
    uint32_t src2 = ip4("192.0.2.11");
    igmp_record recs[2];
    memset(recs, 0, sizeof recs);
    recs[0].type = IGMP_REC_TO_EXCLUDE;
    recs[0].group = g;
    recs[1].type = IGMP_REC_IS_INCLUDE;
    recs[1].group = ip4("239.6.6.7");
    recs[1].n_sources = 1;
    recs[1].sources[0] = src1;
    size_t n = v3_report(frame, s, recs, 2);
    igmp_message msg;
    expect(igmp_parse_ipv4(frame, n, IGMP_LINK_ETHERNET, &msg) == 0, "parse v3");
    expect(msg.n_records == 2, "two records");
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 2, 1, 0);
    const igmp_member *m = NULL;
    expect(igmp_engine_find(&E, g, s, 2, &m) == 1 && m->filter_mode == IGMP_FILTER_EXCLUDE, "exclude");
    expect(igmp_engine_find(&E, ip4("239.6.6.7"), s, 2, &m) == 1 && m->n_sources == 1, "include");
    memset(recs, 0, sizeof recs);
    recs[0].type = IGMP_REC_ALLOW;
    recs[0].group = ip4("239.6.6.7");
    recs[0].n_sources = 1;
    recs[0].sources[0] = src2;
    n = v3_report(frame, s, recs, 1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 2, 1, 10);
    expect(igmp_engine_find(&E, ip4("239.6.6.7"), s, 2, &m) == 1 && m->n_sources == 2, "allow adds source");
    memset(recs, 0, sizeof recs);
    recs[0].type = IGMP_REC_BLOCK;
    recs[0].group = ip4("239.6.6.7");
    recs[0].n_sources = 1;
    recs[0].sources[0] = src1;
    n = v3_report(frame, s, recs, 1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 2, 1, 20);
    expect(igmp_engine_find(&E, ip4("239.6.6.7"), s, 2, &m) == 1 && m->n_sources == 1, "block removes source");
    memset(recs, 0, sizeof recs);
    recs[0].type = IGMP_REC_TO_INCLUDE;
    recs[0].group = g;
    recs[0].n_sources = 0;
    n = v3_report(frame, s, recs, 1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 2, 1, 30);
    igmp_engine_tick(&E, 30 + 100);
    igmp_engine_tick(&E, 30 + 200);
    expect(igmp_engine_find(&E, g, s, 2, NULL) == 0, "empty include leaves group");
    expect(igmp_engine_find(&E, ip4("239.6.6.7"), s, 2, NULL) == 1, "other group remains");
}

static void test_malformed_and_dedup(void) {
    setup(0);
    uint8_t bad[32];
    memset(bad, 0, sizeof bad);
    expect(igmp_engine_on_frame(&E, bad, sizeof bad, IGMP_LINK_ETHERNET, 1, 1, 0) == -1, "malformed");
    expect(E.malformed == 1, "malformed counted");
    uint32_t g = ip4("239.8.8.8");
    size_t n = v2_report(frame, ip4("10.8.0.1"), g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 100);
    int before = igmp_engine_joined_count(&E);
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 9, 1, 120) == 1, "dup iface");
    expect(igmp_engine_joined_count(&E) == before, "dedup no extra member");
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 200) == 0, "later report accepted");
    n = v2_report(frame, ip4("10.8.0.1"), ip4("224.0.0.1"));
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 300) == -1, "link local ignored");
}

static void test_identity_cleanup(void) {
    setup(0);
    uint32_t g1 = ip4("239.9.1.1");
    uint32_t g2 = ip4("239.9.1.2");
    uint32_t a = ip4("10.9.0.1");
    uint32_t b = ip4("10.9.0.2");
    size_t n = v2_report(frame, a, g1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 0);
    n = v2_report(frame, a, g2);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 1);
    n = v2_report(frame, b, g1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 2, 1, 2);
    igmp_engine_bind_pod(&E, a, "pod-a", "node-1");
    igmp_engine_bind_pod(&E, b, "pod-b", "node-1");
    expect(igmp_engine_pod_gone(&E, "pod-a", 50) == 2, "pod-a both groups");
    expect(igmp_engine_find(&E, g1, b, 2, NULL) == 1, "pod-b kept");
    n = v2_report(frame, a, g1);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 60);
    igmp_engine_bind_pod(&E, a, "pod-a2", "node-1");
    igmp_engine_pod_gone(&E, "pod-a", 70);
    expect(igmp_engine_find(&E, g1, a, 1, NULL) == 1, "replacement uid kept");
    expect(igmp_engine_retire_ifgen(&E, 2, 1) == 1, "old ifgen retired");
    expect(igmp_engine_find(&E, g1, b, 2, NULL) == 0, "stale ifindex gone");
    expect(igmp_engine_find(&E, g1, a, 1, NULL) == 1, "other iface kept");
}

static void test_solicit_without_querier(void) {
    setup(0);
    E.cfg.solicit_reports = 1;
    expect(E.we_are_querier == 0, "passive node is not querier");
    expect(E.querier_degraded == 1, "passive starts degraded");
    uint32_t g = ip4("239.8.8.8");
    uint32_t s = ip4("10.8.0.5");
    size_t n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 3, 1, 1000);
    igmp_query_out qs[8];
    int qn = 0;
    igmp_engine_take_queries(&E, qs, &qn, 8);
    expect(qn == 0 && E.queries_sent == 0, "join does not solicit before the group exists");
    expect(igmp_engine_solicit(&E, g, 3, 2) == 1, "solicit queues without being querier");
    expect(igmp_engine_solicit(&E, g, 3, 2) == 0, "duplicate group is one query");
    expect(E.queries_sent == 1, "one query counted");
    igmp_engine_take_queries(&E, qs, &qn, 8);
    expect(qn == 1 && qs[0].group == g && qs[0].version == 2, "group query is queued");
    n = v2_query(frame, E.cfg.self_ip, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 3, 1, 1100);
    expect(E.querier_degraded == 1 && E.queries_seen == 0, "own query is not a foreign querier");
    expect(igmp_engine_joined_count(&E) == 1, "own query keeps the member");
    n = v2_query(frame, ip4("10.0.0.9"), 0);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 3, 1, 1200);
    expect(E.querier_degraded == 0 && E.queries_seen == 1, "foreign query still arms expiry");
    int filled = 0;
    for (int i = 0; i < 32; i++)
        if (igmp_engine_solicit(&E, g + 1 + (uint32_t)i, 0, 2) == 1)
            filled++;
    expect(filled == 32, "queue accepts 32 group queries");
    expect(igmp_engine_solicit(&E, g + 100, 0, 2) == -1, "full queue is reported");
}

static void test_querier_election(void) {
    setup(1);
    expect(E.we_are_querier == 1, "starts as querier when active");
    size_t n = v2_query(frame, ip4("10.0.0.9"), 0);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 10);
    expect(E.we_are_querier == 1, "higher querier loses");
    n = v2_query(frame, ip4("10.0.0.0"), 0);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 20);
    expect(E.we_are_querier == 0, "lower querier wins");
    n = v2_query(frame, ip4("10.0.0.9"), 0);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 30);
    expect(E.we_are_querier == 0, "higher query does not steal from lower querier");
    igmp_engine_tick(&E, 20 + igmp_other_querier_ms(&E.cfg) + 1);
    expect(E.we_are_querier == 1, "querier timeout elects us");
}

static int count_op(const igmp_op *ops, int n, int op) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (ops[i].op == op)
            c++;
    return c;
}

static void test_reconcile(void) {
    igmp_local_sub local[4];
    igmp_remote_sub remote[4];
    igmp_actual actual[8];
    igmp_op ops[16];
    memset(local, 0, sizeof local);
    memset(remote, 0, sizeof remote);
    memset(actual, 0, sizeof actual);
    uint32_t g = ip4("239.10.0.1");
    uint32_t self = ip4("10.244.0.1");
    uint32_t other = ip4("10.244.1.1");
    local[0].group = g;
    local[0].subscriber = ip4("10.1.1.5");
    local[0].joined = 1;
    local[1].group = g;
    local[1].subscriber = ip4("10.1.1.6");
    local[1].joined = 1;
    remote[0].node_ip = other;
    remote[0].group = g;
    remote[0].joined_count = 2;
    int n = igmp_reconcile(local, 2, remote, 1, actual, 0, self, 1, 1, NULL, 0, ops, 16);
    expect(n > 0 && count_op(ops, n, IGMP_OP_GROUP_ADD) == 1, "group add once");
    expect(count_op(ops, n, IGMP_OP_REMOTE_ADD) == 1, "remote add");
    expect(count_op(ops, n, IGMP_OP_LOCAL_DEL) == 0, "no local add via cli");
    actual[0].group = g;
    actual[0].addr = other;
    actual[0].remote = 1;
    actual[0].managed = 1;
    actual[1].group = g;
    actual[1].addr = ip4("10.1.1.5");
    actual[1].remote = 0;
    actual[1].managed = 1;
    actual[2].group = g;
    actual[2].addr = ip4("10.1.1.6");
    actual[2].remote = 0;
    actual[2].managed = 1;
    actual[3].group = g;
    actual[3].addr = ip4("10.9.9.9");
    actual[3].remote = 1;
    actual[3].managed = 0;
    local[1].joined = 0;
    remote[0].joined_count = 1;
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 0, 0, NULL, 0, ops, 16);
    expect(count_op(ops, n, IGMP_OP_LOCAL_DEL) == 0, "grace skips deletes");
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 1, 1, NULL, 0, ops, 16);
    expect(count_op(ops, n, IGMP_OP_LOCAL_DEL) == 1, "stale local deleted");
    expect(count_op(ops, n, IGMP_OP_REMOTE_DEL) == 0, "other node still subscribed");
    int saw_unmanaged = 0;
    for (int i = 0; i < n; i++)
        if (ops[i].addr == ip4("10.9.9.9"))
            saw_unmanaged = 1;
    expect(!saw_unmanaged, "unmanaged preserved");
    local[0].joined = 0;
    remote[0].joined_count = 0;
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 1, 1, NULL, 0, ops, 16);
    expect(count_op(ops, n, IGMP_OP_REMOTE_DEL) == 1, "remote removed when count hits 0");
    expect(count_op(ops, n, IGMP_OP_GROUP_DEL) == 0, "unmanaged subscriber blocks group delete");
    actual[3].managed = 1;
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 1, 1, NULL, 0, ops, 16);
    expect(count_op(ops, n, IGMP_OP_GROUP_DEL) == 1, "empty managed group removed");
    uint32_t hold = other;
    actual[3].managed = 0;
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 1, 1, &hold, 1, ops, 16);
    expect(count_op(ops, n, IGMP_OP_REMOTE_DEL) == 0, "stale node remote held");
    n = igmp_reconcile(local, 2, remote, 1, actual, 4, self, 1, 0, NULL, 0, ops, 16);
    expect(count_op(ops, n, IGMP_OP_REMOTE_DEL) == 0, "coord outage skips remote delete");
    expect(count_op(ops, n, IGMP_OP_LOCAL_DEL) >= 1, "local delete still planned");
}

static void test_lmq_response_and_churn(void) {
    setup(1);
    uint32_t g = ip4("239.12.0.1");
    uint32_t s = ip4("10.12.0.1");
    size_t n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 0);
    n = v2_leave(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 10);
    n = v2_report(frame, s, g);
    igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 80);
    igmp_engine_tick(&E, 80 + 100);
    igmp_engine_tick(&E, 80 + 200);
    expect(igmp_engine_find(&E, g, s, 1, NULL) == 1, "report cancels last-member expiry");
    E.cfg.immediate_leave = 1;
    for (int i = 0; i < 1000; i++) {
        uint32_t sub = 0x0a200000u | (uint32_t)((i % 200) + 1);
        n = v2_report(frame, sub, g);
        igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, (uint32_t)(i + 2), 1, 1000 + i);
        n = v2_leave(frame, sub, g);
        igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, (uint32_t)(i + 2), 1, 1000 + i);
    }
    expect(igmp_engine_joined_count(&E) == 1, "churn removed temporary subscribers");
    expect(E.n_used == 1, "churn does not leak slots");
}

static void test_limits_and_sll(void) {
    setup(0);
    E.cfg.max_members = 1;
    uint32_t g = ip4("239.11.0.1");
    size_t n = v2_report(frame, ip4("10.11.0.1"), g);
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 0) == 0, "first fits");
    n = v2_report(frame, ip4("10.11.0.2"), g);
    expect(igmp_engine_on_frame(&E, frame, n, IGMP_LINK_ETHERNET, 1, 1, 10) == -1, "limit");
    expect(E.limit_drops >= 1, "limit counted");
    uint8_t sll[128];
    memset(sll, 0, sizeof sll);
    n = v2_report(frame, ip4("10.11.0.3"), ip4("239.11.0.2"));
    /* Rebuild as LINUX_SLL: 16 byte header, protocol at 14. */
    size_t ip_off = 14;
    size_t total = n - ip_off;
    memset(sll, 0, 16);
    sll[14] = 0x08;
    sll[15] = 0x00;
    memcpy(sll + 16, frame + ip_off, total);
    igmp_message msg;
    expect(igmp_parse_ipv4(sll, 16 + total, IGMP_LINK_SLL, &msg) == 0, "sll parse");
}

static void test_bulk_leave_without_querier(void) {
    setup(0);
    enum { N = 40 };
    igmp_record recs[N];
    uint8_t big[1024];
    memset(recs, 0, sizeof recs);
    uint32_t base = ip4("239.20.0.1");
    uint32_t src = ip4("10.20.0.8");
    for (int i = 0; i < N; i++) {
        recs[i].type = IGMP_REC_TO_EXCLUDE;
        recs[i].group = base + (uint32_t)i;
    }
    size_t n = v3_report(big, src, recs, N);
    igmp_message msg;
    expect(igmp_parse_ipv4(big, n, IGMP_LINK_ETHERNET, &msg) == 0 && msg.n_records == N &&
               !msg.too_many_records,
           "one report keeps every group record");
    igmp_engine_on_frame(&E, big, n, IGMP_LINK_ETHERNET, 1, 1, 0);
    expect(igmp_engine_joined_count(&E) == N, "bulk join");
    for (int i = 0; i < N; i++) {
        recs[i].type = IGMP_REC_TO_INCLUDE;
        recs[i].n_sources = 0;
    }
    n = v3_report(big, src, recs, N);
    igmp_engine_on_frame(&E, big, n, IGMP_LINK_ETHERNET, 1, 1, 50);
    expect(igmp_engine_joined_count(&E) == N, "leaves are armed, not dropped");
    igmp_engine_tick(&E, 150);
    igmp_engine_tick(&E, 250);
    expect(igmp_engine_joined_count(&E) == 0, "every leave finishes without a querier");
}

int main(void) {
    test_parse_and_join();
    test_v1_and_leave();
    test_leave_on_other_ifindex();
    test_immediate_leave_single();
    test_shared_suppression();
    test_no_expire_without_querier();
    test_v3_records();
    test_bulk_leave_without_querier();
    test_malformed_and_dedup();
    test_identity_cleanup();
    test_solicit_without_querier();
    test_querier_election();
    test_reconcile();
    test_lmq_response_and_churn();
    test_limits_and_sll();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
