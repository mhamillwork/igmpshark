#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "coord.h"
#include "kube_parse.h"
#include "query.h"
#include "runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", msg);
        failures++;
    }
}

static uint32_t ip4(const char *s) {
    uint32_t v = 0;
    igmp_ip_parse(s, &v);
    return v;
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
    igmp[2] = igmp[3] = 0;
    uint16_t c = igmp_checksum(igmp, len);
    igmp[2] = (uint8_t)(c >> 8);
    igmp[3] = (uint8_t)c;
}
static size_t build_frame(uint8_t *out, uint32_t src, uint32_t dst, const uint8_t *igmp, size_t n) {
    memset(out, 0, 14);
    out[12] = 0x08;
    out[13] = 0x00;
    uint8_t *ip = out + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put16(ip + 2, (unsigned)(20 + n));
    ip[8] = 1;
    ip[9] = 2;
    put32(ip + 12, src);
    put32(ip + 16, dst);
    uint16_t c = igmp_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    memcpy(ip + 20, igmp, n);
    return 14 + 20 + n;
}
static size_t v2_leave(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x17;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group, igmp, 8);
}
static size_t v2_report(uint8_t *frame, uint32_t src, uint32_t group) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x16;
    put32(igmp + 4, group);
    finish_igmp(igmp, 8);
    return build_frame(frame, src, group, igmp, 8);
}
static size_t v2_query(uint8_t *frame, uint32_t src) {
    uint8_t igmp[8];
    memset(igmp, 0, sizeof igmp);
    igmp[0] = 0x11;
    igmp[1] = 100;
    finish_igmp(igmp, 8);
    return build_frame(frame, src, 0xe0000001u, igmp, 8);
}

static char *tmpdir(void) {
    char *t = strdup("/tmp/igmpshark-XXXXXX");
    if (!mkdtemp(t)) {
        perror("mkdtemp");
        exit(1);
    }
    return t;
}

static igmp_runtime *make_rt(const char *dir, const char *node, const char *nip, int grace) {
    igmp_config cfg;
    igmp_config_defaults(&cfg);
    cfg.query_interval_ms = 1000;
    cfg.query_response_ms = 100;
    cfg.robustness = 2;
    cfg.last_member_query_ms = 100;
    cfg.startup_grace_ms = grace;
    cfg.solicit_reports = 0;
    igmp_runtime *rt = igmp_runtime_new(&cfg, 0);
    rt->log_json = 0;
    snprintf(rt->node_name, sizeof rt->node_name, "%s", node);
    snprintf(rt->coord_dir, sizeof rt->coord_dir, "%s", dir);
    rt->node_ip = ip4(nip);
    rt->eng->cfg.self_ip = rt->node_ip;
    return rt;
}

static void attach_file(igmp_runtime *rt, const char *path, int dry) {
    igmp_backend *b = calloc(1, sizeof *b);
    backend_file_open(b, path, dry);
    rt->backend = b;
    rt->dry_run = dry;
}

static int has_op(const igmp_runtime *rt, int op, uint32_t addr) {
    for (int i = 0; i < rt->last_op_count; i++)
        if (rt->last_ops[i].op == op && (addr == 0 || rt->last_ops[i].addr == addr))
            return 1;
    return 0;
}

static void test_dry_and_idempotent(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/state", dir);
    FILE *fp = fopen(state, "w");
    fputs("239.9.9.9 10.9.9.9 1 0\n", fp);
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    attach_file(rt, state, 1);
    uint8_t frame[128];
    uint32_t g = ip4("239.1.1.1");
    size_t n = v2_report(frame, ip4("10.1.0.5"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 2, 1);
    int ops = igmp_runtime_reconcile(rt);
    expect(ops >= 1 && has_op(rt, IGMP_OP_GROUP_ADD, 0), "dry-run plans group add");
    expect(rt->mutations == 0, "dry-run mutations stay zero");
    fp = fopen(state, "r");
    char line[128];
    expect(fgets(line, sizeof line, fp) != NULL && strstr(line, "10.9.9.9") != NULL, "dry-run file unchanged");
    fclose(fp);
    rt->dry_run = 0;
    rt->backend->dry_run = 0;
    igmp_runtime_reconcile(rt);
    expect(rt->mutations >= 1, "apply records a mutation");
    uint64_t before = rt->mutations;
    int second = igmp_runtime_reconcile(rt);
    expect(second == 0, "second reconcile is empty");
    expect(rt->mutations == before, "idempotent apply adds nothing");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_pod_lifecycle(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    rt->use_kube = 1;
    uint8_t frame[128];
    uint32_t g1 = ip4("239.2.2.1");
    uint32_t g2 = ip4("239.2.2.2");
    uint32_t a = ip4("10.2.0.1");
    uint32_t b = ip4("10.2.0.2");
    size_t n = v2_report(frame, a, g1);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 4, 1);
    n = v2_report(frame, a, g2);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 4, 1);
    n = v2_report(frame, b, g1);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 4, 1);
    igmp_runtime_pod_upsert(rt, "pod-a", "a", "n1", a, 0, 0, 0);
    igmp_runtime_pod_upsert(rt, "pod-b", "b", "n1", b, 1, 0, 0);
    expect(igmp_engine_joined_count(rt->eng) == 3, "two groups plus other pod");
    igmp_runtime_pod_upsert(rt, "pod-a", "a", "n1", a, 3, 0, 0);
    expect(rt->restarts_ignored == 1, "restart is not deletion");
    expect(igmp_engine_joined_count(rt->eng) == 3, "restart keeps memberships");
    expect(igmp_runtime_pod_delete(rt, "pod-a") == 2, "pod-a both groups");
    expect(igmp_engine_find(rt->eng, g1, b, 4, NULL) == 1, "pod-b kept");
    rt->now_ms = 200;
    n = v2_report(frame, a, g1);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 4, 1);
    igmp_runtime_pod_upsert(rt, "pod-a2", "a2", "n1", a, 0, 0, 0);
    igmp_runtime_pod_delete(rt, "pod-a");
    const igmp_member *m = NULL;
    expect(igmp_engine_find(rt->eng, g1, a, 4, &m) == 1, "replacement survives delayed delete");
    expect(m && strcmp(m->pod_uid, "pod-a2") == 0, "uid rebound");
    igmp_runtime_free(rt);
    free(dir);
}

static void test_api_and_iface(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    rt->use_kube = 1;
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "pod-a", "a", "n1", ip4("10.3.0.1"), 0, 0, 1);
    igmp_runtime_pod_upsert(rt, "pod-b", "b", "n1", ip4("10.3.0.2"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "initial list keeps pods");
    uint8_t frame[128];
    uint32_t g = ip4("239.3.3.3");
    size_t n = v2_report(frame, ip4("10.3.0.1"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 8, 1);
    n = v2_report(frame, ip4("10.3.0.2"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 8, 1);
    n = v2_report(frame, ip4("10.9.9.1"), g);
    expect(igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 8, 1) == -1, "unbound source ignored");
    igmp_runtime_set_api(rt, 0);
    igmp_runtime_pods_begin(rt);
    expect(igmp_runtime_pods_end(rt) == -1, "api down skips resync");
    expect(igmp_engine_joined_count(rt->eng) == 2, "outage keeps members");
    igmp_runtime_set_api(rt, 1);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "pod-b", "b", "n1", ip4("10.3.0.2"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 1, "missing pod removed on resync");
    expect(igmp_engine_find(rt->eng, g, ip4("10.3.0.2"), 8, NULL) == 1, "listed pod kept");
    expect(igmp_engine_find(rt->eng, g, ip4("10.3.0.1"), 8, NULL) == 0, "absent pod cleaned");
    uint32_t gen = igmp_runtime_observe_iface(rt, 8, "veth0", 1);
    expect(gen == 1, "first generation");
    n = v2_report(frame, ip4("10.3.0.2"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 8, gen);
    expect(igmp_runtime_observe_iface(rt, 8, "veth1", 1) == 2, "rename bumps generation");
    expect(igmp_engine_find(rt->eng, g, ip4("10.3.0.2"), 8, NULL) == 0, "old generation retired");
    igmp_runtime_free(rt);
    free(dir);
}

typedef struct {
    igmp_actual rows[32];
    int n;
    int applies;
    int fail_at;
    int failed;
} fake_be;

static int fake_load(igmp_backend *b, igmp_actual *rows, int cap) {
    fake_be *f = b->user;
    int n = f->n < cap ? f->n : cap;
    memcpy(rows, f->rows, (size_t)n * sizeof *rows);
    return n;
}
static int fake_apply(igmp_backend *b, const igmp_op *op) {
    fake_be *f = b->user;
    f->applies++;
    if (!f->failed && f->applies == f->fail_at) {
        f->failed = 1;
        return -1;
    }
    if (op->op == IGMP_OP_GROUP_ADD || op->op == IGMP_OP_REMOTE_ADD) {
        f->rows[f->n].group = op->group;
        f->rows[f->n].addr = op->addr;
        f->rows[f->n].remote = 1;
        f->rows[f->n].managed = 1;
        f->n++;
    } else if (op->op == IGMP_OP_LOCAL_DEL || op->op == IGMP_OP_REMOTE_DEL) {
        int w = 0;
        for (int i = 0; i < f->n; i++) {
            int match = f->rows[i].group == op->group && f->rows[i].addr == op->addr;
            if (!match)
                f->rows[w++] = f->rows[i];
        }
        f->n = w;
    }
    return 0;
}

static void test_apply_budget(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    uint8_t frame[128];
    for (int i = 1; i <= 12; i++) {
        char gbuf[32];
        snprintf(gbuf, sizeof gbuf, "239.8.0.%d", i);
        rt->now_ms = (int64_t)i * 1000;
        size_t n = v2_report(frame, ip4("10.8.0.1"), ip4(gbuf));
        igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    }
    expect(igmp_engine_joined_count(rt->eng) == 12, "twelve groups joined");
    fake_be *f = calloc(1, sizeof *f);
    igmp_backend *b = calloc(1, sizeof *b);
    b->load = fake_load;
    b->apply = fake_apply;
    b->user = f;
    rt->backend = b;
    int first = igmp_runtime_reconcile(rt);
    expect(first == 8, "first pass stops at the apply budget");
    expect(rt->mutations == 8, "eight mutations recorded");
    expect(rt->reconcile_failures == 0, "a full queue is not a failure");
    expect(rt->reconcile_ok == 0, "the plan is not finished");
    int second = igmp_runtime_reconcile(rt);
    expect(second == 4, "remainder is applied next");
    expect(rt->mutations == 12, "every group was applied");
    expect(rt->reconcile_retries == 1, "continuation counts as a retry");
    expect(rt->reconcile_failures == 0, "continuation is not a failure");
    expect(rt->reconcile_ok == 1, "plan finished");
    expect(f->n == 12, "backend holds every group");
    int third = igmp_runtime_reconcile(rt);
    expect(third == 0, "steady state plans nothing");
    expect(rt->mutations == 12, "steady state adds no mutations");
    igmp_runtime_free(rt);
    free(f);
    free(b);
    free(dir);
}

static void test_retry_and_stale(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("239.4.4.4");
    mem.subscriber = ip4("10.4.0.8");
    mem.joined = 1;
    mem.ifindex = 1;
    mem.ifgen = 1;
    expect(igmp_coord_write(dir, "n2", ip4("10.244.1.1"), 0, igmp_coord_now_ms(), &mem, 1) == 0,
           "peer snap");
    uint8_t frame[128];
    size_t n = v2_report(frame, ip4("10.4.0.1"), mem.group);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    fake_be *f = calloc(1, sizeof *f);
    f->fail_at = 2;
    igmp_backend *b = calloc(1, sizeof *b);
    b->load = fake_load;
    b->apply = fake_apply;
    b->user = f;
    rt->backend = b;
    expect(igmp_runtime_reconcile(rt) < 0, "partial failure");
    expect(rt->mutations == 1, "first op applied");
    expect(rt->reconcile_retries == 0, "failure is not yet a retry");
    expect(igmp_runtime_reconcile(rt) > 0, "retry completes");
    expect(rt->reconcile_retries == 1, "retry counted");
    expect(f->n >= 2, "group and remote stored");
    char *dir2 = tmpdir();
    igmp_runtime *rt2 = make_rt(dir2, "n3", "10.244.2.1", 0);
    fake_be *f2 = calloc(1, sizeof *f2);
    f2->fail_at = 1;
    f2->rows[0].group = mem.group;
    f2->rows[0].addr = ip4("10.5.0.5");
    f2->rows[0].remote = 0;
    f2->rows[0].managed = 1;
    f2->n = 1;
    igmp_backend *b2 = calloc(1, sizeof *b2);
    b2->load = fake_load;
    b2->apply = fake_apply;
    b2->user = f2;
    rt2->backend = b2;
    expect(igmp_runtime_reconcile(rt2) < 0, "delete fails once");
    n = v2_report(frame, ip4("10.5.0.5"), mem.group);
    igmp_runtime_on_frame(rt2, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    igmp_runtime_reconcile(rt2);
    expect(rt2->stale_dropped == 1, "stale retry dropped");
    expect(igmp_engine_find(rt2->eng, mem.group, ip4("10.5.0.5"), 1, NULL) == 1, "new join kept");
    expect(f2->n == 1, "stale delete was not applied");
    igmp_runtime_free(rt);
    igmp_runtime_free(rt2);
    free(f);
    free(f2);
    free(b);
    free(b2);
    free(dir);
    free(dir2);
}

static void test_grace_unmanaged_restart_restore(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/map", dir);
    FILE *fp = fopen(state, "w");
    fprintf(fp, "239.6.6.6 %s 0 1\n", "10.6.0.9");
    fprintf(fp, "239.6.6.6 %s 1 0\n", "10.8.8.8");
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 5000);
    attach_file(rt, state, 0);
    igmp_runtime_reconcile(rt);
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.6.0.9")), "grace skips local delete");
    rt->now_ms = 5000;
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.6.0.9")), "stale local removed after grace");
    fp = fopen(state, "r");
    char buf[512];
    size_t n = fread(buf, 1, sizeof buf - 1, fp);
    buf[n] = 0;
    fclose(fp);
    expect(strstr(buf, "10.8.8.8") != NULL, "unmanaged remote preserved");
    fp = fopen(state, "w");
    fclose(fp);
    uint8_t frame[128];
    size_t fn = v2_report(frame, ip4("10.6.0.1"), ip4("239.6.6.1"));
    igmp_runtime_on_frame(rt, frame, fn, IGMP_LINK_ETHERNET, 1, 1);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_GROUP_ADD, 0), "group created");
    fp = fopen(state, "w");
    fclose(fp);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_GROUP_ADD, 0), "map recreation adds the group again");
    igmp_runtime_write_snapshot(rt);
    igmp_runtime *rt2 = make_rt(dir, "n1", "10.244.0.1", 0);
    expect(igmp_runtime_restore(rt2) == 1, "startup restore");
    expect(igmp_engine_joined_count(rt2->eng) == 1, "restored member");
    free(rt->backend);
    igmp_runtime_free(rt);
    igmp_runtime_free(rt2);
    free(dir);
}

static void test_refcount_and_querier(void) {
    char *dir = tmpdir();
    igmp_runtime *a = make_rt(dir, "a", "10.244.0.2", 0);
    a->eng->cfg.active_querier = 1;
    a->eng->cfg.self_ip = ip4("10.244.0.2");
    uint8_t frame[128];
    uint32_t g = ip4("239.7.7.7");
    size_t n = v2_report(frame, ip4("10.7.0.1"), g);
    igmp_runtime_on_frame(a, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    n = v2_report(frame, ip4("10.7.0.2"), g);
    igmp_runtime_on_frame(a, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    igmp_runtime_write_snapshot(a);
    char state[512];
    snprintf(state, sizeof state, "%s/bstate", dir);
    FILE *fp = fopen(state, "w");
    fclose(fp);
    igmp_runtime *b = make_rt(dir, "b", "10.244.0.9", 0);
    attach_file(b, state, 0);
    igmp_runtime_reconcile(b);
    expect(has_op(b, IGMP_OP_REMOTE_ADD, ip4("10.244.0.2")), "remote node added once");
    expect(b->last_op_count == 2, "group add plus one remote");
    igmp_runtime_pod_upsert(a, "p1", "p", "a", ip4("10.7.0.1"), 0, 0, 0);
    igmp_runtime_pod_delete(a, "p1");
    igmp_runtime_write_snapshot(a);
    igmp_runtime_reconcile(b);
    expect(!has_op(b, IGMP_OP_REMOTE_DEL, ip4("10.244.0.2")), "one remaining subscriber keeps the node");
    igmp_runtime_pod_upsert(a, "p2", "p", "a", ip4("10.7.0.2"), 0, 0, 0);
    igmp_runtime_pod_delete(a, "p2");
    igmp_runtime_write_snapshot(a);
    igmp_runtime_reconcile(b);
    expect(has_op(b, IGMP_OP_REMOTE_DEL, ip4("10.244.0.2")), "node removed at count zero");
    igmp_coord_write(dir, "low", ip4("10.244.0.1"), 1, igmp_coord_now_ms(), NULL, 0);
    a->eng->cfg.active_querier = 1;
    a->eng->cfg.self_ip = ip4("10.244.0.2");
    a->eng->we_are_querier = 1;
    a->eng->querier_ip = a->eng->cfg.self_ip;
    a->now_ms = 10;
    igmp_runtime_tick(a);
    expect(a->eng->we_are_querier == 0, "lower daemonset wins election");
    free(b->backend);
    igmp_runtime_free(a);
    igmp_runtime_free(b);
    free(dir);
}

static void test_quiet_subscriber_and_queue(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    rt->use_kube = 1;
    igmp_runtime_pod_upsert(rt, "pod", "p", "n1", ip4("10.8.0.1"), 0, 0, 0);
    uint8_t frame[128];
    uint32_t g = ip4("239.8.8.1");
    size_t n = v2_report(frame, ip4("10.8.0.1"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    igmp_runtime_tick(rt);
    expect(igmp_engine_joined_count(rt->eng) == 1, "silence without querier keeps the pod");
    n = v2_query(frame, ip4("10.0.0.9"));
    rt->now_ms = 1000;
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    rt->now_ms = 2500;
    igmp_runtime_tick(rt);
    expect(igmp_engine_joined_count(rt->eng) == 0, "lost application membership expires");
    expect(igmp_pods_by_uid(&rt->pods, "pod") != NULL, "pod object remains");
    uint8_t junk[64];
    memset(junk, 1, sizeof junk);
    int ok = 0;
    for (int i = 0; i < 64; i++)
        ok += igmp_runtime_enqueue(rt, junk, sizeof junk, IGMP_LINK_ETHERNET, 1, 1) == 0;
    expect(ok == 64, "queue fills to cap");
    expect(igmp_runtime_enqueue(rt, junk, sizeof junk, IGMP_LINK_ETHERNET, 1, 1) != 0, "overflow");
    expect(rt->queue_drops >= 1, "overflow counted");
    expect(igmp_runtime_drain(rt, 100) == 64, "drain empties queue");
    expect(rt->queue_depth == 0, "depth zero");
    char metrics[4096];
    igmp_metrics_render(rt, metrics, sizeof metrics);
    expect(strstr(metrics, "igmpshark_queue_drops_total") != NULL, "metrics rendered");
    uint8_t qpkt[16];
    int qn = igmp_query_build(qpkt, sizeof qpkt, 0, 10000, 2);
    expect(qn == 8 && igmp_checksum(qpkt, 8) == 0, "query checksum");
    const char *list = "Group Subscriber Type\n239.1.1.1 10.1.1.5 Local\n239.1.1.1 10.244.1.1 Remote\n";
    igmp_actual rows[8];
    int nr = igmp_parse_cilium_subscribers(list, rows, 8);
    expect(nr == 2 && rows[0].remote == 0 && rows[1].remote == 1, "cilium list parse");
    const char *v119 = "Group           Subscriber      Type\n"
                       "239.1.1.1       10.1.1.5        Local\n"
                       "239.1.1.1       10.244.1.86     Remote Node\n";
    nr = igmp_parse_cilium_subscribers(v119, rows, 8);
    expect(nr == 2 && rows[0].remote == 0 && rows[1].remote == 1 && rows[1].addr == ip4("10.244.1.86"),
           "cilium 1.19 Remote Node type");
    /* Cilium 1.19.3 prints the group only on the first subscriber. Later
     * lines of that group leave the group column blank. */
    const char *folded = "Group           Subscriber      Type\n"
                         "239.192.14.12   10.42.5.33      Local Endpoint\n"
                         "                10.42.5.149     Local Endpoint\n"
                         "                10.42.7.110     Remote Node\n"
                         "239.1.1.1\n";
    nr = igmp_parse_cilium_subscribers(folded, rows, 8);
    expect(nr == 4, "blank group column stays with the group above");
    expect(rows[0].group == ip4("239.192.14.12") && rows[0].addr == ip4("10.42.5.33") &&
               rows[0].remote == 0,
           "first local endpoint");
    expect(rows[1].group == ip4("239.192.14.12") && rows[1].addr == ip4("10.42.5.149") &&
               rows[1].remote == 0,
           "second local endpoint is kept");
    expect(rows[2].group == ip4("239.192.14.12") && rows[2].addr == ip4("10.42.7.110") &&
               rows[2].remote == 1,
           "remote node on a blank group column");
    expect(rows[3].group == ip4("239.1.1.1") && rows[3].addr == 0, "group with no subscribers");
    igmp_actual one[1];
    expect(igmp_parse_cilium_subscribers(folded, one, 1) < 0,
           "a subscriber list that does not fit is an error");
    igmp_runtime_free(rt);
    free(dir);
}

static void test_snap_clock(void) {
    char *dir = tmpdir();
    int64_t now = igmp_coord_now_ms();
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("239.4.4.4");
    mem.subscriber = ip4("10.4.0.8");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "near", ip4("10.244.1.2"), 0, now + 20000, &mem, 1) == 0,
           "near future snap");
    expect(igmp_coord_write(dir, "far", ip4("10.244.1.3"), 0, now + 120000, &mem, 1) == 0,
           "far future snap");
    expect(igmp_coord_write(dir, "old", ip4("10.244.1.4"), 0, now - 600000, &mem, 1) == 0, "old snap");
    expect(igmp_coord_write(dir, "gap", ip4("10.244.1.5"), 0, now - 15000, &mem, 1) == 0,
           "recently stale snap");
    igmp_peer peers[8];
    int n = igmp_coord_peers(dir, "self", now, 4200, peers, 8);
    expect(n == 4, "four peers");
    int near = 0, far = 0, old = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(peers[i].name, "near") == 0)
            near = peers[i].fresh;
        if (strcmp(peers[i].name, "far") == 0)
            far = peers[i].fresh;
        if (strcmp(peers[i].name, "old") == 0)
            old = peers[i].fresh;
    }
    expect(near == 1, "20s future skew stays fresh");
    expect(far == 0, "2min future skew is stale");
    expect(old == 0, "old snap is stale");
    uint32_t held[4];
    int nstale = 0;
    igmp_remote_sub remote[4];
    int nr = igmp_coord_load_remote(dir, "self", now, 10000, remote, 4, held, 4, &nstale, NULL, 0);
    expect(nr == 1 && remote[0].node_ip == ip4("10.244.1.2"), "20s future peer is installed");
    int saw_gap = 0, saw_far = 0, saw_old = 0;
    for (int i = 0; i < nstale; i++) {
        if (held[i] == ip4("10.244.1.5"))
            saw_gap = 1;
        if (held[i] == ip4("10.244.1.3"))
            saw_far = 1;
        if (held[i] == ip4("10.244.1.4"))
            saw_old = 1;
    }
    expect(saw_gap == 1, "a short publish gap is held");
    expect(saw_far == 0, "a far-future snapshot does not pin remote rows");
    expect(saw_old == 0, "a long-dead snapshot does not pin remote rows");
    free(dir);
}

static int grab_snap(void *user, const char *b64) {
    char **out = user;
    *out = strdup(b64);
    return 0;
}

static void test_snapshot_field(void) {
    const char *json = "{\"items\":[{\"metadata\":{\"name\":\"igmpshark-ws-g3-281\"},"
                       "\"data\":{\"snapshot\":\"Tk9ERSB3cy1nMy0yODEgMTAuMC4wLjEgMCAxCg==\"}}]}";
    char *b64 = NULL;
    int n = kube_each_snapshot(json, grab_snap, &b64);
    expect(n == 1 && b64 && strncmp(b64, "Tk9ERS", 6) == 0, "snapshot value follows the colon");
    free(b64);
    const char *pretty = "{\n  \"data\": {\n    \"snapshot\":\n      \"QUJD\"\n  }\n}\n";
    b64 = NULL;
    n = kube_each_snapshot(pretty, grab_snap, &b64);
    expect(n == 1 && b64 && strcmp(b64, "QUJD") == 0, "snapshot value after whitespace");
    free(b64);
}

static void test_coord_dir_created(void) {
    char *parent = tmpdir();
    char dir[512];
    snprintf(dir, sizeof dir, "%s/coord", parent);
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("239.1.1.1");
    mem.subscriber = ip4("10.1.0.1");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "n1", ip4("10.244.0.1"), 0, igmp_coord_now_ms(), &mem, 1) == 0,
           "snapshot creates the coord directory");
    igmp_remote_sub remote[4];
    int nstale = 0;
    int n = igmp_coord_load_remote(dir, "other", igmp_coord_now_ms(), 600000, remote, 4, NULL, 0,
                                   &nstale, NULL, 0);
    expect(n == 1 && remote[0].group == mem.group && remote[0].node_ip == ip4("10.244.0.1"),
           "peer snapshot is visible");
    free(parent);
}

static int keep_pod(void *user, const kube_event *ev) {
    kube_event *slot = user;
    if (ev->kind == KUBE_EV_UPSERT && strcmp(ev->name, "repbox-0") == 0)
        *slot = *ev;
    return 0;
}

static void test_solicit_repairs_local(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/state", dir);
    FILE *fp = fopen(state, "w");
    expect(fp != NULL, "state file");
    if (fp)
        fclose(fp);
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    rt->eng->cfg.solicit_reports = 1;
    rt->log_json = 0;
    expect(rt->eng->we_are_querier == 0, "repair does not require the querier");
    attach_file(rt, state, 0);
    uint8_t frame[128];
    uint32_t g = ip4("239.1.1.1");
    uint32_t sub = ip4("10.1.0.5");
    size_t n = v2_report(frame, sub, g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 2, 1);
    expect(rt->eng->queries_sent == 0, "report alone does not solicit");
    int ops = igmp_runtime_reconcile(rt);
    expect(ops >= 1 && has_op(rt, IGMP_OP_GROUP_ADD, 0), "group is added");
    igmp_local_join joins[4];
    int jn = igmp_runtime_take_joins(rt, joins, 4);
    expect(jn == 1 && joins[0].group == g && joins[0].subscriber == sub,
           "missing local endpoint queues a TO_EX join");
    igmp_query_out qs[40];
    int qn = 0;
    igmp_engine_take_queries(rt->eng, qs, &qn, 40);
    expect(qn == 1 && qs[0].group == g && qs[0].version == 2, "solicit follows the group add");
    igmp_runtime_reconcile(rt);
    igmp_engine_take_queries(rt->eng, qs, &qn, 40);
    expect(qn == 1 && qs[0].group == g, "missing local endpoint is solicited again");
    fp = fopen(state, "w");
    fputs("239.1.1.1 0.0.0.0 1 1\n239.1.1.1 10.1.0.5 0 1\n", fp);
    fclose(fp);
    int steady = igmp_runtime_reconcile(rt);
    igmp_engine_take_queries(rt->eng, qs, &qn, 40);
    expect(steady == 0 && qn == 0, "local endpoint present stops the solicit");
    jn = igmp_runtime_take_joins(rt, joins, 4);
    expect(jn == 0, "local endpoint present stops the join");

    igmp_runtime *dry = make_rt(dir, "n1", "10.244.0.1", 0);
    dry->eng->cfg.solicit_reports = 1;
    dry->log_json = 0;
    char state2[512];
    snprintf(state2, sizeof state2, "%s/dry", dir);
    fp = fopen(state2, "w");
    fclose(fp);
    attach_file(dry, state2, 1);
    n = v2_report(frame, sub, g);
    igmp_runtime_on_frame(dry, frame, n, IGMP_LINK_ETHERNET, 2, 1);
    igmp_runtime_reconcile(dry);
    igmp_engine_take_queries(dry->eng, qs, &qn, 40);
    expect(qn == 0 && dry->eng->queries_sent == 0, "dry-run does not solicit");
    jn = igmp_runtime_take_joins(dry, joins, 4);
    expect(jn == 0, "dry-run does not inject a join");
    free(rt->backend);
    free(dry->backend);
    igmp_runtime_free(rt);
    igmp_runtime_free(dry);
    free(dir);
}

static void test_solicit_covers_every_group(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/state", dir);
    FILE *fp = fopen(state, "w");
    uint32_t groups[40];
    for (int i = 0; i < 40; i++) {
        char gbuf[32];
        snprintf(gbuf, sizeof gbuf, "239.9.0.%d", i + 1);
        groups[i] = ip4(gbuf);
        fprintf(fp, "%s 0.0.0.0 1 1\n", gbuf);
    }
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "n1", "10.244.0.1", 0);
    rt->eng->cfg.solicit_reports = 1;
    rt->log_json = 0;
    attach_file(rt, state, 0);
    uint8_t frame[128];
    for (int i = 0; i < 40; i++) {
        rt->now_ms = (int64_t)(i + 1) * 1000;
        size_t n = v2_report(frame, ip4("10.9.0.1"), groups[i]);
        igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    }
    expect(igmp_engine_joined_count(rt->eng) == 40, "forty local groups");
    int seen[40];
    memset(seen, 0, sizeof seen);
    igmp_query_out qs[40];
    for (int pass = 0; pass < 2; pass++) {
        int ops = igmp_runtime_reconcile(rt);
        expect(ops == 0, "existing groups are not added again");
        int qn = 0;
        igmp_engine_take_queries(rt->eng, qs, &qn, 40);
        expect(qn == 32, "solicit stops at the pending queue");
        for (int q = 0; q < qn; q++) {
            for (int g = 0; g < 40; g++)
                if (qs[q].group == groups[g])
                    seen[g] = 1;
        }
    }
    int covered = 0;
    for (int g = 0; g < 40; g++)
        covered += seen[g];
    expect(covered == 40, "later passes reach groups past the queue");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_cilium_internal_identity(void) {
    const char *json =
        "["
        "{\"health-endpoint-address\":{\"ipv4\":{\"enabled\":true,\"ip\":\"10.42.5.149\"}},"
        "\"ingress-address\":{\"ipv4\":{\"ip\":\"10.42.5.200\"}},"
        "\"name\":\"ws-g3-281\","
        "\"primary-address\":{\"ipv4\":{\"alloc-range\":\"10.42.5.0/24\",\"enabled\":true,"
        "\"ip\":\"192.168.106.135\"}},"
        "\"secondary-addresses\":[{\"ip\":\"10.42.5.149\"},{\"ip\":\"192.168.106.135\"},"
        "{\"ip\":\"10.42.5.33\"}],"
        "\"source\":\"local\"},"
        "{\"health-endpoint-address\":{\"ipv4\":{\"ip\":\"10.42.7.110\"}},"
        "\"name\":\"default/ws-g3-160\","
        "\"primary-address\":{\"ipv4\":{\"alloc-range\":\"10.42.7.0/24\","
        "\"ip\":\"192.168.106.218\"}},"
        "\"secondary-addresses\":[{\"ip\":\"10.42.7.178\"}]}"
        "]";
    igmp_cilium_node nodes[4];
    int n = igmp_parse_cilium_nodes(json, nodes, 4);
    expect(n == 2, "both nodes are parsed from an array");
    expect(strcmp(nodes[0].name, "ws-g3-281") == 0, "first node name");
    expect(nodes[0].primary == ip4("192.168.106.135"), "kubernetes node IP stays primary");
    expect(nodes[0].health == ip4("10.42.5.149"), "health address is recorded separately");
    expect(nodes[0].internal == ip4("10.42.5.33"), "in-cidr secondary is CiliumInternalIP");
    expect(nodes[1].internal == ip4("10.42.7.178"), "second node internal IP");
    expect(nodes[1].health == ip4("10.42.7.110"), "second health address");
    expect(nodes[1].primary == ip4("192.168.106.218"), "second kubernetes node IP");

    const char *wrapped =
        "{\"nodes-added\":[{\"name\":\"n1\",\"primary-address\":{\"ipv4\":{\"ip\":\"192.168.1.1\"}},"
        "\"secondary-addresses\":[{\"ip\":\"10.1.0.9\"}]}]}";
    n = igmp_parse_cilium_nodes(wrapped, nodes, 4);
    expect(n == 1 && nodes[0].internal == ip4("10.1.0.9") && nodes[0].primary == ip4("192.168.1.1"),
           "nodes-added wrapper without a pod CIDR still skips the primary");

    const char *only_primary =
        "[{\"name\":\"n2\",\"primary-address\":{\"ipv4\":{\"alloc-range\":\"10.42.5.0/24\","
        "\"ip\":\"192.168.106.135\"}},\"secondary-addresses\":[{\"ip\":\"192.168.106.135\"}]}]";
    n = igmp_parse_cilium_nodes(only_primary, nodes, 4);
    expect(n == 1 && nodes[0].internal == 0, "primary is never used as the overlay address");
}

static void test_rewrite_remote_identity(void) {
    char *dir = tmpdir();
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("227.188.50.50");
    mem.subscriber = ip4("10.42.7.50");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "ws-g3-160", ip4("10.42.7.110"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "peer snapshot published the health address");
    igmp_remote_sub remote[4];
    int nstale = 0;
    igmp_ip_rewrite rw;
    memset(&rw, 0, sizeof rw);
    snprintf(rw.name, sizeof rw.name, "%s", "default/ws-g3-160");
    rw.ip = ip4("10.42.7.178");
    int n = igmp_coord_load_remote(dir, "ws-g3-281", igmp_coord_now_ms(), 600000, remote, 4, NULL,
                                   0, &nstale, &rw, 1);
    expect(n == 1 && remote[0].node_ip == ip4("10.42.7.178") && remote[0].group == mem.group,
           "peer address is rewritten to CiliumInternalIP");
    igmp_ip_rewrite other;
    memset(&other, 0, sizeof other);
    snprintf(other.name, sizeof other.name, "%s", "somewhere-else");
    other.ip = ip4("10.9.9.9");
    n = igmp_coord_load_remote(dir, "ws-g3-281", igmp_coord_now_ms(), 600000, remote, 4, NULL, 0,
                               &nstale, &other, 1);
    expect(n == 0, "unknown peer is not installed from the snapshot address");
    free(dir);
}

static void test_runtime_uses_identity(void) {
    char *dir = tmpdir();
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("227.188.50.50");
    mem.subscriber = ip4("10.42.5.31");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "ws-g3-281", ip4("10.42.5.149"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "snapshot still carries the address tcpdump showed");
    char state[512];
    snprintf(state, sizeof state, "%s/state", dir);
    FILE *fp = fopen(state, "w");
    expect(fp != NULL, "empty cilium state");
    if (fp)
        fclose(fp);
    igmp_runtime *rt = make_rt(dir, "ws-g3-160", "10.42.7.178", 0);
    attach_file(rt, state, 0);
    igmp_ip_rewrite rw;
    memset(&rw, 0, sizeof rw);
    snprintf(rw.name, sizeof rw.name, "%s", "ws-g3-281");
    rw.ip = ip4("10.42.5.33");
    igmp_runtime_set_identities(rt, &rw, 1);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.5.33")), "remote subscriber is CiliumInternalIP");
    expect(!has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.5.149")), "health address is not a subscriber");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_toex_and_trie(void) {
    uint8_t pkt[16];
    uint32_t g = ip4("227.188.0.65");
    expect(igmp_v3_toex_build(pkt, sizeof pkt, g) == 16, "to_ex report is 16 bytes");
    expect(pkt[0] == 0x22 && pkt[7] == 1 && pkt[8] == IGMP_REC_TO_EXCLUDE, "to_ex record type");
    expect(pkt[11] == 0, "to_ex has no sources");
    uint32_t got = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) | ((uint32_t)pkt[14] << 8) |
                   pkt[15];
    expect(got == g, "to_ex group address");
    uint8_t check[16];
    memcpy(check, pkt, 16);
    check[2] = check[3] = 0;
    uint16_t sum = igmp_checksum(check, 16);
    expect(pkt[2] == (uint8_t)(sum >> 8) && pkt[3] == (uint8_t)sum, "to_ex checksum");

    const char *pod =
        "Main:\n"
        "  +-- 0.0.0.0/0 3 0 5\n"
        "     +-- 10.42.7.0/24 2 0 1\n"
        "        |-- 10.42.7.50\n"
        "           /32 host UNICAST\n"
        "Local:\n"
        "  +-- 10.42.7.50/32 0 0 1\n"
        "     |-- 10.42.7.50\n"
        "        /32 host LOCAL\n";
    expect(igmp_fib_trie_has_local(pod, ip4("10.42.7.50")) == 1, "pod Local section matches");
    const char *host =
        "Main:\n"
        "  +-- 10.42.7.50/32 1 0 1\n"
        "     |-- 10.42.7.50\n"
        "        /32 host UNICAST\n"
        "Local:\n"
        "  +-- 10.42.7.178/32 0 0 1\n"
        "     |-- 10.42.7.178\n"
        "        /32 host LOCAL\n";
    expect(igmp_fib_trie_has_local(host, ip4("10.42.7.50")) == 0,
           "host route is not a local address");
    expect(igmp_fib_trie_has_local(host, ip4("10.42.7.178")) == 1, "host's own local address matches");
    const char *neighbor =
        "Local:\n"
        "  +-- 10.42.5.0/24 2 0 3\n"
        "     |-- 10.42.5.0\n"
        "        /32 link BROADCAST\n"
        "     |-- 10.42.5.149\n"
        "        /32 host LOCAL\n"
        "     |-- 10.42.5.50\n"
        "        /32 host UNICAST\n";
    expect(igmp_fib_trie_has_local(neighbor, ip4("10.42.5.149")) == 1, "leaf local address matches");
    expect(igmp_fib_trie_has_local(neighbor, ip4("10.42.5.0")) == 0,
           "pod CIDR prefix is not a local pod");
    expect(igmp_fib_trie_has_local(neighbor, ip4("10.42.5.50")) == 0,
           "neighbor LOCAL does not keep a departed pod");
}

static void test_pod_list_without_kind(void) {
    const char *json =
        "{\"kind\":\"PodList\",\"apiVersion\":\"v1\",\"metadata\":{\"resourceVersion\":\"9\"},"
        "\"items\":["
        "{\"metadata\":{\"name\":\"pending\",\"namespace\":\"default\",\"uid\":\"u-pending\","
        "\"deletionTimestamp\":null},\"spec\":{\"nodeName\":\"ws-g3-281\"}},"
        "{\"metadata\":{\"name\":\"repbox-0\",\"namespace\":\"app\",\"uid\":\"u-repbox\"},"
        "\"spec\":{\"nodeName\":\"ws-g3-281\"},"
        "\"status\":{\"podIP\":\"10.42.5.31\",\"podIPs\":[{\"ip\":\"10.42.5.31\"}]}}"
        "]}";
    kube_event found;
    memset(&found, 0, sizeof found);
    int n = kube_parse_pod_list(json, keep_pod, &found);
    expect(n == 2, "list items without kind are both read");
    expect(strcmp(found.name, "repbox-0") == 0, "repbox name");
    expect(strcmp(found.node, "ws-g3-281") == 0, "repbox node");
    expect(found.ip == ip4("10.42.5.31"), "repbox podIP is not taken from podIPs of another object");
    expect(found.kind == KUBE_EV_UPSERT && !found.deleting, "running pod is an upsert");

    const char *watch =
        "{\"type\":\"MODIFIED\",\"object\":{\"metadata\":{\"name\":\"repbox-0\",\"uid\":\"u-repbox\"},"
        "\"spec\":{\"nodeName\":\"ws-g3-281\"},\"status\":{\"podIP\":\"10.42.5.31\"}}}";
    kube_event ev;
    expect(kube_parse_watch_line(watch, &ev) == 1, "watch line");
    expect(ev.ip == ip4("10.42.5.31") && strcmp(ev.node, "ws-g3-281") == 0, "watch pod identity");
}

static void test_leave_is_not_reinjected(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/map", dir);
    FILE *fp = fopen(state, "w");
    fprintf(fp, "239.1.2.3 10.42.7.178 0 1\n");
    fprintf(fp, "239.1.2.3 0.0.0.0 1 1\n");
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    attach_file(rt, state, 0);
    uint8_t frame[256];
    uint32_t g = ip4("239.1.2.3");
    uint32_t s = ip4("10.42.7.178");
    rt->now_ms = 1000;
    size_t n = v2_report(frame, s, g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    rt->now_ms = 1100;
    n = v2_leave(frame, s, g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 4, 1);
    igmp_runtime_reconcile(rt);
    igmp_local_join js[8];
    expect(igmp_runtime_take_joins(rt, js, 8) == 0, "leaving pod is not injected again");
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, s), "cilium local row is deleted while the leave waits");
    igmp_runtime_write_snapshot(rt);
    char path[512];
    snprintf(path, sizeof path, "%s/ws-g3-160.snap", dir);
    fp = fopen(path, "r");
    expect(fp != NULL, "snapshot written");
    char body[1024];
    size_t got = fp ? fread(body, 1, sizeof body - 1, fp) : 0;
    if (fp)
        fclose(fp);
    body[got] = 0;
    expect(strstr(body, "10.42.7.178") == NULL, "snapshot stops publishing the leaving pod");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_cilium_host_annotation(void) {
    const char *json =
        "{\"kind\":\"NodeList\",\"items\":["
        "{\"metadata\":{\"name\":\"ws-g3-160\",\"labels\":{\"name\":\"not-the-node\"},"
        "\"annotations\":{"
        "\"io.cilium.network.ipv4-cilium-host\":\"10.42.7.1\","
        "\"network.cilium.io/ipv4-health-ip\":\"10.42.7.110\","
        "\"network.cilium.io/ipv4-cilium-host\":\"10.42.7.178\""
        "}},\"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"192.168.106.218\"}]}},"
        "{\"metadata\":{\"name\":\"ws-g3-281\",\"annotations\":{"
        "\"network.cilium.io/ipv4-health-ip\":\"10.42.5.149\","
        "\"io.cilium.network.ipv4-cilium-host\":\"10.42.5.33\"}}},"
        "{\"metadata\":{\"name\":\"ws-g3-017\",\"annotations\":{"
        "\"network.cilium.io/ipv4-health-ip\":\"10.42.1.9\"}}}"
        "]}";
    kube_node_ip rows[4];
    int n = kube_parse_cilium_host_ips(json, rows, 4);
    expect(n == 2, "health-only node is not a router");
    expect(strcmp(rows[0].name, "ws-g3-160") == 0, "annotation node name");
    expect(rows[0].ip == ip4("10.42.7.178"), "canonical annotation beats the alias and the health IP");
    expect(strcmp(rows[1].name, "ws-g3-281") == 0 && rows[1].ip == ip4("10.42.5.33"),
           "alias is used when the canonical key is absent");
    const char *one =
        "{\"metadata\":{\"name\":\"ws-g3-160\",\"annotations\":{"
        "\"network.cilium.io/ipv4-cilium-host\":\"10.42.7.178\"}}}";
    n = kube_parse_cilium_host_ips(one, rows, 4);
    expect(n == 1 && rows[0].ip == ip4("10.42.7.178"), "a single node object is accepted");
}

static void test_already_exists_is_success(void) {
    const char *err =
        "failed to add subscriber 10.42.7.110 to multicast group 227.188.0.65 "
        "failed to insert multicast subscriber update key already exists | exit 1";
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_ADD, err, 0) == 1,
           "duplicate subscriber add is the desired state");
    expect(igmp_cilium_result_ok(IGMP_OP_GROUP_ADD, "AlreadyExists", 0) == 1,
           "duplicate group add is success");
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_ADD, "permission denied | exit 1", 0) == 0,
           "a real add failure is still a failure");
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_ADD, err, 1) == 1, "a zero exit is success");
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_DEL, "key not found | exit 1", 0) == 1,
           "deleting a missing subscriber is success");
    expect(igmp_cilium_result_ok(IGMP_OP_GROUP_DEL, "does not exist", 0) == 1,
           "deleting a missing group is success");
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_DEL, err, 0) == 0,
           "already exists does not make a delete succeed");
    expect(igmp_cilium_result_ok(IGMP_OP_REMOTE_ADD, NULL, 0) == 0, "missing output is a failure");
}

static void test_orphan_remote_without_ledger(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/map", dir);
    FILE *fp = fopen(state, "w");
    fprintf(fp, "227.188.0.65 10.42.7.110 1 0\n");
    fprintf(fp, "227.188.0.65 0.0.0.0 1 0\n");
    fprintf(fp, "227.188.0.65 10.42.7.50 0 0\n");
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "ws-g3-017", "10.42.1.1", 0);
    attach_file(rt, state, 0);
    rt->mark_from_ledger = 1;
    snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s/ledger", dir);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_REMOTE_DEL, ip4("10.42.7.110")),
           "remote row is removed after the ledger was wiped");
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.7.50")),
           "an unmanaged local row is not claimed");
    expect(!has_op(rt, IGMP_OP_GROUP_DEL, 0), "unmanaged local blocks group delete");

    fp = fopen(state, "w");
    fprintf(fp, "227.188.0.65 10.42.7.110 1 0\n");
    fprintf(fp, "227.188.0.65 0.0.0.0 1 0\n");
    fclose(fp);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_REMOTE_DEL, ip4("10.42.7.110")), "wrong remote is deleted");
    expect(has_op(rt, IGMP_OP_GROUP_DEL, 0), "group marker does not keep the group");

    fp = fopen(state, "w");
    fprintf(fp, "227.188.0.65 10.42.7.110 1 0\n");
    fprintf(fp, "227.188.0.65 0.0.0.0 1 0\n");
    fclose(fp);
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("227.188.0.65");
    mem.subscriber = ip4("10.42.7.50");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "ws-g3-160", ip4("10.42.7.110"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "peer snapshot still publishes the health address");
    igmp_ip_rewrite rw;
    memset(&rw, 0, sizeof rw);
    snprintf(rw.name, sizeof rw.name, "%s", "ws-g3-160");
    rw.ip = ip4("10.42.7.178");
    igmp_runtime_set_identities(rt, &rw, 1);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.178")), "annotation address is installed");
    expect(has_op(rt, IGMP_OP_REMOTE_DEL, ip4("10.42.7.110")), "health address is removed");
    expect(!has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.110")), "health address is not added");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_departed_local_endpoint(void) {
    char *dir = tmpdir();
    char state[512];
    char held[512];
    snprintf(state, sizeof state, "%s/map", dir);
    snprintf(held, sizeof held, "%s/held", dir);
    FILE *fp = fopen(state, "w");
    fprintf(fp, "239.192.14.12 10.42.7.50 0 0\n");
    fprintf(fp, "239.192.14.12 10.42.7.150 0 0\n");
    fclose(fp);
    fp = fopen(held, "w");
    fprintf(fp, "239.192.14.12 10.42.7.50 0 0\n");
    fprintf(fp, "239.192.14.12 10.42.7.150 0 0\n");
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    attach_file(rt, held, 0);
    rt->use_kube = 1;
    rt->mark_from_ledger = 1;
    snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s/ledger", dir);
    igmp_runtime_reconcile(rt);
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.7.50")),
           "incomplete pod list keeps both local endpoints");
    free(rt->backend);
    igmp_runtime_free(rt);

    rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    attach_file(rt, state, 0);
    rt->use_kube = 1;
    rt->mark_from_ledger = 1;
    snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s/ledger", dir);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "app-new", "app", "ws-g3-160", ip4("10.42.7.150"), 0, 0, 1);
    igmp_runtime_pod_upsert(rt, "elsewhere", "app", "ws-g3-281", ip4("10.42.7.50"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "pod list completed");
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.7.50")), "replaced pod address is removed");
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.7.150")), "current pod address stays");
    expect(!has_op(rt, IGMP_OP_GROUP_DEL, 0), "the live local endpoint keeps the group");
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_new_pod_ip_replays_report(void) {
    char *dir = tmpdir();
    igmp_runtime *rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    uint8_t frame[128];
    uint32_t g = ip4("239.192.14.12");
    uint32_t pod = ip4("10.42.7.252");
    size_t n;
    rt->use_kube = 1;
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "other", "other", "ws-g3-160", ip4("10.42.7.10"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "pod list is complete");
    n = v2_report(frame, pod, g);
    rt->now_ms = 1000;
    expect(igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 3, 1) == -1,
           "report before the new pod ip is ignored");
    expect(igmp_engine_joined_count(rt->eng) == 0, "membership waits for the pod ip");
    expect(rt->ignored_unbound == 1, "unbound report counted");
    igmp_runtime_pod_upsert(rt, "mcast", "mcast", "ws-g3-160", pod, 0, 0, 0);
    expect(igmp_engine_find(rt->eng, g, pod, 3, NULL) == 1, "held report is applied when the pod ip arrives");
    expect(igmp_engine_joined_count(rt->eng) == 1, "new pod ip is a membership");
    rt->now_ms = 1000 + 31000;
    igmp_runtime_tick(rt);
    n = v2_report(frame, ip4("10.42.7.253"), g);
    igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 3, 1);
    rt->now_ms += 31000;
    igmp_runtime_tick(rt);
    igmp_runtime_pod_upsert(rt, "late", "late", "ws-g3-160", ip4("10.42.7.253"), 0, 0, 0);
    expect(igmp_engine_find(rt->eng, g, ip4("10.42.7.253"), 3, NULL) == 0,
           "a report older than the hold window is not replayed");
    igmp_runtime_free(rt);
    free(dir);
}

static int keep_any(void *user, const kube_event *ev) {
    *(kube_event *)user = *ev;
    return 0;
}

static void test_pod_ipv4_not_host_or_podips_key(void) {
    const char *json =
        "{\"kind\":\"PodList\",\"items\":[{\"metadata\":{\"name\":\"mcast\",\"uid\":\"u-mcast\","
        "\"deletionTimestamp\":null},\"spec\":{\"nodeName\":\"ws-g3-160\"},"
        "\"status\":{\"hostIP\":\"192.168.106.218\",\"podIPs\":[{\"ip\":\"10.9.9.9\"}],"
        "\"podIP\":\"10.42.7.155\"}}]}";
    kube_event ev;
    memset(&ev, 0, sizeof ev);
    expect(kube_parse_pod_list(json, keep_any, &ev) == 1, "pod parsed");
    expect(ev.ip == ip4("10.42.7.155"), "podIP wins over an earlier podIPs entry and hostIP");
    const char *v6 =
        "{\"kind\":\"PodList\",\"items\":[{\"metadata\":{\"name\":\"mcast\",\"uid\":\"u-mcast\"},"
        "\"spec\":{\"nodeName\":\"ws-g3-160\"},\"status\":{\"podIP\":\"fd00::155\","
        "\"podIPs\":[{\"ip\":\"fd00::155\"},{\"ip\":\"10.42.7.155\"}]}}]}";
    memset(&ev, 0, sizeof ev);
    expect(kube_parse_pod_list(v6, keep_any, &ev) == 1, "dual-stack pod parsed");
    expect(ev.ip == ip4("10.42.7.155"), "IPv4 is taken from podIPs when podIP is IPv6");
}

static void test_list_meta_ignores_pod_version(void) {
    char rv[64];
    char cont[64];
    const char *json =
        "{\"kind\":\"PodList\",\"metadata\":{\"resourceVersion\":\"100\","
        "\"continue\":\"abc+def/g==\"},\"items\":[{\"metadata\":{"
        "\"resourceVersion\":\"1\",\"continue\":\"nope\",\"name\":\"a\",\"uid\":\"u\"}}]}";
    expect(kube_parse_list_meta(json, rv, sizeof rv, cont, sizeof cont) == 0, "list metadata");
    expect(strcmp(rv, "100") == 0, "list resourceVersion is not the pod's");
    expect(strcmp(cont, "abc+def/g==") == 0, "continue token is kept whole");
    expect(kube_parse_list_meta("{\"metadata\":{\"resourceVersion\":\"9\"},\"items\":[]}", rv,
                                sizeof rv, cont, sizeof cont) == 0,
           "last page");
    expect(strcmp(rv, "9") == 0 && cont[0] == 0, "missing continue is empty");
}

static int pod_155_live(uint32_t ip) {
    return ip == ip4("10.42.7.155");
}

static void test_restart_ip_survives_cleanup(void) {
    char *dir = tmpdir();
    char state[512];
    igmp_runtime *rt;
    uint8_t frame[128];
    uint32_t g = ip4("239.192.14.12");
    uint32_t old = ip4("10.42.7.50");
    uint32_t neu = ip4("10.42.7.155");
    size_t n;
    snprintf(state, sizeof state, "%s/map", dir);
    rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    rt->use_kube = 1;
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "app", "mcast", "ws-g3-160", old, 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "old pod listed");
    n = v2_report(frame, old, g);
    expect(igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 3, 1) == 0, "old ip joined");
    igmp_runtime_set_pod_local_fn(pod_155_live);
    igmp_runtime_pod_upsert(rt, "app", "mcast", "ws-g3-160", neu, 1, 0, 1);
    expect(igmp_engine_find(rt->eng, g, old, 3, NULL) == 0, "previous address is the one removed");
    expect(strcmp(rt->cleanup_reason, "pod-ip-changed") == 0, "ip change names the delete reason");
    n = v2_report(frame, neu, g);
    expect(igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 3, 1) == 0, "new ip joined");
    n = v2_report(frame, neu, ip4("239.192.14.13"));
    expect(igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 3, 1) == 0, "second group joined");
    expect(igmp_engine_joined_count(rt->eng) == 2, "both groups from the new ip");
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "other", "other", "ws-g3-160", ip4("10.42.7.9"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 1, "list missed the restarted pod");
    expect(igmp_engine_find(rt->eng, g, neu, 3, NULL) == 1, "new ip group stays after the list");
    expect(igmp_engine_find(rt->eng, ip4("239.192.14.13"), neu, 3, NULL) == 1,
           "second group stays");
    igmp_runtime_set_pod_local_fn(NULL);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "other", "other", "ws-g3-160", ip4("10.42.7.9"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "pod already absent from the table");
    expect(igmp_engine_find(rt->eng, g, neu, 3, NULL) == 0, "gone once the namespace is gone");
    expect(strcmp(rt->cleanup_reason, "pod-list-absent") == 0, "list absence names the delete reason");

    {
        FILE *fp = fopen(state, "w");
        fprintf(fp, "239.192.14.12 10.42.7.50 0 0\n");
        fprintf(fp, "239.192.14.12 10.42.7.155 0 0\n");
        fclose(fp);
    }
    free(rt->backend);
    igmp_runtime_free(rt);
    rt = make_rt(dir, "ws-g3-160", "10.42.7.110", 0);
    attach_file(rt, state, 0);
    rt->use_kube = 1;
    igmp_runtime_set_pod_local_fn(pod_155_live);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "other", "other", "ws-g3-160", ip4("10.42.7.9"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "list without the new ip");
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, old), "inactive address is still removed");
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, neu), "running new address is not cleared");
    igmp_runtime_set_pod_local_fn(NULL);
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

static void test_unsubscribe_drops_stuck_add(void) {
    char *dir = tmpdir();
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("227.188.0.65");
    mem.subscriber = ip4("10.42.7.50");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "ws-g3-160", ip4("10.42.7.110"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "peer joined");
    igmp_runtime *rt = make_rt(dir, "ws-g3-017", "10.42.1.1", 0);
    fake_be *f = calloc(1, sizeof *f);
    f->fail_at = 2;
    igmp_backend *b = calloc(1, sizeof *b);
    b->load = fake_load;
    b->apply = fake_apply;
    b->user = f;
    rt->backend = b;
    expect(igmp_runtime_reconcile(rt) < 0, "subscriber add fails once");
    expect(has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.110")), "failed plan added the snapshot address");
    char snap[512];
    snprintf(snap, sizeof snap, "%s/ws-g3-160.snap", dir);
    expect(unlink(snap) == 0, "peer unsubscribed");
    igmp_runtime_reconcile(rt);
    expect(rt->stale_dropped == 1, "retry plan dropped when the remote set changed");
    expect(!has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.110")),
           "the failed add is not replayed after unsubscribe");
    expect(has_op(rt, IGMP_OP_GROUP_DEL, 0), "group is deleted on a node with no member");

    expect(igmp_coord_write(dir, "ws-g3-160", ip4("10.42.7.110"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "peer joined again");
    f->fail_at = f->applies + 1;
    f->failed = 0;
    expect(igmp_runtime_reconcile(rt) < 0, "add fails again");
    igmp_ip_rewrite rw;
    memset(&rw, 0, sizeof rw);
    snprintf(rw.name, sizeof rw.name, "%s", "ws-g3-160");
    rw.ip = ip4("10.42.7.178");
    igmp_runtime_set_identities(rt, &rw, 1);
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.178")), "identity change installs CiliumInternalIP");
    expect(!has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.110")), "stale add was not replayed");
    igmp_runtime_free(rt);
    free(f);
    free(b);
    free(dir);
}

static int no_pod_live(uint32_t ip) {
    (void)ip;
    return 0;
}

/* Engine memberships are 0. Cilium still has a departed local endpoint and
 * an old remote node. A fresh snapshot from 160 has to become that node's
 * CiliumInternalIP, and the old rows have to be deleted. */
static void test_empty_engine_replaces_stale_cilium(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/map", dir);
    FILE *fp = fopen(state, "w");
    fputs("239.192.14.12 10.42.5.40 0 0\n", fp);
    fputs("239.192.14.12 10.42.9.9 1 1\n", fp);
    fputs("239.1.1.1 10.42.7.110 1 1\n", fp);
    fclose(fp);
    igmp_snap_mem mem;
    memset(&mem, 0, sizeof mem);
    mem.group = ip4("239.192.14.12");
    mem.subscriber = ip4("10.42.7.155");
    mem.joined = 1;
    expect(igmp_coord_write(dir, "ws-g3-160", ip4("10.42.7.110"), 0, igmp_coord_now_ms(), &mem,
                            1) == 0,
           "160 publishes its current group");
    igmp_runtime *rt = make_rt(dir, "ws-g3-281", "10.42.5.149", 0);
    attach_file(rt, state, 0);
    rt->use_kube = 1;
    rt->mark_from_ledger = 1;
    snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s/ledger", dir);
    igmp_runtime_set_pod_local_fn(no_pod_live);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "other", "other", "ws-g3-281", ip4("10.42.5.9"), 0, 0, 1);
    expect(igmp_runtime_pods_end(rt) == 0, "281 pod list completed without the old ip");
    igmp_ip_rewrite rw;
    memset(&rw, 0, sizeof rw);
    snprintf(rw.name, sizeof rw.name, "%s", "ws-g3-160");
    rw.ip = ip4("10.42.7.110");
    igmp_runtime_set_identities(rt, &rw, 1);
    expect(igmp_engine_joined_count(rt->eng) == 0, "metrics memberships stay 0");
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.5.40")), "departed local endpoint is deleted");
    expect(has_op(rt, IGMP_OP_REMOTE_DEL, ip4("10.42.9.9")), "old remote node is deleted");
    expect(has_op(rt, IGMP_OP_REMOTE_ADD, ip4("10.42.7.110")),
           "160 is installed as its CiliumInternalIP");
    expect(has_op(rt, IGMP_OP_REMOTE_DEL, ip4("10.42.7.110")),
           "160 is removed from a group it no longer publishes");
    expect(igmp_engine_joined_count(rt->eng) == 0, "cleanup does not invent a membership");
    igmp_runtime_set_pod_local_fn(NULL);
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

/* The first reconcile runs before the pod list finishes, so its plan is
 * adds only and does not fit in one pass. After the list completes, that
 * plan must not keep replaying or the old Cilium rows never leave. */
static void test_startup_plan_does_not_block_deletes(void) {
    char *dir = tmpdir();
    char state[512];
    snprintf(state, sizeof state, "%s/map", dir);
    FILE *fp = fopen(state, "w");
    fputs("239.8.0.1 10.42.5.40 0 0\n", fp);
    fclose(fp);
    igmp_runtime *rt = make_rt(dir, "ws-g3-281", "10.42.5.149", 0);
    attach_file(rt, state, 0);
    rt->use_kube = 1;
    rt->mark_from_ledger = 1;
    snprintf(rt->ledger_path, sizeof rt->ledger_path, "%s/ledger", dir);
    igmp_runtime_set_pod_local_fn(no_pod_live);
    igmp_runtime_pods_begin(rt);
    igmp_runtime_pod_upsert(rt, "app", "mcast", "ws-g3-281", ip4("10.8.0.1"), 0, 0, 1);
    uint8_t frame[128];
    for (int i = 1; i <= 12; i++) {
        char gbuf[32];
        snprintf(gbuf, sizeof gbuf, "239.8.0.%d", i);
        rt->now_ms = (int64_t)i * 1000;
        size_t n = v2_report(frame, ip4("10.8.0.1"), ip4(gbuf));
        igmp_runtime_on_frame(rt, frame, n, IGMP_LINK_ETHERNET, 1, 1);
    }
    expect(igmp_engine_joined_count(rt->eng) == 12, "joins recorded before the list ends");
    int first = igmp_runtime_reconcile(rt);
    expect(first == 8, "startup plan is adds and stops at the budget");
    expect(!has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.5.40")),
           "deletes wait until the pod list finishes");
    expect(igmp_runtime_pods_end(rt) == 0, "list keeps the joined pod");
    expect(igmp_engine_joined_count(rt->eng) == 12, "listed pod is not swept");
    igmp_runtime_reconcile(rt);
    expect(has_op(rt, IGMP_OP_LOCAL_DEL, ip4("10.42.5.40")),
           "finished list deletes the departed local endpoint");
    igmp_runtime_set_pod_local_fn(NULL);
    free(rt->backend);
    igmp_runtime_free(rt);
    free(dir);
}

int main(void) {
    test_dry_and_idempotent();
    test_pod_lifecycle();
    test_api_and_iface();
    test_apply_budget();
    test_retry_and_stale();
    test_grace_unmanaged_restart_restore();
    test_refcount_and_querier();
    test_quiet_subscriber_and_queue();
    test_pod_list_without_kind();
    test_snap_clock();
    test_coord_dir_created();
    test_snapshot_field();
    test_solicit_repairs_local();
    test_solicit_covers_every_group();
    test_cilium_internal_identity();
    test_rewrite_remote_identity();
    test_runtime_uses_identity();
    test_toex_and_trie();
    test_leave_is_not_reinjected();
    test_cilium_host_annotation();
    test_already_exists_is_success();
    test_orphan_remote_without_ledger();
    test_departed_local_endpoint();
    test_new_pod_ip_replays_report();
    test_pod_ipv4_not_host_or_podips_key();
    test_list_meta_ignores_pod_version();
    test_restart_ip_survives_cleanup();
    test_unsubscribe_drops_stuck_add();
    test_empty_engine_replaces_stale_cilium();
    test_startup_plan_does_not_block_deletes();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
