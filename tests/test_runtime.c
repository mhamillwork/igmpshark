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
    expect(igmp_coord_write(dir, "n2", ip4("10.244.1.1"), 0, 0, &mem, 1) == 0, "peer snap");
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
    igmp_coord_write(dir, "low", ip4("10.244.0.1"), 1, 0, NULL, 0);
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
    igmp_runtime_free(rt);
    free(dir);
}

static int keep_pod(void *user, const kube_event *ev) {
    kube_event *slot = user;
    if (ev->kind == KUBE_EV_UPSERT && strcmp(ev->name, "repbox-0") == 0)
        *slot = *ev;
    return 0;
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

int main(void) {
    test_dry_and_idempotent();
    test_pod_lifecycle();
    test_api_and_iface();
    test_retry_and_stale();
    test_grace_unmanaged_restart_restore();
    test_refcount_and_querier();
    test_quiet_subscriber_and_queue();
    test_pod_list_without_kind();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
