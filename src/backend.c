#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "backend.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int file_load(igmp_backend *b, igmp_actual *rows, int cap) {
    FILE *fp = fopen((const char *)b->user, "r");
    if (!fp)
        return 0;
    int n = 0;
    char gbuf[64], abuf[64];
    int remote, managed;
    while (n < cap && fscanf(fp, "%63s %63s %d %d", gbuf, abuf, &remote, &managed) == 4) {
        uint32_t g = 0, a = 0;
        if (igmp_ip_parse(gbuf, &g) != 0 || igmp_ip_parse(abuf, &a) != 0)
            continue;
        rows[n].group = g;
        rows[n].addr = a;
        rows[n].remote = remote;
        rows[n].managed = managed;
        n++;
    }
    fclose(fp);
    return n;
}

static int file_write_all(const char *path, const igmp_actual *rows, int n) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    for (int i = 0; i < n; i++) {
        char g[32], a[32];
        fprintf(fp, "%s %s %d %d\n", igmp_ip_fmt(rows[i].group, g, sizeof g),
                igmp_ip_fmt(rows[i].addr, a, sizeof a), rows[i].remote, rows[i].managed);
    }
    if (fclose(fp) != 0)
        return -1;
    if (rename(tmp, path) != 0)
        return -1;
    return 0;
}

static int file_apply(igmp_backend *b, const igmp_op *op) {
    if (b->dry_run)
        return 0;
    igmp_actual rows[512];
    int n = file_load(b, rows, 512);
    if (op->op == IGMP_OP_GROUP_ADD) {
        for (int i = 0; i < n; i++)
            if (rows[i].group == op->group)
                return 0;
        if (n >= 512)
            return -1;
        rows[n].group = op->group;
        rows[n].addr = 0;
        rows[n].remote = 1;
        rows[n].managed = 1;
        n++;
    } else if (op->op == IGMP_OP_GROUP_DEL) {
        int w = 0;
        for (int i = 0; i < n; i++)
            if (!(rows[i].managed && rows[i].group == op->group))
                rows[w++] = rows[i];
        n = w;
    } else if (op->op == IGMP_OP_REMOTE_ADD || op->op == IGMP_OP_LOCAL_DEL ||
               op->op == IGMP_OP_REMOTE_DEL) {
        int remote = op->op == IGMP_OP_LOCAL_DEL ? 0 : 1;
        if (op->op == IGMP_OP_REMOTE_ADD) {
            for (int i = 0; i < n; i++)
                if (rows[i].group == op->group && rows[i].addr == op->addr && rows[i].remote)
                    return 0;
            if (n >= 512)
                return -1;
            rows[n].group = op->group;
            rows[n].addr = op->addr;
            rows[n].remote = 1;
            rows[n].managed = 1;
            n++;
        } else {
            int w = 0;
            for (int i = 0; i < n; i++) {
                int match = rows[i].group == op->group && rows[i].addr == op->addr &&
                            rows[i].remote == remote;
                if (!match)
                    rows[w++] = rows[i];
            }
            n = w;
        }
    }
    return file_write_all((const char *)b->user, rows, n);
}

int backend_file_open(igmp_backend *b, const char *path, int dry_run) {
    memset(b, 0, sizeof *b);
    b->load = file_load;
    b->apply = file_apply;
    b->user = (void *)path;
    b->dry_run = dry_run;
    return 0;
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void flatten_output(char *out, size_t *used) {
    size_t w = 0;
    for (size_t i = 0; i < *used; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c == '\n' || c == '\r' || c == '\t' || c == '"')
            c = ' ';
        if (c < 0x20)
            continue;
        if (c == ' ' && (w == 0 || out[w - 1] == ' '))
            continue;
        out[w++] = (char)c;
    }
    while (w > 0 && out[w - 1] == ' ')
        w--;
    out[w] = 0;
    *used = w;
}

static void note_status(char *out, size_t outlen, size_t used, int status, int timed_out) {
    flatten_output(out, &used);
    if (used + 1 >= outlen)
        return;
    if (timed_out)
        snprintf(out + used, outlen - used, "%stimed out", used ? " | " : "");
    else if (WIFSIGNALED(status))
        snprintf(out + used, outlen - used, "%ssignal %d", used ? " | " : "", WTERMSIG(status));
    else if (WIFEXITED(status))
        snprintf(out + used, outlen - used, "%sexit %d", used ? " | " : "", WEXITSTATUS(status));
    else
        snprintf(out + used, outlen - used, "%sstatus %d", used ? " | " : "", status);
}

static int run_argv(char *const argv[], char *out, size_t outlen, int timeout_ms) {
    int pipefd[2];
    if (outlen == 0)
        return -1;
    out[0] = 0;
    if (pipe(pipefd) != 0)
        return -1;
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0)
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "exec %s: %s", argv[0] ? argv[0] : "", strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    int64_t deadline = mono_ms() + (timeout_ms > 0 ? timeout_ms : 3000);
    int status = 0;
    int done = 0;
    int timed_out = 0;
    while (!done) {
        int left = (int)(deadline - mono_ms());
        if (left < 0)
            left = 0;
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        int pr = poll(&pfd, 1, left > 200 ? 200 : left);
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            if (used + 1 < outlen) {
                ssize_t r = read(pipefd[0], out + used, outlen - 1 - used);
                if (r > 0)
                    used += (size_t)r;
            } else {
                char junk[256];
                if (read(pipefd[0], junk, sizeof junk) < 0 && errno != EAGAIN)
                    done = 1;
            }
        }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            for (;;) {
                if (used + 1 >= outlen)
                    break;
                ssize_t r = read(pipefd[0], out + used, outlen - 1 - used);
                if (r > 0)
                    used += (size_t)r;
                else
                    break;
            }
            done = 1;
        }
        if (!done && mono_ms() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            timed_out = 1;
            done = 1;
        }
    }
    out[used] = 0;
    close(pipefd[0]);
    if (!timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;
    note_status(out, outlen, used, status, timed_out);
    return -1;
}

typedef struct cli_ctx {
    char bin[256];
    char ledger[512];
    int timeout_ms;
} cli_ctx;

/* Cilium 1.19 prints the remote type as "Remote Node". The first token is
 * enough: anything starting with "R" is a CiliumNode address, not a pod. */
int igmp_parse_cilium_subscribers(const char *text, igmp_actual *rows, int cap) {
    if (!text || !rows || cap < 1)
        return -1;
    int n = 0;
    const char *p = text;
    while (*p && n < cap) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[256];
        if (len >= sizeof line)
            len = sizeof line - 1;
        memcpy(line, p, len);
        line[len] = 0;
        char a[64] = "", b[64] = "", c[64] = "";
        int nf = sscanf(line, "%63s %63s %63s", a, b, c);
        uint32_t g = 0, addr = 0;
        if (nf >= 1 && igmp_ip_parse(a, &g) == 0 && igmp_group_routable(g)) {
            if (nf >= 2 && igmp_ip_parse(b, &addr) == 0) {
                rows[n].group = g;
                rows[n].addr = addr;
                rows[n].remote = (c[0] == 'R' || c[0] == 'r') ? 1 : 0;
                if (nf < 3)
                    rows[n].remote = 1;
                rows[n].managed = 0;
                n++;
            } else if (nf == 1) {
                rows[n].group = g;
                rows[n].addr = 0;
                rows[n].remote = 1;
                rows[n].managed = 0;
                n++;
            }
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return n;
}

static const char *json_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t'))
        p++;
    return p;
}

static const char *json_string(const char *p, const char *end, char *out, size_t cap) {
    if (out && cap)
        out[0] = 0;
    if (p >= end || *p != '"')
        return p;
    p++;
    size_t n = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end)
            p++;
        if (out && n + 1 < cap)
            out[n++] = *p;
        p++;
    }
    if (out && cap)
        out[n < cap ? n : cap - 1] = 0;
    if (p < end && *p == '"')
        p++;
    return p;
}

static const char *json_skip(const char *p, const char *end) {
    p = json_ws(p, end);
    if (p >= end)
        return p;
    if (*p == '"')
        return json_string(p, end, NULL, 0);
    if (*p == '{' || *p == '[') {
        int depth = 0;
        int in_str = 0;
        while (p < end) {
            if (in_str) {
                if (*p == '\\' && p + 1 < end) {
                    p += 2;
                    continue;
                }
                if (*p == '"')
                    in_str = 0;
                p++;
                continue;
            }
            if (*p == '"') {
                in_str = 1;
                p++;
                continue;
            }
            if (*p == '{' || *p == '[')
                depth++;
            else if (*p == '}' || *p == ']') {
                depth--;
                p++;
                if (depth == 0)
                    return p;
                continue;
            }
            p++;
        }
        return p;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']')
        p++;
    return p;
}

/* Value of a direct key of the object that starts at `obj`. */
static const char *json_key(const char *obj, const char *end, const char *want, const char **vend) {
    if (!obj || obj >= end || *obj != '{')
        return NULL;
    const char *p = obj + 1;
    while (p < end) {
        p = json_ws(p, end);
        if (p >= end || *p == '}')
            return NULL;
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p != '"')
            return NULL;
        char key[64];
        p = json_string(p, end, key, sizeof key);
        p = json_ws(p, end);
        if (p < end && *p == ':')
            p++;
        p = json_ws(p, end);
        const char *v = p;
        const char *ve = json_skip(p, end);
        if (strcmp(key, want) == 0) {
            if (vend)
                *vend = ve;
            return v;
        }
        p = ve;
    }
    return NULL;
}

static int cidr_has(uint32_t ip, uint32_t base, int prefix) {
    if (prefix >= 32)
        return ip == base;
    if (prefix <= 0)
        return 1;
    uint32_t mask = 0xffffffffu << (32 - prefix);
    return (ip & mask) == (base & mask);
}

static void addressing_ipv4(const char *obj, const char *end, uint32_t *ip, uint32_t *base,
                            int *prefix) {
    const char *ve = NULL;
    const char *v4 = json_key(obj, end, "ipv4", &ve);
    if (!v4 || v4 >= end || *v4 != '{')
        return;
    const char *ie = NULL;
    const char *is = json_key(v4, ve, "ip", &ie);
    if (is && ip) {
        char s[64];
        json_string(is, ie ? ie : ve, s, sizeof s);
        uint32_t v = 0;
        if (igmp_ip_parse(s, &v) == 0)
            *ip = v;
    }
    if (!base || !prefix)
        return;
    const char *ce = NULL;
    const char *cs = json_key(v4, ve, "alloc-range", &ce);
    if (!cs)
        return;
    char s[64];
    json_string(cs, ce ? ce : ve, s, sizeof s);
    char *slash = strchr(s, '/');
    if (!slash)
        return;
    *slash = 0;
    uint32_t b = 0;
    int pre = atoi(slash + 1);
    if (igmp_ip_parse(s, &b) == 0 && pre >= 0 && pre <= 32) {
        *base = b;
        *prefix = pre;
    }
}

static const char *enclosing_object(const char *begin, const char *pos) {
    int depth = 0;
    const char *p = pos;
    while (p > begin) {
        p--;
        if (*p == '"') {
            const char *q = p;
            while (q > begin) {
                q--;
                if (*q != '"')
                    continue;
                int bs = 0;
                const char *b = q;
                while (b > begin && b[-1] == '\\') {
                    bs++;
                    b--;
                }
                if ((bs % 2) == 0) {
                    p = q;
                    break;
                }
            }
            continue;
        }
        if (*p == '}')
            depth++;
        else if (*p == '{') {
            if (depth == 0)
                return p;
            depth--;
        }
    }
    return NULL;
}

static const char *object_end(const char *start, const char *limit) {
    if (!start || *start != '{')
        return NULL;
    return json_skip(start, limit);
}

static void fill_node(const char *obj, const char *end, igmp_cilium_node *n) {
    memset(n, 0, sizeof *n);
    const char *ve = NULL;
    const char *name = json_key(obj, end, "name", &ve);
    if (name)
        json_string(name, ve ? ve : end, n->name, sizeof n->name);
    ve = NULL;
    const char *prim = json_key(obj, end, "primary-address", &ve);
    uint32_t base = 0;
    int prefix = -1;
    if (prim && *prim == '{')
        addressing_ipv4(prim, ve, &n->primary, &base, &prefix);
    ve = NULL;
    const char *health = json_key(obj, end, "health-endpoint-address", &ve);
    if (health && *health == '{')
        addressing_ipv4(health, ve, &n->health, NULL, NULL);
    ve = NULL;
    uint32_t ingress = 0;
    const char *ing = json_key(obj, end, "ingress-address", &ve);
    if (ing && *ing == '{')
        addressing_ipv4(ing, ve, &ingress, NULL, NULL);
    uint32_t sec[8];
    int nsec = 0;
    ve = NULL;
    const char *arr = json_key(obj, end, "secondary-addresses", &ve);
    if (arr && *arr == '[') {
        const char *p = arr + 1;
        const char *ae = ve ? ve : end;
        while (p < ae && nsec < 8) {
            p = json_ws(p, ae);
            if (p >= ae || *p == ']')
                break;
            if (*p == ',') {
                p++;
                continue;
            }
            if (*p != '{') {
                p++;
                continue;
            }
            const char *oe = json_skip(p, ae);
            const char *ie = NULL;
            const char *ip = json_key(p, oe, "ip", &ie);
            if (ip) {
                char s[64];
                json_string(ip, ie ? ie : oe, s, sizeof s);
                if (igmp_ip_parse(s, &sec[nsec]) == 0)
                    nsec++;
            }
            p = oe;
        }
    }
    for (int i = 0; i < nsec; i++) {
        uint32_t ip = sec[i];
        if (ip == 0 || ip == n->primary || ip == n->health || ip == ingress)
            continue;
        if (prefix >= 0 && !cidr_has(ip, base, prefix))
            continue;
        n->internal = ip;
        break;
    }
}

int igmp_parse_cilium_nodes(const char *text, igmp_cilium_node *out, int cap) {
    if (!text || !out || cap < 1)
        return -1;
    int n = 0;
    const char *end = text + strlen(text);
    const char *p = text;
    while (p < end && n < cap) {
        const char *hit = strstr(p, "\"name\"");
        if (!hit || hit >= end)
            break;
        const char *after = json_ws(hit + 6, end);
        if (after >= end || *after != ':') {
            p = hit + 6;
            continue;
        }
        const char *obj = enclosing_object(text, hit);
        if (!obj) {
            p = hit + 6;
            continue;
        }
        const char *oe = object_end(obj, end);
        if (!oe) {
            p = hit + 6;
            continue;
        }
        igmp_cilium_node node;
        fill_node(obj, oe, &node);
        if (node.name[0])
            out[n++] = node;
        p = oe;
    }
    return n;
}

int igmp_cilium_node_list(const char *bin, char *out, size_t outlen, int timeout_ms) {
    char b[256];
    snprintf(b, sizeof b, "%s", bin && bin[0] ? bin : "cilium-dbg");
    char *argv[] = {b, "node", "list", "-o", "json", NULL};
    return run_argv(argv, out, outlen, timeout_ms > 0 ? timeout_ms : 3000);
}

static int ledger_load(const char *path, igmp_actual *rows, int cap) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    int n = 0;
    char gbuf[64], abuf[64];
    int remote = 0;
    while (n < cap && fscanf(fp, "%63s %63s %d", gbuf, abuf, &remote) == 3) {
        if (igmp_ip_parse(gbuf, &rows[n].group) != 0 || igmp_ip_parse(abuf, &rows[n].addr) != 0)
            continue;
        rows[n].remote = remote;
        rows[n].managed = 1;
        n++;
    }
    fclose(fp);
    return n;
}

static int ledger_store(const char *path, const igmp_actual *rows, int n) {
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    for (int i = 0; i < n; i++) {
        char g[32], a[32];
        fprintf(fp, "%s %s %d\n", igmp_ip_fmt(rows[i].group, g, sizeof g),
                igmp_ip_fmt(rows[i].addr, a, sizeof a), rows[i].remote);
    }
    if (fclose(fp) != 0)
        return -1;
    return rename(tmp, path);
}

int igmp_ledger_has(const char *path, uint32_t group, uint32_t addr, int remote) {
    igmp_actual rows[1024];
    int n = ledger_load(path, rows, 1024);
    for (int i = 0; i < n; i++)
        if (rows[i].group == group && rows[i].addr == addr && rows[i].remote == remote)
            return 1;
    return 0;
}

int igmp_ledger_add(const char *path, uint32_t group, uint32_t addr, int remote) {
    if (!path || !path[0])
        return -1;
    igmp_actual rows[1024];
    int n = ledger_load(path, rows, 1024);
    for (int i = 0; i < n; i++)
        if (rows[i].group == group && rows[i].addr == addr && rows[i].remote == remote)
            return 0;
    if (n >= 1024)
        return -1;
    rows[n].group = group;
    rows[n].addr = addr;
    rows[n].remote = remote;
    rows[n].managed = 1;
    return ledger_store(path, rows, n + 1);
}

int igmp_ledger_del(const char *path, uint32_t group, uint32_t addr, int remote) {
    if (!path || !path[0])
        return -1;
    igmp_actual rows[1024];
    int n = ledger_load(path, rows, 1024);
    int w = 0;
    for (int i = 0; i < n; i++) {
        int match = rows[i].group == group && rows[i].addr == addr && rows[i].remote == remote;
        if (!match)
            rows[w++] = rows[i];
    }
    return ledger_store(path, rows, w);
}

static int cli_apply(igmp_backend *b, const igmp_op *op) {
    if (b->dry_run)
        return 0;
    cli_ctx *ctx = b->user;
    char group[32], addr[32];
    igmp_ip_fmt(op->group, group, sizeof group);
    igmp_ip_fmt(op->addr, addr, sizeof addr);
    char *argv[8];
    argv[0] = ctx->bin;
    argv[1] = "bpf";
    argv[2] = "multicast";
    if (op->op == IGMP_OP_GROUP_ADD || op->op == IGMP_OP_GROUP_DEL) {
        argv[3] = "group";
        argv[4] = op->op == IGMP_OP_GROUP_ADD ? "add" : "delete";
        argv[5] = group;
        argv[6] = NULL;
    } else {
        argv[3] = "subscriber";
        argv[4] = (op->op == IGMP_OP_REMOTE_ADD) ? "add" : "delete";
        argv[5] = group;
        argv[6] = addr;
        argv[7] = NULL;
    }
    char buf[1024];
    if (run_argv(argv, buf, sizeof buf, ctx->timeout_ms) != 0) {
        b->failures++;
        snprintf(b->err, sizeof b->err, "cilium command failed: %.180s", buf);
        return -1;
    }
    return 0;
}

static int cli_load(igmp_backend *b, igmp_actual *rows, int cap) {
    cli_ctx *ctx = b->user;
    char buf[1 << 16];
    char *list_argv[] = {ctx->bin, "bpf", "multicast", "subscriber", "list", "all", NULL};
    if (run_argv(list_argv, buf, sizeof buf, ctx->timeout_ms) != 0) {
        b->failures++;
        snprintf(b->err, sizeof b->err, "cilium list failed: %.180s", buf);
        return -1;
    }
    int n = igmp_parse_cilium_subscribers(buf, rows, cap);
    if (n < 0)
        return -1;
    char gbuf[1 << 15];
    char *group_argv[] = {ctx->bin, "bpf", "multicast", "group", "list", NULL};
    if (run_argv(group_argv, gbuf, sizeof gbuf, ctx->timeout_ms) == 0 && n < cap) {
        igmp_actual extra[256];
        int ne = igmp_parse_cilium_subscribers(gbuf, extra, 256);
        for (int i = 0; i < ne && n < cap; i++) {
            int seen = 0;
            for (int j = 0; j < n; j++)
                if (rows[j].group == extra[i].group)
                    seen = 1;
            if (!seen)
                rows[n++] = extra[i];
        }
    }
    return n;
}

int backend_cli_open(igmp_backend *b, const char *argv0, const char *ledger_path, int dry_run,
                     int timeout_ms) {
    memset(b, 0, sizeof *b);
    cli_ctx *ctx = calloc(1, sizeof *ctx);
    if (!ctx)
        return -1;
    snprintf(ctx->bin, sizeof ctx->bin, "%s", argv0 && argv0[0] ? argv0 : "cilium-dbg");
    if (ledger_path)
        snprintf(ctx->ledger, sizeof ctx->ledger, "%s", ledger_path);
    ctx->timeout_ms = timeout_ms > 0 ? timeout_ms : 3000;
    b->load = cli_load;
    b->apply = cli_apply;
    b->user = ctx;
    b->dry_run = dry_run;
    return 0;
}

void backend_cli_close(igmp_backend *b) {
    free(b->user);
    b->user = NULL;
}
