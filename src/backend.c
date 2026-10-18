#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "backend.h"

#include <errno.h>
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

static int run_argv(char *const argv[], char *out, size_t outlen, int timeout_ms) {
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -1;
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
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    int64_t deadline = mono_ms() + (timeout_ms > 0 ? timeout_ms : 3000);
    int status = 0;
    int done = 0;
    while (!done) {
        int left = (int)(deadline - mono_ms());
        if (left < 0)
            left = 0;
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        int pr = poll(&pfd, 1, left);
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            if (used + 1 < outlen) {
                ssize_t r = read(pipefd[0], out + used, outlen - 1 - used);
                if (r > 0)
                    used += (size_t)r;
                else
                    done = 1;
            } else {
                char junk[256];
                if (read(pipefd[0], junk, sizeof junk) <= 0)
                    done = 1;
            }
        }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            done = 1;
        if (mono_ms() >= deadline && !done) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            out[used] = 0;
            return -1;
        }
        if (pr == 0 && w == 0 && mono_ms() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            out[used] = 0;
            return -1;
        }
    }
    out[used] = 0;
    close(pipefd[0]);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
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
