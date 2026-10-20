#define _GNU_SOURCE
/* Run cilium-dbg in the Cilium agent's namespaces.
 *
 * bpf multicast reads /proc/self/mountinfo to find the agent's bpffs.
 * The agent's /proc belongs to its PID namespace. Entering that mount
 * namespace without a matching procfs makes the open fail:
 * "could not get mount info for map root lookup".
 * Remount proc in a private mount namespace so the agent's own /proc
 * is left alone.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int open_ns(int pid, const char *which) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/%s", pid, which);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    return fd;
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = 0;
}

static void sanitize(char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 32 || c > 126 || c == '"' || c == '\\')
            *s = '?';
    }
}

static int read_text(const char *path, char *out, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, (int)cap, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    trim(out);
    return out[0] ? 0 : -1;
}

static const char *base_name(const char *path) {
    const char *b = strrchr(path, '/');
    return b ? b + 1 : path;
}

/* argv0 or the executable, ignoring a " (deleted)" suffix from readlink. */
static int named_agent(const char *path) {
    char buf[300];
    snprintf(buf, sizeof buf, "%s", path);
    char *del = strstr(buf, " (deleted)");
    if (del)
        *del = 0;
    trim(buf);
    return strcmp(base_name(buf), "cilium-agent") == 0;
}

static int is_agent(const char *pidstr) {
    char path[300], comm[64], cmd[512], exe[300];
    snprintf(path, sizeof path, "/proc/%s/comm", pidstr);
    if (read_text(path, comm, sizeof comm) == 0 && strcmp(comm, "cilium-agent") == 0)
        return 1;
    snprintf(path, sizeof path, "/proc/%s/cmdline", pidstr);
    FILE *fp = fopen(path, "r");
    if (fp) {
        size_t n = fread(cmd, 1, sizeof cmd - 1, fp);
        fclose(fp);
        cmd[n] = 0;
        if (n > 0 && named_agent(cmd))
            return 1;
    }
    snprintf(path, sizeof path, "/proc/%s/exe", pidstr);
    ssize_t elen = readlink(path, exe, sizeof exe - 1);
    if (elen > 0) {
        exe[elen] = 0;
        if (named_agent(exe))
            return 1;
    }
    return 0;
}

static int find_agent(int *visible) {
    if (visible)
        *visible = 0;
    DIR *d = opendir("/proc");
    if (!d) {
        fprintf(stderr, "open /proc: %s\n", strerror(errno));
        if (visible)
            *visible = -1;
        return -1;
    }
    struct dirent *de;
    int pid = -1;
    int nproc = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;
        nproc++;
        if (pid > 0)
            continue;
        if (is_agent(de->d_name))
            pid = atoi(de->d_name);
    }
    closedir(d);
    if (visible)
        *visible = nproc;
    return pid;
}

static void report_missing(int visible) {
    char pid1[64] = "unreadable";
    if (read_text("/proc/1/comm", pid1, sizeof pid1) != 0)
        snprintf(pid1, sizeof pid1, "unreadable");
    sanitize(pid1);
    /* A container that did not join the host PID namespace has a tiny /proc
     * and pid 1 is igmpshark. A host /proc has pid 1 as systemd and hundreds
     * of tasks; the cilium pod on this node is then simply not running. */
    int hostish = strcmp(pid1, "systemd") == 0 || strcmp(pid1, "init") == 0;
    if (!hostish && visible < 80) {
        fprintf(stderr,
                "cilium-agent process not found; hostPID is required (pid 1 is %s, %d processes visible)\n",
                pid1, visible);
        return;
    }
    fprintf(stderr,
            "cilium-agent process not found (pid 1 is %s, %d processes visible; no cilium-agent on this node)\n",
            pid1, visible);
}

int main(int argc, char **argv) {
    int visible = 0;
    int agent = find_agent(&visible);
    if (agent <= 0) {
        if (visible >= 0)
            report_missing(visible);
        return 1;
    }
    int mnt = open_ns(agent, "mnt");
    int net = open_ns(agent, "net");
    int pidns = open_ns(agent, "pid");
    if (mnt < 0 || net < 0 || pidns < 0)
        return 1;
    if (setns(mnt, CLONE_NEWNS) != 0 || setns(net, CLONE_NEWNET) != 0 ||
        setns(pidns, CLONE_NEWPID) != 0) {
        fprintf(stderr, "setns: %s\n", strerror(errno));
        return 1;
    }
    close(mnt);
    close(net);
    close(pidns);

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return 1;
    }
    if (child > 0) {
        int status = 0;
        if (waitpid(child, &status, 0) < 0)
            return 1;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);
        return 1;
    }

    /* Parent lives outside this PID namespace. Die with it if the caller
     * hits the command timeout and kills the wrapper. */
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    if (unshare(CLONE_NEWNS) != 0) {
        fprintf(stderr, "unshare mount: %s\n", strerror(errno));
        return 1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fprintf(stderr, "make mounts private: %s\n", strerror(errno));
        return 1;
    }
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        fprintf(stderr, "mount proc: %s\n", strerror(errno));
        return 1;
    }

    const char *dbg = getenv("CILIUM_DBG_IN_AGENT");
    if (!dbg || !dbg[0])
        dbg = "/usr/bin/cilium-dbg";
    char **args = calloc((size_t)argc + 1, sizeof *args);
    if (!args)
        return 1;
    args[0] = (char *)dbg;
    for (int i = 1; i < argc; i++)
        args[i] = argv[i];
    execv(dbg, args);
    fprintf(stderr, "exec %s: %s\n", dbg, strerror(errno));
    return 127;
}
