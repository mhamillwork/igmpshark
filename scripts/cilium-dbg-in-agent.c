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

static int find_agent(void) {
    DIR *d = opendir("/proc");
    if (!d) {
        fprintf(stderr, "open /proc: %s\n", strerror(errno));
        return -1;
    }
    struct dirent *de;
    int pid = -1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;
        char path[300], comm[32];
        snprintf(path, sizeof path, "/proc/%s/comm", de->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp)
            continue;
        if (!fgets(comm, sizeof comm, fp)) {
            fclose(fp);
            continue;
        }
        fclose(fp);
        size_t n = strlen(comm);
        if (n > 0 && comm[n - 1] == '\n')
            comm[n - 1] = 0;
        if (strcmp(comm, "cilium-agent") == 0) {
            pid = atoi(de->d_name);
            break;
        }
    }
    closedir(d);
    return pid;
}

int main(int argc, char **argv) {
    int agent = find_agent();
    if (agent <= 0) {
        fprintf(stderr, "cilium-agent process not found; hostPID is required\n");
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
