#ifndef IGMPSHARK_BACKEND_H
#define IGMPSHARK_BACKEND_H

#include "reconcile.h"

typedef struct igmp_backend igmp_backend;

struct igmp_backend {
    int (*load)(igmp_backend *b, igmp_actual *rows, int cap);
    int (*apply)(igmp_backend *b, const igmp_op *op);
    void *user;
    int dry_run;
    int failures;
    char err[256];
};

int backend_file_open(igmp_backend *b, const char *path, int dry_run);
int backend_cli_open(igmp_backend *b, const char *argv0, const char *ledger_path, int dry_run,
                     int timeout_ms);
void backend_cli_close(igmp_backend *b);

int igmp_ledger_add(const char *path, uint32_t group, uint32_t addr, int remote);
int igmp_ledger_del(const char *path, uint32_t group, uint32_t addr, int remote);
int igmp_ledger_has(const char *path, uint32_t group, uint32_t addr, int remote);

/* Parse `cilium-dbg bpf multicast subscriber list` text. Managed is left 0;
 * the caller marks rows it owns. Returns the number of rows, or -1. */
int igmp_parse_cilium_subscribers(const char *text, igmp_actual *rows, int cap);

#endif
