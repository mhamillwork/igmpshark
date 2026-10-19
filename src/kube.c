#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "kube.h"
#include "kube_parse.h"

#include "igmp_types.h"

#include <curl/curl.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KUBE_Q 256

struct kube_client {
    pthread_t thread;
    pthread_mutex_t mu;
    int stop;
    int started;
    kube_event q[KUBE_Q];
    int qh;
    int qn;
    uint64_t drops;
    char host[128];
    char port[16];
    char ns[128];
    char token[8192];
    char ca[256];
    char node_filter[64];
};

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} buf;

static size_t buf_write(char *ptr, size_t size, size_t nmemb, void *ud) {
    buf *b = ud;
    size_t n = size * nmemb;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 65536;
        while (nc < b->len + n + 1)
            nc *= 2;
        if (nc > (32u << 20))
            return 0;
        char *p = realloc(b->data, nc);
        if (!p)
            return 0;
        b->data = p;
        b->cap = nc;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = 0;
    return n;
}

static int read_file(const char *path, char *out, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    size_t n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        n--;
    out[n] = 0;
    return 0;
}

static int kube_setup_easy(kube_client *k, CURL *c, const char *url, buf *body) {
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_CAINFO, k->ca);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, buf_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, body);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
    struct curl_slist *hdr = NULL;
    char auth[8400];
    snprintf(auth, sizeof auth, "Authorization: Bearer %s", k->token);
    hdr = curl_slist_append(hdr, auth);
    hdr = curl_slist_append(hdr, "Accept: application/json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    return 0;
}

static void push_ev(kube_client *k, const kube_event *ev) {
    pthread_mutex_lock(&k->mu);
    if (k->qn >= KUBE_Q) {
        k->drops++;
        k->stop = k->stop;
        pthread_mutex_unlock(&k->mu);
        return;
    }
    k->q[(k->qh + k->qn) % KUBE_Q] = *ev;
    k->qn++;
    pthread_mutex_unlock(&k->mu);
}

static void push_kind(kube_client *k, int kind) {
    kube_event ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = kind;
    push_ev(k, &ev);
}

static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}

static int parse_string(const char **pp, char *out, size_t cap) {
    const char *p = skip_ws(*pp);
    if (*p != '"')
        return -1;
    p++;
    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char e = *p++;
            if (e == 'n')
                c = '\n';
            else if (e == 't')
                c = '\t';
            else if (e == 'u') {
                p += 4;
                c = '?';
            } else
                c = e;
        }
        if (n + 1 < cap)
            out[n++] = c;
    }
    if (*p != '"')
        return -1;
    out[n] = 0;
    *pp = p + 1;
    return 0;
}

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int b64_decode(const char *in, char *out, size_t cap) {
    int val = 0, valb = -8;
    size_t n = 0;
    for (const char *p = in; *p && *p != '='; p++) {
        int d = b64_val((unsigned char)*p);
        if (d < 0)
            continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            if (n + 1 >= cap)
                return -1;
            out[n++] = (char)((val >> valb) & 0xff);
            valb -= 8;
        }
    }
    out[n] = 0;
    return (int)n;
}

static int b64_encode(const char *in, size_t len, char *out, size_t cap) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = (unsigned char)in[i] << 16;
        if (i + 1 < len)
            v |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < len)
            v |= (unsigned char)in[i + 2];
        char chunk[4];
        chunk[0] = t[(v >> 18) & 63];
        chunk[1] = t[(v >> 12) & 63];
        chunk[2] = i + 1 < len ? t[(v >> 6) & 63] : '=';
        chunk[3] = i + 2 < len ? t[v & 63] : '=';
        if (n + 4 >= cap)
            return -1;
        memcpy(out + n, chunk, 4);
        n += 4;
    }
    out[n] = 0;
    return (int)n;
}

static int push_parsed(void *user, const kube_event *ev) {
    push_ev(user, ev);
    return 0;
}

static void scan_items(kube_client *k, const char *json) {
    kube_parse_pod_list(json, push_parsed, k);
}

static void scan_watch_line(kube_client *k, const char *line) {
    kube_event ev;
    if (kube_parse_watch_line(line, &ev))
        push_ev(k, &ev);
}

static int http_get(kube_client *k, const char *url, long *code, buf *body) {
    CURL *c = curl_easy_init();
    if (!c)
        return -1;
    body->data = NULL;
    body->len = 0;
    body->cap = 0;
    kube_setup_easy(k, c, url, body);
    CURLcode rc = curl_easy_perform(c);
    if (rc == CURLE_OK)
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, code);
    struct curl_slist *hdr = NULL;
    curl_easy_getinfo(c, CURLINFO_PRIVATE, &hdr);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK) {
        free(body->data);
        body->data = NULL;
        return -1;
    }
    return 0;
}

static void *kube_thread(void *arg) {
    kube_client *k = arg;
    char rv[128] = "0";
    while (!k->stop) {
        char url[512];
        snprintf(url, sizeof url, "https://%s:%s/api/v1/pods?limit=500&resourceVersion=%s", k->host,
                 k->port, rv);
        buf body;
        long code = 0;
        if (http_get(k, url, &code, &body) != 0 || code != 200) {
            push_kind(k, KUBE_EV_API_DOWN);
            free(body.data);
            for (int i = 0; i < 20 && !k->stop; i++)
                usleep(100000);
            continue;
        }
        const char *rvpos = strstr(body.data ? body.data : "", "\"resourceVersion\"");
        if (rvpos) {
            const char *p = strchr(rvpos, ':');
            char tmp[128];
            if (p) {
                p = skip_ws(p + 1);
                if (parse_string(&p, tmp, sizeof tmp) == 0)
                    snprintf(rv, sizeof rv, "%s", tmp);
            }
        }
        push_kind(k, KUBE_EV_API_UP);
        push_kind(k, KUBE_EV_BEGIN);
        scan_items(k, body.data ? body.data : "");
        push_kind(k, KUBE_EV_END);
        free(body.data);
        snprintf(url, sizeof url,
                 "https://%s:%s/api/v1/pods?watch=1&resourceVersion=%s&timeoutSeconds=25", k->host,
                 k->port, rv);
        CURL *c = curl_easy_init();
        if (!c)
            continue;
        buf watch;
        memset(&watch, 0, sizeof watch);
        kube_setup_easy(k, c, url, &watch);
        curl_easy_perform(c);
        long wcode = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &wcode);
        curl_easy_cleanup(c);
        if (wcode == 410) {
            snprintf(rv, sizeof rv, "0");
            free(watch.data);
            continue;
        }
        if (watch.data) {
            char *save = NULL;
            for (char *line = strtok_r(watch.data, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
                scan_watch_line(k, line);
            free(watch.data);
        }
        if (wcode != 200)
            push_kind(k, KUBE_EV_API_DOWN);
    }
    return NULL;
}

static int load_identity(kube_client *k) {
    const char *host = getenv("KUBERNETES_SERVICE_HOST");
    const char *port = getenv("KUBERNETES_SERVICE_PORT");
    if (!host || !port)
        return -1;
    snprintf(k->host, sizeof k->host, "%s", host);
    snprintf(k->port, sizeof k->port, "%s", port);
    snprintf(k->ca, sizeof k->ca, "%s",
             "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
    if (read_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace", k->ns, sizeof k->ns) != 0)
        return -1;
    if (read_file("/var/run/secrets/kubernetes.io/serviceaccount/token", k->token, sizeof k->token) != 0)
        return -1;
    return 0;
}

int kube_client_start(kube_client **out) {
    kube_client *k = calloc(1, sizeof *k);
    if (!k)
        return -1;
    if (load_identity(k) != 0) {
        free(k);
        return -1;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    pthread_mutex_init(&k->mu, NULL);
    if (pthread_create(&k->thread, NULL, kube_thread, k) != 0) {
        free(k);
        return -1;
    }
    k->started = 1;
    *out = k;
    return 0;
}

void kube_client_stop(kube_client *k) {
    if (!k)
        return;
    k->stop = 1;
    if (k->started)
        pthread_join(k->thread, NULL);
    pthread_mutex_destroy(&k->mu);
    free(k);
}

int kube_client_poll(kube_client *k, kube_event *ev) {
    if (!k)
        return 0;
    pthread_mutex_lock(&k->mu);
    if (k->qn == 0) {
        pthread_mutex_unlock(&k->mu);
        return 0;
    }
    *ev = k->q[k->qh];
    k->qh = (k->qh + 1) % KUBE_Q;
    k->qn--;
    pthread_mutex_unlock(&k->mu);
    return 1;
}

uint64_t kube_client_drops(const kube_client *k) {
    return k ? k->drops : 0;
}

static kube_client *oneshot(void) {
    static kube_client k;
    static int ready;
    if (!ready) {
        memset(&k, 0, sizeof k);
        if (load_identity(&k) != 0)
            return NULL;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        ready = 1;
    }
    return &k;
}

int kube_publish_snapshot(const char *node, const char *text) {
    kube_client *k = oneshot();
    if (!k || !node || !text)
        return -1;
    char b64[1 << 16];
    if (b64_encode(text, strlen(text), b64, sizeof b64) < 0)
        return -1;
    char name[160];
    snprintf(name, sizeof name, "igmpshark-%s", node);
    char url[512];
    snprintf(url, sizeof url, "https://%s:%s/api/v1/namespaces/%s/configmaps/%s", k->host, k->port,
             k->ns, name);
    char *payload = malloc(strlen(b64) + 512);
    if (!payload)
        return -1;
    snprintf(payload, strlen(b64) + 512,
             "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"%s\","
             "\"labels\":{\"app.kubernetes.io/name\":\"igmpshark\"}},\"data\":{\"snapshot\":\"%s\"}}",
             name, b64);
    buf body;
    memset(&body, 0, sizeof body);
    CURL *c = curl_easy_init();
    kube_setup_easy(k, c, url, &body);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    struct curl_slist *hdr = NULL;
    char auth[8400];
    snprintf(auth, sizeof auth, "Authorization: Bearer %s", k->token);
    hdr = curl_slist_append(hdr, auth);
    hdr = curl_slist_append(hdr, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    curl_slist_free_all(hdr);
    free(body.data);
    if (code == 404 || code == 200 || code == 201) {
        if (code == 404) {
            snprintf(url, sizeof url, "https://%s:%s/api/v1/namespaces/%s/configmaps", k->host, k->port,
                     k->ns);
            c = curl_easy_init();
            memset(&body, 0, sizeof body);
            kube_setup_easy(k, c, url, &body);
            curl_easy_setopt(c, CURLOPT_POST, 1L);
            curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
            curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
            curl_easy_perform(c);
            curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
            curl_easy_cleanup(c);
            free(body.data);
        }
    }
    free(payload);
    return (code == 200 || code == 201) ? 0 : -1;
}

int kube_fetch_snapshots(const char *dir) {
    kube_client *k = oneshot();
    if (!k || !dir)
        return -1;
    char url[512];
    snprintf(url, sizeof url,
             "https://%s:%s/api/v1/namespaces/%s/configmaps?labelSelector=app.kubernetes.io/name%%3Digmpshark",
             k->host, k->port, k->ns);
    buf body;
    long code = 0;
    if (http_get(k, url, &code, &body) != 0 || code != 200) {
        free(body.data);
        return -1;
    }
    const char *p = body.data ? body.data : "";
    int n = 0;
    while ((p = strstr(p, "\"snapshot\"")) != NULL) {
        const char *s = strchr(p, ':');
        char enc[1 << 16];
        char plain[1 << 16];
        if (!s || parse_string(&s, enc, sizeof enc) != 0) {
            p += 10;
            continue;
        }
        if (b64_decode(enc, plain, sizeof plain) < 0) {
            p = s;
            continue;
        }
        char node[64] = "peer";
        const char *np = strstr(plain, "NODE ");
        if (np)
            sscanf(np + 5, "%63s", node);
        char path[512];
        snprintf(path, sizeof path, "%s/%s.snap", dir, node);
        FILE *fp = fopen(path, "w");
        if (fp) {
            fputs(plain, fp);
            if (plain[0] && plain[strlen(plain) - 1] != '\n')
                fputc('\n', fp);
            fclose(fp);
            n++;
        }
        p = s;
    }
    free(body.data);
    return n;
}
