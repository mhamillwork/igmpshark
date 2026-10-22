#include "kube_parse.h"

#include "igmp_types.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p))
        p++;
    return p;
}

static int parse_string(const char **pp, const char *end, char *out, size_t cap) {
    const char *p = skip_ws(*pp, end);
    if (p >= end || *p != '"')
        return -1;
    p++;
    size_t n = 0;
    while (p < end && *p != '"') {
        char c = *p++;
        if (c == '\\' && p < end) {
            char e = *p++;
            if (e == 'n')
                c = '\n';
            else if (e == 't')
                c = '\t';
            else if (e == 'u') {
                for (int i = 0; i < 4 && p < end; i++)
                    p++;
                c = '?';
            } else
                c = e;
        }
        if (n + 1 < cap)
            out[n++] = c;
    }
    if (p >= end || *p != '"')
        return -1;
    out[n] = 0;
    *pp = p + 1;
    return 0;
}

static const char *find_key(const char *s, const char *end, const char *key) {
    size_t n = strlen(key);
    if (n == 0)
        return NULL;
    for (const char *p = s; p + n <= end; p++) {
        if (memcmp(p, key, n) == 0)
            return p;
    }
    return NULL;
}

/* end is one past the last byte of this object. */
static int fill_pod(const char *obj, const char *end, kube_event *ev, int watch_deleted) {
    const char *uid = find_key(obj, end, "\"uid\"");
    const char *name = find_key(obj, end, "\"name\"");
    const char *node = find_key(obj, end, "\"nodeName\"");
    const char *ip = find_key(obj, end, "\"podIP\"");
    const char *del = find_key(obj, end, "\"deletionTimestamp\"");
    memset(ev, 0, sizeof *ev);
    if (!uid || !name)
        return -1;
    const char *p = strchr(uid, ':');
    if (!p || p + 1 >= end)
        return -1;
    p = skip_ws(p + 1, end);
    if (parse_string(&p, end, ev->uid, sizeof ev->uid) != 0)
        return -1;
    p = strchr(name, ':');
    if (!p || p + 1 >= end)
        return -1;
    p = skip_ws(p + 1, end);
    if (parse_string(&p, end, ev->name, sizeof ev->name) != 0)
        return -1;
    if (node) {
        p = strchr(node, ':');
        if (p && p + 1 < end) {
            p = skip_ws(p + 1, end);
            parse_string(&p, end, ev->node, sizeof ev->node);
        }
    }
    if (ip) {
        p = strchr(ip, ':');
        char text[64];
        if (p && p + 1 < end) {
            p = skip_ws(p + 1, end);
            if (parse_string(&p, end, text, sizeof text) == 0)
                igmp_ip_parse(text, &ev->ip);
        }
    }
    int deleting = 0;
    if (del && (ip == NULL || del < ip)) {
        const char *c = strchr(del, ':');
        if (c && c < end) {
            c = skip_ws(c + 1, end);
            if (!(c + 4 <= end && strncmp(c, "null", 4) == 0))
                deleting = 1;
        }
    }
    const char *rst = obj;
    while ((rst = find_key(rst, end, "\"restartCount\"")) != NULL) {
        int v = 0;
        if (sscanf(rst, "\"restartCount\"%*[^0-9]%d", &v) == 1 && v > ev->restart)
            ev->restart = v;
        rst += 14;
        if (rst > end)
            break;
    }
    ev->deleting = deleting || watch_deleted;
    ev->kind = ev->deleting ? KUBE_EV_DELETE : KUBE_EV_UPSERT;
    return 0;
}

/* p points at '{'. Returns one past the matching close, or NULL. */
static const char *end_object(const char *p, const char *limit) {
    if (!p || p >= limit || *p != '{')
        return NULL;
    int depth = 0;
    int in_str = 0;
    int esc = 0;
    for (; p < limit; p++) {
        if (in_str) {
            if (esc)
                esc = 0;
            else if (*p == '\\')
                esc = 1;
            else if (*p == '"')
                in_str = 0;
            continue;
        }
        if (*p == '"')
            in_str = 1;
        else if (*p == '{')
            depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0)
                return p + 1;
        }
    }
    return NULL;
}

static int string_after_key(const char *keyat, const char *end, char *out, size_t cap);

int kube_parse_list_meta(const char *json, char *rv, size_t rv_cap, char *cont, size_t cont_cap) {
    const char *end;
    const char *items;
    const char *meta;
    const char *obj;
    const char *obj_end;
    const char *rvk;
    const char *ck;
    if (rv && rv_cap)
        rv[0] = 0;
    if (cont && cont_cap)
        cont[0] = 0;
    if (!json)
        return -1;
    end = json + strlen(json);
    items = find_key(json, end, "\"items\"");
    meta = find_key(json, end, "\"metadata\"");
    if (!meta || (items && meta > items))
        return -1;
    obj = strchr(meta, '{');
    if (!obj || obj >= end)
        return -1;
    obj_end = end_object(obj, end);
    if (!obj_end)
        return -1;
    rvk = find_key(obj, obj_end, "\"resourceVersion\"");
    if (rvk && rv && rv_cap && string_after_key(rvk, obj_end, rv, rv_cap) != 0)
        rv[0] = 0;
    ck = find_key(obj, obj_end, "\"continue\"");
    if (ck && cont && cont_cap && string_after_key(ck, obj_end, cont, cont_cap) != 0)
        cont[0] = 0;
    return 0;
}

int kube_parse_pod_list(const char *json, int (*cb)(void *user, const kube_event *ev), void *user) {
    if (!json || !cb)
        return -1;
    const char *items = strstr(json, "\"items\"");
    if (!items)
        return 0;
    const char *p = strchr(items, '[');
    if (!p)
        return 0;
    const char *limit = json + strlen(json);
    p++;
    int n = 0;
    for (;;) {
        p = skip_ws(p, limit);
        if (p >= limit || *p == ']')
            break;
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p != '{')
            break;
        const char *obj_end = end_object(p, limit);
        if (!obj_end)
            break;
        kube_event ev;
        if (fill_pod(p, obj_end, &ev, 0) == 0) {
            n++;
            if (cb(user, &ev) != 0)
                break;
        }
        p = obj_end;
    }
    return n;
}

int kube_parse_watch_line(const char *line, kube_event *ev) {
    if (!line || !ev)
        return 0;
    const char *limit = line + strlen(line);
    int deleted = 0;
    const char *type = find_key(line, limit, "\"type\"");
    if (type) {
        const char *p = strchr(type, ':');
        char tp[32];
        if (p && p + 1 < limit) {
            p = skip_ws(p + 1, limit);
            if (parse_string(&p, limit, tp, sizeof tp) == 0 && strcmp(tp, "DELETED") == 0)
                deleted = 1;
        }
    }
    const char *object = find_key(line, limit, "\"object\"");
    const char *start = line;
    if (object) {
        const char *brace = strchr(object, '{');
        if (brace && brace < limit)
            start = brace;
    }
    const char *obj_end = end_object(start, limit);
    if (!obj_end) {
        const char *meta = find_key(start, limit, "\"metadata\"");
        if (!meta)
            return 0;
        start = meta;
        obj_end = limit;
    }
    return fill_pod(start, obj_end, ev, deleted) == 0;
}

int kube_each_snapshot(const char *json, int (*cb)(void *user, const char *b64), void *user) {
    if (!json || !cb)
        return -1;
    const char *end = json + strlen(json);
    const char *p = json;
    char *enc = malloc(1 << 16);
    if (!enc)
        return -1;
    int n = 0;
    while (p < end && (p = strstr(p, "\"snapshot\"")) != NULL) {
        const char *s = strchr(p, ':');
        if (!s || s >= end) {
            p += 10;
            continue;
        }
        s++;
        if (parse_string(&s, end, enc, 1 << 16) != 0) {
            p += 10;
            continue;
        }
        n++;
        if (cb(user, enc) != 0)
            break;
        p = s;
    }
    free(enc);
    return n;
}

static int string_after_key(const char *keyat, const char *end, char *out, size_t cap) {
    const char *p = strchr(keyat, ':');
    if (!p || p >= end)
        return -1;
    p++;
    return parse_string(&p, end, out, cap);
}

static const char *object_after_key(const char *start, const char *end, const char *key) {
    const char *k = find_key(start, end, key);
    if (!k)
        return NULL;
    const char *p = strchr(k, ':');
    if (!p || p >= end)
        return NULL;
    p = skip_ws(p + 1, end);
    if (p >= end || *p != '{')
        return NULL;
    return p;
}

static int ip_after_key(const char *start, const char *end, const char *key, uint32_t *ip) {
    const char *k = find_key(start, end, key);
    if (!k)
        return -1;
    char text[64];
    if (string_after_key(k, end, text, sizeof text) != 0)
        return -1;
    if (igmp_ip_parse(text, ip) != 0 || *ip == 0)
        return -1;
    return 0;
}

/* metadata.name plus the router annotation. The health annotation is a
 * different key and is never copied into ip. */
static int fill_cilium_host(const char *obj, const char *end, kube_node_ip *out) {
    memset(out, 0, sizeof *out);
    const char *meta = object_after_key(obj, end, "\"metadata\"");
    if (!meta)
        return -1;
    const char *meta_end = end_object(meta, end);
    if (!meta_end)
        return -1;
    const char *ann = object_after_key(meta, meta_end, "\"annotations\"");
    if (!ann)
        return -1;
    /* metadata.name is before annotations. Do not take a "name" key that
     * lives inside the annotation map. */
    const char *name = find_key(meta, ann, "\"name\"");
    if (!name)
        name = find_key(meta, meta_end, "\"name\"");
    if (!name || string_after_key(name, meta_end, out->name, sizeof out->name) != 0 || !out->name[0])
        return -1;
    const char *ann_end = end_object(ann, meta_end);
    if (!ann_end)
        return -1;
    if (ip_after_key(ann, ann_end, "\"network.cilium.io/ipv4-cilium-host\"", &out->ip) != 0)
        ip_after_key(ann, ann_end, "\"io.cilium.network.ipv4-cilium-host\"", &out->ip);
    if (out->ip == 0)
        return -1;
    return 0;
}

int kube_parse_cilium_host_ips(const char *json, kube_node_ip *out, int cap) {
    if (!json || !out || cap <= 0)
        return -1;
    const char *limit = json + strlen(json);
    const char *items = strstr(json, "\"items\"");
    const char *p = json;
    if (items) {
        const char *br = strchr(items, '[');
        if (!br)
            return 0;
        p = br + 1;
    }
    int n = 0;
    for (;;) {
        p = skip_ws(p, limit);
        if (p >= limit || *p == ']' || *p == '\0')
            break;
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p != '{')
            break;
        const char *obj_end = end_object(p, limit);
        if (!obj_end)
            break;
        kube_node_ip row;
        if (n < cap && fill_cilium_host(p, obj_end, &row) == 0) {
            int dup = 0;
            for (int i = 0; i < n; i++)
                if (strcmp(out[i].name, row.name) == 0)
                    dup = 1;
            if (!dup)
                out[n++] = row;
        }
        p = obj_end;
        if (!items)
            break;
    }
    return n;
}
