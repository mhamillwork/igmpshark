/* Capture/dissection lifecycle adapted from the attached dbshark reference
 * (src/dbshark.c): wtap_init, epan_init, epan_load_settings, epan_new,
 * epan_dissect_run with tvb_new_real_data, then epan_dissect_free,
 * epan_free, epan_cleanup, wtap_cleanup. PostgreSQL and reassembly-hold
 * behavior from that program is intentionally not included.
 *
 * Wireshark 4.2.6 is GPL-2.0-or-later. This file is GPL-2.0-or-later.
 */
#include "ws_capture.h"

#include <glib.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>

#include <stdio.h>
#include <string.h>

static epan_t *sess;
static epan_dissect_t *edt;
static int ready;
static guint32 fno;
static nstime_t last_ts;
static int igmp_proto = -1;

static const nstime_t *prov_ts(struct packet_provider_data *p, guint32 num) {
    (void)p;
    if (num == 0 || num != fno)
        return NULL;
    return &last_ts;
}

static wtap_block_t prov_mbk(struct packet_provider_data *p, const frame_data *f) {
    (void)p;
    (void)f;
    return NULL;
}

static const struct packet_provider_funcs prov = {
    .get_frame_ts = prov_ts,
    .get_modified_block = prov_mbk,
};

static void vcmdarg_err(const char *fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

int ws_capture_version(int *major, int *minor, int *micro) {
    epan_get_version_number(major, minor, micro);
    return 0;
}

int ws_capture_init(void) {
    int major = 0, minor = 0, micro = 0;
    ws_capture_version(&major, &minor, &micro);
    if (major != 4 || minor != 2 || micro != 6) {
        fprintf(stderr, "igmpshark requires libwireshark 4.2.6, found %d.%d.%d\n",
                major, minor, micro);
        return -1;
    }
    ws_log_init("igmpshark", vcmdarg_err);
    ws_log_set_level(LOG_LEVEL_WARNING);
    init_process_policies();
    char *cfg_err = configuration_init("igmpshark", NULL);
    if (cfg_err) {
        fprintf(stderr, "configuration_init: %s\n", cfg_err);
        g_free(cfg_err);
        return -1;
    }
    wtap_init(TRUE);
    if (!epan_init(NULL, NULL, TRUE)) {
        fprintf(stderr, "epan_init failed\n");
        return -1;
    }
    epan_load_settings();
    char pref[] = "igmp.verify_checksum:TRUE";
    char *pref_err = NULL;
    prefs_set_pref(pref, &pref_err);
    if (pref_err)
        g_free(pref_err);
    prefs_apply_all();
    sess = epan_new(NULL, &prov);
    edt = sess ? epan_dissect_new(sess, TRUE, FALSE) : NULL;
    if (!edt)
        return -1;
    igmp_proto = proto_get_id_by_filter_name("igmp");
    ready = 1;
    return 0;
}

void ws_capture_reset_session(void) {
    if (!ready)
        return;
    if (edt)
        epan_dissect_cleanup(edt);
    if (sess) {
        epan_free(sess);
        sess = NULL;
    }
    sess = epan_new(NULL, &prov);
    if (sess && edt)
        epan_dissect_init(edt, sess, TRUE, FALSE);
    fno = 0;
}

static int layer_has_igmp(const packet_info *pi) {
    if (igmp_proto < 0 || !pi->layers)
        return 0;
    for (wmem_list_frame_t *layer = wmem_list_head(pi->layers); layer;
         layer = wmem_list_frame_next(layer)) {
        if (GPOINTER_TO_INT(wmem_list_frame_data(layer)) == igmp_proto)
            return 1;
    }
    return 0;
}

int ws_capture_frame_is_igmp(const uint8_t *frame, uint32_t caplen, uint32_t wirelen,
                             int wtap_encap) {
    if (!ready || !frame)
        return -1;
    if (fno == UINT32_MAX)
        ws_capture_reset_session();
    wtap_rec rec;
    wtap_rec_init(&rec);
    rec.rec_type = REC_TYPE_PACKET;
    rec.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec.ts.secs = 0;
    rec.ts.nsecs = 0;
    rec.rec_header.packet_header.caplen = caplen;
    rec.rec_header.packet_header.len = wirelen < caplen ? caplen : wirelen;
    rec.rec_header.packet_header.pkt_encap = wtap_encap;
    last_ts = rec.ts;
    frame_data fd;
    frame_data_init(&fd, ++fno, &rec, 0, 0);
    epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &rec,
                     tvb_new_real_data(frame, caplen, rec.rec_header.packet_header.len),
                     &fd, NULL);
    int hit = layer_has_igmp(&edt->pi);
    epan_dissect_reset(edt);
    frame_data_destroy(&fd);
    wtap_rec_cleanup(&rec);
    return hit;
}

void ws_capture_shutdown(void) {
    if (edt) {
        epan_dissect_free(edt);
        edt = NULL;
    }
    if (sess) {
        epan_free(sess);
        sess = NULL;
    }
    if (ready) {
        epan_cleanup();
        wtap_cleanup();
    }
    ready = 0;
}
