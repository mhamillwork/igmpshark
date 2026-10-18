#ifndef IGMPSHARK_WS_CAPTURE_H
#define IGMPSHARK_WS_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

/* libwireshark 4.6.9 dissection. Returns 1 if the igmp dissector accepted
 * the frame, 0 if it did not, -1 if epan is unavailable or failed. */
int ws_capture_init(void);
int ws_capture_frame_is_igmp(const uint8_t *frame, uint32_t caplen, uint32_t wirelen,
                             int wtap_encap);
void ws_capture_reset_session(void);
void ws_capture_shutdown(void);
int ws_capture_version(int *major, int *minor, int *micro);

#endif
