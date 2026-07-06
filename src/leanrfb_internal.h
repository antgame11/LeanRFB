#ifndef LEANRFB_INTERNAL_H
#define LEANRFB_INTERNAL_H

#include "leanrfb.h"
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
  VNC_STATE_DETECT_WEBSOCKET,
  VNC_STATE_PROTOCOL_VERSION,
  VNC_STATE_WAIT_PROTOCOL_VERSION,
  VNC_STATE_WAIT_SECURITY,
  VNC_STATE_WAIT_VNC_AUTH_RESPONSE,
  VNC_STATE_WAIT_CLIENT_INIT,
  VNC_STATE_NORMAL
} vnc_client_state_t;

// RFB pixel format structure (16 bytes)
typedef struct {
  uint8_t bits_per_pixel;
  uint8_t depth;
  uint8_t big_endian_flag;
  uint8_t true_color_flag;
  uint16_t red_max;
  uint16_t green_max;
  uint16_t blue_max;
  uint8_t red_shift;
  uint8_t green_shift;
  uint8_t blue_shift;
  uint8_t padding[3];
} vnc_pixel_fmt_t;

// Large write and read buffer sizes for non-blocking sockets
#define VNC_WRITE_BUF_INIT_SIZE (256 * 1024)
#define VNC_READ_BUF_SIZE (16 * 1024)

// Security limits
#define VNC_MAX_CLIENTS_DEFAULT 16 // default max simultaneous clients
#define VNC_MAX_BLOCKED_IPS 64     // max entries in the blocked-IP list
#define VNC_AUTH_MAX_FAILS 5       // auth failures before blocking
#define VNC_AUTH_WINDOW_SEC 60 // rolling window for failure counting (seconds)
#define VNC_AUTH_BLOCK_SEC 30  // block duration after threshold (seconds)
// Max accepted ClientCutText payload — must be <= VNC_READ_BUF_SIZE - 8
#define VNC_CLIPBOARD_MAX_LEN (VNC_READ_BUF_SIZE - 8)

// Open VP9 video encoding (see docs/custom/rfb_vp9_extension.md). Same TCP rectangle
// framing as H.264 (encoding 50): length(4) + flags(4) + raw VP9 frame payload.
// (VP9 has no NAL/Annex-B structure — the payload is simply the encoder's own complete
// frame packet, keyframe or inter-frame.)
#define VNC_ENCODING_VP9 52

// --- UDP video transport (see docs/custom/rfb_h264_udp_extension.md) ---
// Pseudo-encoding used to negotiate + set up the UDP side-channel. Shared by both H.264
// and VP9 — the one-time setup payload carries a codec byte (see VNC_UDP_CODEC_*)
// so the client knows which decoder to instantiate regardless of which encoding was
// actually negotiated.
#define VNC_ENCODING_UDP_SETUP 51
#define VNC_UDP_CODEC_H264 0
#define VNC_UDP_CODEC_VP9 1

// Datagram type byte (also doubles as the AEAD nonce direction discriminator,
// so the two directions never share nonce space under the same session key).
#define VNC_UDP_TYPE_VIDEO 0  // server -> client, fragmented H.264 payload
#define VNC_UDP_TYPE_HELLO 1  // client -> server, hole-punch / liveness heartbeat

#define VNC_UDP_KEY_LEN 32   // AES-256-GCM key
#define VNC_UDP_CID_LEN 8    // per-session connection id
#define VNC_UDP_TAG_LEN 16   // GCM authentication tag
#define VNC_UDP_HDR_LEN (1 + VNC_UDP_CID_LEN + 8) // type + cid + 64-bit counter
#define VNC_UDP_INNER_HDR_LEN 10 // frame_id(4) frag_idx(2) frag_count(2) flags(1) reserved(1)
#define VNC_UDP_MAX_FRAG_PAYLOAD 1200
#define VNC_UDP_MAX_FRAGS 512
#define VNC_UDP_MAX_DATAGRAM (VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN + VNC_UDP_INNER_HDR_LEN + VNC_UDP_MAX_FRAG_PAYLOAD)

#define VNC_UDP_LIVENESS_TIMEOUT_MS 8000  // no heartbeat/hello within this window -> fall back to TCP
#define VNC_UDP_HEARTBEAT_INTERVAL_MS 2000

// --- Live desktop resize: standard RFB ExtendedDesktopSize/SetDesktopSize extension
// (see docs/custom/rfb_desktop_resize_extension.md). Constants match the reference
// LibVNCServer implementation exactly, verified against its rfbproto.h.
#define VNC_ENCODING_EXT_DESKTOP_SIZE ((int32_t)0xFFFFFECC) // -308
#define VNC_MSG_SET_DESKTOP_SIZE 251 // client -> server

// "reason" (rect x-position) values
#define VNC_EDS_REASON_GENERIC 0       // spontaneous/initial-announcement change
#define VNC_EDS_REASON_THIS_CLIENT 1   // this client's own SetDesktopSize request
#define VNC_EDS_REASON_OTHER_CLIENT 2  // a different client's SetDesktopSize request

// "status" (rect y-position) values — identical to the public VNC_RESIZE_* codes in
// leanrfb.h (VNC_RESIZE_SUCCESS == VNC_EDS_STATUS_SUCCESS, etc.); kept as a separate set
// of names here only to mirror the protocol's own "reason"/"status" terminology.
#define VNC_EDS_STATUS_SUCCESS 0
#define VNC_EDS_STATUS_PROHIBITED 1
#define VNC_EDS_STATUS_OUT_OF_RESOURCES 2
#define VNC_EDS_STATUS_INVALID_LAYOUT 3

// Sliding replay window (64 packets) for anti-replay protection of one direction.
typedef struct {
  uint64_t highest;
  uint64_t bitmap;
} vnc_udp_replay_state_t;

// Blocked-IP entry for brute-force protection
typedef struct {
  char ip[INET_ADDRSTRLEN];
  time_t block_until;
} vnc_blocked_ip_t;

struct vnc_client {
  int fd;
  char ip_addr[32];
  vnc_client_state_t state;
  int protocol_minor;
  vnc_pixel_fmt_t fmt; // Client's requested pixel format
  int format_custom;   // 1 if client format differs from server default format

  // Supported encodings
  int supports_hextile;
  int supports_tight;
  int supports_rich_cursor;
  int send_cursor_update;
  int supports_h264;
  void *h264_enc;
  int supports_vp9;
  void *vp9_enc;
  int force_keyframe_requested; // set when client asks the encoder to emit a fresh IDR/keyframe

  // UDP H.264 transport (see docs/custom/rfb_h264_udp_extension.md)
  int supports_udp;          // client advertised VNC_ENCODING_UDP_SETUP
  int udp_setup_sent;        // 1 once the one-time setup message has been sent over TCP
  int udp_ready;             // 1 once a valid Hello has been received from this client
  uint8_t udp_key[VNC_UDP_KEY_LEN];
  uint8_t udp_cid[VNC_UDP_CID_LEN];
  struct sockaddr_storage udp_addr;
  socklen_t udp_addr_len;
  uint64_t udp_send_ctr;      // monotonic counter for VNC_UDP_TYPE_VIDEO packets
  uint32_t udp_frame_id;      // monotonic frame id, one per encoded frame sent over UDP
  vnc_udp_replay_state_t udp_recv_replay; // anti-replay state for Hello/heartbeat packets
  unsigned long long udp_last_recv_ms;    // last time a valid Hello/heartbeat arrived

  // Output buffering
  uint8_t *write_buf;
  size_t write_cap; // Allocated capacity of write_buf
  size_t write_len; // Total valid bytes in write_buf
  size_t write_pos; // Number of bytes already sent

  // Input buffering
  uint8_t read_buf[VNC_READ_BUF_SIZE];
  size_t read_len;

  // VncAuth challenge
  uint8_t challenge[16];

  // Per-client brute-force tracking
  char client_ip[INET_ADDRSTRLEN]; // IP address only (no port), set on connect
  int auth_fail_count;
  time_t auth_first_fail_time;

  // Update request state
  int update_requested;
  int update_incremental;
  uint16_t req_x, req_y, req_w, req_h;

  // WebSocket connection state
  int is_websocket;
  int ws_handshake_done;
  unsigned long long connect_time_ms;
  uint8_t ws_read_buf[VNC_READ_BUF_SIZE];
  size_t ws_read_len;

  // Client dirty tracking (flags per tile)
  uint8_t *dirty_tiles; // Array of size cols * rows

  // Live desktop resize (see docs/custom/rfb_desktop_resize_extension.md)
  int supports_ext_desktop_size;  // client advertised VNC_ENCODING_EXT_DESKTOP_SIZE
  int pending_ext_desktop_size;   // an ExtendedDesktopSize rect is queued to send
  int ext_desktop_reason;         // VNC_EDS_REASON_* for the queued rect
  int ext_desktop_status;         // VNC_EDS_STATUS_* for the queued rect

  vnc_client_t *next;
};

struct vnc_server {
  int listen_fd;
  uint16_t width;
  uint16_t height;
  char *name;

  // Internal framebuffer copy (always in 32-bit BGRA format, i.e., B in low
  // byte, G, R, X in high byte)
  uint32_t *framebuffer;

  // Grid dimensions for 16x16 tiles
  int cols;
  int rows;

  // Server-wide dirty flags (set when the framebuffer is updated)
  uint8_t *server_dirty; // Array of size cols * rows

  vnc_client_t *clients;

  // Cursor shape
  uint32_t *cursor_pixels;
  uint16_t cursor_w;
  uint16_t cursor_h;
  uint16_t cursor_xhot;
  uint16_t cursor_yhot;

  // Callbacks
  vnc_key_event_cb on_key;
  vnc_pointer_event_cb on_pointer;
  vnc_resize_request_cb on_resize_request;
  void *user_data;

  char *password;

  // Connection and brute-force protection
  int max_clients;
  vnc_blocked_ip_t blocked_ips[VNC_MAX_BLOCKED_IPS];
  int num_blocked_ips;

  // Cached pollfd array (reused across vnc_server_poll calls to avoid
  // malloc/free)
  struct pollfd *pfds_cache;
  int pfds_cap;

  int websocket;

  // UDP H.264 transport
  int udp_fd;          // datagram socket bound to the same port number as listen_fd, or -1 if disabled
  int disable_udp_h264; // mirrors config->disable_udp_h264

  int allow_desktop_resize; // mirrors config->allow_desktop_resize
};

// Byte-order conversion helper functions
static inline uint16_t read_u16_be(const uint8_t *buf) {
  return ((uint16_t)buf[0] << 8) | buf[1];
}

static inline uint32_t read_u32_be(const uint8_t *buf) {
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8) | buf[3];
}

static inline void write_u16_be(uint8_t *buf, uint16_t val) {
  buf[0] = (uint8_t)(val >> 8);
  buf[1] = (uint8_t)val;
}

static inline void write_u32_be(uint8_t *buf, uint32_t val) {
  buf[0] = (uint8_t)(val >> 24);
  buf[1] = (uint8_t)(val >> 16);
  buf[2] = (uint8_t)(val >> 8);
  buf[3] = (uint8_t)val;
}

// Check if pixel formats are identical
static inline int pixel_format_equal(const vnc_pixel_fmt_t *a,
                                     const vnc_pixel_fmt_t *b) {
  return a->bits_per_pixel == b->bits_per_pixel && a->depth == b->depth &&
         a->big_endian_flag == b->big_endian_flag &&
         a->true_color_flag == b->true_color_flag && a->red_max == b->red_max &&
         a->green_max == b->green_max && a->blue_max == b->blue_max &&
         a->red_shift == b->red_shift && a->green_shift == b->green_shift &&
         a->blue_shift == b->blue_shift;
}

// Convert a single pixel from default internal format (BGRA8888) to client
// format
static inline void convert_pixel(uint32_t src_pixel, uint8_t *dst,
                                 const vnc_pixel_fmt_t *fmt) {
  uint8_t b = (uint8_t)(src_pixel & 0xFF);
  uint8_t g = (uint8_t)((src_pixel >> 8) & 0xFF);
  uint8_t r = (uint8_t)((src_pixel >> 16) & 0xFF);

  uint32_t cr = (uint32_t)r * fmt->red_max / 255;
  uint32_t cg = (uint32_t)g * fmt->green_max / 255;
  uint32_t cb = (uint32_t)b * fmt->blue_max / 255;

  uint32_t val = (cr << fmt->red_shift) | (cg << fmt->green_shift) |
                 (cb << fmt->blue_shift);

  if (fmt->bits_per_pixel == 32) {
    if (fmt->big_endian_flag) {
      write_u32_be(dst, val);
    } else {
      dst[0] = (uint8_t)val;
      dst[1] = (uint8_t)(val >> 8);
      dst[2] = (uint8_t)(val >> 16);
      dst[3] = (uint8_t)(val >> 24);
    }
  } else if (fmt->bits_per_pixel == 16) {
    if (fmt->big_endian_flag) {
      write_u16_be(dst, val);
    } else {
      dst[0] = (uint8_t)val;
      dst[1] = (uint8_t)(val >> 8);
    }
  } else if (fmt->bits_per_pixel == 8) {
    dst[0] = (uint8_t)val;
  }
}

static inline int get_pixel_size(const vnc_pixel_fmt_t *fmt, int custom) {
  return !custom ? 4 : (fmt->bits_per_pixel / 8);
}

// Dynamic buffer space check
int client_ensure_write_space(vnc_client_t *client, size_t len);

// JPEG encoder interface
int compress_jpeg(const uint32_t *src, int w, int h, int stride,
                  uint8_t **out_buf, unsigned long *out_size, int quality);

// Hextile encoder interface
int vnc_encode_hextile(vnc_client_t *client, const uint32_t *fb, int fb_width,
                       int fb_height, uint16_t rx, uint16_t ry, uint16_t rw,
                       uint16_t rh);

// H.264 encoder interface
void* vnc_h264_encoder_create(int width, int height, int fps, int quality);
int vnc_h264_encoder_encode(void* enc_ptr, const uint32_t* fb, uint8_t** out_data, int* out_len, int* is_keyframe, int* pts_out);
void vnc_h264_encoder_destroy(void* enc_ptr);
// Force the next encoded frame to be a fresh IDR keyframe (used to recover from UDP packet loss).
void vnc_h264_encoder_force_keyframe(void* enc_ptr);

// VP9 encoder interface — same signatures/semantics as the H.264 ones above.
void* vnc_vp9_encoder_create(int width, int height, int fps, int quality);
int vnc_vp9_encoder_encode(void* enc_ptr, const uint32_t* fb, uint8_t** out_data, int* out_len, int* is_keyframe, int* pts_out);
void vnc_vp9_encoder_destroy(void* enc_ptr);
void vnc_vp9_encoder_force_keyframe(void* enc_ptr);

// --- UDP H.264 transport interface (src/leanrfb_udp.c) ---

// AEAD-seal a plaintext payload into a self-contained UDP datagram.
// out must have room for at least VNC_UDP_HDR_LEN + pt_len + VNC_UDP_TAG_LEN bytes.
// Returns the total datagram length, or -1 on failure.
int vnc_udp_seal(const uint8_t key[VNC_UDP_KEY_LEN], uint8_t type,
                 const uint8_t cid[VNC_UDP_CID_LEN], uint64_t counter,
                 const uint8_t* pt, int pt_len, uint8_t* out, int out_cap);

// Authenticate and decrypt a received UDP datagram.
// pt_out must have room for at least in_len bytes.
// Returns 0 on success (out_type/out_cid/out_counter/pt_out/pt_len_out populated), -1 on failure.
int vnc_udp_open(const uint8_t key[VNC_UDP_KEY_LEN], const uint8_t* in, int in_len,
                 uint8_t* out_type, uint8_t out_cid[VNC_UDP_CID_LEN], uint64_t* out_counter,
                 uint8_t* pt_out, int* pt_len_out);

// Anti-replay sliding window check. Returns 1 if counter is fresh (and records it), 0 if it
// is a replay or too old to accept.
int vnc_udp_replay_check(vnc_udp_replay_state_t* st, uint64_t counter);

// Fragment, encrypt and send one encoded H.264 frame to a client over UDP.
// Returns 0 on success, -1 on failure (caller should fall back to TCP for this frame).
int vnc_udp_send_video_frame(vnc_server_t* server, vnc_client_t* client,
                             const uint8_t* data, int len, int flags);

// Drain and process all pending datagrams on server->udp_fd (Hello/heartbeat handling).
// Bounded so a single call cannot monopolize the poll loop under flood conditions.
void vnc_udp_handle_incoming(vnc_server_t* server);

#endif // LEANRFB_INTERNAL_H
