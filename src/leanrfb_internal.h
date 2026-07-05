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

#endif // LEANRFB_INTERNAL_H
