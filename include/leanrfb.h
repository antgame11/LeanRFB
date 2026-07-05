#ifndef LEANRFB_H
#define LEANRFB_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vnc_server vnc_server_t;
typedef struct vnc_client vnc_client_t;

// Callback type definitions
// keysym values correspond to standard X11 Keysyms (RFC 6143, Section 7.5.4)
typedef void (*vnc_key_event_cb)(vnc_server_t* server, vnc_client_t* client, uint32_t keysym, int down, void* user_data);
// button_mask: bit 0: left, bit 1: middle, bit 2: right, bit 3: wheel up, bit 4: wheel down
typedef void (*vnc_pointer_event_cb)(vnc_server_t* server, vnc_client_t* client, uint16_t x, uint16_t y, uint8_t button_mask, void* user_data);

typedef struct vnc_server_config {
    int port;                  // TCP port to listen on (default 5900 if <= 0)
    const char* listen_host;   // Interface bind address (NULL for all interfaces)
    const char* name;          // VNC server display name (e.g. "VNC Server C")
    uint16_t width;            // Framebuffer width
    uint16_t height;           // Framebuffer height
    const char* password;      // Authentication password (NULL/empty for no authentication)
    int max_clients;           // Maximum simultaneous clients (0 = use default of 16)
    int websocket;             // 1 to enable WebSocket/HTTP mode on the same port
    int disable_udp_h264;      // 1 to disable the encrypted UDP transport for H.264 video
                               // (server falls back to TCP-only H.264 delivery). See
                               // docs/custom/rfb_h264_udp_extension.md for details.

    vnc_key_event_cb on_key;   // Key event callback
    vnc_pointer_event_cb on_pointer; // Pointer event callback
    void* user_data;           // Custom user data pointer passed to callbacks
} vnc_server_config_t;

// Lifecycle management
vnc_server_t* vnc_server_create(const vnc_server_config_t* config);
void vnc_server_destroy(vnc_server_t* server);

// Network polling (non-blocking). Pass timeout in milliseconds (0 for immediate return)
// Returns 0 on success, < 0 on error.
// Call this periodically in your application loop.
int vnc_server_poll(vnc_server_t* server, int timeout_ms);

// Framebuffer updates
// Expects a 32-bit BGRA (or RGBA) buffer of size width * height.
// Compares the new buffer with the internal copy to flag changed 16x16 tiles.
void vnc_server_update_framebuffer(vnc_server_t* server, const uint32_t* fb_data);

// Partial framebuffer update (copies a sub-rectangle of pixel data to the internal framebuffer and marks it dirty)
// Expects rect_data to contain rw * rh pixels in 32-bit BGRA format.
void vnc_server_update_rect(vnc_server_t* server, const uint32_t* rect_data, uint16_t rx, uint16_t ry, uint16_t rw, uint16_t rh);

// Mark a specific region as modified directly (bypasses full screen comparison)
void vnc_server_mark_dirty(vnc_server_t* server, uint16_t x, uint16_t y, uint16_t w, uint16_t h);

// Set the local rendering cursor shape (pixels in 32-bit ARGB/BGRA format)
void vnc_server_set_cursor(vnc_server_t* server, const uint32_t* pixels, uint16_t w, uint16_t h, uint16_t xhot, uint16_t yhot);

// Returns 1 if at least one client is currently connected, 0 otherwise.
// Use this to skip expensive work (e.g., screen capture) when nobody is watching.
int vnc_server_has_clients(const vnc_server_t* server);

#ifdef __cplusplus
}
#endif

#endif // LEANRFB_H
