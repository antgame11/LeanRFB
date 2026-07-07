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
// Called when a client sends text to set on the server's clipboard (RFB ClientCutText message)
typedef void (*vnc_clipboard_event_cb)(vnc_server_t* server, vnc_client_t* client, const char* text, uint32_t len, void* user_data);

// Status codes for vnc_resize_request_cb, matching the standard RFB ExtendedDesktopSize
// extension's status values exactly (see docs/custom/rfb_desktop_resize_extension.md).
#define VNC_RESIZE_SUCCESS            0
#define VNC_RESIZE_PROHIBITED         1
#define VNC_RESIZE_OUT_OF_RESOURCES   2
#define VNC_RESIZE_INVALID_LAYOUT     3

// Called when a client requests a desktop resize (RFB SetDesktopSize message), but only
// if config->allow_desktop_resize is set — otherwise the request is automatically
// answered with VNC_RESIZE_PROHIBITED without this callback being invoked.
// Implementations should attempt to resize the real display (e.g. via XRandR), then:
//   - on success, write the resolution actually applied to *out_width/*out_height
//     (which may differ from the request — e.g. the closest available mode) and
//     return VNC_RESIZE_SUCCESS. The library then handles reallocating the framebuffer
//     and notifying every connected client.
//   - on failure, return one of the other VNC_RESIZE_* codes; *out_width/*out_height
//     are ignored and nothing about the session changes.
typedef int (*vnc_resize_request_cb)(vnc_server_t* server, vnc_client_t* client,
                                     uint16_t req_width, uint16_t req_height,
                                     uint16_t* out_width, uint16_t* out_height,
                                     void* user_data);

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
    int allow_desktop_resize;  // 1 to let clients request a live desktop resize (RFB
                               // ExtendedDesktopSize/SetDesktopSize extension) via
                               // on_resize_request below. Requests are automatically
                               // rejected (VNC_RESIZE_PROHIBITED) when this is 0 or when
                               // on_resize_request is NULL. See
                               // docs/custom/rfb_desktop_resize_extension.md for details.

    vnc_key_event_cb on_key;   // Key event callback
    vnc_pointer_event_cb on_pointer; // Pointer event callback
    vnc_resize_request_cb on_resize_request; // Desktop resize request callback
    vnc_clipboard_event_cb on_clipboard; // Clipboard update event callback
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

// Change the server's framebuffer resolution (e.g. after the real display was resized).
// Reallocates the internal framebuffer, marks every client fully dirty, resets each
// client's video encoder and UDP session so they reinitialize at the new size, and
// queues an ExtendedDesktopSize notification (reason=GenericChange) to every client that
// supports it. Safe to call at any time, including from within on_resize_request.
// See docs/custom/rfb_desktop_resize_extension.md.
void vnc_server_resize_framebuffer(vnc_server_t* server, uint16_t new_width, uint16_t new_height);

// Send text to be set on the client's clipboard (RFB ServerCutText message)
void vnc_server_send_clipboard(vnc_server_t* server, const char* text, uint32_t len);

// Set the local rendering cursor shape (pixels in 32-bit ARGB/BGRA format)
void vnc_server_set_cursor(vnc_server_t* server, const uint32_t* pixels, uint16_t w, uint16_t h, uint16_t xhot, uint16_t yhot);

// Returns 1 if at least one client is currently connected, 0 otherwise.
// Use this to skip expensive work (e.g., screen capture) when nobody is watching.
int vnc_server_has_clients(const vnc_server_t* server);

#ifdef __cplusplus
}
#endif

#endif // LEANRFB_H
