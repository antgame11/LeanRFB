#ifndef VNC_CLIENT_CORE_H
#define VNC_CLIENT_CORE_H

#include <stdint.h>
#include <pthread.h>

#define VNC_ENCODING_EXT_DESKTOP_SIZE -308
#define VNC_ENCODING_UDP_SETUP 51
#define VNC_ENCODING_VP9 52

// QEMU VNC audio extension (see docs/custom/rfb_qemu_audio_extension.md). Wire
// format matches QEMU's ui/vnc.c exactly, so this also interoperates with a
// real QEMU VNC server/client.
#define VNC_ENCODING_AUDIO -259

// Wire values for the QEMU audio SET_FORMAT message's sample-format byte.
#define VNC_AUDIO_FMT_U8  0
#define VNC_AUDIO_FMT_S8  1
#define VNC_AUDIO_FMT_U16 2
#define VNC_AUDIO_FMT_S16 3
#define VNC_AUDIO_FMT_U32 4
#define VNC_AUDIO_FMT_S32 5

typedef enum {
    STATE_WAIT_VERSION,
    STATE_WAIT_SECURITY,
    STATE_WAIT_AUTH_CHALLENGE,
    STATE_WAIT_AUTH_RESULT,
    STATE_WAIT_SERVER_INIT,
    STATE_NORMAL
} vnc_state_t;

typedef struct {
    void (*send_raw)(const uint8_t* data, size_t len, void* user_data);
    void (*on_screen_update)(int x, int y, int w, int h, void* user_data);
    void (*on_desktop_resize)(int w, int h, void* user_data);
    void (*on_clipboard_update)(const char* text, int len, void* user_data);
    void (*on_disconnect)(const char* reason, void* user_data);
    char* (*request_password)(void* user_data);
    // QEMU audio extension (all optional — leave NULL if audio isn't wired up).
    void (*on_audio_supported)(void* user_data);   // server acked our -259 SetEncodings entry
    void (*on_audio_begin)(void* user_data);
    void (*on_audio_data)(const uint8_t* pcm, size_t len, void* user_data);
    void (*on_audio_end)(void* user_data);
#ifndef __EMSCRIPTEN__
    int (*on_custom_encoding)(int fd, uint32_t encoding, uint16_t rx, uint16_t ry, uint16_t rw, uint16_t rh, void* user_data);
#endif
} vnc_core_callbacks_t;

// Global VNC state
extern vnc_state_t vnc_state;
extern int screen_w;
extern int screen_h;
extern uint8_t* backbuffer;
extern pthread_mutex_t backbuffer_mutex;
extern int client_running;
extern int vnc_audio_available; // set once the server has acked our audio SetEncodings entry

// Core functions
void vnc_core_init(const vnc_core_callbacks_t* callbacks, void* user_data);
void vnc_core_cleanup(void);
void vnc_core_process_data(const uint8_t* data, size_t len);

// Input sending APIs
void vnc_core_send_pointer(uint16_t x, uint16_t y, uint8_t button_mask);
void vnc_core_send_key(uint32_t keysym, uint8_t down);
void vnc_core_send_clipboard(const char* text, int len);
void vnc_core_send_fb_request(uint8_t incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h);

// QEMU audio extension APIs. Call vnc_core_request_audio(1) before connecting
// (i.e. before vnc_core_desktop_handshake / the first SetEncodings on web) to
// advertise support; vnc_audio_available then flips to 1 once the server acks.
void vnc_core_request_audio(int enabled);
void vnc_core_send_audio_enable(void);
void vnc_core_send_audio_disable(void);
void vnc_core_send_audio_set_format(uint8_t fmt, uint8_t channels, uint32_t freq);

// Desktop blocking VNC protocol processing functions (called by vnc_client_thread on desktop)
#ifndef __EMSCRIPTEN__
int read_exact(int fd, void* buf, size_t len);
int vnc_core_desktop_handshake(int fd, const char* preferred_encoding);
int vnc_core_process_message(int fd);
#endif

#endif
