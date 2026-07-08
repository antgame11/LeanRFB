#ifndef VNC_CLIENT_CORE_H
#define VNC_CLIENT_CORE_H

#include <stdint.h>
#include <pthread.h>

#define VNC_ENCODING_EXT_DESKTOP_SIZE -308
#define VNC_ENCODING_UDP_SETUP 51
#define VNC_ENCODING_VP9 52

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

// Core functions
void vnc_core_init(const vnc_core_callbacks_t* callbacks, void* user_data);
void vnc_core_cleanup(void);
void vnc_core_process_data(const uint8_t* data, size_t len);

// Input sending APIs
void vnc_core_send_pointer(uint16_t x, uint16_t y, uint8_t button_mask);
void vnc_core_send_key(uint32_t keysym, uint8_t down);
void vnc_core_send_clipboard(const char* text, int len);
void vnc_core_send_fb_request(uint8_t incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h);

// Desktop blocking VNC protocol processing functions (called by vnc_client_thread on desktop)
#ifndef __EMSCRIPTEN__
int read_exact(int fd, void* buf, size_t len);
int vnc_core_desktop_handshake(int fd, const char* preferred_encoding);
int vnc_core_process_message(int fd);
#endif

#endif
