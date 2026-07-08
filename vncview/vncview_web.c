#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <emscripten/emscripten.h>
#include <emscripten/websocket.h>
#include <SDL2/SDL.h>

#include "vnc_client_core.h"

static EMSCRIPTEN_WEBSOCKET_T ws;

static SDL_Window* window = NULL;
static SDL_Renderer* renderer = NULL;
static SDL_Texture* texture = NULL;

/* WebSocket Send Wrapper */
static void send_raw_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    emscripten_websocket_send_binary(ws, (void*)data, len);
}

static void on_screen_update_cb(int x, int y, int w, int h, void* user_data) {
    (void)x; (void)y; (void)w; (void)h; (void)user_data;
    // Handled in main rendering loop since backbuffer is shared
}

static void on_desktop_resize_cb(int w, int h, void* user_data) {
    (void)user_data;
    if (!window) {
        SDL_Init(SDL_INIT_VIDEO);
        window = SDL_CreateWindow("WASM VNC Client", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, w, h, 0);
        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    } else {
        SDL_SetWindowSize(window, w, h);
    }
    if (texture) {
        SDL_DestroyTexture(texture);
    }
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, w, h);
}

/* Clipboard interaction */
EM_JS(void, set_browser_clipboard, (const char* text), {
    var str = UTF8ToString(text);
    navigator.clipboard.writeText(str).catch(function(err) {
        console.error("Failed to write to clipboard:", err);
    });
});

static void on_clipboard_update_cb(const char* text, int len, void* user_data) {
    (void)user_data;
    (void)len;
    set_browser_clipboard(text);
}

static void on_disconnect_cb(const char* reason, void* user_data) {
    (void)user_data;
    printf("VNC Disconnected: %s\n", reason);
}

EMSCRIPTEN_KEEPALIVE
void* web_malloc(size_t size) {
    return malloc(size);
}

static char* request_password_cb(void* user_data) {
    (void)user_data;
    return (char*)EM_ASM_INT({
        var p = prompt("Enter VNC Password:");
        if (!p) p = "";
        var len = lengthBytesUTF8(p) + 1;
        var str = _web_malloc(len);
        stringToUTF8(p, str, len);
        return str;
    });
}

EMSCRIPTEN_KEEPALIVE
void on_web_paste(const char* text) {
    int len = strlen(text);
    vnc_core_send_clipboard(text, len);
}

/* SDL Input mapping */
static uint32_t sdl_key_to_vnc(SDL_Keycode sym) {
    if (sym >= SDLK_SPACE && sym <= SDLK_z) {
        return (uint32_t)sym;
    }
    switch (sym) {
        case SDLK_RETURN:    return 0xFF0D;
        case SDLK_BACKSPACE: return 0xFF08;
        case SDLK_TAB:       return 0xFF09;
        case SDLK_ESCAPE:    return 0xFF1B;
        case SDLK_DELETE:    return 0xFFFF;
        case SDLK_LSHIFT:    return 0xFFE1;
        case SDLK_RSHIFT:    return 0xFFE2;
        case SDLK_LCTRL:     return 0xFFE3;
        case SDLK_RCTRL:     return 0xFFE4;
        case SDLK_LALT:      return 0xFFE9;
        case SDLK_LEFT:      return 0xFF51;
        case SDLK_UP:        return 0xFF52;
        case SDLK_RIGHT:     return 0xFF53;
        case SDLK_DOWN:      return 0xFF54;
        default:             return 0;
    }
}

static uint8_t get_button_mask(void) {
    Uint32 buttons = SDL_GetMouseState(NULL, NULL);
    uint8_t mask = 0;
    if (buttons & SDL_BUTTON(SDL_BUTTON_LEFT))   mask |= 1;
    if (buttons & SDL_BUTTON(SDL_BUTTON_MIDDLE)) mask |= 2;
    if (buttons & SDL_BUTTON(SDL_BUTTON_RIGHT))  mask |= 4;
    return mask;
}

/* WebSocket Handlers */
static EM_BOOL onopen(int eventType, const EmscriptenWebSocketOpenEvent *websocketEvent, void *userData) {
    (void)eventType; (void)websocketEvent; (void)userData;
    printf("WebSocket connection opened!\n");
    return EM_TRUE;
}

static EM_BOOL onerror(int eventType, const EmscriptenWebSocketErrorEvent *websocketEvent, void *userData) {
    (void)eventType; (void)websocketEvent; (void)userData;
    printf("WebSocket error occurred!\n");
    return EM_TRUE;
}

static EM_BOOL onclose(int eventType, const EmscriptenWebSocketCloseEvent *websocketEvent, void *userData) {
    (void)eventType; (void)websocketEvent; (void)userData;
    printf("WebSocket connection closed!\n");
    vnc_core_cleanup();
    return EM_TRUE;
}

static EM_BOOL onmessage(int eventType, const EmscriptenWebSocketMessageEvent *websocketEvent, void *userData) {
    (void)eventType; (void)userData;
    if (websocketEvent->isText) {
        return EM_TRUE;
    }
    vnc_core_process_data(websocketEvent->data, websocketEvent->numBytes);
    return EM_TRUE;
}

EMSCRIPTEN_KEEPALIVE
void connect_vnc(const char* url) {
    EmscriptenWebSocketCreateAttributes attr;
    emscripten_websocket_init_create_attributes(&attr);
    attr.url = url;
    
    ws = emscripten_websocket_new(&attr);
    emscripten_websocket_set_onopen_callback(ws, NULL, onopen);
    emscripten_websocket_set_onerror_callback(ws, NULL, onerror);
    emscripten_websocket_set_onclose_callback(ws, NULL, onclose);
    emscripten_websocket_set_onmessage_callback(ws, NULL, onmessage);

    vnc_core_callbacks_t cb;
    cb.send_raw = send_raw_cb;
    cb.on_screen_update = on_screen_update_cb;
    cb.on_desktop_resize = on_desktop_resize_cb;
    cb.on_clipboard_update = on_clipboard_update_cb;
    cb.on_disconnect = on_disconnect_cb;
    cb.request_password = request_password_cb;

    vnc_core_init(&cb, NULL);
}

/* SDL Main Loop */
static void main_loop(void) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        if (event.type == SDL_QUIT) {
            emscripten_cancel_main_loop();
            return;
        }
        else if (event.type == SDL_MOUSEMOTION) {
            if (client_running) {
                uint16_t x = event.motion.x;
                uint16_t y = event.motion.y;
                vnc_core_send_pointer(x, y, get_button_mask());
            }
        }
        else if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_MOUSEBUTTONUP) {
            if (client_running) {
                uint16_t x = event.button.x;
                uint16_t y = event.button.y;
                vnc_core_send_pointer(x, y, get_button_mask());
            }
        }
        else if (event.type == SDL_KEYDOWN || event.type == SDL_KEYUP) {
            if (client_running) {
                uint32_t keysym = sdl_key_to_vnc(event.key.keysym.sym);
                if (keysym != 0) {
                    vnc_core_send_key(keysym, event.type == SDL_KEYDOWN);
                }
            }
        }
    }
    
    if (renderer && texture && backbuffer) {
        SDL_UpdateTexture(texture, NULL, backbuffer, screen_w * 4);
        SDL_RenderClear(renderer);
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("WASM Client initialized. Awaiting VNC connection...\n");
    emscripten_set_main_loop(main_loop, 0, 1);
    return 0;
}
