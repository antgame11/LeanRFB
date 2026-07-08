#include "vnc_client_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <jpeglib.h>

#ifndef __EMSCRIPTEN__
#include <unistd.h>
#endif

// Global VNC state variables
vnc_state_t vnc_state = STATE_WAIT_VERSION;
int screen_w = 0;
int screen_h = 0;
uint8_t* backbuffer = NULL;
pthread_mutex_t backbuffer_mutex = PTHREAD_MUTEX_INITIALIZER;
int client_running = 0;

static vnc_core_callbacks_t core_callbacks;
static void* core_user_data = NULL;

static uint8_t* input_buf = NULL;
static size_t input_buf_len = 0;
static size_t input_buf_cap = 0;

// Byte-order conversion helper functions
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

static inline uint16_t read_u16_be(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

static inline uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}

/* Compact DES block cipher for VncAuth */
static const uint8_t IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

static const uint8_t PC1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static const uint8_t PC2[] = {
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 24, 12, 4,
    2, 8, 18, 12, 29, 20, 19, 15,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t SHIFTS[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static const uint8_t E_TABLE[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const uint8_t P_TABLE[] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

static const uint8_t S_BOXES[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }
};

static uint64_t permute(uint64_t val, const uint8_t* table, int size, int val_len) {
    uint64_t res = 0;
    for (int i = 0; i < size; i++) {
        int pos = val_len - table[i];
        if ((val >> pos) & 1) {
            res |= ((uint64_t)1 << (size - 1 - i));
        }
    }
    return res;
}

static void des_encrypt_block(const uint8_t* in, const uint8_t* key_bytes, uint8_t* out) {
    uint64_t block = 0;
    for (int i = 0; i < 8; i++) block = (block << 8) | in[i];

    uint64_t key_val = 0;
    for (int i = 0; i < 8; i++) key_val = (key_val << 8) | key_bytes[i];

    uint64_t pc1 = permute(key_val, PC1, 56, 64);
    uint32_t c = (uint32_t)(pc1 >> 28) & 0x0FFFFFFF;
    uint32_t d = (uint32_t)pc1 & 0x0FFFFFFF;
    uint64_t subkeys[16];

    for (int r = 0; r < 16; r++) {
        int shift = SHIFTS[r];
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
        uint64_t cd = ((uint64_t)c << 28) | d;
        subkeys[r] = permute(cd, PC2, 48, 56);
    }

    uint64_t ip = permute(block, IP, 64, 64);
    uint32_t l = (uint32_t)(ip >> 32);
    uint32_t r = (uint32_t)ip;

    for (int round = 0; round < 16; round++) {
        uint32_t prev_l = l;
        l = r;

        uint64_t r_expanded = permute(r, E_TABLE, 48, 32);
        uint64_t xor_val = r_expanded ^ subkeys[round];
        uint32_t s_out = 0;

        for (int i = 0; i < 8; i++) {
            int chunk = (int)((xor_val >> (42 - i * 6)) & 0x3F);
            int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
            int col = (chunk & 0x1E) >> 1;
            uint8_t val = S_BOXES[i][row * 16 + col];
            s_out = (s_out << 4) | val;
        }

        uint32_t f_out = (uint32_t)permute(s_out, P_TABLE, 32, 32);
        r = prev_l ^ f_out;
    }

    uint64_t pre_fp = ((uint64_t)r << 32) | l;
    uint64_t fp = permute(pre_fp, FP, 64, 64);

    for (int i = 0; i < 8; i++) {
        out[7 - i] = (uint8_t)(fp & 0xFF);
        fp >>= 8;
    }
}

static void vnc_encrypt_bytes(const char* password, const uint8_t* challenge, uint8_t* response) {
    unsigned char key[8] = {0};
    size_t pass_len = strlen(password);
    for (int i = 0; i < 8; i++) {
        unsigned char b = (i < (int)pass_len) ? (unsigned char)password[i] : 0;
        unsigned char rev = 0;
        for (int bit = 0; bit < 8; bit++) {
            if (b & (1 << bit)) {
                rev |= (1 << (7 - bit));
            }
        }
        key[i] = rev;
    }

    des_encrypt_block(challenge, key, response);
    des_encrypt_block(challenge + 8, key, response + 8);
}

/* JPEG Decoding */
static int decode_jpeg(const uint8_t* jpeg_data, int jpeg_len, uint8_t* out_bgra, int rx, int ry, int rw, int rh, int screen_width) {
    (void)rh;
    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, jpeg_data, jpeg_len);

    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return -1;
    }

#ifdef JCS_EXT_BGRX
    cinfo.out_color_space = JCS_EXT_BGRX;
#else
    cinfo.out_color_space = JCS_RGB;
#endif

    jpeg_start_decompress(&cinfo);

    pthread_mutex_lock(&backbuffer_mutex);
    while (cinfo.output_scanline < cinfo.output_height) {
        int y = cinfo.output_scanline;
        uint8_t* row_ptr = out_bgra + ((ry + y) * screen_width + rx) * 4;
#ifdef JCS_EXT_BGRX
        JSAMPROW row_pointer[1] = { (JSAMPROW)row_ptr };
        jpeg_read_scanlines(&cinfo, row_pointer, 1);
#else
        uint8_t rgb_row[rw * 3];
        JSAMPROW row_pointer[1] = { (JSAMPROW)rgb_row };
        jpeg_read_scanlines(&cinfo, row_pointer, 1);
        for (int x = 0; x < rw; x++) {
            row_ptr[x * 4 + 0] = rgb_row[x * 3 + 2]; // B
            row_ptr[x * 4 + 1] = rgb_row[x * 3 + 1]; // G
            row_ptr[x * 4 + 2] = rgb_row[x * 3 + 0]; // R
            row_ptr[x * 4 + 3] = 255;
        }
#endif
    }
    pthread_mutex_unlock(&backbuffer_mutex);

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return 0;
}

/* Common APIs */
void vnc_core_init(const vnc_core_callbacks_t* callbacks, void* user_data) {
    core_callbacks = *callbacks;
    core_user_data = user_data;
    vnc_state = STATE_WAIT_VERSION;
    input_buf_len = 0;
}

void vnc_core_cleanup(void) {
    client_running = 0;
    pthread_mutex_lock(&backbuffer_mutex);
    free(backbuffer);
    backbuffer = NULL;
    pthread_mutex_unlock(&backbuffer_mutex);
    free(input_buf);
    input_buf = NULL;
    input_buf_cap = 0;
    input_buf_len = 0;
}

void vnc_core_send_pointer(uint16_t x, uint16_t y, uint8_t button_mask) {
    uint8_t buf[6];
    buf[0] = 5; // PointerEvent
    buf[1] = button_mask;
    write_u16_be(buf + 2, x);
    write_u16_be(buf + 4, y);
    core_callbacks.send_raw(buf, 6, core_user_data);
}

void vnc_core_send_key(uint32_t keysym, uint8_t down) {
    uint8_t buf[8];
    buf[0] = 4; // KeyEvent
    buf[1] = down;
    buf[2] = 0;
    buf[3] = 0;
    write_u32_be(buf + 4, keysym);
    core_callbacks.send_raw(buf, 8, core_user_data);
}

void vnc_core_send_clipboard(const char* text, int len) {
    if (len <= 0) return;
    uint8_t* buf = malloc(8 + (size_t)len);
    if (buf) {
        buf[0] = 6; // ClientCutText
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        write_u32_be(buf + 4, (uint32_t)len);
        memcpy(buf + 8, text, (size_t)len);
        core_callbacks.send_raw(buf, 8 + (size_t)len, core_user_data);
        free(buf);
    }
}

void vnc_core_send_fb_request(uint8_t incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    uint8_t buf[10];
    buf[0] = 3; // FramebufferUpdateRequest
    buf[1] = incremental;
    write_u16_be(buf + 2, x);
    write_u16_be(buf + 4, y);
    write_u16_be(buf + 6, w);
    write_u16_be(buf + 8, h);
    core_callbacks.send_raw(buf, 10, core_user_data);
}

#ifdef __EMSCRIPTEN__
/* Event-driven parser state machine (Web/WASM only) */
static void append_to_input_buffer(const uint8_t* data, size_t len) {
    if (input_buf_len + len > input_buf_cap) {
        input_buf_cap = (input_buf_len + len) * 2;
        input_buf = realloc(input_buf, input_buf_cap);
    }
    memcpy(input_buf + input_buf_len, data, len);
    input_buf_len += len;
}

static void consume_input_buffer(size_t bytes) {
    if (bytes >= input_buf_len) {
        input_buf_len = 0;
    } else {
        memmove(input_buf, input_buf + bytes, input_buf_len - bytes);
        input_buf_len -= bytes;
    }
}

void vnc_core_process_data(const uint8_t* data, size_t len) {
    append_to_input_buffer(data, len);
    
    while (input_buf_len > 0) {
        size_t processed = 0;
        if (vnc_state == STATE_WAIT_VERSION) {
            if (input_buf_len < 12) break;
            char ver[13] = {0};
            memcpy(ver, input_buf, 12);
            
            const char* our_ver = "RFB 003.008\n";
            core_callbacks.send_raw((const uint8_t*)our_ver, 12, core_user_data);
            
            processed = 12;
            vnc_state = STATE_WAIT_SECURITY;
        }
        else if (vnc_state == STATE_WAIT_SECURITY) {
            if (input_buf_len < 1) break;
            uint8_t num_sec_types = input_buf[0];
            if (input_buf_len < 1 + (size_t)num_sec_types) break;
            
            uint8_t selected_sec = 0;
            for (int i = 0; i < num_sec_types; i++) {
                uint8_t sec = input_buf[1 + i];
                if (sec == 2) {
                    selected_sec = 2; // VncAuth
                    break;
                } else if (sec == 1 && selected_sec == 0) {
                    selected_sec = 1; // None
                }
            }
            
            if (selected_sec == 0) {
                core_callbacks.on_disconnect("No supported authentication types", core_user_data);
                return;
            }
            
            core_callbacks.send_raw(&selected_sec, 1, core_user_data);
            processed = 1 + (size_t)num_sec_types;
            if (selected_sec == 2) {
                vnc_state = STATE_WAIT_AUTH_CHALLENGE;
            } else {
                vnc_state = STATE_WAIT_AUTH_RESULT;
            }
        }
        else if (vnc_state == STATE_WAIT_AUTH_CHALLENGE) {
            if (input_buf_len < 16) break;
            
            char* pwd = core_callbacks.request_password(core_user_data);
            if (!pwd) {
                core_callbacks.on_disconnect("Password entry cancelled", core_user_data);
                return;
            }
            
            uint8_t response[16];
            vnc_encrypt_bytes(pwd, input_buf, response);
            free(pwd);
            
            core_callbacks.send_raw(response, 16, core_user_data);
            processed = 16;
            vnc_state = STATE_WAIT_AUTH_RESULT;
        }
        else if (vnc_state == STATE_WAIT_AUTH_RESULT) {
            if (input_buf_len < 4) break;
            uint32_t result = read_u32_be(input_buf);
            if (result != 0) {
                core_callbacks.on_disconnect("Authentication failed (Incorrect Password)", core_user_data);
                return;
            }
            
            uint8_t shared = 1;
            core_callbacks.send_raw(&shared, 1, core_user_data);
            
            processed = 4;
            vnc_state = STATE_WAIT_SERVER_INIT;
        }
        else if (vnc_state == STATE_WAIT_SERVER_INIT) {
            if (input_buf_len < 24) break;
            uint16_t w = read_u16_be(input_buf);
            uint16_t h = read_u16_be(input_buf + 2);
            uint32_t name_len = read_u32_be(input_buf + 20);
            
            if (input_buf_len < 24 + (size_t)name_len) break;
            
            screen_w = w;
            screen_h = h;
            
            pthread_mutex_lock(&backbuffer_mutex);
            backbuffer = realloc(backbuffer, (size_t)w * h * 4);
            memset(backbuffer, 0, (size_t)w * h * 4);
            pthread_mutex_unlock(&backbuffer_mutex);
            
            core_callbacks.on_desktop_resize(w, h, core_user_data);
            
            // Send SetEncodings
            uint8_t encs_msg[16];
            encs_msg[0] = 2; // SetEncodings
            encs_msg[1] = 0;
            write_u16_be(encs_msg + 2, 3);
            write_u32_be(encs_msg + 4, 7); // Tight (JPEG)
            write_u32_be(encs_msg + 8, 0); // Raw
            write_u32_be(encs_msg + 12, (uint32_t)VNC_ENCODING_EXT_DESKTOP_SIZE);
            core_callbacks.send_raw(encs_msg, 16, core_user_data);

            // Send initial FramebufferUpdateRequest
            vnc_core_send_fb_request(0, 0, 0, w, h);

            processed = 24 + (size_t)name_len;
            vnc_state = STATE_NORMAL;
            client_running = 1;
        }
        else if (vnc_state == STATE_NORMAL) {
            if (input_buf_len < 1) break;
            uint8_t msg_type = input_buf[0];
            if (msg_type == 0) { // FramebufferUpdate
                if (input_buf_len < 4) break;
                uint16_t num_rects = read_u16_be(input_buf + 2);
                
                size_t offset = 4;
                int rects_parsed = 0;
                while (rects_parsed < num_rects) {
                    if (input_buf_len < offset + 12) break;
                    uint16_t rx = read_u16_be(input_buf + offset);
                    uint16_t ry = read_u16_be(input_buf + offset + 2);
                    uint16_t rw = read_u16_be(input_buf + offset + 4);
                    uint16_t rh = read_u16_be(input_buf + offset + 6);
                    int32_t encoding = (int32_t)read_u32_be(input_buf + offset + 8);
                    
                    if (encoding == 0) { // Raw
                        size_t rect_bytes = (size_t)rw * rh * 4;
                        if (input_buf_len < offset + 12 + rect_bytes) break;
                        
                        const uint8_t* src = input_buf + offset + 12;
                        pthread_mutex_lock(&backbuffer_mutex);
                        for (int y = 0; y < rh; y++) {
                            memcpy(backbuffer + (((size_t)ry + y) * screen_w + rx) * 4, src + y * rw * 4, rw * 4);
                        }
                        pthread_mutex_unlock(&backbuffer_mutex);
                        
                        offset += 12 + rect_bytes;
                        rects_parsed++;
                        core_callbacks.on_screen_update(rx, ry, rw, rh, core_user_data);
                    }
                    else if (encoding == 7) { // Tight/JPEG
                        // Byte layout: compression-control byte (0x90 for JPEG), then
                        // a compact length prefix, then the JPEG data itself.
                        if (input_buf_len < offset + 14) break;
                        uint32_t jpeg_size = 0;
                        uint8_t b1 = input_buf[offset + 13];
                        size_t len_bytes = 1;
                        if (b1 & 0x80) {
                            if (input_buf_len < offset + 15) break;
                            uint8_t b2 = input_buf[offset + 14];
                            len_bytes = 2;
                            if (b2 & 0x80) {
                                if (input_buf_len < offset + 16) break;
                                uint8_t b3 = input_buf[offset + 15];
                                len_bytes = 3;
                                jpeg_size = (b1 & 0x7F) | ((uint32_t)(b2 & 0x7F) << 7) | ((uint32_t)b3 << 14);
                            } else {
                                jpeg_size = (b1 & 0x7F) | ((uint32_t)b2 << 7);
                            }
                        } else {
                            jpeg_size = b1;
                        }

                        if (input_buf_len < offset + 13 + len_bytes + jpeg_size) break;

                        const uint8_t* jpeg_data = input_buf + offset + 13 + len_bytes;
                        decode_jpeg(jpeg_data, (int)jpeg_size, backbuffer, rx, ry, rw, rh, screen_w);

                        offset += 13 + len_bytes + jpeg_size;
                        rects_parsed++;
                        core_callbacks.on_screen_update(rx, ry, rw, rh, core_user_data);
                    }
                    else if (encoding == VNC_ENCODING_EXT_DESKTOP_SIZE) {
                        // Payload: numberOfScreens(1) + pad(3), then one 16-byte
                        // screen structure per screen. Must be consumed even though
                        // we only care about the overall width/height in rw/rh.
                        if (input_buf_len < offset + 12 + 4) break;
                        uint8_t num_screens = input_buf[offset + 12];
                        size_t body_len = 4 + (size_t)num_screens * 16;
                        if (input_buf_len < offset + 12 + body_len) break;

                        if (ry == 0 && rw > 0 && rh > 0 && (rw != screen_w || rh != screen_h)) {
                            screen_w = rw;
                            screen_h = rh;
                            pthread_mutex_lock(&backbuffer_mutex);
                            backbuffer = realloc(backbuffer, (size_t)screen_w * screen_h * 4);
                            pthread_mutex_unlock(&backbuffer_mutex);
                            core_callbacks.on_desktop_resize(rw, rh, core_user_data);
                        }
                        offset += 12 + body_len;
                        rects_parsed++;
                    }
                    else {
                        offset += 12;
                        rects_parsed++;
                    }
                }
                
                if (rects_parsed < num_rects) break;
                
                vnc_core_send_fb_request(1, 0, 0, screen_w, screen_h);
                processed = offset;
            }
            else if (msg_type == 3) { // ServerCutText
                if (input_buf_len < 8) break;
                uint32_t length = read_u32_be(input_buf + 4);
                if (input_buf_len < 8 + (size_t)length) break;
                
                char* text = malloc(length + 1);
                if (text) {
                    memcpy(text, input_buf + 8, length);
                    text[length] = '\0';
                    core_callbacks.on_clipboard_update(text, (int)length, core_user_data);
                    free(text);
                }
                
                processed = 8 + (size_t)length;
            }
            else {
                processed = 1;
            }
        }
        
        if (processed == 0) break;
        consume_input_buffer(processed);
    }
}
#endif

#ifndef __EMSCRIPTEN__
/* Desktop-specific blocking I/O functions */
int read_exact(int fd, void* buf, size_t len) {
    size_t total = 0;
    char* p = (char*)buf;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return 0;
}

static int decode_hextile(int fd, uint8_t* out_bgra, int rx, int ry, int rw, int rh, int screen_width) {
    uint32_t bg = 0xFFFFFFFF;
    uint32_t fg = 0;
    uint8_t subenc = 0;

    for (int ty = ry; ty < ry + rh; ty += 16) {
        int th = (ry + rh - ty < 16) ? (ry + rh - ty) : 16;
        for (int tx = rx; tx < rx + rw; tx += 16) {
            int tw = (rx + rw - tx < 16) ? (rx + rw - tx) : 16;

            if (read_exact(fd, &subenc, 1) < 0) return -1;

            if (subenc & 1) { // Raw
                pthread_mutex_lock(&backbuffer_mutex);
                for (int y = 0; y < th; y++) {
                    size_t offset = ((ty + y) * (size_t)screen_width + tx) * 4;
                    if (read_exact(fd, out_bgra + offset, (size_t)tw * 4) < 0) {
                        pthread_mutex_unlock(&backbuffer_mutex);
                        return -1;
                    }
                }
                pthread_mutex_unlock(&backbuffer_mutex);
            } else {
                if (subenc & 2) { // BackgroundSpecified
                    if (read_exact(fd, &bg, 4) < 0) return -1;
                }
                if (subenc & 4) { // ForegroundSpecified
                    if (read_exact(fd, &fg, 4) < 0) return -1;
                }

                pthread_mutex_lock(&backbuffer_mutex);
                for (int y = 0; y < th; y++) {
                    uint32_t* row = (uint32_t*)out_bgra + (ty + y) * screen_width + tx;
                    for (int x = 0; x < tw; x++) {
                        row[x] = bg;
                    }
                }
                pthread_mutex_unlock(&backbuffer_mutex);

                if (subenc & 8) { // AnySubrects
                    uint8_t num_subrects = 0;
                    if (read_exact(fd, &num_subrects, 1) < 0) return -1;

                    for (int i = 0; i < num_subrects; i++) {
                        uint32_t color = fg;
                        if (subenc & 16) { // SubrectsColoured
                            if (read_exact(fd, &color, 4) < 0) return -1;
                        }

                        uint8_t pos = 0, size = 0;
                        if (read_exact(fd, &pos, 1) < 0 || read_exact(fd, &size, 1) < 0) return -1;

                        int sx = pos >> 4;
                        int sy = pos & 0x0F;
                        int sw = (size >> 4) + 1;
                        int sh = (size & 0x0F) + 1;

                        pthread_mutex_lock(&backbuffer_mutex);
                        for (int y = 0; y < sh; y++) {
                            uint32_t* row = (uint32_t*)out_bgra + (ty + sy + y) * screen_width + tx + sx;
                            for (int x = 0; x < sw; x++) {
                                row[x] = color;
                            }
                        }
                        pthread_mutex_unlock(&backbuffer_mutex);
                    }
                }
            }
        }
    }
    return 0;
}

int vnc_core_desktop_handshake(int fd, const char* preferred_encoding) {
    // 1. Version Handshake
    char ver[13] = {0};
    if (read_exact(fd, ver, 12) < 0) return -1;
    printf("Server version: %.12s", ver);
    send(fd, "RFB 003.008\n", 12, 0);

    // 2. Security Handshake
    uint8_t num_sec_types = 0;
    if (read_exact(fd, &num_sec_types, 1) < 0 || num_sec_types == 0) return -1;

    uint8_t* sec_types = malloc(num_sec_types);
    if (read_exact(fd, sec_types, num_sec_types) < 0) {
        free(sec_types);
        return -1;
    }

    uint8_t selected_sec = 0;
    for (int i = 0; i < num_sec_types; i++) {
        if (sec_types[i] == 2) {
            selected_sec = 2;
            break;
        } else if (sec_types[i] == 1 && selected_sec == 0) {
            selected_sec = 1;
        }
    }
    free(sec_types);

    if (selected_sec == 0) return -1;
    send(fd, &selected_sec, 1, 0);

    // 3. Authenticate
    if (selected_sec == 2) {
        uint8_t challenge[16];
        if (read_exact(fd, challenge, 16) < 0) return -1;

        char* pwd = core_callbacks.request_password(core_user_data);
        if (!pwd) return -1;

        uint8_t response[16];
        vnc_encrypt_bytes(pwd, challenge, response);
        free(pwd);

        send(fd, response, 16, 0);
    }

    uint32_t sec_result = 0;
    if (read_exact(fd, &sec_result, 4) < 0) return -1;
    sec_result = read_u32_be((uint8_t*)&sec_result);
    if (sec_result != 0) return -1;

    // 4. ClientInit
    uint8_t shared = 1;
    send(fd, &shared, 1, 0);

    // 5. ServerInit
    uint16_t w = 0, h = 0;
    uint8_t pix_fmt[16];
    uint32_t name_len = 0;

    if (read_exact(fd, &w, 2) < 0 || read_exact(fd, &h, 2) < 0 ||
        read_exact(fd, pix_fmt, 16) < 0 || read_exact(fd, &name_len, 4) < 0) {
        return -1;
    }
    w = read_u16_be((uint8_t*)&w);
    h = read_u16_be((uint8_t*)&h);
    name_len = read_u32_be((uint8_t*)&name_len);

    char* server_name = malloc(name_len + 1);
    if (read_exact(fd, server_name, name_len) < 0) {
        free(server_name);
        return -1;
    }
    server_name[name_len] = '\0';
    printf("Server name: %s (%dx%d)\n", server_name, w, h);
    free(server_name);

    screen_w = w;
    screen_h = h;

    pthread_mutex_lock(&backbuffer_mutex);
    backbuffer = realloc(backbuffer, (size_t)w * h * 4);
    memset(backbuffer, 0, (size_t)w * h * 4);
    pthread_mutex_unlock(&backbuffer_mutex);

    core_callbacks.on_desktop_resize(w, h, core_user_data);

    // Send SetEncodings
    uint8_t encs_msg[128];
    encs_msg[0] = 2;
    encs_msg[1] = 0;

    int num_encs = 0;
    if (strcmp(preferred_encoding, "h264") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 50); // H.264
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, VNC_ENCODING_UDP_SETUP); // opt into the UDP transport
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 7);  // Tight (JPEG)
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    } else if (strcmp(preferred_encoding, "vp9") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, VNC_ENCODING_VP9); // VP9
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, VNC_ENCODING_UDP_SETUP); // opt into the UDP transport
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 7);  // Tight (JPEG)
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    } else if (strcmp(preferred_encoding, "jpeg") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 7);  // Tight (JPEG)
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    } else if (strcmp(preferred_encoding, "hextile") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    }
    write_u32_be(encs_msg + 4 + (num_encs++) * 4, 0); // Raw fallback
    write_u32_be(encs_msg + 4 + (num_encs++) * 4, (uint32_t)VNC_ENCODING_EXT_DESKTOP_SIZE);
    write_u16_be(encs_msg + 2, num_encs);

    send(fd, encs_msg, 4 + (size_t)num_encs * 4, 0);

    // Initial Request
    vnc_core_send_fb_request(0, 0, 0, w, h);
    client_running = 1;

    return 0;
}

int vnc_core_process_message(int fd) {
    uint8_t msg_type = 0;
    if (recv(fd, &msg_type, 1, 0) <= 0) return -1;

    if (msg_type == 0) { // FramebufferUpdate
        uint8_t pad;
        uint16_t num_rects;
        if (read_exact(fd, &pad, 1) < 0 || read_exact(fd, &num_rects, 2) < 0) return -1;
        num_rects = read_u16_be((uint8_t*)&num_rects);

        for (int i = 0; i < num_rects; i++) {
            uint16_t rx, ry, rw, rh;
            uint32_t encoding;
            if (read_exact(fd, &rx, 2) < 0 || read_exact(fd, &ry, 2) < 0 ||
                read_exact(fd, &rw, 2) < 0 || read_exact(fd, &rh, 2) < 0 ||
                read_exact(fd, &encoding, 4) < 0) return -1;

            rx = read_u16_be((uint8_t*)&rx);
            ry = read_u16_be((uint8_t*)&ry);
            rw = read_u16_be((uint8_t*)&rw);
            rh = read_u16_be((uint8_t*)&rh);
            encoding = read_u32_be((uint8_t*)&encoding);

            if (encoding == 0) { // Raw
                pthread_mutex_lock(&backbuffer_mutex);
                for (int y = 0; y < rh; y++) {
                    size_t offset = (((size_t)ry + y) * screen_w + rx) * 4;
                    if (read_exact(fd, backbuffer + offset, (size_t)rw * 4) < 0) {
                        pthread_mutex_unlock(&backbuffer_mutex);
                        return -1;
                    }
                }
                pthread_mutex_unlock(&backbuffer_mutex);
                core_callbacks.on_screen_update(rx, ry, rw, rh, core_user_data);
            } 
            else if (encoding == 5) { // Hextile
                if (decode_hextile(fd, backbuffer, rx, ry, rw, rh, screen_w) < 0) return -1;
                core_callbacks.on_screen_update(rx, ry, rw, rh, core_user_data);
            }
            else if (encoding == 7) { // Tight (JPEG)
                uint32_t jpeg_size = 0;
                uint8_t ctrl = 0;
                if (read_exact(fd, &ctrl, 1) < 0) return -1; // Tight compression-control byte (0x90 for JPEG)
                uint8_t b1 = 0;
                if (read_exact(fd, &b1, 1) < 0) return -1;
                if (b1 & 0x80) {
                    uint8_t b2 = 0;
                    if (read_exact(fd, &b2, 1) < 0) return -1;
                    if (b2 & 0x80) {
                        uint8_t b3 = 0;
                        if (read_exact(fd, &b3, 1) < 0) return -1;
                        jpeg_size = (b1 & 0x7F) | ((uint32_t)(b2 & 0x7F) << 7) | ((uint32_t)b3 << 14);
                    } else {
                        jpeg_size = (b1 & 0x7F) | ((uint32_t)b2 << 7);
                    }
                } else {
                    jpeg_size = b1;
                }

                uint8_t* jpeg_data = malloc(jpeg_size);
                if (!jpeg_data) return -1;
                if (read_exact(fd, jpeg_data, jpeg_size) < 0) {
                    free(jpeg_data);
                    return -1;
                }

                if (decode_jpeg(jpeg_data, (int)jpeg_size, backbuffer, rx, ry, rw, rh, screen_w) < 0) {
                    free(jpeg_data);
                    return -1;
                }
                free(jpeg_data);
                core_callbacks.on_screen_update(rx, ry, rw, rh, core_user_data);
            }
            else if (encoding == (uint32_t)VNC_ENCODING_EXT_DESKTOP_SIZE) {
                // Payload: numberOfScreens(1) + pad(3), then one 16-byte screen
                // structure per screen. Must be read off the wire even though we
                // only care about the overall width/height in rw/rh.
                uint8_t num_screens = 0;
                uint8_t pad3[3];
                if (read_exact(fd, &num_screens, 1) < 0 || read_exact(fd, pad3, 3) < 0) return -1;
                for (int s = 0; s < num_screens; s++) {
                    uint8_t screen_struct[16];
                    if (read_exact(fd, screen_struct, 16) < 0) return -1;
                }

                if (ry == 0 && rw > 0 && rh > 0 && (rw != screen_w || rh != screen_h)) {
                    screen_w = rw;
                    screen_h = rh;
                    pthread_mutex_lock(&backbuffer_mutex);
                    backbuffer = realloc(backbuffer, (size_t)screen_w * screen_h * 4);
                    pthread_mutex_unlock(&backbuffer_mutex);
                    core_callbacks.on_desktop_resize(rw, rh, core_user_data);
                }
            }
            else {
                if (core_callbacks.on_custom_encoding) {
                    if (core_callbacks.on_custom_encoding(fd, encoding, rx, ry, rw, rh, core_user_data) < 0) {
                        return -1;
                    }
                }
            }
        }

        vnc_core_send_fb_request(1, 0, 0, screen_w, screen_h);
    }
    else if (msg_type == 3) { // ServerCutText
        uint8_t pad[3];
        uint32_t length;
        if (read_exact(fd, pad, 3) < 0 || read_exact(fd, &length, 4) < 0) return -1;
        length = read_u32_be((uint8_t*)&length);

        char* text = malloc(length + 1);
        if (!text) return -1;
        if (read_exact(fd, text, length) < 0) {
            free(text);
            return -1;
        }
        text[length] = '\0';
        core_callbacks.on_clipboard_update(text, (int)length, core_user_data);
        free(text);
    }
    return 0;
}
#endif
