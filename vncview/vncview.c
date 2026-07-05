#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <jpeglib.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavutil/imgutils.h>
#include <time.h>

// Standard VNC macros
#define write_u16_be(buf, val) do { \
    (buf)[0] = (uint8_t)((val) >> 8); \
    (buf)[1] = (uint8_t)(val); \
} while(0)

#define write_u32_be(buf, val) do { \
    (buf)[0] = (uint8_t)((val) >> 24); \
    (buf)[1] = (uint8_t)((val) >> 16); \
    (buf)[2] = (uint8_t)((val) >> 8); \
    (buf)[3] = (uint8_t)(val); \
} while(0)

static inline uint16_t read_u16_be(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

static inline uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}

// --- Encrypted UDP transport for H.264 (see docs/custom/rfb_h264_udp_extension.md) ---
// Mirrors the constants and AEAD framing used by src/leanrfb_udp.c; vncview.c does not
// link against libleanrfb, so the wire format is reimplemented here (the VNC auth DES
// helper above is duplicated the same way).
#define VNC_ENCODING_UDP_SETUP 51
#define VNC_UDP_TYPE_VIDEO 0
#define VNC_UDP_TYPE_HELLO 1
#define VNC_UDP_KEY_LEN 32
#define VNC_UDP_CID_LEN 8
#define VNC_UDP_TAG_LEN 16
#define VNC_UDP_HDR_LEN (1 + VNC_UDP_CID_LEN + 8)
#define VNC_UDP_INNER_HDR_LEN 10
#define VNC_UDP_MAX_FRAG_PAYLOAD 1200
#define VNC_UDP_MAX_FRAGS 512
#define VNC_UDP_MAX_DATAGRAM (VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN + VNC_UDP_INNER_HDR_LEN + VNC_UDP_MAX_FRAG_PAYLOAD)
#define VNC_UDP_HEARTBEAT_INTERVAL_MS 2000
#define VNC_UDP_SETUP_PAYLOAD_LEN (2 + VNC_UDP_CID_LEN + VNC_UDP_KEY_LEN)
#define VNC_MSG_REQUEST_KEYFRAME 254

typedef struct {
    uint64_t highest;
    uint64_t bitmap;
} udp_replay_state_t;

static unsigned long long vv_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void udp_build_nonce(uint8_t type, const uint8_t cid[VNC_UDP_CID_LEN], uint64_t counter, uint8_t nonce[12]) {
    nonce[0] = type;
    nonce[1] = cid[0];
    nonce[2] = cid[1];
    nonce[3] = cid[2];
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }
}

static int udp_seal(const uint8_t key[VNC_UDP_KEY_LEN], uint8_t type,
                    const uint8_t cid[VNC_UDP_CID_LEN], uint64_t counter,
                    const uint8_t* pt, int pt_len, uint8_t* out, int out_cap) {
    if (out_cap < VNC_UDP_HDR_LEN + pt_len + VNC_UDP_TAG_LEN) return -1;

    out[0] = type;
    memcpy(out + 1, cid, VNC_UDP_CID_LEN);
    for (int i = 0; i < 8; i++) {
        out[1 + VNC_UDP_CID_LEN + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }

    uint8_t nonce[12];
    udp_build_nonce(type, cid, counter, nonce);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int len = 0;
    int ciphertext_len = 0;
    uint8_t* ciphertext = out + VNC_UDP_HDR_LEN;

    if (ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
    if (ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && EVP_EncryptUpdate(ctx, NULL, &len, out, VNC_UDP_HDR_LEN) != 1) ok = 0;
    if (ok && pt_len > 0 && EVP_EncryptUpdate(ctx, ciphertext, &len, pt, pt_len) != 1) ok = 0;
    if (ok) ciphertext_len = (pt_len > 0) ? len : 0;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) ok = 0;
    if (ok) ciphertext_len += len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VNC_UDP_TAG_LEN, ciphertext + ciphertext_len) != 1) ok = 0;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return -1;
    return VNC_UDP_HDR_LEN + ciphertext_len + VNC_UDP_TAG_LEN;
}

static int udp_open(const uint8_t key[VNC_UDP_KEY_LEN], const uint8_t* in, int in_len,
                    uint8_t* out_type, uint64_t* out_counter, uint8_t* pt_out, int* pt_len_out) {
    if (in_len < VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN) return -1;

    uint8_t type = in[0];
    const uint8_t* cid = in + 1;
    uint64_t counter = 0;
    for (int i = 0; i < 8; i++) {
        counter = (counter << 8) | in[1 + VNC_UDP_CID_LEN + i];
    }

    int ciphertext_len = in_len - VNC_UDP_HDR_LEN - VNC_UDP_TAG_LEN;
    const uint8_t* ciphertext = in + VNC_UDP_HDR_LEN;
    const uint8_t* tag = in + in_len - VNC_UDP_TAG_LEN;

    uint8_t nonce[12];
    udp_build_nonce(type, cid, counter, nonce);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int len = 0;
    int plaintext_len = 0;

    if (ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
    if (ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && EVP_DecryptUpdate(ctx, NULL, &len, in, VNC_UDP_HDR_LEN) != 1) ok = 0;
    if (ok && ciphertext_len > 0 && EVP_DecryptUpdate(ctx, pt_out, &len, ciphertext, ciphertext_len) != 1) ok = 0;
    if (ok) plaintext_len = (ciphertext_len > 0) ? len : 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VNC_UDP_TAG_LEN, (void*)tag) != 1) ok = 0;
    if (ok && EVP_DecryptFinal_ex(ctx, pt_out + plaintext_len, &len) <= 0) ok = 0;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return -1;

    *out_type = type;
    *out_counter = counter;
    *pt_len_out = plaintext_len;
    return 0;
}

static int udp_replay_check(udp_replay_state_t* st, uint64_t counter) {
    if (counter > st->highest) {
        uint64_t shift = counter - st->highest;
        st->bitmap = (shift >= 64) ? 0 : (st->bitmap << shift);
        st->bitmap |= 1ULL;
        st->highest = counter;
        return 1;
    }
    uint64_t diff = st->highest - counter;
    if (diff >= 64) return 0;
    uint64_t mask = 1ULL << diff;
    if (st->bitmap & mask) return 0;
    st->bitmap |= mask;
    return 1;
}

// VNC auth helper
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
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
    DES_key_schedule schedule;
    DES_set_key((DES_cblock*)key, &schedule);
    DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)response, &schedule, DES_ENCRYPT);
    DES_ecb_encrypt((DES_cblock*)(challenge + 8), (DES_cblock*)(response + 8), &schedule, DES_ENCRYPT);
}
#pragma GCC diagnostic pop

// Last used address helpers
static void load_last_address(char* host_out, int* port_out) {
    char path[512];
    snprintf(path, sizeof(path), "%s/.config/vncviewer/last_address.conf", g_get_home_dir());
    FILE* f = fopen(path, "r");
    if (!f) {
        strcpy(host_out, "127.0.0.1");
        *port_out = 5900;
        return;
    }
    if (fscanf(f, "%255s %d", host_out, port_out) != 2) {
        strcpy(host_out, "127.0.0.1");
        *port_out = 5900;
    }
    fclose(f);
}

static void save_last_address(const char* host, int port) {
    char path[512];
    snprintf(path, sizeof(path), "%s/.config/vncviewer", g_get_home_dir());
    g_mkdir_with_parents(path, 0700);
    snprintf(path, sizeof(path), "%s/.config/vncviewer/last_address.conf", g_get_home_dir());
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s %d\n", host, port);
        fclose(f);
    }
}

// Global UI widgets
static GtkWidget* main_window = NULL;
static GtkWidget* viewer_window = NULL;
static GtkWidget* drawing_area = NULL;
static GtkWidget* entry_address = NULL;
static GtkWidget* combo_encoding = NULL;

// Thread-shared VNC client states
static int vnc_fd = -1;
static int screen_w = 0;
static int screen_h = 0;
static uint8_t* backbuffer = NULL;
static pthread_mutex_t backbuffer_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int client_running = 0;
static uint8_t button_mask = 0;
static char preferred_encoding[32] = "h264";
static volatile int waiting_for_draw = 0;

// UDP H.264 transport state (owned by vnc_client_thread; see docs/custom/rfb_h264_udp_extension.md)
static int udp_fd = -1;
static struct in_addr udp_server_in_addr; // set from the TCP connection's resolved address
static struct sockaddr_in udp_server_addr;
static uint8_t udp_key[VNC_UDP_KEY_LEN];
static uint8_t udp_cid[VNC_UDP_CID_LEN];
static uint64_t udp_send_ctr = 0;
static udp_replay_state_t udp_recv_replay;
static volatile int udp_active = 0;
static unsigned long long udp_last_heartbeat_ms = 0;
static unsigned long long udp_last_keyframe_request_ms = 0;

// UDP frame reassembly state (single in-flight frame; stale/incomplete frames are dropped
// rather than blocking, since low latency matters more than never losing a frame here)
static int reasm_active = 0;
static uint32_t reasm_frame_id = 0;
static uint16_t reasm_frag_count = 0;
static uint16_t reasm_frags_got = 0;
static uint16_t reasm_last_frag_len = 0;
static uint8_t reasm_flags = 0;
static uint8_t* reasm_buf = NULL;
static size_t reasm_buf_cap = 0;
static uint8_t reasm_got_bitmap[(VNC_UDP_MAX_FRAGS + 7) / 8];
static int have_last_completed_frame = 0;
static uint32_t last_completed_frame_id = 0;

// FFmpeg variables
static AVCodecContext* codec_ctx = NULL;
static AVFrame* frame = NULL;
static AVPacket* pkt = NULL;
static struct SwsContext* sws_ctx = NULL;
static AVBufferRef* hw_device_ctx = NULL;
static AVFrame* sw_frame = NULL;
static enum AVPixelFormat hw_pix_fmt = AV_PIX_FMT_NONE;
static enum AVPixelFormat last_format = AV_PIX_FMT_NONE;
static enum AVPixelFormat expected_hw_pix_fmt = AV_PIX_FMT_NONE;

static enum AVPixelFormat get_hw_format(AVCodecContext *ctx, const enum AVPixelFormat *pix_fmts) {
    (void)ctx;
    const enum AVPixelFormat *p;
    for (p = pix_fmts; *p != -1; p++) {
        if (*p == expected_hw_pix_fmt) {
            hw_pix_fmt = *p;
            return *p;
        }
    }
    fprintf(stderr, "Failed to get expected HW surface format.\n");
    return AV_PIX_FMT_NONE;
}

static void init_decoder(int width, int height) {
    const AVCodec* codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        fprintf(stderr, "Error: H.264 decoder not found in libavcodec\n");
        return;
    }
    codec_ctx = avcodec_alloc_context3(codec);
    codec_ctx->width = width;
    codec_ctx->height = height;
    codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    
    codec_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    codec_ctx->flags2 |= AV_CODEC_FLAG2_FAST;
    codec_ctx->thread_count = 0;
    codec_ctx->thread_type = FF_THREAD_SLICE;

    // Attempt to initialize GPU VA-API (Intel/AMD)
    int ret = av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_VAAPI, NULL, NULL, 0);
    if (ret >= 0) {
        codec_ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
        codec_ctx->get_format = get_hw_format;
        expected_hw_pix_fmt = AV_PIX_FMT_VAAPI;
        printf("[VNCVIEW] GPU VA-API Hardware Decoding enabled successfully.\n");
    } else {
        // Try GPU CUDA (Nvidia)
        ret = av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_CUDA, NULL, NULL, 0);
        if (ret >= 0) {
            codec_ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
            codec_ctx->get_format = get_hw_format;
            expected_hw_pix_fmt = AV_PIX_FMT_CUDA;
            printf("[VNCVIEW] GPU CUDA Hardware Decoding enabled successfully.\n");
        } else {
            expected_hw_pix_fmt = AV_PIX_FMT_NONE;
            printf("[VNCVIEW] GPU Hardware Decoding not supported. Falling back to CPU software decoding.\n");
        }
    }

    AVDictionary* opts = NULL;
    av_dict_set(&opts, "tune", "zerolatency", 0);
    
    if (avcodec_open2(codec_ctx, codec, &opts) < 0) {
        fprintf(stderr, "Error: Could not open libavcodec H.264 decoder\n");
    }
    av_dict_free(&opts);

    frame = av_frame_alloc();
    pkt = av_packet_alloc();
    sw_frame = av_frame_alloc();
    last_format = AV_PIX_FMT_NONE;
}

static void reset_decoder(int width, int height) {
    if (codec_ctx) {
        avcodec_free_context(&codec_ctx);
        codec_ctx = NULL;
    }
    if (frame) {
        av_frame_free(&frame);
        frame = NULL;
    }
    if (pkt) {
        av_packet_free(&pkt);
        pkt = NULL;
    }
    if (sw_frame) {
        av_frame_free(&sw_frame);
        sw_frame = NULL;
    }
    if (hw_device_ctx) {
        av_buffer_unref(&hw_device_ctx);
        hw_device_ctx = NULL;
    }
    if (sws_ctx) {
        sws_freeContext(sws_ctx);
        sws_ctx = NULL;
    }
    hw_pix_fmt = AV_PIX_FMT_NONE;
    last_format = AV_PIX_FMT_NONE;
    expected_hw_pix_fmt = AV_PIX_FMT_NONE;
    init_decoder(width, height);
}

static int decode_h264(const uint8_t* data, int len, uint8_t* out_bgra, int width, int height) {
    if (!codec_ctx) {
        init_decoder(width, height);
        if (!codec_ctx) return -1;
    }
    pkt->data = (uint8_t*)data;
    pkt->size = len;

    int ret = avcodec_send_packet(codec_ctx, pkt);
    if (ret < 0) return -1;

    ret = avcodec_receive_frame(codec_ctx, frame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
        return 0;
    } else if (ret < 0) {
        return -1;
    }

    AVFrame* src_frame = frame;
    if (frame->format == hw_pix_fmt && hw_pix_fmt != AV_PIX_FMT_NONE) {
        av_frame_unref(sw_frame);
        int err = av_hwframe_transfer_data(sw_frame, frame, 0);
        if (err >= 0) {
            src_frame = sw_frame;
        }
    }

    if (!sws_ctx || last_format != src_frame->format) {
        if (sws_ctx) {
            sws_freeContext(sws_ctx);
        }
        sws_ctx = sws_getContext(codec_ctx->width, codec_ctx->height, src_frame->format,
                                 width, height, AV_PIX_FMT_BGRA,
                                 SWS_BILINEAR, NULL, NULL, NULL);
        last_format = src_frame->format;
    }

    uint8_t* dest[4] = { out_bgra, NULL, NULL, NULL };
    int dest_linesize[4] = { width * 4, 0, 0, 0 };

    pthread_mutex_lock(&backbuffer_mutex);
    sws_scale(sws_ctx, (const uint8_t *const *)src_frame->data, src_frame->linesize, 0, codec_ctx->height,
              dest, dest_linesize);
    pthread_mutex_unlock(&backbuffer_mutex);

    return 1;
}

// JPEG Decoder utilizing libjpeg
static int decode_jpeg(const uint8_t* jpeg_data, int jpeg_len, uint8_t* out_bgra, int rx, int ry, int rw, int rh, int screen_width) {
    (void)rw;
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

    cinfo.out_color_space = JCS_EXT_BGRX;
    jpeg_start_decompress(&cinfo);

    pthread_mutex_lock(&backbuffer_mutex);
    while (cinfo.output_scanline < cinfo.output_height) {
        int y = cinfo.output_scanline;
        uint8_t* row_ptr = out_bgra + ((ry + y) * screen_width + rx) * 4;
        JSAMPROW row_pointer[1] = { (JSAMPROW)row_ptr };
        jpeg_read_scanlines(&cinfo, row_pointer, 1);
    }
    pthread_mutex_unlock(&backbuffer_mutex);

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return 0;
}

// Hextile Decoder
static int decode_hextile(int fd, uint8_t* out_bgra, int rx, int ry, int rw, int rh, int screen_width) {
    uint32_t bg = 0xFFFFFFFF;
    uint32_t fg = 0;
    uint8_t subenc = 0;
    
    extern int read_exact(int fd, void* buf, size_t len);

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

static void send_fb_request(int fd, uint8_t incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    uint8_t buf[10];
    buf[0] = 3; 
    buf[1] = incremental;
    write_u16_be(buf + 2, x);
    write_u16_be(buf + 4, y);
    write_u16_be(buf + 6, w);
    write_u16_be(buf + 8, h);
    send(fd, buf, 10, 0);
}

// Drawing area callbacks
static gboolean on_draw(GtkWidget* widget, cairo_t* cr, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (!backbuffer) return FALSE;

    pthread_mutex_lock(&backbuffer_mutex);
    cairo_surface_t* surface = cairo_image_surface_create_for_data(
        backbuffer, CAIRO_FORMAT_RGB24, screen_w, screen_h, screen_w * 4);
    cairo_set_source_surface(cr, surface, 0, 0);
    cairo_paint(cr);
    cairo_surface_destroy(surface);

    if (waiting_for_draw && vnc_fd >= 0) {
        waiting_for_draw = 0;
        send_fb_request(vnc_fd, 1, 0, 0, screen_w, screen_h);
    }
    pthread_mutex_unlock(&backbuffer_mutex);

    return FALSE;
}

static void send_pointer(double x, double y, uint8_t mask) {
    if (vnc_fd >= 0) {
        uint8_t buf[6];
        buf[0] = 5; 
        buf[1] = mask;
        write_u16_be(buf + 2, (uint16_t)x);
        write_u16_be(buf + 4, (uint16_t)y);
        send(vnc_fd, buf, 6, 0);
    }
}

static gboolean on_motion(GtkWidget* widget, GdkEventMotion* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    send_pointer(event->x, event->y, button_mask);
    return TRUE;
}

static gboolean on_button(GtkWidget* widget, GdkEventButton* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    int down = (event->type == GDK_BUTTON_PRESS) ? 1 : 0;
    int button = event->button;
    if (button == 1) {
        if (down) button_mask |= 1; else button_mask &= ~1;
    } else if (button == 2) {
        if (down) button_mask |= 2; else button_mask &= ~2;
    } else if (button == 3) {
        if (down) button_mask |= 4; else button_mask &= ~4;
    }
    send_pointer(event->x, event->y, button_mask);
    return TRUE;
}

static gboolean on_scroll(GtkWidget* widget, GdkEventScroll* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    uint8_t mask = button_mask;
    if (event->direction == GDK_SCROLL_UP) {
        mask |= 8;
        send_pointer(event->x, event->y, mask);
        mask &= ~8;
        send_pointer(event->x, event->y, mask);
    } else if (event->direction == GDK_SCROLL_DOWN) {
        mask |= 16;
        send_pointer(event->x, event->y, mask);
        mask &= ~16;
        send_pointer(event->x, event->y, mask);
    }
    return TRUE;
}

static void send_key(uint8_t down, uint32_t keysym) {
    if (vnc_fd >= 0) {
        uint8_t buf[8];
        buf[0] = 4; 
        buf[1] = down;
        buf[2] = 0;
        buf[3] = 0;
        write_u32_be(buf + 4, keysym);
        send(vnc_fd, buf, 8, 0);
    }
}

static gboolean on_key_event(GtkWidget* widget, GdkEventKey* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    int down = (event->type == GDK_KEY_PRESS) ? 1 : 0;
    send_key(down, event->keyval);
    return TRUE;
}

static gboolean queue_draw_idle(gpointer data) {
    (void)data;
    gtk_widget_queue_draw(drawing_area);
    return FALSE;
}

static gboolean destroy_widget_idle(gpointer data) {
    if (data && data == viewer_window) {
        gtk_widget_destroy(GTK_WIDGET(viewer_window));
        viewer_window = NULL;
    }
    return FALSE;
}

// Ask the server for a fresh IDR keyframe (rate-limited). Used to recover quickly from
// UDP packet/frame loss rather than waiting for the encoder's periodic GOP boundary.
static void request_keyframe(void) {
    unsigned long long now = vv_now_ms();
    if (now - udp_last_keyframe_request_ms < 500) return;
    udp_last_keyframe_request_ms = now;
    if (vnc_fd >= 0) {
        uint8_t msg = VNC_MSG_REQUEST_KEYFRAME;
        send(vnc_fd, &msg, 1, 0);
    }
}

// Send an authenticated Hello/heartbeat datagram: opens the NAT mapping on first send and
// keeps it (and the server's liveness timer) alive afterwards.
static void udp_send_hello(void) {
    if (udp_fd < 0) return;
    uint8_t out[VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN];
    int len = udp_seal(udp_key, VNC_UDP_TYPE_HELLO, udp_cid, udp_send_ctr++, NULL, 0, out, sizeof(out));
    if (len > 0) {
        sendto(udp_fd, out, (size_t)len, 0, (struct sockaddr*)&udp_server_addr, sizeof(udp_server_addr));
    }
    udp_last_heartbeat_ms = vv_now_ms();
}

// Handle the one-time VNC_ENCODING_UDP_SETUP rectangle: sets up the local UDP socket + key
// and immediately punches a Hello through to the server.
static void udp_handle_setup(const uint8_t* payload) {
    uint16_t port = read_u16_be(payload);
    memcpy(udp_cid, payload + 2, VNC_UDP_CID_LEN);
    memcpy(udp_key, payload + 2 + VNC_UDP_CID_LEN, VNC_UDP_KEY_LEN);

    if (udp_fd < 0) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    memset(&udp_server_addr, 0, sizeof(udp_server_addr));
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_port = htons(port);
    udp_server_addr.sin_addr = udp_server_in_addr;

    udp_send_ctr = 0;
    udp_recv_replay.highest = 0;
    udp_recv_replay.bitmap = 0;
    reasm_active = 0;
    have_last_completed_frame = 0;

    if (udp_fd >= 0) {
        udp_active = 1;
        udp_send_hello();
    }
}

static void reasm_start(uint32_t frame_id, uint16_t frag_count) {
    size_t needed = (size_t)frag_count * VNC_UDP_MAX_FRAG_PAYLOAD;
    if (needed > reasm_buf_cap) {
        uint8_t* new_buf = realloc(reasm_buf, needed);
        if (!new_buf) return; // drop this frame; we'll pick up the next one
        reasm_buf = new_buf;
        reasm_buf_cap = needed;
    }
    memset(reasm_got_bitmap, 0, sizeof(reasm_got_bitmap));
    reasm_frame_id = frame_id;
    reasm_frag_count = frag_count;
    reasm_frags_got = 0;
    reasm_last_frag_len = 0;
    reasm_active = 1;
}

// Process one authenticated+decrypted VIDEO payload (inner header + fragment bytes).
static void reasm_add_fragment(const uint8_t* pt, int pt_len) {
    if (pt_len < VNC_UDP_INNER_HDR_LEN) return;

    uint32_t frame_id = read_u32_be(pt);
    uint16_t frag_idx = read_u16_be(pt + 4);
    uint16_t frag_count = read_u16_be(pt + 6);
    uint8_t flags = pt[8];
    int frag_len = pt_len - VNC_UDP_INNER_HDR_LEN;

    if (frag_count == 0 || frag_count > VNC_UDP_MAX_FRAGS || frag_idx >= frag_count) return;

    if (!reasm_active || frame_id != reasm_frame_id) {
        // A new frame started before the previous one finished (or this is simply the
        // first frame seen) — dropping the stale partial frame is the right call for
        // latency, but it also means we lost data, so ask for a keyframe to recover.
        if (reasm_active && reasm_frags_got < reasm_frag_count) {
            request_keyframe();
        }
        if (have_last_completed_frame && frame_id != last_completed_frame_id + 1) {
            request_keyframe();
        }
        reasm_start(frame_id, frag_count);
    }
    if (!reasm_active || !reasm_buf) return;

    size_t byte_off = (size_t)frag_idx * VNC_UDP_MAX_FRAG_PAYLOAD;
    if (byte_off + (size_t)frag_len > reasm_buf_cap) return;

    if (!(reasm_got_bitmap[frag_idx / 8] & (1 << (frag_idx % 8)))) {
        memcpy(reasm_buf + byte_off, pt + VNC_UDP_INNER_HDR_LEN, (size_t)frag_len);
        reasm_got_bitmap[frag_idx / 8] |= (1 << (frag_idx % 8));
        reasm_frags_got++;
        reasm_flags = flags;
        if (frag_idx == frag_count - 1) reasm_last_frag_len = (uint16_t)frag_len;
    }

    if (reasm_frags_got == reasm_frag_count) {
        size_t total_len = (size_t)(reasm_frag_count - 1) * VNC_UDP_MAX_FRAG_PAYLOAD + reasm_last_frag_len;

        if (reasm_flags & 2) {
            reset_decoder(screen_w, screen_h);
        }
        if (total_len > 0) {
            decode_h264(reasm_buf, (int)total_len, backbuffer, screen_w, screen_h);
        }

        have_last_completed_frame = 1;
        last_completed_frame_id = frame_id;
        reasm_active = 0;

        pthread_mutex_lock(&backbuffer_mutex);
        waiting_for_draw = 1;
        pthread_mutex_unlock(&backbuffer_mutex);
        g_idle_add((GSourceFunc)queue_draw_idle, NULL);
    }
}

// Drain all pending datagrams on udp_fd and feed authenticated VIDEO payloads to the
// frame reassembler. Bounded so one call can't monopolize the network thread.
static void udp_drain(void) {
    uint8_t buf[VNC_UDP_MAX_DATAGRAM];
    uint8_t plaintext[VNC_UDP_MAX_DATAGRAM];

    for (int iter = 0; iter < 256; iter++) {
        ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
        if (n <= 0) return;
        if (n < VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN) continue;
        if (buf[0] != VNC_UDP_TYPE_VIDEO) continue; // only the server sends VIDEO datagrams
        if (memcmp(buf + 1, udp_cid, VNC_UDP_CID_LEN) != 0) continue;

        uint8_t type = 0;
        uint64_t counter = 0;
        int pt_len = 0;
        if (udp_open(udp_key, buf, (int)n, &type, &counter, plaintext, &pt_len) < 0) continue;
        if (!udp_replay_check(&udp_recv_replay, counter)) continue;

        reasm_add_fragment(plaintext, pt_len);
    }
}

// Background network client loop thread (after handshake is complete)
static void* vnc_client_thread(void* arg) {
    (void)arg;
    int fd = vnc_fd;
    int w = screen_w;
    int h = screen_h;

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
    } else if (strcmp(preferred_encoding, "jpeg") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 7);  // Tight
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    } else if (strcmp(preferred_encoding, "hextile") == 0) {
        write_u32_be(encs_msg + 4 + (num_encs++) * 4, 5);  // Hextile
    }
    write_u32_be(encs_msg + 4 + (num_encs++) * 4, 0); // Raw fallback
    write_u16_be(encs_msg + 2, num_encs);
    
    send(fd, encs_msg, 4 + (size_t)num_encs * 4, 0);

    // Initial frame request
    send_fb_request(fd, 0, 0, 0, w, h);

    client_running = 1;
    while (client_running) {
        struct pollfd pfds[2];
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = udp_fd; // may be -1 until the UDP setup rect arrives; poll() ignores that
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll(pfds, 2, 1000); // wake at least once/sec to service the UDP heartbeat
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (udp_active && vv_now_ms() - udp_last_heartbeat_ms >= VNC_UDP_HEARTBEAT_INTERVAL_MS) {
            udp_send_hello();
        }

        if (pfds[1].revents & POLLIN) {
            udp_drain();
        }

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (!(pfds[0].revents & POLLIN)) continue;

        uint8_t msg_type = 0;
        if (recv(fd, &msg_type, 1, 0) <= 0) break;

        if (msg_type == 0) { // FramebufferUpdate
            uint8_t pad;
            uint16_t num_rects;
            if (read_exact(fd, &pad, 1) < 0 || read_exact(fd, &num_rects, 2) < 0) break;
            num_rects = read_u16_be((uint8_t*)&num_rects);

            for (int i = 0; i < num_rects; i++) {
                uint16_t rx, ry, rw, rh;
                uint32_t encoding;
                if (read_exact(fd, &rx, 2) < 0 || read_exact(fd, &ry, 2) < 0 ||
                    read_exact(fd, &rw, 2) < 0 || read_exact(fd, &rh, 2) < 0 ||
                    read_exact(fd, &encoding, 4) < 0) goto exit_thread;

                rx = read_u16_be((uint8_t*)&rx);
                ry = read_u16_be((uint8_t*)&ry);
                rw = read_u16_be((uint8_t*)&rw);
                rh = read_u16_be((uint8_t*)&rh);
                encoding = read_u32_be((uint8_t*)&encoding);

                if (encoding == 0) { // Raw
                    pthread_mutex_lock(&backbuffer_mutex);
                    for (int y = 0; y < rh; y++) {
                        size_t offset = ((ry + y) * (size_t)w + rx) * 4;
                        if (read_exact(fd, backbuffer + offset, (size_t)rw * 4) < 0) {
                            pthread_mutex_unlock(&backbuffer_mutex);
                            goto exit_thread;
                        }
                    }
                    pthread_mutex_unlock(&backbuffer_mutex);
                } 
                else if (encoding == 5) { // Hextile
                    if (decode_hextile(fd, backbuffer, rx, ry, rw, rh, w) < 0) goto exit_thread;
                }
                else if (encoding == 7) { // Tight (JPEG)
                    uint8_t comp_byte = 0;
                    if (read_exact(fd, &comp_byte, 1) < 0) goto exit_thread;

                    uint32_t jpeg_size = 0;
                    uint8_t b1 = 0;
                    if (read_exact(fd, &b1, 1) < 0) goto exit_thread;
                    if (b1 < 128) {
                        jpeg_size = b1;
                    } else {
                        uint8_t b2 = 0;
                        if (read_exact(fd, &b2, 1) < 0) goto exit_thread;
                        if (b2 < 128) {
                            jpeg_size = (b1 & 0x7F) | ((uint32_t)b2 << 7);
                        } else {
                            uint8_t b3 = 0;
                            if (read_exact(fd, &b3, 1) < 0) goto exit_thread;
                            jpeg_size = (b1 & 0x7F) | ((uint32_t)(b2 & 0x7F) << 7) | ((uint32_t)b3 << 14);
                        }
                    }

                    uint8_t* jpeg_data = malloc(jpeg_size);
                    if (read_exact(fd, jpeg_data, jpeg_size) < 0) {
                        free(jpeg_data);
                        goto exit_thread;
                    }

                    decode_jpeg(jpeg_data, jpeg_size, backbuffer, rx, ry, rw, rh, w);
                    free(jpeg_data);
                }
                else if (encoding == 50) { // H.264
                    uint32_t length = 0;
                    uint32_t flags = 0;
                    if (read_exact(fd, &length, 4) < 0 || read_exact(fd, &flags, 4) < 0) goto exit_thread;
                    length = read_u32_be((uint8_t*)&length);
                    flags = read_u32_be((uint8_t*)&flags);

                    uint8_t* payload = malloc(length);
                    if (read_exact(fd, payload, length) < 0) {
                        free(payload);
                        goto exit_thread;
                    }

                    if (flags & 2) {
                        reset_decoder(w, h);
                    }

                    if (length > 0) {
                        decode_h264(payload, length, backbuffer, w, h);
                    }
                    free(payload);
                }
                else if (encoding == VNC_ENCODING_UDP_SETUP) {
                    uint8_t setup_payload[VNC_UDP_SETUP_PAYLOAD_LEN];
                    if (read_exact(fd, setup_payload, sizeof(setup_payload)) < 0) goto exit_thread;
                    udp_handle_setup(setup_payload);
                }
            }

            pthread_mutex_lock(&backbuffer_mutex);
            waiting_for_draw = 1;
            pthread_mutex_unlock(&backbuffer_mutex);

            g_idle_add((GSourceFunc)queue_draw_idle, NULL);
        }
    }

exit_thread:
    client_running = 0;
    vnc_fd = -1;
    close(fd);
    if (udp_fd >= 0) {
        close(udp_fd);
        udp_fd = -1;
    }
    udp_active = 0;
    memset(udp_key, 0, sizeof(udp_key)); // don't leave session key material lying around
    free(reasm_buf);
    reasm_buf = NULL;
    reasm_buf_cap = 0;
    reasm_active = 0;
    if (viewer_window) {
        g_idle_add(destroy_widget_idle, viewer_window);
    }
    return NULL;
}

static void on_viewer_destroy(void) {
    client_running = 0;
    if (vnc_fd >= 0) {
        close(vnc_fd);
        vnc_fd = -1;
    }
    if (codec_ctx) {
        avcodec_free_context(&codec_ctx);
        codec_ctx = NULL;
    }
    if (frame) {
        av_frame_free(&frame);
        frame = NULL;
    }
    if (pkt) {
        av_packet_free(&pkt);
        pkt = NULL;
    }
    if (sw_frame) {
        av_frame_free(&sw_frame);
        sw_frame = NULL;
    }
    if (hw_device_ctx) {
        av_buffer_unref(&hw_device_ctx);
        hw_device_ctx = NULL;
    }
    if (sws_ctx) {
        sws_freeContext(sws_ctx);
        sws_ctx = NULL;
    }
    hw_pix_fmt = AV_PIX_FMT_NONE;
    last_format = AV_PIX_FMT_NONE;
    expected_hw_pix_fmt = AV_PIX_FMT_NONE;
    viewer_window = NULL;
    gtk_widget_show_all(main_window);
}

// Dialog helper to request password on the main thread
static char* prompt_password(GtkWindow* parent) {
    GtkWidget* dialog = gtk_dialog_new_with_buttons("VNC Authentication Required",
                                                    parent,
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_OK", GTK_RESPONSE_OK,
                                                    NULL);
    GtkWidget* content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    GtkWidget* label = gtk_label_new("This VNC server requires password authentication:");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    GtkWidget* entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE); // Mask character entry
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_widget_show_all(dialog);
    
    char* password_ret = NULL;
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_OK) {
        password_ret = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
    }
    
    gtk_widget_destroy(dialog);
    return password_ret;
}

static void show_error_dialog(GtkWindow* parent, const char* message) {
    GtkWidget* dialog = gtk_message_dialog_new(parent,
                                               GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               GTK_MESSAGE_ERROR,
                                               GTK_BUTTONS_OK,
                                               "%s", message);
    gtk_window_set_title(GTK_WINDOW(dialog), "VNC Connection Error");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Perform VNC socket connect and initial handshake synchronously on GUI thread
static void on_btn_connect_clicked(GtkButton* btn, gpointer user_data) {
    (void)btn;
    GtkWindow* parent = GTK_WINDOW(user_data);
    const char* addr_text = gtk_entry_get_text(GTK_ENTRY(entry_address));
    if (addr_text[0] == '\0') {
        show_error_dialog(parent, "Please enter a VNC server address.");
        return;
    }

    char host[256] = {0};
    int port = 5900;
    
    const char* colon = strchr(addr_text, ':');
    if (colon) {
        int host_len = colon - addr_text;
        if (host_len > 255) host_len = 255;
        strncpy(host, addr_text, host_len);
        port = atoi(colon + 1);
    } else {
        strncpy(host, addr_text, sizeof(host) - 1);
    }

    // Save configuration
    save_last_address(host, port);

    // Parse preferred encoding option
    int enc_active = gtk_combo_box_get_active(GTK_COMBO_BOX(combo_encoding));
    if (enc_active == 0) strcpy(preferred_encoding, "h264");
    else if (enc_active == 1) strcpy(preferred_encoding, "jpeg");
    else if (enc_active == 2) strcpy(preferred_encoding, "hextile");
    else strcpy(preferred_encoding, "raw");

    // Perform socket connection
    struct hostent* he = gethostbyname(host);
    if (!he) {
        show_error_dialog(parent, "Could not resolve hostname.");
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *(struct in_addr*)he->h_addr;
    udp_server_in_addr = addr.sin_addr; // remembered for the UDP H.264 side-channel

    // Timeout connecting in case of unreachable hosts (default 3 seconds)
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        show_error_dialog(parent, "Failed to connect to VNC server.");
        return;
    }

    // Clear timeout setting for runtime VNC operations
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    // 1. Version Handshake
    char ver[13] = {0};
    if (read_exact(fd, ver, 12) < 0) {
        close(fd);
        show_error_dialog(parent, "Failed to read VNC protocol version.");
        return;
    }
    send(fd, "RFB 003.008\n", 12, 0);

    // 2. Security Handshake
    uint8_t num_sec_types = 0;
    if (read_exact(fd, &num_sec_types, 1) < 0 || num_sec_types == 0) {
        close(fd);
        show_error_dialog(parent, "No valid security types returned from server.");
        return;
    }

    uint8_t* sec_types = malloc(num_sec_types);
    if (read_exact(fd, sec_types, num_sec_types) < 0) {
        free(sec_types);
        close(fd);
        show_error_dialog(parent, "Failed to read VNC security options.");
        return;
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

    if (selected_sec == 0) {
        close(fd);
        show_error_dialog(parent, "No supported authentication method (requires None or VncAuth).");
        return;
    }

    send(fd, &selected_sec, 1, 0);

    // 3. Authenticate
    if (selected_sec == 2) { // VncAuth required
        uint8_t challenge[16];
        if (read_exact(fd, challenge, 16) < 0) {
            close(fd);
            show_error_dialog(parent, "Failed to read VncAuth challenge.");
            return;
        }

        // Prompt user for password using the modal dialog
        char* pwd = prompt_password(parent);
        if (!pwd) {
            close(fd);
            return; // cancelled
        }

        uint8_t response[16];
        vnc_encrypt_bytes(pwd, challenge, response);
        g_free(pwd);

        send(fd, response, 16, 0);
    }

    uint32_t sec_result = 0;
    if (read_exact(fd, &sec_result, 4) < 0) {
        close(fd);
        show_error_dialog(parent, "Failed to read authentication result.");
        return;
    }
    sec_result = read_u32_be((uint8_t*)&sec_result);

    if (sec_result != 0) {
        close(fd);
        show_error_dialog(parent, "Authentication failed (Incorrect Password).");
        return;
    }

    // 4. ClientInit
    uint8_t shared = 1;
    send(fd, &shared, 1, 0);

    // 5. ServerInit
    uint16_t w = 0, h = 0;
    uint8_t pix_fmt[16];
    uint32_t name_len = 0;

    if (read_exact(fd, &w, 2) < 0 || read_exact(fd, &h, 2) < 0 ||
        read_exact(fd, pix_fmt, 16) < 0 || read_exact(fd, &name_len, 4) < 0) {
        close(fd);
        show_error_dialog(parent, "Failed to read ServerInit description.");
        return;
    }
    w = read_u16_be((uint8_t*)&w);
    h = read_u16_be((uint8_t*)&h);
    name_len = read_u32_be((uint8_t*)&name_len);

    char* server_name = malloc(name_len + 1);
    if (read_exact(fd, server_name, name_len) < 0) {
        free(server_name);
        close(fd);
        show_error_dialog(parent, "Failed to read VNC server desktop name.");
        return;
    }
    free(server_name);

    vnc_fd = fd;
    screen_w = w;
    screen_h = h;

    // Allocate local framebuffer
    pthread_mutex_lock(&backbuffer_mutex);
    backbuffer = realloc(backbuffer, (size_t)w * h * 4);
    memset(backbuffer, 0, (size_t)w * h * 4);
    pthread_mutex_unlock(&backbuffer_mutex);

    // Hide main entry connection window
    gtk_widget_hide(main_window);

    // Create live streaming window
    viewer_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[256];
    snprintf(title, sizeof(title), "%s:%d - vncviewer", host, port);
    gtk_window_set_title(GTK_WINDOW(viewer_window), title);
    gtk_window_set_default_size(GTK_WINDOW(viewer_window), screen_w, screen_h);

    drawing_area = gtk_drawing_area_new();
    gtk_container_add(GTK_CONTAINER(viewer_window), drawing_area);

    gtk_widget_set_can_focus(drawing_area, TRUE);
    gtk_widget_set_events(drawing_area, GDK_POINTER_MOTION_MASK | 
                                        GDK_BUTTON_PRESS_MASK | 
                                        GDK_BUTTON_RELEASE_MASK |
                                        GDK_SCROLL_MASK |
                                        GDK_KEY_PRESS_MASK |
                                        GDK_KEY_RELEASE_MASK);

    g_signal_connect(G_OBJECT(drawing_area), "draw", G_CALLBACK(on_draw), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "motion-notify-event", G_CALLBACK(on_motion), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "button-press-event", G_CALLBACK(on_button), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "button-release-event", G_CALLBACK(on_button), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "scroll-event", G_CALLBACK(on_scroll), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "key-press-event", G_CALLBACK(on_key_event), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "key-release-event", G_CALLBACK(on_key_event), NULL);

    g_signal_connect(G_OBJECT(viewer_window), "destroy", G_CALLBACK(on_viewer_destroy), NULL);

    gtk_widget_show_all(viewer_window);
    gtk_widget_grab_focus(drawing_area);

    // Spawn background VNC receiver thread
    pthread_t thread;
    pthread_create(&thread, NULL, vnc_client_thread, NULL);
    pthread_detach(thread);
}

int main(int argc, char* argv[]) {
    gtk_init(&argc, &argv);

    // Create main clean dialog window
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "VNC Connection Manager");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 380, 240);
    gtk_window_set_resizable(GTK_WINDOW(main_window), FALSE);
    gtk_window_set_position(GTK_WINDOW(main_window), GTK_WIN_POS_CENTER);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // CSS Styling for visual aesthetics (Wow factor)
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider,
        "window { background-color: #1e1e24; color: #f5f5f6; font-family: 'Inter', sans-serif; }\n"
        "box { padding: 24px; }\n"
        "entry { background-color: #2b2b36; color: white; border: 1px solid #4f46e5; border-radius: 6px; padding: 10px; font-size: 14px; margin-bottom: 12px; }\n"
        "combobox { background-color: #2b2b36; border: 1px solid #4f46e5; border-radius: 6px; padding: 4px; font-size: 13px; margin-bottom: 16px; }\n"
        "button { background-color: #4f46e5; color: white; border-radius: 6px; padding: 12px; font-weight: bold; font-size: 14px; }\n"
        "button:hover { background-color: #4338ca; }\n"
        "label.title { font-size: 20px; font-weight: bold; color: white; margin-bottom: 6px; }\n"
        "label.subtitle { font-size: 12px; color: #9ca3af; margin-bottom: 20px; }\n"
        "label.field { font-size: 12px; font-weight: bold; color: #d1d5db; margin-bottom: 6px; }\n", -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    // Title label
    GtkWidget* lbl_title = gtk_label_new("leanrfb VNC Client");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_title), "title");
    gtk_widget_set_halign(lbl_title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_title, FALSE, FALSE, 0);

    GtkWidget* lbl_sub = gtk_label_new("Enter your remote VNC address to connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_sub), "subtitle");
    gtk_widget_set_halign(lbl_sub, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_sub, FALSE, FALSE, 0);

    // Server address label & field
    GtkWidget* lbl_addr = gtk_label_new("VNC Server Address:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_addr), "field");
    gtk_widget_set_halign(lbl_addr, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_addr, FALSE, FALSE, 0);

    entry_address = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_address), "127.0.0.1:5900");
    gtk_box_pack_start(GTK_BOX(vbox), entry_address, FALSE, FALSE, 0);

    // Pre-fill last used connection
    char last_host[256];
    int last_port;
    load_last_address(last_host, &last_port);
    char full_addr[300];
    snprintf(full_addr, sizeof(full_addr), "%s:%d", last_host, last_port);
    gtk_entry_set_text(GTK_ENTRY(entry_address), full_addr);

    // Preferred encoding label & field
    GtkWidget* lbl_enc = gtk_label_new("Preferred Encoding:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_enc), "field");
    gtk_widget_set_halign(lbl_enc, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_enc, FALSE, FALSE, 0);

    combo_encoding = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "H.264 Video (Zero Latency)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Tight JPEG (Medium Bandwidth)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Hextile (Low CPU)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Raw (Local Connection)");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_encoding), 0);
    gtk_box_pack_start(GTK_BOX(vbox), combo_encoding, FALSE, FALSE, 0);

    // Connect button
    GtkWidget* btn_connect = gtk_button_new_with_label("Connect");
    g_signal_connect(btn_connect, "clicked", G_CALLBACK(on_btn_connect_clicked), main_window);
    gtk_box_pack_start(GTK_BOX(vbox), btn_connect, FALSE, FALSE, 0);

    // Connect Entry Activate (pressing Enter key connects)
    g_signal_connect(G_OBJECT(entry_address), "activate", G_CALLBACK(on_btn_connect_clicked), main_window);

    gtk_widget_show_all(main_window);
    gtk_main();
    return 0;
}
