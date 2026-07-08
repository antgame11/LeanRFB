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
#include <openssl/evp.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavutil/imgutils.h>
#include <pulse/simple.h>
#include <pulse/error.h>
#include <time.h>

#include "vnc_client_core.h"

// Non-essential diagnostic logging
#ifdef VNC_DEBUG
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[VNCVIEW DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) do {} while (0)
#endif

// Byte-order conversion helper functions (needed locally for UDP headers)
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

static inline uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}

// --- Encrypted UDP transport for H.264 (see docs/custom/rfb_h264_udp_extension.md) ---
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
// A lost fragment stalls video until this fires (abandon + request a fresh
// keyframe) — was 400ms, which reads as very laggy on any real packet loss.
// Comfortably above LAN jitter but far quicker to recover than before.
#define VNC_UDP_REASM_TIMEOUT_MS 120
#define VNC_UDP_CODEC_H264 0
#define VNC_UDP_CODEC_VP9 1
#define VNC_UDP_SETUP_PAYLOAD_LEN (2 + VNC_UDP_CID_LEN + VNC_UDP_KEY_LEN + 1)
#define VNC_ENCODING_VP9 52
#define VNC_MSG_REQUEST_KEYFRAME 254

// Live desktop resize debounce configuration
#define VNC_MSG_SET_DESKTOP_SIZE 251
#define VNC_RESIZE_DEBOUNCE_MS 400

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
        if (shift >= 64) st->bitmap = 0;
        else st->bitmap <<= shift;
        st->highest = counter;
        st->bitmap |= 1ULL;
        return 1;
    }
    uint64_t age = st->highest - counter;
    if (age >= 64) return 0;
    if (st->bitmap & (1ULL << age)) return 0; // replay
    st->bitmap |= (1ULL << age);
    return 1;
}

// Global UI widgets
static GtkWidget* main_window = NULL;
static GtkWidget* viewer_window = NULL;
static GtkWidget* drawing_area = NULL;
static GtkWidget* entry_address = NULL;
static GtkWidget* combo_encoding = NULL;
static GtkWidget* check_audio = NULL;

// QEMU audio extension playback (see docs/custom/rfb_qemu_audio_extension.md).
// Only ever touched from vnc_client_thread (the background socket reader), since
// that's the thread on_audio_begin/on_audio_data/on_audio_end fire on — no locking
// needed between them. The GTK main thread only reads want_audio (set once, before
// the handshake) and never touches audio_playback itself.
static int want_audio = 0;
static pa_simple* audio_playback = NULL;

// TCP socket descriptor
int vnc_fd = -1;
static uint8_t button_mask = 0;
static char preferred_encoding[32] = "h264";
static volatile int waiting_for_draw = 0;

// Live desktop resize variables
static guint resize_debounce_source = 0;
static int pending_resize_w = 0;
static int pending_resize_h = 0;

// UDP H.264 transport state variables
static int udp_fd = -1;
static struct in_addr udp_server_in_addr;
static struct sockaddr_in udp_server_addr;
static uint8_t udp_key[VNC_UDP_KEY_LEN];
static uint8_t udp_cid[VNC_UDP_CID_LEN];
static uint64_t udp_send_ctr = 0;
static udp_replay_state_t udp_recv_replay;
static volatile int udp_active = 0;
static unsigned long long udp_last_heartbeat_ms = 0;
static unsigned long long udp_last_keyframe_request_ms = 0;
static unsigned long long reasm_start_ms = 0;

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
static AVFrame* sw_frame = NULL;
static AVBufferRef* hw_device_ctx = NULL;
static enum AVPixelFormat hw_pix_fmt = AV_PIX_FMT_NONE;
static AVPacket* pkt = NULL;
static struct SwsContext* sws_ctx = NULL;
static enum AVPixelFormat last_format = AV_PIX_FMT_NONE;
static int decoder_primed = 0;
static enum AVCodecID active_video_codec_id = AV_CODEC_ID_H264;
static enum AVPixelFormat expected_hw_pix_fmt = AV_PIX_FMT_NONE;

// GTK clipboard synchronization variables
static char* last_sent_clipboard = NULL;

static void show_error_dialog(GtkWindow* parent, const char* message) {
    GtkWidget* dialog = gtk_message_dialog_new(parent,
                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                               GTK_MESSAGE_ERROR,
                                               GTK_BUTTONS_CLOSE,
                                               "%s", message);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
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

static void load_last_address(char* host_out, int* port_out) {
    char path[512];
    snprintf(path, sizeof(path), "%s/.config/vncviewer/last_address.conf", g_get_home_dir());
    FILE* f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%255s %d", host_out, port_out) != 2) {
            strcpy(host_out, "127.0.0.1");
            *port_out = 5900;
        }
        fclose(f);
    } else {
        strcpy(host_out, "127.0.0.1");
        *port_out = 5900;
    }
}

static enum AVPixelFormat get_hw_format(AVCodecContext *ctx, const enum AVPixelFormat *pix_fmts) {
    (void)ctx;
    const enum AVPixelFormat *p;
    for (p = pix_fmts; *p != -1; p++) {
        if (*p == expected_hw_pix_fmt) {
            return *p;
        }
    }
    fprintf(stderr, "Failed to get HW surface format.\n");
    return AV_PIX_FMT_NONE;
}

static void reset_decoder(int w, int h) {
    if (codec_ctx) {
        avcodec_free_context(&codec_ctx);
        codec_ctx = NULL;
    }
    if (frame) {
        av_frame_free(&frame);
        frame = NULL;
    }
    if (sw_frame) {
        av_frame_free(&sw_frame);
        sw_frame = NULL;
    }
    if (pkt) {
        av_packet_free(&pkt);
        pkt = NULL;
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
    decoder_primed = 0;

    const AVCodec* codec = avcodec_find_decoder(active_video_codec_id);
    if (!codec) {
        fprintf(stderr, "Error: Decoder not found in libavcodec\n");
        return;
    }

    codec_ctx = avcodec_alloc_context3(codec);
    if (!codec_ctx) return;

    // Check for VAAPI HW acceleration options
    int use_vaapi = 0;
    for (int i = 0;; i++) {
        const AVCodecHWConfig *config = avcodec_get_hw_config(codec, i);
        if (!config) break;
        if (config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX && config->device_type == AV_HWDEVICE_TYPE_VAAPI) {
            expected_hw_pix_fmt = config->pix_fmt;
            use_vaapi = 1;
            break;
        }
    }

    if (use_vaapi) {
        if (av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_VAAPI, NULL, NULL, 0) >= 0) {
            codec_ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
            codec_ctx->get_format = get_hw_format;
            DEBUG_LOG("VAAPI Hardware acceleration initialized successfully");
        } else {
            DEBUG_LOG("VAAPI Hardware acceleration creation failed — falling back to CPU decoding");
        }
    }

    codec_ctx->width = w;
    codec_ctx->height = h;
    codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;

    AVDictionary* opts = NULL;
    av_dict_set(&opts, "threads", "auto", 0);
    if (avcodec_open2(codec_ctx, codec, &opts) < 0) {
        fprintf(stderr, "Error: Could not open libavcodec decoder\n");
        av_dict_free(&opts);
        avcodec_free_context(&codec_ctx);
        codec_ctx = NULL;
        return;
    }
    av_dict_free(&opts);

    frame = av_frame_alloc();
    sw_frame = av_frame_alloc();
    pkt = av_packet_alloc();
    decoder_primed = 1;
    DEBUG_LOG("Decoder initialized successfully (size=%dx%d)", w, h);
}

static void decode_video(const uint8_t* payload, int len, uint8_t* out_bgra, int w, int h) {
    if (!decoder_primed || !codec_ctx) return;

    pkt->data = (uint8_t*)payload;
    pkt->size = len;

    int ret = avcodec_send_packet(codec_ctx, pkt);
    if (ret < 0) {
        DEBUG_LOG("decode_video: avcodec_send_packet failed (ret=%d, len=%d)", ret, len);
        return;
    }

    while (ret >= 0) {
        ret = avcodec_receive_frame(codec_ctx, frame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            break;
        } else if (ret < 0) {
            DEBUG_LOG("decode_video: avcodec_receive_frame failed (ret=%d)", ret);
            return;
        }

        AVFrame* src_frame = frame;
        if (frame->hw_frames_ctx) {
            if (av_hwframe_transfer_data(sw_frame, frame, 0) < 0) {
                DEBUG_LOG("decode_video: Failed to transfer VAAPI surface to CPU memory");
                continue;
            }
            src_frame = sw_frame;
        }

        if (src_frame->width != w || src_frame->height != h) {
            continue;
        }

        enum AVPixelFormat fmt = src_frame->format;
        if (!sws_ctx || last_format != fmt) {
            if (sws_ctx) sws_freeContext(sws_ctx);
            sws_ctx = sws_getContext(w, h, fmt, w, h, AV_PIX_FMT_BGRA, SWS_FAST_BILINEAR, NULL, NULL, NULL);
            last_format = fmt;
        }

        if (sws_ctx) {
            uint8_t* dst[4] = { out_bgra, NULL, NULL, NULL };
            int dst_stride[4] = { w * 4, 0, 0, 0 };
            pthread_mutex_lock(&backbuffer_mutex);
            sws_scale(sws_ctx, (const uint8_t* const*)src_frame->data, src_frame->linesize, 0, h, dst, dst_stride);
            pthread_mutex_unlock(&backbuffer_mutex);
        }
    }
}

static void request_keyframe(void) {
    if (vnc_fd < 0) return;
    DEBUG_LOG("requesting keyframe from server...");
    uint8_t msg = VNC_MSG_REQUEST_KEYFRAME;
    send(vnc_fd, &msg, 1, 0);
}

static void udp_handle_setup(const uint8_t* payload) {
    uint16_t port = ((uint16_t)payload[0] << 8) | payload[1];
    memcpy(udp_cid, payload + 2, VNC_UDP_CID_LEN);
    memcpy(udp_key, payload + 2 + VNC_UDP_CID_LEN, VNC_UDP_KEY_LEN);
    uint8_t codec_id = payload[2 + VNC_UDP_CID_LEN + VNC_UDP_KEY_LEN];

    if (udp_fd >= 0) {
        close(udp_fd);
        udp_fd = -1;
    }

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        fprintf(stderr, "Error: Could not open UDP socket\n");
        return;
    }

    memset(&udp_server_addr, 0, sizeof(udp_server_addr));
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_port = htons(port);
    udp_server_addr.sin_addr = udp_server_in_addr;

    if (connect(udp_fd, (struct sockaddr*)&udp_server_addr, sizeof(udp_server_addr)) < 0) {
        fprintf(stderr, "Error: UDP connect failed\n");
        close(udp_fd);
        udp_fd = -1;
        return;
    }

    int flags = fcntl(udp_fd, F_GETFL, 0);
    fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK);

    active_video_codec_id = (codec_id == VNC_UDP_CODEC_VP9) ? AV_CODEC_ID_VP9 : AV_CODEC_ID_H264;
    reset_decoder(screen_w, screen_h);

    udp_send_ctr = 0;
    memset(&udp_recv_replay, 0, sizeof(udp_recv_replay));
    udp_last_heartbeat_ms = 0;
    udp_last_keyframe_request_ms = 0;
    udp_active = 1;

    reasm_active = 0;
    have_last_completed_frame = 0;

    DEBUG_LOG("UDP encrypted side-channel established successfully with CID=%02X%02X%02X%02X%02X%02X%02X%02X on port %d (codec=%d)",
              udp_cid[0], udp_cid[1], udp_cid[2], udp_cid[3],
              udp_cid[4], udp_cid[5], udp_cid[6], udp_cid[7],
              port, codec_id);
}

static void reasm_start(uint32_t frame_id, uint16_t frag_count) {
    reasm_active = 1;
    reasm_frame_id = frame_id;
    reasm_frag_count = frag_count;
    reasm_frags_got = 0;
    reasm_last_frag_len = 0;
    reasm_flags = 0;
    reasm_start_ms = vv_now_ms();

    size_t req = (size_t)frag_count * VNC_UDP_MAX_FRAG_PAYLOAD;
    if (req > reasm_buf_cap) {
        reasm_buf_cap = req;
        reasm_buf = realloc(reasm_buf, reasm_buf_cap);
    }
    memset(reasm_got_bitmap, 0, sizeof(reasm_got_bitmap));
}

static gboolean queue_draw_idle(gpointer data) {
    (void)data;
    if (drawing_area) {
        gtk_widget_queue_draw(drawing_area);
    }
    return FALSE;
}

static void reasm_add_fragment(const uint8_t* pt, int pt_len) {
    if (pt_len < VNC_UDP_INNER_HDR_LEN) return;

    // Wire layout (see VNC_UDP_INNER_HDR_LEN in leanrfb_internal.h, and the server's
    // matching write order in src/leanrfb_udp.c): frame_id(4) frag_idx(2) frag_count(2)
    // flags(1) reserved(1). There is no explicit fragment-length field on the wire —
    // the payload length is implicit in how many plaintext bytes followed the header.
    uint32_t frame_id = ((uint32_t)pt[0] << 24) | ((uint32_t)pt[1] << 16) | ((uint32_t)pt[2] << 8) | pt[3];
    uint16_t frag_idx = ((uint16_t)pt[4] << 8) | pt[5];
    uint16_t frag_count = ((uint16_t)pt[6] << 8) | pt[7];
    uint8_t flags = pt[8] & 0x03;
    uint16_t frag_len = (uint16_t)(pt_len - VNC_UDP_INNER_HDR_LEN);

    if (frag_idx >= frag_count || frag_len > VNC_UDP_MAX_FRAG_PAYLOAD) return;

    if (!reasm_active || frame_id > reasm_frame_id) {
        if (have_last_completed_frame && frame_id <= last_completed_frame_id) return;

        if (reasm_active) {
            DEBUG_LOG("reasm: abandoning incomplete frame %u in favor of new frame %u", reasm_frame_id, frame_id);
            request_keyframe();
        }
        if (have_last_completed_frame && frame_id != last_completed_frame_id + 1) {
            DEBUG_LOG("reasm: frame id gap detected (last completed=%u, now=%u) — a whole frame was lost",
                      last_completed_frame_id, frame_id);
            request_keyframe();
        }
        DEBUG_LOG("reasm: starting frame %u (%u fragments)", frame_id, frag_count);
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
        DEBUG_LOG("reasm: frame %u complete (%u fragments, %zu bytes, flags=0x%02x, primed=%d)",
                  frame_id, reasm_frag_count, total_len, reasm_flags, decoder_primed);

        if (reasm_flags & 2) {
            reset_decoder(screen_w, screen_h);
        }
        if (decoder_primed && total_len > 0) {
            decode_video(reasm_buf, (int)total_len, backbuffer, screen_w, screen_h);
        }

        have_last_completed_frame = 1;
        last_completed_frame_id = frame_id;
        reasm_active = 0;

        pthread_mutex_lock(&backbuffer_mutex);
        waiting_for_draw = 1;
        pthread_mutex_unlock(&backbuffer_mutex);
        g_idle_add((GSourceFunc)queue_draw_idle, NULL);

        // The server only encodes/sends another video frame once it sees a fresh
        // FramebufferUpdateRequest (client->update_requested), same as for any other
        // encoding — but UDP-delivered frames never go through vnc_core_process_message's
        // TCP FramebufferUpdate handling, which is the only place that request normally
        // gets sent. Without this, the server sends exactly one frame over UDP and then
        // stops forever (has nothing left asking it to continue), leaving the client
        // stuck on a single stale/black frame. Re-request here so UDP video keeps flowing.
        if (vnc_fd >= 0) {
            vnc_core_send_fb_request(1, 0, 0, screen_w, screen_h);
        }
    }
}

static void udp_drain(void) {
    uint8_t buf[VNC_UDP_MAX_DATAGRAM];
    uint8_t plaintext[VNC_UDP_MAX_DATAGRAM];

    for (int iter = 0; iter < 256; iter++) {
        ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
        if (n <= 0) return;
        if (n < VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN) continue;
        if (buf[0] != VNC_UDP_TYPE_VIDEO) continue;
        if (memcmp(buf + 1, udp_cid, VNC_UDP_CID_LEN) != 0) continue;

        uint8_t type = 0;
        uint64_t counter = 0;
        int pt_len = 0;
        if (udp_open(udp_key, buf, (int)n, &type, &counter, plaintext, &pt_len) < 0) {
            DEBUG_LOG("udp_drain: AEAD authentication failed on a %zd-byte datagram — dropping", n);
            continue;
        }
        if (!udp_replay_check(&udp_recv_replay, counter)) {
            DEBUG_LOG("udp_drain: replay/out-of-window counter=%llu — dropping", (unsigned long long)counter);
            continue;
        }

        reasm_add_fragment(plaintext, pt_len);
    }
}

static void reasm_check_timeout(void) {
    if (!reasm_active) return;
    if (vv_now_ms() - reasm_start_ms < VNC_UDP_REASM_TIMEOUT_MS) return;

    DEBUG_LOG("reasm: frame %u timed out at %u/%u fragments — abandoning and re-requesting",
              reasm_frame_id, reasm_frags_got, reasm_frag_count);
    reasm_active = 0;
    request_keyframe();
    if (vnc_fd >= 0) {
        vnc_core_send_fb_request(1, 0, 0, screen_w, screen_h);
    }
}

static gboolean apply_server_clipboard_idle(gpointer data) {
    char* text = (char*)data;
    if (text) {
        GtkClipboard* clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
        free(last_sent_clipboard);
        last_sent_clipboard = strdup(text);
        gtk_clipboard_set_text(clipboard, text, -1);
        free(text);
    }
    return FALSE;
}

static void on_clipboard_text_received(GtkClipboard* clipboard, const char* text, gpointer user_data) {
    (void)clipboard;
    (void)user_data;
    if (text && vnc_fd >= 0) {
        if (last_sent_clipboard && strcmp(last_sent_clipboard, text) == 0) {
            return;
        }
        free(last_sent_clipboard);
        last_sent_clipboard = strdup(text);
        
        int len = strlen(text);
        vnc_core_send_clipboard(text, len);
    }
}

static void on_clipboard_owner_change(GtkClipboard* clipboard, GdkEvent* event, gpointer user_data) {
    (void)event;
    (void)user_data;
    gtk_clipboard_request_text(clipboard, on_clipboard_text_received, NULL);
}

static gboolean destroy_widget_idle(gpointer data) {
    gtk_widget_destroy(GTK_WIDGET(data));
    return FALSE;
}

// Background network client loop thread (after handshake is complete)
static void* vnc_client_thread(void* arg) {
    (void)arg;
    int fd = vnc_fd;

    while (client_running) {
        struct pollfd pfds[2];
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = udp_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll(pfds, 2, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (udp_active) {
            udp_drain();
            reasm_check_timeout();

            // Heartbeat
            unsigned long long now = vv_now_ms();
            if (now - udp_last_heartbeat_ms >= VNC_UDP_HEARTBEAT_INTERVAL_MS) {
                uint8_t payload[1] = { 0 }; 
                uint8_t cipher[VNC_UDP_MAX_DATAGRAM];
                int cipher_len = udp_seal(udp_key, VNC_UDP_TYPE_HELLO, udp_cid, ++udp_send_ctr, payload, 0, cipher, sizeof(cipher));
                if (cipher_len > 0 && udp_fd >= 0) {
                    sendto(udp_fd, cipher, (size_t)cipher_len, 0, (struct sockaddr*)&udp_server_addr, sizeof(udp_server_addr));
                }
                udp_last_heartbeat_ms = now;
            }
        }

        if (pfds[0].revents & POLLIN) {
            if (vnc_core_process_message(fd) < 0) {
                break;
            }
        }
    }

    DEBUG_LOG("vnc_client_thread: exiting (connection closed or fatal read error)");
    client_running = 0;
    vnc_fd = -1;
    close(fd);
    if (udp_fd >= 0) {
        close(udp_fd);
        udp_fd = -1;
    }
    udp_active = 0;
    memset(udp_key, 0, sizeof(udp_key));
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
    if (audio_playback) {
        pa_simple_free(audio_playback);
        audio_playback = NULL;
    }
    if (sws_ctx) {
        sws_freeContext(sws_ctx);
        sws_ctx = NULL;
    }
    hw_pix_fmt = AV_PIX_FMT_NONE;
    last_format = AV_PIX_FMT_NONE;
    expected_hw_pix_fmt = AV_PIX_FMT_NONE;
    decoder_primed = 0;
    viewer_window = NULL;
    gtk_widget_show_all(main_window);
}

// Dialog helper to request password on the main thread
static char* prompt_password(void) {
    GtkWidget* dialog = gtk_dialog_new_with_buttons("VNC Authentication Required",
                                                    GTK_WINDOW(main_window),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_OK", GTK_RESPONSE_OK,
                                                    NULL);
    GtkWidget* content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget* label = gtk_label_new("Enter password to connect to server:");
    GtkWidget* entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);

    gtk_container_add(GTK_CONTAINER(content_area), label);
    gtk_container_add(GTK_CONTAINER(content_area), entry);
    gtk_widget_show_all(dialog);

    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

    char* result = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
        result = strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
    }
    gtk_widget_destroy(dialog);
    return result;
}

// UI Event Handlers
static gboolean on_draw(GtkWidget* widget, cairo_t* cr, gpointer user_data) {
    (void)widget;
    (void)user_data;
    pthread_mutex_lock(&backbuffer_mutex);
    if (!backbuffer || screen_w <= 0 || screen_h <= 0) {
        pthread_mutex_unlock(&backbuffer_mutex);
        cairo_set_source_rgb(cr, 0.1, 0.1, 0.1);
        cairo_paint(cr);
        return TRUE;
    }

    cairo_surface_t* surface = cairo_image_surface_create_for_data(backbuffer,
                                                                  CAIRO_FORMAT_RGB24,
                                                                  screen_w, screen_h,
                                                                  screen_w * 4);
    
    // Clear background to sleek dark color
    cairo_set_source_rgb(cr, 0.05, 0.05, 0.05);
    cairo_paint(cr);

    // Compute center scaling
    int win_w = gtk_widget_get_allocated_width(drawing_area);
    int win_h = gtk_widget_get_allocated_height(drawing_area);
    double scale_x = (double)win_w / screen_w;
    double scale_y = (double)win_h / screen_h;
    double scale = (scale_x < scale_y) ? scale_x : scale_y;

    double dx = (win_w - screen_w * scale) / 2.0;
    double dy = (win_h - screen_h * scale) / 2.0;

    cairo_save(cr);
    cairo_translate(cr, dx, dy);
    cairo_scale(cr, scale, scale);

    cairo_set_source_surface(cr, surface, 0, 0);
    cairo_paint(cr);
    cairo_restore(cr);

    cairo_surface_destroy(surface);
    waiting_for_draw = 0;
    pthread_mutex_unlock(&backbuffer_mutex);
    return TRUE;
}

static gboolean on_motion(GtkWidget* widget, GdkEventMotion* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (vnc_fd < 0 || screen_w <= 0 || screen_h <= 0) return TRUE;

    int win_w = gtk_widget_get_allocated_width(drawing_area);
    int win_h = gtk_widget_get_allocated_height(drawing_area);
    double scale_x = (double)win_w / screen_w;
    double scale_y = (double)win_h / screen_h;
    double scale = (scale_x < scale_y) ? scale_x : scale_y;
    double dx = (win_w - screen_w * scale) / 2.0;
    double dy = (win_h - screen_h * scale) / 2.0;

    double rx = (event->x - dx) / scale;
    double ry = (event->y - dy) / scale;

    if (rx < 0) rx = 0;
    if (rx >= screen_w) rx = screen_w - 1;
    if (ry < 0) ry = 0;
    if (ry >= screen_h) ry = screen_h - 1;

    vnc_core_send_pointer((uint16_t)rx, (uint16_t)ry, button_mask);
    return TRUE;
}

static gboolean on_button(GtkWidget* widget, GdkEventButton* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (vnc_fd < 0 || screen_w <= 0 || screen_h <= 0) return TRUE;

    if (event->type == GDK_BUTTON_PRESS || event->type == GDK_BUTTON_RELEASE) {
        uint8_t mask = 0;
        if (event->button == GDK_BUTTON_PRIMARY) mask = 1;
        else if (event->button == GDK_BUTTON_MIDDLE) mask = 2;
        else if (event->button == GDK_BUTTON_SECONDARY) mask = 4;

        if (event->type == GDK_BUTTON_PRESS) {
            button_mask |= mask;
        } else {
            button_mask &= ~mask;
        }

        int win_w = gtk_widget_get_allocated_width(drawing_area);
        int win_h = gtk_widget_get_allocated_height(drawing_area);
        double scale_x = (double)win_w / screen_w;
        double scale_y = (double)win_h / screen_h;
        double scale = (scale_x < scale_y) ? scale_x : scale_y;
        double dx = (win_w - screen_w * scale) / 2.0;
        double dy = (win_h - screen_h * scale) / 2.0;

        double rx = (event->x - dx) / scale;
        double ry = (event->y - dy) / scale;

        if (rx < 0) rx = 0;
        if (rx >= screen_w) rx = screen_w - 1;
        if (ry < 0) ry = 0;
        if (ry >= screen_h) ry = screen_h - 1;

        vnc_core_send_pointer((uint16_t)rx, (uint16_t)ry, button_mask);
    }
    return TRUE;
}

static gboolean on_scroll(GtkWidget* widget, GdkEventScroll* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (vnc_fd < 0 || screen_w <= 0 || screen_h <= 0) return TRUE;

    uint8_t temp_mask = button_mask;
    if (event->direction == GDK_SCROLL_UP) temp_mask |= 8;
    else if (event->direction == GDK_SCROLL_DOWN) temp_mask |= 16;
    else if (event->direction == GDK_SCROLL_LEFT) temp_mask |= 32;
    else if (event->direction == GDK_SCROLL_RIGHT) temp_mask |= 64;

    int win_w = gtk_widget_get_allocated_width(drawing_area);
    int win_h = gtk_widget_get_allocated_height(drawing_area);
    double scale_x = (double)win_w / screen_w;
    double scale_y = (double)win_h / screen_h;
    double scale = (scale_x < scale_y) ? scale_x : scale_y;
    double dx = (win_w - screen_w * scale) / 2.0;
    double dy = (win_h - screen_h * scale) / 2.0;

    double rx = (event->x - dx) / scale;
    double ry = (event->y - dy) / scale;

    if (rx < 0) rx = 0;
    if (rx >= screen_w) rx = screen_w - 1;
    if (ry < 0) ry = 0;
    if (ry >= screen_h) ry = screen_h - 1;

    vnc_core_send_pointer((uint16_t)rx, (uint16_t)ry, temp_mask);
    vnc_core_send_pointer((uint16_t)rx, (uint16_t)ry, button_mask);
    return TRUE;
}

static guint map_gdk_keyval_to_keysym(guint keyval) {
    if (keyval >= GDK_KEY_KP_Space && keyval <= GDK_KEY_KP_9) {
        switch (keyval) {
            case GDK_KEY_KP_Space: return 0xFF80;
            case GDK_KEY_KP_Tab: return 0xFF89;
            case GDK_KEY_KP_Enter: return 0xFF8D;
            case GDK_KEY_KP_F1: return 0xFF91;
            case GDK_KEY_KP_F2: return 0xFF92;
            case GDK_KEY_KP_F3: return 0xFF93;
            case GDK_KEY_KP_F4: return 0xFF94;
            case GDK_KEY_KP_Home: return 0xFF95;
            case GDK_KEY_KP_Left: return 0xFF96;
            case GDK_KEY_KP_Up: return 0xFF97;
            case GDK_KEY_KP_Right: return 0xFF98;
            case GDK_KEY_KP_Down: return 0xFF99;
            case GDK_KEY_KP_Page_Up: return 0xFF9A;
            case GDK_KEY_KP_Page_Down: return 0xFF9B;
            case GDK_KEY_KP_End: return 0xFF9C;
            case GDK_KEY_KP_Begin: return 0xFF9D;
            case GDK_KEY_KP_Insert: return 0xFF9E;
            case GDK_KEY_KP_Delete: return 0xFF9F;
            case GDK_KEY_KP_Equal: return 0xFFBD;
            case GDK_KEY_KP_Multiply: return 0xFFAA;
            case GDK_KEY_KP_Add: return 0xFFAB;
            case GDK_KEY_KP_Separator: return 0xFFAC;
            case GDK_KEY_KP_Subtract: return 0xFFAD;
            case GDK_KEY_KP_Decimal: return 0xFFAE;
            case GDK_KEY_KP_Divide: return 0xFFAF;
            case GDK_KEY_KP_0: return 0xFFB0;
            case GDK_KEY_KP_1: return 0xFFB1;
            case GDK_KEY_KP_2: return 0xFFB2;
            case GDK_KEY_KP_3: return 0xFFB3;
            case GDK_KEY_KP_4: return 0xFFB4;
            case GDK_KEY_KP_5: return 0xFFB5;
            case GDK_KEY_KP_6: return 0xFFB6;
            case GDK_KEY_KP_7: return 0xFFB7;
            case GDK_KEY_KP_8: return 0xFFB8;
            case GDK_KEY_KP_9: return 0xFFB9;
        }
    }

    switch (keyval) {
        case GDK_KEY_BackSpace: return 0xFF08;
        case GDK_KEY_Tab: return 0xFF09;
        case GDK_KEY_Linefeed: return 0xFF0A;
        case GDK_KEY_Clear: return 0xFF0B;
        case GDK_KEY_Return: return 0xFF0D;
        case GDK_KEY_Pause: return 0xFF13;
        case GDK_KEY_Scroll_Lock: return 0xFF14;
        case GDK_KEY_Sys_Req: return 0xFF15;
        case GDK_KEY_Escape: return 0xFF1B;
        case GDK_KEY_Delete: return 0xFFFF;
        case GDK_KEY_Home: return 0xFF50;
        case GDK_KEY_Left: return 0xFF51;
        case GDK_KEY_Up: return 0xFF52;
        case GDK_KEY_Right: return 0xFF53;
        case GDK_KEY_Down: return 0xFF54;
        case GDK_KEY_Page_Up: return 0xFF55;
        case GDK_KEY_Page_Down: return 0xFF56;
        case GDK_KEY_End: return 0xFF57;
        case GDK_KEY_Begin: return 0xFF58;
        case GDK_KEY_Select: return 0xFF60;
        case GDK_KEY_Print: return 0xFF61;
        case GDK_KEY_Execute: return 0xFF62;
        case GDK_KEY_Insert: return 0xFF63;
        case GDK_KEY_Undo: return 0xFF65;
        case GDK_KEY_Redo: return 0xFF66;
        case GDK_KEY_Menu: return 0xFF67;
        case GDK_KEY_Find: return 0xFF68;
        case GDK_KEY_Cancel: return 0xFF69;
        case GDK_KEY_Help: return 0xFF6A;
        case GDK_KEY_Break: return 0xFF6B;
        case GDK_KEY_Mode_switch: return 0xFF7E;
        case GDK_KEY_Num_Lock: return 0xFF7F;
        case GDK_KEY_F1: return 0xFFBE;
        case GDK_KEY_F2: return 0xFFBF;
        case GDK_KEY_F3: return 0xFFC0;
        case GDK_KEY_F4: return 0xFFC1;
        case GDK_KEY_F5: return 0xFFC2;
        case GDK_KEY_F6: return 0xFFC3;
        case GDK_KEY_F7: return 0xFFC4;
        case GDK_KEY_F8: return 0xFFC5;
        case GDK_KEY_F9: return 0xFFC6;
        case GDK_KEY_F10: return 0xFFC7;
        case GDK_KEY_F11: return 0xFFC8;
        case GDK_KEY_F12: return 0xFFC9;
        case GDK_KEY_Shift_L: return 0xFFE1;
        case GDK_KEY_Shift_R: return 0xFFE2;
        case GDK_KEY_Control_L: return 0xFFE3;
        case GDK_KEY_Control_R: return 0xFFE4;
        case GDK_KEY_Caps_Lock: return 0xFFE5;
        case GDK_KEY_Shift_Lock: return 0xFFE6;
        case GDK_KEY_Meta_L: return 0xFFE7;
        case GDK_KEY_Meta_R: return 0xFFE8;
        case GDK_KEY_Alt_L: return 0xFFE9;
        case GDK_KEY_Alt_R: return 0xFFEA;
        case GDK_KEY_Super_L: return 0xFFEB;
        case GDK_KEY_Super_R: return 0xFFEC;
        case GDK_KEY_Hyper_L: return 0xFFED;
        case GDK_KEY_Hyper_R: return 0xFFEE;
    }

    if (keyval >= 0x20 && keyval <= 0xFF) return keyval;

    return 0;
}

static gboolean on_key_event(GtkWidget* widget, GdkEventKey* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (vnc_fd < 0) return TRUE;

    guint keysym = map_gdk_keyval_to_keysym(event->keyval);
    if (keysym > 0) {
        uint8_t down = (event->type == GDK_KEY_PRESS) ? 1 : 0;
        vnc_core_send_key(keysym, down);
    }
    return TRUE;
}

static gboolean apply_remote_desktop_size_idle(gpointer data) {
    (void)data;
    if (viewer_window && drawing_area) {
        gtk_window_resize(GTK_WINDOW(viewer_window), screen_w, screen_h);
        gtk_widget_set_size_request(drawing_area, screen_w, screen_h);
        gtk_widget_queue_draw(drawing_area);
        DEBUG_LOG("UI size updated to %dx%d to match server", screen_w, screen_h);
    }
    return FALSE;
}

static gboolean debounce_resize_timeout(gpointer data) {
    (void)data;
    resize_debounce_source = 0;
    if (vnc_fd >= 0) {
        DEBUG_LOG("Client-driven desktop resize: sending SetDesktopSize request to %dx%d...",
                  pending_resize_w, pending_resize_h);
        
        uint8_t msg[8];
        msg[0] = VNC_MSG_SET_DESKTOP_SIZE;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 1; // number of screens
        write_u16_be(msg + 4, pending_resize_w);
        write_u16_be(msg + 6, pending_resize_h);
        send(vnc_fd, msg, 8, 0);

        uint8_t scr_info[16];
        write_u32_be(scr_info + 0, 0); // screen ID
        write_u16_be(scr_info + 4, 0); // x-position
        write_u16_be(scr_info + 6, 0); // y-position
        write_u16_be(scr_info + 8, pending_resize_w);
        write_u16_be(scr_info + 10, pending_resize_h);
        write_u32_be(scr_info + 12, 0); // flags
        send(vnc_fd, scr_info, 16, 0);
    }
    return FALSE;
}

static gboolean on_viewer_configure(GtkWidget* widget, GdkEventConfigure* event, gpointer user_data) {
    (void)widget;
    (void)user_data;
    if (vnc_fd < 0 || screen_w <= 0 || screen_h <= 0) return FALSE;

    int new_w = event->width;
    int new_h = event->height;

    // Check if the user is dragging or resizing the window
    if (new_w != screen_w || new_h != screen_h) {
        if (resize_debounce_source != 0) {
            g_source_remove(resize_debounce_source);
        }
        pending_resize_w = new_w;
        pending_resize_h = new_h;
        resize_debounce_source = g_timeout_add(VNC_RESIZE_DEBOUNCE_MS, debounce_resize_timeout, NULL);
    }
    return FALSE;
}

// Client Core Callbacks
static void send_raw_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    if (vnc_fd >= 0) {
        send(vnc_fd, data, len, 0);
    }
}

static void on_screen_update_cb(int x, int y, int w, int h, void* user_data) {
    (void)x; (void)y; (void)w; (void)h; (void)user_data;
    pthread_mutex_lock(&backbuffer_mutex);
    waiting_for_draw = 1;
    pthread_mutex_unlock(&backbuffer_mutex);
    g_idle_add((GSourceFunc)queue_draw_idle, NULL);
}

static void on_desktop_resize_cb(int w, int h, void* user_data) {
    (void)w; (void)h; (void)user_data;
    g_idle_add(apply_remote_desktop_size_idle, NULL);
}

static void on_clipboard_update_cb(const char* text, int len, void* user_data) {
    (void)user_data;
    char* copy = malloc((size_t)len + 1);
    if (copy) {
        memcpy(copy, text, (size_t)len);
        copy[len] = '\0';
        g_idle_add(apply_server_clipboard_idle, copy);
    }
}

static gboolean show_error_dialog_idle(gpointer data) {
    char* msg = (char*)data;
    show_error_dialog(GTK_WINDOW(main_window), msg);
    free(msg);
    return FALSE;
}

static void on_disconnect_cb(const char* reason, void* user_data) {
    (void)user_data;
    char* copy = strdup(reason);
    g_idle_add(show_error_dialog_idle, copy);
}

static char* request_password_cb(void* user_data) {
    (void)user_data;
    return prompt_password();
}

// QEMU audio extension callbacks (see docs/custom/rfb_qemu_audio_extension.md).
// All four fire on vnc_client_thread (the background socket reader), never the GTK
// main thread, so audio_playback needs no locking between them.
static void on_audio_supported_cb(void* user_data) {
    (void)user_data;
    if (!want_audio) return;
    vnc_core_send_audio_set_format(VNC_AUDIO_FMT_S16, 2, 44100);
    vnc_core_send_audio_enable();
}

static void on_audio_begin_cb(void* user_data) {
    (void)user_data;
    if (audio_playback) return;

    pa_sample_spec spec;
    spec.format = PA_SAMPLE_S16LE;
    spec.channels = 2;
    spec.rate = 44100;

    int pa_err = 0;
    audio_playback = pa_simple_new(NULL, "vncviewer", PA_STREAM_PLAYBACK, NULL,
                                   "VNC server audio", &spec, NULL, NULL, &pa_err);
    if (!audio_playback) {
        fprintf(stderr, "Error: could not open audio playback: %s\n", pa_strerror(pa_err));
    }
}

static void on_audio_data_cb(const uint8_t* pcm, size_t len, void* user_data) {
    (void)user_data;
    if (!audio_playback || len == 0) return;

    int pa_err = 0;
    if (pa_simple_write(audio_playback, pcm, len, &pa_err) < 0) {
        DEBUG_LOG("audio playback write failed: %s", pa_strerror(pa_err));
    }
}

static void on_audio_end_cb(void* user_data) {
    (void)user_data;
    if (audio_playback) {
        pa_simple_free(audio_playback);
        audio_playback = NULL;
    }
}

static int on_custom_encoding_cb(int fd, uint32_t encoding, uint16_t rx, uint16_t ry, uint16_t rw, uint16_t rh, void* user_data) {
    (void)rx; (void)ry; (void)user_data;
    if (encoding == 50 || encoding == VNC_ENCODING_VP9) { // H.264 / VP9
        active_video_codec_id = (encoding == VNC_ENCODING_VP9) ? AV_CODEC_ID_VP9 : AV_CODEC_ID_H264;
        uint32_t length = 0;
        uint32_t flags = 0;
        if (read_exact(fd, &length, 4) < 0 || read_exact(fd, &flags, 4) < 0) return -1;
        length = read_u32_be((uint8_t*)&length);
        flags = read_u32_be((uint8_t*)&flags);

        uint8_t* payload = malloc(length);
        if (read_exact(fd, payload, length) < 0) {
            free(payload);
            return -1;
        }

        if (flags & 2) {
            reset_decoder(rw, rh);
        }

        if (decoder_primed && length > 0) {
            decode_video(payload, (int)length, backbuffer, rw, rh);
        }
        free(payload);

        pthread_mutex_lock(&backbuffer_mutex);
        waiting_for_draw = 1;
        pthread_mutex_unlock(&backbuffer_mutex);
        g_idle_add((GSourceFunc)queue_draw_idle, NULL);
        return 0;
    }
    else if (encoding == VNC_ENCODING_UDP_SETUP) {
        uint8_t setup_payload[VNC_UDP_SETUP_PAYLOAD_LEN];
        if (read_exact(fd, setup_payload, sizeof(setup_payload)) < 0) return -1;
        udp_handle_setup(setup_payload);
        return 0;
    }
    return 0;
}

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

    save_last_address(host, port);

    int enc_active = gtk_combo_box_get_active(GTK_COMBO_BOX(combo_encoding));
    if (enc_active == 0) strcpy(preferred_encoding, "h264");
    else if (enc_active == 1) strcpy(preferred_encoding, "vp9");
    else if (enc_active == 2) strcpy(preferred_encoding, "jpeg");
    else if (enc_active == 3) strcpy(preferred_encoding, "hextile");
    else strcpy(preferred_encoding, "raw");
    DEBUG_LOG("connecting to %s:%d with preferred encoding=%s", host, port, preferred_encoding);

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
    udp_server_in_addr = addr.sin_addr;

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
    DEBUG_LOG("TCP connect succeeded");

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    vnc_fd = fd;

    // Initialize VNC Core
    vnc_core_callbacks_t cb;
    cb.send_raw = send_raw_cb;
    cb.on_screen_update = on_screen_update_cb;
    cb.on_desktop_resize = on_desktop_resize_cb;
    cb.on_clipboard_update = on_clipboard_update_cb;
    cb.on_disconnect = on_disconnect_cb;
    cb.request_password = request_password_cb;
    cb.on_audio_supported = on_audio_supported_cb;
    cb.on_audio_begin = on_audio_begin_cb;
    cb.on_audio_data = on_audio_data_cb;
    cb.on_audio_end = on_audio_end_cb;
    cb.on_custom_encoding = on_custom_encoding_cb;

    vnc_core_init(&cb, NULL);
    want_audio = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_audio));
    vnc_core_request_audio(want_audio);

    // Perform VNC handshake synchronously on main thread (necessary for password dialog)
    if (vnc_core_desktop_handshake(vnc_fd, preferred_encoding) < 0) {
        vnc_core_cleanup();
        close(vnc_fd);
        vnc_fd = -1;
        show_error_dialog(parent, "VNC protocol handshake failed.");
        return;
    }

    gtk_widget_hide(main_window);

    // Create Viewer Window
    viewer_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[384];
    snprintf(title, sizeof(title), "VNC Viewer - %s:%d", host, port);
    gtk_window_set_title(GTK_WINDOW(viewer_window), title);
    gtk_window_set_default_size(GTK_WINDOW(viewer_window), screen_w, screen_h);

    drawing_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(drawing_area, screen_w, screen_h);
    gtk_container_add(GTK_CONTAINER(viewer_window), drawing_area);

    gtk_widget_add_events(drawing_area, GDK_POINTER_MOTION_MASK |
                                         GDK_BUTTON_PRESS_MASK |
                                         GDK_BUTTON_RELEASE_MASK |
                                         GDK_SCROLL_MASK);

    g_signal_connect(G_OBJECT(drawing_area), "draw", G_CALLBACK(on_draw), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "motion-notify-event", G_CALLBACK(on_motion), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "button-press-event", G_CALLBACK(on_button), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "button-release-event", G_CALLBACK(on_button), NULL);
    g_signal_connect(G_OBJECT(drawing_area), "scroll-event", G_CALLBACK(on_scroll), NULL);
    g_signal_connect(G_OBJECT(viewer_window), "key-press-event", G_CALLBACK(on_key_event), NULL);
    g_signal_connect(G_OBJECT(viewer_window), "key-release-event", G_CALLBACK(on_key_event), NULL);
    g_signal_connect(G_OBJECT(viewer_window), "configure-event", G_CALLBACK(on_viewer_configure), NULL);
    g_signal_connect(G_OBJECT(viewer_window), "destroy", G_CALLBACK(on_viewer_destroy), NULL);

    gtk_widget_show_all(viewer_window);

    // Setup GtkClipboard monitor
    GtkClipboard* clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    g_signal_connect(clipboard, "owner-change", G_CALLBACK(on_clipboard_owner_change), NULL);

    // Spawn VNC reader thread
    pthread_t tid;
    client_running = 1;
    pthread_create(&tid, NULL, vnc_client_thread, NULL);
    pthread_detach(tid);
}

int main(int argc, char* argv[]) {
    gtk_init(&argc, &argv);

    char host[256];
    int port = 5900;
    load_last_address(host, &port);

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "Connect to VNC Server");
    gtk_container_set_border_width(GTK_CONTAINER(main_window), 20);
    gtk_window_set_default_size(GTK_WINDOW(main_window), 450, 180);

    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    GtkWidget* label = gtk_label_new("VNC Server Address (host:port or host):");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    entry_address = gtk_entry_new();
    char addr_str[384];
    snprintf(addr_str, sizeof(addr_str), "%s:%d", host, port);
    gtk_entry_set_text(GTK_ENTRY(entry_address), addr_str);
    gtk_box_pack_start(GTK_BOX(vbox), entry_address, FALSE, FALSE, 0);

    // Encoding choice dropdown
    GtkWidget* hbox_enc = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox), hbox_enc, FALSE, FALSE, 0);
    
    GtkWidget* label_enc = gtk_label_new("Preferred Encoding:");
    gtk_box_pack_start(GTK_BOX(hbox_enc), label_enc, FALSE, FALSE, 0);

    combo_encoding = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "H.264 Video");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "VP9 Video");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Tight (JPEG)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Hextile");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_encoding), "Raw");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_encoding), 0);
    gtk_box_pack_start(GTK_BOX(hbox_enc), combo_encoding, TRUE, TRUE, 0);

    // QEMU audio extension opt-in (see docs/custom/rfb_qemu_audio_extension.md).
    // Only takes effect if the server also has it enabled — otherwise this is a no-op.
    check_audio = gtk_check_button_new_with_label("Enable audio (if server supports it)");
    gtk_box_pack_start(GTK_BOX(vbox), check_audio, FALSE, FALSE, 0);

    GtkWidget* btn_connect = gtk_button_new_with_label("Connect");
    gtk_box_pack_start(GTK_BOX(vbox), btn_connect, FALSE, FALSE, 0);

    g_signal_connect(btn_connect, "clicked", G_CALLBACK(on_btn_connect_clicked), main_window);
    g_signal_connect(G_OBJECT(entry_address), "activate", G_CALLBACK(on_btn_connect_clicked), main_window);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_widget_show_all(main_window);
    gtk_main();

    vnc_core_cleanup();

    return 0;
}
