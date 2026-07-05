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
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <openssl/des.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavutil/imgutils.h>

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

// Global codec pointers
static AVCodecContext* codec_ctx = NULL;
static AVFrame* frame = NULL;
static AVPacket* pkt = NULL;
static struct SwsContext* sws_ctx = NULL;

static void init_decoder(int width, int height) {
    const AVCodec* codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        fprintf(stderr, "Error: H.264 decoder not found in libavcodec\n");
        exit(1);
    }
    codec_ctx = avcodec_alloc_context3(codec);
    codec_ctx->width = width;
    codec_ctx->height = height;
    codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    
    if (avcodec_open2(codec_ctx, codec, NULL) < 0) {
        fprintf(stderr, "Error: Could not open libavcodec H.264 decoder\n");
        exit(1);
    }
    frame = av_frame_alloc();
    pkt = av_packet_alloc();
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
    if (sws_ctx) {
        sws_freeContext(sws_ctx);
        sws_ctx = NULL;
    }
    init_decoder(width, height);
}

static int decode_h264(const uint8_t* data, int len, uint8_t* out_bgra, int width, int height) {
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

    if (!sws_ctx) {
        sws_ctx = sws_getContext(codec_ctx->width, codec_ctx->height, codec_ctx->pix_fmt,
                                 width, height, AV_PIX_FMT_BGRA,
                                 SWS_BILINEAR, NULL, NULL, NULL);
    }

    uint8_t* dest[4] = { out_bgra, NULL, NULL, NULL };
    int dest_linesize[4] = { width * 4, 0, 0, 0 };

    sws_scale(sws_ctx, (const uint8_t *const *)frame->data, frame->linesize, 0, codec_ctx->height,
              dest, dest_linesize);

    return 1;
}

// Protocol helper
static int read_exact(int fd, void* buf, size_t len) {
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
    buf[0] = 3; // FramebufferUpdateRequest
    buf[1] = incremental;
    write_u16_be(buf + 2, x);
    write_u16_be(buf + 4, y);
    write_u16_be(buf + 6, w);
    write_u16_be(buf + 8, h);
    send(fd, buf, 10, 0);
}

static void send_key_event(int fd, uint8_t down, uint32_t keysym) {
    uint8_t buf[8];
    buf[0] = 4; // KeyEvent
    buf[1] = down;
    buf[2] = 0;
    buf[3] = 0;
    write_u32_be(buf + 4, keysym);
    send(fd, buf, 8, 0);
}

static void send_pointer_event(int fd, uint16_t x, uint16_t y, uint8_t button_mask) {
    uint8_t buf[6];
    buf[0] = 5; // PointerEvent
    buf[1] = button_mask;
    write_u16_be(buf + 2, x);
    write_u16_be(buf + 4, y);
    send(fd, buf, 6, 0);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port> [password]\n", argv[0]);
        return 1;
    }

    const char* host = argv[1];
    int port = atoi(argv[2]);
    const char* password = (argc > 3) ? argv[3] : "";

    // Connect to server
    struct hostent* he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Error: Could not resolve hostname '%s'\n", host);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *(struct in_addr*)he->h_addr;

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error: Connect to %s:%d failed: %s\n", host, port, strerror(errno));
        close(fd);
        return 1;
    }

    printf("Connected to VNC server at %s:%d\n", host, port);

    // 1. Handshake: Version
    char ver[13] = {0};
    if (read_exact(fd, ver, 12) < 0) {
        fprintf(stderr, "Error: Failed to read server version\n");
        close(fd);
        return 1;
    }
    printf("Server Version: %s", ver);

    send(fd, "RFB 003.008\n", 12, 0);

    // 2. Handshake: Security Types
    uint8_t num_sec_types = 0;
    if (read_exact(fd, &num_sec_types, 1) < 0) {
        fprintf(stderr, "Error: Failed to read security types count\n");
        close(fd);
        return 1;
    }

    if (num_sec_types == 0) {
        fprintf(stderr, "Error: No security types supported by server\n");
        close(fd);
        return 1;
    }

    uint8_t* sec_types = malloc(num_sec_types);
    if (read_exact(fd, sec_types, num_sec_types) < 0) {
        fprintf(stderr, "Error: Failed to read security types\n");
        free(sec_types);
        close(fd);
        return 1;
    }

    // Select security type: prefer VncAuth (2) or None (1)
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
        fprintf(stderr, "Error: No supported security type found ( None/VncAuth required)\n");
        close(fd);
        return 1;
    }

    // Send selected security type
    send(fd, &selected_sec, 1, 0);

    // 3. Security Authentication
    if (selected_sec == 2) { // VncAuth
        uint8_t challenge[16];
        if (read_exact(fd, challenge, 16) < 0) {
            fprintf(stderr, "Error: Failed to read VncAuth challenge\n");
            close(fd);
            return 1;
        }

        uint8_t response[16];
        vnc_encrypt_bytes(password, challenge, response);
        send(fd, response, 16, 0);
    }

    // Read security result
    uint32_t sec_result = 0;
    if (read_exact(fd, &sec_result, 4) < 0) {
        fprintf(stderr, "Error: Failed to read security result\n");
        close(fd);
        return 1;
    }
    sec_result = read_u32_be((uint8_t*)&sec_result);

    if (sec_result != 0) {
        fprintf(stderr, "Error: Authentication failed (code %d)\n", sec_result);
        close(fd);
        return 1;
    }
    printf("Authentication succeeded.\n");

    // 4. ClientInit
    uint8_t shared = 1;
    send(fd, &shared, 1, 0);

    // 5. ServerInit
    uint16_t w = 0, h = 0;
    uint8_t pix_fmt[16];
    uint32_t name_len = 0;

    if (read_exact(fd, &w, 2) < 0 || read_exact(fd, &h, 2) < 0 ||
        read_exact(fd, pix_fmt, 16) < 0 || read_exact(fd, &name_len, 4) < 0) {
        fprintf(stderr, "Error: Failed to read ServerInit\n");
        close(fd);
        return 1;
    }
    w = read_u16_be((uint8_t*)&w);
    h = read_u16_be((uint8_t*)&h);
    name_len = read_u32_be((uint8_t*)&name_len);

    char* server_name = malloc(name_len + 1);
    if (read_exact(fd, server_name, name_len) < 0) {
        fprintf(stderr, "Error: Failed to read server name\n");
        free(server_name);
        close(fd);
        return 1;
    }
    server_name[name_len] = '\0';
    printf("Connected to server '%s' (%dx%d)\n", server_name, w, h);
    free(server_name);

    // Send SetEncodings: request H264 (50), then Raw (0)
    uint8_t encs_msg[12];
    encs_msg[0] = 2; // SetEncodings
    encs_msg[1] = 0;
    write_u16_be(encs_msg + 2, 2); // 2 encodings
    write_u32_be(encs_msg + 4, 50); // H.264
    write_u32_be(encs_msg + 8, 0);  // Raw
    send(fd, encs_msg, 12, 0);

    // Initial FramebufferUpdateRequest
    send_fb_request(fd, 0, 0, 0, w, h);

    // Initialize H.264 Decoder
    init_decoder(w, h);

    // Setup X11 Window
    Display* dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "Error: Could not open X11 display\n");
        close(fd);
        return 1;
    }

    int screen = DefaultScreen(dpy);
    Window win = XCreateSimpleWindow(dpy, RootWindow(dpy, screen), 10, 10, w, h, 1,
                                     BlackPixel(dpy, screen), WhitePixel(dpy, screen));
    XStoreName(dpy, win, "leanrfb vncview (H.264 client)");
    XSelectInput(dpy, win, ExposureMask | KeyPressMask | KeyReleaseMask |
                           PointerMotionMask | ButtonPressMask | ButtonReleaseMask);
    XMapWindow(dpy, win);
    GC gc = XCreateGC(dpy, win, 0, NULL);

    // Allocate local backbuffer (BGRA format)
    uint8_t* backbuffer = malloc((size_t)w * h * 4);
    memset(backbuffer, 0, (size_t)w * h * 4);

    XImage* ximage = XCreateImage(dpy, DefaultVisual(dpy, screen), 24, ZPixmap, 0,
                                  (char*)backbuffer, w, h, 32, w * 4);

    int running = 1;
    struct pollfd fds[2];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[1].fd = ConnectionNumber(dpy);
    fds[1].events = POLLIN;

    uint8_t button_mask = 0;

    printf("Starting rendering event loop...\n");

    while (running) {
        int poll_ret = poll(fds, 2, 10);
        if (poll_ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 1. Process VNC messages
        if (fds[0].revents & POLLIN) {
            uint8_t msg_type = 0;
            if (recv(fd, &msg_type, 1, 0) <= 0) {
                printf("Server disconnected.\n");
                break;
            }

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
                        read_exact(fd, &encoding, 4) < 0) break;

                    rx = read_u16_be((uint8_t*)&rx);
                    ry = read_u16_be((uint8_t*)&ry);
                    rw = read_u16_be((uint8_t*)&rw);
                    rh = read_u16_be((uint8_t*)&rh);
                    encoding = read_u32_be((uint8_t*)&encoding);

                    if (encoding == 0) { // Raw
                        // Read raw BGRA pixels directly into the backbuffer
                        for (int y = 0; y < rh; y++) {
                            size_t offset = ((ry + y) * (size_t)w + rx) * 4;
                            if (read_exact(fd, backbuffer + offset, (size_t)rw * 4) < 0) goto loop_exit;
                        }
                        XPutImage(dpy, win, gc, ximage, rx, ry, rx, ry, rw, rh);
                    }
                    else if (encoding == 50) { // H.264
                        uint32_t length = 0;
                        uint32_t flags = 0;
                        if (read_exact(fd, &length, 4) < 0 || read_exact(fd, &flags, 4) < 0) goto loop_exit;
                        length = read_u32_be((uint8_t*)&length);
                        flags = read_u32_be((uint8_t*)&flags);

                        uint8_t* payload = malloc(length);
                        if (read_exact(fd, payload, length) < 0) {
                            free(payload);
                            goto loop_exit;
                        }

                        if (flags & 2) { // resetAllContextsFlag
                            reset_decoder(w, h);
                        }

                        if (length > 0) {
                            if (decode_h264(payload, length, backbuffer, w, h) > 0) {
                                // Draw decoded frame to screen
                                XPutImage(dpy, win, gc, ximage, 0, 0, 0, 0, w, h);
                            }
                        }
                        free(payload);
                    }
                }
                XFlush(dpy);

                // Request next incremental frame
                send_fb_request(fd, 1, 0, 0, w, h);
            }
        }

        // 2. Process X11 Events
        while (XPending(dpy)) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            switch (ev.type) {
                case Expose:
                    // Redraw the screen from backbuffer
                    XPutImage(dpy, win, gc, ximage, 0, 0, 0, 0, w, h);
                    XFlush(dpy);
                    break;
                case KeyPress:
                case KeyRelease: {
                    KeySym keysym = XLookupKeysym(&ev.xkey, 0);
                    int down = (ev.type == KeyPress) ? 1 : 0;
                    send_key_event(fd, down, (uint32_t)keysym);
                    break;
                }
                case MotionNotify:
                    send_pointer_event(fd, ev.xmotion.x, ev.xmotion.y, button_mask);
                    break;
                case ButtonPress:
                case ButtonRelease: {
                    int down = (ev.type == ButtonPress) ? 1 : 0;
                    int button = ev.xbutton.button;
                    if (button == 1) {
                        if (down) button_mask |= 1; else button_mask &= ~1;
                    } else if (button == 2) {
                        if (down) button_mask |= 2; else button_mask &= ~2;
                    } else if (button == 3) {
                        if (down) button_mask |= 4; else button_mask &= ~4;
                    } else if (button == 4) { // Scroll Up
                        if (down) button_mask |= 8; else button_mask &= ~8;
                    } else if (button == 5) { // Scroll Down
                        if (down) button_mask |= 16; else button_mask &= ~16;
                    }
                    send_pointer_event(fd, ev.xbutton.x, ev.xbutton.y, button_mask);
                    break;
                }
            }
        }
    }

loop_exit:
    printf("Exiting client...\n");

    // Cleanup X11
    XFreeGC(dpy, gc);
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);

    // Cleanup decoder
    if (codec_ctx) {
        avcodec_free_context(&codec_ctx);
    }
    if (frame) av_frame_free(&frame);
    if (pkt) av_packet_free(&pkt);
    if (sws_ctx) sws_freeContext(sws_ctx);

    free(backbuffer);
    close(fd);
    return 0;
}
