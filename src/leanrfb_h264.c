#include "leanrfb_internal.h"
#include <libavcodec/avcodec.h>
#include <libavutil/opt.h>
#include <libavutil/hwcontext.h>
#include <libavutil/imgutils.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    AVCodecContext* codec_ctx;
    AVFrame* sw_frame;
    AVFrame* hw_frame;
    AVPacket* pkt;
    AVBufferRef* hw_device_ctx;
    int width;
    int height;
    int pts;
    int is_hw; // 1 = VA-API, 2 = NVENC, 0 = Software x264
    int force_keyframe; // set by vnc_h264_encoder_force_keyframe(), consumed on next encode
} vnc_h264_encoder_t;

// Color space conversion helper functions (fast integer logic)
static void bgra_to_yuv420p(const uint32_t* fb, int w, int h, AVFrame* frame) {
    uint8_t* y = frame->data[0];
    uint8_t* u = frame->data[1];
    uint8_t* v = frame->data[2];
    int y_stride = frame->linesize[0];
    int u_stride = frame->linesize[1];
    int v_stride = frame->linesize[2];

    for (int row = 0; row < h; row++) {
        const uint32_t* src_row = fb + row * w;
        uint8_t* dst_y = y + row * y_stride;
        uint8_t* dst_u = u + (row / 2) * u_stride;
        uint8_t* dst_v = v + (row / 2) * v_stride;

        for (int col = 0; col < w; col++) {
            uint32_t pixel = src_row[col];
            int b = pixel & 0xFF;
            int g = (pixel >> 8) & 0xFF;
            int r = (pixel >> 16) & 0xFF;

            int Y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            dst_y[col] = (uint8_t)(Y < 0 ? 0 : (Y > 255 ? 255 : Y));

            if (row % 2 == 0 && col % 2 == 0) {
                int U = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                int V = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                dst_u[col / 2] = (uint8_t)(U < 0 ? 0 : (U > 255 ? 255 : U));
                dst_v[col / 2] = (uint8_t)(V < 0 ? 0 : (V > 255 ? 255 : V));
            }
        }
    }
}

static void bgra_to_nv12(const uint32_t* fb, int w, int h, AVFrame* frame) {
    uint8_t* y = frame->data[0];
    uint8_t* uv = frame->data[1];
    int y_stride = frame->linesize[0];
    int uv_stride = frame->linesize[1];

    for (int row = 0; row < h; row++) {
        const uint32_t* src_row = fb + row * w;
        uint8_t* dst_y = y + row * y_stride;
        uint8_t* dst_uv = uv + (row / 2) * uv_stride;

        for (int col = 0; col < w; col++) {
            uint32_t pixel = src_row[col];
            int b = pixel & 0xFF;
            int g = (pixel >> 8) & 0xFF;
            int r = (pixel >> 16) & 0xFF;

            int Y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            dst_y[col] = (uint8_t)(Y < 0 ? 0 : (Y > 255 ? 255 : Y));

            if (row % 2 == 0 && col % 2 == 0) {
                int U = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                int V = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                int col_half = col / 2;
                dst_uv[col_half * 2] = (uint8_t)(U < 0 ? 0 : (U > 255 ? 255 : U));
                dst_uv[col_half * 2 + 1] = (uint8_t)(V < 0 ? 0 : (V > 255 ? 255 : V));
            }
        }
    }
}

void* vnc_h264_encoder_create(int width, int height, int fps, int quality) {
    (void)quality;
    vnc_h264_encoder_t* enc = calloc(1, sizeof(vnc_h264_encoder_t));
    if (!enc) return NULL;

    enc->width = width;
    enc->height = height;
    enc->pts = 0;
    enc->pkt = av_packet_alloc();

    // 1. Try to initialize NVIDIA NVENC GPU Encoder
    const AVCodec* codec = avcodec_find_encoder_by_name("h264_nvenc");
    if (codec) {
        enc->codec_ctx = avcodec_alloc_context3(codec);
        enc->codec_ctx->width = width;
        enc->codec_ctx->height = height;
        enc->codec_ctx->time_base = (AVRational){1, fps};
        enc->codec_ctx->framerate = (AVRational){fps, 1};
        enc->codec_ctx->pix_fmt = AV_PIX_FMT_NV12;
        enc->codec_ctx->gop_size = fps * 2;
        enc->codec_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
        // B-frames require the decoder to buffer frames out of display order —
        // pure latency with no benefit for a live desktop stream. LOW_DELAY above
        // is only a hint some encoders honor; this is the field that actually
        // guarantees it across NVENC/VAAPI/libx264.
        enc->codec_ctx->max_b_frames = 0;

        int64_t bitrate = vnc_video_target_bitrate(width, height, fps);
        enc->codec_ctx->bit_rate = bitrate;
        enc->codec_ctx->rc_max_rate = bitrate;
        enc->codec_ctx->rc_buffer_size = (int)(bitrate / 4); // ~250ms, keeps frame sizes consistent for low latency

        av_opt_set(enc->codec_ctx->priv_data, "preset", "p1", 0); // Fastest low latency preset
        av_opt_set(enc->codec_ctx->priv_data, "tune", "ull", 0);   // Ultra low latency
        
        int open_ret = avcodec_open2(enc->codec_ctx, codec, NULL);
        if (open_ret >= 0) {
            enc->is_hw = 2; // NVENC
            printf("[VNC SERVER] GPU NVENC Hardware Encoding enabled successfully.\n");
            goto init_frames;
        }
        {
            char errbuf[128];
            av_strerror(open_ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[VNC SERVER] H.264: NVENC avcodec_open2 failed, trying VAAPI next: %s\n", errbuf);
        }
        avcodec_free_context(&enc->codec_ctx);
    }

    // 2. Try to initialize Intel/AMD VA-API GPU Encoder
    codec = avcodec_find_encoder_by_name("h264_vaapi");
    if (codec) {
        int ret = av_hwdevice_ctx_create(&enc->hw_device_ctx, AV_HWDEVICE_TYPE_VAAPI, NULL, NULL, 0);
        if (ret >= 0) {
            enc->codec_ctx = avcodec_alloc_context3(codec);
            enc->codec_ctx->width = width;
            enc->codec_ctx->height = height;
            enc->codec_ctx->time_base = (AVRational){1, fps};
            enc->codec_ctx->framerate = (AVRational){fps, 1};
            enc->codec_ctx->pix_fmt = AV_PIX_FMT_VAAPI;
            enc->codec_ctx->gop_size = fps * 2;
            enc->codec_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
        // B-frames require the decoder to buffer frames out of display order —
        // pure latency with no benefit for a live desktop stream. LOW_DELAY above
        // is only a hint some encoders honor; this is the field that actually
        // guarantees it across NVENC/VAAPI/libx264.
        enc->codec_ctx->max_b_frames = 0;

            {
                int64_t bitrate = vnc_video_target_bitrate(width, height, fps);
                enc->codec_ctx->bit_rate = bitrate;
                enc->codec_ctx->rc_max_rate = bitrate;
                enc->codec_ctx->rc_buffer_size = (int)(bitrate / 4); // ~250ms, keeps frame sizes consistent for low latency
            }

            // Create VA-API frames context
            AVBufferRef* hw_frames_ref = av_hwframe_ctx_alloc(enc->hw_device_ctx);
            if (hw_frames_ref) {
                AVHWFramesContext* frames_ctx = (AVHWFramesContext*)hw_frames_ref->data;
                frames_ctx->format = AV_PIX_FMT_VAAPI;
                frames_ctx->sw_format = AV_PIX_FMT_NV12;
                frames_ctx->width = width;
                frames_ctx->height = height;
                frames_ctx->initial_pool_size = 4;
                if (av_hwframe_ctx_init(hw_frames_ref) >= 0) {
                    enc->codec_ctx->hw_frames_ctx = av_buffer_ref(hw_frames_ref);
                }
                av_buffer_unref(&hw_frames_ref);
            }

            if (!enc->codec_ctx->hw_frames_ctx) {
                fprintf(stderr, "[VNC SERVER] H.264: VAAPI hw_frames_ctx init failed, trying libx264 next\n");
            } else {
                int open_ret = avcodec_open2(enc->codec_ctx, codec, NULL);
                if (open_ret >= 0) {
                    enc->is_hw = 1; // VA-API
                    enc->hw_frame = av_frame_alloc();
                    printf("[VNC SERVER] GPU VA-API Hardware Encoding enabled successfully.\n");
                    goto init_frames;
                }
                char errbuf[128];
                av_strerror(open_ret, errbuf, sizeof(errbuf));
                fprintf(stderr, "[VNC SERVER] H.264: VAAPI avcodec_open2 failed, trying libx264 next: %s\n", errbuf);
            }
            if (enc->codec_ctx->hw_frames_ctx) av_buffer_unref(&enc->codec_ctx->hw_frames_ctx);
            avcodec_free_context(&enc->codec_ctx);
            av_buffer_unref(&enc->hw_device_ctx);
            enc->hw_device_ctx = NULL;
        }
    }

    // 3. Fallback: CPU Software libx264 via libavcodec
    codec = avcodec_find_encoder_by_name("libx264");
    if (codec) {
        enc->codec_ctx = avcodec_alloc_context3(codec);
        enc->codec_ctx->width = width;
        enc->codec_ctx->height = height;
        enc->codec_ctx->time_base = (AVRational){1, fps};
        enc->codec_ctx->framerate = (AVRational){fps, 1};
        enc->codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
        enc->codec_ctx->gop_size = fps * 2;
        enc->codec_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
        // B-frames require the decoder to buffer frames out of display order —
        // pure latency with no benefit for a live desktop stream. LOW_DELAY above
        // is only a hint some encoders honor; this is the field that actually
        // guarantees it across NVENC/VAAPI/libx264.
        enc->codec_ctx->max_b_frames = 0;

        {
            int64_t bitrate = vnc_video_target_bitrate(width, height, fps);
            enc->codec_ctx->bit_rate = bitrate;
            enc->codec_ctx->rc_max_rate = bitrate;
            enc->codec_ctx->rc_buffer_size = (int)(bitrate / 4); // ~250ms, keeps frame sizes consistent for low latency
        }

        enc->codec_ctx->thread_count = 0;
        enc->codec_ctx->thread_type = FF_THREAD_SLICE;

        av_opt_set(enc->codec_ctx->priv_data, "preset", "ultrafast", 0);
        av_opt_set(enc->codec_ctx->priv_data, "tune", "zerolatency", 0);
        
        int open_ret = avcodec_open2(enc->codec_ctx, codec, NULL);
        if (open_ret >= 0) {
            enc->is_hw = 0; // Software libx264
            printf("[VNC SERVER] GPU Hardware Encoding not supported. Falling back to CPU software encoding.\n");
            goto init_frames;
        }
        {
            char errbuf[128];
            av_strerror(open_ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[VNC SERVER] H.264: libx264 avcodec_open2 failed: %s\n", errbuf);
        }
        avcodec_free_context(&enc->codec_ctx);
    }

    // Encoder setup failed completely — no NVENC, VAAPI, or libx264 encoder could be
    // opened. This client will never receive any H.264 video (silent black screen
    // otherwise, since vnc_send_video_update() just returns when *enc_slot is NULL).
    fprintf(stderr, "[VNC SERVER] H.264: no usable encoder found (NVENC/VAAPI/libx264 all failed or unavailable)\n");
    av_packet_free(&enc->pkt);
    free(enc);
    return NULL;

init_frames:
    enc->sw_frame = av_frame_alloc();
    enc->sw_frame->width = width;
    enc->sw_frame->height = height;
    enc->sw_frame->format = (enc->is_hw > 0) ? AV_PIX_FMT_NV12 : AV_PIX_FMT_YUV420P;
    av_frame_get_buffer(enc->sw_frame, 0);
    return enc;
}

int vnc_h264_encoder_encode(void* enc_ptr, const uint32_t* fb, uint8_t** out_data, int* out_len, int* is_keyframe, int* pts_out) {
    vnc_h264_encoder_t* enc = (vnc_h264_encoder_t*)enc_ptr;
    if (!enc || !fb) return -1;

    av_frame_make_writable(enc->sw_frame);

    if (enc->is_hw > 0) {
        bgra_to_nv12(fb, enc->width, enc->height, enc->sw_frame);
    } else {
        bgra_to_yuv420p(fb, enc->width, enc->height, enc->sw_frame);
    }

    AVFrame* send_frame = enc->sw_frame;
    if (enc->is_hw == 1) { // VA-API hardware context texture upload
        av_frame_unref(enc->hw_frame);
        int err = av_hwframe_get_buffer(enc->codec_ctx->hw_frames_ctx, enc->hw_frame, 0);
        if (err < 0) {
            char errbuf[128];
            av_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "[VNC SERVER] H.264: av_hwframe_get_buffer failed: %s\n", errbuf);
            return -1;
        }
        err = av_hwframe_transfer_data(enc->hw_frame, enc->sw_frame, 0);
        if (err < 0) {
            char errbuf[128];
            av_strerror(err, errbuf, sizeof(errbuf));
            fprintf(stderr, "[VNC SERVER] H.264: av_hwframe_transfer_data failed: %s\n", errbuf);
            return -1;
        }
        send_frame = enc->hw_frame;
    }

    send_frame->pts = enc->pts++;
    if (pts_out) {
        *pts_out = (int)send_frame->pts;
    }
    if (enc->force_keyframe) {
        send_frame->pict_type = AV_PICTURE_TYPE_I;
        send_frame->flags |= AV_FRAME_FLAG_KEY;
        enc->force_keyframe = 0;
    }

    int ret = avcodec_send_frame(enc->codec_ctx, send_frame);
    if (ret < 0) {
        char errbuf[128];
        av_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[VNC SERVER] H.264: avcodec_send_frame failed: %s\n", errbuf);
        return -1;
    }

    av_packet_unref(enc->pkt);
    ret = avcodec_receive_packet(enc->codec_ctx, enc->pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
        *out_data = NULL;
        *out_len = 0;
        *is_keyframe = 0;
        return 0;
    } else if (ret < 0) {
        char errbuf[128];
        av_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[VNC SERVER] H.264: avcodec_receive_packet failed: %s\n", errbuf);
        return -1;
    }

    *out_data = enc->pkt->data;
    *out_len = enc->pkt->size;
    *is_keyframe = (enc->pkt->flags & AV_PKT_FLAG_KEY) ? 1 : 0;
    return 0;
}

void vnc_h264_encoder_force_keyframe(void* enc_ptr) {
    vnc_h264_encoder_t* enc = (vnc_h264_encoder_t*)enc_ptr;
    if (enc) enc->force_keyframe = 1;
}

void vnc_h264_encoder_destroy(void* enc_ptr) {
    vnc_h264_encoder_t* enc = (vnc_h264_encoder_t*)enc_ptr;
    if (!enc) return;

    if (enc->codec_ctx) {
        avcodec_free_context(&enc->codec_ctx);
    }
    if (enc->sw_frame) {
        av_frame_free(&enc->sw_frame);
    }
    if (enc->hw_frame) {
        av_frame_free(&enc->hw_frame);
    }
    if (enc->pkt) {
        av_packet_free(&enc->pkt);
    }
    if (enc->hw_device_ctx) {
        av_buffer_unref(&enc->hw_device_ctx);
    }
    free(enc);
}
