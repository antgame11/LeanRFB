#include "leanrfb_internal.h"
#include <x264.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    x264_t* encoder;
    x264_picture_t pic_in;
    x264_picture_t pic_out;
    int width;
    int height;
    int pts;
} vnc_h264_encoder_t;

void* vnc_h264_encoder_create(int width, int height, int fps, int quality) {
    vnc_h264_encoder_t* enc = calloc(1, sizeof(vnc_h264_encoder_t));
    if (!enc) return NULL;

    x264_param_t param;
    if (x264_param_default_preset(&param, "ultrafast", "zerolatency") < 0) {
        free(enc);
        return NULL;
    }

    param.i_width = width;
    param.i_height = height;
    param.i_fps_num = fps;
    param.i_fps_den = 1;
    param.i_keyint_max = fps * 2; // Keyframe every 2 seconds
    param.b_intra_refresh = 1;
    param.i_threads = 1; // Single-threaded for zero lookahead latency

    if (x264_param_apply_profile(&param, "baseline") < 0) {
        free(enc);
        return NULL;
    }

    int crf = 23;
    if (quality > 0 && quality <= 100) {
        crf = 51 - (quality * 51 / 100);
        if (crf < 10) crf = 10;
    }
    param.rc.i_rc_method = X264_RC_CRF;
    param.rc.f_rf_constant = (float)crf;

    enc->encoder = x264_encoder_open(&param);
    if (!enc->encoder) {
        free(enc);
        return NULL;
    }

    if (x264_picture_alloc(&enc->pic_in, X264_CSP_I420, width, height) < 0) {
        x264_encoder_close(enc->encoder);
        free(enc);
        return NULL;
    }

    enc->width = width;
    enc->height = height;
    enc->pts = 0;
    return enc;
}

int vnc_h264_encoder_encode(void* enc_ptr, const uint32_t* fb, uint8_t** out_data, int* out_len, int* is_keyframe, int* pts_out) {
    vnc_h264_encoder_t* enc = (vnc_h264_encoder_t*)enc_ptr;
    if (!enc || !fb) return -1;

    int w = enc->width;
    int h = enc->height;
    uint8_t* y = enc->pic_in.img.plane[0];
    uint8_t* u = enc->pic_in.img.plane[1];
    uint8_t* v = enc->pic_in.img.plane[2];

    // BGRA to YUV420p color-space conversion
    for (int row = 0; row < h; row++) {
        const uint32_t* src_row = fb + row * w;
        for (int col = 0; col < w; col++) {
            uint32_t pixel = src_row[col];
            uint8_t r = (pixel >> 16) & 0xFF;
            uint8_t g = (pixel >> 8) & 0xFF;
            uint8_t b = pixel & 0xFF;

            int Y = (int)(0.299f * r + 0.587f * g + 0.114f * b);
            y[row * w + col] = (uint8_t)(Y < 0 ? 0 : (Y > 255 ? 255 : Y));

            if (row % 2 == 0 && col % 2 == 0) {
                int U = (int)(-0.169f * r - 0.331f * g + 0.500f * b + 128);
                int V = (int)(0.500f * r - 0.419f * g - 0.081f * b + 128);
                int uv_idx = (row / 2) * (w / 2) + (col / 2);
                u[uv_idx] = (uint8_t)(U < 0 ? 0 : (U > 255 ? 255 : U));
                v[uv_idx] = (uint8_t)(V < 0 ? 0 : (V > 255 ? 255 : V));
            }
        }
    }

    enc->pic_in.i_pts = enc->pts++;
    if (pts_out) {
        *pts_out = enc->pts;
    }

    x264_nal_t* nals;
    int i_nals;
    int frame_size = x264_encoder_encode(enc->encoder, &nals, &i_nals, &enc->pic_in, &enc->pic_out);
    if (frame_size < 0) {
        return -1;
    }

    if (frame_size > 0) {
        *out_data = nals[0].p_payload;
        *out_len = frame_size;
        *is_keyframe = enc->pic_out.b_keyframe;
    } else {
        *out_data = NULL;
        *out_len = 0;
        *is_keyframe = 0;
    }

    return 0;
}

void vnc_h264_encoder_destroy(void* enc_ptr) {
    vnc_h264_encoder_t* enc = (vnc_h264_encoder_t*)enc_ptr;
    if (!enc) return;
    x264_picture_clean(&enc->pic_in);
    x264_encoder_close(enc->encoder);
    free(enc);
}
