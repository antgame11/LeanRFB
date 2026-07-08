// QEMU-compatible VNC audio extension (see docs/custom/rfb_qemu_audio_extension.md).
// Wire format matches QEMU's ui/vnc.c exactly (VNC_ENCODING_AUDIO=-259,
// VNC_MSG_{CLIENT,SERVER}_QEMU=255 wrapper, ENABLE/DISABLE/SET_FORMAT and
// BEGIN/END/DATA sub-messages), so this also interoperates with a real QEMU
// VNC client/server.
//
// Capture side: there's no "guest audio" to hook into here (unlike QEMU, which
// captures its emulated sound card's own mixer output) — this server streams
// whatever is actually playing on the host's default audio output. On Linux
// that's the sink's PulseAudio/PipeWire-pulse "monitor" source, which mirrors
// everything passing through the sink without needing root or a kernel loopback
// module. `pa_simple_read()` blocks, so each audio-enabled client gets its own
// capture thread; the main poll loop drains the resulting ring buffer and
// writes DATA messages out over the client's normal (non-blocking) socket.
#include "leanrfb_internal.h"
#include <pulse/simple.h>
#include <pulse/error.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VNC_AUDIO_RING_CAP (256 * 1024)
#define VNC_AUDIO_CAPTURE_CHUNK 4096

struct vnc_audio_capture {
    pthread_t thread;
    pthread_mutex_t mutex;
    uint8_t* ring;
    size_t ring_len;
    volatile int stop;
    pa_sample_spec spec;
};

static pa_sample_format_t vnc_audio_pa_format(uint8_t wire_fmt) {
    switch (wire_fmt) {
        case VNC_AUDIO_FMT_U8:  return PA_SAMPLE_U8;
        case VNC_AUDIO_FMT_S32: return PA_SAMPLE_S32LE;
        // PulseAudio has no signed-8-bit or unsigned-16/32-bit sample types;
        // S16LE is what this project's own client always requests anyway, so
        // treat anything else as S16LE rather than fail the whole stream.
        case VNC_AUDIO_FMT_S16:
        default:
            return PA_SAMPLE_S16LE;
    }
}

static void* vnc_audio_capture_thread_main(void* arg) {
    vnc_audio_capture_t* cap = (vnc_audio_capture_t*)arg;
    int pa_err = 0;

    pa_simple* pa = pa_simple_new(
        NULL,                      // default server
        "leanrfb VNC server",      // application name
        PA_STREAM_RECORD,
        "@DEFAULT_MONITOR@",       // monitor of whatever the default sink is
        "VNC client audio",        // stream description
        &cap->spec,
        NULL, NULL, &pa_err);

    if (!pa) {
        fprintf(stderr, "[VNC AUDIO] Could not open capture stream: %s\n", pa_strerror(pa_err));
        return NULL;
    }

    uint8_t chunk[VNC_AUDIO_CAPTURE_CHUNK];
    while (!cap->stop) {
        if (pa_simple_read(pa, chunk, sizeof(chunk), &pa_err) < 0) {
            fprintf(stderr, "[VNC AUDIO] Capture read failed: %s\n", pa_strerror(pa_err));
            break;
        }

        pthread_mutex_lock(&cap->mutex);
        size_t space = VNC_AUDIO_RING_CAP - cap->ring_len;
        size_t take = sizeof(chunk) < space ? sizeof(chunk) : space;
        if (take > 0) {
            memcpy(cap->ring + cap->ring_len, chunk, take);
            cap->ring_len += take;
        }
        // If the poll loop can't drain fast enough the buffer just fills up and
        // we start dropping newly-captured samples (backpressure) rather than
        // growing without bound or blocking the capture thread indefinitely.
        pthread_mutex_unlock(&cap->mutex);
    }

    pa_simple_free(pa);
    return NULL;
}

vnc_audio_capture_t* vnc_audio_capture_start(uint8_t wire_fmt, int channels, int freq) {
    vnc_audio_capture_t* cap = (vnc_audio_capture_t*)calloc(1, sizeof(*cap));
    if (!cap) return NULL;

    cap->ring = (uint8_t*)malloc(VNC_AUDIO_RING_CAP);
    if (!cap->ring) {
        free(cap);
        return NULL;
    }

    pthread_mutex_init(&cap->mutex, NULL);
    cap->spec.format = vnc_audio_pa_format(wire_fmt);
    cap->spec.channels = (uint8_t)((channels == 1 || channels == 2) ? channels : 2);
    cap->spec.rate = (uint32_t)(freq > 0 ? freq : 44100);
    cap->stop = 0;
    cap->ring_len = 0;

    if (pthread_create(&cap->thread, NULL, vnc_audio_capture_thread_main, cap) != 0) {
        pthread_mutex_destroy(&cap->mutex);
        free(cap->ring);
        free(cap);
        return NULL;
    }

    return cap;
}

void vnc_audio_capture_stop(vnc_audio_capture_t* cap) {
    if (!cap) return;
    cap->stop = 1;
    pthread_join(cap->thread, NULL);
    pthread_mutex_destroy(&cap->mutex);
    free(cap->ring);
    free(cap);
}

size_t vnc_audio_capture_drain(vnc_audio_capture_t* cap, uint8_t* out, size_t max_len) {
    if (!cap) return 0;

    pthread_mutex_lock(&cap->mutex);
    size_t take = cap->ring_len < max_len ? cap->ring_len : max_len;
    if (take > 0) {
        memcpy(out, cap->ring, take);
        memmove(cap->ring, cap->ring + take, cap->ring_len - take);
        cap->ring_len -= take;
    }
    pthread_mutex_unlock(&cap->mutex);

    return take;
}
