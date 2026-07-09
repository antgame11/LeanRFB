#define _GNU_SOURCE
#include "leanrfb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>
#include <spa/param/video/raw-utils.h>

#define BTN_LEFT   0x110
#define BTN_RIGHT  0x111
#define BTN_MIDDLE 0x112

typedef struct {
    GMainLoop *loop;
    guint32 response;
    GVariant *results;
} PortalResponseData;

typedef struct {
    GDBusConnection *conn;
    char *sc_session_handle;
    char *rd_session_handle;
    uint32_t stream_node_id;
    int pw_fd;
    
    // VNC Server
    vnc_server_t *vnc_server;
    uint32_t *fb;
    int width;
    int height;
    pthread_mutex_t fb_mutex;
    uint8_t last_buttons;
    
    // PipeWire
    struct pw_main_loop *pw_loop;
    struct pw_stream *pw_stream;
    struct spa_hook pw_stream_listener;
    int negotiated;
    enum spa_video_format video_format;
} ServerData;

static void on_portal_response(GDBusConnection *conn, const gchar *sender, const gchar *path,
                               const gchar *interface, const gchar *member, GVariant *parameters,
                               gpointer user_data) {
    (void)conn; (void)sender; (void)path; (void)interface; (void)member;
    PortalResponseData *data = (PortalResponseData *)user_data;
    g_variant_get(parameters, "(u@a{sv})", &data->response, &data->results);
    if (data->results) {
        g_variant_ref(data->results);
    }
    g_main_loop_quit(data->loop);
}

static char *call_portal_method(GDBusConnection *conn, const char *interface, const char *method, GVariant *parameters, GVariant **results_out) {
    GError *error = NULL;
    GVariant *res = g_dbus_connection_call_sync(conn,
                                                "org.freedesktop.portal.Desktop",
                                                "/org/freedesktop/portal/desktop",
                                                interface,
                                                method,
                                                parameters,
                                                G_VARIANT_TYPE("(o)"),
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1, NULL, &error);
    if (!res) {
        fprintf(stderr, "[WAYLAND SERVER] Portal call %s.%s failed: %s\n", interface, method, error->message);
        g_error_free(error);
        return NULL;
    }
    const char *req_path;
    g_variant_get(res, "(o)", &req_path);
    
    PortalResponseData data = {0};
    data.loop = g_main_loop_new(NULL, FALSE);
    
    guint sub_id = g_dbus_connection_signal_subscribe(conn,
                                                      "org.freedesktop.portal.Desktop",
                                                      "org.freedesktop.portal.Request",
                                                      "Response",
                                                      req_path,
                                                      NULL,
                                                      G_DBUS_SIGNAL_FLAGS_NONE,
                                                      on_portal_response,
                                                      &data,
                                                      NULL);
                                                      
    g_main_loop_run(data.loop);
    g_main_loop_unref(data.loop);
    g_dbus_connection_signal_unsubscribe(conn, sub_id);
    g_variant_unref(res);
    
    if (data.response != 0) {
        fprintf(stderr, "[WAYLAND SERVER] Portal request %s.%s cancelled or failed (response code %d)\n", interface, method, data.response);
        if (data.results) g_variant_unref(data.results);
        return NULL;
    }
    
    char *session_handle = NULL;
    if (results_out) {
        *results_out = data.results;
    } else {
        if (data.results) {
            g_variant_lookup(data.results, "session_handle", "s", &session_handle);
            g_variant_unref(data.results);
        }
    }
    
    return session_handle;
}

static void send_portal_key(GDBusConnection *conn, const char *session_handle, uint32_t keysym, uint32_t state) {
    GError *error = NULL;
    GVariantBuilder options_builder;
    g_variant_builder_init(&options_builder, G_VARIANT_TYPE("a{sv}"));
    GVariant *options = g_variant_builder_end(&options_builder);
    
    GVariant *res = g_dbus_connection_call_sync(conn,
                                                "org.freedesktop.portal.Desktop",
                                                "/org/freedesktop/portal/desktop",
                                                "org.freedesktop.portal.RemoteDesktop",
                                                "NotifyKeyboardKeysym",
                                                g_variant_new("(o@a{sv}uu)", session_handle, options, (guint32)keysym, (guint32)state),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1, NULL, &error);
    if (!res) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to inject key event: %s\n", error->message);
        g_error_free(error);
    } else {
        g_variant_unref(res);
    }
}

static void send_portal_pointer_motion(GDBusConnection *conn, const char *session_handle, uint32_t stream_node_id, double x, double y) {
    GError *error = NULL;
    GVariantBuilder options_builder;
    g_variant_builder_init(&options_builder, G_VARIANT_TYPE("a{sv}"));
    GVariant *options = g_variant_builder_end(&options_builder);
    
    GVariant *res = g_dbus_connection_call_sync(conn,
                                                "org.freedesktop.portal.Desktop",
                                                "/org/freedesktop/portal/desktop",
                                                "org.freedesktop.portal.RemoteDesktop",
                                                "NotifyPointerMotionAbsolute",
                                                g_variant_new("(o@a{sv}udd)", session_handle, options, (guint32)stream_node_id, x, y),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1, NULL, &error);
    if (!res) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to inject pointer motion: %s\n", error->message);
        g_error_free(error);
    } else {
        g_variant_unref(res);
    }
}

static void send_portal_pointer_button(GDBusConnection *conn, const char *session_handle, int32_t button, uint32_t state) {
    GError *error = NULL;
    GVariantBuilder options_builder;
    g_variant_builder_init(&options_builder, G_VARIANT_TYPE("a{sv}"));
    GVariant *options = g_variant_builder_end(&options_builder);
    
    GVariant *res = g_dbus_connection_call_sync(conn,
                                                "org.freedesktop.portal.Desktop",
                                                "/org/freedesktop/portal/desktop",
                                                "org.freedesktop.portal.RemoteDesktop",
                                                "NotifyPointerButton",
                                                g_variant_new("(o@a{sv}iu)", session_handle, options, (gint32)button, (guint32)state),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1, NULL, &error);
    if (!res) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to inject pointer button: %s\n", error->message);
        g_error_free(error);
    } else {
        g_variant_unref(res);
    }
}

static void send_portal_pointer_axis_discrete(GDBusConnection *conn, const char *session_handle, uint32_t axis, int32_t steps) {
    GError *error = NULL;
    GVariantBuilder options_builder;
    g_variant_builder_init(&options_builder, G_VARIANT_TYPE("a{sv}"));
    GVariant *options = g_variant_builder_end(&options_builder);
    
    GVariant *res = g_dbus_connection_call_sync(conn,
                                                "org.freedesktop.portal.Desktop",
                                                "/org/freedesktop/portal/desktop",
                                                "org.freedesktop.portal.RemoteDesktop",
                                                "NotifyPointerAxisDiscrete",
                                                g_variant_new("(o@a{sv}ui)", session_handle, options, (guint32)axis, (gint32)steps),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1, NULL, &error);
    if (!res) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to inject pointer axis: %s\n", error->message);
        g_error_free(error);
    } else {
        g_variant_unref(res);
    }
}

static void on_process(void *userdata) {
    ServerData *data = (ServerData *)userdata;
    struct pw_buffer *b;
    struct spa_buffer *buf;
    
    if ((b = pw_stream_dequeue_buffer(data->pw_stream)) == NULL) {
        return;
    }
    
    buf = b->buffer;
    if (buf->datas[0].data == NULL) {
        pw_stream_queue_buffer(data->pw_stream, b);
        return;
    }
    
    pthread_mutex_lock(&data->fb_mutex);
    if (data->fb) {
        uint8_t *src = buf->datas[0].data;
        uint8_t *dst = (uint8_t *)data->fb;
        int src_stride = buf->datas[0].chunk->stride;
        int dst_stride = data->width * 4;
        
        if (data->video_format == SPA_VIDEO_FORMAT_BGRx || data->video_format == SPA_VIDEO_FORMAT_BGRA) {
            int copy_w = data->width * 4;
            for (int y = 0; y < data->height; y++) {
                memcpy(dst + y * dst_stride, src + y * src_stride, copy_w);
            }
        } else if (data->video_format == SPA_VIDEO_FORMAT_RGBx || data->video_format == SPA_VIDEO_FORMAT_RGBA) {
            for (int y = 0; y < data->height; y++) {
                uint32_t *src_row = (uint32_t *)(src + y * src_stride);
                uint32_t *dst_row = (uint32_t *)(dst + y * dst_stride);
                for (int x = 0; x < data->width; x++) {
                    uint32_t pixel = src_row[x];
                    // Swap R and B
                    dst_row[x] = ((pixel & 0xFF) << 16) | (pixel & 0xFF00) | ((pixel & 0xFF0000) >> 16);
                }
            }
        }
    }
    pthread_mutex_unlock(&data->fb_mutex);
    
    pw_stream_queue_buffer(data->pw_stream, b);
}

static void on_param_changed(void *userdata, uint32_t id, const struct spa_pod *param) {
    ServerData *data = (ServerData *)userdata;
    if (id != SPA_PARAM_Format || param == NULL) return;
    
    struct spa_video_info_raw raw_info;
    if (spa_format_video_raw_parse(param, &raw_info) < 0) return;
    
    data->width = raw_info.size.width;
    data->height = raw_info.size.height;
    data->video_format = raw_info.format;
    data->negotiated = 1;
    
    printf("[WAYLAND SERVER] Negotiated video size: %dx%d, format: %d\n", data->width, data->height, (int)data->video_format);
}

static const struct pw_stream_events stream_events = {
    PW_VERSION_STREAM_EVENTS,
    .process = on_process,
    .param_changed = on_param_changed,
};

static void *run_pw_loop(void *userdata) {
    struct pw_main_loop *loop = (struct pw_main_loop *)userdata;
    pw_main_loop_run(loop);
    return NULL;
}

static void on_key(vnc_server_t* server, vnc_client_t* client, uint32_t keysym, int down, void* user_data) {
    (void)server; (void)client;
    ServerData *data = (ServerData *)user_data;
    send_portal_key(data->conn, data->rd_session_handle, keysym, down ? 1 : 0);
}

static void on_pointer(vnc_server_t* server, vnc_client_t* client, uint16_t x, uint16_t y, uint8_t button_mask, void* user_data) {
    (void)server; (void)client;
    ServerData *data = (ServerData *)user_data;
    
    send_portal_pointer_motion(data->conn, data->rd_session_handle, data->stream_node_id, (double)x, (double)y);
    
    int diff = button_mask ^ data->last_buttons;
    if (diff) {
        if (diff & 1) {
            send_portal_pointer_button(data->conn, data->rd_session_handle, BTN_LEFT, (button_mask & 1) ? 1 : 0);
        }
        if (diff & 2) {
            send_portal_pointer_button(data->conn, data->rd_session_handle, BTN_MIDDLE, (button_mask & 2) ? 1 : 0);
        }
        if (diff & 4) {
            send_portal_pointer_button(data->conn, data->rd_session_handle, BTN_RIGHT, (button_mask & 4) ? 1 : 0);
        }
        
        // Vertical wheel
        if ((diff & 8) && (button_mask & 8)) {
            send_portal_pointer_axis_discrete(data->conn, data->rd_session_handle, 0, -1);
        }
        if ((diff & 16) && (button_mask & 16)) {
            send_portal_pointer_axis_discrete(data->conn, data->rd_session_handle, 0, 1);
        }
        
        // Horizontal wheel
        if ((diff & 32) && (button_mask & 32)) {
            send_portal_pointer_axis_discrete(data->conn, data->rd_session_handle, 1, -1);
        }
        if ((diff & 64) && (button_mask & 64)) {
            send_portal_pointer_axis_discrete(data->conn, data->rd_session_handle, 1, 1);
        }
        
        data->last_buttons = button_mask;
    }
}

int main(int argc, char *argv[]) {
    int port = 5900;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("[WAYLAND SERVER] Starting VNC Wayland Portal Server...\n");
    
    ServerData data = {0};
    pthread_mutex_init(&data.fb_mutex, NULL);
    
    // 1. D-Bus session setup
    GError *error = NULL;
    data.conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!data.conn) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to connect to session bus: %s\n", error->message);
        g_error_free(error);
        return 1;
    }
    
    // 2. ScreenCast CreateSession
    GVariantBuilder opt_builder;
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opt_builder, "{sv}", "session_handle_token", g_variant_new_string("sc_session"));
    g_variant_builder_add(&opt_builder, "{sv}", "handle_token", g_variant_new_string("sc_create_req"));
    data.sc_session_handle = call_portal_method(data.conn, "org.freedesktop.portal.ScreenCast", "CreateSession",
                                                g_variant_new("(@a{sv})", g_variant_builder_end(&opt_builder)), NULL);
    if (!data.sc_session_handle) {
        return 1;
    }
    printf("[WAYLAND SERVER] ScreenCast session handle: %s\n", data.sc_session_handle);
    
    // 3. ScreenCast SelectSources
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opt_builder, "{sv}", "types", g_variant_new_uint32(1)); // Monitor
    g_variant_builder_add(&opt_builder, "{sv}", "multiple", g_variant_new_boolean(FALSE));
    g_variant_builder_add(&opt_builder, "{sv}", "handle_token", g_variant_new_string("sc_select_req"));
    if (!call_portal_method(data.conn, "org.freedesktop.portal.ScreenCast", "SelectSources",
                             g_variant_new("(o@a{sv})", data.sc_session_handle, g_variant_builder_end(&opt_builder)), NULL)) {
        return 1;
    }
    
    // 4. RemoteDesktop CreateSession
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opt_builder, "{sv}", "session_handle_token", g_variant_new_string("rd_session"));
    g_variant_builder_add(&opt_builder, "{sv}", "handle_token", g_variant_new_string("rd_create_req"));
    data.rd_session_handle = call_portal_method(data.conn, "org.freedesktop.portal.RemoteDesktop", "CreateSession",
                                                g_variant_new("(@a{sv})", g_variant_builder_end(&opt_builder)), NULL);
    if (!data.rd_session_handle) {
        return 1;
    }
    printf("[WAYLAND SERVER] RemoteDesktop session handle: %s\n", data.rd_session_handle);
    
    // 5. RemoteDesktop SelectDevices
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opt_builder, "{sv}", "types", g_variant_new_uint32(3)); // Keyboard & Pointer
    g_variant_builder_add(&opt_builder, "{sv}", "handle_token", g_variant_new_string("rd_select_req"));
    if (!call_portal_method(data.conn, "org.freedesktop.portal.RemoteDesktop", "SelectDevices",
                             g_variant_new("(o@a{sv})", data.rd_session_handle, g_variant_builder_end(&opt_builder)), NULL)) {
        return 1;
    }
    
    // 6. RemoteDesktop Start (Linked with ScreenCast session)
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opt_builder, "{sv}", "remote_desktop_session", g_variant_new_string(data.sc_session_handle));
    g_variant_builder_add(&opt_builder, "{sv}", "handle_token", g_variant_new_string("rd_start_req"));
    GVariant *start_results = NULL;
    call_portal_method(data.conn, "org.freedesktop.portal.RemoteDesktop", "Start",
                       g_variant_new("(os@a{sv})", data.rd_session_handle, "", g_variant_builder_end(&opt_builder)), &start_results);
    if (!start_results) {
        return 1;
    }
    
    // Get streams info
    GVariant *streams = g_variant_lookup_value(start_results, "streams", G_VARIANT_TYPE("a(ua{sv})"));
    if (!streams) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to find streams in Start response\n");
        g_variant_unref(start_results);
        return 1;
    }
    
    GVariantIter iter;
    g_variant_iter_init(&iter, streams);
    GVariant *stream_val;
    if (g_variant_iter_next(&iter, "@(ua{sv})", &stream_val)) {
        g_variant_get(stream_val, "(u@a{sv})", &data.stream_node_id, NULL);
        g_variant_unref(stream_val);
    }
    g_variant_unref(streams);
    g_variant_unref(start_results);
    
    printf("[WAYLAND SERVER] ScreenCast stream PipeWire Node ID: %u\n", data.stream_node_id);
    
    // 7. ScreenCast OpenPipeWireRemote to get FD
    g_variant_builder_init(&opt_builder, G_VARIANT_TYPE("a{sv}"));
    GUnixFDList *out_fd_list = NULL;
    GVariant *pw_res = g_dbus_connection_call_with_unix_fd_list_sync(data.conn,
                                                                    "org.freedesktop.portal.Desktop",
                                                                    "/org/freedesktop/portal/desktop",
                                                                    "org.freedesktop.portal.ScreenCast",
                                                                    "OpenPipeWireRemote",
                                                                    g_variant_new("(o@a{sv})", data.sc_session_handle, g_variant_builder_end(&opt_builder)),
                                                                    G_VARIANT_TYPE("(h)"),
                                                                    G_DBUS_CALL_FLAGS_NONE,
                                                                    -1, NULL, &out_fd_list, NULL, &error);
    if (!pw_res) {
        fprintf(stderr, "[WAYLAND SERVER] OpenPipeWireRemote failed: %s\n", error->message);
        g_error_free(error);
        return 1;
    }
    gint32 fd_idx;
    g_variant_get(pw_res, "(h)", &fd_idx);
    data.pw_fd = g_unix_fd_list_get(out_fd_list, fd_idx, NULL);
    g_object_unref(out_fd_list);
    g_variant_unref(pw_res);
    
    printf("[WAYLAND SERVER] PipeWire remote FD: %d\n", data.pw_fd);
    
    // 8. Initialize PipeWire
    pw_init(NULL, NULL);
    data.pw_loop = pw_main_loop_new(NULL);
    struct pw_context *context = pw_context_new(pw_main_loop_get_loop(data.pw_loop), NULL, 0);
    struct pw_core *core = pw_context_connect_fd(context, data.pw_fd, NULL, 0);
    if (!core) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to connect to PipeWire using FD\n");
        return 1;
    }
    
    // 9. Create PipeWire stream
    struct pw_properties *props = pw_properties_new(PW_KEY_MEDIA_TYPE, "Video",
                                                    PW_KEY_MEDIA_CATEGORY, "Capture",
                                                    PW_KEY_MEDIA_ROLE, "Screen", NULL);
    data.pw_stream = pw_stream_new(core, "leanrfb-capture", props);
    pw_stream_add_listener(data.pw_stream, &data.pw_stream_listener, &stream_events, &data);
    
    uint8_t format_buffer[1024];
    struct spa_pod_builder b = SPA_POD_BUILDER_INIT(format_buffer, sizeof(format_buffer));
    const struct spa_pod *params[1];
    params[0] = spa_pod_builder_add_object(&b,
        SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
        SPA_FORMAT_mediaType,      SPA_POD_Id(SPA_MEDIA_TYPE_video),
        SPA_FORMAT_mediaSubtype,   SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        SPA_FORMAT_VIDEO_format,   SPA_POD_CHOICE_ENUM_Id(4,
                                       SPA_VIDEO_FORMAT_BGRx,
                                       SPA_VIDEO_FORMAT_BGRA,
                                       SPA_VIDEO_FORMAT_RGBx,
                                       SPA_VIDEO_FORMAT_RGBA));
                                       
    if (pw_stream_connect(data.pw_stream,
                          PW_DIRECTION_INPUT,
                          data.stream_node_id,
                          PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                          params, 1) < 0) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to connect PipeWire stream\n");
        return 1;
    }
    
    // Start PipeWire thread
    pthread_t pw_thread;
    pthread_create(&pw_thread, NULL, run_pw_loop, data.pw_loop);
    
    // Wait for resolution negotiation
    printf("[WAYLAND SERVER] Waiting for PipeWire format negotiation...\n");
    while (!data.negotiated) {
        usleep(10000);
    }
    
    // Allocate framebuffer
    data.fb = malloc(data.width * data.height * sizeof(uint32_t));
    memset(data.fb, 0, data.width * data.height * sizeof(uint32_t));
    
    // 10. Start VNC Server
    vnc_server_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = port;
    config.name = "leanrfb Wayland Server";
    config.width = data.width;
    config.height = data.height;
    config.on_key = on_key;
    config.on_pointer = on_pointer;
    config.user_data = &data;
    
    data.vnc_server = vnc_server_create(&config);
    if (!data.vnc_server) {
        fprintf(stderr, "[WAYLAND SERVER] Failed to create VNC server\n");
        return 1;
    }
    
    printf("[WAYLAND SERVER] VNC server active on port %d. Connect using a VNC viewer.\n", port);
    
    while (1) {
        pthread_mutex_lock(&data.fb_mutex);
        vnc_server_update_framebuffer(data.vnc_server, data.fb);
        pthread_mutex_unlock(&data.fb_mutex);
        
        vnc_server_poll(data.vnc_server, 16);
    }
    
    // Clean up
    free(data.fb);
    vnc_server_destroy(data.vnc_server);
    pw_stream_destroy(data.pw_stream);
    pw_main_loop_destroy(data.pw_loop);
    g_object_unref(data.conn);
    free(data.sc_session_handle);
    free(data.rd_session_handle);
    pthread_mutex_destroy(&data.fb_mutex);
    
    return 0;
}
