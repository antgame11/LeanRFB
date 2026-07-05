#include "leanrfb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#define WIDTH 800
#define HEIGHT 600

static void on_key(vnc_server_t* server, vnc_client_t* client, uint32_t keysym, int down, void* user_data) {
    (void)server;
    (void)client;
    (void)user_data;
    printf("[KEY EVENT] keysym: 0x%04X, state: %s\n", keysym, down ? "DOWN" : "UP");
}

static void on_pointer(vnc_server_t* server, vnc_client_t* client, uint16_t x, uint16_t y, uint8_t button_mask, void* user_data) {
    (void)server;
    (void)client;
    (void)user_data;
    printf("[POINTER EVENT] x: %d, y: %d, buttons: 0x%02X\n", x, y, button_mask);
}

int main(int argc, char* argv[]) {
    int port = 5900;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("Starting VNC Demo Server on port %d...\n", port);

    vnc_server_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = port;
    config.name = "leanrfb Demo Server";
    config.width = WIDTH;
    config.height = HEIGHT;
    config.on_key = on_key;
    config.on_pointer = on_pointer;

    vnc_server_t* server = vnc_server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create VNC server\n");
        return 1;
    }

    uint32_t* fb = malloc(WIDTH * HEIGHT * sizeof(uint32_t));
    if (!fb) {
        vnc_server_destroy(server);
        return 1;
    }

    printf("VNC server running. Connect with a client (e.g., vncviewer localhost:%d)\n", port);

    int frame = 0;
    int box_x = 100, box_y = 100;
    int box_dx = 4, box_dy = 3;
    const int box_size = 80;

    while (1) {
        // Draw bouncing box and background gradient
        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                // Background gradient
                uint8_t r = (uint8_t)((x * 255) / WIDTH);
                uint8_t g = (uint8_t)((y * 255) / HEIGHT);
                uint8_t b = (uint8_t)((frame * 2) & 0xFF);
                
                // BGRA format: B in low byte, G, R, X in high byte
                fb[y * WIDTH + x] = (uint32_t)b | ((uint32_t)g << 8) | ((uint32_t)r << 16);
            }
        }

        // Move bouncing box
        box_x += box_dx;
        box_y += box_dy;
        if (box_x < 0 || box_x + box_size > WIDTH) {
            box_dx = -box_dx;
            box_x += box_dx;
        }
        if (box_y < 0 || box_y + box_size > HEIGHT) {
            box_dy = -box_dy;
            box_y += box_dy;
        }

        // Draw bouncing box (solid green-yellow)
        for (int y = box_y; y < box_y + box_size; y++) {
            for (int x = box_x; x < box_x + box_size; x++) {
                if (x >= 0 && x < WIDTH && y >= 0 && y < HEIGHT) {
                    fb[y * WIDTH + x] = 0x00FFFF00; // Yellow-Green
                }
            }
        }

        // Feed to VNC server
        vnc_server_update_framebuffer(server, fb);

        // Poll for events (roughly 60fps, 16ms sleep)
        vnc_server_poll(server, 16);

        frame++;
    }

    free(fb);
    vnc_server_destroy(server);
    return 0;
}
