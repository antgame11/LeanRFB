# LeanRFB

> [!WARNING]
> **AI Disclaimer**: This codebase was written entirely by artificial intelligence. Please thoroughly verify, test, and assess its suitability for production environments.

LeanRFB is a fast, lightweight, and secure VNC (RFB protocol) server library written in C99. It provides features like Hextile and Tight (JPEG) encoding, customizable event callbacks, and a robust security architecture.

## Features

- **Integrated Web & WebSocket Support**:
  - Auto-detects WebSocket (noVNC) vs. standard VNC clients on the same port with a negligible 100ms auto-negotiation window.
  - Serves the standalone HTML client (`vnc_lite_standalone.html`) directly via HTTP GET requests.
  - Native binary WebSocket frame encapsulation (supports cursor updates, JPEG, and Hextile encodings) out-of-the-box, removing the need for external tools like `websockify`.
- **High Performance**: 
  - Adaptive tile change detection with early-exit row comparison.
  - Zero-allocation network polling loops (cached pollfd context).
  - Single-flush network buffering (coalesces update headers, rectangles, and pixel data to minimize `send()` syscalls).
  - Skips server frame capturing and processing when no clients are connected.
- **Robust Security**:
  - Constant-time memory comparison for authentication challenges (mitigates timing side-channel attacks).
  - Hard failure on insecure challenge generation (requires cryptographically secure entropy from `/dev/urandom`).
  - IP brute-force rate-limiting and temporary lockout blocks.
  - Size-bounded clipboard inputs (prevents denial-of-service memory exhaustions via massive `ClientCutText` messages).
  - Strict Unix SHM permission limits (created with `0600` permissions rather than world-accessible `0777`).

## Codebase Structure

- **`src/` and `include/`**: The core library (`leanrfb`) implementation and API headers.
- **`x11_vnc/`**: The main first-class application (`x11_vnc_server`), containing its source, configuration (`x11_vnc_server.conf`), and standalone HTML client asset.
- **`examples/`**: Minimal examples using the library (e.g. `demo_server.c`).

## Build Instructions

To build the static library `libleanrfb.a`, the `demo_server` example, and the `x11_vnc_server` program, run:

```bash
make
```

To clean up intermediate object files and executables:

```bash
make clean
```

## Running the Applications

### 1. X11 VNC Server
Shares your active X11 desktop session:

```bash
./x11_vnc_server [port] [password]
```

By default, the server reads options from `x11_vnc/x11_vnc_server.conf`. You can toggle the WebSocket/HTTP server on the same port by setting `websocket=y` in the configuration. When enabled, navigating to `http://localhost:<port>/` in your web browser will serve the standalone noVNC web client, which connects back to the VNC session via WebSocket automatically.

*Note: The password string passed on the command line is immediately wiped from the process's `argv` space to prevent disclosure via local process listing utilities (like `ps`).*

### 2. Demo Server (Example)
A simple programmatic test server that creates a basic memory framebuffer:

```bash
./demo_server <port> [password]
```

## API Usage

Include the header:

```c
#include "leanrfb.h"
```

Configure and initialize the server:

```c
vnc_server_config_t config = {
    .port = 5900,
    .listen_host = "0.0.0.0",
    .name = "My Desktop",
    .width = 1920,
    .height = 1080,
    .password = "securitypasswd",
    .max_clients = 8,
    .on_key = my_key_callback,
    .on_pointer = my_pointer_callback
};

vnc_server_t* server = vnc_server_create(&config);
```

Periodically poll and feed your frame updates inside your main loop:

```c
while (running) {
    // Only capture and feed frames if we have clients
    if (vnc_server_has_clients(server)) {
        uint32_t* screen_pixels = capture_screen();
        vnc_server_update_framebuffer(server, screen_pixels);
    }
    
    // Poll VNC network events (with a 10ms timeout)
    vnc_server_poll(server, 10);
}

vnc_server_destroy(server);
```
