# Live Desktop Resize (ExtendedDesktopSize / SetDesktopSize)

This document describes support for the standard RFB **"remote resizing"** extension —
the same feature TigerVNC and other VNC implementations expose under that name — which
lets a connected client ask the server to change the *actual* remote desktop resolution,
not just how a video stream happens to be encoded. In this implementation, resizing the
`vncviewer` window (e.g. dragging a corner) resizes the real X11 session on the server
via XRandR — every application on that display sees the new resolution, and every other
connected VNC client sees the same resized desktop.

This is not a custom protocol invention: the wire format below is implemented exactly as
specified by the community RFB protocol extensions (verified against the reference
[LibVNCServer](https://github.com/LibVNC/libvncserver) implementation), so it is, in
principle, compatible with any conforming third-party VNC client or server — this
project just also happens to be the first to *drive* it end-to-end (XRandR on the server,
window-resize detection on the client).

## 1. Encoding negotiation

- **ExtendedDesktopSize pseudo-encoding ID: `-308`**

A client advertises support by including `-308` in `SetEncodings`. The server then sends
an `ExtendedDesktopSize` rectangle (see §3) announcing the current framebuffer size and
telling the client it may now send `SetDesktopSize` requests. `vncviewer` always
advertises this — it's independent of which pixel/video encoding is in use.

## 2. SetDesktopSize (client → server message, type `251`)

Sent by the client whenever it wants to request a specific desktop resolution (in this
implementation: whenever its window settles at a new size after being resized by the
user — see §5).

| Field | Size | Description |
|---|---|---|
| `type` | 1 byte | `251` |
| `pad1` | 1 byte | unused |
| `width` | 2 bytes (`uint16_t`, BE) | requested framebuffer width |
| `height` | 2 bytes (`uint16_t`, BE) | requested framebuffer height |
| `number-of-screens` | 1 byte | number of screen entries that follow |
| `pad2` | 1 byte | unused |

Followed by `number-of-screens` screen entries (16 bytes each):

| Field | Size | Description |
|---|---|---|
| `id` | 4 bytes (`uint32_t`, BE) | screen identifier |
| `x-position` | 2 bytes (`uint16_t`, BE) | screen's x offset |
| `y-position` | 2 bytes (`uint16_t`, BE) | screen's y offset |
| `width` | 2 bytes (`uint16_t`, BE) | screen width |
| `height` | 2 bytes (`uint16_t`, BE) | screen height |
| `flags` | 4 bytes (`uint32_t`, BE) | screen flags |

`vncviewer` always sends exactly one screen (`id=0`, `x=0`, `y=0`, matching the requested
width/height, `flags=0`) since this server only ever exposes a single display — the
multi-screen layout list exists in the spec for multi-monitor VNC setups, which this
implementation doesn't attempt to model.

## 3. ExtendedDesktopSize (server → client rectangle, encoding `-308`)

Sent by the server: once, right after a client's first `SetEncodings` advertises support
(announcing the current size); and every time either the desktop is resized or a
`SetDesktopSize` request is rejected.

The standard 12-byte `FramebufferUpdate` rectangle header is reused with different field
meanings for this encoding:

| Rect header field | Meaning |
|---|---|
| `x-position` | **reason**: `0` = spontaneous/initial announcement, `1` = this client's own request, `2` = a different client's request |
| `y-position` | **status**: `0` = success, `1` = resize prohibited, `2` = out of resources, `3` = invalid screen layout |
| `width` / `height` | the framebuffer size this rectangle describes |
| `encoding-type` | `-308` |

Rectangle payload:

| Field | Size | Description |
|---|---|---|
| `number-of-screens` | 1 byte | |
| padding | 3 bytes | |

Followed by `number-of-screens` screen entries, same 16-byte layout as §2.

Per spec, the server sends this rectangle to the *requesting* client for every
`SetDesktopSize` it receives (success or failure), and — only on success — also sends it
(with reason `2`) to every *other* connected client that has advertised support, since the
desktop resize affects the shared session, not just the requester.

## 4. Server-side: what actually resizes the desktop

`vnc_server_config_t.allow_desktop_resize` (see `include/leanrfb.h`) gates the feature
entirely — it defaults to **off**, since enabling it lets any connecting client change
the host's real screen resolution. When on, an application-supplied
`on_resize_request` callback is invoked for each `SetDesktopSize`:

```c
typedef int (*vnc_resize_request_cb)(vnc_server_t* server, vnc_client_t* client,
                                     uint16_t req_width, uint16_t req_height,
                                     uint16_t* out_width, uint16_t* out_height,
                                     void* user_data);
```

The callback attempts the real resize (in `x11_vnc_server`, via XRandR — see below),
writes back the resolution *actually* applied (which may differ from what was requested
— see §6), and returns one of `VNC_RESIZE_SUCCESS` / `VNC_RESIZE_PROHIBITED` /
`VNC_RESIZE_OUT_OF_RESOURCES` / `VNC_RESIZE_INVALID_LAYOUT` (these map 1:1 onto the wire
status codes in §3). On success, the library itself handles the bookkeeping via
`vnc_server_resize_framebuffer()`: reallocating the framebuffer and every client's dirty
tile grid (marking a full redraw), dropping each client's H.264/VP9 encoder so it's
recreated at the new size, forcing a fresh keyframe, and resetting each client's UDP video
session so it re-handshakes at the new resolution rather than risk stale state.

`x11_vnc_server`'s callback (`x11_vnc/x11_vnc_server.c`) calls `x11_set_resolution()` —
the same XRandR mode-switching helper used by the static `resize_resolution` startup
option (see the main `x11_vnc_server.conf` comments) — then reallocates its MIT-SHM
capture buffers to match. Enable it with:

```
allow_resize=y
```

Like `resize_resolution`, this only switches among modes the display driver already
advertises (it does not synthesize a custom XRandR modeline); unlike that option, it
picks the *closest* available mode rather than requiring an exact match, since a live
window resize can ask for an arbitrary pixel size that no fixed mode list will contain
exactly.

## 5. Client-side: detecting a local resize

`vncviewer` connects to the drawing area's `configure-event` (fired whenever its
allocated size changes, including window resizes) and debounces: each event resets a
400ms timer, so a `SetDesktopSize` request is only sent once the size has stopped
changing for that long — dragging a window edge fires many events per second, and
resizing the real X display on every one of them would be very disruptive.

To avoid a feedback loop — the server's own confirmation causes the client to resize its
window, which itself fires another `configure-event` — the handler only acts when the
new size differs from what the client currently believes the desktop size is
(`screen_w`/`screen_h`, which are updated *before* the window is resized in response to a
server confirmation). This makes the guard a simple equality check rather than something
timing-dependent.

## 6. Why the applied size can differ from the request

Both `resize_resolution` (startup) and live client-driven resizing only select from
modes the X driver already advertises. A window being dragged pixel-by-pixel will very
rarely land exactly on one of those; `x11_set_resolution()` therefore picks the closest
available mode (smallest combined width+height difference) rather than failing. The
server reports back whatever size it actually applied (`out_width`/`out_height` from the
callback), and the client resizes its own window to match that confirmed size — so the
two stay in sync even though neither necessarily matches the client's original, arbitrary
request.

## 7. Threat model / operational notes

- Disabled by default (`allow_resize=n`) — this is the master switch; even a client that
  advertises and sends `SetDesktopSize` gets an automatic `VNC_RESIZE_PROHIBITED` unless
  an operator has explicitly turned it on.
- A resize affects every connected client's session simultaneously — there is one shared
  desktop, not a per-client virtual one. This is inherent to sharing a real X11 display
  rather than a limitation of this extension specifically.
- The XRandR mode-switching helper (`x11_set_resolution`) is scoped to single-output
  setups: it grows/shrinks the overall screen bounding box assuming there's only one
  connected display to worry about. On a real multi-monitor host this could affect other
  outputs' usable area — this is documented as an explicit scope limitation, not something
  the library guards against.
- On clean shutdown (`SIGINT`/`SIGTERM`), `x11_vnc_server` restores whatever resolution
  the display had before it made *any* change (whether from `resize_resolution` at
  startup or a live client request), so the host is never left resized after the server
  exits.
