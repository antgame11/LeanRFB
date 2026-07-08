# VNC Audio (QEMU-compatible extension)

This document describes support for streaming desktop audio over an existing VNC
connection, using the same non-standard-but-widely-deployed extension QEMU's own VNC
server/client implement (`ui/vnc.c`). The wire format below was verified directly against
QEMU's source, byte for byte, so it also interoperates with a real QEMU VNC client or
server — not just this project's own `vncviewer`.

Unlike QEMU (which captures its *emulated* sound card's mixer output), this server has no
guest audio to hook into — it streams whatever is actually playing on the *host's* default
audio output, captured from PulseAudio/PipeWire's monitor source (see §4).

## 1. Encoding negotiation

- **Audio pseudo-encoding ID: `-259`**

A client advertises support by including `-259` in `SetEncodings`. If the server has audio
streaming enabled (`enable_audio=y`, see §4), it acks by sending a bare `FramebufferUpdate`
rectangle with `encoding=-259`, `x=0`, `y=0`, `width`/`height` set to the current
framebuffer size, and **no rectangle payload at all** — it exists purely as a feature ack,
not to carry data. If the server doesn't have audio enabled, no ack is sent and the client
should not send audio control messages (doing so gets it disconnected — see §2).

## 2. Client → server: audio control (message type `255`)

All client-driven audio control is wrapped in QEMU's generic extension envelope:

| Field | Size | Description |
|---|---|---|
| `message-type` | 1 byte | `255` |
| `qemu-sub-type` | 1 byte | `1` = audio (this project doesn't implement sub-type `0`, QEMU's extended-key-event message, but still consumes its fixed 12-byte length so the stream stays in sync if a QEMU-aware client sends one) |
| `audio-operation` | 2 bytes (`uint16_t`, BE) | `0` = ENABLE, `1` = DISABLE, `2` = SET_FORMAT |

`SET_FORMAT` carries additional fields after the 4-byte header above:

| Field | Size | Description |
|---|---|---|
| `format` | 1 byte | `0`=U8, `1`=S8, `2`=U16, `3`=S16, `4`=U32, `5`=S32 |
| `channels` | 1 byte | `1` or `2` |
| `frequency` | 4 bytes (`uint32_t`, BE) | sample rate, Hz (capped at 48000) |

Samples are always little-endian on the wire — QEMU's own implementation hardcodes this
(`vs->as.big_endian = false`) and never exposes a way for the client to ask for
big-endian, so this server does the same. `vncviewer`/`vncview_web` always request
`S16`/2ch/44100Hz, matching QEMU's own default; PulseAudio has no native U16/U32/S8 sample
type, so if a peer requests one of those this server captures as S16LE instead rather than
failing the stream.

A client that sends any audio message without first having its `-259` `SetEncodings` entry
acked gets disconnected, same as QEMU's own server.

## 3. Server → client: audio data (message type `255`)

| Field | Size | Description |
|---|---|---|
| `message-type` | 1 byte | `255` |
| `qemu-sub-type` | 1 byte | `1` (audio) |
| `audio-operation` | 2 bytes (`uint16_t`, BE) | `0`=END, `1`=BEGIN, `2`=DATA |

`DATA` carries additional fields after the 4-byte header above:

| Field | Size | Description |
|---|---|---|
| `length` | 4 bytes (`uint32_t`, BE) | byte length of the PCM payload that follows |
| `pcm` | `length` bytes | raw interleaved PCM samples, in the format last negotiated via `SET_FORMAT` |

`BEGIN` is sent once a capture stream actually starts (i.e. right after a successful
`ENABLE`); `END` once it stops (`DISABLE`, or the client disconnects). Note this is a
capture-thread-lifecycle signal, not a guarantee that audio is *currently* playing — the
monitor source referenced in §4 keeps a stream open (and silent) whenever the underlying
sink isn't suspended, so `DATA` messages can carry silence just as validly as they carry
real audio.

## 4. Server-side: where the audio actually comes from

`vnc_server_config_t.enable_audio` (see `include/leanrfb.h`) gates the feature entirely —
it defaults to **off**, since turning it on lets any connecting client listen to whatever
is playing on the host. `x11_vnc_server.conf`'s `enable_audio=y/n` maps directly onto it.

There's no "guest sound card" analogous to QEMU's own emulated audio hardware to capture
from here — this is a real Linux desktop, so instead each audio-enabled client gets a
dedicated capture thread (`src/leanrfb_audio.c`) that opens a blocking PulseAudio
`pa_simple` recording stream against the special device name `@DEFAULT_MONITOR@`. On any
system running PulseAudio (or PipeWire's pulse-compatible layer, which is the default on
most current distros) this always resolves to *the monitor of whatever the current default
sink is* — i.e. a live mirror of the desktop's actual audio output — without needing to
know the sink's real name, be root, or load a kernel loopback module. If no PulseAudio/
PipeWire session is reachable, the capture thread logs an error and produces no data (the
client stays in the `BEGIN`-but-silent state).

The blocking `pa_simple_read()` calls run on their own thread per client (audio streaming
is opt-in per client and typically only one or zero clients use it at a time) precisely so
they can't stall the server's single-threaded, non-blocking `poll()` loop; captured bytes
land in a small mutex-protected ring buffer that the poll loop drains and forwards as
`DATA` messages every iteration, independent of the video `FramebufferUpdateRequest` cycle.

## 5. Client-side playback

- Desktop (`vncview.c`): plays back via a second PulseAudio `pa_simple` stream
  (`PA_STREAM_PLAYBACK`), fed from the same background thread that reads the VNC socket.
- Web (`vncview_web.c`): plays back via SDL2's `SDL_QueueAudio`, since the WASM build
  already links SDL2 for video rendering.

Both are opt-in via a UI toggle — audio isn't requested in `SetEncodings` at all unless the
user has asked for it, so connecting to an audio-capable server doesn't implicitly start
capturing/streaming host audio.

## 6. Threat model / operational notes

- Disabled by default (`enable_audio=n`) — the master switch; a client can advertise and
  send `ENABLE` all it wants, but gets disconnected instead of a capture stream unless an
  operator has explicitly turned this on.
- Any client that successfully enables audio hears *everything* passing through the
  host's default sink for as long as it stays enabled — this is a single shared monitor
  source, not a per-application or per-client audio scope.
- Capture format conversion is intentionally minimal (see §2) — this isn't a general
  transcoding layer, just enough to interoperate with the small set of formats QEMU's own
  wire protocol defines and PulseAudio can natively produce.
