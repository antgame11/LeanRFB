# Open VP9 Encoding VNC Extension

This document specifies the Open VP9 video compression encoding extension for the Remote Framebuffer (RFB) protocol. It is a sibling to the [Open H.264 Encoding extension](rfb_h264_extension.md) — same handshake shape, same rectangle framing, same [encrypted UDP transport](rfb_h264_udp_extension.md) — with VP9 as the video codec instead of H.264.

VP9 (via libvpx or VA-API hardware encoding) is offered as an alternative to H.264 for
operators who prefer its compression efficiency/licensing profile, or who want to compare
codecs for a given workload. Unlike H.264/H.265, NVIDIA's NVENC has no VP9 encoder, so on
NVIDIA GPUs this extension always falls back to VA-API (if available) or software
encoding — see §3.

## 1. Encoding Negotiation

During the initial connection handshake, after authentication completes, the client sends a VNC `SetEncodings` message to advertise its capabilities.

- **VP9 Encoding ID**: `52` (Open VP9 Encoding).

If both the client and the server agree on encoding `52`, the server is permitted to transmit screen frame updates encoded as VP9 video packets. A client picks *one* video codec at a time (H.264 *or* VP9) — advertising both in the same `SetEncodings` message is not meaningful with this server implementation, which prefers H.264 if both `50` and `52` are present.

## 2. FramebufferUpdate Rectangle Header

Identical in shape to the H.264 extension:

- **X-position**: `0` (typically covers full screen)
- **Y-position**: `0`
- **Width**: Framebuffer width
- **Height**: Framebuffer height
- **Encoding-type**: `52` (Open VP9)

## 3. Payload Structure

The rectangle data payload follows immediately after the 12-byte standard VNC rectangle header, and is byte-for-byte the same framing as the H.264 extension:

| Field Name | Size (Bytes) | Data Type | Description |
|---|---|---|
| `length` | 4 | `uint32_t` (Big-Endian) | The size of the raw VP9 frame payload. |
| `flags` | 4 | `uint32_t` (Big-Endian) | Flags controlling client-side decoder context (same semantics as the H.264 extension: bit `0x02` = reset all decoder contexts). |
| `payload` | `length` | `uint8_t[]` | One complete VP9 frame (keyframe or inter-frame), exactly as emitted by the encoder. |

Unlike H.264/H.265, **VP9 has no NAL-unit/Annex-B structure** — there is no start-code
scanning and nothing analogous to in-band SPS/PPS to prepend. Each `payload` is simply
one self-contained encoder output packet; the client hands it to `avcodec_send_packet()`
for the VP9 decoder as-is.

## 4. Encoder selection (server side)

`src/leanrfb_vp9.c` tries, in order:

1. **VA-API** (`vp9_vaapi`) — Intel/AMD GPU hardware encoding.
2. **Software** (`libvpx-vp9`) — CPU encoding, configured for lowest-latency operation
   (`deadline=realtime`, `cpu-used=8`, `lag-in-frames=0`, `tune-content=screen`).

There is deliberately no NVENC attempt: NVIDIA's NVENC hardware encoder does not support
VP9 encoding (only H.264/H.265/AV1 on recent GPUs), so H.264 or H.265 remain the right
choice for lowest-latency NVIDIA GPU encoding today.

## 5. Decoder selection (client side)

`vncview` uses libavcodec's native `vp9` decoder, with the same VA-API/CUDA hardware
decode acceleration attempt used for H.264 (VP9 hardware *decode* is broadly supported,
including by NVDEC, even though NVENC can't *encode* it).

## 6. Relationship to the UDP transport

VP9 video can be delivered over the same [encrypted UDP transport](rfb_h264_udp_extension.md)
as H.264: a client advertising both `52` and `51` (`VNC_ENCODING_UDP_SETUP`) gets the same
AES-256-GCM-secured, fragmented, self-healing delivery described in that document. The
one-time UDP setup payload carries an extra **codec byte** (`0` = H.264, `1` = VP9) so the
client knows which decoder to instantiate regardless of which transport actually delivers
the bytes — see that document's §3 for the updated payload layout.
