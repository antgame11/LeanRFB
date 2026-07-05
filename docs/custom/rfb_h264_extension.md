# Open H.264 Encoding VNC Extension

This document specifies the Open H.264 video compression encoding extension for the Remote Framebuffer (RFB) protocol.

## 1. Encoding Negotiation

During the initial connection handshake, after authentication completes, the client sends a VNC `SetEncodings` message to advertise its capabilities.

- **H.264 Encoding ID**: `50` (Open H.264 Encoding).

If both the client and the server agree on encoding `50`, the server is permitted to transmit screen frame updates encoded as H.264 video packets.

## 2. FramebufferUpdate Rectangle Header

When sending screen updates, the server sends a standard RFB `FramebufferUpdate` message containing one or more rectangles. For H.264 encoded updates:

- **X-position**: `0` (typically covers full screen)
- **Y-position**: `0`
- **Width**: Framebuffer width
- **Height**: Framebuffer height
- **Encoding-type**: `50` (Open H.264)

## 3. Payload Structure

The rectangle data payload follows immediately after the 12-byte standard VNC rectangle header:

| Field Name | Size (Bytes) | Data Type | Description |
|---|---|---|---|
| `length` | 4 | `uint32_t` (Big-Endian) | The size of the raw H.264 bitstream. |
| `flags` | 4 | `uint32_t` (Big-Endian) | Flags controlling client-side decoder context. |
| `payload` | `length` | `uint8_t[]` | Raw H.264 Annex B stream containing NAL units. |

### Decoder Flags

- **`flags = 2` (`resetAllContextsFlag`)**: Tells the client to discard all existing H.264 video decoder contexts and initialize/configure a fresh decoder. Must be sent on the very first H.264 update containing a keyframe (IDR).
- **`flags = 1` (`resetContextFlag`)**: Resets only the context for the current rectangle.
- **`flags = 0`**: Standard delta frame or keyframe with no context reset.

### H.264 Stream Format

The raw H.264 bitstream must be structured in **Annex B** format:
- Each NAL unit is preceded by a `0x00000001` or `0x000001` start code.
- Keyframes (IDR) must be prepended with SPS (Sequence Parameter Set, NAL unit type 7) and PPS (Picture Parameter Set, NAL unit type 8) NAL units to configure the client's decoder.
