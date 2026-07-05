# Encrypted UDP Transport for H.264 (Open UDP Video Extension)

This document specifies an optional, encrypted UDP side-channel for delivering the
[Open H.264 Encoding](rfb_h264_extension.md) video stream with lower and more consistent
latency than TCP — the goal is smooth, responsive, gaming-like interactive performance.
It is a companion extension to encoding `50` and does not change how H.264 itself is
encoded; it only changes how the encoded bytes get from server to client.

TCP forces every frame update to wait for retransmission of any earlier lost segment
before later data can be processed ("head-of-line blocking"), which under real-world
packet loss produces exactly the kind of latency spikes and stutter that make remote
desktops feel unresponsive for fast-moving content. UDP has no such ordering guarantee,
so a single lost datagram only costs one video frame, not a multi-second stall — at the
price of the transport no longer being reliable, ordered, or (on its own) authenticated.
The rest of this document is about how those properties are restored where they matter
(authenticity, integrity, confidentiality, replay protection) without reintroducing
head-of-line blocking.

## 1. Design summary

- The existing TCP RFB connection remains the control channel for the entire session:
  handshake, authentication, input events, clipboard, and (as a fallback) H.264 video
  itself all continue to work exactly as before. UDP is strictly additive.
- Once negotiated, the server hands the client a fresh, random, single-use AES-256-GCM
  key and connection id over the *already-authenticated* TCP connection. Every UDP
  datagram is authenticated-encrypted with that key, so an attacker who does not have
  the key cannot inject, replay, or read frames, even though UDP itself has no
  connection state.
- Each encoded H.264 frame is fragmented into small datagrams and reassembled by the
  client. If any fragment is lost, at worst one video frame is skipped — the decoder
  self-heals via the encoder's existing periodic keyframes, and the client can also
  proactively request an immediate keyframe when it detects loss.
- If the client's network can't do UDP at all (symmetric NAT that never opens, UDP
  blocked by a firewall, etc.), the server automatically continues delivering H.264 over
  TCP for that client, exactly as it did before this extension existed. UDP is only ever
  used once the transport has actually proven itself live.

## 2. Negotiation

A new pseudo-encoding is introduced:

- **UDP Transport Setup encoding ID: `51`**

A client that wants the UDP transport advertises both `50` (H.264) and `51` in its
`SetEncodings` message. If the server also supports UDP (see §7) and sees both, it will,
the first time it has H.264 data to send to that client, send a one-time **setup
message** and thereafter attempt UDP delivery for that client's video.

Advertising `51` without `50` has no effect. A server or client that does not recognize
`51` simply ignores it, per normal RFB pseudo-encoding rules — the connection continues
to work over TCP exactly as it does today.

## 3. Setup message

The setup message is carried as an ordinary `FramebufferUpdate` rectangle on the TCP
control channel (the same mechanism the H.264 extension itself uses), with:

- **X/Y position**: `0`
- **Width/Height**: framebuffer width/height (unused, present for header uniformity)
- **Encoding-type**: `51` (UDP Transport Setup)

The rectangle payload (42 bytes, no length prefix — the size is fixed) is:

| Field | Size | Description |
|---|---|---|
| `udp_port` | 2 bytes (`uint16_t`, BE) | UDP port the server is listening on |
| `cid` | 8 bytes | Random connection id for this UDP session |
| `key` | 32 bytes | Random AES-256-GCM key for this UDP session |

The server binds its UDP socket to the **same port number** as the TCP listener (UDP and
TCP occupy independent namespaces, so no additional port needs to be opened through a
firewall or NAT beyond what TCP already requires). `udp_port` is included explicitly
so operators are free to run a UDP relay/NAT mapping on a different externally-visible
port if their setup needs it.

The key and connection id are generated fresh (via a CSPRNG) for every session and are
never reused. They are transmitted once, over the TCP connection that has already
completed the RFB security handshake (VncAuth or None) — the UDP channel therefore
inherits whatever trust the TCP channel already established. If TCP itself is not
trusted, e.g. because you're relying on VncAuth for confidentiality (it does not provide
any), the UDP video content isn't either — this is no worse than the TCP-only baseline,
which sends the same H.264 bytes over a plaintext TCP socket.

## 4. Datagram wire format

Every UDP datagram (in both directions) is:

```
[type:1][cid:8][counter:8, BE][ciphertext ...][tag:16]
```

- **`type`**: `0` = VIDEO (server -> client only), `1` = HELLO (client -> server only,
  used for hole-punching and liveness). `type` is never interpreted before the datagram
  is authenticated to decide *whether* to process it (see §6) — but it doubles as the
  leading byte of the AEAD nonce, which keeps the two directions in disjoint nonce
  spaces under the shared session key (see §5).
- **`cid`**: identifies which session/client this datagram belongs to. It is not secret
  (it is analogous to a QUIC connection id) — the actual secret is the AES key, and
  authenticity comes from the GCM tag, not from `cid` being hidden.
- **`counter`**: a 64-bit, per-direction, strictly monotonically increasing sequence
  number. It forms part of the AEAD nonce and is also the anti-replay sequence number.
- **`ciphertext`**: AES-256-GCM output. The plaintext depends on `type` (§4.1/§4.2).
- **`tag`**: the 16-byte GCM authentication tag.

The nonce fed to AES-256-GCM is 12 bytes: `type (1) || cid[0..2] (3) || counter (8, BE)`.
The additional authenticated data (AAD) is the 17-byte cleartext header
(`type || cid || counter`), so those fields are tamper-evident even though they're sent
unencrypted (the receiver needs `cid` to look up the right key before it can even
attempt decryption).

Because `counter` is per-direction and always increases within one session, and `type`
is fixed per direction, and `cid` is unique per session, the same key is never used to
encrypt two different plaintexts under the same nonce — the fundamental precondition for
GCM's security.

### 4.1 VIDEO datagram plaintext (server -> client)

```
[frame_id:4][frag_idx:2][frag_count:2][flags:1][reserved:1][fragment bytes...]
```

- `frame_id`: monotonically increasing counter, one per H.264 frame sent over UDP
  (independent of the AEAD `counter`, which increases per *datagram*, i.e. per fragment).
- `frag_idx` / `frag_count`: this fragment's index and the total number of fragments the
  frame was split into (fragments are `VNC_UDP_MAX_FRAG_PAYLOAD` = 1200 bytes each except
  the last, which is at most 1200 bytes).
- `flags`: same semantics as the H.264 extension's TCP path — bit 1 (`0x02`,
  `resetAllContextsFlag`) tells the client to discard its decoder and initialize a fresh
  one; it is set on the frame that establishes (or re-establishes, after a keyframe
  request) a clean decode point.

A frame that would require more than 512 fragments (roughly 600 KB) is not sent over
UDP at all — the server falls back to TCP for that specific frame only.

### 4.2 HELLO datagram plaintext (client -> server)

Empty (zero-length plaintext; GCM supports authenticating a zero-length message). All
the information the server needs — which session this is, and a fresh replay-protected
sequence number proving this isn't a captured retransmission — is already in the
authenticated header.

## 5. Session lifecycle: hole-punching and liveness

1. On receiving the setup message, the client opens a UDP socket and immediately sends a
   HELLO datagram to `server_ip:udp_port`. This is a standard UDP hole-punch: it opens
   the outbound NAT/firewall mapping so the server's replies can reach the client.
2. The server does not send any UDP video to a client until it has received and
   authenticated at least one HELLO from it, and learns the client's UDP source
   `(address, port)` from that packet (rather than assuming the TCP peer address is
   reachable on UDP, or trusting a client-declared address) — this also means the server
   never sends unsolicited data to an address that hasn't first proven it holds the
   session key, so this extension cannot be used as a UDP reflection/amplification
   vector against a third party.
3. The client re-sends a HELLO every 2 seconds as a heartbeat, both to keep the NAT
   mapping alive and so the server can detect a client that has gone away.
4. The server tracks the last time it received a valid HELLO/heartbeat per client. If
   more than 8 seconds pass without one, it treats UDP as no longer live for that client
   and reverts to sending H.264 over TCP until a new HELLO arrives.
5. An unrecognized `cid`, or a datagram that fails authentication, is dropped silently —
   the server/client never responds to an unauthenticated datagram. This is deliberate:
   it removes any oracle an attacker could use to probe for valid sessions or keys, and
   (combined with point 2) means the UDP socket never amplifies traffic toward a spoofed
   source address.

## 6. Anti-replay

Both sides maintain a 64-entry sliding-window replay filter per receive direction,
keyed off the AEAD `counter` (the same value used in the nonce): a counter that is
higher than any seen before is always accepted (and the window slides forward); a
counter within the trailing 64 is accepted only if not already seen; anything older is
rejected. This follows the same design as IPsec/DTLS/QUIC replay windows. A captured and
re-sent datagram — whether a HELLO or a video fragment — is therefore rejected the
second time it arrives.

## 7. Fragment loss and recovery (why this doesn't just stutter differently)

Video frames are requested one at a time: the client only sends its next
`FramebufferUpdateRequest` after it finishes decoding and displaying the current frame.
If a UDP fragment for the in-flight frame is lost, that frame would otherwise never
finish reassembling, and the client would never ask for the next one, stalling the whole
stream — this extension avoids that outcome:

- The client gives up on a frame whose fragments stop arriving after ~400ms, discards
  the partial data, and asks the server for a fresh keyframe (a small control message,
  msg type `254`, `RequestKeyframe`, no payload — sent on the existing TCP connection).
  It then immediately requests the next framebuffer update itself, so the exchange keeps
  moving instead of waiting on a frame that will never complete.
- The server treats `RequestKeyframe` by forcing its encoder to emit a fresh IDR frame
  (bypassing inter-frame prediction) and marks that frame's `flags` with
  `resetAllContextsFlag`, so the client's decoder starts clean regardless of what it did
  or didn't successfully decode before.
- Independently of loss recovery, the encoder already emits a periodic keyframe (every
  2 seconds at the configured frame rate), which bounds how long any corruption from a
  lost fragment can persist even without an explicit request.
- Both endpoints size their UDP socket receive buffers generously (4 MB) to reduce the
  chance of the kernel dropping datagrams during a burst (e.g. a keyframe's worth of
  fragments arriving back-to-back) in the first place.

## 8. Server configuration

`vnc_server_config_t.disable_udp_h264` (see `include/leanrfb.h`) controls whether the
server offers this transport at all; it defaults to enabled (`0`). Set it to `1` to
force H.264 video over TCP only, e.g. on networks where UDP is blocked or filtered.

For `x11_vnc_server`, this is exposed in `x11_vnc_server.conf` as:

```
enable_udp=y   # or n to disable
```

Disabling it costs nothing for clients that don't ask for `51` in the first place, and
clients that do ask will simply keep receiving H.264 over TCP, unchanged from before this
extension existed.

## 9. Threat model summary

| Property | How it's provided |
|---|---|
| Confidentiality of video content | AES-256-GCM with a random per-session key |
| Integrity / tamper detection | GCM authentication tag over header + payload |
| Authenticity (can't be forged without the key) | GCM tag verification; unauthenticated datagrams are dropped silently |
| Replay protection | 64-entry sliding window over the AEAD counter, per direction |
| No reflection/amplification via this socket | Server never sends to an address until it authenticates a HELLO from it; never replies to invalid datagrams |
| Key distribution | Sent once, over the already-authenticated TCP control channel, never reused across sessions |
| NAT/firewall traversal | Client-initiated hole-punch (HELLO) — the server never has to be the first to send |
| Graceful degradation | Falls back to TCP automatically if UDP is blocked, not yet confirmed live, or goes stale |

Out of scope / accepted limitations: this extension does not add DoS protection beyond
what's described above (e.g. it does not rate-limit the volume of well-formed HELLO
packets a single source can send); operators on hostile networks should apply ordinary
firewall/rate-limiting controls to the UDP port, the same as they would for the TCP port.
