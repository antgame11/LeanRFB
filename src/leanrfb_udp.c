// Encrypted UDP transport for H.264 video (see docs/custom/rfb_h264_udp_extension.md).
//
// Every datagram is authenticated-encrypted with AES-256-GCM using a random
// per-connection key that is handed to the client over the already-authenticated
// TCP control channel. The wire format is:
//
//   [type:1][cid:8][counter:8 BE][ciphertext...][tag:16]
//
// `type` also selects the AEAD nonce's leading byte, which keeps the two
// directions (server->client video, client->server hello/heartbeat) in
// disjoint nonce spaces even though they share one key. `counter` is a
// per-direction, per-session monotonic value that both forms the rest of the
// nonce and doubles as an anti-replay sequence number.
#include "leanrfb_internal.h"
#include <openssl/evp.h>
#include <string.h>
#include <sys/socket.h>

// Exposed (non-static) in leanrfb.c so it can be shared with this file.
unsigned long long vnc_get_time_ms(void);

static void build_nonce(uint8_t type, const uint8_t cid[VNC_UDP_CID_LEN], uint64_t counter, uint8_t nonce[12]) {
    nonce[0] = type;
    nonce[1] = cid[0];
    nonce[2] = cid[1];
    nonce[3] = cid[2];
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }
}

int vnc_udp_seal(const uint8_t key[VNC_UDP_KEY_LEN], uint8_t type,
                 const uint8_t cid[VNC_UDP_CID_LEN], uint64_t counter,
                 const uint8_t* pt, int pt_len, uint8_t* out, int out_cap) {
    if (out_cap < VNC_UDP_HDR_LEN + pt_len + VNC_UDP_TAG_LEN) return -1;

    out[0] = type;
    memcpy(out + 1, cid, VNC_UDP_CID_LEN);
    for (int i = 0; i < 8; i++) {
        out[1 + VNC_UDP_CID_LEN + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }

    uint8_t nonce[12];
    build_nonce(type, cid, counter, nonce);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int len = 0;
    int ciphertext_len = 0;
    uint8_t* ciphertext = out + VNC_UDP_HDR_LEN;

    if (ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
    if (ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && EVP_EncryptUpdate(ctx, NULL, &len, out, VNC_UDP_HDR_LEN) != 1) ok = 0; // AAD = header
    if (ok && pt_len > 0 && EVP_EncryptUpdate(ctx, ciphertext, &len, pt, pt_len) != 1) ok = 0;
    if (ok) ciphertext_len = (pt_len > 0) ? len : 0;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) ok = 0;
    if (ok) ciphertext_len += len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VNC_UDP_TAG_LEN, ciphertext + ciphertext_len) != 1) ok = 0;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return -1;

    return VNC_UDP_HDR_LEN + ciphertext_len + VNC_UDP_TAG_LEN;
}

int vnc_udp_open(const uint8_t key[VNC_UDP_KEY_LEN], const uint8_t* in, int in_len,
                 uint8_t* out_type, uint8_t out_cid[VNC_UDP_CID_LEN], uint64_t* out_counter,
                 uint8_t* pt_out, int* pt_len_out) {
    if (in_len < VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN) return -1;

    uint8_t type = in[0];
    const uint8_t* cid = in + 1;
    uint64_t counter = 0;
    for (int i = 0; i < 8; i++) {
        counter = (counter << 8) | in[1 + VNC_UDP_CID_LEN + i];
    }

    int ciphertext_len = in_len - VNC_UDP_HDR_LEN - VNC_UDP_TAG_LEN;
    const uint8_t* ciphertext = in + VNC_UDP_HDR_LEN;
    const uint8_t* tag = in + in_len - VNC_UDP_TAG_LEN;

    uint8_t nonce[12];
    build_nonce(type, cid, counter, nonce);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int len = 0;
    int plaintext_len = 0;

    if (ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
    if (ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && EVP_DecryptUpdate(ctx, NULL, &len, in, VNC_UDP_HDR_LEN) != 1) ok = 0; // AAD = header
    if (ok && ciphertext_len > 0 && EVP_DecryptUpdate(ctx, pt_out, &len, ciphertext, ciphertext_len) != 1) ok = 0;
    if (ok) plaintext_len = (ciphertext_len > 0) ? len : 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VNC_UDP_TAG_LEN, (void*)tag) != 1) ok = 0;
    // EVP_DecryptFinal_ex returns <= 0 if the authentication tag does not match.
    if (ok && EVP_DecryptFinal_ex(ctx, pt_out + plaintext_len, &len) <= 0) ok = 0;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return -1;

    *out_type = type;
    memcpy(out_cid, cid, VNC_UDP_CID_LEN);
    *out_counter = counter;
    *pt_len_out = plaintext_len;
    return 0;
}

int vnc_udp_replay_check(vnc_udp_replay_state_t* st, uint64_t counter) {
    if (counter > st->highest) {
        uint64_t shift = counter - st->highest;
        st->bitmap = (shift >= 64) ? 0 : (st->bitmap << shift);
        st->bitmap |= 1ULL;
        st->highest = counter;
        return 1;
    }

    uint64_t diff = st->highest - counter;
    if (diff >= 64) return 0; // too old, outside the replay window
    uint64_t mask = 1ULL << diff;
    if (st->bitmap & mask) return 0; // already seen
    st->bitmap |= mask;
    return 1;
}

int vnc_udp_send_video_frame(vnc_server_t* server, vnc_client_t* client,
                             const uint8_t* data, int len, int flags) {
    if (server->udp_fd < 0 || len <= 0) return -1;

    int frag_count = (len + VNC_UDP_MAX_FRAG_PAYLOAD - 1) / VNC_UDP_MAX_FRAG_PAYLOAD;
    if (frag_count > VNC_UDP_MAX_FRAGS) return -1; // frame too large for UDP delivery; caller falls back to TCP

    uint32_t frame_id = client->udp_frame_id++;
    uint8_t plaintext[VNC_UDP_INNER_HDR_LEN + VNC_UDP_MAX_FRAG_PAYLOAD];
    uint8_t datagram[VNC_UDP_MAX_DATAGRAM];

    for (int i = 0; i < frag_count; i++) {
        int off = i * VNC_UDP_MAX_FRAG_PAYLOAD;
        int chunk = len - off;
        if (chunk > VNC_UDP_MAX_FRAG_PAYLOAD) chunk = VNC_UDP_MAX_FRAG_PAYLOAD;

        plaintext[0] = (uint8_t)(frame_id >> 24);
        plaintext[1] = (uint8_t)(frame_id >> 16);
        plaintext[2] = (uint8_t)(frame_id >> 8);
        plaintext[3] = (uint8_t)frame_id;
        plaintext[4] = (uint8_t)(i >> 8);
        plaintext[5] = (uint8_t)i;
        plaintext[6] = (uint8_t)(frag_count >> 8);
        plaintext[7] = (uint8_t)frag_count;
        plaintext[8] = (uint8_t)flags;
        plaintext[9] = 0; // reserved
        memcpy(plaintext + VNC_UDP_INNER_HDR_LEN, data + off, (size_t)chunk);

        int pt_len = VNC_UDP_INNER_HDR_LEN + chunk;
        int dlen = vnc_udp_seal(client->udp_key, VNC_UDP_TYPE_VIDEO, client->udp_cid,
                                client->udp_send_ctr++, plaintext, pt_len, datagram, sizeof(datagram));
        if (dlen < 0) continue; // should not happen; best-effort otherwise

        // Best-effort: UDP video tolerates loss, so a failed sendto() (e.g. transient
        // EAGAIN on a full socket buffer) just drops this fragment rather than the frame.
        sendto(server->udp_fd, datagram, (size_t)dlen, 0,
               (struct sockaddr*)&client->udp_addr, client->udp_addr_len);
    }

    return 0;
}

void vnc_udp_handle_incoming(vnc_server_t* server) {
    if (server->udp_fd < 0) return;

    uint8_t buf[VNC_UDP_MAX_DATAGRAM];
    uint8_t plaintext[VNC_UDP_MAX_DATAGRAM];

    // Bound the drain loop so a flood of bogus datagrams cannot monopolize vnc_server_poll().
    for (int iter = 0; iter < 256; iter++) {
        struct sockaddr_storage src_addr;
        socklen_t addr_len = sizeof(src_addr);
        ssize_t n = recvfrom(server->udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr*)&src_addr, &addr_len);
        if (n <= 0) return;

        if (n < VNC_UDP_HDR_LEN + VNC_UDP_TAG_LEN) continue;
        if (buf[0] != VNC_UDP_TYPE_HELLO) continue; // only clients send Hello/heartbeat; VIDEO is server->client only
        const uint8_t* cid = buf + 1;

        vnc_client_t* client = server->clients;
        for (; client; client = client->next) {
            if (client->supports_udp && client->udp_setup_sent &&
                memcmp(client->udp_cid, cid, VNC_UDP_CID_LEN) == 0) {
                break;
            }
        }
        if (!client) continue; // unknown session — drop silently, never respond (no reflection/amplification)

        uint8_t type = 0;
        uint8_t out_cid[VNC_UDP_CID_LEN];
        uint64_t counter = 0;
        int pt_len = 0;
        if (vnc_udp_open(client->udp_key, buf, (int)n, &type, out_cid, &counter, plaintext, &pt_len) < 0) {
            continue; // forged/corrupt/wrong-key datagram — drop silently
        }
        if (!vnc_udp_replay_check(&client->udp_recv_replay, counter)) continue;

        // Authenticated Hello/heartbeat: (re)learn the client's UDP endpoint (handles NAT
        // rebinding) and mark the transport live.
        memcpy(&client->udp_addr, &src_addr, addr_len);
        client->udp_addr_len = addr_len;
        client->udp_ready = 1;
        client->udp_last_recv_ms = vnc_get_time_ms();
    }
}
