/**
 * @file ssh_transport.c
 * @brief Minimal SSH-2 server transport layer: version exchange, curve25519
 *        key exchange, ecdsa-sha2-nistp256 host key, AES-GCM packet protection.
 *
 * Deliberately small: every primitive comes from mbedTLS, which the firmware
 * already links for WPA3-SAE / WPA2-Enterprise, so the SSH server costs only
 * the protocol code itself.
 */

#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "lwip/sockets.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"

#include "ssh_transport.h"
#include "router_config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static const char *TAG = "ssh";

/* Generic on purpose: don't advertise the device to scanners */
#define SSH_VERSION_STR     "SSH-2.0-SSH"
#define SSH_HOSTKEY_NVS_KEY "rc_hostkey"

#define SSH_RX_BUF_SIZE     4608    /* largest accepted packet (client KEXINIT ~2 KB) */
#define SSH_TX_BUF_SIZE     (SSH_MAX_DATA_CHUNK + 512)
#define SSH_TX_OVERHEAD     (4 + 1 + 19 + 16)   /* length, padlen, max pad, tag */
#define SSH_PACKET_TIMEOUT_US (30LL * 1000000)  /* finishing a started packet */
#define SSH_MAX_VERSION_LINES 16
#define SSH_KEXINIT_MAX     320
#define SSH_MAX_PREAUTH_REKEYS 1

/* Algorithm names */
static const char ALG_KEX[]     = "curve25519-sha256";
static const char ALG_KEX_OLD[] = "curve25519-sha256@libssh.org";
static const char ALG_STRICT_C[] = "kex-strict-c-v00@openssh.com";
static const char ALG_HOSTKEY[] = "ecdsa-sha2-nistp256";
static const char ALG_CURVE[]   = "nistp256";
static const char ALG_AES128[]  = "aes128-gcm@openssh.com";
static const char ALG_AES256[]  = "aes256-gcm@openssh.com";

static const char LIST_KEX[]     = "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com";
static const char LIST_CIPHERS[] = "aes128-gcm@openssh.com,aes256-gcm@openssh.com";
static const char LIST_MACS[]    = "hmac-sha2-256";   /* ignored with AEAD ciphers */
static const char LIST_COMP[]    = "none";

/* ---- Host key ---- */

static bool s_hk_loaded;
static uint8_t s_hk_priv[32];
static uint8_t s_hk_pub[65];     /* uncompressed point 04 || X || Y */

/* ---- Connection ---- */

typedef struct {
    mbedtls_gcm_context gcm;
    uint8_t iv[12];
    bool active;
} ssh_dir_t;

struct ssh_conn {
    int fd;
    ssh_abort_fn abort_fn;

    uint8_t *rx;
    uint8_t *tx;
    ssh_out_t out;
    uint32_t rx_seq;
    uint32_t tx_seq;
    ssh_dir_t rxd;
    ssh_dir_t txd;

    char v_c[256];               /* client version string (without CRLF) */
    uint8_t kexinit_s[SSH_KEXINIT_MAX];
    size_t kexinit_s_len;
    bool kexinit_sent;           /* our KEXINIT for the current exchange is out */
    bool strict;                 /* strict kex negotiated (Terrapin mitigation) */
    bool have_session_id;
    uint8_t session_id[32];
    bool authenticated;          /* set by the auth layer: lifts the rekey limit */
    uint8_t preauth_rekeys;
};

/* ---- Small helpers ---- */

static int ssh_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

static inline void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static inline uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void iv_increment(uint8_t iv[12])
{
    /* RFC 5647: the last 8 bytes are a big-endian invocation counter */
    for (int i = 11; i >= 4; i--) {
        if (++iv[i] != 0) break;
    }
}

/* ---- Builder / reader ---- */

uint8_t *ssh_put_reserve(ssh_out_t *o, size_t n)
{
    if (o->err || o->len + n > o->cap) {
        o->err = true;
        return NULL;
    }
    uint8_t *p = o->p + o->len;
    o->len += n;
    return p;
}

void ssh_put_u8(ssh_out_t *o, uint8_t v)
{
    uint8_t *p = ssh_put_reserve(o, 1);
    if (p) *p = v;
}

void ssh_put_u32(ssh_out_t *o, uint32_t v)
{
    uint8_t *p = ssh_put_reserve(o, 4);
    if (p) put32(p, v);
}

void ssh_put_string(ssh_out_t *o, const void *data, size_t len)
{
    uint8_t *p = ssh_put_reserve(o, 4 + len);
    if (p) {
        put32(p, (uint32_t)len);
        if (len) memcpy(p + 4, data, len);
    }
}

void ssh_put_cstr(ssh_out_t *o, const char *s)
{
    ssh_put_string(o, s, strlen(s));
}

/* mpint from an unsigned big-endian byte string */
static void put_mpint(ssh_out_t *o, const uint8_t *be, size_t len)
{
    while (len > 0 && be[0] == 0) { be++; len--; }
    bool pad = (len > 0 && (be[0] & 0x80));
    uint8_t *p = ssh_put_reserve(o, 4 + pad + len);
    if (p) {
        put32(p, (uint32_t)(len + pad));
        if (pad) p[4] = 0;
        memcpy(p + 4 + pad, be, len);
    }
}

void ssh_in_init(ssh_in_t *in, uint8_t *p, size_t len)
{
    in->p = p;
    in->len = len;
    in->pos = 0;
    in->err = false;
}

uint8_t ssh_get_u8(ssh_in_t *in)
{
    if (in->err || in->pos + 1 > in->len) { in->err = true; return 0; }
    return in->p[in->pos++];
}

uint32_t ssh_get_u32(ssh_in_t *in)
{
    if (in->err || in->pos + 4 > in->len) { in->err = true; return 0; }
    uint32_t v = get32(in->p + in->pos);
    in->pos += 4;
    return v;
}

bool ssh_get_bool(ssh_in_t *in)
{
    return ssh_get_u8(in) != 0;
}

uint8_t *ssh_get_string(ssh_in_t *in, size_t *len)
{
    uint32_t n = ssh_get_u32(in);
    if (in->err || n > in->len - in->pos) { in->err = true; *len = 0; return NULL; }
    uint8_t *p = in->p + in->pos;
    in->pos += n;
    *len = n;
    return p;
}

bool ssh_get_string_eq(ssh_in_t *in, const char *s)
{
    size_t len;
    const uint8_t *p = ssh_get_string(in, &len);
    return p && len == strlen(s) && memcmp(p, s, len) == 0;
}

/* Is `name` an element of the comma-separated name-list? */
static bool namelist_has(const uint8_t *list, size_t len, const char *name)
{
    size_t nlen = strlen(name);
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && list[j] != ',') j++;
        if (j - i == nlen && memcmp(list + i, name, nlen) == 0) return true;
        i = j + 1;
    }
    return false;
}

/* First entry of the client's list that is in `cands`; returns its index or -1.
 * *first_match tells whether it was the client's first entry (kex guess check). */
static int namelist_choose(const uint8_t *list, size_t len, const char *const *cands,
                           int ncands, bool *first_match)
{
    size_t i = 0;
    bool first = true;
    while (i < len) {
        size_t j = i;
        while (j < len && list[j] != ',') j++;
        for (int k = 0; k < ncands; k++) {
            if (j - i == strlen(cands[k]) && memcmp(list + i, cands[k], j - i) == 0) {
                if (first_match) *first_match = first;
                return k;
            }
        }
        first = false;
        i = j + 1;
    }
    return -1;
}

/* ---- Host key ---- */

/* Host key public blob: string "ecdsa-sha2-nistp256", string "nistp256", string Q */
static void put_hostkey_blob(ssh_out_t *o)
{
    ssh_put_u32(o, 4 + 19 + 4 + 8 + 4 + 65);
    ssh_put_cstr(o, ALG_HOSTKEY);
    ssh_put_cstr(o, ALG_CURVE);
    ssh_put_string(o, s_hk_pub, sizeof(s_hk_pub));
}

static int hostkey_derive_pub(uint8_t priv[32], uint8_t pub[65], bool generate)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    size_t olen = 0;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        if (generate) {
            ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, ssh_rng, NULL);
            if (ret == 0) ret = mbedtls_mpi_write_binary(&d, priv, 32);
        } else {
            ret = mbedtls_mpi_read_binary(&d, priv, 32);
            if (ret == 0) ret = mbedtls_ecp_check_privkey(&grp, &d);
            if (ret == 0) ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, ssh_rng, NULL);
        }
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, pub, 65);
        if (ret == 0 && olen != 65) ret = -1;
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

esp_err_t ssh_hostkey_init(void)
{
    if (s_hk_loaded) return ESP_OK;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    size_t len = sizeof(s_hk_priv);
    err = nvs_get_blob(nvs, SSH_HOSTKEY_NVS_KEY, s_hk_priv, &len);
    if (err == ESP_OK && len == sizeof(s_hk_priv) &&
        hostkey_derive_pub(s_hk_priv, s_hk_pub, false) == 0) {
        s_hk_loaded = true;
    } else {
        ESP_LOGI(TAG, "Generating SSH host key");
        if (hostkey_derive_pub(s_hk_priv, s_hk_pub, true) == 0 &&
            nvs_set_blob(nvs, SSH_HOSTKEY_NVS_KEY, s_hk_priv, sizeof(s_hk_priv)) == ESP_OK &&
            nvs_commit(nvs) == ESP_OK) {
            s_hk_loaded = true;
        }
    }
    nvs_close(nvs);

    if (!s_hk_loaded) {
        mbedtls_platform_zeroize(s_hk_priv, sizeof(s_hk_priv));
        ESP_LOGE(TAG, "SSH host key unavailable");
        return ESP_FAIL;
    }
    return ESP_OK;
}

void ssh_hostkey_fingerprint(char *out, size_t out_len)
{
    if (!s_hk_loaded) {
        snprintf(out, out_len, "(none)");
        return;
    }
    uint8_t blob[4 + 19 + 4 + 8 + 4 + 65 + 4];
    ssh_out_t o = { .p = blob, .len = 0, .cap = sizeof(blob) };
    put_hostkey_blob(&o);

    uint8_t hash[32];
    mbedtls_sha256(blob + 4, o.len - 4, hash, 0);

    unsigned char b64[48];
    size_t olen = 0;
    if (mbedtls_base64_encode(b64, sizeof(b64), &olen, hash, sizeof(hash)) != 0) {
        snprintf(out, out_len, "(error)");
        return;
    }
    while (olen > 0 && b64[olen - 1] == '=') olen--;   /* OpenSSH omits padding */
    b64[olen] = '\0';
    snprintf(out, out_len, "SHA256:%s", (char *)b64);
}

/* ---- Socket I/O ---- */

static int read_exact(ssh_conn_t *c, uint8_t *buf, size_t n, int64_t deadline_us)
{
    size_t got = 0;
    while (got < n) {
        if (c->abort_fn && c->abort_fn()) return SSH_ERR_ABORT;
        if (deadline_us && esp_timer_get_time() > deadline_us) return SSH_ERR_TIMEOUT;

        ssize_t r = recv(c->fd, buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return SSH_ERR_CLOSED;
        }
        if (r == 0) return SSH_ERR_CLOSED;
        got += r;
    }
    return 0;
}

static int send_all(ssh_conn_t *c, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = send(c->fd, buf, n, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            return SSH_ERR_CLOSED;
        }
        buf += r;
        n -= r;
    }
    return 0;
}

/* ---- Packet layer ---- */

ssh_out_t *ssh_out_begin(ssh_conn_t *c, uint8_t type)
{
    c->out.p = c->tx + 5;
    c->out.len = 0;
    c->out.cap = SSH_TX_BUF_SIZE - SSH_TX_OVERHEAD;
    c->out.err = false;
    ssh_put_u8(&c->out, type);
    return &c->out;
}

esp_err_t ssh_out_send(ssh_conn_t *c)
{
    if (c->out.err) {
        ESP_LOGE(TAG, "Outgoing packet too large");
        return ESP_ERR_INVALID_SIZE;
    }
    size_t plen = c->out.len;
    size_t blk = c->txd.active ? 16 : 8;
    /* With AES-GCM the 4-byte length is AAD and not part of the block alignment */
    size_t base = c->txd.active ? (1 + plen) : (4 + 1 + plen);
    size_t pad = blk - (base % blk);
    if (pad < 4) pad += blk;

    uint32_t packet_len = (uint32_t)(1 + plen + pad);
    uint8_t *t = c->tx;
    put32(t, packet_len);
    t[4] = (uint8_t)pad;
    esp_fill_random(t + 5 + plen, pad);

    size_t total = 4 + packet_len;
    if (c->txd.active) {
        if (mbedtls_gcm_crypt_and_tag(&c->txd.gcm, MBEDTLS_GCM_ENCRYPT, packet_len,
                                      c->txd.iv, 12, t, 4, t + 4, t + 4,
                                      16, t + total) != 0) {
            return ESP_FAIL;
        }
        iv_increment(c->txd.iv);
        total += 16;
    }
    c->tx_seq++;
    return send_all(c, t, total) == 0 ? ESP_OK : ESP_FAIL;
}

/* Read one packet. deadline_us = 0: wait forever for its first byte. */
static int read_packet(ssh_conn_t *c, uint8_t **payload, int64_t deadline_us)
{
    uint8_t *b = c->rx;
    int r = read_exact(c, b, 4, deadline_us);
    if (r < 0) return r;

    uint32_t plen = get32(b);
    size_t tag = c->rxd.active ? 16 : 0;
    /* Bound plen before doing arithmetic on it: size_t is 32 bits here, so
     * "plen + 4 + tag > size" wraps for plen near UINT32_MAX and let a
     * 4 GB read into the rx buffer through (pre-auth heap overflow). */
    if (plen < 8 || plen > SSH_RX_BUF_SIZE - 4 - tag) {
        ESP_LOGW(TAG, "Bad packet length %lu", (unsigned long)plen);
        return SSH_ERR_PROTO;
    }
    bool aligned = c->rxd.active ? (plen % 16 == 0) : ((plen + 4) % 8 == 0);
    if (!aligned) {
        ESP_LOGW(TAG, "Bad packet length %lu", (unsigned long)plen);
        return SSH_ERR_PROTO;
    }

    r = read_exact(c, b + 4, plen + tag, esp_timer_get_time() + SSH_PACKET_TIMEOUT_US);
    if (r < 0) return r == SSH_ERR_TIMEOUT ? SSH_ERR_CLOSED : r;

    if (c->rxd.active) {
        if (mbedtls_gcm_auth_decrypt(&c->rxd.gcm, plen, c->rxd.iv, 12, b, 4,
                                     b + 4 + plen, 16, b + 4, b + 4) != 0) {
            ESP_LOGW(TAG, "Packet authentication failed");
            return SSH_ERR_PROTO;
        }
        iv_increment(c->rxd.iv);
    }

    uint8_t padlen = b[4];
    if (padlen < 4 || (uint32_t)padlen + 2 > plen) return SSH_ERR_PROTO;
    c->rx_seq++;
    *payload = b + 5;
    return (int)(plen - padlen - 1);
}

esp_err_t ssh_send_unimplemented(ssh_conn_t *c)
{
    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_UNIMPLEMENTED);
    ssh_put_u32(o, c->rx_seq - 1);
    return ssh_out_send(c);
}

void ssh_send_disconnect(ssh_conn_t *c, uint32_t reason, const char *msg)
{
    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_DISCONNECT);
    ssh_put_u32(o, reason);
    ssh_put_cstr(o, msg);
    ssh_put_cstr(o, "");
    ssh_out_send(c);
}

/* ---- Key exchange ---- */

static void hash_string(mbedtls_sha256_context *h, const void *data, size_t len)
{
    uint8_t l[4];
    put32(l, (uint32_t)len);
    mbedtls_sha256_update(h, l, 4);
    mbedtls_sha256_update(h, data, len);
}

static esp_err_t send_kexinit(ssh_conn_t *c)
{
    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_KEXINIT);
    uint8_t *cookie = ssh_put_reserve(o, 16);
    if (cookie) esp_fill_random(cookie, 16);
    ssh_put_cstr(o, LIST_KEX);
    ssh_put_cstr(o, ALG_HOSTKEY);
    ssh_put_cstr(o, LIST_CIPHERS);
    ssh_put_cstr(o, LIST_CIPHERS);
    ssh_put_cstr(o, LIST_MACS);
    ssh_put_cstr(o, LIST_MACS);
    ssh_put_cstr(o, LIST_COMP);
    ssh_put_cstr(o, LIST_COMP);
    ssh_put_cstr(o, "");
    ssh_put_cstr(o, "");
    ssh_put_u8(o, 0);       /* first_kex_packet_follows */
    ssh_put_u32(o, 0);      /* reserved */
    if (o->err || o->len > sizeof(c->kexinit_s)) return ESP_FAIL;
    memcpy(c->kexinit_s, o->p, o->len);
    c->kexinit_s_len = o->len;
    c->kexinit_sent = true;
    return ssh_out_send(c);
}

/* Key derivation (RFC 4253 7.2): HASH(K || H || letter || session_id) */
static void derive_key(const uint8_t *k_mpint, size_t k_len, const uint8_t h[32],
                       char letter, const uint8_t sid[32], uint8_t out[32])
{
    mbedtls_sha256_context s;
    mbedtls_sha256_init(&s);
    mbedtls_sha256_starts(&s, 0);
    mbedtls_sha256_update(&s, k_mpint, k_len);
    mbedtls_sha256_update(&s, h, 32);
    mbedtls_sha256_update(&s, (const uint8_t *)&letter, 1);
    mbedtls_sha256_update(&s, sid, 32);
    mbedtls_sha256_finish(&s, out);
    mbedtls_sha256_free(&s);
}

static int set_keys(ssh_dir_t *d, const uint8_t *k_mpint, size_t k_len, const uint8_t h[32],
                    const uint8_t sid[32], char iv_letter, char key_letter, unsigned key_bits)
{
    uint8_t buf[32];
    derive_key(k_mpint, k_len, h, iv_letter, sid, buf);
    memcpy(d->iv, buf, 12);
    derive_key(k_mpint, k_len, h, key_letter, sid, buf);
    mbedtls_gcm_free(&d->gcm);
    mbedtls_gcm_init(&d->gcm);
    int ret = mbedtls_gcm_setkey(&d->gcm, MBEDTLS_CIPHER_ID_AES, buf, key_bits);
    mbedtls_platform_zeroize(buf, sizeof(buf));
    d->active = (ret == 0);
    return ret;
}

/* Wait for the next key-exchange packet of the given type. */
static int kex_wait(ssh_conn_t *c, uint8_t want, uint8_t **p, int64_t deadline, bool *skip_one)
{
    for (;;) {
        int n = read_packet(c, p, deadline);
        if (n < 0) return n;
        uint8_t type = (*p)[0];
        if (skip_one && *skip_one) {      /* wrong first_kex_packet_follows guess */
            *skip_one = false;
            continue;
        }
        if (type == want) return n;
        /* Strict kex forbids anything else during the initial exchange */
        if (!c->strict && (type == SSH_MSG_IGNORE || type == SSH_MSG_DEBUG)) continue;
        if (type == SSH_MSG_DISCONNECT) return SSH_ERR_CLOSED;
        ESP_LOGW(TAG, "Unexpected message %u during key exchange", type);
        return SSH_ERR_PROTO;
    }
}

/* Run a key exchange; `ci` / `ci_len` is the client's KEXINIT payload, which
 * lives in the rx buffer and is consumed (hashed) before anything else is read. */
static esp_err_t do_kex(ssh_conn_t *c, uint8_t *ci, size_t ci_len, int64_t deadline)
{
    static const char *const kex_algs[] = { ALG_KEX, ALG_KEX_OLD };
    static const char *const ciphers[] = { ALG_AES128, ALG_AES256 };
    const char *fail = "no matching algorithm";
    bool initial = !c->have_session_id;
    bool skip_guess = false;
    int ret = -1;

    if (!c->kexinit_sent && send_kexinit(c) != ESP_OK) return ESP_FAIL;

    /* --- Negotiate from the client's KEXINIT --- */
    ssh_in_t in;
    ssh_in_init(&in, ci, ci_len);
    ssh_get_u8(&in);
    in.pos += 16;                                  /* cookie */
    size_t l_kex, l_hk, l_ecs, l_esc, l_mcs, l_msc, l_ccs, l_csc, l1, l2;
    uint8_t *kex = ssh_get_string(&in, &l_kex);
    uint8_t *hk  = ssh_get_string(&in, &l_hk);
    uint8_t *ecs = ssh_get_string(&in, &l_ecs);
    uint8_t *esc = ssh_get_string(&in, &l_esc);
    ssh_get_string(&in, &l_mcs);
    ssh_get_string(&in, &l_msc);
    uint8_t *ccs = ssh_get_string(&in, &l_ccs);
    uint8_t *csc = ssh_get_string(&in, &l_csc);
    ssh_get_string(&in, &l1);
    ssh_get_string(&in, &l2);
    bool guess_follows = ssh_get_bool(&in);
    if (in.err) {
        ssh_send_disconnect(c, SSH_DISCONNECT_PROTOCOL_ERROR, "bad KEXINIT");
        return ESP_FAIL;
    }

    bool kex_first = false;
    int kex_idx = namelist_choose(kex, l_kex, kex_algs, 2, &kex_first);
    bool hk_first = false;
    static const char *const hk_algs[] = { ALG_HOSTKEY };
    int hk_idx = namelist_choose(hk, l_hk, hk_algs, 1, &hk_first);
    int c2s = namelist_choose(ecs, l_ecs, ciphers, 2, NULL);
    int s2c = namelist_choose(esc, l_esc, ciphers, 2, NULL);
    if (kex_idx < 0 || hk_idx < 0 || c2s < 0 || s2c < 0 ||
        !namelist_has(ccs, l_ccs, "none") || !namelist_has(csc, l_csc, "none")) {
        ESP_LOGW(TAG, "Key exchange failed: %s", fail);
        ssh_send_disconnect(c, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, fail);
        return ESP_FAIL;
    }
    if (initial) c->strict = namelist_has(kex, l_kex, ALG_STRICT_C);
    skip_guess = guess_follows && !(kex_first && hk_first);

    /* --- Exchange hash, part 1: V_C, V_S, I_C, I_S --- */
    mbedtls_sha256_context h;
    mbedtls_sha256_init(&h);
    mbedtls_sha256_starts(&h, 0);
    hash_string(&h, c->v_c, strlen(c->v_c));
    hash_string(&h, SSH_VERSION_STR, sizeof(SSH_VERSION_STR) - 1);
    hash_string(&h, ci, ci_len);
    hash_string(&h, c->kexinit_s, c->kexinit_s_len);

    /* --- Ephemeral curve25519 --- */
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z, r, s;
    mbedtls_ecp_point Q, Qc;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&z);
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&Qc);

    uint8_t q_s[32], q_c[32], k[32], hval[32], buf[32];
    uint8_t k_mpint[4 + 33];
    size_t k_mpint_len = 0;
    size_t olen;

    uint8_t *p;
    int n = kex_wait(c, SSH_MSG_KEX_ECDH_INIT, &p, deadline, &skip_guess);
    if (n < 0) goto out;
    ssh_in_init(&in, p, n);
    ssh_get_u8(&in);
    size_t qlen;
    uint8_t *qc = ssh_get_string(&in, &qlen);
    if (in.err || qlen != 32) {
        fail = "bad ECDH_INIT";
        goto out;
    }
    memcpy(q_c, qc, 32);

    fail = "key agreement failed";
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0 ||
        mbedtls_ecp_gen_keypair(&grp, &d, &Q, ssh_rng, NULL) != 0 ||
        mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, q_s, sizeof(q_s)) != 0 || olen != 32 ||
        mbedtls_ecp_point_read_binary(&grp, &Qc, q_c, 32) != 0 ||
        mbedtls_ecdh_compute_shared(&grp, &z, &Qc, &d, ssh_rng, NULL) != 0 ||
        mbedtls_mpi_write_binary_le(&z, k, 32) != 0) {
        goto out;
    }
    {
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++) acc |= k[i];
        if (acc == 0) goto out;               /* low-order point */
    }

    /* RFC 8731: the X25519 output bytes are K, read as a big-endian integer */
    {
        ssh_out_t ko = { .p = k_mpint, .len = 0, .cap = sizeof(k_mpint) };
        put_mpint(&ko, k, 32);
        k_mpint_len = ko.len;
    }

    /* --- Exchange hash, part 2: K_S, Q_C, Q_S, K --- */
    {
        uint8_t blob[4 + 104];
        ssh_out_t bo = { .p = blob, .len = 0, .cap = sizeof(blob) };
        put_hostkey_blob(&bo);
        mbedtls_sha256_update(&h, blob, bo.len);
    }
    hash_string(&h, q_c, 32);
    hash_string(&h, q_s, 32);
    mbedtls_sha256_update(&h, k_mpint, k_mpint_len);
    mbedtls_sha256_finish(&h, hval);

    if (initial) {
        memcpy(c->session_id, hval, 32);
        c->have_session_id = true;
    }

    /* --- Sign H with the host key (ECDSA over SHA-256(H)) --- */
    fail = "host key signature failed";
    mbedtls_sha256(hval, 32, buf, 0);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_init(&d);
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_mpi_read_binary(&d, s_hk_priv, 32) != 0 ||
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, buf, 32, MBEDTLS_MD_SHA256,
                                   ssh_rng, NULL) != 0) {
        goto out;
    }
    uint8_t rb[32], sb[32];
    if (mbedtls_mpi_write_binary(&r, rb, 32) != 0 || mbedtls_mpi_write_binary(&s, sb, 32) != 0) {
        goto out;
    }

    /* --- KEX_ECDH_REPLY: K_S, Q_S, signature --- */
    {
        ssh_out_t *o = ssh_out_begin(c, SSH_MSG_KEX_ECDH_REPLY);
        put_hostkey_blob(o);
        ssh_put_string(o, q_s, 32);
        uint8_t *sig_len = ssh_put_reserve(o, 4);
        size_t sig_start = o->len;
        ssh_put_cstr(o, ALG_HOSTKEY);
        uint8_t *inner_len = ssh_put_reserve(o, 4);
        size_t inner_start = o->len;
        put_mpint(o, rb, 32);
        put_mpint(o, sb, 32);
        if (o->err) goto out;
        put32(inner_len, (uint32_t)(o->len - inner_start));
        put32(sig_len, (uint32_t)(o->len - sig_start));
        if (ssh_out_send(c) != ESP_OK) goto out;
    }

    ssh_out_begin(c, SSH_MSG_NEWKEYS);
    if (ssh_out_send(c) != ESP_OK) goto out;
    if (c->strict) c->tx_seq = 0;
    if (set_keys(&c->txd, k_mpint, k_mpint_len, hval, c->session_id, 'B', 'D',
                 s2c == 1 ? 256 : 128) != 0) {
        goto out;
    }

    fail = "NEWKEYS expected";
    n = kex_wait(c, SSH_MSG_NEWKEYS, &p, deadline, NULL);
    if (n < 0) goto out;
    if (c->strict) c->rx_seq = 0;
    if (set_keys(&c->rxd, k_mpint, k_mpint_len, hval, c->session_id, 'A', 'C',
                 c2s == 1 ? 256 : 128) != 0) {
        goto out;
    }

    c->kexinit_sent = false;
    ret = 0;

out:
    if (ret != 0) {
        ESP_LOGW(TAG, "Key exchange failed: %s", fail);
        ssh_send_disconnect(c, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, fail);
    }
    mbedtls_sha256_free(&h);
    mbedtls_ecp_point_free(&Qc); mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&s); mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&z); mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    mbedtls_platform_zeroize(k, sizeof(k));
    mbedtls_platform_zeroize(k_mpint, sizeof(k_mpint));
    mbedtls_platform_zeroize(hval, sizeof(hval));
    return ret == 0 ? ESP_OK : ESP_FAIL;
}

/* ---- Public connection API ---- */

ssh_conn_t *ssh_conn_new(int fd, ssh_abort_fn abort_fn)
{
    if (!s_hk_loaded) return NULL;

    ssh_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->rx = malloc(SSH_RX_BUF_SIZE);
    c->tx = malloc(SSH_TX_BUF_SIZE);
    if (!c->rx || !c->tx) {
        free(c->rx);
        free(c->tx);
        free(c);
        return NULL;
    }
    c->fd = fd;
    c->abort_fn = abort_fn;
    mbedtls_gcm_init(&c->rxd.gcm);
    mbedtls_gcm_init(&c->txd.gcm);

    /* 1 s receive poll so kick/shutdown/timeouts are noticed; bounded sends */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    tv.tv_sec = 10;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return c;
}

void ssh_conn_free(ssh_conn_t *c)
{
    if (!c) return;
    mbedtls_gcm_free(&c->rxd.gcm);
    mbedtls_gcm_free(&c->txd.gcm);
    /* Wipe decrypted traffic (passwords, command output) from the heap */
    mbedtls_platform_zeroize(c->rx, SSH_RX_BUF_SIZE);
    mbedtls_platform_zeroize(c->tx, SSH_TX_BUF_SIZE);
    free(c->rx);
    free(c->tx);
    mbedtls_platform_zeroize(c, sizeof(*c));
    free(c);
}

esp_err_t ssh_handshake(ssh_conn_t *c, uint32_t timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    if (send_all(c, (const uint8_t *)SSH_VERSION_STR "\r\n", sizeof(SSH_VERSION_STR) + 1) != 0) {
        return ESP_FAIL;
    }

    /* Client may send other lines before its version string (RFC 4253 4.2) */
    for (int lines = 0; ; lines++) {
        if (lines >= SSH_MAX_VERSION_LINES) return ESP_FAIL;
        size_t pos = 0;
        for (;;) {
            uint8_t ch;
            if (read_exact(c, &ch, 1, deadline) < 0) return ESP_FAIL;
            if (ch == '\n') break;
            if (pos >= sizeof(c->v_c) - 1) return ESP_FAIL;
            c->v_c[pos++] = (char)ch;
        }
        if (pos > 0 && c->v_c[pos - 1] == '\r') pos--;
        c->v_c[pos] = '\0';
        if (strncmp(c->v_c, "SSH-", 4) == 0) break;
    }
    if (strncmp(c->v_c, "SSH-2.0-", 8) != 0 && strncmp(c->v_c, "SSH-1.99-", 9) != 0) {
        ESP_LOGW(TAG, "Unsupported client version");
        return ESP_FAIL;
    }

    if (send_kexinit(c) != ESP_OK) return ESP_FAIL;

    uint8_t *p;
    int n = read_packet(c, &p, deadline);
    if (n < 0 || p[0] != SSH_MSG_KEXINIT) {
        /* With strict kex, KEXINIT must be the very first packet; we require
         * it from every client, which only rejects broken implementations. */
        ESP_LOGW(TAG, "Expected KEXINIT");
        return ESP_FAIL;
    }
    return do_kex(c, p, n, deadline);
}

void ssh_set_authenticated(ssh_conn_t *c)
{
    c->authenticated = true;
}

int ssh_recv(ssh_conn_t *c, uint8_t **payload, uint32_t timeout_ms)
{
    /* One deadline for the whole call. Restarting it for every skipped
     * IGNORE/DEBUG or rekey let a client that never logs in hold the only
     * session slot forever (and stretch the idle timeout). */
    int64_t deadline = timeout_ms ? esp_timer_get_time() + (int64_t)timeout_ms * 1000 : 0;
    for (;;) {
        int n = read_packet(c, payload, deadline);
        if (n < 0) return n;

        switch ((*payload)[0]) {
        case SSH_MSG_IGNORE:
        case SSH_MSG_DEBUG:
        case SSH_MSG_UNIMPLEMENTED:
            continue;
        case SSH_MSG_DISCONNECT:
            return SSH_ERR_CLOSED;
        case SSH_MSG_KEXINIT:
            /* Client-initiated re-key. Each costs an X25519 and an ECDSA
             * signature, so an unauthenticated client gets only a few. */
            if (!c->authenticated && c->preauth_rekeys++ >= SSH_MAX_PREAUTH_REKEYS) {
                ssh_send_disconnect(c, SSH_DISCONNECT_PROTOCOL_ERROR, "too many key exchanges");
                return SSH_ERR_PROTO;
            }
            if (do_kex(c, *payload, n, esp_timer_get_time() + 60LL * 1000000) != ESP_OK) {
                return SSH_ERR_PROTO;
            }
            continue;
        case SSH_MSG_NEWKEYS:
        case SSH_MSG_KEX_ECDH_INIT:
            return SSH_ERR_PROTO;
        default:
            return n;
        }
    }
}
