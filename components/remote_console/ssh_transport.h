/**
 * @file ssh_transport.h
 * @brief Minimal SSH-2 server transport layer (RFC 4253) for the remote console
 *
 * Algorithms (all built on crypto the firmware already links for WPA3/EAP):
 *   kex:     curve25519-sha256 (+ @libssh.org alias), strict kex (Terrapin)
 *   hostkey: ecdsa-sha2-nistp256, generated on first use and kept in NVS
 *   cipher:  aes128-gcm@openssh.com, aes256-gcm@openssh.com
 *   mac:     implicit (AEAD), compression: none
 *
 * One connection is served at a time; buffers are allocated per connection.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Message numbers (RFC 4250) */
#define SSH_MSG_DISCONNECT                 1
#define SSH_MSG_IGNORE                     2
#define SSH_MSG_UNIMPLEMENTED              3
#define SSH_MSG_DEBUG                      4
#define SSH_MSG_SERVICE_REQUEST            5
#define SSH_MSG_SERVICE_ACCEPT             6
#define SSH_MSG_KEXINIT                    20
#define SSH_MSG_NEWKEYS                    21
#define SSH_MSG_KEX_ECDH_INIT              30
#define SSH_MSG_KEX_ECDH_REPLY             31
#define SSH_MSG_USERAUTH_REQUEST           50
#define SSH_MSG_USERAUTH_FAILURE           51
#define SSH_MSG_USERAUTH_SUCCESS           52
#define SSH_MSG_USERAUTH_BANNER            53
#define SSH_MSG_GLOBAL_REQUEST             80
#define SSH_MSG_REQUEST_FAILURE            82
#define SSH_MSG_CHANNEL_OPEN               90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION  91
#define SSH_MSG_CHANNEL_OPEN_FAILURE       92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST      93
#define SSH_MSG_CHANNEL_DATA               94
#define SSH_MSG_CHANNEL_EXTENDED_DATA      95
#define SSH_MSG_CHANNEL_EOF                96
#define SSH_MSG_CHANNEL_CLOSE              97
#define SSH_MSG_CHANNEL_REQUEST            98
#define SSH_MSG_CHANNEL_SUCCESS            99
#define SSH_MSG_CHANNEL_FAILURE            100

/* Disconnect reason codes */
#define SSH_DISCONNECT_PROTOCOL_ERROR          2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED     3
#define SSH_DISCONNECT_MAC_ERROR               5
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE   7
#define SSH_DISCONNECT_BY_APPLICATION          11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS    12
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS    14

/* ssh_recv() error codes */
#define SSH_ERR_TIMEOUT   (-1)   /* no packet within the timeout */
#define SSH_ERR_ABORT     (-2)   /* abort callback returned true (kick/shutdown) */
#define SSH_ERR_CLOSED    (-3)   /* peer closed / sent DISCONNECT / socket error */
#define SSH_ERR_PROTO     (-4)   /* protocol or crypto failure */

/** Largest CHANNEL_DATA payload the server sends in one packet */
#define SSH_MAX_DATA_CHUNK  1024

typedef struct ssh_conn ssh_conn_t;

/** Polled about once a second while blocked on the socket. */
typedef bool (*ssh_abort_fn)(void);

/** Output packet builder (writes into the connection's tx buffer). */
typedef struct {
    uint8_t *p;
    size_t len;
    size_t cap;
    bool err;
} ssh_out_t;

/** Input packet reader. */
typedef struct {
    uint8_t *p;
    size_t len;
    size_t pos;
    bool err;
} ssh_in_t;

/* ---- Host key (NVS key "rc_hostkey", 32-byte P-256 private scalar) ---- */

/** Load the host key from NVS, generating and storing one if missing. */
esp_err_t ssh_hostkey_init(void);

/** "SHA256:<base64>" fingerprint of the host key, as shown by ssh clients.
 *  Writes "(none)" if no key has been loaded/generated yet. */
void ssh_hostkey_fingerprint(char *out, size_t out_len);

/* ---- Connection ---- */

ssh_conn_t *ssh_conn_new(int fd, ssh_abort_fn abort_fn);
void ssh_conn_free(ssh_conn_t *c);

/** Version exchange and initial key exchange; must finish within timeout_ms. */
esp_err_t ssh_handshake(ssh_conn_t *c, uint32_t timeout_ms);

/** Receive the next packet above the transport layer (IGNORE/DEBUG/rekey are
 *  handled internally). timeout_ms = 0 waits forever.
 *  @return payload length (> 0, payload[0] is the message number) or SSH_ERR_* */
int ssh_recv(ssh_conn_t *c, uint8_t **payload, uint32_t timeout_ms);

/** Mark the user as authenticated (lifts the pre-auth rekey limit). */
void ssh_set_authenticated(ssh_conn_t *c);

/** Start a new outgoing packet of the given message type. */
ssh_out_t *ssh_out_begin(ssh_conn_t *c, uint8_t type);
/** Encrypt and send the packet started with ssh_out_begin(). */
esp_err_t ssh_out_send(ssh_conn_t *c);

/** Send SSH_MSG_UNIMPLEMENTED for the most recently received packet. */
esp_err_t ssh_send_unimplemented(ssh_conn_t *c);
/** Send SSH_MSG_DISCONNECT (best effort). */
void ssh_send_disconnect(ssh_conn_t *c, uint32_t reason, const char *msg);

/* ---- Builder / reader helpers ---- */

void ssh_put_u8(ssh_out_t *o, uint8_t v);
void ssh_put_u32(ssh_out_t *o, uint32_t v);
void ssh_put_string(ssh_out_t *o, const void *data, size_t len);
void ssh_put_cstr(ssh_out_t *o, const char *s);
/** Reserve room for n raw bytes and return a pointer to it (NULL on overflow). */
uint8_t *ssh_put_reserve(ssh_out_t *o, size_t n);

void ssh_in_init(ssh_in_t *in, uint8_t *p, size_t len);
uint8_t ssh_get_u8(ssh_in_t *in);
uint32_t ssh_get_u32(ssh_in_t *in);
bool ssh_get_bool(ssh_in_t *in);
/** Returns a pointer into the packet (not NUL-terminated); NULL on error. */
uint8_t *ssh_get_string(ssh_in_t *in, size_t *len);
/** True if the next string equals s; consumes it either way. */
bool ssh_get_string_eq(ssh_in_t *in, const char *s);

#ifdef __cplusplus
}
#endif
