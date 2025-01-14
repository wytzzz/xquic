/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TLS_COMMON_H
#define XQC_TLS_COMMON_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <xquic/xquic.h>

/**
 * @brief definitions for inner usage
 */

#ifdef WORDS_BIGENDIAN
#  define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#  define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */


#define XQC_SSL_SUCCESS 1   /* openssl or boringssl 1 success */
#define XQC_SSL_FAIL    0   /* openssl or boringssl 0 failure */


#define XQC_UINT32_MAX  (0xffffffff)


//7天过期
#define XQC_SESSION_DEFAULT_TIMEOUT (7 * 24 * 60 * 60)

#define INITIAL_SECRET_MAX_LEN  32

//salt
static const char * const (xqc_crypto_initial_salt)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};

static const char * const (xqc_crypto_retry_key)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};

static const char * const (xqc_crypto_retry_nonce)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};


/*

xqc_ssl_session_ticket_key_t 并不是直接表示 NewSessionTicket 消息，
而是用于管理加密和认证 ticket 字段的密钥。它的作用是支持服务器端加密和解密 ticket。

会话票据的名称（用于标识密钥）。
用于认证的 HMAC 密钥。
用于加密的 AES 密钥

服务器生成一个 xqc_ssl_session_ticket_key_t 实例：
随机生成 name、hmac_key 和 aes_key。
设置 size 为 64。
使用 aes_key 加密会话票据内容。
使用 hmac_key 对加密后的票据生成 HMAC。
将加密后的票据和 name 发送给客户端

客户端存储会话票据和 name。
在后续连接中，将会话票据和 name 发送回服务器。
服务器通过 name 找到对应的密钥。
使用 hmac_key 验证票据的完整性。
使用 aes_key 解密票据内容，恢复会话

*/
typedef struct xqc_ssl_session_ticket_key_s {
    size_t                      size;
    uint8_t                     name[16];
    uint8_t                     hmac_key[32];
    uint8_t                     aes_key[32];
} xqc_ssl_session_ticket_key_t;


#define XQC_EARLY_DATA_CONTEXT          "xquic"
#define XQC_EARLY_DATA_CONTEXT_LEN      (sizeof(XQC_EARLY_DATA_CONTEXT) - 1)



/* the default max depth of cert chain is 100 */
#define XQC_MAX_VERIFY_DEPTH 100

#define XQC_TLS_SELF_SIGNED_CERT(err_code) \
    (err_code == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT \
        || err_code == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)


#endif
