/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"
#include "src/tls/xqc_hkdf.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"


#define XQC_NONCE_LEN        16
#define XQC_HP_SAMPLELEN     16
#define XQC_HP_MASKLEN       5

#define XQC_FAKE_HP_MASK        "\x00\x00\x00\x00\x00"
#define XQC_FAKE_AEAD_OVERHEAD  XQC_TLS_AEAD_OVERHEAD_MAX_LEN

static inline void
xqc_vec_init(xqc_vec_t *vec)
{
    vec->base = NULL;
    vec->len = 0;
}

static inline void
xqc_vec_free(xqc_vec_t *vec)
{
    if (vec->base) {
        xqc_free(vec->base);
    }

    vec->base = NULL;
    vec->len = 0;
}

static inline xqc_int_t
xqc_vec_assign(xqc_vec_t * vec, const uint8_t * data, size_t data_len)
{
    /* Try to reuse memory and we don't need to free memory before xqc_vec_assign */
    if (!vec->base) {
        vec->base = xqc_malloc(data_len);
        if (!vec->base) {
            return -XQC_EMALLOC;
        }
    } else if (vec->base && vec->len != data_len) {
        xqc_free(vec->base);
        vec->base = xqc_malloc(data_len);
        if (!vec->base) {
            return -XQC_EMALLOC;
        }
    }

    memcpy(vec->base, data, data_len);
    vec->len = data_len;
    return XQC_OK;
}

static inline void
xqc_ckm_init(xqc_crypto_km_t *ckm)
{
    xqc_vec_init(&ckm->secret);
    xqc_vec_init(&ckm->key);
    xqc_vec_init(&ckm->iv);

    ckm->aead_ctx = NULL;
}

static inline void
xqc_ckm_free(xqc_crypto_km_t *ckm)
{
    xqc_vec_free(&ckm->secret);
    xqc_vec_free(&ckm->key);
    xqc_vec_free(&ckm->iv);

    xqc_aead_ctx_free(ckm->aead_ctx);
    ckm->aead_ctx = NULL;
}

/* set aead suites, cipher suites and digest suites */
//这个函数创建了QUIC连接加密需要的crypto对象,主要进行了以下初始化:


xqc_crypto_t *
xqc_crypto_create(uint32_t cipher_id, xqc_log_t *log)
{
    xqc_crypto_t *crypto = xqc_malloc(sizeof(xqc_crypto_t));
    if (crypto == NULL) {
        return NULL;
    }

    crypto->log = log;
    crypto->key_phase = 0;

    xqc_vec_init(&crypto->keys.tx_hp);
    xqc_vec_init(&crypto->keys.rx_hp);
    crypto->keys.tx_hp_ctx = NULL;
    crypto->keys.rx_hp_ctx = NULL;

    for (int i = 0; i < XQC_KEY_PHASE_CNT; i++) {
        xqc_ckm_init(&crypto->keys.tx_ckm[i]);
        xqc_ckm_init(&crypto->keys.rx_ckm[i]);
    }
    
    //根据cipher_id设置加密套件,支持AES-128-GCM、AES-256-GCM、CHACHA20-POLY1305等。
    //初始化pp_aead对象,用于1-RTT数据的AEAD加密。
    //初始化hp_cipher对象,用于header保护的加密。
    //初始化消息摘要md对象
    //初始化密钥对象keys,包括tx/rx密钥容器等
    //为每个key phase初始化密钥材料对象tx/rx_ckm
    switch (cipher_id) {
    /* TLS_AES_128_GCM_SHA256 */
    case XQC_TLS13_AES_128_GCM_SHA256:
        xqc_aead_init_aes_gcm(&crypto->pp_aead, 128);
        xqc_cipher_init_aes_ctr(&crypto->hp_cipher, 128);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    /* TLS_AES_256_GCM_SHA384 */
    case XQC_TLS13_AES_256_GCM_SHA384:
        xqc_aead_init_aes_gcm(&crypto->pp_aead, 256);
        xqc_cipher_init_aes_ctr(&crypto->hp_cipher, 256);
        xqc_digest_init_to_sha384(&crypto->md);
        break;

    /* TLS_CHACHA20_POLY1305_SHA256 */
    case XQC_TLS13_CHACHA20_POLY1305_SHA256:
        xqc_aead_init_chacha20_poly1305(&crypto->pp_aead);
        xqc_cipher_init_chacha20(&crypto->hp_cipher);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    case NID_undef:
        xqc_aead_init_null(&crypto->pp_aead, XQC_FAKE_AEAD_OVERHEAD);
        xqc_cipher_init_null(&crypto->hp_cipher);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    default: /* TLS_AES_128_CCM_SHA256、TLS_AES_128_CCM_8_SHA256 not support */
        xqc_log(log, XQC_LOG_ERROR, "|not supoort cipher_id|%u|", cipher_id);
        xqc_free(crypto);
        return NULL;
    }

    return crypto;
}

void
xqc_crypto_destroy(xqc_crypto_t *crypto)
{
    if (crypto) {
        xqc_vec_free(&crypto->keys.tx_hp);
        xqc_vec_free(&crypto->keys.rx_hp);

        xqc_hp_ctx_free(crypto->keys.tx_hp_ctx);
        crypto->keys.tx_hp_ctx = NULL;
        xqc_hp_ctx_free(crypto->keys.rx_hp_ctx);
        crypto->keys.rx_hp_ctx = NULL;

        for (int i = 0; i < XQC_KEY_PHASE_CNT; i++) {
            xqc_ckm_free(&crypto->keys.tx_ckm[i]);
            xqc_ckm_free(&crypto->keys.rx_ckm[i]);
        }

        xqc_free(crypto);
    }
}

void
xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen, uint64_t pktno, uint32_t path_id)
{
    size_t i;

    memcpy(dest, iv, ivlen);

    /* To calculate the nonce, a 96 bit path-and-packet-number is composed of the
     * 32 bit Connection ID Sequence Number in byte order, two zero bits, and the
     * 62 bits of the reconstructed QUIC packet number in network byte order.
     * If the IV is larger than 96 bits, the path-and-packet-number is left-padded
     * with zeros to the size of the IV. 
     * The exclusive OR of the padded packet number and the IV forms the AEAD nonce.
     */

    pktno = bswap64(pktno);
    for (i = 0; i < 8; ++i) {
        dest[ivlen - 8 + i] ^= ((uint8_t *)&pktno)[i];
    }

    path_id = ntohl(path_id);
    for (i = 0; i < 4; ++i) {
        dest[ivlen - 12 + i] ^= ((uint8_t *)&path_id)[i];
    }
}


xqc_int_t
xqc_crypto_encrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end)
{
    xqc_int_t       ret;

    uint8_t         mask[XQC_HP_MASKLEN];
    size_t          nwrite;

    /* packet number position and sample position */
    size_t   pktno_len  = XQC_PACKET_SHORT_HEADER_PKTNO_LEN(header);
    uint8_t *sample     = pktno + 4;

    /* hp cipher and key */
    xqc_hdr_protect_cipher_t *hp_cipher = &crypto->hp_cipher;
    xqc_vec_t *hp  = &crypto->keys.tx_hp;
    if (hp_cipher == NULL || hp->base == NULL || hp->len == 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|hp encrypt key NULL|");
        return -XQC_EENCRYPT;
    }

    /* get length of packet number */
    if (pktno + pktno_len > end) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal pkt, pkt num exceed buffer");
        return -XQC_EILLPKT;
    }

    /* generate header protection mask */
    ret = hp_cipher->hp_mask(hp_cipher, crypto->keys.tx_hp_ctx,
                             mask, XQC_HP_MASKLEN, &nwrite,                  /* mask */
                             XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK) - 1, /* plaintext */
                             hp->base, hp->len,                              /* key */
                             sample, XQC_HP_SAMPLELEN);                      /* sample */
    if (ret != XQC_OK || nwrite < XQC_HP_MASKLEN) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|calculate header protection mask error|ret:%d|nwrite:%z|", ret, nwrite);
        return -XQC_EENCRYPT;
    }

    /* protect the first byte of header */
    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        *header = (uint8_t)(*header ^ (mask[0] & 0x1f));

    } else {
        *header = (uint8_t)(*header ^ (mask[0] & 0x0f));
    }

    /* protect packet number */
    for (size_t i = 0; i < pktno_len; ++i) {
        *(pktno + i) ^= mask[i + 1];
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_decrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end)
{
    xqc_int_t ret;
    size_t nwrite;

    /* header protection cipher and rx hp key */
    xqc_hdr_protect_cipher_t *hp_cipher = &crypto->hp_cipher;
    xqc_vec_t *hp = &crypto->keys.rx_hp;
    if (hp->base == NULL || hp->len == 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|hp rx key NULL|");
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* generate hp mask */
    uint8_t mask[XQC_HP_MASKLEN];
    uint8_t *sample = pktno + 4;
    ret = hp_cipher->hp_mask(hp_cipher, crypto->keys.rx_hp_ctx,
                             mask, XQC_HP_MASKLEN, &nwrite,                     /* mask */
                             XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK) - 1,    /* ciphertext */
                             hp->base, hp->len,                                 /* key */
                             sample, XQC_HP_SAMPLELEN);                         /* sample */
    if (ret != XQC_OK || nwrite < XQC_HP_MASKLEN) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|calculate header protection mask error|ret:%d|"
                "nwrite:%z|", ret, nwrite);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* remove protection for first byte */
    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        header[0] = (uint8_t)(header[0] ^ (mask[0] & 0x1f));

    } else {
        header[0] = (uint8_t)(header[0] ^ (mask[0] & 0x0f));
    }

    /* get length of packet number */
    size_t pktno_len = XQC_PACKET_SHORT_HEADER_PKTNO_LEN(header);
    if (pktno + pktno_len > end) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal pkt, pkt num exceed buffer");
        return -XQC_EILLPKT;
    }

    /* remove protection for packet number */
    for (size_t i = 0; i < pktno_len; ++i) {
        pktno[i] = pktno[i] ^ mask[i + 1];
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_encrypt_payload(xqc_crypto_t *crypto,
    uint64_t pktno, xqc_uint_t key_phase, uint32_t path_id,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_int_t ret;
    uint8_t nonce[XQC_NONCE_LEN];

    /* aead function and tx key */
    xqc_pkt_protect_aead_t *pp_aead = &crypto->pp_aead;
    xqc_crypto_km_t        *ckm     = &crypto->keys.tx_ckm[key_phase];
    if (ckm->key.base == NULL || ckm->key.len == 0
        || ckm->iv.base == NULL || ckm->iv.len == 0)
    {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|pp encrypt key NULL|key_phase:%ui|", key_phase);
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    /* generate nonce for aead encryption with original packet number */
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, pktno, path_id);

    /* do aead encryption */
    ret = pp_aead->encrypt(pp_aead, ckm->aead_ctx,
                           dst, dst_cap, dst_len,         /* dest */
                           payload, payload_len,          /* plaintext */
                           ckm->key.base, ckm->key.len,   /* tx key */
                           nonce, ckm->iv.len,            /* nonce and iv */
                           header, header_len);           /* ad */
    if (ret != XQC_OK
        || *dst_len != (payload_len + xqc_aead_overhead(pp_aead, payload_len)))
    {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|encrypt packet error|ret:%d|nwrite:%z|", ret, *dst_len);
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_decrypt_payload(xqc_crypto_t *crypto,
    uint64_t pktno, xqc_uint_t key_phase, uint32_t path_id,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_int_t ret;
    uint8_t nonce[XQC_NONCE_LEN];

    /* keys for decryption */
    xqc_pkt_protect_aead_t *pp_aead = &crypto->pp_aead;
    xqc_crypto_km_t        *ckm     = &crypto->keys.rx_ckm[key_phase];
    if (ckm->key.base == NULL || ckm->key.len == 0
        || ckm->iv.base == NULL || ckm->iv.len == 0)
    {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|decrypt key NULL|key_phase:%ui|", key_phase);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* create nonce */
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, pktno, path_id);

    /* do aead decryption */
    ret = pp_aead->decrypt(pp_aead, ckm->aead_ctx,
                           dst, dst_cap, dst_len,       /* dest */
                           payload, payload_len,        /* ciphertext */
                           ckm->key.base, ckm->key.len, /* rx key */
                           nonce, ckm->iv.len,          /* nonce and iv */
                           header, header_len);         /* ad */
    if (ret != XQC_OK
        || *dst_len != (payload_len - xqc_aead_overhead(pp_aead, payload_len)))
    {
        /* decrypt error might be common */
        xqc_log(crypto->log, XQC_LOG_INFO,
                "|decrypt payload error|ret:%d|write:%z|", ret, *dst_len);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    return XQC_OK;
}


/* derive packet protection keys and store them in xqc_crypto_t */

xqc_int_t
xqc_crypto_derive_packet_protection_key(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic key";

    size_t keylen = crypto->pp_aead.keylen;
    if (keylen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, keylen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = keylen;
    return XQC_OK;
}

xqc_int_t
xqc_crypto_derive_packet_protection_iv(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic iv";

    /* 
     * he Length provided with "quic iv" is the minimum length of the AEAD nonce
     * or 8 bytes if that is larger 
     */
    size_t ivlen = xqc_max(8, crypto->pp_aead.noncelen);
    if (ivlen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, ivlen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = ivlen;
    return XQC_OK;
}

xqc_int_t
xqc_crypto_derive_header_protection_key(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic hp";

    size_t keylen = crypto->hp_cipher.keylen;
    if (keylen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, keylen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = keylen;
    return XQC_OK;
}

#define XQC_MAX_KNP_LEN 64

/*
 * xqc_crypto_derive_keys - 从 secrets 中派生数据包保护所需的密钥材料
 *
 * 此函数用于从 QUIC 的 `secret` 中派生出数据包保护所需的密钥材料，包括：
 *   - 加密密钥 (key)
 *   - 初始化向量 (IV)
 *   - 包头保护密钥 (header protection key, hp)
 *
 * 根据密钥用途（接收或发送），将派生的密钥存储到对应的加密上下文中。
 *
 * 参数:
 *   crypto - QUIC 的加密上下文，包含密钥和算法信息。
 *   secret - 输入的密钥材料，用于派生密钥、IV 和 HP。
 *   secretlen - 输入密钥材料的长度。
 *   type - 密钥的用途（接收或发送），如 XQC_KEY_TYPE_RX_READ 或 XQC_KEY_TYPE_TX_WRITE。
 *
 * 返回值:
 *   - XQC_OK: 成功派生密钥并存储。
 *   - 其他错误码: 失败，具体错误码见返回值。
 */
xqc_int_t
xqc_crypto_derive_keys(xqc_crypto_t *crypto, const uint8_t *secret, size_t secretlen,
    xqc_key_type_t type)
{
    /* 定义用于存储派生密钥的缓冲区 */
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}, hp[XQC_MAX_KNP_LEN] = {0}; 
    size_t  keycap = XQC_MAX_KNP_LEN,   ivcap = XQC_MAX_KNP_LEN,   hpcap = XQC_MAX_KNP_LEN;
    size_t  keylen = 0,                 ivlen = 0,                 hplen = 0;

    xqc_int_t ret;
    
    // 从 secret 派生加密密钥 (key)
    ret = xqc_crypto_derive_packet_protection_key(crypto, key, keycap, &keylen, secret, secretlen);
    if (ret != XQC_OK || keylen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_key failed|ret:%d|", ret);
        return ret;
    }

    // 从 secret 派生初始化向量 (IV)
    ret = xqc_crypto_derive_packet_protection_iv(crypto, iv, ivcap, &ivlen, secret, secretlen);
    if (ret != XQC_OK || ivlen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_iv failed|ret:%d|", ret);
        return ret;
    }

    // 从 secret 派生包头保护密钥 (HP key)
    ret = xqc_crypto_derive_header_protection_key(crypto, hp, hpcap, &hplen, secret, secretlen);
    if (ret != XQC_OK || hplen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_header_protection_key failed|ret:%d|", ret);
        return ret;
    }

    /* 存储派生的密钥 */
    xqc_crypto_km_t *p_ckm = NULL;
    xqc_vec_t *p_hp = NULL;
    void **p_hp_ctx = NULL;
    
    // 根据密钥用途 (type)，选择存储位置
    switch (type) {
    case XQC_KEY_TYPE_RX_READ:  // 接收方向的密钥
        p_ckm = &crypto->keys.rx_ckm[crypto->key_phase];
        p_hp = &crypto->keys.rx_hp;
        p_hp_ctx = &crypto->keys.rx_hp_ctx;
        break;

    case XQC_KEY_TYPE_TX_WRITE:  // 发送方向的密钥
        p_ckm = &crypto->keys.tx_ckm[crypto->key_phase];
        p_hp = &crypto->keys.tx_hp;
        p_hp_ctx = &crypto->keys.tx_hp_ctx;
        break;

    default:  // 非法的密钥类型
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }
    
    // 将派生的 key 存储到加密上下文中
    if (xqc_vec_assign(&p_ckm->key, key, keylen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    // 将派生的 IV 存储到加密上下文中
    if (xqc_vec_assign(&p_ckm->iv, iv, ivlen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    // 将派生的 HP key 存储到加密上下文中
    if (xqc_vec_assign(p_hp, hp, hplen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }
    
    // 如果启用了 AEAD 加密，创建 AEAD 上下文并存储
    if (crypto->pp_aead.aead) {
        xqc_aead_ctx_free(p_ckm->aead_ctx);  // 释放旧的 AEAD 上下文
        p_ckm->aead_ctx = xqc_aead_ctx_new(&crypto->pp_aead, type, key, ivlen);
        if (!p_ckm->aead_ctx) {
            return -XQC_TLS_DERIVE_KEY_ERROR;
        }
    }
    
    // 如果启用了包头保护，创建 HP 上下文并存储
    if (crypto->hp_cipher.cipher) {
        xqc_hp_ctx_free(*p_hp_ctx);  // 释放旧的 HP 上下文
        *p_hp_ctx = xqc_hp_ctx_new(&crypto->hp_cipher, hp);
        if (!(*p_hp_ctx)) {
            return -XQC_TLS_DERIVE_KEY_ERROR;
        }
    }

    return XQC_OK;  // 成功派生并存储密钥
}

xqc_int_t
xqc_crypto_save_application_traffic_secret_0(xqc_crypto_t *crypto,
    const uint8_t *secret, size_t secretlen, xqc_key_type_t type)
{
    xqc_crypto_km_t *ckm;
    switch (type) {
    case XQC_KEY_TYPE_RX_READ:
        ckm = &crypto->keys.rx_ckm[crypto->key_phase];
        break;

    case XQC_KEY_TYPE_TX_WRITE:
        ckm = &crypto->keys.tx_ckm[crypto->key_phase];
        break;
    
    default:
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    xqc_vec_assign(&ckm->secret, secret, secretlen);
    return XQC_OK;
}

xqc_bool_t
xqc_crypto_is_key_ready(xqc_crypto_t *crypto, xqc_key_type_t type)
{
    xqc_crypto_km_t *km;
    xqc_vec_t *hp;

    if (type == XQC_KEY_TYPE_RX_READ) {
        km = &crypto->keys.rx_ckm[crypto->key_phase];
        hp = &crypto->keys.rx_hp;

    } else {
        km = &crypto->keys.tx_ckm[crypto->key_phase];
        hp = &crypto->keys.tx_hp;
    }

    if (!km->key.base || km->key.len == 0
        || !km->iv.base || km->iv.len == 0)
    {
        return XQC_FALSE;
    }

    if (!hp->base || hp->len == 0) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


/* derive initial secret (for initial encryption level) */
/**
 * @brief 生成客户端和服务器的初始密钥（Initial Secret）
 *
 * @param cli_initial_secret      输出参数，生成的客户端初始密钥
 * @param cli_initial_secret_len  客户端初始密钥的长度
 * @param svr_initial_secret      输出参数，生成的服务器初始密钥
 * @param svr_initial_secret_len  服务器初始密钥的长度
 * @param cid                     连接 ID，用于生成初始密钥的输入
 * @param salt                    固定的盐值，用于生成初始密钥的输入
 * @param saltlen                 盐值的长度
 *
 * @return XQC_OK 表示成功，其他值表示失败
 *
 * @details
 * 该函数基于 QUIC 协议的密钥派生机制，生成客户端和服务器的初始密钥，用于保护初始数据包。
 * 初始密钥的生成基于 HKDF（HMAC-based Key Derivation Function），具体步骤如下：
 * 1. 使用连接 ID（Connection ID, CID）和固定的盐值（Salt）通过 `HKDF-Extract` 生成一个通用的初始密钥。
 * 2. 使用通用的初始密钥通过 `HKDF-Expand-Label` 分别派生出客户端和服务器的初始密钥。
 */
xqc_int_t
xqc_crypto_derive_initial_secret(uint8_t *cli_initial_secret, size_t cli_initial_secret_len,
    uint8_t *svr_initial_secret, size_t svr_initial_secret_len, const xqc_cid_t *cid,
    const uint8_t *salt, size_t saltlen)
{
    static uint8_t LABEL_SVR_IN[] = "server in";
    static uint8_t LABEL_CLI_IN[] = "client in";
    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN] = {0};   /* the common initial secret */

    xqc_digest_t md;
    xqc_digest_init_to_sha256(&md);

    /* initial secret */
    //随机化
    xqc_int_t ret = xqc_hkdf_extract(initial_secret, INITIAL_SECRET_MAX_LEN, cid->cid_buf,
                                     cid->cid_len, salt, saltlen, &md);
    if (ret != XQC_OK) {
        return ret;
    }

    /* derive client initial secret for packet protection */
    //打标签
    ret = xqc_hkdf_expand_label(cli_initial_secret, cli_initial_secret_len,
                                initial_secret, INITIAL_SECRET_MAX_LEN,
                                LABEL_CLI_IN, xqc_lengthof(LABEL_CLI_IN), &md);
    if (ret != XQC_OK) {
        return ret;
    }

    /* derive server initial secret for packet protection */
    ret = xqc_hkdf_expand_label(svr_initial_secret, svr_initial_secret_len,
                                initial_secret, INITIAL_SECRET_MAX_LEN,
                                LABEL_SVR_IN, xqc_lengthof(LABEL_SVR_IN), &md);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}


ssize_t
xqc_crypto_aead_tag_len(xqc_crypto_t *crypto)
{
    return crypto->pp_aead.taglen;
}

/*
 * xqc_crypto_derive_updated_keys - 更新 QUIC 的加密密钥
 *
 * 此函数用于在密钥更新时，从当前的加密密钥派生出新的密钥材料。
 * QUIC 协议中，密钥更新是通过 HKDF 扩展标签派生新的密钥材料实现的。
 * 新的密钥材料包括：
 *   - 应用流量密钥 (Application Traffic Secret)
 *   - 加密密钥 (Key)
 *   - 初始化向量 (IV)
 *
 * 参数:
 *   crypto - QUIC 的加密上下文，包含当前密钥和算法信息。
 *   type - 密钥的用途（接收或发送），如 XQC_KEY_TYPE_RX_READ 或 XQC_KEY_TYPE_TX_WRITE。
 *
 * 返回值:
 *   - XQC_OK: 成功派生并更新密钥。
 *   - 其他错误码: 失败，具体错误码见返回值。
 */
xqc_int_t
xqc_crypto_derive_updated_keys(xqc_crypto_t *crypto, xqc_key_type_t type)
{
    xqc_int_t ret;

    // 当前密钥阶段和更新后的密钥阶段
    xqc_uint_t current_key_phase = crypto->key_phase;
    xqc_uint_t updated_key_phase = current_key_phase ^ 1;  // 切换密钥阶段

    xqc_crypto_km_t *current_ckm, *updated_ckm;

    // 根据密钥用途选择当前和更新后的密钥上下文
    switch (type) {
    case XQC_KEY_TYPE_RX_READ:  // 接收方向的密钥
        current_ckm = &crypto->keys.rx_ckm[current_key_phase];
        updated_ckm = &crypto->keys.rx_ckm[updated_key_phase];
        break;

    case XQC_KEY_TYPE_TX_WRITE:  // 发送方向的密钥
        current_ckm = &crypto->keys.tx_ckm[current_key_phase];
        updated_ckm = &crypto->keys.tx_ckm[updated_key_phase];
        break;

    default:  // 非法的密钥类型
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    /* 更新应用流量密钥 (Application Traffic Secret) */
    static uint8_t LABEL[] = "quic ku";  // QUIC 密钥更新的标签
    uint8_t dest_buf[XQC_MAX_KNP_LEN];

    // 检查当前密钥长度是否有效
    if (current_ckm->secret.len > XQC_MAX_KNP_LEN) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    // 使用 HKDF 扩展标签派生新的应用流量密钥
    ret = xqc_hkdf_expand_label(dest_buf, current_ckm->secret.len,
                                current_ckm->secret.base, current_ckm->secret.len,
                                LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    // 将派生的应用流量密钥存储到更新后的密钥上下文
    xqc_vec_assign(&updated_ckm->secret, dest_buf, current_ckm->secret.len);

    /* 使用新的应用流量密钥派生加密密钥和初始化向量 */
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}; 
    size_t  keycap = XQC_MAX_KNP_LEN,   ivcap = XQC_MAX_KNP_LEN;
    size_t  keylen = 0,                 ivlen = 0;

    // 派生加密密钥
    ret = xqc_crypto_derive_packet_protection_key(crypto, key, keycap, &keylen,
                                                  updated_ckm->secret.base,
                                                  updated_ckm->secret.len);
    if (ret != XQC_OK || keylen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_key failed|ret:%d|", ret);
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    // 派生初始化向量 (IV)
    ret = xqc_crypto_derive_packet_protection_iv(crypto, iv, ivcap, &ivlen,
                                                 updated_ckm->secret.base,
                                                 updated_ckm->secret.len);
    if (ret != XQC_OK || ivlen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_iv failed|ret:%d|", ret);
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    // 将派生的加密密钥存储到更新后的密钥上下文
    if (xqc_vec_assign(&updated_ckm->key, key, keylen) != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    // 将派生的初始化向量存储到更新后的密钥上下文
    if (xqc_vec_assign(&updated_ckm->iv, iv, ivlen) != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    /* 如果启用了 AEAD 加密，创建新的 AEAD 上下文 */
    if (crypto->pp_aead.aead) {
        xqc_aead_ctx_free(updated_ckm->aead_ctx);  // 释放旧的 AEAD 上下文
        updated_ckm->aead_ctx = xqc_aead_ctx_new(&crypto->pp_aead, type, key, ivlen);
        if (!updated_ckm->aead_ctx) {
            return -XQC_TLS_UPDATE_KEY_ERROR;
        }
    }

    return XQC_OK;  // 成功更新密钥
}

void
xqc_crypto_discard_old_keys(xqc_crypto_t *crypto)
{
    xqc_uint_t discard_key_phase = crypto->key_phase ^ 1;

    xqc_ckm_free(&crypto->keys.rx_ckm[discard_key_phase]);
    xqc_ckm_free(&crypto->keys.tx_ckm[discard_key_phase]);
}

xqc_int_t
xqc_crypto_aead_encrypt(xqc_crypto_t *crypto,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_int_t ret;
    xqc_pkt_protect_aead_t *pp_aead = &crypto->pp_aead;

    void *aead_ctx = xqc_aead_ctx_new(&crypto->pp_aead, XQC_KEY_TYPE_TX_WRITE, key, noncelen);
    if (!aead_ctx) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    /* do aead encryption */
    ret = pp_aead->encrypt(pp_aead, aead_ctx, dst, dst_cap, dst_len,
                           plaintext, plaintextlen,
                           key, keylen,
                           nonce, noncelen,
                           ad, adlen);

    if (ret != XQC_OK) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|encrypt packet error|ret:%d|nwrite:%z|", ret, *dst_len);
        goto end;
    }

end:
    xqc_aead_ctx_free(aead_ctx);
    return ret;
}
