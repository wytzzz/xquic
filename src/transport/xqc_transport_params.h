/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TRANSPORT_PARAMS_H_
#define XQC_TRANSPORT_PARAMS_H_

#include <xquic/xquic.h>
#include "src/transport/xqc_defs.h"

/* default value for max_ack_delay */
#define XQC_DEFAULT_MAX_ACK_DELAY               25

/* default value for ack_delay_exponent */
#define XQC_DEFAULT_ACK_DELAY_EXPONENT          3

/* default value for max_udp_payload_size */
#define XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE        65527

/* default value for active_connection_id_limit */
#define XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT  2

/* max buffer length of encoded transport parameter */
#define XQC_MAX_TRANSPORT_PARAM_BUF_LEN         512



/**
 * @brief transport parameter type
 */
typedef enum {
    /* transport parameter for client */
    XQC_TP_TYPE_CLIENT_HELLO,

    /* transport parameter for server */
    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS

} xqc_transport_params_type_t;


/**
 * @brief definition of transport parameter types
 */
typedef enum {
    XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID         = 0x0000,
    XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT                    = 0x0001,
    XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN               = 0x0002,
    XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE                = 0x0003,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA                    = 0x0004,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 0x0005,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI         = 0x0007,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI            = 0x0008,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI             = 0x0009,
    XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT                  = 0x000a,
    XQC_TRANSPORT_PARAM_MAX_ACK_DELAY                       = 0x000b,
    XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION            = 0x000c,
    XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS                   = 0x000d,
    XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT          = 0x000e,
    XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID        = 0x000f,
    XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID          = 0x0010,

    /* upper limit of params defined in [Transport] */
    XQC_TRANSPORT_PARAM_PROTOCOL_MAX,

    /* max datagram frame size */
    XQC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE             = 0x0020,

    /* do no cryption on 0-RTT and 1-RTT packets */
    XQC_TRANSPORT_PARAM_NO_CRYPTO                           = 0x1000,

    /* multipath quic attributes */
    XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_04                 = 0x0f739bbc1b666d04,
    XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_05                 = 0x0f739bbc1b666d05,
    XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_06                 = 0x0f739bbc1b666d06,

    /* upper limit of params defined by xquic */
    XQC_TRANSPORT_PARAM_UNKNOWN,
} xqc_transport_param_id_t;


typedef struct {
    uint8_t                 ipv4[4];
    uint16_t                ipv4_port;
    uint8_t                 ipv6[16];
    uint16_t                ipv6_port;
    xqc_cid_t               cid;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_preferred_addr_t;


/* transport parameters *//* 传输参数 */
typedef struct {
    /* 首选地址，用于服务器向客户端提供备用地址以支持连接迁移 */
    xqc_preferred_addr_t    preferred_address;

    /* 指示是否存在首选地址 */
    uint8_t                 preferred_address_present;

    /* 原始目标连接 ID，用于服务器在重定向连接时标识客户端的初始连接 ID */
    xqc_cid_t               original_dest_connection_id;

    /* 指示是否存在原始目标连接 ID */
    uint8_t                 original_dest_connection_id_present;

    /* 最大空闲超时时间（以微秒为单位）。如果连接在此时间内无活动，则会被关闭 */
    xqc_usec_t              max_idle_timeout;

    /* 无状态重置令牌，用于在连接被无状态重置时标识连接 */
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];

    /* 指示是否存在无状态重置令牌 */
    uint8_t                 stateless_reset_token_present;

    /* 最大 UDP 负载大小，表示单个 QUIC 数据包的最大大小 */
    uint64_t                max_udp_payload_size;

    /* 初始流量控制窗口，表示连接上允许的最大数据量（以字节为单位） */
    uint64_t                initial_max_data;

    /* 本地双向流的初始最大数据量（以字节为单位） */
    uint64_t                initial_max_stream_data_bidi_local;

    /* 远端双向流的初始最大数据量（以字节为单位） */
    uint64_t                initial_max_stream_data_bidi_remote;

    /* 单向流的初始最大数据量（以字节为单位） */
    uint64_t                initial_max_stream_data_uni;

    /* 双向流的初始最大数量 */
    uint64_t                initial_max_streams_bidi;

    /* 单向流的初始最大数量 */
    uint64_t                initial_max_streams_uni;

    /* ACK 延迟指数，用于缩放 ACK 延迟值（默认值为 3） */
    uint64_t                ack_delay_exponent;

    /* 最大 ACK 延迟（以微秒为单位），表示发送 ACK 的最大延迟时间 */
    xqc_usec_t              max_ack_delay;

    /* 禁用主动迁移标志。如果设置为 1，则禁止连接迁移 */
    xqc_flag_t              disable_active_migration;

    /* 活跃连接 ID 的最大数量 */
    uint64_t                active_connection_id_limit;

    /* 初始源连接 ID，用于标识客户端的初始连接 ID */
    xqc_cid_t               initial_source_connection_id;

    /* 指示是否存在初始源连接 ID */
    uint8_t                 initial_source_connection_id_present;

    /* 重试源连接 ID，用于在重试过程中标识客户端的连接 ID */
    xqc_cid_t               retry_source_connection_id;

    /* 指示是否存在重试源连接 ID */
    uint8_t                 retry_source_connection_id_present;

    /* 
     * 支持 Datagram（RFC 9221）。
     * 默认值为 0，表示不支持 Datagram。
     * 特殊值 65535 表示接受 QUIC 数据包中任意长度的 Datagram 帧。
     */
    uint64_t                max_datagram_frame_size;

    /**
     * no_crypto 是 xQUIC 自定义的实验性传输参数。
     * 如果 no_crypto 设置为 1，则 xQUIC 不会对 0-RTT 或 1-RTT 数据包进行加密。
     * no_crypto 的作用仅限于当前连接，不适用于未来的连接，禁止存储该参数。
     * 注意：no_crypto 可能会被修改或移除，因为它不是官方参数。
     */
    uint64_t                no_crypto;

    /**
     * enable_multipath 是 xQUIC 自定义的实验性传输参数。
     * 如果 enable_multipath 设置为 1，则启用多路径 QUIC。
     * 
     * 参考：https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#section-3
     * enable_multipath 的作用仅限于当前连接，不适用于未来的连接，禁止存储该参数。
     * 注意：enable_multipath 可能会被修改或移除，因为它不是官方参数。
     */
    uint64_t                enable_multipath;

    /* 多路径版本，用于指定多路径 QUIC 的版本 */
    xqc_multipath_version_t   multipath_version;

} xqc_transport_params_t;



/**
 * encode transport parameters. 
 * @param params input transport parameter structure
 * @param exttype the occasion of transport parameter
 * @param out pointer of destination buffer
 * @param out_cap capacity of output data buffer
 * @param out_len encoded buffer len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_encode_transport_params(const xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, uint8_t *out, size_t out_cap, size_t *out_len);


/**
 * decode transport parameters. 
 * @param params output transport parameter structure
 * @param exttype the occasion of transport parameter
 * @param in encoded transport parameter buf
 * @param in_len encoded transport parameter buf len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_decode_transport_params(xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, const uint8_t *in, size_t in_len);


xqc_int_t xqc_read_transport_params(char *tp_data, size_t tp_data_len,
    xqc_transport_params_t *params);

ssize_t xqc_write_transport_params(char *tp_buf, size_t cap,
    const xqc_transport_params_t *params);

void xqc_init_transport_params(xqc_transport_params_t *params);


#endif /* XQC_TRANSPORT_PARAMS_H_ */