/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_frame.h"
#include "src/tls/xqc_tls_defs.h"

/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-14.2
 * In the absence of these mechanisms, QUIC endpoints SHOULD NOT send
 * datagrams larger than the smallest allowed maximum datagram size.
 */
/* without XQC_EXTRA_SPACE & XQC_ACK_SPACE */
#define XQC_MAX_PACKET_OUT_SIZE  XQC_QUIC_MAX_MSS
#define XQC_PACKET_OUT_SIZE      XQC_QUIC_MIN_MSS  
#define XQC_PACKET_OUT_EXT_SPACE (XQC_TLS_AEAD_OVERHEAD_MAX_LEN + XQC_ACK_SPACE)
#define XQC_PACKET_OUT_BUF_CAP   (XQC_MAX_PACKET_OUT_SIZE + XQC_PACKET_OUT_EXT_SPACE)

#define XQC_MAX_STREAM_FRAME_IN_PO  3

/*
XQC_POF_IN_FLIGHT：标记正在传输中的数据包（即，已发送但尚未收到确认的数据包）。
XQC_POF_LOST：表明被认为丢失的数据包。通常在重传超时（RTO）时间流逝后，没有收到确认时会发生这种情况。
XQC_POF_DCID_NOT_DONE：表示数据包的目的连接ID（Destination Connection ID）处理未完成。
XQC_POF_RESERVED：保留的标志位，可能用于未来的用途。
XQC_POF_TLP：表示尾部丢失探测数据包（Tail Loss Probe）。这些是特殊的数据包，用于在怀疑出现尾部丢失时探测路径状况。
XQC_POF_STREAM_UNACK：标记那些流数据未被确认的数据包。
XQC_POF_RETRANSED：标记已经被重传的数据包。
XQC_POF_NOTIFY：需要在数据包被确认、丢失等情况时通知用户。
XQC_POF_RESEND：表示需要重发的数据包。
XQC_POF_REINJECTED_ORIGIN：表示原始数据被重新注入。
XQC_POF_REINJECTED_REPLICA：表示副本数据被重新注入。
XQC_POF_IN_PATH_BUF_LIST：在路径缓冲列表中的数据包（FIXED：复制时重置）。
XQC_POF_IN_UNACK_LIST：在未确认列表中的数据包（FIXED：复制时重置）。
XQC_POF_NOT_SCHEDULE：表示不被调度的数据包。
XQC_POF_NOT_REINJECT：表示不被重新注入的数据包。
XQC_POF_DROPPED_DGRAM：表示已被丢弃的数据报。
XQC_POF_REINJECT_DIFF_PATH：表示经由不同路径重新注入的数据包。
XQC_POF_PMTUD_PROBING：表示进行路径最大传输单元发现（PMTUD）探测的数据包。
XQC_POF_QOS_HIGH：表示高质量服务（QoS）等级的数据包。
XQC_POF_QOS_PROBING：表示进行QoS探测的数据包
*/
typedef enum {
    XQC_POF_IN_FLIGHT           = 1 << 0,
    XQC_POF_LOST                = 1 << 1,
    XQC_POF_DCID_NOT_DONE       = 1 << 2,
    XQC_POF_RESERVED            = 1 << 3,
    XQC_POF_TLP                 = 1 << 4,
    XQC_POF_STREAM_UNACK        = 1 << 5,
    XQC_POF_RETRANSED           = 1 << 6,
    XQC_POF_NOTIFY              = 1 << 7,  /* need to notify user when a packet is acked, lost, etc. */
    XQC_POF_RESEND              = 1 << 8,
    XQC_POF_REINJECTED_ORIGIN   = 1 << 9,
    XQC_POF_REINJECTED_REPLICA  = 1 << 10,
    XQC_POF_IN_PATH_BUF_LIST    = 1 << 11, /* FIXED: reset when copy */
    XQC_POF_IN_UNACK_LIST       = 1 << 12, /* FIXED: reset when copy */
    XQC_POF_NOT_SCHEDULE        = 1 << 13,
    XQC_POF_NOT_REINJECT        = 1 << 14,
    XQC_POF_DROPPED_DGRAM       = 1 << 15,
    XQC_POF_REINJECT_DIFF_PATH  = 1 << 16,
    XQC_POF_PMTUD_PROBING       = 1 << 17,
    XQC_POF_QOS_HIGH            = 1 << 18,
    XQC_POF_QOS_PROBING         = 1 << 19,
} xqc_packet_out_flag_t;


typedef struct xqc_po_stream_frame_s {
    xqc_stream_id_t         ps_stream_id;
    uint64_t                ps_offset;
    unsigned int            ps_length;
    unsigned int            ps_type_offset; //流帧类型的偏移量，用于标记帧类型在数据包中的位置。
    unsigned int            ps_length_offset; //表示流帧长度字段在整个帧内的偏移位
    unsigned char           ps_is_used;  //标记该流帧结构是否已被使用。这通常用于管理内存和资源，确保数据结构得到有效利用。
    //表示流帧是否设置了FIN标志。FIN标志表示数据流的结束，即没有更多的数据被发送。
    unsigned char           ps_has_fin;     /* whether fin flag from stream frame is set  */
    //RESET_STREAM帧用于提前终止流，例如在发生错误或其他流的终止条件发生时。
    unsigned char           ps_is_reset;    /* whether frame is RESET_STREAM */
} xqc_po_stream_frame_t;

typedef struct xqc_packet_out_s {
    xqc_packet_t            po_pkt;  // 数据包基础信息,如包类型、包号等。
    xqc_list_head_t         po_list;

    /* pointers should carefully assign in xqc_packet_out_copy */
    unsigned char          *po_buf;  //数据包数据缓冲区。
    unsigned char          *po_ppktno;  //: 包号字段在po_buf中的偏移。
    unsigned char          *po_payload; //数据payload在po_buf中的偏移。
    xqc_packet_out_t       *po_origin;  //如果是重传,指向原始发送包。        /* point to original packet before retransmitted */
    void                   *po_user_data;  //用户自定义数据。     /* used to differ inner PING and user PING */
    unsigned char          *po_padding;  // 补位字段偏移,用于头部更改。      /* used to reassemble packets carrying new header */

    size_t                  po_buf_cap;        /* capcacity of po_buf */
    unsigned int            po_buf_size;     //po_buf可用总大小。     /* size of po_buf can be used */
    unsigned int            po_used_size; //po_buf中已使用大小
    unsigned int            po_enc_size;   //加密后的总大小      /* size of po after being encrypted */
    unsigned int            po_ack_offset; //ACK frame偏移。
    xqc_packet_out_flag_t   po_flag;
    /* Largest Acknowledged in ACK frame, initiated to be 0 */
    xqc_packet_number_t     po_largest_ack;  // ACK中确认的最大包号。
    xqc_usec_t              po_sent_time; //发送时间。
    xqc_frame_type_bit_t    po_frame_types; // 包含的frame类型位标志。

    /* the stream related to stream frame */
    xqc_po_stream_frame_t   po_stream_frames[XQC_MAX_STREAM_FRAME_IN_PO]; // STREAM frame信息。
    unsigned int            po_stream_frames_idx;

    uint32_t                po_origin_ref_cnt;  //原始包引用计数。 /* reference count of original packet */
    uint32_t                po_acked;//确认标志
    uint64_t                po_delivered;       /* the sum of delivered data before sending packet P */
    xqc_usec_t              po_delivered_time;  /* the time of last acked packet before sending packet P */
    xqc_usec_t              po_first_sent_time; /* the time of first sent packet during current sample period */
    xqc_bool_t              po_is_app_limited;

    /* For BBRv2 */
    /* the inflight bytes when the packet is sent (including itself) */
    uint64_t                po_tx_in_flight;  //发送时的在途字节数
    /* how many packets have been lost when the packet is sent */
    uint32_t                po_lost; //发送时已丢失的包数

    /* only meaningful if it contains a DATAGRAM frame */
    uint64_t                po_dgram_id; //路由标志

    /* Multipath */
    uint8_t                 po_path_flag;
    uint64_t                po_path_id; //发送路径ID。
    unsigned int            po_cc_size; /* TODO: check cc size != send size */

    /* Reinjection */
    uint64_t                po_stream_offset; //重新注入时的流偏移。
    uint64_t                po_stream_id;

    /* PMTUD Probing */
    size_t                  po_max_pkt_out_size;

    /* ping notification */
    xqc_ping_record_t      *po_pr;
} xqc_packet_out_t;

xqc_bool_t xqc_packet_out_on_specific_path(xqc_connection_t *conn, 
    xqc_packet_out_t *po, xqc_path_ctx_t **path);

xqc_bool_t xqc_packet_out_can_attach_ack(xqc_packet_out_t *po, 
    xqc_path_ctx_t *path, xqc_pkt_type_t pkt_type);

xqc_bool_t xqc_packet_out_can_pto_probe(xqc_packet_out_t *po, uint64_t path_id);

void xqc_packet_out_remove_ack_frame(xqc_packet_out_t *po);

xqc_packet_out_t *xqc_packet_out_create(size_t po_buf_cap);

void xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src);

xqc_packet_out_t *xqc_packet_out_get(xqc_send_queue_t *send_queue);

xqc_packet_out_t *xqc_packet_out_get_and_insert_send(xqc_send_queue_t *send_queue, enum xqc_pkt_type pkt_type);

void xqc_packet_out_destroy(xqc_packet_out_t *packet_out);

void xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

xqc_packet_out_t *xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type);

xqc_packet_out_t *xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need);

xqc_packet_out_t *xqc_write_packet_for_stream(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need,
    xqc_stream_t *stream);

int xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_int_t xqc_write_ack_or_mp_ack_to_packets(xqc_connection_t *conn);

xqc_int_t xqc_write_ack_or_mp_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, 
    xqc_pkt_num_space_t pns, xqc_path_ctx_t *path, xqc_bool_t is_mp_ack);

int xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

int xqc_write_ping_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, 
    void *po_user_data, xqc_bool_t notify, xqc_ping_record_t *pr);

int xqc_write_conn_close_to_packet(xqc_connection_t *conn, uint64_t err_code);

int xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code, uint64_t final_size);

int xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code);

int xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit);

int xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

int xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional);

int xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data);

int xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, 
xqc_stream_id_t stream_id, uint64_t max_stream_data, xqc_pkt_type_t xqc_pkt_type);

int xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional);

int xqc_write_new_token_to_packet(xqc_connection_t *conn);

int xqc_write_stream_frame_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, xqc_pkt_type_t pkt_type,
    uint8_t fin, const unsigned char *payload, size_t payload_size, size_t *send_data_written);

int xqc_write_datagram_frame_to_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, 
    const unsigned char *data, size_t data_len, uint64_t *dgram_id, xqc_bool_t use_supplied_dgram_id,
    xqc_data_qos_level_t qos_level);

int xqc_write_handshake_done_frame_to_packet(xqc_connection_t *conn);

xqc_int_t xqc_write_new_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t retire_prior_to);

xqc_int_t xqc_write_retire_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t seq_num);

xqc_int_t xqc_write_path_challenge_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, 
    xqc_bool_t attach_path_status);

xqc_int_t xqc_write_path_response_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path,
    unsigned char *path_response_data);

int xqc_write_ack_mp_to_one_packet(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

xqc_int_t xqc_write_path_abandon_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_write_path_status_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_write_path_standby_or_available_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

int xqc_write_pmtud_ping_to_packet(xqc_path_ctx_t *path, size_t probing_size, xqc_pkt_type_t pkt_type);


#endif /* _XQC_PACKET_OUT_H_INCLUDED_ */
