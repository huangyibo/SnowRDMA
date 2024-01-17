#ifndef __RDMA_H_
#define __RDMA_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>

typedef struct RdmaConn RdmaConn;

/* callback funcs for RDMA connection level in Async communication (Non-Blocking) */
typedef void (*RdmaRecvCallbackFunc)(RdmaConn *conn, void *data, size_t data_len);
typedef void (*RdmaConnectedCallbackFunc)(RdmaConn *conn);
typedef void (*RdmaDisconnectCallbackFunc)(RdmaConn *conn);
typedef void (*RdmaAcceptCallbackFunc)(RdmaConn *conn);

typedef enum RdmaCmdType
{
    REG_LOCAL_ADDR, /* register local addr */
    REG_PHYS_ADDR,  /* register physical mem */
    CONN_GOODBYE,       /* disconnect cmd between server and client */
} RdmaCmdType;

typedef struct RdmaCmd
{
    uint8_t magic;
    uint8_t version;
    uint8_t cmd_opcode;
    uint8_t rsvd[13];
    uint64_t addr;
    uint32_t length;
    uint32_t key;
} RdmaCmd;

#define MIN(a, b) (a) < (b) ? a : b
#define RDMA_MAX_SGE 1024
#define RDMA_DEFAULT_RX_LEN (1024 * 1024)
#define RDMA_CMD_MAGIC 'R'

/* Error codes */
#define RDMA_OK 0
#define RDMA_ERR -1

extern int rdmaListenBacklog;
extern int rdmaTimeoutms;
extern int rdmaPollEventTimeoutms;
extern int rdmaMaxInlineData; /* max inline data enabled by RNIC,
                                    0 indicate no inline optimization. */
extern int rdmaRetryCount;
extern int rdmaRnrRetryCount;
extern int rdmaMaxConcurrentWorkRequests; /* used to handle a batch of CQEs */
extern int rdmaRecvDepth;

extern int rdmaQp2CqMode;             /* One QP to One CQ by default */
extern int rdmaCommMode;              /* Blocking by default */
extern bool rdmaEnablePhysAddrAccess; /* disable by default */

typedef enum
{
    ONE_TO_ONE = 0, /* One QP is mapped to one CQ */
    MANY_TO_ONE,    /* Many QP is mapped to one CQ */
} RdmaQpCqMapping;

/* RDMA communication mode: SYNC (Blocking), ASYNC (Non-Blocking) */
typedef enum
{
    RDMA_BLOCKING = 0,
    RDMA_NON_BLOCKING,
} RdmaCommMode;

typedef struct RdmaOptions
{

    /* set the number of backlog for RDMA Listener when rdma_listen().
     * Default: 128
     */
    int rdma_listen_backlog;

    /** set timeout (ms) value for rdma_resolve_addr() and rdma_resolve_route().
     * Default: 1000 ms
     */
    int rdma_timeoutms;

    /** set the timeout (ms) value for poll() when polling RDMA cm event channel
     * and completion event channel.
     *  Default: 10 ms
     */
    int rdma_poll_event_timeoutms;

    /** the max inline data size enabled by RNIC. 0 indicate no inline optimization.
     * Default: 0
     */
    int rdma_max_inline_data;

    /** set the retry times for rdma_connect() and rdma_listen().
     * Default: 7
     */
    int rdma_retry_count;

    /** set the maximum number of times that a send operation from the remote peer
     * should be retried on a connection after receiving a receiver not ready (RNR)
     * error. RNR errors are generated when a send request arrives before a buffer
     * has been posted to receive the incoming data. Applies only to RDMA_PS_TCP.
     * Default: 7
     */
    int rdma_rnr_retry_count;

    /** set the maximum number of concurrent work requests for one ibv_poll_cq()
     * invocation. This can be used to handle a batch of CQEs for a better
     * throughput.
     * Default: 128 + 2048 * 2
     */
    int rdma_max_concurrent_work_requests;

    /** set the recv depth of RDMA recv buffers for ibv_post_recv() in two-sided
     * messaging verbs.
     * Default: 1024
     */
    int rdma_recv_depth;

    /** set the mode of RDMA QP instances to CQ instance mapping relationship.
     * Default: MANY_TO_ONE
     */
    RdmaQpCqMapping rdma_qp2cq_mode;

    /** set the mode of RDMA communication: SYNC (Blocking), ASYNC (Non-Blocking)
     * Default: RDMA_NON_BLOCKING
     */
    RdmaCommMode rdma_comm_mode;

    /** set whehther enable Remote Direct Physical Memory Access (RDPMA).
     * Default: false
     */
    bool rdma_enable_phys_addr_access;

    RdmaRecvCallbackFunc recv_callback;
    RdmaConnectedCallbackFunc connected_callback;
    RdmaDisconnectCallbackFunc disconnect_callback;
    RdmaAcceptCallbackFunc accept_callback;
} RdmaOptions;

typedef RdmaOptions RdmaServerOptions;
typedef RdmaOptions RdmaConnOptions;

typedef enum
{
    CONN_STATE_NONE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_ACCEPTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_MR_READY,
    CONN_STATE_CLOSED,
    CONN_STATE_ERROR,
} ConnectionState;

typedef enum
{
    ACCEPTED_CONN = 0, /* server side accept */
    CONNECTED_CONN,    /* client side connect */
} ConnectionType;

/* used to describe the type of Work Request Context for different RDMA opcodes */
typedef enum
{
    RECV_CONTEXT,
    WRITE_CONTEXT,
    SEND_CONTEXT,
} RdmaReqCtxType;

typedef struct RdmaWrCtx
{
    RdmaReqCtxType type;
    void *rdma_conn;    /* RdmaConn in this case */
    void *private_data; /* For example, RdmaCmd context in IBV_WC_RECV */
} RdmaWrCtx;

struct RdmaConn
{
    struct rdma_cm_id *cm_id;
    int last_errno;
    ConnectionState state;
    ConnectionType type;

    char *ip;
    int port;
    struct ibv_pd *pd;
    struct rdma_event_channel *cm_channel;
    struct ibv_comp_channel *comp_channel;
    struct ibv_cq *cq;
    uint32_t max_inline_data;

    /* TX */
    char *tx_addr; /* remote side */
    uint32_t tx_length;
    uint32_t tx_offset;
    uint32_t tx_key;
    char *send_buf; /* local side */
    uint32_t send_length;
    uint32_t send_offset;
    uint32_t send_ops;
    struct ibv_mr *send_mr;

    /* RX */
    uint32_t rx_offset;
    char *recv_buf;
    unsigned int recv_length;
    unsigned int recv_offset;
    struct ibv_mr *recv_mr;

    /* Physical memory TX mr over RDMA.
     * Note that when register full physical memory,
     * the phys addr is NULL and the MR length is 0. */
    uint32_t tx_pa_rkey; /* remote key */
    char *tx_pa_addr;    /* remote physical memory */
    unsigned int tx_pa_length;
    unsigned int tx_pa_offset;

    /* CMD 0 ~ RDMA_MAX_SGE for recv buffer
     * RDMA_MAX_SGE ~ 2 * RDMA_MAX_SGE - 1 for send buffer
     */
    RdmaCmd *cmd_buf;
    struct ibv_mr *cmd_mr;
    RdmaWrCtx *rx_ctx;
    RdmaWrCtx *tx_ctx;

    pthread_cond_t status_cond;
    pthread_mutex_t status_mutex;

    RdmaConnOptions options;

    /* callbacks for control and data plane */
    RdmaRecvCallbackFunc recv_callback;
    RdmaConnectedCallbackFunc connected_callback;
    RdmaDisconnectCallbackFunc disconnect_callback;
};

typedef struct RdmaListener
{
    struct rdma_cm_id *cm_id;
    struct rdma_event_channel *cm_channel;
    RdmaServerOptions options;

    /* callbacks for server-side control plane */
    RdmaAcceptCallbackFunc accept_callback;
} RdmaListener;

/* common RDMA interfaces/handlers */

/* RDMA server side interfaces */
int rdmaServer(RdmaListener **listener, const char *ip,
               const int port, const RdmaServerOptions *opt);
int rdmaServerStart(RdmaListener *listener);
int rdmaServerStop(RdmaListener *listener);
void rdmaServerRelease(RdmaListener *listener);
int rdmaServerSetAcceptCallback(RdmaListener *listener, RdmaAcceptCallbackFunc func);

/* RDMA client side interfaces */
RdmaConn *rdmaConn(const RdmaServerOptions *opt);
int rdmaConnect(RdmaConn *conn, char *serverip, int port);
void rdmaConnClose(RdmaConn *conn);
int rdmaConnSetRecvCallback(RdmaConn *conn, RdmaRecvCallbackFunc func);
int rdmaConnSetConnectedCallback(RdmaConn *conn, RdmaConnectedCallbackFunc func);
int rdmaConnSetDisconnectCallback(RdmaConn *conn, RdmaDisconnectCallbackFunc func);

void rdmaRuntimeStop(void);

/* data plane interfaces. Signaled by default. */
size_t rdmaConnSend(RdmaConn *conn, void *data, size_t data_len);
/* size_t rdmaConnSendWithImm(RdmaConn *conn, uint32_t imm_data, const void *data, size_t data_len); */
size_t rdmaConnWrite(RdmaConn *conn, const void *data, size_t data_len);
int rdmaConnWriteWithImm(RdmaConn *conn, uint32_t imm_data,
                         const void *data, size_t data_len);
int rdmaConnRead(RdmaConn *conn, void *data_buf, size_t buf_len);

/* RDMA blocking interfaces that require RDMA_BLOCKING mode.
 * Assume that remote addr is RDMA-registered before use.
 */
int rdmaSyncWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                          uint32_t lkey, uint64_t remote_addr,
                          uint32_t rkey, uint32_t length);
int rdmaSyncReadSignaled(RdmaConn *conn, uint64_t local_addr,
                         uint32_t lkey, uint64_t remote_addr,
                         uint32_t rkey, uint32_t length);

/* RDMA physical memory access interfaces. */
int rdmaPAWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                        uint32_t lkey, uint64_t remote_addr, uint32_t length);
int rdmaPAReadSignaled(RdmaConn *conn, uint64_t local_addr,
                       uint32_t lkey, uint64_t remote_addr, uint32_t length);

/* RDMA blocking interfaces require RDMA_BLOCKING mode */
int rdmaPASyncWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                            uint32_t lkey, uint64_t remote_addr, uint32_t length);
int rdmaPASyncReadSignaled(RdmaConn *conn, uint64_t local_addr,
                           uint32_t lkey, uint64_t remote_addr, uint32_t length);

/* RDMA tracing and debug helpers */

#ifdef NDEBUG
#define rdmaDebug(fmt, ...)
#else
#define rdmaDebug(fmt, ...) \
    fprintf(stdout, "[DEBUG] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define rdmaInfo(fmt, ...) \
    fprintf(stdout, "[INFO] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define rdmaWarn(fmt, ...) \
    fprintf(stdout, "[WARN] (%s:%d: errno: %s) " fmt "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define rdmaErr(fmt, ...) \
    fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " fmt "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#endif // !__RDMA_H_