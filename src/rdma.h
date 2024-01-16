#ifndef __RDMA_H_
#define __RDMA_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>

typedef enum RdmaCmdType
{
    REG_LOCAL_ADDR, /* register local addr */
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

typedef struct RdmaConn
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

    /* Physical memory TX mr over RDMA */
    uint32_t tx_pa_rkey; /* remote key */

    /* CMD 0 ~ RDMA_MAX_SGE for recv buffer
     * RDMA_MAX_SGE ~ 2 * RDMA_MAX_SGE - 1 for send buffer
     */
    RdmaCmd *cmd_buf;
    struct ibv_mr *cmd_mr;
    RdmaWrCtx *rx_ctx;
    RdmaWrCtx *tx_ctx;

    pthread_cond_t status_cond;
    pthread_mutex_t status_mutex;
} RdmaConn;

typedef struct RdmaListener
{
    struct rdma_cm_id *cm_id;
    struct rdma_event_channel *cm_channel;
} RdmaListener;

/* common RDMA interfaces/handlers */

/* RDMA server side interfaces */
int rdmaServer(RdmaListener **listener, char *ip, int port);
int rdmaServerStart(RdmaListener *listener);
int rdmaServerStop(RdmaListener *listener);
void rdmaServerRelease(RdmaListener *listener);

/* RDMA client side interfaces */
RdmaConn *rdmaConn(void);
int rdmaConnect(RdmaConn *conn, char *serverip, int port);
void rdmaConnClose(RdmaConn *conn);

void rdmaRuntimeStop(void);

/* data plane interfaces. Signaled by default. */
size_t rdmaConnSend(RdmaConn *conn, void *data, size_t data_len);
/* size_t rdmaConnSendWithImm(RdmaConn *conn, uint32_t imm_data, const void *data, size_t data_len); */
size_t rdmaConnWrite(RdmaConn *conn, const void *data, size_t data_len);
int rdmaConnWriteWithImm(RdmaConn *conn, uint32_t imm_data, const void *data, size_t data_len);
int rdmaConnRead(RdmaConn *conn, void *data_buf, size_t buf_len);

/* physical memory access interfaces */
int rdmaSyncWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                          uint32_t lkey, uint64_t remote_addr, uint32_t length);
int rdmaSyncReadSignaled(RdmaConn *conn, uint64_t local_addr,
                         uint32_t lkey, uint64_t remote_addr, uint32_t length);

/* RDMA tracing and debug helpers */
// #define NDEBUG 1

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