#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>

#include "common.h"
#include "rdma.h"
#include "rdma_helpers.h"

#define ANET_ERR_LEN 256
#define NET_IP_STR_LEN 46 /* INET6_ADDRSTRLEN is 46, but we need to be sure */

#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#define MIN(a, b) (a) < (b) ? a : b

/* RDMA Flags environment variables */
int rdmaListenBacklog = 128;
int rdmaTimeoutms = 1000;
int rdmaPollEventTimeoutms = 10;
int rdmaMaxInlineData = 0; /* max inline data enabled by RNIC,
                                    0 indicate no inline optimization. */
int rdmaRetryCount = 7;
int rdmaRnrRetryCount = 7;
int rdmaMaxConcurrentWorkRequests = 128 + 2048 * 2; /* used to handle a batch of CQEs */
int rdmaRecvDepth = RDMA_MAX_SGE;

int rdmaQp2CqMode = ONE_TO_ONE;
int rdmaCommMode = RDMA_NON_BLOCKING;
bool rdmaEnablePhysAddrAccess = false;

/* a global RDMA context structure.
 * Note that all members in this context are globally shared.
 * Each RDMA ib device (i.e., each port) has unique ibv_context.
 * So we assume that all RDMA QPs over the same ibv_context share
 * the globally unique PD, CQ, and completion channel instance.
 * A dedicated worker thread will be created to process CQ for
 * each IB context.
 */
struct rdma_context
{
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp_channel;

    /* RDMA-registered physical memory */
    struct ibv_mr *phys_mr;

    pthread_t cq_poller_thread;
};

/* global RDMA-related variables */
static struct rdma_context *g_ctx;
static atomic_bool g_should_stop = ATOMIC_VAR_INIT(false);
static atomic_bool c_should_stop = ATOMIC_VAR_INIT(false);

static struct rdma_event_channel *g_cm_channel;
static pthread_t g_ev_poller_thread;                                 /* used to process rdma event channel */
static atomic_bool g_ev_poller_should_stop = ATOMIC_VAR_INIT(false); /* false by default*/

static void *rdmaPollCQ(void *);
static void *rdmaCompChannelStart(void *ptr);
static int rdmaContextInit(struct ibv_context *verbs);
static void rdmaContextRelease(void);
static int rdmaConnCreate(struct rdma_cm_id *id, RdmaConn *conn);
static void rdmaConnRelease(RdmaConn *conn);
static void *rdmaCmChannelStart(void *ptr); /* run in a thread */

/* common RDMA helpers and handlers */
static int rdmaPollEvents(struct rdma_event_channel *event_channel, void *poll_ctx);
static int rdmaOnConnectRequest(struct rdma_cm_event *ev);
static int rdmaOnAddrResolved(struct rdma_cm_event *ev);
static int rdmaOnRouteResolved(struct rdma_cm_event *ev);
static int rdmaOnConnected(struct rdma_cm_event *ev, void *poll_ctx);
static int rdmaOnDisconnected(struct rdma_cm_event *ev);
static int rdmaOnRejected(struct rdma_cm_event *ev);

static int connRdmaSyncRxMr(RdmaConn *conn, struct rdma_cm_id *cm_id);
static int connRdmaSyncPhysRxMr(RdmaConn *conn, struct rdma_cm_id *cm_id);
static int connRdmaSayBye(RdmaConn *conn, struct rdma_cm_id *cm_id);

// static int rdmaRegSendbuf(RdmaConn *conn, unsigned int length);
static int rdmaSendCommand(RdmaConn *conn, struct rdma_cm_id *id, RdmaCmd *cmd, void *tx_ctx);
// static int rdmaConnRegisterRx(RdmaConn *conn, struct rdma_cm_id *id);

static int rdmaConnHandleRecv(RdmaConn *conn, struct rdma_cm_id *cm_id,
                              RdmaCmd *cmd, RdmaWrCtx *wr_ctx, uint32_t byte_len);
static int rdmaConnHandleSend(RdmaConn *conn, RdmaCmd *cmd);

static inline void rdmaSetDefaultOptions(RdmaOptions *dst_opt)
{
    if (dst_opt)
    {
        dst_opt->rdma_listen_backlog = 128;
        dst_opt->rdma_timeoutms = 1000;
        dst_opt->rdma_poll_event_timeoutms = 10;
        dst_opt->rdma_max_inline_data = 0;
        dst_opt->rdma_retry_count = 7;
        dst_opt->rdma_rnr_retry_count = 7;
        dst_opt->rdma_max_concurrent_work_requests = 128 + 2048 * 2;
        dst_opt->rdma_recv_depth = RDMA_MAX_SGE;
        dst_opt->rdma_qp2cq_mode = MANY_TO_ONE;
        dst_opt->rdma_comm_mode = RDMA_NON_BLOCKING;
        dst_opt->rdma_enable_phys_addr_access = false;
    }
}

static inline void rdmaSetGlobalEnv(const RdmaOptions *opt)
{
    if (!opt)
        return;

    if (opt->rdma_poll_event_timeoutms > 0)
    {
        rdmaPollEventTimeoutms = opt->rdma_poll_event_timeoutms;
    }

    if (opt->rdma_max_inline_data > 0)
    {
        rdmaMaxInlineData = opt->rdma_max_inline_data;
    }

    if (opt->rdma_retry_count > 0)
    {
        rdmaRetryCount = opt->rdma_retry_count;
    }

    if (opt->rdma_rnr_retry_count)
    {
        rdmaRnrRetryCount = opt->rdma_rnr_retry_count;
    }

    if (opt->rdma_max_concurrent_work_requests > 0)
    {
        rdmaMaxConcurrentWorkRequests = opt->rdma_max_concurrent_work_requests;
    }

    if (opt->rdma_qp2cq_mode >= 0)
    {
        rdmaQp2CqMode = (opt->rdma_comm_mode == RDMA_BLOCKING) ? ONE_TO_ONE : opt->rdma_qp2cq_mode;
    }

    if (opt->rdma_comm_mode >= 0)
    {
        rdmaCommMode = opt->rdma_comm_mode;
    }

    if (opt->rdma_recv_depth > 0)
    {
        rdmaRecvDepth = opt->rdma_recv_depth;
    }

    rdmaEnablePhysAddrAccess = opt->rdma_enable_phys_addr_access;
}

static inline void rdmaConnSetEnv(RdmaConn *conn, const RdmaOptions *opt)
{
    if (!opt)
        return;

    if (opt->rdma_comm_mode == RDMA_BLOCKING)
    {
        conn->options.rdma_qp2cq_mode = ONE_TO_ONE;
    }
    if (opt->rdma_recv_depth > 0)
    {
        conn->options.rdma_recv_depth = opt->rdma_recv_depth;
    }
    if (opt->rdma_timeoutms > 0)
    {
        conn->options.rdma_timeoutms = opt->rdma_timeoutms;
    }
    if (opt->recv_callback)
    {
        rdmaConnSetRecvCallback(conn, opt->recv_callback);
    }
    if (opt->write_callback)
    {
        rdmaConnSetWriteCallback(conn, opt->write_callback);
    }
    if (opt->read_callback)
    {
        rdmaConnSetReadCallback(conn, opt->read_callback);
    }
    if (opt->connected_callback)
    {
        rdmaConnSetConnectedCallback(conn, opt->connected_callback);
    }
    if (opt->disconnect_callback)
    {
        rdmaConnSetDisconnectCallback(conn, opt->disconnect_callback);
    }
}

/* To make RDMA apps forkable, buffer which is registered as RDMA
 * memory region should be aligned to page size. And the length
 * also need to be aligned to page size.
 */
static void *page_aligned_alloc(size_t size)
{
    void *tmp;
    size_t aligned_size, page_size = sysconf(_SC_PAGESIZE);

    aligned_size = (size + page_size - 1) & (~(page_size - 1));
    if (posix_memalign(&tmp, page_size, aligned_size))
    {
        rdmaErr("posix_memalign failed");
        return NULL;
    }

    memset(tmp, 0x00, aligned_size);

    return tmp;
}

static int rdmaPostRecv(RdmaConn *ctx, struct rdma_cm_id *cm_id, RdmaCmd *cmd, void *rx_ctx)
{
    struct ibv_sge sge;
    size_t length = sizeof(RdmaCmd);
    struct ibv_recv_wr recv_wr, *bad_wr;
    int ret;

    sge.addr = (uint64_t)cmd;
    sge.length = length;
    sge.lkey = ctx->cmd_mr->lkey;

    recv_wr.wr_id = (uint64_t)rx_ctx;
    recv_wr.sg_list = &sge;
    recv_wr.num_sge = 1;
    recv_wr.next = NULL;

    ret = ibv_post_recv(cm_id->qp, &recv_wr, &bad_wr);
    if (ret && (ret != EAGAIN))
    {
        rdmaWarn("RDMA: post recv failed: %d", ret);
        return RDMA_ERR;
    }

    return RDMA_OK;
}

static void rdmaDestroyIoBuf(RdmaConn *conn)
{
    if (conn->recv_mr)
    {
        ibv_dereg_mr(conn->recv_mr);
        conn->recv_mr = NULL;
    }

    if (conn->recv_buf)
    {
        free(conn->recv_buf);
        conn->recv_buf = NULL;
    }

    if (conn->send_mr)
    {
        ibv_dereg_mr(conn->send_mr);
        conn->send_mr = NULL;
    }

    if (conn->send_buf)
    {
        free(conn->send_buf);
        conn->send_buf = NULL;
    }

    if (conn->cmd_mr)
    {
        ibv_dereg_mr(conn->cmd_mr);
        conn->cmd_mr = NULL;
    }

    if (conn->cmd_buf)
    {
        free(conn->cmd_buf);
        conn->cmd_buf = NULL;
    }

    if (conn->rx_ctx)
    {
        free(conn->rx_ctx);
        conn->rx_ctx = NULL;
    }

    if (conn->tx_ctx)
    {
        free(conn->tx_ctx);
        conn->tx_ctx = NULL;
    }
}

/* register RDMA MRs for two-sided messaging and one-sided memory */
static int rdmaSetupIoBuf(RdmaConn *conn, struct rdma_cm_id *cm_id)
{
    int access = IBV_ACCESS_LOCAL_WRITE;
    size_t length = sizeof(RdmaCmd) * rdmaRecvDepth * 2;
    RdmaCmd *cmd;
    RdmaWrCtx *rx_ctx;
    int i;

    /* setup RDMA cmd buf for two-sided messaging */
    conn->cmd_buf = page_aligned_alloc(length);
    conn->cmd_mr = ibv_reg_mr(conn->pd, conn->cmd_buf, length, access);
    if (!conn->cmd_mr)
    {
        rdmaWarn("RDMA: reg mr for CMD error %d (%s)", errno, strerror(errno));
        goto err;
    }

    /* setup RDMAQ work request contexts for two-sided messaging */
    length = sizeof(RdmaWrCtx) * rdmaRecvDepth;
    conn->rx_ctx = page_aligned_alloc(length);
    conn->tx_ctx = page_aligned_alloc(length);

    for (i = 0; i < rdmaRecvDepth; i++)
    {
        cmd = conn->cmd_buf + i;
        rx_ctx = conn->rx_ctx + i;

        rx_ctx->type = RECV_CONTEXT;
        rx_ctx->rdma_conn = (void *)conn;
        rx_ctx->private_data = (void *)cmd;

        if (rdmaPostRecv(conn, cm_id, cmd, (void *)rx_ctx) == RDMA_ERR)
        {
            rdmaWarn("RDMA: post recv failed");
            goto err;
        }
    }

    /* setup RDMA data buf for one-sided verbs */
    length = RDMA_DEFAULT_RX_LEN;
    conn->recv_buf = page_aligned_alloc(length);
    conn->recv_length = length;
    conn->recv_mr = rdma_reg_mem(conn->pd, conn->recv_buf, conn->recv_length);
    if (!conn->recv_mr)
    {
        rdmaWarn("RDMA: reg mr for RDMA recv buf error %d (%s)", errno, strerror(errno));
        goto err;
    }

    return RDMA_OK;

err:
    rdmaDestroyIoBuf(conn);
    return RDMA_ERR;
}

static int rdmaAdjustSendbuf(RdmaConn *conn, unsigned int length)
{
    if (length == conn->send_length)
        return RDMA_OK;

    /* try to free old send MR & buffer */
    if (conn->send_length)
    {
        ibv_dereg_mr(conn->send_mr);
        free(conn->send_buf);
        conn->send_length = 0;
    }

    /* setup new send MR & buffer */
    conn->send_length = length;
    conn->send_buf = page_aligned_alloc(conn->send_length);
    conn->send_mr = rdma_reg_mem(conn->pd, conn->send_buf, conn->send_length);
    if (!conn->send_mr)
    {
        rdmaErr("RDMA: reg send mr failed %d(%s)", errno, strerror(errno));
        free(conn->send_buf);
        conn->send_buf = NULL;
        conn->send_length = 0;
        return RDMA_ERR;
    }

    return RDMA_OK;
}

static int rdmaConnHandleRecvImm(RdmaConn *conn, struct rdma_cm_id *cm_id,
                                 RdmaCmd *cmd, RdmaWrCtx *wr_ctx,
                                 struct ibv_wc *wc, uint32_t byte_len)
{
    uint32_t rx_offset = ntohl(wc->imm_data);
    char *rx_buffer = conn->recv_buf + rx_offset;

    if (unlikely(rx_offset + byte_len > conn->recv_length))
    {
        rdmaErr("RDMA: recv buffer overflow. Please adjust RDMA MR");
        return RDMA_ERR;
    }
    conn->rx_offset += byte_len;

    if (conn->recv_callback)
    {
        conn->recv_callback(conn, rx_buffer, byte_len);
    }

    return rdmaPostRecv(conn, cm_id, cmd, wr_ctx);
}

/* rdma common helpers */
int rdmaContextInit(struct ibv_context *verbs)
{
    if (g_ctx)
    {
        if (g_ctx->ctx != verbs)
        {
            rdmaWarn("cannot handle events in more than one IB context");
        }

        return RDMA_OK;
    }

    /* The ibv_fork_init() func initializes libibverbs'data structures to handle
     * fork() func calls correctly and avoid data corruption.
     */
    if (ibv_fork_init())
    {
        rdmaWarn("RDMA: FATAL error, ibv_fork_init failed");
    }

    g_ctx = (struct rdma_context *)malloc(sizeof(struct rdma_context));
    assert(g_ctx);

    g_ctx->ctx = verbs;

    g_ctx->pd = ibv_alloc_pd(g_ctx->ctx);
    if (!g_ctx->pd)
    {
        rdmaErr("RDMA: ibv alloc pd failed");
        goto err;
    }

    /* register RDMA-enabled physical memory when enabled */
    if (rdmaEnablePhysAddrAccess)
    {
        g_ctx->phys_mr = rdma_exp_reg_phys_mem_full(g_ctx->pd);
        if (!g_ctx->phys_mr)
        {
            rdmaErr("RDMA: ibv exp reg mr error");
            goto err;
        }
    }

    g_ctx->comp_channel = ibv_create_comp_channel(g_ctx->ctx);
    if (!g_ctx->comp_channel)
    {
        rdmaErr("RDMA: ibv create comp channel failed");
        goto err;
    }

    g_ctx->cq = ibv_create_cq(g_ctx->ctx, RDMA_MAX_SGE * 2, NULL, g_ctx->comp_channel, 0);
    if (!g_ctx->cq)
    {
        rdmaErr("RDMA: ibv create cq failed");
        goto err;
    }
    ibv_req_notify_cq(g_ctx->cq, 0);

    pthread_create(&g_ctx->cq_poller_thread, NULL, rdmaCompChannelStart, (void *)g_ctx);

    return RDMA_OK;
err:
    rdmaContextRelease();
    return RDMA_ERR;
}

static void rdmaContextRelease(void)
{
    if (!g_ctx)
        return;

    if (g_ctx->cq)
    {
        ibv_destroy_cq(g_ctx->cq);
    }

    if (g_ctx->comp_channel)
    {
        ibv_destroy_comp_channel(g_ctx->comp_channel);
    }

    if (g_ctx->pd)
    {
        ibv_dealloc_pd(g_ctx->pd);
    }

    /* dealloc other rdma resources like mw here */
}

void rdmaRuntimeStop()
{
    /* wait for poller thread */
    atomic_store(&g_should_stop, true);
    atomic_store(&c_should_stop, true);
    pthread_join(g_ev_poller_thread, NULL);

    if (g_ctx)
    {
        pthread_join(g_ctx->cq_poller_thread, NULL);
    }

    rdmaContextRelease();
    if (g_cm_channel)
        rdma_destroy_event_channel(g_cm_channel);
}

struct ibv_mr *rdmaConnRegMem(RdmaConn *conn, size_t size)
{
    void *buf;

    buf = malloc(size);
    if (!buf)
        return NULL;
    memset(buf, 0, size);

    return rdma_reg_mem(conn->pd, buf, size);
}

void rdmaConnDeregMem(RdmaConn *conn, struct ibv_mr *mr)
{
    void *buf = mr->addr;
    rdma_dereg_mem(mr);
    free(buf);
    buf = NULL;
}

int rdmaConnHandleRecv(RdmaConn *conn, struct rdma_cm_id *cm_id,
                       RdmaCmd *cmd, RdmaWrCtx *wr_ctx, uint32_t byte_len)
{
    if (unlikely(byte_len != sizeof(RdmaCmd)))
    {
        rdmaErr("RDMA: FATAL error, recv corrupted cmd");
        return RDMA_ERR;
    }

    switch (cmd->cmd_opcode)
    {
    case REG_LOCAL_ADDR:
        conn->tx_addr = (char *)cmd->addr;
        conn->tx_length = ntohl(cmd->length);
        conn->tx_key = ntohl(cmd->key);
        conn->tx_offset = 0;
        rdmaAdjustSendbuf(conn, conn->tx_length);

        /* notify the waiting side once connected */
        conn->state = RDMA_CONN_STATE_MR_READY;
        if (conn->type == CONNECTED_CONN)
        {
            pthread_mutex_lock(&conn->status_mutex);
            pthread_cond_broadcast(&conn->status_cond); /* signal waiting threads */
            pthread_mutex_unlock(&conn->status_mutex);
        }
        break;

    case REG_PHYS_ADDR:
        conn->tx_pa_addr = (char *)cmd->addr;
        conn->tx_pa_length = ntohl(cmd->length);
        conn->tx_pa_rkey = ntohl(cmd->key);
        conn->tx_pa_offset = 0;
        break;

    case CONN_GOODBYE:
        rdmaInfo("RDMA: disconnect with host %s:%d", conn->ip, conn->port);
        // rdma_disconnect(cm_id);

        break;

    default:
        rdmaErr("RDMA: FATAL error, unknown RDMA cmd");
        return RDMA_ERR;
    }

    return rdmaPostRecv(conn, cm_id, cmd, wr_ctx);
}

int rdmaConnHandleSend(RdmaConn *conn, RdmaCmd *cmd)
{
    /* mark this RDMA cmd has already sent */
    cmd->magic = 0;

    switch (cmd->cmd_opcode)
    {
    case CONN_GOODBYE:
        /* start disconnect once the CONN_GOODBYE msg arrives at peer host. */
        rdma_disconnect(conn->cm_id);
        break;

    default:
        break;
    }

    return RDMA_OK;
}

void *rdmaPollCQ(void *ctx_ptr)
{
    struct rdma_cm_id *id;
    struct rdma_context *ctx = (struct rdma_context *)ctx_ptr;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    struct ibv_wc wc[rdmaMaxConcurrentWorkRequests];
    RdmaCmd *cmd;
    RdmaConn *conn;
    RdmaWrCtx *wr_ctx;
    int num_ev, i;
    assert(ctx_ptr);

    /* wait for the completion event */
    if (ibv_get_cq_event(ctx->comp_channel, &ev_cq, &ev_ctx) < 0)
    {
        if (errno != EAGAIN)
        {
            rdmaWarn("RDMA: get CQ event error %s", strerror(errno));
            return NULL;
        }
    }

    /*  ack the event */
    ibv_ack_cq_events(ev_cq, 1);

    /* request notification upon the next completion event */
    if (ibv_req_notify_cq(ev_cq, 0))
    {
        rdmaWarn("RDMA: notify CQ error %s", strerror(errno));
        return NULL;
    }

    /* empty the CQ by polling all of the cvompletions from the CQ (if any exist) */
pollcq:
    num_ev = ibv_poll_cq(ctx->cq, rdmaMaxConcurrentWorkRequests, wc);
    if (num_ev < 0)
    {
        rdmaWarn("RDMA: poll recv CQ error %s", strerror(errno));
        return NULL;
    }
    else if (num_ev == 0)
    {
        goto out;
    }

    for (i = 0; i < num_ev; i++)
    {
        if (wc[i].status != IBV_WC_SUCCESS)
        {
            rdmaDebug("(Ignored) RDMA: CQ handle error status: %s[0x%x], opcode : 0x%x",
                      ibv_wc_status_str(wc[i].status), wc[i].status, wc[i].opcode);
            // goto out;
            continue;
        }

        switch (wc[i].opcode)
        {
        case IBV_WC_RECV:
            wr_ctx = (RdmaWrCtx *)wc[i].wr_id;
            conn = (RdmaConn *)wr_ctx->rdma_conn;
            cmd = (RdmaCmd *)wr_ctx->private_data;
            id = conn->cm_id;

            if (rdmaConnHandleRecv(conn, id, cmd, wr_ctx, wc[i].byte_len) == RDMA_ERR)
            {
                rdmaErr("RDMA: rdma connection handle Recv error");
                goto out;
            }
            break;

        case IBV_WC_RECV_RDMA_WITH_IMM:
            wr_ctx = (RdmaWrCtx *)wc[i].wr_id;
            conn = (RdmaConn *)wr_ctx->rdma_conn;
            cmd = (RdmaCmd *)wr_ctx->private_data;
            if (rdmaConnHandleRecvImm(conn, conn->cm_id, cmd, wr_ctx, &wc[i], wc[i].byte_len) == RDMA_ERR)
            {
                rdmaErr("RDMA: rdma connection handle Recv Imm error");
                conn->state = RDMA_CONN_STATE_ERROR;
                goto out;
            }

            break;

        case IBV_WC_RDMA_WRITE:
            conn = (RdmaConn *)wc[i].wr_id;
            if (conn && conn->write_callback)
            {
                conn->write_callback(conn, wc[i].byte_len);
            }

            break;

        case IBV_WC_RDMA_READ:
            conn = (RdmaConn *)wc[i].wr_id;
            if (conn && conn->read_callback)
            {
                conn->read_callback(conn, wc[i].byte_len);
            }

            break;

        case IBV_WC_SEND:
            wr_ctx = (RdmaWrCtx *)wc[i].wr_id;
            conn = (RdmaConn *)wr_ctx->rdma_conn;
            cmd = (RdmaCmd *)wr_ctx->private_data;

            if (rdmaConnHandleSend(conn, cmd) == RDMA_ERR)
            {
                goto out;
            }

            break;

        default:
            rdmaWarn("RDMA: unexpected opcode 0x[%x]", wc[i].opcode);
            break;
        }
    }

    goto pollcq;
out:
    return NULL;
}

void *rdmaCompChannelStart(void *ctx_ptr)
{
    struct rdma_context *ctx = (struct rdma_context *)ctx_ptr;
    assert(ctx);
    int flags = fcntl(ctx->comp_channel->fd, F_GETFL);
    int ret = fcntl(ctx->comp_channel->fd, F_SETFL, flags | O_NONBLOCK);
    int error_flags = POLLERR | POLLHUP | POLLNVAL;
    struct pollfd pfd = {
        .fd = ctx->comp_channel->fd,
        .events = POLLIN,
        .revents = 0};
    int num_events = 0;

    if (ret != 0)
    {
        rdmaErr("RDMA: fcntl rdma completion channel fd failed status: %s", strerror(errno));
        return NULL;
    }

    if (ret != 0)
    {
        rdmaErr("RDMA: fcntl rdma completion channel fd failed status: %s", strerror(errno));
        return NULL;
    }

    while (!atomic_load(&c_should_stop))
    {
        num_events = poll(&pfd, 1, rdmaPollEventTimeoutms);

        if (num_events == -1)
        {
            rdmaErr("RDMA: poll rdma completion channel faild (%s)", strerror(errno));
            break;
        }
        else if (num_events == 0)
        {
            // rdmaDebug("RDMA: rdma completion channel timeout reached. No events");
            continue;
        }

        if ((pfd.revents & error_flags) != 0)
        {
            rdmaErr("RDMA: rdma cm event channel poll err");
            break;
        }

        if (!(pfd.revents & POLLIN))
            continue;

        rdmaPollCQ(ctx);
    }

    rdmaDebug("rdma poll CQ thread exit!");

    return NULL;
}

int rdmaConnCreate(struct rdma_cm_id *id, RdmaConn *conn)
{
    struct ibv_qp_init_attr init_attr;
    int ret;

    ret = rdmaContextInit(id->verbs);
    if (ret != RDMA_OK)
    {
        rdmaErr("RDMA: failed to init RDMA context");
        goto reject;
    }

    /* setup context for this connection */
    conn->cm_id = id;
    conn->pd = g_ctx->pd;
    conn->cq = g_ctx->cq;
    conn->max_inline_data = rdmaMaxInlineData;

    /* setup RDMA QP */
    memset(&init_attr, 0, sizeof(init_attr));
    init_attr.cap.max_send_wr = RDMA_MAX_SGE;
    init_attr.cap.max_recv_wr = RDMA_MAX_SGE;
    init_attr.cap.max_send_sge = 1;
    init_attr.cap.max_recv_sge = 1;
    init_attr.cap.max_inline_data = rdmaMaxInlineData;
    init_attr.qp_type = IBV_QPT_RC;
    init_attr.send_cq = g_ctx->cq;
    init_attr.recv_cq = g_ctx->cq;

    ret = rdma_create_qp(id, g_ctx->pd, &init_attr);
    if (ret)
    {
        rdmaWarn("RDMA: create qp failed %d (%s)", errno, strerror(errno));
        goto reject;
    }

    if (rdmaSetupIoBuf(conn, id) == RDMA_ERR)
    {
        rdmaWarn("RDMA: setup RDMA IO Buf failed");
        goto reject;
    }

    return RDMA_OK;

reject:
    return RDMA_ERR;
}

void rdmaConnRelease(RdmaConn *conn)
{
    if (!conn || !conn->cm_id)
        return;

    rdma_destroy_qp(conn->cm_id);
    rdmaDestroyIoBuf(conn);

    if (conn->cm_id)
        rdma_destroy_id(conn->cm_id);
    conn->cm_id = NULL;

    if (conn->ip)
        free(conn->ip);

    free(conn);
    conn = NULL;
}

void *rdmaCmChannelStart(void *ptr)
{
    int flags = fcntl(g_cm_channel->fd, F_GETFL);
    int ret = fcntl(g_cm_channel->fd, F_SETFL, flags | O_NONBLOCK);
    assert(ret == 0);
    int error_flags = POLLERR | POLLHUP | POLLNVAL;
    struct pollfd pfd = {
        .fd = g_cm_channel->fd,
        .events = POLLIN,
        .revents = 0};
    int num_events = 0;

    if (ret != 0)
    {
        rdmaErr("RDMA: fcntl rdma cm event channel fd failed status: %s", strerror(errno));
        return NULL;
    }

    while (!atomic_load(&g_should_stop))
    {
        num_events = poll(&pfd, 1, rdmaPollEventTimeoutms);

        if (num_events == -1)
        {
            rdmaErr("RDMA: poll rdma cm event channel faild (%s)", strerror(errno));
            break;
        }
        else if (num_events == 0)
        {
            // rdmaDebug("RDMA: rdma cm event channel timeout reached. No events");
            continue;
        }

        if ((pfd.revents & error_flags) != 0)
        {
            rdmaErr("RDMA: rdma cm event channel poll err");
            break;
        }

        if (!(pfd.revents & POLLIN))
            continue;

        ret = rdmaPollEvents(g_cm_channel, NULL);
        if (ret != 0)
        {
            rdmaErr("RDMA: poll CM events failed (%s)", strerror(errno));
            break;
        }
    }

    rdmaDebug("rdma poll CM event thread exit!");

    return NULL;
}

/* public RDMA interfaces */

/* RDMA server side */

int rdmaServer(RdmaListener **listener, const char *ip,
               const int port, const RdmaServerOptions *opt)
{
    struct addrinfo hints, *addrinfo;
    struct sockaddr_storage sock_addr;
    struct rdma_cm_id *listen_cmid = NULL;
    struct rdma_event_channel *listen_channel = NULL;
    char _port[6]; /* strlen("65536") */
    int ret = RDMA_OK, af_type = AF_INET, afonly = 1;
    assert(*listener);
    assert(ip);

    *listener = (RdmaListener *)malloc(sizeof(RdmaListener));
    if (*listener == NULL)
    {
        rdmaErr("RDMA: failed to alloc RdmaListener %d (%s)", errno, strerror(errno));
        goto err;
    }
    memset(*listener, 0, sizeof(**listener));

    /* parse IP addr info */
    sprintf(_port, "%d", port);
    af_type = strchr(ip, ':') ? AF_INET6 : AF_INET;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af_type;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(ip, _port, &hints, &addrinfo);
    if (ret || !addrinfo)
    {
        rdmaErr("RDMA: failed to get addr info for %s:%d", ip, port);
        ret = RDMA_ERR;
        goto err;
    }

    /* create listen event channel */
    listen_channel = rdma_create_event_channel();
    if (!listen_channel)
    {
        rdmaErr("RDMA: create event channel failed");
        ret = RDMA_ERR;
        goto err;
    }

    /* setup Rdma Server Options */
    rdmaSetDefaultOptions(&(*listener)->options);
    if (opt)
    {
        // memcpy(&(*listener)->options, opt, sizeof(*opt));
        if (opt->rdma_comm_mode == RDMA_BLOCKING)
        {
            (*listener)->options.rdma_qp2cq_mode = ONE_TO_ONE;
            rdmaQp2CqMode = ONE_TO_ONE;
        }
        if (opt->accept_callback)
        {
            rdmaServerSetAcceptCallback(*listener, opt->accept_callback);
        }
        rdmaSetGlobalEnv(opt);
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    if (addrinfo->ai_family == AF_INET6)
    {
        memcpy(&sock_addr, addrinfo->ai_addr, sizeof(struct sockaddr_in6));
        ((struct sockaddr_in6 *)&sock_addr)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&sock_addr)->sin6_port = htons(port);
    }
    else
    {
        memcpy(&sock_addr, addrinfo->ai_addr, sizeof(struct sockaddr_in));
        ((struct sockaddr_in *)&sock_addr)->sin_family = AF_INET;
        ((struct sockaddr_in *)&sock_addr)->sin_port = htons(port);
    }

    /* create listen rdma cm id */
    ret = rdma_create_id(listen_channel, &listen_cmid, NULL, RDMA_PS_TCP);
    if (ret)
    {
        rdmaErr("RDMA: create listen cm id error %d", errno);
        goto err;
    }

    rdma_set_option(listen_cmid, RDMA_OPTION_ID, RDMA_OPTION_ID_AFONLY,
                    &afonly, sizeof(afonly));

    ret = rdma_bind_addr(listen_cmid, (struct sockaddr *)&sock_addr);
    if (ret)
    {
        rdmaErr("RDMA: bind addr error for %s:%d", ip, port);
        goto err;
    }

    ret = rdma_listen(listen_cmid, (*listener)->options.rdma_listen_backlog);
    if (ret)
    {
        rdmaErr("RDMA: listen addr error %d", errno);
        goto err;
    }

    (*listener)->cm_id = listen_cmid;
    (*listener)->cm_channel = listen_channel;
    ret = RDMA_OK;
    goto end;

err:
    if (listen_cmid)
        rdma_destroy_id(listen_cmid);
    if (listen_channel)
        rdma_destroy_event_channel(listen_channel);
    ret = RDMA_ERR;

end:
    if (addrinfo)
        freeaddrinfo(addrinfo);

    return ret;
}

int rdmaPollEvents(struct rdma_event_channel *event_channel, void *poll_ctx)
{
    int ret = RDMA_OK;
    struct rdma_cm_event *ev, event_copy;
    enum rdma_cm_event_type ev_type;

    ret = rdma_get_cm_event(event_channel, &ev);
    if (ret)
    {
        if (errno != EAGAIN)
        {
            rdmaWarn("RDMA: rdma event channel get cm event failed, %s", strerror(errno));
        }
        return RDMA_ERR;
    }

    /* Note that failing to acknowledge events will result in rdma_destroy_id() blocking. */
    memcpy(&event_copy, ev, sizeof(*ev));
    rdma_ack_cm_event(ev);

    ev_type = event_copy.event;
    switch (ev_type)
    {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        ret = rdmaOnConnectRequest(&event_copy);
        break;
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        ret = rdmaOnAddrResolved(&event_copy);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        ret = rdmaOnRouteResolved(&event_copy);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ret = rdmaOnConnected(&event_copy, poll_ctx);
        break;
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_DISCONNECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
        ret = rdmaOnDisconnected(&event_copy);
        break;
    case RDMA_CM_EVENT_REJECTED:
        ret = rdmaOnRejected(&event_copy);
        break;
    default:
        rdmaWarn("RDMA: rdma cm event channel get unknown event %d (%s)",
                 ev_type, rdma_event_str(ev_type));
    }

    return ret;
}

int rdmaOnConnectRequest(struct rdma_cm_event *ev)
{
    int ret = RDMA_OK;
    struct rdma_cm_id *cmid = ev->id;
    struct sockaddr_storage caddr;
    RdmaConn *conn = NULL; /* used to store accepted RDMA connection */
    struct rdma_conn_param conn_param = {
        .responder_resources = 1,
        .initiator_depth = 1,
        .retry_count = rdmaRetryCount,
        .rnr_retry_count = rdmaRnrRetryCount,
    };
    char cip[NET_IP_STR_LEN];
    int cport = 0;

    rdmaDebug("rdmaOnConnectRequest recv a new connection");
    memcpy(&caddr, &cmid->route.addr.dst_addr, sizeof(caddr));
    if (caddr.ss_family == AF_INET)
    {
        struct sockaddr_in *s = (struct sockaddr_in *)&caddr;
        inet_ntop(AF_INET, (void *)&(s->sin_addr), cip, sizeof(cip));
        cport = ntohs(s->sin_port);
    }
    else
    {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&caddr;
        inet_ntop(AF_INET6, (void *)&(s->sin6_addr), cip, cport);
        cport = ntohs(s->sin6_port);
    }

    conn = malloc(sizeof(RdmaConn));
    if (!conn)
    {
        goto err;
    }
    memset(conn, 0, sizeof(*conn));

    conn->ip = strdup(cip);
    conn->port = cport;
    conn->state = RDMA_CONN_STATE_ACCEPTING;
    conn->type = ACCEPTED_CONN;
    conn->send_length = 0;
    conn->recv_length = 0;
    conn->tx_length = 0;
    pthread_cond_init(&conn->status_cond, NULL);
    pthread_mutex_init(&conn->status_mutex, NULL);

    cmid->context = conn;
    if (rdmaConnCreate(cmid, conn) != RDMA_OK)
    {
        rdmaErr("RDMA: failed to create accepted RDMA Connection (%s:%d)", cip, cport);
        goto err;
    }

    ret = rdma_accept(cmid, &conn_param);
    if (ret)
    {
        rdmaErr("RDMA: accept failed %d (%s)", errno, strerror(errno));
        goto err;
    }

    return RDMA_OK;

err:
    /* free rdma related resource */
    rdmaConnRelease(conn);

    /* reject connect request if hitting error*/
    rdma_reject(cmid, NULL, 0);

    return RDMA_ERR;
}

int rdmaOnAddrResolved(struct rdma_cm_event *ev)
{
    struct rdma_cm_id *id = ev->id;
    RdmaConn *conn = id->context;

    /* resolve route at most 1000ms */
    if (rdma_resolve_route(id, conn->options.rdma_timeoutms) != 0)
    {
        rdmaErr("RDMA: resolve route failed with timeout %d ms", conn->options.rdma_timeoutms);
        rdmaOnRejected(ev);
        return RDMA_ERR;
    }

    return RDMA_OK;
}

int rdmaOnRouteResolved(struct rdma_cm_event *ev)
{
    struct rdma_cm_id *id = ev->id;
    struct rdma_conn_param conn_param = {0};
    RdmaConn *conn = id->context;

    if (rdmaConnCreate(id, conn) != RDMA_OK)
    {
        rdmaErr("RDMA: failed to create RDMA Connection Resource");
        return RDMA_ERR;
    }

    /* rdma connect with param */
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;
    conn_param.retry_count = rdmaRetryCount;
    conn_param.rnr_retry_count = rdmaRnrRetryCount;
    if (rdma_connect(id, &conn_param))
    {
        rdmaErr("RDMA: rdma_connect() failed in error (%s)", strerror(errno));
        rdmaOnRejected(ev);
        return RDMA_ERR;
    }

    return RDMA_OK;
}

static RdmaCmd *rdmaAllocCmdBuf(RdmaConn *conn, RdmaWrCtx **tx_ctx)
{
    RdmaCmd *_cmd;
    RdmaWrCtx *_tx_ctx;
    int i;

    /* find an unused cmd buffer */
    for (i = rdmaRecvDepth; i < 2 * rdmaRecvDepth; i++)
    {
        _cmd = conn->cmd_buf + i;
        if (!_cmd->magic)
        {
            break;
        }
    }

    assert(i < 2 * rdmaRecvDepth);

    /* find corresponding RdmaWrCtx */
    _tx_ctx = conn->tx_ctx + i - rdmaRecvDepth;
    *tx_ctx = _tx_ctx;

    return _cmd;
}

int rdmaSendCommand(RdmaConn *conn, struct rdma_cm_id *id, RdmaCmd *cmd, void *tx_ctx)
{
    int ret;

    ret = rdma_send_signaled(id->qp, (uint64_t)tx_ctx, (uint64_t)cmd,
                             sizeof(RdmaCmd), conn->cmd_mr->lkey, conn->max_inline_data);
    if (ret)
    {
        rdmaWarn("RDMA: post send RDMA cmd failed %d", ret);
        conn->state = RDMA_CONN_STATE_ERROR;
        return RDMA_ERR;
    }

    return RDMA_OK;
}

/* sync RDMA recv MR to remote via two sided messaging */
int connRdmaSyncRxMr(RdmaConn *conn, struct rdma_cm_id *cm_id)
{
    RdmaCmd *cmd;
    RdmaWrCtx *tx_ctx;

    cmd = rdmaAllocCmdBuf(conn, &tx_ctx);

    cmd->addr = (uint64_t)conn->recv_buf;
    cmd->length = htonl(conn->recv_length);
    cmd->key = htonl(conn->recv_mr->rkey);
    cmd->cmd_opcode = REG_LOCAL_ADDR;
    cmd->magic = RDMA_CMD_MAGIC;

    tx_ctx->type = SEND_CONTEXT;
    tx_ctx->rdma_conn = (void *)conn;
    tx_ctx->private_data = (void *)cmd;

    conn->rx_offset = 0;
    conn->recv_offset = 0;

    return rdmaSendCommand(conn, cm_id, cmd, tx_ctx);
}

int connRdmaSyncPhysRxMr(RdmaConn *conn, struct rdma_cm_id *cm_id)
{
    RdmaCmd *cmd;
    RdmaWrCtx *tx_ctx;

    if (!rdmaEnablePhysAddrAccess)
        return RDMA_OK;

    if (rdmaEnablePhysAddrAccess && (!g_ctx || !g_ctx->phys_mr))
    {
        rdmaDebug("You should enable Physical Memory Access over RDMA before use. \n"
                  "Note that you need to enable RDMA Physical Address Memory Region"
                  " (pa-mr) in MLNX_OFED driver.");
        return RDMA_ERR;
    }

    cmd = rdmaAllocCmdBuf(conn, &tx_ctx);

    cmd->addr = (uint64_t)g_ctx->phys_mr->addr;
    cmd->length = htonl(g_ctx->phys_mr->length);
    cmd->key = htonl(g_ctx->phys_mr->rkey);
    cmd->cmd_opcode = REG_PHYS_ADDR;
    cmd->magic = RDMA_CMD_MAGIC;

    tx_ctx->type = SEND_CONTEXT;
    tx_ctx->rdma_conn = (void *)conn;
    tx_ctx->private_data = (void *)cmd;

    return rdmaSendCommand(conn, cm_id, cmd, tx_ctx);
}

int connRdmaSayBye(RdmaConn *conn, struct rdma_cm_id *cm_id)
{
    RdmaCmd *cmd;
    RdmaWrCtx *tx_ctx;

    cmd = rdmaAllocCmdBuf(conn, &tx_ctx);

    cmd->cmd_opcode = CONN_GOODBYE;
    cmd->magic = RDMA_CMD_MAGIC;

    tx_ctx->type = SEND_CONTEXT;
    tx_ctx->rdma_conn = (void *)conn;
    tx_ctx->private_data = (void *)cmd;

    return rdmaSendCommand(conn, cm_id, cmd, tx_ctx);
}

int rdmaOnConnected(struct rdma_cm_event *ev, void *poll_ctx)
{
    struct rdma_cm_id *id = ev->id;
    RdmaConn *conn = id->context;

    connRdmaSyncPhysRxMr(conn, id);
    connRdmaSyncRxMr(conn, id);
    conn->state = RDMA_CONN_STATE_CONNECTED;

    if (conn->type == ACCEPTED_CONN && poll_ctx)
    {
        RdmaListener *listener = poll_ctx;
        if (listener->accept_callback)
        {
            listener->accept_callback(conn);
        }
    }
    else if (conn->type == CONNECTED_CONN)
    {
        /* ConnectCallback for client side */
        if (conn->connected_callback)
        {
            conn->connected_callback(conn);
        }
    }

    return RDMA_OK;
}

int rdmaOnDisconnected(struct rdma_cm_event *ev)
{
    struct rdma_cm_id *id = ev->id;
    RdmaConn *conn = id->context;

    conn->state = RDMA_CONN_STATE_CLOSED;
    /* call Disconnect Callback before release */
    if (conn->disconnect_callback)
    {
        conn->disconnect_callback(conn);
    }
    pthread_mutex_lock(&conn->status_mutex);
    pthread_cond_broadcast(&conn->status_cond); /* signal waiting threads */
    pthread_mutex_unlock(&conn->status_mutex);
    rdmaConnRelease(conn);

    return RDMA_OK;
}

int rdmaOnRejected(struct rdma_cm_event *ev)
{
    struct rdma_cm_id *id = ev->id;
    RdmaConn *conn = id->context;

    conn->state = RDMA_CONN_STATE_ERROR;

    return RDMA_OK;
}

/* note that rdmaServerStart can also run in a thread in an async manner. */
int rdmaServerStart(RdmaListener *listener)
{
    int flags = fcntl(listener->cm_channel->fd, F_GETFL);
    int ret = fcntl(listener->cm_channel->fd, F_SETFL, flags | O_NONBLOCK);
    assert(ret == 0);
    int error_flags = POLLERR | POLLHUP | POLLNVAL;
    struct pollfd pfd = {
        .fd = listener->cm_channel->fd,
        .events = POLLIN,
        .revents = 0};
    int num_events = 0;

    if (ret != 0)
    {
        rdmaErr("RDMA: fcntl rdma cm event channel fd failed status: %s", strerror(errno));
        return RDMA_ERR;
    }

    while (!atomic_load(&g_should_stop))
    {
        num_events = poll(&pfd, 1, rdmaPollEventTimeoutms);

        if (num_events == -1)
        {
            rdmaErr("RDMA: poll rdma cm event channel faild (%s)", strerror(errno));
            goto err;
        }
        else if (num_events == 0)
        {
            // rdmaDebug("RDMA: rdma cm event channel timeout reached. No events");
            continue;
        }

        if ((pfd.revents & error_flags) != 0)
        {
            rdmaErr("RDMA: rdma cm event channel poll err");
            goto err;
        }

        if (!(pfd.revents & POLLIN))
            continue;

        ret = rdmaPollEvents(listener->cm_channel, listener);
        if (ret != 0)
        {
            rdmaErr("RDMA: poll CM events failed (%s)", strerror(errno));
            goto err;
        }
    }

    ret = RDMA_OK;
    goto end;
err:
    ret = RDMA_ERR;

end:
    return ret;
}

int rdmaServerStop(RdmaListener *listener)
{
    int ret = RDMA_OK;

    atomic_store(&g_should_stop, true);
    rdmaContextRelease();

    return ret;
}

void rdmaServerRelease(RdmaListener *listener)
{
    if (!listener)
        return;

    if (listener->cm_id)
    {
        rdma_destroy_id(listener->cm_id);
    }

    if (listener->cm_channel)
    {
        rdma_destroy_event_channel(listener->cm_channel);
    }

    free(listener);
}

int rdmaServerSetAcceptCallback(RdmaListener *listener, RdmaAcceptCallbackFunc func)
{
    if (listener->accept_callback == func)
        return RDMA_OK;

    listener->accept_callback = func;

    return RDMA_OK;
}

/** rdma client side */

RdmaConn *rdmaConn(const RdmaServerOptions *opt)
{
    RdmaConn *conn;

    if (!g_cm_channel)
    {
        g_cm_channel = rdma_create_event_channel();
        if (!g_cm_channel)
        {
            rdmaErr("RDMA: create cm event channel failed %d(%s)", errno, strerror(errno));
            return NULL;
        }

        atomic_store(&g_ev_poller_should_stop, false);
        pthread_create(&g_ev_poller_thread, NULL, rdmaCmChannelStart, NULL);
    }

    conn = malloc(sizeof(RdmaConn));
    if (!conn)
    {
        rdmaErr("RDMA: malloc RdmaConn failed %s", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));

    /* setup Rdma Server Options */
    rdmaSetDefaultOptions(&conn->options);
    if (opt)
    {
        rdmaConnSetEnv(conn, opt);
        rdmaSetGlobalEnv(opt);
    }

    conn->state = RDMA_CONN_STATE_NONE;
    conn->type = CONNECTED_CONN;
    conn->cm_channel = g_cm_channel;
    conn->send_length = 0;
    conn->recv_length = 0;
    conn->tx_length = 0;
    pthread_cond_init(&conn->status_cond, NULL);
    pthread_mutex_init(&conn->status_mutex, NULL);

    if (rdma_create_id(conn->cm_channel, &(conn->cm_id), (void *)conn, RDMA_PS_TCP))
    {
        rdmaErr("RDMA: create cm id failed %d(%s", errno, strerror(errno));
        goto err;
    }

    return conn;

err:
    if (conn)
        free(conn);

    return NULL;
}

int rdmaConnect(RdmaConn *conn, char *serverip, int port)
{
    struct addrinfo hints, *servinfo = NULL;
    struct sockaddr_storage saddr;
    char _port[6]; /* strlen("65535") */
    int ret = RDMA_ERR;

    snprintf(_port, 6, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(serverip, _port, &hints, &servinfo))
    {
        hints.ai_family = AF_INET6;
        if (getaddrinfo(serverip, _port, &hints, &servinfo))
        {
            rdmaWarn("RDMA: bad server addr info %d(%s)", errno, strerror(errno));
            goto out;
        }
    }

    if (servinfo->ai_family == PF_INET)
    {
        memcpy(&saddr, servinfo->ai_addr, sizeof(struct sockaddr_in));
        ((struct sockaddr_in *)&saddr)->sin_port = htons(port);
    }
    else if (servinfo->ai_family == PF_INET6)
    {
        memcpy(&saddr, servinfo->ai_addr, sizeof(struct sockaddr_in6));
        ((struct sockaddr_in6 *)&saddr)->sin6_port = htons(port);
    }
    else
    {
        rdmaWarn("RDMA: Unsupported family");
        goto out;
    }

    /* resolve addr at most 1000ms */
    conn->ip = strdup(serverip);
    conn->port = port;
    conn->state = RDMA_CONN_STATE_CONNECTING;
    if (rdma_resolve_addr(conn->cm_id, NULL,
                          (struct sockaddr *)&saddr, rdmaTimeoutms))
    {
        rdmaWarn("RDMA: cannot resolve addr %s:%d (error: %s)",
                 serverip, port, strerror(errno));
        goto out;
    }

    /* wait for connected state */
    pthread_mutex_lock(&conn->status_mutex);
    pthread_cond_wait(&conn->status_cond, &conn->status_mutex);
    pthread_mutex_unlock(&conn->status_mutex);

    ret = RDMA_OK;
out:
    if (servinfo)
    {
        freeaddrinfo(servinfo);
    }

    return ret;
}

void rdmaConnClose(RdmaConn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;

    if (!cm_id)
        return;

    // rdma_disconnect(cm_id);
    connRdmaSayBye(conn, cm_id);
    pthread_mutex_lock(&conn->status_mutex);
    pthread_cond_wait(&conn->status_cond, &conn->status_mutex);
    pthread_mutex_unlock(&conn->status_mutex);
}

int rdmaConnSetRecvCallback(RdmaConn *conn, RdmaRecvCallbackFunc func)
{
    if (func == conn->recv_callback)
        return RDMA_OK;

    conn->recv_callback = func;

    return RDMA_OK;
}

int rdmaConnSetWriteCallback(RdmaConn *conn, RdmaWriteCallbackFunc func)
{
    if (func == conn->write_callback)
        return RDMA_OK;

    conn->write_callback = func;

    return RDMA_OK;
}

int rdmaConnSetReadCallback(RdmaConn *conn, RdmaReadCallbackFunc func)
{
    if (func == conn->read_callback)
        return RDMA_OK;

    conn->read_callback = func;

    return RDMA_OK;
}

int rdmaConnSetConnectedCallback(RdmaConn *conn, RdmaConnectedCallbackFunc func)
{
    if (func == conn->connected_callback)
        return RDMA_OK;

    conn->connected_callback = func;

    return RDMA_OK;
}

int rdmaConnSetDisconnectCallback(RdmaConn *conn, RdmaDisconnectCallbackFunc func)
{
    if (func == conn->disconnect_callback)
        return RDMA_OK;

    conn->disconnect_callback = func;

    return RDMA_OK;
}

/* data plane interfaces. Signaled by default. */
size_t rdmaConnSend(RdmaConn *conn, void *data, size_t data_len)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    uint32_t off = conn->tx_offset;
    char *addr = conn->send_buf + off;
    char *remote_addr = conn->tx_addr + conn->tx_offset;
    int ret;
    uint32_t tosend;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    assert(conn->tx_offset <= conn->tx_length);
    tosend = MIN(conn->tx_length - conn->tx_offset, data_len);
    if (!tosend)
    {
        rdmaWarn("no idle tx memory for RDMA WRITE");
        return 0;
    }

    memcpy(addr, data, data_len);

    if (!conn->write_callback && (++conn->send_ops % (RDMA_MAX_SGE / 2)) != 0)
    {
        ret = rdma_write_with_imm(cm_id->qp, (uint64_t)conn, htonl(conn->tx_offset),
                                  (uint64_t)addr, conn->send_mr->lkey,
                                  (uint64_t)remote_addr, conn->tx_key,
                                  data_len, rdmaMaxInlineData);
    }
    else
    {
        ret = rdma_write_with_imm_signaled(cm_id->qp, (uint64_t)conn, htonl(conn->tx_offset),
                                           (uint64_t)addr, conn->send_mr->lkey,
                                           (uint64_t)remote_addr, conn->tx_key,
                                           data_len, rdmaMaxInlineData);
    }
    if (ret)
    {
        rdmaErr("RDMA: post send failed : %s", strerror(errno));
        return RDMA_ERR;
    }

    conn->tx_offset += data_len;

    return data_len;
}

// size_t rdmaConnSendWithImm(RdmaConn *conn, uint32_t imm_data,
//                            const void *data, size_t data_len)
// {
//     return RDMA_OK;
// }

/* RDMA Write with data copy. Here we assume that input data buf
 * is not RDMA-registered MR.
 */
size_t rdmaConnWrite(RdmaConn *conn, const void *data, size_t data_len)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    uint32_t off = conn->tx_offset;
    char *addr = conn->send_buf + off;
    char *remote_addr = conn->tx_addr + conn->tx_offset;
    int ret;
    uint32_t tosend;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    assert(conn->tx_offset <= conn->tx_length);
    tosend = MIN(conn->tx_length - conn->tx_offset, data_len);
    if (!tosend)
    {
        return 0;
    }

    memcpy(addr, data, data_len);

    if (!conn->write_callback && (++conn->send_ops % (RDMA_MAX_SGE / 2)) != 0)
    {
        ret = rdma_write(cm_id->qp, (uint64_t)conn,
                         (uint64_t)addr, conn->send_mr->lkey,
                         (uint64_t)remote_addr, conn->tx_key,
                         data_len, rdmaMaxInlineData);
    }
    else
    {
        ret = rdma_write_signaled(cm_id->qp, (uint64_t)conn,
                                  (uint64_t)addr, conn->send_mr->lkey,
                                  (uint64_t)remote_addr, conn->tx_key,
                                  data_len, rdmaMaxInlineData);
    }
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA WRITE : %s", strerror(errno));
        return RDMA_ERR;
    }

    conn->tx_offset += data_len;

    return data_len;
}

int rdmaConnWriteWithImm(RdmaConn *conn, uint32_t imm_data,
                         const void *data, size_t data_len)
{
    return RDMA_OK;
}

int rdmaConnRead(RdmaConn *conn, void *local_buf, uint32_t lkey,
                 void *remote_buf, uint32_t rkey, size_t length)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_read_signaled(cm_id->qp, (uint64_t)conn, (uint64_t)local_buf, lkey,
                             (uint64_t)remote_buf, rkey, length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA READ : %s", strerror(errno));
        return RDMA_ERR;
    }

    return length;
}

int rdmaSyncWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                          uint32_t lkey, uint64_t remote_addr,
                          uint32_t rkey, uint32_t length)
{
    struct rdma_cm_id *id = conn->cm_id;
    struct ibv_wc wc = {0};
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_write_signaled(id->qp, (uint64_t)conn, local_addr,
                              lkey, remote_addr, rkey,
                              length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA WRITE : %s", strerror(errno));
        return RDMA_ERR;
    }

    while (ibv_poll_cq(conn->cq, 1, &wc) == 0);

    return length;
}

int rdmaSyncReadSignaled(RdmaConn *conn, uint64_t local_addr,
                         uint32_t lkey, uint64_t remote_addr,
                         uint32_t rkey, uint32_t length)
{
    struct rdma_cm_id *id = conn->cm_id;
    struct ibv_wc wc = {0};
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_read_signaled(id->qp, (uint64_t)conn, local_addr, lkey,
                             remote_addr, rkey,
                             length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA READ : %s", strerror(errno));
        return RDMA_ERR;
    }

    while (ibv_poll_cq(conn->cq, 1, &wc) == 0);

    return length;
}

int rdmaPAWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                        uint32_t lkey, uint64_t remote_addr, uint32_t length)
{
    struct rdma_cm_id *id = conn->cm_id;
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_write_signaled(id->qp, (uint64_t)conn, local_addr, lkey,
                              remote_addr, conn->tx_pa_rkey,
                              length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA Write : %s", strerror(errno));
        return RDMA_ERR;
    }

    return length;
}

int rdmaPAReadSignaled(RdmaConn *conn, uint64_t local_addr,
                       uint32_t lkey, uint64_t remote_addr, uint32_t length)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_read_signaled(cm_id->qp, (uint64_t)conn, local_addr, lkey,
                             remote_addr, conn->tx_pa_rkey, length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA READ : %s", strerror(errno));
        return RDMA_ERR;
    }

    return length;
}

int rdmaPASyncWriteSignaled(RdmaConn *conn, uint64_t local_addr,
                            uint32_t lkey, uint64_t remote_addr, uint32_t length)
{
    struct rdma_cm_id *id = conn->cm_id;
    struct ibv_wc wc = {0};
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_write_signaled(id->qp, (uint64_t)conn, local_addr, lkey,
                              remote_addr, conn->tx_pa_rkey,
                              length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA Write : %s", strerror(errno));
        return RDMA_ERR;
    }

    while (ibv_poll_cq(conn->cq, 1, &wc) == 0)
        ;

    return length;
}

int rdmaPASyncReadSignaled(RdmaConn *conn, uint64_t local_addr,
                           uint32_t lkey, uint64_t remote_addr, uint32_t length)
{
    struct rdma_cm_id *id = conn->cm_id;
    struct ibv_wc wc = {0};
    int ret;

    if (conn->state == RDMA_CONN_STATE_ERROR || conn->state == RDMA_CONN_STATE_CLOSED)
    {
        return RDMA_ERR;
    }

    ret = rdma_read_signaled(id->qp, (uint64_t)conn, local_addr, lkey,
                             remote_addr, conn->tx_pa_rkey,
                             length, conn->max_inline_data);
    if (ret)
    {
        rdmaErr("RDMA: post send failed for RDMA READ : %s", strerror(errno));
        return RDMA_ERR;
    }

    while (ibv_poll_cq(conn->cq, 1, &wc) == 0);

    return length;
}
