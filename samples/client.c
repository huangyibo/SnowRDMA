#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "rdma.h"

char *serverip;
int port = 8888;

char *hello_msg = "hahahaahahaha!";
char *local_msg_buf;
struct ibv_mr *data_mr;

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s <RDMA-server-address> <server-port>\n", argv0);
    exit(1);
}

static uint64_t time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* params for test */
static RdmaConn *conn;
static int max_cnt = 1000000;
static int cur_cnt = 0;
static unsigned long remote_addr = 0xff1ba1000;
pthread_cond_t g_cond;
pthread_mutex_t g_mutex;
uint64_t start_time, end_time;
static int nr_outstanding_reqs = 32;

void clientRecvSuccess(RdmaConn *conn, void *data, size_t data_len)
{
    printf("RDMA: recv data from peer (%s:%d): %s\n", conn->ip, conn->port, (char *)data);
}

void clientWriteSuccess(RdmaConn *conn, size_t data_len)
{
    printf("RDMA WRITE to peer (%s:%d) success\n", conn->ip, conn->port);
}

void clientReadSuccess(RdmaConn *conn, size_t data_len)
{
    // printf("RDMA READ from peer (%s:%d): %s\n", conn->ip, conn->port, local_msg_buf);

    // if (local_msg_buf && data_mr)
    // {
    //     printf("RDMA conn de-register data mr\n");
    //     rdmaConnDeregMem(conn, data_mr);
    //     local_msg_buf = NULL;
    // }

    cur_cnt++;
    if (cur_cnt < max_cnt) {
        rdmaPAReadSignaled(conn, (unsigned long)local_msg_buf, data_mr->lkey, remote_addr, strlen(hello_msg));
    }
    else if (cur_cnt == max_cnt)
    {
        end_time = time_get_ns();
        printf("====> %lld reqs per second ====\n", max_cnt * 1000000000ll / (end_time - start_time));

        pthread_mutex_lock(&g_mutex);
        pthread_cond_signal(&g_cond);
        pthread_mutex_unlock(&g_mutex);
    }

}

void clientConnectSuccess(RdmaConn *conn)
{
    printf("RDMA: one connection (%s:%d) connect success to server\n", conn->ip, conn->port);
}

void clientDisconnectSuccess(RdmaConn *conn)
{
    printf("RDMA: one connection (%s:%d) disconnect success\n", conn->ip, conn->port);
}

int main(int argc, char *argv[])
{
    RdmaConnOptions opt = {0};
    int ret = RDMA_ERR;
    int i;

    if (argc != 3)
        usage(argv[0]);

    serverip = argv[1];
    port = atoi(argv[2]);

    opt.rdma_recv_depth = 32;
    opt.recv_callback = clientRecvSuccess;
    opt.write_callback = clientWriteSuccess;
    opt.read_callback = clientReadSuccess;
    opt.connected_callback = clientConnectSuccess;
    opt.disconnect_callback = clientDisconnectSuccess;
    conn = rdmaConn(&opt);
    if (!conn)
    {
        rdmaErr("create rdma connection failed");
        goto end;
    }
    // rdmaConnSetRecvCallback(conn, clientRecvSuccess);

    ret = rdmaConnect(conn, serverip, port);
    if (ret != RDMA_OK)
    {
        rdmaErr("rdma connect failed");
        goto end;
    }

    ret = rdmaConnSend(conn, hello_msg, strlen(hello_msg));
    printf("rdmaConnSend success %d bytes\n", ret);
    if (ret != strlen(hello_msg))
    {
        rdmaErr("rdma send msg failed");
        goto end;
    }

    rdmaConnWrite(conn, hello_msg, strlen(hello_msg));

    data_mr = rdmaConnRegMem(conn, strlen(hello_msg) + 1);
    if (!data_mr)
    {
        rdmaErr("rdma register memory failed");
        goto end;
    }
    local_msg_buf = (char *)data_mr->addr;
    // rdmaConnRead(conn, local_msg_buf, data_mr->lkey, conn->tx_addr, conn->tx_key, strlen(hello_msg));

    /* test PA MR */
    #define TEST_MSG "Umich RBPF!"
    // rdmaConnRead(conn, local_msg_buf, data_mr->lkey, (void *)remote_addr, conn->tx_pa_rkey, strlen(hello_msg));
    memcpy((void *)local_msg_buf, TEST_MSG, strlen(TEST_MSG));
    rdmaPAWriteSignaled(conn, (unsigned long)local_msg_buf, data_mr->lkey, remote_addr, strlen(hello_msg));

    pthread_cond_init(&g_cond, NULL);
    pthread_mutex_init(&g_mutex, NULL);

    start_time = time_get_ns();
    for (i = 0; i <= nr_outstanding_reqs; i++)
    {
        rdmaPAReadSignaled(conn, (unsigned long)local_msg_buf, data_mr->lkey, remote_addr, strlen(hello_msg));
    }

    pthread_mutex_lock(&g_mutex);
    pthread_cond_wait(&g_cond, &g_mutex);
    pthread_mutex_unlock(&g_mutex);

    ret = RDMA_OK;

end:
    if (local_msg_buf && data_mr)
    {
        sleep(1);
        printf("RDMA conn de-register data mr\n");
        rdmaConnDeregMem(conn, data_mr);
        local_msg_buf = NULL;
    }
    if (conn)
    {
        rdmaConnClose(conn);
    }
    rdmaRuntimeStop();

    pthread_mutex_destroy(&g_mutex);
    pthread_cond_destroy(&g_cond);

    return ret;
}
