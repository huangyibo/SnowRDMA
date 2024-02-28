#include <stdio.h>
#include <unistd.h>
#include "rdma.h"

char *serverip = "192.168.1.13";
int port = 8888;

char *hello_msg = "hahahaahahaha!";
char *local_msg_buf;
struct ibv_mr *data_mr;

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
    printf("RDMA READ from peer (%s:%d): %s\n", conn->ip, conn->port, local_msg_buf);
    if (local_msg_buf && data_mr)
    {
        printf("RDMA conn de-register data mr\n");
        rdmaConnDeregMem(conn, data_mr);
        local_msg_buf = NULL;
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
    RdmaConn *conn;
    RdmaConnOptions opt = {0};
    int ret = RDMA_ERR;

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
    unsigned long remote_addr = 0xff1ba1000;
    #define TEST_MSG "Umich RBPF!"
    // rdmaConnRead(conn, local_msg_buf, data_mr->lkey, (void *)remote_addr, conn->tx_pa_rkey, strlen(hello_msg));
    memcpy((void *)local_msg_buf, TEST_MSG, strlen(TEST_MSG));
    rdmaPAWriteSignaled(conn, (unsigned long)local_msg_buf, data_mr->lkey, remote_addr, strlen(hello_msg));
    rdmaPAReadSignaled(conn, (unsigned long)local_msg_buf, data_mr->lkey, remote_addr, strlen(hello_msg));

    ret = RDMA_OK;

end:
    if (conn)
    {
        rdmaConnClose(conn);
    }
    rdmaRuntimeStop();

    return ret;
}
