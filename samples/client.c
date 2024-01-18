#include <stdio.h>
#include <unistd.h>
#include "rdma.h"

char *serverip = "192.168.1.9";
int port = 8888;

char *hello_msg = "Hello World!";

void clientRecvSuccess(RdmaConn *conn, void *data, size_t data_len)
{
    printf("RDMA: recv data from peer (%s:%d): %s\n", conn->ip, conn->port, (char *)data);
}

void clientWriteSuccess(RdmaConn *conn, size_t data_len)
{
    printf("RDMA WRITE to peer (%s:%d) success\n", conn->ip, conn->port);
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

    ret = RDMA_OK;

end:
    if (conn)
    {
        rdmaConnClose(conn);
    }
    rdmaRuntimeStop();

    return ret;
}
