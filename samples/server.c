#include <stdio.h>
#include "rdma.h"

char *serverip = "192.168.1.9";
int port = 8888;

void connRecvSuccess(RdmaConn *conn, void *data, size_t data_len)
{
    printf("RDMA: recv data from peer: %s\n", (char *)data);
    rdmaConnSend(conn, data, data_len);
}

void serverAcceptSuccess(RdmaConn *conn)
{
    printf("RDMA: Accepted a new connection. Let's register recv callback here\n");
    rdmaConnSetRecvCallback(conn, connRecvSuccess);
    printf("rdmaConnSetRecvCallback success\n");
}

int main(int argc, char *argv[])
{
    RdmaListener *server;
    RdmaServerOptions opt = {0};
    int ret;

    opt.rdma_recv_depth = 512;
    opt.rdma_enable_phys_addr_access = false;
    opt.accept_callback = serverAcceptSuccess;
    ret = rdmaServer(&server, serverip, port, &opt);
    if (ret != RDMA_OK)
    {
        rdmaErr("create rdma server failed");
        goto err;
    }
    // rdmaServerSetAcceptCallback(server, serverAcceptSuccess);

    rdmaServerStart(server);

    rdmaServerStop(server);
    rdmaServerRelease(server);

    return 0;

err:
    return -1;
}
