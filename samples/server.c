#include <stdio.h>
#include "rdma.h"

char *serverip = "192.168.1.9";
int port = 8888;

int main(int argc, char *argv[])
{
    RdmaListener *server;
    RdmaServerOptions opt = {0};
    int ret;

    opt.rdma_recv_depth = 512;
    opt.rdma_enable_phys_addr_access = false;
    ret = rdmaServer(&server, serverip, port, &opt);
    if (ret != RDMA_OK)
    {
        rdmaErr("create rdma server failed");
        goto err;
    }

    rdmaServerStart(server);

    rdmaServerStop(server);
    rdmaServerRelease(server);

    return 0;

err:
    return -1;
}
