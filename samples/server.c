#include <stdio.h>
#include "rdma.h"

char *serverip = "192.168.1.9";
int port = 8888;

int main(int argc, char *argv[])
{
    RdmaListener *server;
    int ret;

    ret = rdmaServer(&server, serverip, port);
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
