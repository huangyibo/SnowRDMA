#include <stdio.h>
#include <unistd.h>
#include "rdma.h"

char *serverip = "192.168.1.9";
int port = 8888;

char *hello_msg = "Hello World!";

int main(int argc, char *argv[])
{
    RdmaConn *conn;
    int ret = RDMA_ERR;

    conn = rdmaConn();
    if (!conn)
    {
        rdmaErr("create rdma connection failed");
        goto end;
    }

    ret = rdmaConnect(conn, serverip, port);
    if (ret != RDMA_OK)
    {
        rdmaErr("rdma connect failed");
        goto end;
    }

    ret = rdmaConnSend(conn, hello_msg, strlen(hello_msg));
    printf("rdmaConnSend: ret = %d\n", ret);
    if (ret != strlen(hello_msg))
    {
        rdmaErr("rdma send msg failed");
        goto end;
    }

    ret = RDMA_OK;

end:
    if (conn)
    {
        rdmaConnClose(conn);
    }
    rdmaRuntimeStop();

    return ret;
}
