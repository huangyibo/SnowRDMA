# SnowRDMA
A high-performance and easy-to-use RDMA library, called SnowRDMA. 
I call it "SnowRDMA" because I completed its main development work during 
a snow storm in Ann Arbor, MI. My wife Eva just suggests "SnowRDMA" to 
commemorate the first snow in 2024 we experienced together.

## Introduction

SnowRDMA provides easy-to-use RDMA programming interfaces for control
and data plane operations while preserving high performance networking,
so that a programmer without RDMA experience can easily take advantage
of high performance benefits by RDMA (e.g., ultra-low latency, high
throughput, and near-zero CPU utilization). This provides three types of
interfaces:

(1) server side control interfaces:
```c
  /* init RDMA server */
  int rdmaServer(RdmaListener **listener, char *ip, int port);

  /* start RDMA server runtime */
  int rdmaServerStart(RdmaListener *listener);

  /* stop RDMA server runtime */
  int rdmaServerStop(RdmaListener *listener);

  /* release global RDMA server context */
  void rdmaServerRelease(RdmaListener *listener);
```

(2) client side control interfaces:
```c
  /* create a new rdma connection as endpoint */
  RdmaConn *rdmaConn(void);

  /* try to connect remote RDMA server with serving IP and port */
  int rdmaConnect(RdmaConn *conn, char *serverip, int port);

  /* try to close given a client rdma connection */
  void rdmaConnClose(RdmaConn *conn);

  /* explicitly stop background rdma runtime */
  void rdmaRuntimeStop(void);
```

(3) data plane interfaces: RDMA signaled by default
```c
    /* use RDMA WRITE WITH IMM as main send primitive */
    size_t rdmaConnSend(RdmaConn *conn, void *data, size_t data_len);

    size_t rdmaConnSendWithImm(RdmaConn *conn, uint32_t imm_data,
                                const void *data, size_t data_len);

    /* use RDMA WRITE to send data. Assume that data is a pre-registered RDMA MR */
    size_t rdmaConnWrite(RdmaConn *conn, const void *data, size_t data_len);
    int rdmaConnWriteWithImm(RdmaConn *conn, uint32_t imm_data,
                              const void *data, size_t data_len);

    /* use RDMA READ to recv data. Assume that data buffer is a
        pre-registered RDMA MR */
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
```
