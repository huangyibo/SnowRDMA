# SnowRDMA -- An ultral-fast and easy-to-use RDMA library

*Hope that you'd be glad to add a star if you think this repo is helpful!*

## Overview

A high-performance and easy-to-use RDMA library, called SnowRDMA. 
I call it "SnowRDMA" because I completed its main development work during 
a snowstorm in Ann Arbor, MI. My wife Eva just suggested "SnowRDMA" to 
commemorate the first snow in 2024 we experienced together.
SnowRDMA provides user-friendly RDMA programming abstractions while 
preserving ultra-fast networking IO by integrating with advanced RDMA 
hardware features. 

The features supported by SnowRDMA include:

- Callback based asynchronous programming model.
- Support event and polling driven RDMA completion model.
- Support Remote Directly Physical Memory Access (PA-MR) feature.
  - Note that this feature needs to be enabled in the MLNX_OFED driver
    at boot time. Please refer to this google doc [PA MR in RDMA
](https://docs.google.com/document/d/12bsFDSS3jV7WQ7OdfP2SEaooYVrPnhxDR8b_hpwQDgc/edit?usp=sharing).
- Single-thread IO model.
- Support CPU affinity setting.
- Support to adjust the outstanding RDMA Read/Atomic handled by RDMA NIC.
  - Use RDMA *max_rd_atomic* feature at a QP(Queue Pair) level, which
    allows us to adjust the number of outstanding RDMA Read or Atomic operations
    handled by RDMA NIC.
  - Note that we set QP's *max_rd_atomic* as the RNIC's max_qp_rd_atom by default.
    By this, the throughput of RDMA Read is improved from ~0.9M requests per second (RPS)
    to ~4.9M RPS in a testbed with Mellanox CX4 NIC.

Features that will be supported as next plans:

- Multi-thread RDMA IO model.
- Adaptive event/polling switching.
- Support connection-level RDMA QoS feature.
- Support enhanced atomic operations including:
  - Masked Compare and Swap
  - Masked Fetch and Add 
- Support XRC--- [eXtended Reliable Connected Transport Service for InfiniBand](https://docs.nvidia.com/networking/display/mlnxofedv497100lts/advanced+transport)
  - Significantly reduce QPs number and the associated memory resources required when
    establishing all-to-all process connectivity in large clusters.
- Support Dynamically Connected Transport (DCT)
  - DCT connections only stay connected when they are active.
  - Smaller memory footprint, less overhead to set connections, higher
    on-chip cache utilization.
  - Note that DCT is supported only in mlx5 driver.
- Support resource domain for higher data-path performance.
- Support User-Mode Memory Registration (UMR) for efficiently
  scattering data through appropriate memory keys on the remote side.
- ...




## SnowRDMA Usage

SnowRDMA provides easy-to-use RDMA programming interfaces for control
and data plane operations while preserving high performance networking,
so that a developer without RDMA experience can easily take advantage
of performance benefits by RDMA--- e.g., ultra-low latency at a 
sub-microsecond level, high throughput(25Gbps~800Gbps), and near-zero 
CPU utilization. This provides three types of interfaces:

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

  /* set AcceptCallback for RDMA server */
  typedef void (*RdmaAcceptCallbackFunc)(RdmaConn *conn);
  int rdmaServerSetAcceptCallback(RdmaListener *listener, RdmaAcceptCallbackFunc func);

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

  /* set RecvCallback for each RDMA connection */
  typedef void (*RdmaRecvCallbackFunc)(RdmaConn *conn, void *data, size_t data_len);
  int rdmaConnSetRecvCallback(RdmaConn *conn, RdmaRecvCallbackFunc func);
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
