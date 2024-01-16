#ifndef __RDMA_HELPERS_H_
#define __RDMA_HELPERS_H_

#include <rdma/rdma_cma.h>
#include <stdlib.h>

struct ibv_mr *rdma_exp_reg_phys_mem_range(struct ibv_pd *pd, void *buf, size_t size);

struct ibv_mr *rdma_exp_reg_phys_mem_full(struct ibv_pd *pd);

struct ibv_mr *rdma_reg_mem_readonly(struct ibv_pd *pd, void *buf, size_t size);

struct ibv_mr *rdma_reg_mem_writeonly(struct ibv_pd *pd, void *buf, size_t size);
/* with Write and Read */
struct ibv_mr *rdma_reg_mem(struct ibv_pd *pd, void *buf, size_t size);

struct ibv_mr *rdma_reg_mem_atomic(struct ibv_pd *pd, void *buf, size_t size);

struct ibv_mr *rdma_reg_mem_for_mw(struct ibv_pd *pd, void *buf, size_t size);

void rdma_dereg_mem(struct ibv_mr *mr);

int rdma_poll_send_comp(struct ibv_qp *qp, struct ibv_wc *wc, int num);

int rdma_poll_recv_comp(struct ibv_qp *qp, struct ibv_wc *wc, int num);

int rdma_post_srq_recv(struct ibv_srq *srq, uint64_t wr_id,
                       uint64_t local_addr, uint32_t lkey,
                       uint32_t length);

int rdma_post_recv(struct ibv_qp *qp, uint64_t wr_id,
                   uint64_t local_addr, uint32_t lkey,
                   uint32_t length);

int rdma_two_sided_send(struct ibv_qp *qp, enum ibv_wr_opcode opcode,
                        const uint32_t max_inline_data, unsigned int send_flags,
                        uint64_t wr_id, uint32_t imm_data, uint64_t local_addr,
                        uint32_t lkey, uint32_t length);

int rdma_one_sided_send(struct ibv_qp *qp, enum ibv_wr_opcode opcode,
                        const uint32_t max_inline_data, unsigned int send_flags,
                        uint64_t wr_id, uint32_t imm_data,
                        uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey, uint32_t length);

int rdma_send_signaled(struct ibv_qp *qp, uint64_t wr_id,
                       uint64_t local_addr, uint32_t length,
                       uint32_t lkey, const uint32_t max_inline_data);

int rdma_send(struct ibv_qp *qp, uint64_t wr_id,
              uint64_t local_addr, uint32_t length,
              uint32_t lkey, const uint32_t max_inline_data);

int rdma_send_with_imm_signaled(struct ibv_qp *qp, uint64_t wr_id, uint32_t imm_data,
                                uint64_t local_addr, uint32_t length,
                                uint32_t lkey, const uint32_t max_inline_data);

int rdma_send_with_imm(struct ibv_qp *qp, uint64_t wr_id, uint32_t imm_data,
                       uint64_t local_addr, uint32_t length,
                       uint32_t lkey, const uint32_t max_inline_data);

int rdma_write_signaled(struct ibv_qp *qp, uint64_t wr_id,
                        uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey,
                        uint32_t length, const uint32_t max_inline_data);

int rdma_write(struct ibv_qp *qp, uint64_t wr_id,
               uint64_t local_addr, uint32_t lkey,
               uint64_t remote_addr, uint32_t rkey,
               uint32_t length, const uint32_t max_inline_data);

/** TODO: Need to rethink this interface design */
int rdma_write_send_signaled(struct ibv_qp *qp, uint64_t wr_id,
                             uint64_t local_addr, uint32_t lkey,
                             uint64_t remote_addr, uint32_t rkey, uint32_t length,
                             uint32_t payload, const uint32_t max_inline_data);

/** TODO: Need to rethink this interface design */
int rdma_write_write_signaled(struct ibv_qp *qp, uint64_t wr_id,
                              uint64_t local_addr, uint32_t lkey,
                              uint64_t remote_addr, uint32_t rkey, uint32_t length,
                              uint32_t payload, const uint32_t max_inline_data);

int rdma_send_cas_signaled(struct ibv_qp *qp, uint64_t wr_id,
                           uint64_t local_addr, uint32_t lkey,
                           uint64_t remote_addr, uint32_t rkey,
                           uint64_t expected, uint64_t swap);

int rdma_write_with_imm_signaled(struct ibv_qp *qp, uint64_t wr_id,
                                 uint32_t imm_data, uint64_t local_addr, uint32_t lkey,
                                 uint64_t remote_addr, uint32_t rkey, uint32_t length,
                                 const uint32_t max_inline_data);

int rdma_write_with_imm(struct ibv_qp *qp, uint64_t wr_id,
                        uint32_t imm_data, uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey, uint32_t length,
                        const uint32_t max_inline_data);

int rdma_read_signaled(struct ibv_qp *qp, uint64_t wr_id,
                       uint64_t local_addr, uint32_t lkey,
                       uint64_t remote_addr, uint32_t rkey,
                       uint32_t length, const uint32_t max_inline_data);

int rdma_read(struct ibv_qp *qp, uint64_t wr_id,
              uint64_t local_addr, uint32_t lkey,
              uint64_t remote_addr, uint32_t rkey,
              uint32_t length, const uint32_t max_inline_data);

#endif // !__RDMA_HELPERS_H_