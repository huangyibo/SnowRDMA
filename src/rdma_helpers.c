#include "rdma_helpers.h"

struct ibv_mr *rdma_exp_reg_phys_mem_range(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size,
                      IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
}

struct ibv_mr *rdma_exp_reg_phys_mem_full(struct ibv_pd *pd)
{
    struct ibv_exp_reg_mr_in in = {0};
    in.pd = pd;
    in.addr = NULL;
    in.length = 0;
    in.exp_access = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ |
                    IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_LOCAL_WRITE |
                    IBV_EXP_ACCESS_PHYSICAL_ADDR;
    return ibv_exp_reg_mr(&in);
}

struct ibv_mr *rdma_reg_mem_readonly(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
}

struct ibv_mr *rdma_reg_mem_writeonly(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
}

struct ibv_mr *rdma_reg_mem(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size,
                      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
                          IBV_ACCESS_REMOTE_WRITE);
}

struct ibv_mr *rdma_reg_mem_atomic(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size,
                      IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE |
                          IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
}

struct ibv_mr *rdma_reg_mem_for_mw(struct ibv_pd *pd, void *buf, size_t size)
{
    return ibv_reg_mr(pd, buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_MW_BIND);
}

void rdma_dereg_mem(struct ibv_mr *mr)
{
    ibv_dereg_mr(mr);
}

int rdma_poll_send_comp(struct ibv_qp *qp, struct ibv_wc *wc, int num)
{
    return ibv_poll_cq(qp->send_cq, num, wc);
}

int rdma_poll_recv_comp(struct ibv_qp *qp, struct ibv_wc *wc, int num)
{
    return ibv_poll_cq(qp->recv_cq, num, wc);
}

int rdma_post_srq_recv(struct ibv_srq *srq, uint64_t wr_id,
                       uint64_t local_addr, uint32_t lkey,
                       uint32_t length)
{
    struct ibv_sge sge;
    struct ibv_recv_wr wr, *bad;

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_srq_recv(srq, &wr, &bad);
}

int rdma_post_recv(struct ibv_qp *qp, uint64_t wr_id,
                   uint64_t local_addr, uint32_t lkey,
                   uint32_t length)
{
    struct ibv_sge sge;
    struct ibv_recv_wr wr, *bad;

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_recv(qp, &wr, &bad);
}

int rdma_two_sided_send(struct ibv_qp *qp, enum ibv_wr_opcode opcode,
                        const uint32_t max_inline_data, unsigned int send_flags,
                        uint64_t wr_id, uint32_t imm_data, uint64_t local_addr,
                        uint32_t lkey, uint32_t length)
{

    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad;

    if (length != 0 && length <= max_inline_data)
    {
        send_flags |= IBV_SEND_INLINE;
    }

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = opcode;

    wr.send_flags = send_flags;
    wr.imm_data = imm_data;

    return ibv_post_send(qp, &wr, &bad);
}

int rdma_one_sided_send(struct ibv_qp *qp, enum ibv_wr_opcode opcode,
                        const uint32_t max_inline_data, unsigned int send_flags,
                        uint64_t wr_id, uint32_t imm_data,
                        uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey, uint32_t length)
{
    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad;

    if (length != 0 && length <= max_inline_data)
    {
        send_flags |= IBV_SEND_INLINE;
    }

    sge.addr = local_addr;
    sge.length = length;
    sge.lkey = lkey;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = opcode;

    wr.send_flags = send_flags;
    wr.imm_data = imm_data;

    wr.wr.rdma.remote_addr = remote_addr;
    wr.wr.rdma.rkey = rkey;

    return ibv_post_send(qp, &wr, &bad);
}

int rdma_send_signaled(struct ibv_qp *qp, uint64_t wr_id,
                       uint64_t local_addr, uint32_t length,
                       uint32_t lkey, const uint32_t max_inline_data)
{
    return rdma_two_sided_send(qp, IBV_WR_SEND, max_inline_data,
                               IBV_SEND_SIGNALED, wr_id, 0,
                               local_addr, lkey, length);
}

int rdma_send(struct ibv_qp *qp, uint64_t wr_id,
              uint64_t local_addr, uint32_t length,
              uint32_t lkey, const uint32_t max_inline_data)
{
    return rdma_two_sided_send(qp, IBV_WR_SEND, max_inline_data,
                               0, wr_id, 0, local_addr, lkey, length);
}

int rdma_send_with_imm_signaled(struct ibv_qp *qp, uint64_t wr_id, uint32_t imm_data,
                                uint64_t local_addr, uint32_t length,
                                uint32_t lkey, const uint32_t max_inline_data)
{
    return rdma_two_sided_send(qp, IBV_WR_SEND_WITH_IMM,
                               max_inline_data, IBV_SEND_SIGNALED,
                               wr_id, 0, local_addr, lkey, length);
}

int rdma_send_with_imm(struct ibv_qp *qp, uint64_t wr_id, uint32_t imm_data,
                       uint64_t local_addr, uint32_t length,
                       uint32_t lkey, const uint32_t max_inline_data)
{
    return rdma_two_sided_send(qp, IBV_WR_SEND_WITH_IMM,
                               max_inline_data, 0, wr_id, 0,
                               local_addr, lkey, length);
}

int rdma_write_signaled(struct ibv_qp *qp, uint64_t wr_id,
                        uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey,
                        uint32_t length, const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_WRITE, max_inline_data,
                               IBV_SEND_SIGNALED, wr_id, 0, local_addr,
                               lkey, remote_addr, rkey, length);
}

int rdma_write(struct ibv_qp *qp, uint64_t wr_id,
               uint64_t local_addr, uint32_t lkey,
               uint64_t remote_addr, uint32_t rkey,
               uint32_t length, const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_WRITE, max_inline_data,
                               0, wr_id, 0, local_addr, lkey,
                               remote_addr, rkey, length);
}

/** TODO: Need to rethink this interface design */
int rdma_write_send_signaled(struct ibv_qp *qp, uint64_t wr_id,
                             uint64_t local_addr, uint32_t lkey,
                             uint64_t remote_addr, uint32_t rkey, uint32_t length,
                             uint32_t payload, const uint32_t max_inline_data)
{
    struct ibv_sge sge[2];
    struct ibv_send_wr wr[2], *bad;

    sge[0].addr = local_addr;
    sge[0].length = length;
    sge[0].lkey = lkey;

    wr[0].wr_id = wr_id;
    wr[0].next = &wr[1];
    wr[0].sg_list = &sge[0];
    wr[0].num_sge = 1;
    wr[0].opcode = IBV_WR_RDMA_WRITE;
    wr[0].send_flags = (length <= max_inline_data ? IBV_SEND_INLINE : 0);

    wr[0].wr.rdma.remote_addr = remote_addr;
    wr[0].wr.rdma.rkey = rkey;

    sge[1].addr = local_addr;
    sge[1].length = payload;
    sge[1].lkey = lkey;

    wr[1].wr_id = wr_id;
    wr[1].next = NULL;
    wr[1].sg_list = &sge[1];
    wr[1].num_sge = 1;
    wr[1].opcode = IBV_WR_SEND;
    wr[1].send_flags = IBV_SEND_SIGNALED |
                       (payload <= max_inline_data ? IBV_SEND_INLINE : 0);

    return ibv_post_send(qp, wr, &bad);
}

/** TODO: Need to rethink this interface design */
int rdma_write_write_signaled(struct ibv_qp *qp, uint64_t wr_id,
                              uint64_t local_addr, uint32_t lkey,
                              uint64_t remote_addr, uint32_t rkey, uint32_t length,
                              uint32_t payload, const uint32_t max_inline_data)
{
    struct ibv_sge sge[2];
    struct ibv_send_wr wr[2], *bad;

    sge[0].addr = local_addr;
    sge[0].length = length;
    sge[0].lkey = lkey;

    wr[0].wr_id = wr_id;
    wr[0].next = &wr[1];
    wr[0].sg_list = &sge[0];
    wr[0].num_sge = 1;
    wr[0].opcode = IBV_WR_RDMA_WRITE;
    wr[0].send_flags = (length <= max_inline_data ? IBV_SEND_INLINE : 0);

    wr[0].wr.rdma.remote_addr = remote_addr;
    wr[0].wr.rdma.rkey = rkey;

    sge[1].addr = local_addr;
    sge[1].length = payload;
    sge[1].lkey = lkey;

    wr[1].wr_id = wr_id;
    wr[1].next = NULL;
    wr[1].sg_list = &sge[1];
    wr[1].num_sge = 1;
    wr[1].opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    wr[1].send_flags = IBV_SEND_SIGNALED |
                       (payload <= max_inline_data ? IBV_SEND_INLINE : 0);

    wr[1].wr.rdma.remote_addr = remote_addr;
    wr[1].wr.rdma.rkey = rkey;

    return ibv_post_send(qp, wr, &bad);
}

int rdma_send_cas_signaled(struct ibv_qp *qp, uint64_t wr_id,
                           uint64_t local_addr, uint32_t lkey,
                           uint64_t remote_addr, uint32_t rkey,
                           uint64_t expected, uint64_t swap)
{
    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad;

    sge.addr = local_addr;
    sge.length = sizeof(uint64_t);
    sge.lkey = lkey;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
    wr.send_flags = IBV_SEND_SIGNALED;

    wr.wr.atomic.remote_addr = remote_addr;
    wr.wr.atomic.rkey = rkey;
    wr.wr.atomic.compare_add = expected; /* expected value in remote address */
    wr.wr.atomic.swap = swap;            /* the value that remote address will be assigned to */

    return ibv_post_send(qp, &wr, &bad);
}

int rdma_write_with_imm_signaled(struct ibv_qp *qp, uint64_t wr_id,
                                 uint32_t imm_data, uint64_t local_addr, uint32_t lkey,
                                 uint64_t remote_addr, uint32_t rkey, uint32_t length,
                                 const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_WRITE_WITH_IMM, max_inline_data,
                               IBV_SEND_SIGNALED, wr_id, imm_data, local_addr,
                               lkey, remote_addr, rkey, length);
}

int rdma_write_with_imm(struct ibv_qp *qp, uint64_t wr_id,
                        uint32_t imm_data, uint64_t local_addr, uint32_t lkey,
                        uint64_t remote_addr, uint32_t rkey, uint32_t length,
                        const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_WRITE_WITH_IMM, max_inline_data,
                               0, wr_id, imm_data, local_addr,
                               lkey, remote_addr, rkey, length);
}

int rdma_read_signaled(struct ibv_qp *qp, uint64_t wr_id,
                       uint64_t local_addr, uint32_t lkey,
                       uint64_t remote_addr, uint32_t rkey,
                       uint32_t length, const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_READ, max_inline_data,
                               IBV_SEND_SIGNALED, wr_id, 0, local_addr,
                               lkey, remote_addr, rkey, length);
}

int rdma_read(struct ibv_qp *qp, uint64_t wr_id,
              uint64_t local_addr, uint32_t lkey,
              uint64_t remote_addr, uint32_t rkey,
              uint32_t length, const uint32_t max_inline_data)
{
    return rdma_one_sided_send(qp, IBV_WR_RDMA_READ, max_inline_data,
                               0, wr_id, 0, local_addr,
                               lkey, remote_addr, rkey, length);
}
