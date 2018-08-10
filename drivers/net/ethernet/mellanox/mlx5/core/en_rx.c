/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/prefetch.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#endif
#include "en.h"
#include "en_tc.h"
#include "eswitch.h"
#include "en_rep.h"
#include "ipoib/ipoib.h"
#include "en_accel/ipsec_rxtx.h"
#include "lib/clock.h"

static inline bool mlx5e_rx_hw_stamp(struct hwtstamp_config *config)
{
	return config->rx_filter == HWTSTAMP_FILTER_ALL;
}

static inline void mlx5e_read_cqe_slot(struct mlx5e_cq *cq, u32 cqcc,
				       void *data)
{
	u32 ci = cqcc & cq->wq.sz_m1;

	memcpy(data, mlx5_cqwq_get_wqe(&cq->wq, ci), sizeof(struct mlx5_cqe64));
}

static inline void mlx5e_read_title_slot(struct mlx5e_rq *rq,
					 struct mlx5e_cq *cq, u32 cqcc)
{
	mlx5e_read_cqe_slot(cq, cqcc, &cq->title);
	cq->decmprs_left        = be32_to_cpu(cq->title.byte_cnt);
	cq->decmprs_wqe_counter = be16_to_cpu(cq->title.wqe_counter);
	rq->stats.cqe_compress_blks++;
}

static inline void mlx5e_read_mini_arr_slot(struct mlx5e_cq *cq, u32 cqcc)
{
	mlx5e_read_cqe_slot(cq, cqcc, cq->mini_arr);
	cq->mini_arr_idx = 0;
}

static inline void mlx5e_cqes_update_owner(struct mlx5e_cq *cq, u32 cqcc, int n)
{
	u8 op_own = (cqcc >> cq->wq.log_sz) & 1;
	u32 wq_sz = 1 << cq->wq.log_sz;
	u32 ci = cqcc & cq->wq.sz_m1;
	u32 ci_top = min_t(u32, wq_sz, ci + n);

	for (; ci < ci_top; ci++, n--) {
		struct mlx5_cqe64 *cqe = mlx5_cqwq_get_wqe(&cq->wq, ci);

		cqe->op_own = op_own;
	}

	if (unlikely(ci == wq_sz)) {
		op_own = !op_own;
		for (ci = 0; ci < n; ci++) {
			struct mlx5_cqe64 *cqe = mlx5_cqwq_get_wqe(&cq->wq, ci);

			cqe->op_own = op_own;
		}
	}
}

static inline void mlx5e_decompress_cqe(struct mlx5e_rq *rq,
					struct mlx5e_cq *cq, u32 cqcc)
{
	cq->title.byte_cnt     = cq->mini_arr[cq->mini_arr_idx].byte_cnt;
	cq->title.check_sum    = cq->mini_arr[cq->mini_arr_idx].checksum;
	cq->title.op_own      &= 0xf0;
	cq->title.op_own      |= 0x01 & (cqcc >> cq->wq.log_sz);
	cq->title.wqe_counter  = cpu_to_be16(cq->decmprs_wqe_counter);

	if (rq->wq_type == MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ)
		cq->decmprs_wqe_counter +=
			mpwrq_get_cqe_consumed_strides(&cq->title);
	else
		cq->decmprs_wqe_counter =
			(cq->decmprs_wqe_counter + 1) & rq->wq.sz_m1;
}

static inline void mlx5e_decompress_cqe_no_hash(struct mlx5e_rq *rq,
						struct mlx5e_cq *cq, u32 cqcc)
{
	mlx5e_decompress_cqe(rq, cq, cqcc);
	cq->title.rss_hash_type   = 0;
	cq->title.rss_hash_result = 0;
}

static inline u32 mlx5e_decompress_cqes_cont(struct mlx5e_rq *rq,
					     struct mlx5e_cq *cq,
					     int update_owner_only,
					     int budget_rem)
{
	u32 cqcc = cq->wq.cc + update_owner_only;
	u32 cqe_count;
	u32 i;

	cqe_count = min_t(u32, cq->decmprs_left, budget_rem);

	for (i = update_owner_only; i < cqe_count;
	     i++, cq->mini_arr_idx++, cqcc++) {
		if (cq->mini_arr_idx == MLX5_MINI_CQE_ARRAY_SIZE)
			mlx5e_read_mini_arr_slot(cq, cqcc);

		mlx5e_decompress_cqe_no_hash(rq, cq, cqcc);
		rq->handle_rx_cqe(rq, &cq->title);
	}
	mlx5e_cqes_update_owner(cq, cq->wq.cc, cqcc - cq->wq.cc);
	cq->wq.cc = cqcc;
	cq->decmprs_left -= cqe_count;
	rq->stats.cqe_compress_pkts += cqe_count;

	return cqe_count;
}

static inline u32 mlx5e_decompress_cqes_start(struct mlx5e_rq *rq,
					      struct mlx5e_cq *cq,
					      int budget_rem)
{
	mlx5e_read_title_slot(rq, cq, cq->wq.cc);
	mlx5e_read_mini_arr_slot(cq, cq->wq.cc + 1);
	mlx5e_decompress_cqe(rq, cq, cq->wq.cc);
	rq->handle_rx_cqe(rq, &cq->title);
	cq->mini_arr_idx++;

	return mlx5e_decompress_cqes_cont(rq, cq, 1, budget_rem) - 1;
}

#define RQ_PAGE_SIZE(rq) ((1 << rq->buff.page_order) << PAGE_SHIFT)

static inline void mlx5e_rx_cache_page_swap(struct mlx5e_page_cache *cache,
					    u32 a, u32 b)
{
	struct mlx5e_dma_info tmp;

	tmp = cache->page_cache[a];
	cache->page_cache[a] = cache->page_cache[b];
	cache->page_cache[b] = tmp;
}

static inline void
mlx5e_rx_cache_reduce_reset_watch(struct mlx5e_page_cache *cache)
{
	struct mlx5e_page_cache_reduce *reduce = &cache->reduce;

	reduce->next_ts = ilog2(cache->sz) == cache->log_min_sz ?
		MAX_JIFFY_OFFSET :
		jiffies + reduce->graceful_period;
	reduce->successive = 0;
}

static inline bool mlx5e_rx_cache_is_empty(struct mlx5e_page_cache *cache)
{
	return cache->head < 0;
}
static inline bool mlx5e_rx_cache_page_busy(struct mlx5e_page_cache *cache,
					    u32 i)
{
	return atomic_read(&cache->page_cache[i].page->_count) != 1;
}

static inline bool mlx5e_rx_cache_check_reduce(struct mlx5e_rq *rq)
{
	struct mlx5e_page_cache *cache = &rq->page_cache;

	if (unlikely(test_bit(MLX5E_RQ_STATE_CACHE_REDUCE_PENDING, &rq->state)))
		return false;

	if (time_before(jiffies, cache->reduce.next_ts))
		return false;

	if (likely(!mlx5e_rx_cache_is_empty(cache)) &&
	    mlx5e_rx_cache_page_busy(cache, cache->head))
		goto reset_watch;

	if (ilog2(cache->sz) == cache->log_min_sz)
		goto reset_watch;

	/* would like to reduce */
	if (cache->reduce.successive < MLX5E_PAGE_CACHE_REDUCE_SUCCESSIVE_CNT) {
		cache->reduce.successive++;
		return false;
	}

	return true;

reset_watch:
	mlx5e_rx_cache_reduce_reset_watch(cache);
	return false;

}

static inline void mlx5e_rx_cache_may_reduce(struct mlx5e_rq *rq)
{
	struct mlx5e_page_cache *cache = &rq->page_cache;
	struct mlx5e_page_cache_reduce *reduce = &cache->reduce;
	int max_new_head;

	if (!mlx5e_rx_cache_check_reduce(rq))
		return;

	/* do reduce */
	rq->stats.cache_rdc++;
	cache->sz >>= 1;
	max_new_head = (cache->sz >> 1) - 1;
	if (cache->head > max_new_head) {
		u32 npages = cache->head - max_new_head;

		cache->head = max_new_head;
		if (cache->lrs >= cache->head)
			cache->lrs = 0;

		memcpy(reduce->pending, &cache->page_cache[cache->head + 1],
		       npages * sizeof(*reduce->pending));
		reduce->npages = npages;
		set_bit(MLX5E_RQ_STATE_CACHE_REDUCE_PENDING, &rq->state);
	}

	mlx5e_rx_cache_reduce_reset_watch(cache);
}

static inline bool mlx5e_rx_cache_extend(struct mlx5e_rq *rq)
{
	struct mlx5e_page_cache *cache = &rq->page_cache;
	struct mlx5e_page_cache_reduce *reduce = &cache->reduce;

	if (ilog2(cache->sz) == cache->log_max_sz)
		return false;

	rq->stats.cache_ext++;
	cache->sz <<= 1;

	mlx5e_rx_cache_reduce_reset_watch(cache);
	schedule_delayed_work_on(smp_processor_id(), &reduce->reduce_work,
				 reduce->delay);
	return true;
}

static inline bool mlx5e_page_is_reserved(struct page *page)
{
	return page_is_pfmemalloc(page) || page_to_nid(page) != numa_node_id();
}

static inline bool mlx5e_rx_cache_put(struct mlx5e_rq *rq,
				      struct mlx5e_dma_info *dma_info)
{
	struct mlx5e_page_cache *cache = &rq->page_cache;

	if (unlikely(mlx5e_page_is_reserved(dma_info->page))) {
		rq->stats.cache_waive++;
		return false;
	}

	if (unlikely(cache->head == cache->sz - 1)) {
		if (!mlx5e_rx_cache_extend(rq)) {
			rq->stats.cache_full++;
			return false;
		}
	}

	if (unlikely(page_is_pfmemalloc(dma_info->page)))
		return false;

	cache->page_cache[++cache->head] = *dma_info;
	return true;
}

static inline bool mlx5e_rx_cache_get(struct mlx5e_rq *rq,
				      struct mlx5e_dma_info *dma_info)
{
	struct mlx5e_page_cache *cache = &rq->page_cache;

	if (unlikely(mlx5e_rx_cache_is_empty(cache)))
		goto err_no_page;

	mlx5e_rx_cache_page_swap(cache, cache->head, cache->lrs);
	cache->lrs++;
	if (cache->lrs >= cache->head)
		cache->lrs = 0;
	if (mlx5e_rx_cache_page_busy(cache, cache->head))
		goto err_no_page;

	rq->stats.cache_reuse++;
	*dma_info = cache->page_cache[cache->head--];

	return true;

err_no_page:
	cache->reduce.successive = 0;

	return false;
}

static inline int mlx5e_page_alloc_mapped(struct mlx5e_rq *rq,
					  struct mlx5e_dma_info *dma_info)
{
	if (!mlx5e_rx_cache_get(rq, dma_info)) {
		dma_info->page = dev_alloc_pages(rq->buff.page_order);
		if (unlikely(!dma_info->page))
			return -ENOMEM;
		rq->stats.cache_alloc++;
	}

	dma_info->addr = dma_map_page(rq->pdev, dma_info->page, 0,
				      RQ_PAGE_SIZE(rq), rq->buff.map_dir);
	if (unlikely(dma_mapping_error(rq->pdev, dma_info->addr))) {
		put_page(dma_info->page);
		dma_info->page = NULL;
		return -ENOMEM;
	}

	return 0;
}

void mlx5e_page_release(struct mlx5e_rq *rq, struct mlx5e_dma_info *dma_info,
			bool recycle)
{
	dma_unmap_page(rq->pdev, dma_info->addr, RQ_PAGE_SIZE(rq),
		       rq->buff.map_dir);

	if (likely(recycle) && mlx5e_rx_cache_put(rq, dma_info))
		return;

	put_page(dma_info->page);
}

static inline bool mlx5e_page_reuse(struct mlx5e_rq *rq,
				    struct mlx5e_wqe_frag_info *wi)
{
	return rq->wqe.page_reuse && wi->di.page &&
		(wi->offset + rq->wqe.frag_sz <= RQ_PAGE_SIZE(rq)) &&
		!mlx5e_page_is_reserved(wi->di.page);
}

int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct mlx5e_wqe_frag_info *wi = &rq->wqe.frag_info[ix];

	/* check if page exists, hence can be reused */
	if (!wi->di.page) {
		if (unlikely(mlx5e_page_alloc_mapped(rq, &wi->di)))
			return -ENOMEM;
		wi->offset = 0;
	}

	wqe->data.addr = cpu_to_be64(wi->di.addr + wi->offset +
				     rq->rx_headroom);
	return 0;
}

static inline void mlx5e_free_rx_wqe(struct mlx5e_rq *rq,
				     struct mlx5e_wqe_frag_info *wi)
{
	mlx5e_page_release(rq, &wi->di, true);
	wi->di.page = NULL;
}

static inline void mlx5e_free_rx_wqe_reuse(struct mlx5e_rq *rq,
					   struct mlx5e_wqe_frag_info *wi)
{
	if (mlx5e_page_reuse(rq, wi)) {
		rq->stats.page_reuse++;
		return;
	}

	mlx5e_free_rx_wqe(rq, wi);
}

void mlx5e_dealloc_rx_wqe(struct mlx5e_rq *rq, u16 ix)
{
	struct mlx5e_wqe_frag_info *wi = &rq->wqe.frag_info[ix];

	if (wi->di.page)
		mlx5e_free_rx_wqe(rq, wi);
}

static inline int mlx5e_mpwqe_strides_per_page(struct mlx5e_rq *rq)
{
	return rq->mpwqe_num_strides >> MLX5_MPWRQ_WQE_PAGE_ORDER;
}

static inline void mlx5e_add_skb_frag_mpwqe(struct mlx5e_rq *rq,
					    struct sk_buff *skb,
					    struct mlx5e_mpw_info *wi,
					    u32 page_idx, u32 frag_offset,
					    u32 len)
{
	unsigned int truesize =	ALIGN(len, rq->mpwqe_stride_sz);

	dma_sync_single_for_cpu(rq->pdev,
				wi->umr.dma_info[page_idx].addr + frag_offset,
				len, DMA_FROM_DEVICE);
	wi->skbs_frags[page_idx]++;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			wi->umr.dma_info[page_idx].page, frag_offset,
			len, truesize);
}

static inline void
mlx5e_copy_skb_header_mpwqe(struct device *pdev,
			    struct sk_buff *skb,
			    struct mlx5e_mpw_info *wi,
			    u32 page_idx, u32 offset,
			    u32 headlen)
{
	u16 headlen_pg = min_t(u32, headlen, PAGE_SIZE - offset);
	struct mlx5e_dma_info *dma_info = &wi->umr.dma_info[page_idx];
	unsigned int len;

	 /* Aligning len to sizeof(long) optimizes memcpy performance */
	len = ALIGN(headlen_pg, sizeof(long));
	dma_sync_single_for_cpu(pdev, dma_info->addr + offset, len,
				DMA_FROM_DEVICE);
	skb_copy_to_linear_data_offset(skb, 0,
				       page_address(dma_info->page) + offset,
				       len);
	if (unlikely(offset + headlen > PAGE_SIZE)) {
		dma_info++;
		headlen_pg = len;
		len = ALIGN(headlen - headlen_pg, sizeof(long));
		dma_sync_single_for_cpu(pdev, dma_info->addr, len,
					DMA_FROM_DEVICE);
		skb_copy_to_linear_data_offset(skb, headlen_pg,
					       page_address(dma_info->page),
					       len);
	}
}

static inline void mlx5e_post_umr_wqe(struct mlx5e_rq *rq, u16 ix)
{
	struct mlx5e_mpw_info *wi = &rq->mpwqe.info[ix];
	struct mlx5e_icosq *sq = &rq->channel->icosq;
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5e_umr_wqe *wqe;
	u8 num_wqebbs = DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_BB);
	u16 pi;

	/* fill sq edge with nops to avoid wqe wrap around */
	while ((pi = (sq->pc & wq->sz_m1)) > sq->edge) {
		sq->db.ico_wqe[pi].opcode = MLX5_OPCODE_NOP;
		sq->db.ico_wqe[pi].num_wqebbs = 1;
		mlx5e_post_nop(wq, sq->sqn, &sq->pc);
	}

	wqe = mlx5_wq_cyc_get_wqe(wq, pi);
	memcpy(wqe, &wi->umr.wqe, sizeof(*wqe));
	wqe->ctrl.opmod_idx_opcode =
		cpu_to_be32((sq->pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
			    MLX5_OPCODE_UMR);

	sq->db.ico_wqe[pi].opcode = MLX5_OPCODE_UMR;
	sq->db.ico_wqe[pi].num_wqebbs = num_wqebbs;
	sq->pc += num_wqebbs;
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, &wqe->ctrl);
}

static int mlx5e_alloc_rx_umr_mpwqe(struct mlx5e_rq *rq,
				    struct mlx5e_rx_wqe *wqe,
				    u16 ix)
{
	struct mlx5e_mpw_info *wi = &rq->mpwqe.info[ix];
	u64 dma_offset = (u64)mlx5e_get_wqe_mtt_offset(rq, ix) << PAGE_SHIFT;
	int pg_strides = mlx5e_mpwqe_strides_per_page(rq);
	int err;
	int i;

	for (i = 0; i < MLX5_MPWRQ_PAGES_PER_WQE; i++) {
		struct mlx5e_dma_info *dma_info = &wi->umr.dma_info[i];

		err = mlx5e_page_alloc_mapped(rq, dma_info);
		if (unlikely(err))
			goto err_unmap;
		wi->umr.mtt[i] = cpu_to_be64(dma_info->addr | MLX5_EN_WR);
		atomic_add(pg_strides, &dma_info->page->_count);
		wi->skbs_frags[i] = 0;
	}

	wi->consumed_strides = 0;
	wqe->data.addr = cpu_to_be64(dma_offset);

	return 0;

err_unmap:
	while (--i >= 0) {
		struct mlx5e_dma_info *dma_info = &wi->umr.dma_info[i];

		atomic_sub(pg_strides, &dma_info->page->_count);
		mlx5e_page_release(rq, dma_info, true);
	}

	return err;
}

void mlx5e_free_rx_mpwqe(struct mlx5e_rq *rq, struct mlx5e_mpw_info *wi)
{
	int pg_strides = mlx5e_mpwqe_strides_per_page(rq);
	int i;

	for (i = 0; i < MLX5_MPWRQ_PAGES_PER_WQE; i++) {
		struct mlx5e_dma_info *dma_info = &wi->umr.dma_info[i];

		atomic_sub(pg_strides - wi->skbs_frags[i], &dma_info->page->_count);
		mlx5e_page_release(rq, dma_info, true);
	}
}

void mlx5e_post_rx_mpwqe(struct mlx5e_rq *rq)
{
	struct mlx5_wq_ll *wq = &rq->wq;
	struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(wq, wq->head);

	clear_bit(MLX5E_RQ_STATE_UMR_WQE_IN_PROGRESS, &rq->state);

	if (unlikely(!test_bit(MLX5E_RQ_STATE_ENABLED, &rq->state))) {
		mlx5e_free_rx_mpwqe(rq, &rq->mpwqe.info[wq->head]);
		return;
	}

	mlx5_wq_ll_push(wq, be16_to_cpu(wqe->next.next_wqe_index));

	/* ensure wqes are visible to device before updating doorbell record */
#ifdef dma_wmb
	dma_wmb();
#else
	wmb();
#endif

	mlx5_wq_ll_update_db_record(wq);

	mlx5e_rx_cache_may_reduce(rq);
}

int mlx5e_alloc_rx_mpwqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix)
{
	int err;

	err = mlx5e_alloc_rx_umr_mpwqe(rq, wqe, ix);
	if (unlikely(err))
		return err;
	set_bit(MLX5E_RQ_STATE_UMR_WQE_IN_PROGRESS, &rq->state);
	mlx5e_post_umr_wqe(rq, ix);
	return -EBUSY;
}

void mlx5e_dealloc_rx_mpwqe(struct mlx5e_rq *rq, u16 ix)
{
	struct mlx5e_mpw_info *wi = &rq->mpwqe.info[ix];

	mlx5e_free_rx_mpwqe(rq, wi);
}

#define RQ_CANNOT_POST(rq) \
	(!test_bit(MLX5E_RQ_STATE_ENABLED, &rq->state) || \
	 test_bit(MLX5E_RQ_STATE_UMR_WQE_IN_PROGRESS, &rq->state))

bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5_wq_ll *wq = &rq->wq;

	if (unlikely(RQ_CANNOT_POST(rq)))
		return false;

	while (!mlx5_wq_ll_is_full(wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(wq, wq->head);
		int err;

		err = rq->alloc_wqe(rq, wqe, wq->head);
		if (err == -EBUSY)
			return true;
		if (unlikely(err)) {
			rq->stats.buff_alloc_err++;
			break;
		}

		mlx5_wq_ll_push(wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
#ifdef dma_wmb
	dma_wmb();
#else
	wmb();
#endif

	mlx5_wq_ll_update_db_record(wq);

	mlx5e_rx_cache_may_reduce(rq);

	return !mlx5_wq_ll_is_full(wq);
}

static void mlx5e_lro_update_hdr(struct sk_buff *skb, struct mlx5_cqe64 *cqe,
				 u32 cqe_bcnt)
{
	struct ethhdr	*eth = (struct ethhdr *)(skb->data);
	struct iphdr	*ipv4;
	struct ipv6hdr	*ipv6;
	struct tcphdr	*tcp;
	int network_depth = 0;
	__be16 proto;
	u16 tot_len;

	u8 l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	int tcp_ack = ((l4_hdr_type == CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA) ||
		       (l4_hdr_type == CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA));

	skb->mac_len = ETH_HLEN;
	proto = __vlan_get_protocol(skb, eth->h_proto, &network_depth);

	ipv4 = (struct iphdr *)(skb->data + network_depth);
	ipv6 = (struct ipv6hdr *)(skb->data + network_depth);
	tot_len = cqe_bcnt - network_depth;

	if (proto == htons(ETH_P_IP)) {
		tcp = (struct tcphdr *)(skb->data + network_depth +
					sizeof(struct iphdr));
		ipv6 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	} else {
		tcp = (struct tcphdr *)(skb->data + network_depth +
					sizeof(struct ipv6hdr));
		ipv4 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
	}

	if (get_cqe_lro_tcppsh(cqe))
		tcp->psh                = 1;

	if (tcp_ack) {
		tcp->ack                = 1;
		tcp->ack_seq            = cqe->lro_ack_seq_num;
		tcp->window             = cqe->lro_tcp_win;
	}

	if (ipv4) {
		ipv4->ttl               = cqe->lro_min_ttl;
		ipv4->tot_len           = cpu_to_be16(tot_len);
		ipv4->check             = 0;
		ipv4->check             = ip_fast_csum((unsigned char *)ipv4,
						       ipv4->ihl);
	} else {
		ipv6->hop_limit         = cqe->lro_min_ttl;
		ipv6->payload_len       = cpu_to_be16(tot_len -
						      sizeof(struct ipv6hdr));
	}
}

static inline void mlx5e_skb_set_hash(struct mlx5_cqe64 *cqe,
				      struct sk_buff *skb)
{
	u8 cht = cqe->rss_hash_type;
	int ht = (cht & CQE_RSS_HTYPE_L4) ? PKT_HASH_TYPE_L4 :
		 (cht & CQE_RSS_HTYPE_IP) ? PKT_HASH_TYPE_L3 :
					    PKT_HASH_TYPE_NONE;
	skb_set_hash(skb, be32_to_cpu(cqe->rss_hash_result), ht);
}

static inline bool is_first_ethertype_ip(struct sk_buff *skb)
{
	__be16 ethertype = ((struct ethhdr *)skb->data)->h_proto;

	return (ethertype == htons(ETH_P_IP) || ethertype == htons(ETH_P_IPV6));
}

static inline void mlx5e_handle_csum(struct net_device *netdev,
				     struct mlx5_cqe64 *cqe,
				     struct mlx5e_rq *rq,
				     struct sk_buff *skb,
				     bool   lro)
{
	if (unlikely(!(netdev->features & NETIF_F_RXCSUM)))
		goto csum_none;

	if (lro) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		return;
	}

	if (is_first_ethertype_ip(skb)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = csum_unfold((__force __sum16)cqe->check_sum);
		rq->stats.csum_complete++;
		return;
	}

	if (likely((cqe->hds_ip_ext & CQE_L3_OK) &&
		   (cqe->hds_ip_ext & CQE_L4_OK))) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		if (cqe_is_tunneled(cqe)) {
			skb->csum_level = 1;
			skb->encapsulation = 1;
			rq->stats.csum_unnecessary_inner++;
		}
		return;
	}
csum_none:
	skb->ip_summed = CHECKSUM_NONE;
	rq->stats.csum_none++;
}

static inline void mlx5e_build_rx_skb(struct mlx5_cqe64 *cqe,
				      u32 cqe_bcnt,
				      struct mlx5e_rq *rq,
				      struct sk_buff *skb)
{
	struct net_device *netdev = rq->netdev;
	int lro_num_seg;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u8 l4_hdr_type;

	lro_num_seg = be32_to_cpu(cqe->srqn) >> 24;
	if (lro_num_seg > 1) {
		mlx5e_lro_update_hdr(skb, cqe, cqe_bcnt);
		skb_shinfo(skb)->gso_size = DIV_ROUND_UP(cqe_bcnt, lro_num_seg);
		/* Subtract one since we already counted this as one
		 * "regular" packet in mlx5e_complete_rx_cqe()
		 */
		rq->stats.packets += lro_num_seg - 1;
		rq->stats.lro_packets++;
		rq->stats.lro_bytes += cqe_bcnt;
		/* Flush GRO to avoid OOO packets, since GSO bypasses the
		 * GRO queue. This was fixed in dev_gro_receive() in kernel 4.10
		 */
		napi_gro_flush(rq->cq.napi, false);
	}

	if (unlikely(mlx5e_rx_hw_stamp(rq->tstamp)))
		skb_hwtstamps(skb)->hwtstamp =
				mlx5_timecounter_cyc2time(rq->clock, get_cqe_ts(cqe));

	skb_record_rx_queue(skb, rq->ix);

	if (likely(netdev->features & NETIF_F_RXHASH))
		mlx5e_skb_set_hash(cqe, skb);

	if (cqe_has_vlan(cqe))
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       be16_to_cpu(cqe->vlan_info));

	skb->mark = be32_to_cpu(cqe->sop_drop_qpn) & MLX5E_TC_FLOW_ID_MASK;

	l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	mlx5e_handle_csum(netdev, cqe, rq, skb,
			  !!lro_num_seg ||
			  (IS_SW_LRO(&priv->channels.params) &&
			  (l4_hdr_type != CQE_L4_HDR_TYPE_NONE) &&
			  (l4_hdr_type != CQE_L4_HDR_TYPE_UDP)));

	skb->protocol = eth_type_trans(skb, netdev);
	if (unlikely(mlx5_get_cqe_ft(cqe) ==
		     cpu_to_be32(MLX5_FS_OFFLOAD_FLOW_TAG)))
		skb->protocol = 0xffff;
}

static inline void mlx5e_complete_rx_cqe(struct mlx5e_rq *rq,
					 struct mlx5_cqe64 *cqe,
					 u32 cqe_bcnt,
					 struct sk_buff *skb)
{
	rq->stats.packets++;
	rq->stats.bytes += cqe_bcnt;
	mlx5e_build_rx_skb(cqe, cqe_bcnt, rq, skb);
}



static inline
struct sk_buff *skb_from_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe,
			     struct mlx5e_wqe_frag_info *wi, u32 cqe_bcnt)
{
	struct mlx5e_dma_info *di = &wi->di;
	struct sk_buff *skb;
	void *va, *data;
	u16 rx_headroom = rq->rx_headroom;
	u32 frag_size;

	va             = page_address(di->page) + wi->offset;
	data           = va + rx_headroom;
	frag_size      = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);

	dma_sync_single_range_for_cpu(rq->pdev,
				      di->addr + wi->offset,
				      0, frag_size,
				      DMA_FROM_DEVICE);
	prefetch(data);
	wi->offset += frag_size;

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		rq->stats.wqe_err++;
		return NULL;
	}


	skb = build_skb(va, frag_size);
	if (unlikely(!skb)) {
		rq->stats.buff_alloc_err++;
		return NULL;
	}

	/* queue up for recycling/reuse */
	atomic_inc(&di->page->_count);

	skb_reserve(skb, rx_headroom);
	skb_put(skb, cqe_bcnt);

	return skb;
}

void mlx5e_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct mlx5e_priv *priv = netdev_priv(rq->netdev);
	struct mlx5e_wqe_frag_info *wi;
	struct mlx5e_rx_wqe *wqe;
	__be16 wqe_counter_be;
	struct sk_buff *skb;
	u16 wqe_counter;
	u32 cqe_bcnt;

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	wi             = &rq->wqe.frag_info[wqe_counter];
	cqe_bcnt       = be32_to_cpu(cqe->byte_cnt);

	skb = skb_from_cqe(rq, cqe, wi, cqe_bcnt);
	if (!skb) {
		/* probably for XDP */
		if (rq->wqe.xdp_xmit) {
			wi->di.page = NULL;
			rq->wqe.xdp_xmit = false;
			/* do not return page to cache, it will be returned on XDP_TX completion */
			goto wq_ll_pop;
		}
		/* probably an XDP_DROP, save the page-reuse checks */
		mlx5e_free_rx_wqe(rq, wi);
		goto wq_ll_pop;
	}

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);
	if (IS_SW_LRO(&priv->channels.params))
		lro_receive_skb(&rq->sw_lro.lro_mgr, skb, NULL);
	else
	napi_gro_receive(rq->cq.napi, skb);

	mlx5e_free_rx_wqe_reuse(rq, wi);
wq_ll_pop:
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		       &wqe->next.next_wqe_index);
}

#ifdef CONFIG_MLX5_ESWITCH
void mlx5e_handle_rx_cqe_rep(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct net_device *netdev = rq->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_rep_priv *rpriv  = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5e_rep_context *context;
	struct mlx5e_wqe_frag_info *wi;
	struct mlx5e_rx_wqe *wqe;
	struct sk_buff *skb;
	__be16 wqe_counter_be;
	u16 wqe_counter;
	u32 cqe_bcnt;

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	wi             = &rq->wqe.frag_info[wqe_counter];
	cqe_bcnt       = be32_to_cpu(cqe->byte_cnt);

	skb = skb_from_cqe(rq, cqe, wi, cqe_bcnt);
	if (!skb) {
		if (rq->wqe.xdp_xmit) {
			wi->di.page = NULL;
			rq->wqe.xdp_xmit = false;
			/* do not return page to cache, it will be returned on XDP_TX completion */
			goto wq_ll_pop;
		}
		/* probably an XDP_DROP, save the page-reuse checks */
		mlx5e_free_rx_wqe(rq, wi);
		goto wq_ll_pop;
	}

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);

	context = mlx5e_rep_to_context(rep);
	if (context->vlan && skb_vlan_tag_present(skb))
		skb_vlan_pop(skb);

	napi_gro_receive(rq->cq.napi, skb);

	mlx5e_free_rx_wqe_reuse(rq, wi);
wq_ll_pop:
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		       &wqe->next.next_wqe_index);
}
#endif

static inline void mlx5e_mpwqe_fill_rx_skb(struct mlx5e_rq *rq,
					   struct mlx5_cqe64 *cqe,
					   struct mlx5e_mpw_info *wi,
					   u32 cqe_bcnt,
					   struct sk_buff *skb)
{
	u16 stride_ix      = mpwrq_get_cqe_stride_index(cqe);
	u32 wqe_offset     = stride_ix * rq->mpwqe_stride_sz;
	u32 head_offset    = wqe_offset & (PAGE_SIZE - 1);
	u32 page_idx       = wqe_offset >> PAGE_SHIFT;
	u32 head_page_idx  = page_idx;
	u16 headlen = min_t(u16, MLX5_MPWRQ_SMALL_PACKET_THRESHOLD, cqe_bcnt);
	u32 frag_offset    = head_offset + headlen;
	u16 byte_cnt       = cqe_bcnt - headlen;

	if (unlikely(frag_offset >= PAGE_SIZE)) {
		page_idx++;
		frag_offset -= PAGE_SIZE;
	}

	while (byte_cnt) {
		u32 pg_consumed_bytes =
			min_t(u32, PAGE_SIZE - frag_offset, byte_cnt);

		mlx5e_add_skb_frag_mpwqe(rq, skb, wi, page_idx, frag_offset,
					 pg_consumed_bytes);
		byte_cnt -= pg_consumed_bytes;
		frag_offset = 0;
		page_idx++;
	}
	/* copy header */
	mlx5e_copy_skb_header_mpwqe(rq->pdev, skb, wi, head_page_idx,
				    head_offset, headlen);
	/* skb linear part was allocated with headlen and aligned to long */
	skb->tail += headlen;
	skb->len  += headlen;
}

void mlx5e_handle_rx_cqe_mpwrq(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	u16 cstrides       = mpwrq_get_cqe_consumed_strides(cqe);
	struct mlx5e_priv *priv = netdev_priv(rq->netdev);
	u16 wqe_id         = be16_to_cpu(cqe->wqe_id);
	struct mlx5e_mpw_info *wi = &rq->mpwqe.info[wqe_id];
	struct mlx5e_rx_wqe  *wqe = mlx5_wq_ll_get_wqe(&rq->wq, wqe_id);
	struct sk_buff *skb;
	u16 cqe_bcnt;

	wi->consumed_strides += cstrides;

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		rq->stats.wqe_err++;
		goto mpwrq_cqe_out;
	}

	if (unlikely(mpwrq_is_filler_cqe(cqe))) {
		rq->stats.mpwqe_filler++;
		goto mpwrq_cqe_out;
	}

	skb = napi_alloc_skb(rq->cq.napi,
			     ALIGN(MLX5_MPWRQ_SMALL_PACKET_THRESHOLD,
				   sizeof(long)));
	if (unlikely(!skb)) {
		rq->stats.buff_alloc_err++;
		goto mpwrq_cqe_out;
	}

	prefetchw(skb->data);
	cqe_bcnt = mpwrq_get_cqe_byte_cnt(cqe);

	mlx5e_mpwqe_fill_rx_skb(rq, cqe, wi, cqe_bcnt, skb);
	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);
	if (IS_SW_LRO(&priv->channels.params))
		lro_receive_skb(&rq->sw_lro.lro_mgr, skb, NULL);
	else
	napi_gro_receive(rq->cq.napi, skb);

mpwrq_cqe_out:
	if (likely(wi->consumed_strides < rq->mpwqe_num_strides))
		return;

	mlx5e_free_rx_mpwqe(rq, wi);
	mlx5_wq_ll_pop(&rq->wq, cqe->wqe_id, &wqe->next.next_wqe_index);
}

int mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	int work_done = 0;
	struct mlx5e_priv *priv;
	if (MLX5_CAP_GEN(cq->mdev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		priv = mlx5i_epriv(rq->netdev);
	else
		priv = netdev_priv(rq->netdev);

	if (unlikely(!test_bit(MLX5E_RQ_STATE_ENABLED, &rq->state)))
		return 0;

	if (cq->decmprs_left)
		work_done += mlx5e_decompress_cqes_cont(rq, cq, 0, budget);

	for (; work_done < budget; work_done++) {
		struct mlx5_cqe64 *cqe = mlx5_cqwq_get_cqe(&cq->wq);

		if (!cqe)
			break;

		if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED) {
			work_done +=
				mlx5e_decompress_cqes_start(rq, cq,
							    budget - work_done);
			continue;
		}

		mlx5_cqwq_pop(&cq->wq);

		rq->handle_rx_cqe(rq, cqe);
	}


	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	if (IS_SW_LRO(&priv->channels.params))
		lro_flush_all(&rq->sw_lro.lro_mgr);

	return work_done;
}

bool mlx5e_poll_xdpsq_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_xdpsq *sq;
	struct mlx5e_rq *rq;
	u16 sqcc;
	int i;

	sq = container_of(cq, struct mlx5e_xdpsq, cq);

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return false;

	rq = container_of(sq, struct mlx5e_rq, xdpsq);

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	for (i = 0; i < MLX5E_TX_CQ_POLL_BUDGET; i++) {
		struct mlx5_cqe64 *cqe;
		u16 wqe_counter;
		bool last_wqe;

		cqe = mlx5_cqwq_get_cqe(&cq->wq);
		if (!cqe)
			break;

		mlx5_cqwq_pop(&cq->wq);

		wqe_counter = be16_to_cpu(cqe->wqe_counter);

		do {
			struct mlx5e_dma_info *di;
			u16 ci;

			last_wqe = (sqcc == wqe_counter);

			ci = sqcc & sq->wq.sz_m1;
			di = &sq->db.di[ci];

			sqcc++;
			/* Recycle RX page */
			mlx5e_page_release(rq, di, true);
		} while (!last_wqe);
	}

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->cc = sqcc;
	return (i == MLX5E_TX_CQ_POLL_BUDGET);
}

void mlx5e_free_xdpsq_descs(struct mlx5e_xdpsq *sq)
{
	struct mlx5e_rq *rq = container_of(sq, struct mlx5e_rq, xdpsq);
	struct mlx5e_dma_info *di;
	u16 ci;

	while (sq->cc != sq->pc) {
		ci = sq->cc & sq->wq.sz_m1;
		di = &sq->db.di[ci];
		sq->cc++;

		mlx5e_page_release(rq, di, false);
	}
}

#ifdef CONFIG_MLX5_CORE_IPOIB

#define MLX5_IB_GRH_DGID_OFFSET 24
#define MLX5_GID_SIZE           16

static inline void mlx5i_complete_rx_cqe(struct mlx5e_rq *rq,
					 struct mlx5_cqe64 *cqe,
					 u32 cqe_bcnt,
					 struct sk_buff *skb)
{
	struct net_device *netdev;
	struct hwtstamp_config *tstamp;
	struct mlx5e_priv *priv;
	char *pseudo_header;
	u32 qpn;
	u8 *dgid;
	u8 g;
       struct mlx5e_priv *parent_priv = mlx5i_epriv(rq->netdev);

	qpn = be32_to_cpu(cqe->sop_drop_qpn) & 0xffffff;
	netdev = mlx5i_get_qpn_netdev(rq->netdev, qpn);

	/* No mapping is present, cannot process SKB. This might happen due to
	 * child interface going while having unprocessed CQEs on parent RQ
	 */
	if (unlikely(!netdev)) {
		/* TBD: add drop counters and increase them */
		skb->dev = NULL;
		pr_warn_once("Unable to map QPN %u to dev - dropping skb\n", qpn);
		return;
	}

	g = (be32_to_cpu(cqe->flags_rqpn) >> 28) & 3;
	dgid = skb->data + MLX5_IB_GRH_DGID_OFFSET;
	if ((!g) || dgid[0] != 0xff)
		skb->pkt_type = PACKET_HOST;
	else if (memcmp(dgid, netdev->broadcast + 4, MLX5_GID_SIZE) == 0)
		skb->pkt_type = PACKET_BROADCAST;
	else
		skb->pkt_type = PACKET_MULTICAST;

	/* TODO: IB/ipoib: Allow mcast packets from other VFs
	 * 68996a6e760e5c74654723eeb57bf65628ae87f4
	 */

	skb_pull(skb, MLX5_IB_GRH_BYTES);

	skb->protocol = *((__be16 *)(skb->data));

	if (parent_priv->netdev->features & NETIF_F_LRO) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = csum_unfold((__force __sum16)cqe->check_sum);
		rq->stats.csum_complete++;
	}

	priv = mlx5i_epriv(netdev);
	tstamp = &priv->tstamp;

	if (unlikely(mlx5e_rx_hw_stamp(tstamp)))
		skb_hwtstamps(skb)->hwtstamp =
				mlx5_timecounter_cyc2time(rq->clock, get_cqe_ts(cqe));

	skb_record_rx_queue(skb, rq->ix);

	if (likely(netdev->features & NETIF_F_RXHASH))
		mlx5e_skb_set_hash(cqe, skb);

	/* 20 bytes of ipoib header and 4 for encap existing */
	pseudo_header = skb_push(skb, MLX5_IPOIB_PSEUDO_LEN);
	memset(pseudo_header, 0, MLX5_IPOIB_PSEUDO_LEN);
	skb_reset_mac_header(skb);
	skb_pull(skb, MLX5_IPOIB_HARD_LEN);

	skb->dev = netdev;

	rq->stats.packets++;
	rq->stats.bytes += cqe_bcnt;
}

void mlx5i_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct mlx5e_wqe_frag_info *wi;
	struct mlx5e_rx_wqe *wqe;
	__be16 wqe_counter_be;
	struct sk_buff *skb;
	u16 wqe_counter;
	u32 cqe_bcnt;
	struct mlx5e_priv *priv = mlx5i_epriv(rq->netdev);

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	wi             = &rq->wqe.frag_info[wqe_counter];
	cqe_bcnt       = be32_to_cpu(cqe->byte_cnt);

	skb = skb_from_cqe(rq, cqe, wi, cqe_bcnt);
	if (!skb)
		goto wq_free_wqe;

	mlx5i_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);
	if (unlikely(!skb->dev)) {
		dev_kfree_skb_any(skb);
		goto wq_free_wqe;
	}
	if (priv->netdev->features & NETIF_F_LRO)
		lro_receive_skb(&rq->sw_lro.lro_mgr, skb, NULL);
	else
		napi_gro_receive(rq->cq.napi, skb);

wq_free_wqe:
	mlx5e_free_rx_wqe_reuse(rq, wi);
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		       &wqe->next.next_wqe_index);
}

#endif /* CONFIG_MLX5_CORE_IPOIB */

#ifdef CONFIG_MLX5_EN_IPSEC

void mlx5e_ipsec_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct mlx5e_wqe_frag_info *wi;
	struct mlx5e_rx_wqe *wqe;
	__be16 wqe_counter_be;
	struct sk_buff *skb;
	u16 wqe_counter;
	u32 cqe_bcnt;

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	wi             = &rq->wqe.frag_info[wqe_counter];
	cqe_bcnt       = be32_to_cpu(cqe->byte_cnt);

	skb = skb_from_cqe(rq, cqe, wi, cqe_bcnt);
	if (unlikely(!skb)) {
		/* a DROP, save the page-reuse checks */
		mlx5e_free_rx_wqe(rq, wi);
		goto wq_ll_pop;
	}
	skb = mlx5e_ipsec_handle_rx_skb(rq->netdev, skb);
	if (unlikely(!skb)) {
		mlx5e_free_rx_wqe(rq, wi);
		goto wq_ll_pop;
	}

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);
	napi_gro_receive(rq->cq.napi, skb);

	mlx5e_free_rx_wqe_reuse(rq, wi);
wq_ll_pop:
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		       &wqe->next.next_wqe_index);
}

#endif /* CONFIG_MLX5_EN_IPSEC */
