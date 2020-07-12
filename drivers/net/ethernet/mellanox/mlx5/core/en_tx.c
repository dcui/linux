/*
 * Copyright (c) 2015-2016, Mellanox Technologies. All rights reserved.
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

#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include "en.h"

#define MLX5E_SQ_NOPS_ROOM  MLX5_SEND_WQE_MAX_WQEBBS
#define MLX5E_SQ_STOP_ROOM (MLX5_SEND_WQE_MAX_WQEBBS +\
			    MLX5E_SQ_NOPS_ROOM)

void mlx5e_send_nop(struct mlx5e_sq *sq, bool notify_hw)
{
	struct mlx5_wq_cyc                *wq  = &sq->wq;

	u16 pi = sq->pc & wq->sz_m1;
	struct mlx5e_tx_wqe              *wqe  = mlx5_wq_cyc_get_wqe(wq, pi);

	struct mlx5_wqe_ctrl_seg         *cseg = &wqe->ctrl;

	memset(cseg, 0, sizeof(*cseg));

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_NOP);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | 0x01);

	sq->pc++;
	sq->stats.nop++;

	if (notify_hw) {
		cseg->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
		mlx5e_tx_notify_hw(sq, &wqe->ctrl, 0);
	}
}

static inline void mlx5e_tx_dma_unmap(struct device *pdev,
				      struct mlx5e_sq_dma *dma)
{
	switch (dma->type) {
	case MLX5E_DMA_MAP_SINGLE:
		dma_unmap_single(pdev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	case MLX5E_DMA_MAP_PAGE:
		dma_unmap_page(pdev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	default:
		WARN_ONCE(true, "mlx5e_tx_dma_unmap unknown DMA type!\n");
	}
}

static inline void mlx5e_dma_push(struct mlx5e_sq *sq,
				  dma_addr_t addr,
				  u32 size,
				  enum mlx5e_dma_map_type map_type)
{
	u32 i = sq->dma_fifo_pc & sq->dma_fifo_mask;

	sq->db.txq.dma_fifo[i].addr = addr;
	sq->db.txq.dma_fifo[i].size = size;
	sq->db.txq.dma_fifo[i].type = map_type;
	sq->dma_fifo_pc++;
}

static inline struct mlx5e_sq_dma *mlx5e_dma_get(struct mlx5e_sq *sq, u32 i)
{
	return &sq->db.txq.dma_fifo[i & sq->dma_fifo_mask];
}

static void mlx5e_dma_unmap_wqe_err(struct mlx5e_sq *sq, u8 num_dma)
{
	int i;

	for (i = 0; i < num_dma; i++) {
		struct mlx5e_sq_dma *last_pushed_dma =
			mlx5e_dma_get(sq, --sq->dma_fifo_pc);

		mlx5e_tx_dma_unmap(sq->pdev, last_pushed_dma);
	}
}

u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
		       void *accel_priv, select_queue_fallback_t fallback)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int channel_ix = fallback(dev, skb);
	int up = 0;

	if (!netdev_get_num_tc(dev))
		return channel_ix;

	if (skb_vlan_tag_present(skb))
		up = skb->vlan_tci >> VLAN_PRIO_SHIFT;

	/* channel_ix can be larger than num_channels since
	 * dev->num_real_tx_queues = num_channels * num_tc
	 */
	if (channel_ix >= priv->params.num_channels)
		channel_ix = reciprocal_scale(channel_ix,
					      priv->params.num_channels);

	return priv->channeltc_to_txq_map[channel_ix][up];
}

static inline int mlx5e_skb_l2_header_offset(struct sk_buff *skb)
{
#define MLX5E_MIN_INLINE (ETH_HLEN + VLAN_HLEN)

	return max(skb_network_offset(skb), MLX5E_MIN_INLINE);
}

static inline int mlx5e_skb_l3_header_offset(struct sk_buff *skb)
{
	struct flow_keys keys;

	if (skb_transport_header_was_set(skb))
		return skb_transport_offset(skb);
	else if (skb_flow_dissect_flow_keys(skb, &keys, 0))
		return keys.control.thoff;
	else
		return mlx5e_skb_l2_header_offset(skb);
}

static inline u16 mlx5e_calc_min_inline(enum mlx5_inline_modes mode,
					struct sk_buff *skb)
{
	u16 hlen;

	switch (mode) {
	case MLX5_INLINE_MODE_NONE:
		return 0;
	case MLX5_INLINE_MODE_TCP_UDP:
		hlen = eth_get_headlen(skb->data, skb_headlen(skb));
		if (hlen == ETH_HLEN && !skb_vlan_tag_present(skb))
			hlen += VLAN_HLEN;
		break;
	case MLX5_INLINE_MODE_IP:
		/* When transport header is set to zero, it means no transport
		 * header. When transport header is set to 0xff's, it means
		 * transport header wasn't set.
		 */
		if (skb_transport_offset(skb)) {
			hlen = mlx5e_skb_l3_header_offset(skb);
			break;
		}
		/* fall through */
	case MLX5_INLINE_MODE_L2:
	default:
		hlen = mlx5e_skb_l2_header_offset(skb);
	}
	return min_t(u16, hlen, skb_headlen(skb));
}

static inline u16 mlx5e_get_inline_hdr_size(struct mlx5e_sq *sq,
					    struct sk_buff *skb, bool bf)
{
	/* Some NIC TX decisions, e.g loopback, are based on the packet
	 * headers and occur before the data gather.
	 * Therefore these headers must be copied into the WQE
	 */
	if (bf) {
		u16 ihs = skb_headlen(skb);

		if (skb_vlan_tag_present(skb))
			ihs += VLAN_HLEN;

		if (ihs <= sq->max_inline)
			return skb_headlen(skb);
	}
	return mlx5e_calc_min_inline(sq->min_inline_mode, skb);
}

static inline void mlx5e_tx_skb_pull_inline(unsigned char **skb_data,
					    unsigned int *skb_len,
					    unsigned int len)
{
	*skb_len -= len;
	*skb_data += len;
}

static inline void mlx5e_insert_vlan(void *start, struct sk_buff *skb, u16 ihs,
				     unsigned char **skb_data,
				     unsigned int *skb_len)
{
	struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)start;
	int cpy1_sz = 2 * ETH_ALEN;
	int cpy2_sz = ihs - cpy1_sz;

	memcpy(vhdr, *skb_data, cpy1_sz);
	mlx5e_tx_skb_pull_inline(skb_data, skb_len, cpy1_sz);
	vhdr->h_vlan_proto = skb->vlan_proto;
	vhdr->h_vlan_TCI = cpu_to_be16(skb_vlan_tag_get(skb));
	memcpy(&vhdr->h_vlan_encapsulated_proto, *skb_data, cpy2_sz);
	mlx5e_tx_skb_pull_inline(skb_data, skb_len, cpy2_sz);
}

static inline u32 skb_mac_header_len(const struct sk_buff *skb)
{
        return skb->network_header - skb->mac_header;
}

/**
 * skb_frag_must_loop - Test if %p is a high memory page
 * @p: fragment's page
 */
static inline bool skb_frag_must_loop(struct page *p)
{
#if defined(CONFIG_HIGHMEM)
        if (PageHighMem(p))
                return true;
#endif
        return false;
}

static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
        return frag->page_offset;
}

/**
 *      skb_frag_foreach_page - loop over pages in a fragment
 *
 *      @f:             skb frag to operate on
 *      @f_off:         offset from start of f->bv_page
 *      @f_len:         length from f_off to loop over
 *      @p:             (temp var) current page
 *      @p_off:         (temp var) offset from start of current page,
 *                                 non-zero only on first page.
 *      @p_len:         (temp var) length in current page,
 *                                 < PAGE_SIZE only on first and last page.
 *      @copied:        (temp var) length so far, excluding current p_len.
 *
 *      A fragment can hold a compound page, in which case per-page
 *      operations, notably kmap_atomic, must be called for each
 *      regular page.
 */
#define skb_frag_foreach_page(f, f_off, f_len, p, p_off, p_len, copied) \
        for (p = skb_frag_page(f) + ((f_off) >> PAGE_SHIFT),            \
             p_off = (f_off) & (PAGE_SIZE - 1),                         \
             p_len = skb_frag_must_loop(p) ?                            \
             min_t(u32, f_len, PAGE_SIZE - p_off) : f_len,              \
             copied = 0;                                                \
             copied < f_len;                                            \
             copied += p_len, p++, p_off = 0,                           \
             p_len = min_t(u32, f_len - copied, PAGE_SIZE))             \

static void skb_dump(const char *level, const struct sk_buff *skb, bool full_pkt)
{
        static atomic_t can_dump_full = ATOMIC_INIT(5);
        struct skb_shared_info *sh = skb_shinfo(skb);
        struct net_device *dev = skb->dev;
        struct sock *sk = skb->sk;
        struct sk_buff *list_skb;
        bool has_mac, has_trans;
        int headroom, tailroom;
        int i, len, seg_len;

        if (full_pkt)
                full_pkt = atomic_dec_if_positive(&can_dump_full) >= 0;

        if (full_pkt)
                len = skb->len;
        else
                len = min_t(int, skb->len, MAX_HEADER + 128);

        headroom = skb_headroom(skb);
        tailroom = skb_tailroom(skb);

        has_mac = skb_mac_header_was_set(skb);
        has_trans = skb_transport_header_was_set(skb);

        printk("%sskb len=%u headroom=%u headlen=%u tailroom=%u\n"
               "mac=(%d,%d) net=(%d,%d) trans=%d\n"
               "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
               "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
               "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
               level, skb->len, headroom, skb_headlen(skb), tailroom,
               has_mac ? skb->mac_header : -1,
               has_mac ? skb_mac_header_len(skb) : -1,
               skb->network_header,
               has_trans ? skb_network_header_len(skb) : -1,
               has_trans ? skb->transport_header : -1,
               sh->tx_flags, sh->nr_frags,
               sh->gso_size, sh->gso_type, sh->gso_segs,
               skb->csum, skb->ip_summed, skb->csum_complete_sw,
               skb->csum_valid, skb->csum_level,
               skb->hash, skb->sw_hash, skb->l4_hash,
               ntohs(skb->protocol), skb->pkt_type, skb->skb_iif);

        if (dev)
                printk("%sdev name=%s feat=0x%pNF\n",
                       level, dev->name, &dev->features);
        if (sk)
                printk("%ssk family=%hu type=%u proto=%u\n",
                       level, sk->sk_family, sk->sk_type, sk->sk_protocol);

        if (full_pkt && headroom)
                print_hex_dump(level, "skb headroom: ", DUMP_PREFIX_OFFSET,
                               16, 1, skb->head, headroom, false);

        seg_len = min_t(int, skb_headlen(skb), len);
        if (seg_len)
                print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
                               16, 1, skb->data, seg_len, false);
        len -= seg_len;

        if (full_pkt && tailroom)
                print_hex_dump(level, "skb tailroom: ", DUMP_PREFIX_OFFSET,
                               16, 1, skb_tail_pointer(skb), tailroom, false);

        for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
                skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
                u32 p_off, p_len, copied;
                struct page *p;
                u8 *vaddr;

                skb_frag_foreach_page(frag, skb_frag_off(frag),
                                      skb_frag_size(frag), p, p_off, p_len,
                                      copied) {
                        seg_len = min_t(int, p_len, len);
                        vaddr = kmap_atomic(p);
                        print_hex_dump(level, "skb frag:     ",
                                       DUMP_PREFIX_OFFSET,
                                       16, 1, vaddr + p_off, seg_len, false);
                        kunmap_atomic(vaddr);
                        len -= seg_len;
                        if (!len)
                                break;
                }
        }

        if (full_pkt && skb_has_frag_list(skb)) {
                printk("skb fraglist:\n");
                skb_walk_frags(skb, list_skb)
                        skb_dump(level, list_skb, true);
        }
}

/* skb->data points to an ethernet frame */
static void test_send_mac(struct sk_buff *skb)
{
    int len, off, frag_index, src_len, copied;
    struct sk_buff *fskb = skb;
    unsigned char *src_vbuf;
    skb_frag_t *frag;
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned short dport;

    if (skb->protocol != htons(ETH_P_IP))
	return;

    BUILD_BUG_ON(sizeof(struct ethhdr) != ETH_HLEN);

    iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    if (iph->protocol != IPPROTO_UDP)
	return;

    if (WARN_ON_ONCE(iph->ihl != 5))
	return;

    off = sizeof(struct udphdr) + sizeof(struct iphdr) + ETH_HLEN;
    len = skb->len - off;

    if (len <= 0 || len > 1400)
        return;

    if (WARN_ON_ONCE(skb_headlen(skb) < off))
	return;

    udph = (struct udphdr *)(iph + 1);
    dport = ntohs(udph->dest);
    if (dport < 1000 || dport > 1010)
        return;

    frag_index = 0;
    src_vbuf = skb->data;
    src_len = skb->len - skb->data_len;
    copied = 0;
    while (likely(copied < len))
    {
        while (unlikely(src_len == 0))
        {
            if (frag_index < skb_shinfo(skb)->nr_frags)
            {
                frag = &skb_shinfo(skb)->frags[frag_index++];
                src_vbuf = skb_frag_address(frag);
                src_len = frag->size;
            }
            else
            {
                if (skb_shinfo(skb)->frag_list != NULL)
                    skb = skb_shinfo(skb)->frag_list;
                else
                    skb = skb->next;
                frag_index = 0;
                src_vbuf = skb->data;
                src_len = skb->len - skb->data_len;
            }
        }

        if (unlikely(off != 0))
        {
            if (off < src_len)
            {
                src_vbuf += off;
                src_len -= off;
                off = 0;
            }
            else
            {
                off -= src_len;
                src_len = 0;
            }
            continue;
        }

        if (unlikely(*src_vbuf != (copied & 255)))
            break;

        src_vbuf++;
        src_len--;
        copied++;
    }

    if (copied < len)
    {
        printk(KERN_ERR "cdx: mlx tx nic: DEBUG: send data mismatch detected "
               "%pI4:%hu -> %pI4:%hu, len = 0x%x\n",
               &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest),len);

        skb_dump(KERN_ERR, fskb, true);

        skb = fskb;
	off = sizeof(struct udphdr) + sizeof(struct iphdr) + ETH_HLEN;
        frag_index = 0;
        src_vbuf = skb->data;
        src_len = skb->len - skb->data_len;
        copied = 0;
        while (copied < len)
        {
            while (src_len == 0)
            {
                if (frag_index < skb_shinfo(skb)->nr_frags)
                {
                    frag = &skb_shinfo(skb)->frags[frag_index++];
                    src_vbuf = skb_frag_address(frag);
                    src_len = frag->size;
                }
                else
                {
                    if (skb_shinfo(skb)->frag_list != NULL)
                        skb = skb_shinfo(skb)->frag_list;
                    else
                        skb = skb->next;
                    frag_index = 0;
                    src_vbuf = skb->data;
                    src_len = skb->len - skb->data_len;
                }
            }

            if (off != 0)
            {
                if (off < src_len)
                {
                    src_vbuf += off;
                    src_len -= off;
                    off = 0;
                }
                else
                {
                    off -= src_len;
                    src_len = 0;
                }
                continue;
            }

            if (*src_vbuf != (copied & 255))
            {
                printk(KERN_ERR "cdx: mlx tx nic: DEBUG: send:  buf[0x%x] = 0x%02hhx"
                       " [expected 0x%02x]\n",
                       copied,*src_vbuf,(copied & 255));
            }

            src_vbuf++;
            src_len--;
            copied++;
        }

        printk(KERN_ERR "\n");
    }
}

static netdev_tx_t mlx5e_sq_xmit(struct mlx5e_sq *sq, struct sk_buff *skb)
{
	struct mlx5_wq_cyc       *wq   = &sq->wq;

	u16 pi = sq->pc & wq->sz_m1;
	struct mlx5e_tx_wqe      *wqe  = mlx5_wq_cyc_get_wqe(wq, pi);
	struct mlx5e_tx_wqe_info *wi   = &sq->db.txq.wqe_info[pi];

	struct mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl;
	struct mlx5_wqe_eth_seg  *eseg = &wqe->eth;
	struct mlx5_wqe_data_seg *dseg;

	unsigned char *skb_data = skb->data;
	unsigned int skb_len = skb->len;
	u8  opcode = MLX5_OPCODE_SEND;
	dma_addr_t dma_addr = 0;
	unsigned int num_bytes;
	bool bf = false;
	u16 headlen;
	u16 ds_cnt;
	u16 ihs;
	int i;

	memset(wqe, 0, sizeof(*wqe));

	if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		WARN_ON_ONCE(1); //cdx
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM;
		if (skb->encapsulation) {
			eseg->cs_flags |= MLX5_ETH_WQE_L3_INNER_CSUM |
					  MLX5_ETH_WQE_L4_INNER_CSUM;
			sq->stats.csum_partial_inner++;
		} else {
			eseg->cs_flags |= MLX5_ETH_WQE_L4_CSUM;
			sq->stats.csum_partial++;
		}
	} else
		sq->stats.csum_none++;

	if (sq->cc != sq->prev_cc) {
		sq->prev_cc = sq->cc;
		sq->bf_budget = (sq->cc == sq->pc) ? MLX5E_SQ_BF_BUDGET : 0;
	}

	if (skb_is_gso(skb)) {
		WARN_ON_ONCE(1); //cdx
		eseg->mss    = cpu_to_be16(skb_shinfo(skb)->gso_size);
		opcode       = MLX5_OPCODE_LSO;

		if (skb->encapsulation) {
			ihs = skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
			sq->stats.tso_inner_packets++;
			sq->stats.tso_inner_bytes += skb->len - ihs;
		} else {
			ihs = skb_transport_offset(skb) + tcp_hdrlen(skb);
			sq->stats.tso_packets++;
			sq->stats.tso_bytes += skb->len - ihs;
		}

		sq->stats.packets += skb_shinfo(skb)->gso_segs;
		num_bytes = skb->len + (skb_shinfo(skb)->gso_segs - 1) * ihs;
	} else {
		bf = sq->bf_budget &&
		     !skb->xmit_more &&
		     !skb_shinfo(skb)->nr_frags;
		ihs = mlx5e_get_inline_hdr_size(sq, skb, bf);
		sq->stats.packets++;
		num_bytes = max_t(unsigned int, skb->len, ETH_ZLEN);
	}

	sq->stats.bytes += num_bytes;
	wi->num_bytes = num_bytes;

	ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;
	if (ihs) {
		if (skb_vlan_tag_present(skb)) {
			mlx5e_insert_vlan(eseg->inline_hdr.start, skb, ihs, &skb_data, &skb_len);
			ihs += VLAN_HLEN;
		} else {
			memcpy(eseg->inline_hdr.start, skb_data, ihs);
			mlx5e_tx_skb_pull_inline(&skb_data, &skb_len, ihs);
		}
		eseg->inline_hdr.sz = cpu_to_be16(ihs);
		ds_cnt += DIV_ROUND_UP(ihs - sizeof(eseg->inline_hdr.start), MLX5_SEND_WQE_DS);
	} else if (skb_vlan_tag_present(skb)) {
		eseg->insert.type = cpu_to_be16(MLX5_ETH_WQE_INSERT_VLAN);
		eseg->insert.vlan_tci = cpu_to_be16(skb_vlan_tag_get(skb));
	}

	dseg = (struct mlx5_wqe_data_seg *)cseg + ds_cnt;

	wi->num_dma = 0;

	headlen = skb_len - skb->data_len;
	if (headlen) {
		dma_addr = dma_map_single(sq->pdev, skb_data, headlen,
					  DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(headlen);

		mlx5e_dma_push(sq, dma_addr, headlen, MLX5E_DMA_MAP_SINGLE);
		wi->num_dma++;

		dseg++;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[i];
		int fsz = skb_frag_size(frag);

		dma_addr = skb_frag_dma_map(sq->pdev, frag, 0, fsz,
					    DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(fsz);

		mlx5e_dma_push(sq, dma_addr, fsz, MLX5E_DMA_MAP_PAGE);
		wi->num_dma++;

		dseg++;
	}

	test_send_mac(skb); //cdx

	ds_cnt += wi->num_dma;

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | opcode);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | ds_cnt);

	sq->db.txq.skb[pi] = skb;

	wi->num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS);
	sq->pc += wi->num_wqebbs;

	netdev_tx_sent_queue(sq->txq, wi->num_bytes);

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	if (unlikely(!mlx5e_sq_has_room_for(sq, MLX5E_SQ_STOP_ROOM))) {
		netif_tx_stop_queue(sq->txq);
		sq->stats.stopped++;
	}

	sq->stats.xmit_more += skb->xmit_more;
	if (!skb->xmit_more || netif_xmit_stopped(sq->txq)) {
		int bf_sz = 0;

		if (bf && test_bit(MLX5E_SQ_STATE_BF_ENABLE, &sq->state))
			bf_sz = wi->num_wqebbs << 3;

		cseg->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
		mlx5e_tx_notify_hw(sq, &wqe->ctrl, bf_sz);
	}

	/* fill sq edge with nops to avoid wqe wrap around */
	while ((pi = (sq->pc & wq->sz_m1)) > sq->edge) {
		sq->db.txq.skb[pi] = NULL;
		mlx5e_send_nop(sq, false);
	}

	if (bf)
		sq->bf_budget--;

	return NETDEV_TX_OK;

dma_unmap_wqe_err:
	sq->stats.dropped++;
	mlx5e_dma_unmap_wqe_err(sq, wi->num_dma);

	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_sq *sq = priv->txq_to_sq_map[skb_get_queue_mapping(skb)];

	return mlx5e_sq_xmit(sq, skb);
}

bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_sq *sq;
	u32 dma_fifo_cc;
	u32 nbytes;
	u16 npkts;
	u16 sqcc;
	int i;

	sq = container_of(cq, struct mlx5e_sq, cq);

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return false;

	npkts = 0;
	nbytes = 0;

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	/* avoid dirtying sq cache line every cqe */
	dma_fifo_cc = sq->dma_fifo_cc;

	for (i = 0; i < MLX5E_TX_CQ_POLL_BUDGET; i++) {
		struct mlx5_cqe64 *cqe;
		u16 wqe_counter;
		bool last_wqe;

		cqe = mlx5e_get_cqe(cq);
		if (!cqe)
			break;

		mlx5_cqwq_pop(&cq->wq);

		wqe_counter = be16_to_cpu(cqe->wqe_counter);

		do {
			struct mlx5e_tx_wqe_info *wi;
			struct sk_buff *skb;
			u16 ci;
			int j;

			last_wqe = (sqcc == wqe_counter);

			ci = sqcc & sq->wq.sz_m1;
			skb = sq->db.txq.skb[ci];
			wi = &sq->db.txq.wqe_info[ci];

			if (unlikely(!skb)) { /* nop */
				sqcc++;
				continue;
			}

			if (unlikely(skb_shinfo(skb)->tx_flags &
				     SKBTX_HW_TSTAMP)) {
				struct skb_shared_hwtstamps hwts = {};

				mlx5e_fill_hwstamp(sq->tstamp,
						   get_cqe_ts(cqe), &hwts);
				skb_tstamp_tx(skb, &hwts);
			}

			for (j = 0; j < wi->num_dma; j++) {
				struct mlx5e_sq_dma *dma =
					mlx5e_dma_get(sq, dma_fifo_cc++);

				mlx5e_tx_dma_unmap(sq->pdev, dma);
			}

			npkts++;
			nbytes += wi->num_bytes;
			sqcc += wi->num_wqebbs;
			dev_kfree_skb(skb);
		} while (!last_wqe);
	}

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;

	netdev_tx_completed_queue(sq->txq, npkts, nbytes);

	if (netif_tx_queue_stopped(sq->txq) &&
	    mlx5e_sq_has_room_for(sq, MLX5E_SQ_STOP_ROOM)) {
		netif_tx_wake_queue(sq->txq);
		sq->stats.wake++;
	}

	return (i == MLX5E_TX_CQ_POLL_BUDGET);
}

void mlx5e_free_tx_descs(struct mlx5e_sq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	struct sk_buff *skb;
	u16 ci;
	int i;

	if (sq->type != MLX5E_SQ_TXQ)
		return;

	while (sq->cc != sq->pc) {
		ci = sq->cc & sq->wq.sz_m1;
		skb = sq->db.txq.skb[ci];
		wi = &sq->db.txq.wqe_info[ci];

		if (!skb) { /* nop */
			sq->cc++;
			continue;
		}

		for (i = 0; i < wi->num_dma; i++) {
			struct mlx5e_sq_dma *dma =
				mlx5e_dma_get(sq, sq->dma_fifo_cc++);

			mlx5e_tx_dma_unmap(sq->pdev, dma);
		}

		dev_kfree_skb_any(skb);
		sq->cc += wi->num_wqebbs;
	}
}
