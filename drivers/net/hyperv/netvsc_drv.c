/*
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <linux/netpoll.h>

#include <net/arp.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/pkt_sched.h>

#include "hyperv_net.h"

/* Restrict GSO size to account for NVGRE */
#define NETVSC_GSO_MAX_SIZE	62768

#define RING_SIZE_MIN 64
static int ring_size = 128;
module_param(ring_size, int, S_IRUGO);
MODULE_PARM_DESC(ring_size, "Ring buffer size (# of pages)");

static int max_num_vrss_chns = 8;

static const u32 default_msg = NETIF_MSG_DRV | NETIF_MSG_PROBE |
				NETIF_MSG_LINK | NETIF_MSG_IFUP |
				NETIF_MSG_IFDOWN | NETIF_MSG_RX_ERR |
				NETIF_MSG_TX_ERR;

static int debug = -1;
module_param(debug, int, S_IRUGO);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

static void do_set_multicast(struct work_struct *w)
{
	struct net_device_context *ndevctx =
		container_of(w, struct net_device_context, work);
	struct netvsc_device *nvdev;
	struct rndis_device *rdev;

	nvdev = hv_get_drvdata(ndevctx->device_ctx);
	if (nvdev == NULL || nvdev->ndev == NULL)
		return;

	rdev = nvdev->extension;
	if (rdev == NULL)
		return;

	if (nvdev->ndev->flags & IFF_PROMISC)
		rndis_filter_set_packet_filter(rdev,
			NDIS_PACKET_TYPE_PROMISCUOUS);
	else
		rndis_filter_set_packet_filter(rdev,
			NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_ALL_MULTICAST |
			NDIS_PACKET_TYPE_DIRECTED);
}

static void netvsc_set_multicast_list(struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);

	schedule_work(&net_device_ctx->work);
}

static int netvsc_open(struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *device_obj = net_device_ctx->device_ctx;
	struct net_device *vf_netdev;
	struct netvsc_device *nvdev;
	struct rndis_device *rdev;
	int ret = 0;

	netif_carrier_off(net);

	/* Open up the device */
	ret = rndis_filter_open(device_obj);
	if (ret != 0) {
		netdev_err(net, "unable to open device (ret %d).\n", ret);
		return ret;
	}

	netif_tx_wake_all_queues(net);

	nvdev = hv_get_drvdata(device_obj);
	vf_netdev = nvdev->vf_netdev;
	rdev = nvdev->extension;
	if (!rdev->link_state)
		netif_carrier_on(net);

	if (vf_netdev) {
		/* Setting synthetic device up transparently sets
		 * slave as up. If open fails, then slave will be
		 * still be offline (and not used).
		 */
		ret = dev_open(vf_netdev);
		if (ret)
			netdev_warn(net,
				    "unable to open slave: %s: %d\n",
				    vf_netdev->name, ret);
	}
	return 0;
}

static int netvsc_close(struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *device_obj = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(device_obj);
	struct net_device *vf_netdev = nvdev->vf_netdev;
	int ret;
	u32 aread, awrite, i, msec = 10, retry = 0, retry_max = 20;
	struct vmbus_channel *chn;

	netif_tx_disable(net);

	/* Make sure netvsc_set_multicast_list doesn't re-enable filter! */
	cancel_work_sync(&net_device_ctx->work);
	ret = rndis_filter_close(device_obj);
	if (ret != 0) {
		netdev_err(net, "unable to close device (ret %d).\n", ret);
		return ret;
	}

	/* Ensure pending bytes in ring are read */
	while (true) {
		aread = 0;
		for (i = 0; i < nvdev->num_chn; i++) {
			chn = nvdev->chn_table[i];
			if (!chn)
				continue;

			hv_get_ringbuffer_availbytes(&chn->inbound, &aread,
						     &awrite);

			if (aread)
				break;

			hv_get_ringbuffer_availbytes(&chn->outbound, &aread,
						     &awrite);

			if (aread)
				break;
		}

		retry++;
		if (retry > retry_max || aread == 0)
			break;

		msleep(msec);

		if (msec < 1000)
			msec *= 2;
	}

	if (aread) {
		netdev_err(net, "Ring buffer not empty after closing rndis\n");
		ret = -ETIMEDOUT;
	}

	if (vf_netdev)
		dev_close(vf_netdev);

	return ret;
}

static void *init_ppi_data(struct rndis_message *msg, u32 ppi_size,
				int pkt_type)
{
	struct rndis_packet *rndis_pkt;
	struct rndis_per_packet_info *ppi;

	rndis_pkt = &msg->msg.pkt;
	rndis_pkt->data_offset += ppi_size;

	ppi = (struct rndis_per_packet_info *)((void *)rndis_pkt +
		rndis_pkt->per_pkt_info_offset + rndis_pkt->per_pkt_info_len);

	ppi->size = ppi_size;
	ppi->type = pkt_type;
	ppi->ppi_offset = sizeof(struct rndis_per_packet_info);

	rndis_pkt->per_pkt_info_len += ppi_size;

	return ppi;
}

union sub_key {
	u64 k;
	struct {
		u8 pad[3];
		u8 kb;
		u32 ka;
	};
};

static u32 comp_hash(u8 *key, int klen, void *data, int dlen)
{
	union sub_key subk;
	int k_next = 4;
	u8 dt;
	int i, j;
	u32 ret = 0;

	subk.k = 0;
	subk.ka = ntohl(*(u32 *)key);

	for (i = 0; i < dlen; i++) {
		subk.kb = key[k_next];
		k_next = (k_next + 1) % klen;
		dt = ((u8 *)data)[i];
		for (j = 0; j < 8; j++) {
			if (dt & 0x80)
				ret ^= subk.ka;
			dt <<= 1;
			subk.k <<= 1;
		}
	}

	return ret;
}

bool netvsc_set_hash(u32 *hash, struct sk_buff *skb)
{
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__be32 dbuf[9];
	int data_len;

	if (eth_hdr(skb)->h_proto != htons(ETH_P_IP) &&
	    eth_hdr(skb)->h_proto != htons(ETH_P_IPV6))
		return false;

	iphdr = ip_hdr(skb);
	ipv6hdr = ipv6_hdr(skb);

	if (iphdr->version == 4) {
		dbuf[0] = iphdr->saddr;
		dbuf[1] = iphdr->daddr;
		if (iphdr->protocol == IPPROTO_TCP) {
			dbuf[2] = *(__be32 *)&tcp_hdr(skb)->source;
			data_len = 12;
		} else {
			data_len = 8;
		}
	} else if (ipv6hdr->version == 6) {
		memcpy(dbuf, &ipv6hdr->saddr, 32);
		if (ipv6hdr->nexthdr == IPPROTO_TCP) {
			dbuf[8] = *(__be32 *)&tcp_hdr(skb)->source;
			data_len = 36;
		} else {
			data_len = 32;
		}
	} else {
		return false;
	}

	*hash = comp_hash(netvsc_hash_key, HASH_KEYLEN, dbuf, data_len);

	return true;
}

static u16 netvsc_pick_tx(struct net_device *ndev, struct sk_buff *skb)
{
	struct net_device_context *net_device_ctx = netdev_priv(ndev);
	struct hv_device *dev = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(dev);

	u32 hash;
	u16 q_idx = 0;

	if (ndev->real_num_tx_queues <= 1)
		return 0;

	if (netvsc_set_hash(&hash, skb)) {
		q_idx = nvdev->send_table[hash % VRSS_SEND_TAB_SIZE] %
			ndev->real_num_tx_queues;
		skb_set_hash(skb, hash, PKT_HASH_TYPE_L3);
	}

	return q_idx;
}

static u16 netvsc_select_queue(struct net_device *ndev, struct sk_buff *skb,
			void *accel_priv, select_queue_fallback_t fallback)
{
	struct net_device_context *ndc = netdev_priv(ndev);
	struct net_device *vf_netdev;
	struct hv_device *dev;
	struct netvsc_device *nvdev;
	u16 txq;

	rcu_read_lock();
	dev = ndc->device_ctx;
	nvdev = hv_get_drvdata(dev);
	vf_netdev = rcu_dereference(nvdev->vf_netdev);
	if (vf_netdev) {
		txq = skb_rx_queue_recorded(skb) ? skb_get_rx_queue(skb) : 0;
		qdisc_skb_cb(skb)->slave_dev_queue_mapping = skb->queue_mapping;
	} else {
		txq = netvsc_pick_tx(ndev, skb);
	}
	rcu_read_unlock();

	while (unlikely(txq >= ndev->real_num_tx_queues))
		txq -= ndev->real_num_tx_queues;

	return txq;
}

void netvsc_xmit_completion(void *context)
{
	struct hv_netvsc_packet *packet = (struct hv_netvsc_packet *)context;
	struct sk_buff *skb = (struct sk_buff *)
		(unsigned long)packet->send_completion_tid;

	if (skb)
		dev_kfree_skb_any(skb);
}

static u32 fill_pg_buf(struct page *page, u32 offset, u32 len,
			struct hv_page_buffer *pb)
{
	int j = 0;

	/* Deal with compund pages by ignoring unused part
	 * of the page.
	 */
	page += (offset >> PAGE_SHIFT);
	offset &= ~PAGE_MASK;

	while (len > 0) {
		unsigned long bytes;

		bytes = PAGE_SIZE - offset;
		if (bytes > len)
			bytes = len;
		pb[j].pfn = page_to_pfn(page);
		pb[j].offset = offset;
		pb[j].len = bytes;

		offset += bytes;
		len -= bytes;

		if (offset == PAGE_SIZE && len) {
			page++;
			offset = 0;
			j++;
		}
	}

	return j + 1;
}

static u32 init_page_array(void *hdr, u32 len, struct sk_buff *skb,
			   struct hv_netvsc_packet *packet)
{
	struct hv_page_buffer *pb = packet->page_buf;
	u32 slots_used = 0;
	char *data = skb->data;
	int frags = skb_shinfo(skb)->nr_frags;
	int i;

	/* The packet is laid out thus:
	 * 1. hdr: RNDIS header and PPI
	 * 2. skb linear data
	 * 3. skb fragment data
	 */
	if (hdr != NULL)
		slots_used += fill_pg_buf(virt_to_page(hdr),
					offset_in_page(hdr),
					len, &pb[slots_used]);

	packet->rmsg_size = len;
	packet->rmsg_pgcnt = slots_used;

	slots_used += fill_pg_buf(virt_to_page(data),
				offset_in_page(data),
				skb_headlen(skb), &pb[slots_used]);

	for (i = 0; i < frags; i++) {
		skb_frag_t *frag = skb_shinfo(skb)->frags + i;

		slots_used += fill_pg_buf(skb_frag_page(frag),
					frag->page_offset,
					skb_frag_size(frag), &pb[slots_used]);
	}
	return slots_used;
}

static int count_skb_frag_slots(struct sk_buff *skb)
{
	int i, frags = skb_shinfo(skb)->nr_frags;
	int pages = 0;

	for (i = 0; i < frags; i++) {
		skb_frag_t *frag = skb_shinfo(skb)->frags + i;
		unsigned long size = skb_frag_size(frag);
		unsigned long offset = frag->page_offset;

		/* Skip unused frames from start of page */
		offset &= ~PAGE_MASK;
		pages += PFN_UP(offset + size);
	}
	return pages;
}

static int netvsc_get_slots(struct sk_buff *skb)
{
	char *data = skb->data;
	unsigned int offset = offset_in_page(data);
	unsigned int len = skb_headlen(skb);
	int slots;
	int frag_slots;

	slots = DIV_ROUND_UP(offset + len, PAGE_SIZE);
	frag_slots = count_skb_frag_slots(skb);
	return slots + frag_slots;
}

static u32 get_net_transport_info(struct sk_buff *skb, u32 *trans_off)
{
	u32 ret_val = TRANSPORT_INFO_NOT_IP;

	if ((eth_hdr(skb)->h_proto != htons(ETH_P_IP)) &&
		(eth_hdr(skb)->h_proto != htons(ETH_P_IPV6))) {
		goto not_ip;
	}

	*trans_off = skb_transport_offset(skb);

	if ((eth_hdr(skb)->h_proto == htons(ETH_P_IP))) {
		struct iphdr *iphdr = ip_hdr(skb);

		if (iphdr->protocol == IPPROTO_TCP)
			ret_val = TRANSPORT_INFO_IPV4_TCP;
		else if (iphdr->protocol == IPPROTO_UDP)
			ret_val = TRANSPORT_INFO_IPV4_UDP;
	} else {
		if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
			ret_val = TRANSPORT_INFO_IPV6_TCP;
		else if (ipv6_hdr(skb)->nexthdr == IPPROTO_UDP)
			ret_val = TRANSPORT_INFO_IPV6_UDP;
	}

not_ip:
	return ret_val;
}

static int netvsc_vf_xmit(struct net_device *net, struct net_device *vf_netdev,
			  struct sk_buff *skb)
{
	int rc;

	skb->dev = vf_netdev;
	skb->queue_mapping = qdisc_skb_cb(skb)->slave_dev_queue_mapping;

	rc = dev_queue_xmit(skb);
	return rc;
}

static int netvsc_start_xmit(struct sk_buff *skb, struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *dev = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(dev);
	struct hv_netvsc_packet *packet = NULL;
	int ret;
	unsigned int num_data_pgs;
	struct rndis_message *rndis_msg;
	struct rndis_packet *rndis_pkt;
	struct net_device *vf_netdev;
	u32 rndis_msg_size;
	bool isvlan;
	bool linear = false;
	struct rndis_per_packet_info *ppi;
	struct ndis_tcp_ip_checksum_info *csum_info;
	struct ndis_tcp_lso_info *lso_info;
	int  hdr_offset;
	u32 net_trans_info;
	u32 hash;
	u32 skb_length;
	u32 pkt_sz;
	struct hv_page_buffer page_buf[MAX_PAGE_BUFFER_COUNT];
	struct netvsc_stats *tx_stats = this_cpu_ptr(net_device_ctx->tx_stats);

	/* if VF is present and up then redirect packets
	 * already called with rcu_read_lock_bh
	 */
	vf_netdev = rcu_dereference_bh(nvdev->vf_netdev);
	if (vf_netdev && netif_running(vf_netdev) &&
	    !netpoll_tx_running(net))
		return netvsc_vf_xmit(net, vf_netdev, skb);

	/* We will atmost need two pages to describe the rndis
	 * header. We can only transmit MAX_PAGE_BUFFER_COUNT number
	 * of pages in a single packet. If skb is scattered around
	 * more pages we try linearizing it.
	 */

check_size:
	skb_length = skb->len;
	num_data_pgs = netvsc_get_slots(skb) + 2;
	if (num_data_pgs > MAX_PAGE_BUFFER_COUNT && linear) {
		net_alert_ratelimited("packet too big: %u pages (%u bytes)\n",
				      num_data_pgs, skb->len);
		ret = -EFAULT;
		goto drop;
	} else if (num_data_pgs > MAX_PAGE_BUFFER_COUNT) {
		if (skb_linearize(skb)) {
			net_alert_ratelimited("failed to linearize skb\n");
			ret = -ENOMEM;
			goto drop;
		}
		linear = true;
		goto check_size;
	}

	pkt_sz = sizeof(struct hv_netvsc_packet) + RNDIS_AND_PPI_SIZE;

	ret = skb_cow_head(skb, pkt_sz);
	if (ret) {
		netdev_err(net, "unable to alloc hv_netvsc_packet\n");
		ret = -ENOMEM;
		goto drop;
	}
	/* Use the headroom for building up the packet */
	packet = (struct hv_netvsc_packet *)skb->head;

	packet->status = 0;
	packet->xmit_more = skb->xmit_more;

	packet->vlan_tci = skb->vlan_tci;
	packet->page_buf = page_buf;

	packet->q_idx = skb_get_queue_mapping(skb);

	packet->is_data_pkt = true;
	packet->total_data_buflen = skb->len;

	packet->rndis_msg = (struct rndis_message *)((unsigned long)packet +
				sizeof(struct hv_netvsc_packet));

	memset(packet->rndis_msg, 0, RNDIS_AND_PPI_SIZE);

	/* Set the completion routine */
	packet->send_completion = netvsc_xmit_completion;
	packet->send_completion_ctx = packet;
	packet->send_completion_tid = (unsigned long)skb;

	isvlan = packet->vlan_tci & VLAN_TAG_PRESENT;

	/* Add the rndis header */
	rndis_msg = packet->rndis_msg;
	rndis_msg->ndis_msg_type = RNDIS_MSG_PACKET;
	rndis_msg->msg_len = packet->total_data_buflen;
	rndis_pkt = &rndis_msg->msg.pkt;
	rndis_pkt->data_offset = sizeof(struct rndis_packet);
	rndis_pkt->data_len = packet->total_data_buflen;
	rndis_pkt->per_pkt_info_offset = sizeof(struct rndis_packet);

	rndis_msg_size = RNDIS_MESSAGE_SIZE(struct rndis_packet);

	hash = skb_get_hash_raw(skb);
	if (hash != 0 && net->real_num_tx_queues > 1) {
		rndis_msg_size += NDIS_HASH_PPI_SIZE;
		ppi = init_ppi_data(rndis_msg, NDIS_HASH_PPI_SIZE,
				    NBL_HASH_VALUE);
		*(u32 *)((void *)ppi + ppi->ppi_offset) = hash;
	}

	if (isvlan) {
		struct ndis_pkt_8021q_info *vlan;

		rndis_msg_size += NDIS_VLAN_PPI_SIZE;
		ppi = init_ppi_data(rndis_msg, NDIS_VLAN_PPI_SIZE,
					IEEE_8021Q_INFO);
		vlan = (struct ndis_pkt_8021q_info *)((void *)ppi +
						ppi->ppi_offset);
		vlan->vlanid = packet->vlan_tci & VLAN_VID_MASK;
		vlan->pri = (packet->vlan_tci & VLAN_PRIO_MASK) >>
				VLAN_PRIO_SHIFT;
	}

	net_trans_info = get_net_transport_info(skb, &hdr_offset);
	if (net_trans_info == TRANSPORT_INFO_NOT_IP)
		goto do_send;

	/*
	 * Setup the sendside checksum offload only if this is not a
	 * GSO packet.
	 */
	if (skb_is_gso(skb))
		goto do_lso;

	if ((skb->ip_summed == CHECKSUM_NONE) ||
	    (skb->ip_summed == CHECKSUM_UNNECESSARY))
		goto do_send;

	rndis_msg_size += NDIS_CSUM_PPI_SIZE;
	ppi = init_ppi_data(rndis_msg, NDIS_CSUM_PPI_SIZE,
			    TCPIP_CHKSUM_PKTINFO);

	csum_info = (struct ndis_tcp_ip_checksum_info *)((void *)ppi +
			ppi->ppi_offset);

	if (net_trans_info & (INFO_IPV4 << 16))
		csum_info->transmit.is_ipv4 = 1;
	else
		csum_info->transmit.is_ipv6 = 1;

	if (net_trans_info & INFO_TCP) {
		csum_info->transmit.tcp_checksum = 1;
		csum_info->transmit.tcp_header_offset = hdr_offset;
	} else if (net_trans_info & INFO_UDP) {
		/* UDP checksum offload is not supported on ws2008r2.
		 * Furthermore, on ws2012 and ws2012r2, there are some
		 * issues with udp checksum offload from Linux guests.
		 * (these are host issues).
		 * For now compute the checksum here.
		 */
		struct udphdr *uh;
		u16 udp_len;

		ret = skb_cow_head(skb, 0);
		if (ret)
			goto drop;

		uh = udp_hdr(skb);
		udp_len = ntohs(uh->len);
		uh->check = 0;
		uh->check = csum_tcpudp_magic(ip_hdr(skb)->saddr,
					      ip_hdr(skb)->daddr,
					      udp_len, IPPROTO_UDP,
					      csum_partial(uh, udp_len, 0));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;

		csum_info->transmit.udp_checksum = 0;
	}
	goto do_send;

do_lso:
	rndis_msg_size += NDIS_LSO_PPI_SIZE;
	ppi = init_ppi_data(rndis_msg, NDIS_LSO_PPI_SIZE,
			    TCP_LARGESEND_PKTINFO);

	lso_info = (struct ndis_tcp_lso_info *)((void *)ppi +
			ppi->ppi_offset);

	lso_info->lso_v2_transmit.type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
	if (net_trans_info & (INFO_IPV4 << 16)) {
		lso_info->lso_v2_transmit.ip_version =
			NDIS_TCP_LARGE_SEND_OFFLOAD_IPV4;
		ip_hdr(skb)->tot_len = 0;
		ip_hdr(skb)->check = 0;
		tcp_hdr(skb)->check =
		~csum_tcpudp_magic(ip_hdr(skb)->saddr,
				   ip_hdr(skb)->daddr, 0, IPPROTO_TCP, 0);
	} else {
		lso_info->lso_v2_transmit.ip_version =
			NDIS_TCP_LARGE_SEND_OFFLOAD_IPV6;
		ipv6_hdr(skb)->payload_len = 0;
		tcp_hdr(skb)->check =
		~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
				&ipv6_hdr(skb)->daddr, 0, IPPROTO_TCP, 0);
	}
	lso_info->lso_v2_transmit.tcp_header_offset = hdr_offset;
	lso_info->lso_v2_transmit.mss = skb_shinfo(skb)->gso_size;

do_send:
	/* Start filling in the page buffers with the rndis hdr */
	rndis_msg->msg_len += rndis_msg_size;
	packet->total_data_buflen = rndis_msg->msg_len;
	packet->page_buf_cnt = init_page_array(rndis_msg, rndis_msg_size,
					       skb, packet);

	ret = netvsc_send(net_device_ctx->device_ctx, packet);

drop:
	if (ret == 0) {
		u64_stats_update_begin(&tx_stats->syncp);
		tx_stats->packets++;
		tx_stats->bytes += skb_length;
		u64_stats_update_end(&tx_stats->syncp);
	} else {
		if (ret != -EAGAIN) {
			dev_kfree_skb_any(skb);
			net->stats.tx_dropped++;
		}
	}

	return (ret == -EAGAIN) ? NETDEV_TX_BUSY : NETDEV_TX_OK;
}

/*
 * netvsc_linkstatus_callback - Link up/down notification
 */
void netvsc_linkstatus_callback(struct hv_device *device_obj,
				struct rndis_message *resp)
{
	struct rndis_indicate_status *indicate = &resp->msg.indicate_status;
	struct net_device *net;
	struct net_device_context *ndev_ctx;
	struct netvsc_device *net_device;
	struct rndis_device *rdev;

	net_device = hv_get_drvdata(device_obj);
	rdev = net_device->extension;

	switch (indicate->status) {
	case RNDIS_STATUS_MEDIA_CONNECT:
		rdev->link_state = false;
		break;
	case RNDIS_STATUS_MEDIA_DISCONNECT:
		rdev->link_state = true;
		break;
	case RNDIS_STATUS_NETWORK_CHANGE:
		rdev->link_change = true;
		break;
	default:
		return;
	}

	net = net_device->ndev;

	if (!net || net->reg_state != NETREG_REGISTERED)
		return;

	ndev_ctx = netdev_priv(net);
	if (!rdev->link_state) {
		schedule_delayed_work(&ndev_ctx->dwork, 0);
		schedule_delayed_work(&ndev_ctx->dwork, msecs_to_jiffies(20));
	} else {
		schedule_delayed_work(&ndev_ctx->dwork, 0);
	}
}

static struct sk_buff *netvsc_alloc_recv_skb(struct net_device *net,
				struct hv_netvsc_packet *packet,
				struct ndis_tcp_ip_checksum_info *csum_info,
				void *data, u16 vlan_tci)
{
	struct sk_buff *skb;

	skb = netdev_alloc_skb_ip_align(net, packet->total_data_buflen);
	if (!skb)
		return skb;

	/*
	 * Copy to skb. This copy is needed here since the memory pointed by
	 * hv_netvsc_packet cannot be deallocated
	 */
	memcpy(skb_put(skb, packet->total_data_buflen), data,
	       packet->total_data_buflen);

	skb->protocol = eth_type_trans(skb, net);
	if (csum_info) {
		/* We only look at the IP checksum here.
		 * Should we be dropping the packet if checksum
		 * failed? How do we deal with other checksums - TCP/UDP?
		 */
		if (csum_info->receive.ip_checksum_succeeded)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;
	}

	if (vlan_tci & VLAN_TAG_PRESENT)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       vlan_tci);

	return skb;
}


/*
 * netvsc_recv_callback - Callback when we receive a packet from the
 * "wire" on the specified device.
 */
int netvsc_recv_callback(struct hv_device *device_obj,
			 struct hv_netvsc_packet *packet,
			 void **data,
			 struct ndis_tcp_ip_checksum_info *csum_info,
			 struct vmbus_channel *channel,
			 u16 vlan_tci)
{
/*
	struct net_device *net;
	struct net_device_context *net_device_ctx;
	struct sk_buff *skb;
	struct netvsc_stats *rx_stats;
	struct netvsc_device *netvsc_dev = hv_get_drvdata(device_obj);
	u32 bytes_recvd = packet->total_data_buflen;
	int ret = 0;

	net = netvsc_dev->ndev;
	if (!net || net->reg_state != NETREG_REGISTERED)
		return NVSP_STAT_FAIL;

	vf_netdev = rcu_dereference(netvsc_dev->vf_netdev);
	if (vf_netdev) {
		struct sk_buff *vf_skb;
		atomic_inc(&netvsc_dev->vf_use_cnt);
		if (!netvsc_dev->vf_inject) {
			atomic_dec(&netvsc_dev->vf_use_cnt);
			goto vf_injection_done;
		}

		vf_skb = netvsc_alloc_recv_skb(vf_netdev, packet,
					       csum_info, *data, vlan_tci);
		if (vf_skb != NULL) {
			++vf_netdev->stats.rx_packets;
			vf_netdev->stats.rx_bytes += bytes_recvd;
			netif_receive_skb(vf_skb);
		} else {
			++net->stats.rx_dropped;
			ret = NVSP_STAT_FAIL;
		}
		atomic_dec(&netvsc_dev->vf_use_cnt);
		return ret;
	}

vf_injection_done:
	net_device_ctx = netdev_priv(net);
	rx_stats = this_cpu_ptr(net_device_ctx->rx_stats);

	skb = netvsc_alloc_recv_skb(net, packet, csum_info, *data, vlan_tci);
	if (unlikely(!skb)) {
		++net->stats.rx_dropped;
		return NVSP_STAT_FAIL;
	}
	skb_record_rx_queue(skb, channel->
			    offermsg.offer.sub_channel_index);

	u64_stats_update_begin(&rx_stats->syncp);
	rx_stats->packets++;
	rx_stats->bytes += packet->total_data_buflen;
	u64_stats_update_end(&rx_stats->syncp);

	netif_receive_skb(skb);

	return 0;
*/
	struct net_device *net;
	struct netvsc_device *net_device;
	struct sk_buff *skb;
	struct netvsc_stats *rx_stats;

	net_device = hv_get_drvdata(device_obj);
	net = net_device->ndev;

	if (net->reg_state != NETREG_REGISTERED)
		return NVSP_STAT_FAIL;

	if (unlikely(!net_device))
		goto drop;

	/* Allocate a skb - TODO direct I/O to pages? */
	skb = netvsc_alloc_recv_skb(net, packet, csum_info, *data, vlan_tci);

	if (unlikely(!skb)) {
drop:
		++net->stats.rx_dropped;
		return NVSP_STAT_FAIL;
	}

	skb_record_rx_queue(skb, channel->
			    offermsg.offer.sub_channel_index);

	/*
	 * Even if injecting the packet, record the statistics
	 * on the synthetic device because modifying the VF device
	 * statistics will not work correctly.
	 */
	u64_stats_update_begin(&rx_stats->syncp);
	rx_stats->packets++;
	rx_stats->bytes += packet->total_data_buflen;
	u64_stats_update_end(&rx_stats->syncp);

	netif_receive_skb(skb);

	return 0;
}

static void netvsc_get_drvinfo(struct net_device *net,
			       struct ethtool_drvinfo *info)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *dev = net_device_ctx->device_ctx;

	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strlcpy(info->fw_version, "N/A", sizeof(info->fw_version));
	strlcpy(info->bus_info, vmbus_dev_name(dev), sizeof(info->bus_info));
}

static void netvsc_get_channels(struct net_device *net,
				struct ethtool_channels *channel)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *dev = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(dev);

	if (nvdev) {
		channel->max_combined	= nvdev->max_chn;
		channel->combined_count = nvdev->num_chn;
	}
}

static int netvsc_set_channels(struct net_device *net,
			       struct ethtool_channels *channels)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *dev = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(dev);
	struct netvsc_device_info device_info;
	u32 num_chn;
	u32 max_chn;
	int ret = 0;
	bool recovering = false;

	if (!nvdev || nvdev->destroy)
		return -ENODEV;

	num_chn = nvdev->num_chn;
	max_chn = min_t(u32, nvdev->max_chn, num_online_cpus());

	if (nvdev->nvsp_version < NVSP_PROTOCOL_VERSION_5) {
		pr_info("vRSS unsupported before NVSP Version 5\n");
		return -EINVAL;
	}

	/* We do not support rx, tx, or other */
	if (!channels ||
	    channels->rx_count ||
	    channels->tx_count ||
	    channels->other_count ||
	    (channels->combined_count < 1))
		return -EINVAL;

	if (channels->combined_count > max_chn) {
		pr_info("combined channels too high, using %d\n", max_chn);
		channels->combined_count = max_chn;
	}

	ret = netvsc_close(net);
	if (ret)
		goto out;

 do_set:
	nvdev->start_remove = true;
	rndis_filter_device_remove(dev);

	nvdev->num_chn = channels->combined_count;

	net_device_ctx->device_ctx = dev;
	hv_set_drvdata(dev, net);

	memset(&device_info, 0, sizeof(device_info));
	device_info.num_chn = nvdev->num_chn; /* passed to RNDIS */
	device_info.ring_size = ring_size;
	device_info.max_num_vrss_chns = max_num_vrss_chns;

	ret = rndis_filter_device_add(dev, &device_info);
	if (ret) {
		if (recovering) {
			netdev_err(net, "unable to add netvsc device (ret %d)\n", ret);
			return ret;
		}
		goto recover;
	}

	nvdev = hv_get_drvdata(dev);

	ret = netif_set_real_num_tx_queues(net, nvdev->num_chn);
	if (ret) {
		if (recovering) {
			netdev_err(net, "could not set tx queue count (ret %d)\n", ret);
			return ret;
		}
		goto recover;
	}

	ret = netif_set_real_num_rx_queues(net, nvdev->num_chn);
	if (ret) {
		if (recovering) {
			netdev_err(net, "could not set rx queue count (ret %d)\n", ret);
			return ret;
		}
		goto recover;
	}

 out:
	netvsc_open(net);

	return ret;

 recover:
	/* If the above failed, we attempt to recover through the same
	 * process but with the original number of channels.
	 */
	netdev_err(net, "could not set channels, recovering\n");
	recovering = true;
	channels->combined_count = num_chn;
	goto do_set;
}

/*
 * Define ethtool dependencies here.
 */
static inline int ethtool_validate_speed(__u32 speed)
{
        return speed <= INT_MAX || speed == SPEED_UNKNOWN;
}

static inline int ethtool_validate_duplex(__u8 duplex)
{
        switch (duplex) {
        case DUPLEX_HALF:
        case DUPLEX_FULL:
        case DUPLEX_UNKNOWN:
                return 1;
        }

        return 0;
}

static bool netvsc_validate_ethtool_ss_cmd(const struct ethtool_cmd *cmd)
{
	struct ethtool_cmd diff1 = *cmd;
	struct ethtool_cmd diff2 = {};

	ethtool_cmd_speed_set(&diff1, 0);
	diff1.duplex = 0;
	/* advertising and cmd are usually set */
	diff1.advertising = 0;
	diff1.cmd = 0;
	/* We set port to PORT_OTHER */
	diff2.port = PORT_OTHER;

	return !memcmp(&diff1, &diff2, sizeof(diff1));
}

static void netvsc_init_settings(struct net_device *dev)
{
	struct net_device_context *ndc = netdev_priv(dev);

	ndc->speed = SPEED_UNKNOWN;
	ndc->duplex = DUPLEX_FULL;
}

static int netvsc_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct net_device_context *ndc = netdev_priv(dev);

	ethtool_cmd_speed_set(cmd, ndc->speed);
	cmd->duplex = ndc->duplex;
	cmd->port = PORT_OTHER;

	return 0;
}

static int netvsc_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct net_device_context *ndc = netdev_priv(dev);
	u32 speed;

	speed = ethtool_cmd_speed(cmd);
	if (!ethtool_validate_speed(speed) ||
	    !ethtool_validate_duplex(cmd->duplex) ||
	    !netvsc_validate_ethtool_ss_cmd(cmd))
		return -EINVAL;

	ndc->speed = speed;
	ndc->duplex = cmd->duplex;

	return 0;
}

static int netvsc_change_mtu(struct net_device *ndev, int mtu)
{
	struct net_device_context *ndevctx = netdev_priv(ndev);
	struct hv_device *hdev =  ndevctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(hdev);
	struct net_device *vf_netdev = rtnl_dereference(nvdev->vf_netdev);
	struct netvsc_device_info device_info;
	int limit = ETH_DATA_LEN;
	bool was_opened;
	int ret = 0;

	if (nvdev == NULL || nvdev->destroy)
		return -ENODEV;

	if (nvdev->nvsp_version >= NVSP_PROTOCOL_VERSION_2)
		limit = NETVSC_MTU - ETH_HLEN;

	if (mtu < NETVSC_MTU_MIN || mtu > limit)
		return -EINVAL;

	if (vf_netdev) {
		ret = dev_set_mtu(vf_netdev, mtu);
		if (ret)
			return ret;
	}

	netif_device_detach(ndev);
	was_opened = rndis_filter_opened(nvdev);
	if (was_opened)
		rndis_filter_close(hdev);

	rndis_filter_device_remove(hdev);
	ndev->mtu = mtu;

	rndis_filter_device_add(hdev, &device_info);

	if (was_opened)
		rndis_filter_open(hdev);

	netif_device_attach(ndev);

	return ret;
}

static struct rtnl_link_stats64 *netvsc_get_stats64(struct net_device *net,
						    struct rtnl_link_stats64 *t)
{
	struct net_device_context *ndev_ctx = netdev_priv(net);
	int cpu;

	for_each_possible_cpu(cpu) {
		struct netvsc_stats *tx_stats = per_cpu_ptr(ndev_ctx->tx_stats,
							    cpu);
		struct netvsc_stats *rx_stats = per_cpu_ptr(ndev_ctx->rx_stats,
							    cpu);
		u64 tx_packets, tx_bytes, rx_packets, rx_bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&tx_stats->syncp);
			tx_packets = tx_stats->packets;
			tx_bytes = tx_stats->bytes;
		} while (u64_stats_fetch_retry_irq(&tx_stats->syncp, start));

		do {
			start = u64_stats_fetch_begin_irq(&rx_stats->syncp);
			rx_packets = rx_stats->packets;
			rx_bytes = rx_stats->bytes;
		} while (u64_stats_fetch_retry_irq(&rx_stats->syncp, start));

		t->tx_bytes	+= tx_bytes;
		t->tx_packets	+= tx_packets;
		t->rx_bytes	+= rx_bytes;
		t->rx_packets	+= rx_packets;
	}

	t->tx_dropped	= net->stats.tx_dropped;
	t->tx_errors	= net->stats.tx_dropped;

	t->rx_dropped	= net->stats.rx_dropped;
	t->rx_errors	= net->stats.rx_errors;

	return t;
}

static int netvsc_set_mac_addr(struct net_device *ndev, void *p)
{
	struct net_device_context *ndevctx = netdev_priv(ndev);
	struct hv_device *hdev =  ndevctx->device_ctx;
	struct sockaddr *addr = p;
	char save_adr[ETH_ALEN];
	unsigned char save_aatype;
	int err;

	memcpy(save_adr, ndev->dev_addr, ETH_ALEN);
	save_aatype = ndev->addr_assign_type;

	err = eth_mac_addr(ndev, p);
	if (err != 0)
		return err;

	err = rndis_filter_set_device_mac(hdev, addr->sa_data);
	if (err != 0) {
		/* roll back to saved MAC */
		memcpy(ndev->dev_addr, save_adr, ETH_ALEN);
		ndev->addr_assign_type = save_aatype;
	}

	return err;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void netvsc_poll_controller(struct net_device *net)
{
	/* As netvsc_start_xmit() works synchronous we don't have to
	 * trigger anything here.
	 */
}
#endif

static const struct ethtool_ops ethtool_ops = {
	.get_drvinfo	= netvsc_get_drvinfo,
	.get_link	= ethtool_op_get_link,
	.get_channels   = netvsc_get_channels,
	.set_channels   = netvsc_set_channels,
	.get_settings	= netvsc_get_settings,
	.set_settings	= netvsc_set_settings,
};

static const struct net_device_ops device_ops = {
	.ndo_open =			netvsc_open,
	.ndo_stop =			netvsc_close,
	.ndo_start_xmit =		netvsc_start_xmit,
	.ndo_set_rx_mode =		netvsc_set_multicast_list,
	.ndo_change_mtu =		netvsc_change_mtu,
	.ndo_validate_addr =		eth_validate_addr,
	.ndo_set_mac_address =		netvsc_set_mac_addr,
	.ndo_select_queue =		netvsc_select_queue,
	.ndo_get_stats64 =		netvsc_get_stats64,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller =		netvsc_poll_controller,
#endif
};

/*
 * Send GARP packet to network peers after migrations.
 * After Quick Migration, the network is not immediately operational in the
 * current context when receiving RNDIS_STATUS_MEDIA_CONNECT event. So, add
 * another netif_notify_peers() into a delayed work, otherwise GARP packet
 * will not be sent after quick migration, and cause network disconnection.
 * Also, we update the carrier status here.
 */
static void netvsc_link_change(struct work_struct *w)
{
	struct net_device_context *ndev_ctx;
	struct net_device *net;
	struct netvsc_device *net_device;
	struct rndis_device *rdev;
	bool notify, refresh = false;
	char *argv[] = { "/etc/init.d/network", "restart", NULL };
	char *envp[] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

	rtnl_lock();

	ndev_ctx = container_of(w, struct net_device_context, dwork.work);
	net_device = hv_get_drvdata(ndev_ctx->device_ctx);
	rdev = net_device->extension;
	net = net_device->ndev;

	if (rdev->link_state) {
		netif_carrier_off(net);
		notify = false;
	} else {
		netif_carrier_on(net);
		notify = true;
		if (rdev->link_change) {
			rdev->link_change = false;
			refresh = true;
		}
	}

	rtnl_unlock();

	if (refresh)
		call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

	if (notify)
		netdev_notify_peers(net);
}

static void netvsc_free_netdev(struct net_device *netdev)
{
	struct net_device_context *net_device_ctx = netdev_priv(netdev);

	free_percpu(net_device_ctx->tx_stats);
	free_percpu(net_device_ctx->rx_stats);
	free_netdev(netdev);
}

static struct net_device *get_netvsc_bymac(const u8 *mac)
{
	struct net_device *dev;

	ASSERT_RTNL();
	for_each_netdev(&init_net, dev) {
	if (dev->netdev_ops != &device_ops)
			continue;	/* not a netvsc device */

		if (ether_addr_equal(mac, dev->perm_addr))
			return dev;
	}

	return NULL;
}

static struct net_device *get_netvsc_byref(struct net_device *vf_netdev)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for_each_netdev(&init_net, dev) {
		struct net_device_context *net_device_ctx;
		struct hv_device *device_obj;
		struct netvsc_device *nvdev;

		if (dev->netdev_ops != &device_ops)
			continue;	/* not a netvsc device */

		net_device_ctx = netdev_priv(dev);
		device_obj = net_device_ctx->device_ctx;
		nvdev = hv_get_drvdata(device_obj);

		if (nvdev == NULL)
			continue;	/* device is removed */

		if (rtnl_dereference(nvdev->vf_netdev) == vf_netdev)
			return dev;	/* a match */
	}

	return NULL;
}

/* Called when VF is injecting data into network stack.
 * Change the associated network device from VF to netvsc.
 * note: already called with rcu_read_lock
 */
static rx_handler_result_t netvsc_vf_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct net_device *ndev = rcu_dereference(skb->dev->rx_handler_data);

	skb->dev = ndev;

	/* TODO: stats */
	return RX_HANDLER_ANOTHER;
}

static int netvsc_vf_join(struct net_device *vf_netdev,
			  struct net_device *ndev)
{
	struct net_device_context *ndev_ctx = netdev_priv(ndev);
	int ret;

	ret = netdev_rx_handler_register(vf_netdev,
					 netvsc_vf_handle_frame, ndev);
	if (ret != 0) {
		netdev_err(vf_netdev,
			   "can not register netvsc VF receive handler (err = %d)\n",
			   ret);
		goto rx_handler_failed;
	}

	ret = netdev_upper_dev_link(vf_netdev, ndev);
	if (ret != 0) {
		netdev_err(vf_netdev,
			   "can not set master device %s (err = %d)\n",
			   ndev->name, ret);
		goto upper_link_failed;
	}

	/* set slave flag before open to prevent IPv6 addrconf */
	vf_netdev->flags |= IFF_SLAVE;

	schedule_work(&ndev_ctx->vf_takeover);

	call_netdevice_notifiers(NETDEV_JOIN, vf_netdev);

	netdev_info(vf_netdev, "joined to %s\n", ndev->name);

	return 0;

upper_link_failed:
	netdev_rx_handler_unregister(vf_netdev);
rx_handler_failed:
	return ret;
}

/* Setup VF as slave of the synthetic device.
 * Runs in workqueue to avoid recursion in netlink callbacks.
 */
static void netvsc_vf_setup(struct work_struct *w)
{
	struct net_device_context *ndev_ctx
		= container_of(w, struct net_device_context, vf_takeover);
	struct hv_device *device_obj = ndev_ctx->device_ctx;
	struct netvsc_device *nvdev = hv_get_drvdata(device_obj);
	struct net_device *ndev = hv_get_drvdata(device_obj);
	struct net_device *vf_netdev;
	int ret;

	rtnl_lock();
	vf_netdev = rtnl_dereference(nvdev->vf_netdev);
	if (vf_netdev) {
		ret = dev_set_mtu(vf_netdev, nvdev->ndev->mtu);
		if (ret)
			netdev_warn(vf_netdev,
				    "unable to change mtu to %u\n", ndev->mtu);
		if (netif_running(ndev)) {
			ret = dev_open(vf_netdev);
			if (ret)
				netdev_warn(vf_netdev,
					    "unable to open: %d\n", ret);
		}
	}
	rtnl_unlock();
}

static struct netvsc_device *get_netvsc_device(char *mac)
{
	struct net_device *dev;
	struct net_device_context *netvsc_ctx = NULL;
	int rtnl_locked;

	rtnl_locked = rtnl_trylock();

	for_each_netdev(&init_net, dev) {
		if (memcmp(dev->dev_addr, mac, ETH_ALEN) == 0) {
			if (dev->netdev_ops != &device_ops)
				continue;
			netvsc_ctx = netdev_priv(dev);
			break;
		}
	}
	if (rtnl_locked)
		rtnl_unlock();

	if (netvsc_ctx == NULL)
		return NULL;

	return hv_get_drvdata(netvsc_ctx->device_ctx);
}

static int netvsc_register_vf(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct net_device_context *net_device_ctx;
	struct netvsc_device *netvsc_dev;
	const struct ethtool_ops *eth_ops = vf_netdev->ethtool_ops;

	if (eth_ops == NULL || eth_ops == &ethtool_ops)
		return NOTIFY_DONE;

	if (vf_netdev->addr_len != ETH_ALEN)
		return NOTIFY_DONE;

	/*
	 * We will use the MAC address to locate the synthetic interface to
	 * associate with the VF interface. If we don't find a matching
	 * synthetic interface, move on.
	 */
	ndev = get_netvsc_bymac(vf_netdev->perm_addr);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = hv_get_drvdata(net_device_ctx->device_ctx);
	if (!netvsc_dev || rtnl_dereference(netvsc_dev->vf_netdev))
		return NOTIFY_DONE;

	if (netvsc_vf_join(vf_netdev, ndev) != 0)
		return NOTIFY_DONE;

	netdev_info(netvsc_dev->ndev, "VF registering: %s\n", vf_netdev->name);

	dev_hold(vf_netdev);
	rcu_assign_pointer(netvsc_dev->vf_netdev, vf_netdev);

//	call_netdevice_notifiers(NETDEV_UP, vf_netdev);

	return NOTIFY_OK;
}

static void netvsc_inject_enable(struct netvsc_device *net_device_ctx)
{
	net_device_ctx->vf_inject = true;
}

static void netvsc_inject_disable(struct netvsc_device *net_device_ctx)
{
	net_device_ctx->vf_inject = false;

	/* Wait for currently active users to drain out. */
	while (atomic_read(&net_device_ctx->vf_use_cnt) != 0)
		udelay(50);
}

static int netvsc_vf_up(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct netvsc_device *netvsc_dev;
	struct net_device_context *net_device_ctx;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = hv_get_drvdata(net_device_ctx->device_ctx);

	netdev_info(netvsc_dev->ndev, "VF up: %s\n", vf_netdev->name);
	netvsc_inject_enable(netvsc_dev);

	rndis_filter_open(net_device_ctx->device_ctx);

	netvsc_switch_datapath(netvsc_dev, true);
	netdev_info(netvsc_dev->ndev, "Data path switched to VF: %s\n",
		    vf_netdev->name);

	call_netdevice_notifiers(NETDEV_NOTIFY_PEERS, vf_netdev);

	return NOTIFY_OK;
}


static int netvsc_vf_down(struct net_device *vf_netdev, bool rndis_close)
{
	struct net_device *ndev;
	struct netvsc_device *netvsc_dev;
	struct net_device_context *net_device_ctx;
	const struct ethtool_ops *eth_ops = vf_netdev->ethtool_ops;

	if (eth_ops == &ethtool_ops)
		return NOTIFY_DONE;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	netvsc_dev = get_netvsc_device(vf_netdev->dev_addr);

	netdev_info(netvsc_dev->ndev, "VF down: %s\n", vf_netdev->name);
	net_device_ctx = netdev_priv(netvsc_dev->ndev);

	netvsc_inject_disable(netvsc_dev);

	netvsc_switch_datapath(netvsc_dev, false);
	netdev_info(netvsc_dev->ndev, "Data path switched from VF: %s\n",
		    vf_netdev->name);

	if (rndis_close)
		rndis_filter_close(net_device_ctx->device_ctx);

	call_netdevice_notifiers(NETDEV_NOTIFY_PEERS, ndev);

	return NOTIFY_OK;
}


static int netvsc_unregister_vf(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct netvsc_device *netvsc_dev;
	struct net_device_context *net_device_ctx;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = hv_get_drvdata(net_device_ctx->device_ctx);
	cancel_work_sync(&net_device_ctx->vf_takeover);

	netdev_info(netvsc_dev->ndev, "VF unregistering: %s\n",
		    vf_netdev->name);

	netvsc_vf_down(vf_netdev, false);
	netvsc_inject_disable(netvsc_dev);

	netdev_rx_handler_unregister(vf_netdev);
	netdev_upper_dev_unlink(vf_netdev, ndev);
	RCU_INIT_POINTER(netvsc_dev->vf_netdev, NULL);
	dev_put(vf_netdev);

	return NOTIFY_OK;
}

static int netvsc_probe(struct hv_device *dev,
			const struct hv_vmbus_device_id *dev_id)
{
	struct net_device *net = NULL;
	struct net_device_context *net_device_ctx;
	struct netvsc_device_info device_info;
	struct netvsc_device *nvdev;
	int ret;
	u32 max_needed_headroom;

	net = alloc_etherdev_mq(sizeof(struct net_device_context),
				num_online_cpus());
	if (!net)
		return -ENOMEM;

	max_needed_headroom = sizeof(struct hv_netvsc_packet) +
			      RNDIS_AND_PPI_SIZE;

	netif_carrier_off(net);

	net_device_ctx = netdev_priv(net);
	net_device_ctx->device_ctx = dev;
	net_device_ctx->msg_enable = netif_msg_init(debug, default_msg);
	if (netif_msg_probe(net_device_ctx))
		netdev_dbg(net, "netvsc msg_enable: %d\n",
			   net_device_ctx->msg_enable);

	net_device_ctx->tx_stats = netdev_alloc_pcpu_stats(struct netvsc_stats);
	if (!net_device_ctx->tx_stats) {
		free_netdev(net);
		return -ENOMEM;
	}
	net_device_ctx->rx_stats = netdev_alloc_pcpu_stats(struct netvsc_stats);
	if (!net_device_ctx->rx_stats) {
		free_percpu(net_device_ctx->tx_stats);
		free_netdev(net);
		return -ENOMEM;
	}

	hv_set_drvdata(dev, net);
	INIT_DELAYED_WORK(&net_device_ctx->dwork, netvsc_link_change);
	INIT_WORK(&net_device_ctx->work, do_set_multicast);
	INIT_DELAYED_WORK(&net_device_ctx->vf_takeover, netvsc_vf_setup);

	net->netdev_ops = &device_ops;

	net->hw_features = NETIF_F_RXCSUM | NETIF_F_SG | NETIF_F_IP_CSUM |
				NETIF_F_TSO;
	net->features = NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_SG | NETIF_F_RXCSUM |
			NETIF_F_IP_CSUM | NETIF_F_TSO;

	net->ethtool_ops = &ethtool_ops;
	SET_NETDEV_DEV(net, &dev->device);

	/*
	 * Request additional head room in the skb.
	 * We will use this space to build the rndis
	 * heaser and other state we need to maintain.
	 */
	net->needed_headroom = max_needed_headroom;

	/* Notify the netvsc driver of the new device */
	memset(&device_info, 0, sizeof(device_info));
	device_info.ring_size = ring_size;
	device_info.max_num_vrss_chns = max_num_vrss_chns;
	ret = rndis_filter_device_add(dev, &device_info);
	if (ret != 0) {
		netdev_err(net, "unable to add netvsc device (ret %d)\n", ret);
		netvsc_free_netdev(net);
		hv_set_drvdata(dev, NULL);
		return ret;
	}
	memcpy(net->dev_addr, device_info.mac_adr, ETH_ALEN);

	nvdev = hv_get_drvdata(dev);
	netif_set_real_num_tx_queues(net, nvdev->num_chn);
	netif_set_real_num_rx_queues(net, nvdev->num_chn);

	netvsc_init_settings(net);

	netif_set_gso_max_size(net, NETVSC_GSO_MAX_SIZE);

	ret = register_netdev(net);
	if (ret != 0) {
		pr_err("Unable to register netdev.\n");
		rndis_filter_device_remove(dev);
		netvsc_free_netdev(net);
	} else {
		schedule_delayed_work(&net_device_ctx->dwork, 0);
	}

	return ret;
}

static int netvsc_remove(struct hv_device *dev)
{
	struct net_device *net;
	struct net_device_context *ndev_ctx;
	struct netvsc_device *net_device;
	struct net_device *vf_netdev;

	net_device = hv_get_drvdata(dev);
	net = net_device->ndev;

	if (net == NULL) {
		dev_err(&dev->device, "No net device to remove\n");
		return 0;
	}


	ndev_ctx = netdev_priv(net);
	netif_device_detach(net);
	cancel_delayed_work_sync(&ndev_ctx->dwork);

	rtnl_lock();
	vf_netdev = rtnl_dereference(net_device->vf_netdev);
	if (vf_netdev)
		netvsc_unregister_vf(vf_netdev);

	unregister_netdev(net);

	rndis_filter_device_remove(dev);
	rtnl_unlock();

	hv_set_drvdata(dev, NULL);

	netvsc_free_netdev(net);
	return 0;
}

static const struct hv_vmbus_device_id id_table[] = {
	/* Network guid */
	{ HV_NIC_GUID, },
	{ },
};

MODULE_DEVICE_TABLE(vmbus, id_table);

/* The one and only one */
static struct  hv_driver netvsc_drv = {
	.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = netvsc_probe,
	.remove = netvsc_remove,
};

/*
 * On Hyper-V, every VF interface is matched with a corresponding
 * synthetic interface. The synthetic interface is presented first
 * to the guest. When the corresponding VF instance is registered,
 * we will take care of switching the data path.
 */
static int netvsc_netdev_event(struct notifier_block *this,
			       unsigned long event, void *ptr)
{
	struct net_device *event_dev = netdev_notifier_info_to_dev(ptr);

	/* Skip our own events */
	if (event_dev->netdev_ops == &device_ops)
		return NOTIFY_DONE;

	/* Avoid non-Ethernet type devices */
	if (event_dev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	/* Avoid Vlan dev with same MAC registering as VF */
	if (is_vlan_dev(event_dev))
		return NOTIFY_DONE;

	/* Avoid Bonding master dev with same MAC registering as VF */
	if (event_dev->priv_flags & IFF_BONDING &&
	    event_dev->flags & IFF_MASTER)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		return netvsc_register_vf(event_dev);
	case NETDEV_UNREGISTER:
		return netvsc_unregister_vf(event_dev);
	case NETDEV_UP:
		return netvsc_vf_up(event_dev);
	case NETDEV_DOWN:
		return netvsc_vf_down(event_dev, true);
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block netvsc_netdev_notifier = {
	.notifier_call = netvsc_netdev_event,
};

static void __exit netvsc_drv_exit(void)
{
	unregister_netdevice_notifier(&netvsc_netdev_notifier);
	vmbus_driver_unregister(&netvsc_drv);
}

static int __init netvsc_drv_init(void)
{
	int ret;

	if (ring_size < RING_SIZE_MIN) {
		ring_size = RING_SIZE_MIN;
		pr_info("Increased ring_size to %d (min allowed)\n",
			ring_size);
	}

	ret = vmbus_driver_register(&netvsc_drv);
	if (ret)
		return ret;

	register_netdevice_notifier(&netvsc_netdev_notifier);
	return 0;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microsoft Hyper-V network driver");

module_init(netvsc_drv_init);
module_exit(netvsc_drv_exit);
