#undef TRACE_SYSTEM
#define TRACE_SYSTEM netvsc

#if !defined(_NETVSC_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NETVSC_TRACE_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(netvsc_send,
	TP_PROTO(const struct net_device *ndev,
		 const struct hv_netvsc_packet *packet,
		 const struct sk_buff *skb),
	TP_ARGS(ndev, packet, skb),
	TP_STRUCT__entry(
		__string(dev_name, ndev->name)
		__field(const void *, skb)
		__field(u16, queue)
		__field(u16, packets)
		__field(u32, send_index)
		__field(u32, bytes)
	),
	TP_fast_assign(
		__assign_str(dev_name, ndev->name);
		__entry->skb = skb;
		__entry->queue = packet->q_idx;
		__entry->send_index = packet->send_buf_index;
		__entry->packets = packet->total_packets;
		__entry->bytes = packet->total_bytes;
	),
	TP_printk("%s:[%u] id=%p snd=%u packets=%u bytes=%u",
		  __get_str(dev_name), __entry->queue,
		  __entry->skb, __entry->send_index,
		  __entry->packets, __entry->bytes)
);

DEFINE_EVENT(netvsc_send, netvsc_send_complete,
	TP_PROTO(const struct net_device *ndev,
		 const struct hv_netvsc_packet *packet,
		 const struct sk_buff *skb),
	TP_ARGS(ndev, packet, skb)
);

DEFINE_EVENT(netvsc_send, netvsc_send_packet,
	TP_PROTO(const struct net_device *ndev,
		 const struct hv_netvsc_packet *packet,
		 const struct sk_buff *skb),
	TP_ARGS(ndev, packet, skb)
);

TRACE_EVENT(netvsc_receive,
	TP_PROTO(const struct net_device *ndev, u16 qidx, u32 len),
	TP_ARGS(ndev, qidx, len),
	TP_STRUCT__entry(
		__field(u32, len)
		__field(u16, index)
		__string(dev_name, ndev->name)
	),
	TP_fast_assign(
	 	__assign_str(dev_name, ndev->name);
		__entry->index = qidx;
		__entry->len = len;
	),
	TP_printk("%s: receive queue %u len %u",
		  __get_str(dev_name), __entry->index, __entry->len)
);

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE netvsc_trace
#endif /* _NETVSC_TRACE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
