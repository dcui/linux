#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <net/udp.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>

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

static struct task_struct *task[4];

static int
test_recv(void *arg)
{
    unsigned short port;
    struct socket *sock;
    int result, len, peeked, off, frag_index, src_len, copied;
    wait_queue_head_t wait;
    struct sockaddr_in addr;
    struct sk_buff *skb, *fskb;
    unsigned char *src_vbuf;
    skb_frag_t *frag;
    unsigned int ip;

    port = (unsigned long)arg;

    printk(KERN_ERR "DEBUG: test_recv(0x%hx) ENTER\n",port);

    result = sock_create_kern(&init_net,
                              AF_INET,
                              SOCK_DGRAM,
                              IPPROTO_UDP,
                              &sock);
    if (result < 0)
    {
        printk(KERN_ERR "DEBUG: sock_create_kern() failed [%d].",result);
        init_waitqueue_head(&wait);
        wait_event_interruptible(wait,kthread_should_stop());
        return 0;
    }

    len = 16 * 1024 * 1024;
    result = kernel_setsockopt(sock,SOL_SOCKET,SO_RCVBUFFORCE,
                               (char *)&len,sizeof(len));
    if (result < 0)
    {
        printk(KERN_ERR "DEBUG: kernel_setsockopt() failed [%d].",result);
        sock_release(sock);
        init_waitqueue_head(&wait);
        wait_event_interruptible(wait,kthread_should_stop());
        return 0;
    }

    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    result = kernel_bind(sock,(struct sockaddr *)&addr,sizeof(addr));
    if (result < 0)
    {
        printk(KERN_ERR "DEBUG: kernel_bind() failed [%d].",result);
        sock_release(sock);
        init_waitqueue_head(&wait);
        wait_event_interruptible(wait,kthread_should_stop());
        return 0;
    }

    while (!kthread_should_stop())
    {
        cond_resched();

        off = 0;
        skb = __skb_recv_datagram(sock->sk,MSG_DONTWAIT,&peeked,&off,&len);
        if (skb == NULL)
        {
            if (len == -EAGAIN || len == -EWOULDBLOCK)
                continue;
            printk(KERN_ERR "DEBUG: __skb_recv_datagram() failed [%d].",len);
            sock_release(sock);
            init_waitqueue_head(&wait);
            wait_event_interruptible(wait,kthread_should_stop());
            return 0;
        }

        fskb = skb;
        off = sizeof(struct udphdr);
        len = skb->len - off;

        if (len <= 0 || len > 1400)
        {
            printk(KERN_ERR "DEBUG: invalid packet length [%d].",len);
            skb_free_datagram_locked(sock->sk,fskb);
            sock_release(sock);
            init_waitqueue_head(&wait);
            wait_event_interruptible(wait,kthread_should_stop());
            return 0;
        }

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
            ip = ntohl(ip_hdr(fskb)->saddr);

            printk(KERN_ERR "DEBUG: receive data mismatch detected "
                   "[port = %hu, len = 0x%x, from %u.%u.%u.%u:%hu]\n",
                   port,len,
                   (ip >> 24) & 255,(ip >> 16) & 255,
                   (ip >> 8) & 255,(ip >> 0) & 255,
                   ntohs(udp_hdr(fskb)->source));

            skb_dump(KERN_ERR, fskb, true);

            skb = fskb;
            off = sizeof(struct udphdr);
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
                    printk(KERN_ERR "DEBUG:  buf[0x%x] = 0x%02hhx"
                           " [expected 0x%02x]\n",
                           copied,*src_vbuf,(copied & 255));
                }

                src_vbuf++;
                src_len--;
                copied++;
            }
        }

        UDP_INC_STATS_USER(sock_net(sock->sk),UDP_MIB_INDATAGRAMS,0);
        skb_free_datagram_locked(sock->sk,fskb);

        printk(KERN_ERR "\n");
    }

    sock_release(sock);

    printk(KERN_ERR "DEBUG: test_recv(0x%hx) EXIT\n",port);

    return 0;
}

static __init int test_init(void)
{
    task[0] = kthread_run(test_recv,(void *)1003,"test_recv/1003");
    WARN_ON(IS_ERR(task[0]));

    task[1] = kthread_run(test_recv,(void *)1004,"test_recv/1004");
    WARN_ON(IS_ERR(task[1]));

    task[2] = kthread_run(test_recv,(void *)1005,"test_recv/1005");
    WARN_ON(IS_ERR(task[2]));

    task[3] = kthread_run(test_recv,(void *)1007,"test_recv/1007");
    WARN_ON(IS_ERR(task[3]));

    return 0;
}

static void test_exit(void)
{
    int i;

    for (i = 0; i < 4; i++)
        if (!IS_ERR(task[i]))
            kthread_stop(task[i]);
}

module_init(test_init);
module_exit(test_exit);
