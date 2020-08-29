# xdp_buffer 结构

[TOC]

## 结构定义

```c
/* linux-4.18-rc8 */
struct xdp_buff {
        void *data;
        void *data_end;
        void *data_meta;
        void *data_hard_start;
        unsigned long handle;
        struct xdp_rxq_info *rxq;
};

struct xdp_frame {
        void *data;
        u16 len;
        u16 headroom;
        u16 metasize;
        /* Lifetime of xdp_rxq_info is limited to NAPI/enqueue time,
         * while mem info is valid on remote CPU.
         */
        struct xdp_mem_info mem;
        struct net_device *dev_rx; /* used by cpumap */
};

/* Convert xdp_buff to xdp_frame */
static inline
struct xdp_frame *convert_to_xdp_frame(struct xdp_buff *xdp)
{
        struct xdp_frame *xdp_frame;
        int metasize;
        int headroom;

        /* TODO: implement clone, copy, use "native" MEM_TYPE */
        if (xdp->rxq->mem.type == MEM_TYPE_ZERO_COPY)
                return NULL;

        /* Assure headroom is available for storing info */
        headroom = xdp->data - xdp->data_hard_start;
        metasize = xdp->data - xdp->data_meta;
        metasize = metasize > 0 ? metasize : 0;
        if (unlikely((headroom - metasize) < sizeof(*xdp_frame)))
                return NULL;

        /* Store info in top of packet */
        xdp_frame = xdp->data_hard_start;

        xdp_frame->data = xdp->data;
        xdp_frame->len  = xdp->data_end - xdp->data;
        xdp_frame->headroom = headroom - sizeof(*xdp_frame);
        xdp_frame->metasize = metasize;

        /* rxq only valid until napi_schedule ends, convert to xdp_mem_info */
        xdp_frame->mem = xdp->rxq->mem;

        return xdp_frame;
}
```

`data_hard_start` <= `data_meta` <= `data` < `data_end`

## 网卡驱动对应代码

```c
$ vi drivers/net/ethernet/intel/i40e/i40e_txrx.c
/**
 * i40e_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 **/
static int i40e_clean_rx_irq(struct i40e_ring *rx_ring, int budget)
{
        unsigned int total_rx_bytes = 0, total_rx_packets = 0;
        struct sk_buff *skb = rx_ring->skb;
        u16 cleaned_count = I40E_DESC_UNUSED(rx_ring);
        unsigned int xdp_xmit = 0;
        bool failure = false;
        struct xdp_buff xdp;

        xdp.rxq = &rx_ring->xdp_rxq;

        while (likely(total_rx_packets < (unsigned int)budget)) {
                struct i40e_rx_buffer *rx_buffer;
                union i40e_rx_desc *rx_desc;
                unsigned int size;
                u16 vlan_tag;
                u8 rx_ptype;
                u64 qword;

                /* return some buffers to hardware, one at a time is too slow */
                if (cleaned_count >= I40E_RX_BUFFER_WRITE) {
                        failure = failure ||
                                  i40e_alloc_rx_buffers(rx_ring, cleaned_count);
                        cleaned_count = 0;
                }

                rx_desc = I40E_RX_DESC(rx_ring, rx_ring->next_to_clean);

                /* status_error_len will always be zero for unused descriptors
                 * because it's cleared in cleanup, and overlaps with hdr_addr
                 * which is always zero because packet split isn't used, if the
                 * hardware wrote DD then the length will be non-zero
                 */
                qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);

                /* This memory barrier is needed to keep us from reading
                 * any other fields out of the rx_desc until we have
                 * verified the descriptor has been written back.
                 */
                dma_rmb();

                if (unlikely(i40e_rx_is_programming_status(qword))) {
                        i40e_clean_programming_status(rx_ring, rx_desc, qword);
                        cleaned_count++;
                        continue;
                }
                size = (qword & I40E_RXD_QW1_LENGTH_PBUF_MASK) >>
                       I40E_RXD_QW1_LENGTH_PBUF_SHIFT;
                if (!size)
                        break;

                i40e_trace(clean_rx_irq, rx_ring, rx_desc, skb);
                rx_buffer = i40e_get_rx_buffer(rx_ring, size);

                /* retrieve a buffer from the ring */
                if (!skb) {
                        // 构造 xdp 结构并调用 xdp 函数 ！！！
                        xdp.data = page_address(rx_buffer->page) +
                                   rx_buffer->page_offset;
                        xdp.data_meta = xdp.data;
                        xdp.data_hard_start = xdp.data -
                                              i40e_rx_offset(rx_ring);
                        xdp.data_end = xdp.data + size;
												// i40e_run_xdp 会返回 skb 结构
                        skb = i40e_run_xdp(rx_ring, &xdp);
                }

                if (IS_ERR(skb)) { // 调用 xdp 失败的结果
                        unsigned int xdp_res = -PTR_ERR(skb);

                        if (xdp_res & (I40E_XDP_TX | I40E_XDP_REDIR)) {
                                xdp_xmit |= xdp_res;
                                i40e_rx_buffer_flip(rx_ring, rx_buffer, size);
                        } else {
                                rx_buffer->pagecnt_bias++;
                        }
                        total_rx_bytes += size;
                        total_rx_packets++;
                } else if (skb) {
                        i40e_add_rx_frag(rx_ring, rx_buffer, skb, size);
                } else if (ring_uses_build_skb(rx_ring)) {
                        skb = i40e_build_skb(rx_ring, rx_buffer, &xdp); // 构造 skb 结构
                } else {
                        skb = i40e_construct_skb(rx_ring, rx_buffer, &xdp); // 构造 skb 结构
                }

                /* exit if we failed to retrieve a buffer */
                if (!skb) {
                        rx_ring->rx_stats.alloc_buff_failed++;
                        rx_buffer->pagecnt_bias++;
                        break;
                }

                i40e_put_rx_buffer(rx_ring, rx_buffer);
                cleaned_count++;

                if (i40e_is_non_eop(rx_ring, rx_desc, skb))
                        continue;

                if (i40e_cleanup_headers(rx_ring, skb, rx_desc)) {
                        skb = NULL;
                        continue;
                }

                /* probably a little skewed due to removing CRC */
                total_rx_bytes += skb->len;

                qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);
                rx_ptype = (qword & I40E_RXD_QW1_PTYPE_MASK) >>
                           I40E_RXD_QW1_PTYPE_SHIFT;

                /* populate checksum, VLAN, and protocol */
                i40e_process_skb_fields(rx_ring, rx_desc, skb, rx_ptype);

                vlan_tag = (qword & BIT(I40E_RX_DESC_STATUS_L2TAG1P_SHIFT)) ?
                           le16_to_cpu(rx_desc->wb.qword0.lo_dword.l2tag1) : 0;

                i40e_trace(clean_rx_irq_rx, rx_ring, rx_desc, skb);
                i40e_receive_skb(rx_ring, skb, vlan_tag);
                skb = NULL;

                /* update budget accounting */
                total_rx_packets++;
        }
  
          if (xdp_xmit & I40E_XDP_REDIR)
                xdp_do_flush_map();

        if (xdp_xmit & I40E_XDP_TX) {
                struct i40e_ring *xdp_ring =
                        rx_ring->vsi->xdp_rings[rx_ring->queue_index];

                i40e_xdp_ring_update_tail(xdp_ring);
        }

        rx_ring->skb = skb;

        u64_stats_update_begin(&rx_ring->syncp);
        rx_ring->stats.packets += total_rx_packets;
        rx_ring->stats.bytes += total_rx_bytes;
        u64_stats_update_end(&rx_ring->syncp);
        rx_ring->q_vector->rx.total_packets += total_rx_packets;
        rx_ring->q_vector->rx.total_bytes += total_rx_bytes;

        /* guarantee a trip back through this routine if there was a failure */
        return failure ? budget : (int)total_rx_packets;
}
```

ring_uses_build_skb 函数定义

drivers/net/ethernet/intel/i40e/i40e_txrx.c

```c
419 static inline bool ring_uses_build_skb(struct i40e_ring *ring)
420 {
421         return !!(ring->flags & I40E_RXR_FLAGS_BUILD_SKB_ENABLED);
422 }

2088 /**
2089  * i40e_build_skb - Build skb around an existing buffer
2090  * @rx_ring: Rx descriptor ring to transact packets on
2091  * @rx_buffer: Rx buffer to pull data from
2092  * @xdp: xdp_buff pointing to the data
2093  *
2094  * This function builds an skb around an existing Rx buffer, taking care
2095  * to set up the skb correctly and avoid any memcpy overhead.
2096  */
2097 static struct sk_buff *i40e_build_skb(struct i40e_ring *rx_ring,
2098                                       struct i40e_rx_buffer *rx_buffer,
2099                                       struct xdp_buff *xdp)
2100 {
2101         unsigned int metasize = xdp->data - xdp->data_meta;
2102 #if (PAGE_SIZE < 8192)
2103         unsigned int truesize = i40e_rx_pg_size(rx_ring) / 2;
2104 #else
2105         unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
2106                                 SKB_DATA_ALIGN(xdp->data_end -
2107                                                xdp->data_hard_start);
2108 #endif
2109         struct sk_buff *skb;
2110
2111         /* Prefetch first cache line of first page. If xdp->data_meta
2112          * is unused, this points exactly as xdp->data, otherwise we
2113          * likely have a consumer accessing first few bytes of meta
2114          * data, and then actual data.
2115          */
2116         prefetch(xdp->data_meta);
2117 #if L1_CACHE_BYTES < 128
2118         prefetch(xdp->data_meta + L1_CACHE_BYTES);
2119 #endif
2120         /* build an skb around the page buffer */
2121         skb = build_skb(xdp->data_hard_start, truesize);
2122         if (unlikely(!skb))
2123                 return NULL;
2124
2125         /* update pointers within the skb to store the data */
2126         skb_reserve(skb, xdp->data - xdp->data_hard_start);
2127         __skb_put(skb, xdp->data_end - xdp->data);
2128         if (metasize)
2129                 skb_metadata_set(skb, metasize);
2130
2131         /* buffer is used by skb, update page_offset */
2132 #if (PAGE_SIZE < 8192)
2133         rx_buffer->page_offset ^= truesize;
2134 #else
2135         rx_buffer->page_offset += truesize;
2136 #endif
2137
2138         return skb;
2139 }
```



需要确认头文件？

```c
# vi drivers/net/ethernet/intel/i40evf/i40e_trace.h
/**
 * i40e_trace() macro enables shared code to refer to trace points
 * like:
 *
 * trace_i40e{,vf}_example(args...)
 *
 * ... as:
 *
 * i40e_trace(example, args...)
 *
 * ... to resolve to the PF or VF version of the tracepoint without
 * ifdefs, and to allow tracepoints to be disabled entirely at build
 * time.
 *
 * Trace point should always be referred to in the driver via this
 * macro.
 *
 * Similarly, i40e_trace_enabled(trace_name) wraps references to
 * trace_i40e{,vf}_<trace_name>_enabled() functions.
 */
#define _I40E_TRACE_NAME(trace_name) (trace_ ## i40evf ## _ ## trace_name)
#define I40E_TRACE_NAME(trace_name) _I40E_TRACE_NAME(trace_name)

#define i40e_trace(trace_name, args...) I40E_TRACE_NAME(trace_name)(args)

// i40e_trace(clean_rx_irq, rx_ring, rx_desc, skb);
```



i40e_run_xdp 函数定义如下：

```c
/**
 * i40e_run_xdp - run an XDP program
 * @rx_ring: Rx ring being processed
 * @xdp: XDP buffer containing the frame
 **/
static struct sk_buff *i40e_run_xdp(struct i40e_ring *rx_ring,
                                    struct xdp_buff *xdp)
{
        int err, result = I40E_XDP_PASS;
        struct i40e_ring *xdp_ring;
        struct bpf_prog *xdp_prog;
        u32 act;

        rcu_read_lock();
        xdp_prog = READ_ONCE(rx_ring->xdp_prog);

        if (!xdp_prog)
                goto xdp_out;

        prefetchw(xdp->data_hard_start); /* xdp_frame write */

        // 调用定义的 xdp prog 程序，并根据结果码执行对应的动作
        act = bpf_prog_run_xdp(xdp_prog, xdp); //
        switch (act) {
        case XDP_PASS:
                break;
        case XDP_TX:
                xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->queue_index];
                result = i40e_xmit_xdp_tx_ring(xdp, xdp_ring);
                break;
        case XDP_REDIRECT:
                err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
                result = !err ? I40E_XDP_REDIR : I40E_XDP_CONSUMED;
                break;
        default:
                bpf_warn_invalid_xdp_action(act);
        case XDP_ABORTED:
                trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
                /* fallthrough -- handle aborts by dropping packet */
        case XDP_DROP:
                result = I40E_XDP_CONSUMED;
                break;
        }
xdp_out:
        rcu_read_unlock();
        return ERR_PTR(-result);
}
```



## 网卡 ring_buffer 结构

vi drivers/net/ethernet/intel/i40e/i40e_txrx.c

```c
/**
 * i40e_get_rx_buffer - Fetch Rx buffer and synchronize data for use
 * @rx_ring: rx descriptor ring to transact packets on
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct i40e_rx_buffer *i40e_get_rx_buffer(struct i40e_ring *rx_ring,
                                                 const unsigned int size)
{
        struct i40e_rx_buffer *rx_buffer;

        rx_buffer = &rx_ring->rx_bi[rx_ring->next_to_clean];
        prefetchw(rx_buffer->page);

        /* we are reusing so sync this buffer for CPU use */
        dma_sync_single_range_for_cpu(rx_ring->dev,
                                      rx_buffer->dma,
                                      rx_buffer->page_offset,
                                      size,
                                      DMA_FROM_DEVICE);

        /* We have pulled a buffer for use, so decrement pagecnt_bias */
        /* We have pulled a buffer for use, so decrement pagecnt_bias */
        rx_buffer->pagecnt_bias--;

        return rx_buffer;
}
```



对应结构定义

vi drivers/net/ethernet/intel/i40e/i40e_txrx.h

```c
/* struct that defines a descriptor ring, associated with a VSI */
struct i40e_ring {
        struct i40e_ring *next;         /* pointer to next ring in q_vector */
        void *desc;                     /* Descriptor ring memory */
        struct device *dev;             /* Used for DMA mapping */
        struct net_device *netdev;      /* netdev ring maps to */
        struct bpf_prog *xdp_prog;
        union {
                struct i40e_tx_buffer *tx_bi;
                struct i40e_rx_buffer *rx_bi;  // 此处结构应该为数组结构，下面我们查找初始化的地方
        };
        DECLARE_BITMAP(state, __I40E_RING_STATE_NBITS);
        u16 queue_index;                /* Queue number of ring */
        u8 dcb_tc;                      /* Traffic class of ring */
        u8 __iomem *tail;

        /* high bit set means dynamic, use accessor routines to read/write.
         * hardware only supports 2us resolution for the ITR registers.
         * these values always store the USER setting, and must be converted
         * before programming to a register.
         */
        u16 itr_setting;

        u16 count;                      /* Number of descriptors */
        u16 reg_idx;                    /* HW register index of the ring */
        u16 rx_buf_len;

        /* used in interrupt processing */
        u16 next_to_use;
        u16 next_to_clean;

        u8 atr_sample_rate;
        u8 atr_count;

        bool ring_active;               /* is ring online or not */
        bool arm_wb;            /* do something to arm write back */
        u8 packet_stride;

        u16 flags;
#define I40E_TXR_FLAGS_WB_ON_ITR                BIT(0)
#define I40E_RXR_FLAGS_BUILD_SKB_ENABLED        BIT(1)
#define I40E_TXR_FLAGS_XDP                      BIT(2)

        /* stats structs */
        struct i40e_queue_stats stats;
        struct u64_stats_sync syncp;
        union {
                struct i40e_tx_queue_stats tx_stats;
                struct i40e_rx_queue_stats rx_stats;
        };

        unsigned int size;              /* length of descriptor ring in bytes */
        dma_addr_t dma;                 /* physical address of ring */

        struct i40e_vsi *vsi;           /* Backreference to associated VSI */
        struct i40e_q_vector *q_vector; /* Backreference to associated vector */

        struct rcu_head rcu;            /* to avoid race on free */
        u16 next_to_alloc;
        struct sk_buff *skb;            /* When i40e_clean_rx_ring_irq() must
                                         * return before it sees the EOP for
                                         * the current packet, we save that skb
                                         * here and resume receiving this
                                         * packet the next time
                                         * i40e_clean_rx_ring_irq() is called
                                         * for this ring.
                                         */

        struct i40e_channel *ch;
        struct xdp_rxq_info xdp_rxq;
} ____cacheline_internodealigned_in_smp;


struct i40e_rx_buffer {
        dma_addr_t dma;
        struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
        __u32 page_offset;
#else
        __u16 page_offset;
#endif
        __u16 pagecnt_bias;
};

```

drivers/net/ethernet/intel/i40e/i40e_txrx.c

```c
/**
 * i40e_setup_rx_descriptors - Allocate Rx descriptors
 * @rx_ring: Rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int i40e_setup_rx_descriptors(struct i40e_ring *rx_ring)
{
        struct device *dev = rx_ring->dev;
        int err = -ENOMEM;
        int bi_size;

        /* warn if we are about to overwrite the pointer */
        WARN_ON(rx_ring->rx_bi);
        // !!! 初始化 rx_ring->rx_bi 结构
        bi_size = sizeof(struct i40e_rx_buffer) * rx_ring->count;
        rx_ring->rx_bi = kzalloc(bi_size, GFP_KERNEL);
        if (!rx_ring->rx_bi)
                goto err;

        u64_stats_init(&rx_ring->syncp);

        /* Round up to nearest 4K */
        rx_ring->size = rx_ring->count * sizeof(union i40e_32byte_rx_desc);
        rx_ring->size = ALIGN(rx_ring->size, 4096);
        rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
                                           &rx_ring->dma, GFP_KERNEL);
  
  // ...
}
```

