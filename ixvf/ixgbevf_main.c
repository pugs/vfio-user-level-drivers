/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
/*
 * Original driver heavily hacked and reduced to run in user mode
 */

/*******************************************************************************

  Intel 82599 Virtual Function driver
  Copyright(c) 1999 - 2009 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


/******************************************************************************
 Copyright (c)2006 - 2007 Myricom, Inc. for some LRO specific code
******************************************************************************/
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/pci_regs.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include "../uld/kcompat.h"
#include "../uld/uld.h"
#include "../uld/skbuff.h"
#include "kcompat.h"
#include "ixgbevf.h"
#include "ixvf_uld.h"

#include "../vfio/vfio_lib.h"

#define	IXVF_MSIX_RQ	0
#define	IXVF_MSIX_WQ	1
#define	IXVF_MSIX_MBX	2

char ixgbevf_driver_name[] = "ixgbevf";
static const char ixgbevf_driver_string[] =
	"Intel(R) 82599 Virtual Function";

#define DRIVERNAPI "-NAPI"

#define DRV_VERSION "1.0.1" DRIVERNAPI 
const char ixgbevf_driver_version[] = DRV_VERSION;
char ixgbevf_copyright[] = "Copyright (c) 1999-2009 Intel Corporation.";

#define DEFAULT_DEBUG_LEVEL_SHIFT 3

/* forward decls */
static void ixgbevf_set_itr_msix(struct ixgbevf_q_vector *q_vector);
static void ixgbevf_write_eitr(struct ixgbevf_adapter *adapter, int v_idx,
			       u32 itr_reg);

/**
 *  ixgbe_validate_mac_addr - Validate MAC address
 *  @mac_addr: pointer to MAC address.
 *
 *  Tests a MAC address to ensure it is a valid Individual Address
 **/
s32 ixgbevf_validate_mac_addr(u8 *mac_addr)
{
	s32 status = 0;

	/* Make sure it is not a multicast address */
	if (IXGBE_IS_MULTICAST(mac_addr)) {
		hw_dbg(hw, "MAC address is multicast\n");
		status = IXGBE_ERR_INVALID_MAC_ADDR;
	/* Not a broadcast address */
	} else if (IXGBE_IS_BROADCAST(mac_addr)) {
		hw_dbg(hw, "MAC address is broadcast\n");
		status = IXGBE_ERR_INVALID_MAC_ADDR;
	/* Reject the zero address */
	} else if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
	           mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0) {
		hw_dbg(hw, "MAC address is all zeros\n");
		status = IXGBE_ERR_INVALID_MAC_ADDR;
	}
	return status;
}

static inline void ixgbevf_release_rx_desc(struct ixgbe_hw *hw,
					   struct ixgbevf_ring *rx_ring,
					   u32 val)
{
	/*
	 * Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	IXGBE_WRITE_REG(hw, IXGBE_VFRDT(rx_ring->reg_idx), val);
}

/*
 * ixgbe_set_ivar - set the IVAR registers, mapping interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 *
 */
static void ixgbevf_set_ivar(struct ixgbevf_adapter *adapter, s8 direction,
	                   u8 queue, u8 msix_vector)
{
	u32 ivar, index;
	struct ixgbe_hw *hw = &adapter->hw;
	if (direction == -1) {
		/* other causes */
		msix_vector |= IXGBE_IVAR_ALLOC_VAL;
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR_MISC);
		ivar &= ~0xFF;
		ivar |= msix_vector;
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR_MISC, ivar);
	} else {
		/* tx or rx causes */
		msix_vector |= IXGBE_IVAR_ALLOC_VAL;
		index = ((16 * (queue & 1)) + (8 * direction));
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR(queue >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR(queue >> 1), ivar);
	}
}

static void ixgbevf_unmap_and_free_tx_resource(struct ixgbevf_adapter *adapter,
					       struct ixgbevf_tx_buffer
					       *tx_buffer_info)
{
	if (tx_buffer_info->dma) {
#ifdef notdef
		pci_unmap_page(adapter->pdev, tx_buffer_info->dma,
		               tx_buffer_info->length, PCI_DMA_TODEVICE);

#endif
		tx_buffer_info->dma = 0;
	}
	if (tx_buffer_info->skb) {
		skb_free(tx_buffer_info->skb);
		tx_buffer_info->skb = NULL;
	}
	/* tx_buffer_info must be completely set up in the transmit path */
}

static inline bool ixgbevf_check_tx_hang(struct ixgbevf_adapter *adapter,
					 struct ixgbevf_ring *tx_ring,
					 unsigned int eop)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 head, tail;

	/* Detect a transmit hang in hardware, this serializes the
	 * check with the clearing of time_stamp and movement of eop */
	head = IXGBE_READ_REG(hw, tx_ring->head);
	tail = IXGBE_READ_REG(hw, tx_ring->tail);
	adapter->detect_tx_hung = false;
	if ((head != tail) &&
	    tx_ring->tx_buffer_info[eop].time_stamp &&
	    jiffies() > tx_ring->tx_buffer_info[eop].time_stamp + HZ) {
		/* detected Tx unit hang */
		union ixgbe_adv_tx_desc *tx_desc;
		tx_desc = IXGBE_TX_DESC_ADV(*tx_ring, eop);
		DPRINTK(DRV, ERR, "Detected Tx Unit Hang\n"
			"  Tx Queue             <%d>\n"
			"  TDH, TDT             <%x>, <%x>\n"
			"  next_to_use          <%x>\n"
			"  next_to_clean        <%x>\n"
			"tx_buffer_info[next_to_clean]\n"
			"  time_stamp           <%lx>\n"
			"  jiffies              <%x>\n",
			tx_ring->queue_index,
			head, tail,
			tx_ring->next_to_use, eop,
			tx_ring->tx_buffer_info[eop].time_stamp, jiffies());
		return true;
	}

	return false;
}

#define IXGBE_MAX_TXD_PWR	14
#define IXGBE_MAX_DATA_PER_TXD	(1 << IXGBE_MAX_TXD_PWR)

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S) (((S) >> IXGBE_MAX_TXD_PWR) + \
			 (((S) & (IXGBE_MAX_DATA_PER_TXD - 1)) ? 1 : 0))
#ifdef MAX_SKB_FRAGS
#define DESC_NEEDED (TXD_USE_COUNT(IXGBE_MAX_DATA_PER_TXD) /* skb->data */ + \
	MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE) + 1)      /* for context */
#else
#define DESC_NEEDED TXD_USE_COUNT(IXGBE_MAX_DATA_PER_TXD)
#endif

static void ixgbevf_tx_timeout(struct ixgbevf_adapter *);

/**
 * ixgbevf_clean_tx_irq - Reclaim resources after transmit completes
 * @adapter: board private structure
 * @tx_ring: tx ring to clean
 **/
static bool ixgbevf_clean_tx_irq(struct ixgbevf_adapter *adapter,
				 struct ixgbevf_ring *tx_ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	union ixgbe_adv_tx_desc *tx_desc, *eop_desc;
	struct ixgbevf_tx_buffer *tx_buffer_info;
	unsigned int i, eop, count = 0;
	unsigned int total_bytes = 0, total_packets = 0;

	i = tx_ring->next_to_clean;
	eop = tx_ring->tx_buffer_info[i].next_to_watch;
	eop_desc = IXGBE_TX_DESC_ADV(*tx_ring, eop);

	while ((eop_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)) &&
	       (count < tx_ring->work_limit)) {
		bool cleaned = false;
		for ( ; !cleaned; count++) {
			struct sk_buff *skb;
			tx_desc = IXGBE_TX_DESC_ADV(*tx_ring, i);
			tx_buffer_info = &tx_ring->tx_buffer_info[i];
			cleaned = (i == eop);
			skb = tx_buffer_info->skb;

			if (cleaned && skb) {
#ifdef NETIF_F_TSO
				unsigned int segs, bytecount;

				/* gso_segs is currently only valid for tcp */
				segs = skb_shinfo(skb)->gso_segs ?: 1;
				/* multiply data chunks by size of headers */
				bytecount = ((segs - 1) * skb_headlen(skb)) +
				            skb->len;
				total_packets += segs;
				total_bytes += bytecount;
#else
				total_packets++;
				total_bytes += skb->len;
#endif
			}

			ixgbevf_unmap_and_free_tx_resource(adapter,
							   tx_buffer_info);

			tx_desc->wb.status = 0;

			i++;
			if (i == tx_ring->count)
				i = 0;
		}

		eop = tx_ring->tx_buffer_info[i].next_to_watch;
		eop_desc = IXGBE_TX_DESC_ADV(*tx_ring, eop);
	}

	tx_ring->next_to_clean = i;

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(count &&
	             (IXGBE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
	}

	if (adapter->detect_tx_hung) {
		if (ixgbevf_check_tx_hang(adapter, tx_ring, i)) {
			/* schedule immediate reset if we believe we hung */
			DPRINTK(PROBE, INFO,
			        "tx hang %d detected, resetting adapter\n",
			        adapter->tx_timeout_count + 1);
			ixgbevf_tx_timeout(adapter);
		}
	}

	/* re-arm the interrupt */
	if ((count >= tx_ring->work_limit) &&
	    (!test_bit(__IXGBEVF_DOWN, &adapter->state))) {
		IXGBE_WRITE_REG(hw, IXGBE_VTEICS, tx_ring->v_idx);
	}

	tx_ring->total_bytes += total_bytes;
	tx_ring->total_packets += total_packets;

//	adapter->net_stats.tx_bytes += total_bytes;
//	adapter->net_stats.tx_packets += total_packets;

	return (count < tx_ring->work_limit);
}

/**
 * ixgbevf_receive_skb - Send a completed packet up the stack
 * @skb: packet to send up
 **/
static void ixgbevf_receive_skb(struct ixgbevf_adapter *adapter, struct sk_buff *skb)
{
	if (adapter->skb_recv_head) {
		adapter->skb_recv_tail->next = skb;
		adapter->skb_recv_tail = skb;
	} else {
		adapter->skb_recv_head = skb;
		adapter->skb_recv_tail = skb;
	}
}

/**
 * ixgbevf_rx_checksum - indicate in skb if hw indicated a good cksum
 * @adapter: address of board private structure
 * @status_err: hardware indication of status of receive
 * @skb: skb currently being received and modified
 **/
static inline void ixgbevf_rx_checksum(struct ixgbevf_adapter *adapter,
				       u32 status_err, struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* Rx csum disabled */
	if (!(adapter->flags & IXGBE_FLAG_RX_CSUM_ENABLED))
		return;

	/* if IP and error */
	if ((status_err & IXGBE_RXD_STAT_IPCS) &&
	    (status_err & IXGBE_RXDADV_ERR_IPE)) {
		adapter->hw_csum_rx_error++;
		return;
	}

	if (!(status_err & IXGBE_RXD_STAT_L4CS))
		return;

	if (status_err & IXGBE_RXDADV_ERR_TCPE) {
		adapter->hw_csum_rx_error++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	adapter->hw_csum_rx_good++;
}

/**
 * ixgbevf_alloc_rx_buffers - Replace used receive buffers; packet split
 * @adapter: address of board private structure
 **/
static void ixgbevf_alloc_rx_buffers(struct ixgbevf_adapter *adapter,
				     struct ixgbevf_ring *rx_ring,
				     int cleaned_count)
{
	union ixgbe_adv_rx_desc *rx_desc;
	struct ixgbevf_rx_buffer *bi;
	unsigned int i;

	i = rx_ring->next_to_use;
	bi = &rx_ring->rx_buffer_info[i];

	while (cleaned_count--) {
		rx_desc = IXGBE_RX_DESC_ADV(*rx_ring, i);

#ifdef notdef
		if (!bi->page_dma &&
		    (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED)) {
			if (!bi->page) {
				bi->page = alloc_page(GFP_ATOMIC);
				if (!bi->page) {
					adapter->alloc_rx_page_failed++;
					goto no_buffers;
				}
				bi->page_offset = 0;
			} else {
				/* use a half page if we're re-using */
				bi->page_offset ^= (PAGE_SIZE / 2);
			}

			bi->page_dma = pci_map_page(pdev, bi->page,
			                            bi->page_offset,
			                            (PAGE_SIZE / 2),
			                            PCI_DMA_FROMDEVICE);
		}
#endif

		if (!bi->skb) {
			struct sk_buff *skb = skb_alloc(adapter->uld);

			if (!skb) {
				adapter->alloc_rx_buff_failed++;
				goto no_buffers;
			}

			/*
			 * Make buffer alignment 2 beyond a 16 byte boundary
			 * this will result in a 16 byte aligned IP header after
			 * the 14 byte MAC header is removed
			 */
			skb_pull(skb, NET_IP_ALIGN);

			bi->skb = skb;

			bi->dma = skb->dma_addr + (skb->data - skb->buf);
		}
		/* Refresh the desc even if buffer_addrs didn't change because
		 * each write-back erases this info. */
		if (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED) {
			rx_desc->read.pkt_addr = cpu_to_le64(bi->page_dma);
			rx_desc->read.hdr_addr = cpu_to_le64(bi->dma);
		} else {
			rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
		}

		i++;
		if (i == rx_ring->count)
			i = 0;
		bi = &rx_ring->rx_buffer_info[i];
	}

no_buffers:
	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;
		if (i-- == 0)
			i = (rx_ring->count - 1);

		ixgbevf_release_rx_desc(&adapter->hw, rx_ring, i);
	}
}

static inline void ixgbevf_irq_enable_queues(struct ixgbevf_adapter *adapter,
					     u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEIMS, mask);
}

static inline u16 ixgbevf_get_hdr_info(union ixgbe_adv_rx_desc *rx_desc)
{
	return rx_desc->wb.lower.lo_dword.hs_rss.hdr_info;
}

static inline u16 ixgbevf_get_pkt_info(union ixgbe_adv_rx_desc *rx_desc)
{
	return rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;
}

static bool ixgbevf_clean_rx_irq(struct ixgbevf_q_vector *q_vector,
				 struct ixgbevf_ring *rx_ring,
				 int *work_done, int work_to_do)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	union ixgbe_adv_rx_desc *rx_desc, *next_rxd;
	struct ixgbevf_rx_buffer *rx_buffer_info, *next_buffer;
	struct sk_buff *skb;
	unsigned int i;
	u32 len, staterr;
	u16 hdr_info;
	bool cleaned = false;
	int cleaned_count = 0;
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;

	i = rx_ring->next_to_clean;
	rx_desc = IXGBE_RX_DESC_ADV(*rx_ring, i);
	staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
	rx_buffer_info = &rx_ring->rx_buffer_info[i];

	while (staterr & IXGBE_RXD_STAT_DD) {
		u32 upper_len = 0;
		if (*work_done >= work_to_do)
			break;
		(*work_done)++;

		if (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED) {
			hdr_info = le16_to_cpu(ixgbevf_get_hdr_info(rx_desc));
			len = (hdr_info & IXGBE_RXDADV_HDRBUFLEN_MASK) >>
			       IXGBE_RXDADV_HDRBUFLEN_SHIFT;
			if (hdr_info & IXGBE_RXDADV_SPH)
				adapter->rx_hdr_split++;
			if (len > IXGBEVF_RX_HDR_SIZE)
				len = IXGBEVF_RX_HDR_SIZE;
			upper_len = le16_to_cpu(rx_desc->wb.upper.length);
		} else {
			len = le16_to_cpu(rx_desc->wb.upper.length);
		}
		cleaned = true;

		skb = rx_buffer_info->skb;
		rx_buffer_info->skb = NULL;

#ifdef notdef
		if (len && !skb_shinfo(skb)->nr_frags) {
			pci_unmap_single(pdev, rx_buffer_info->dma,
			                 rx_ring->rx_buf_len,
			                 PCI_DMA_FROMDEVICE);
			skb_put(skb, len);
		}
#else
		skb->len = len;
#endif

#ifdef notdef
		if (upper_len) {
  			pci_unmap_page(pdev, rx_buffer_info->page_dma,
  			               PAGE_SIZE / 2, PCI_DMA_FROMDEVICE);
			rx_buffer_info->page_dma = 0;
			skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
			                   rx_buffer_info->page,
			                   rx_buffer_info->page_offset,
			                   upper_len);

			if ((rx_ring->rx_buf_len > (PAGE_SIZE / 2)) ||
			    (page_count(rx_buffer_info->page) != 1))
				rx_buffer_info->page = NULL;
			else
				get_page(rx_buffer_info->page);

			skb->len += upper_len;
			skb->data_len += upper_len;
			skb->truesize += upper_len;
		}
#endif

		i++;
		if (i == rx_ring->count)
			i = 0;

		next_rxd = IXGBE_RX_DESC_ADV(*rx_ring, i);
//		prefetch(next_rxd);
		cleaned_count++;

		next_buffer = &rx_ring->rx_buffer_info[i];

#ifdef notdef
		if (!(staterr & IXGBE_RXD_STAT_EOP)) {
			if (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED) {
				rx_buffer_info->skb = next_buffer->skb;
				rx_buffer_info->dma = next_buffer->dma;
				next_buffer->skb = skb;
				next_buffer->dma = 0;
			} else {
				skb->next = next_buffer->skb;
				skb->next->prev = skb;
			}
			adapter->non_eop_descs++;
			goto next_desc;
		}
#endif

		/* ERR_MASK will only have valid bits if EOP set */
		if (unlikely(staterr & IXGBE_RXDADV_ERR_FRAME_ERR_MASK)) {
			skb_free(skb);
			goto next_desc;
		}

		ixgbevf_rx_checksum(adapter, staterr, skb);

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;
		total_rx_packets++;

		ixgbevf_receive_skb(adapter, skb);

next_desc:
		rx_desc->wb.upper.status_error = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IXGBEVF_RX_BUFFER_WRITE) {
			ixgbevf_alloc_rx_buffers(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		rx_buffer_info = &rx_ring->rx_buffer_info[i];

		staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
	}

	rx_ring->next_to_clean = i;
	cleaned_count = IXGBE_DESC_UNUSED(rx_ring);

	if (cleaned_count)
		ixgbevf_alloc_rx_buffers(adapter, rx_ring, cleaned_count);

	rx_ring->total_packets += total_rx_packets;
	rx_ring->total_bytes += total_rx_bytes;
//	adapter->net_stats.rx_bytes += total_rx_bytes;
//	adapter->net_stats.rx_packets += total_rx_packets;

	return cleaned;
}

/**
 * ixgbevf_clean_rxonly - msix (aka one shot) rx clean routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function is optimized for cleaning one queue only on a single
 * q_vector!!!
 **/
static int ixgbevf_clean_rxonly(struct ixgbevf_q_vector *q_vector, int budget)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbevf_ring *rx_ring = NULL;
	int work_done = 0;
	long r_idx;

	r_idx = 0;
	rx_ring = &(adapter->rx_ring[r_idx]);

	ixgbevf_clean_rx_irq(q_vector, rx_ring, &work_done, budget);

#ifdef XXX_HAVE_NETDEV_NAPI_LIST
	if (!netif_running(adapter->netdev))
		work_done = 0;

#endif

	/* If all Rx work done, exit the polling mode */
	if (work_done < budget) {
//		napi_complete(napi);
		if (adapter->itr_setting & 1)
			ixgbevf_set_itr_msix(q_vector);
		if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
			ixgbevf_irq_enable_queues(adapter, rx_ring->v_idx);
	}

	return work_done;
}

#ifdef notdef
/**
 * ixgbevf_clean_rxonly_many - msix (aka one shot) rx clean routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean more than one rx queue associated with a
 * q_vector.
 **/
static int ixgbevf_clean_rxonly_many(struct ixgbevf_q_vector *q_vector, int budget)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbevf_ring *rx_ring = NULL;
	int work_done = 0, i;
	long r_idx;
	u64 enable_mask = 0;

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling */
	budget /= (q_vector->rxr_count ?: 1);
	budget = max(budget, 1);
	r_idx = 0;
	for (i = 0; i < 1; i++) {
		rx_ring = &(adapter->rx_ring[r_idx]);
		ixgbevf_clean_rx_irq(q_vector, rx_ring, &work_done, budget);
		enable_mask |= rx_ring->v_idx;
	}

#ifdef XXX_HAVE_NETDEV_NAPI_LIST
	if (!netif_running(adapter->netdev))
		work_done = 0;

#endif
	r_idx = 0;
	rx_ring = &(adapter->rx_ring[r_idx]);

	/* If all Rx work done, exit the polling mode */
	if (work_done < budget) {
//		napi_complete(napi);
		if (adapter->itr_setting & 1)
			ixgbevf_set_itr_msix(q_vector);
		if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
			ixgbevf_irq_enable_queues(adapter, enable_mask);
	}

	return work_done;
}
#endif


/**
 * ixgbevf_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * ixgbevf_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
static void ixgbevf_configure_msix(struct ixgbevf_adapter *adapter)
{
	struct ixgbevf_q_vector *q_vector;
	struct ixgbe_hw *hw = &adapter->hw;
	int i, j, q_vectors, v_idx, r_idx;
	u32 mask;

	q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;

	/*
	 * Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < q_vectors; v_idx++) {
		q_vector = adapter->q_vector[v_idx];
		/* XXX for_each_bit(...) */
		r_idx = 0;

		for (i = 0; i < 1; i++) {
			j = adapter->rx_ring[r_idx].reg_idx;
			ixgbevf_set_ivar(adapter, 0, j, v_idx);
		}
		r_idx = 0;

		for (i = 0; i < 1; i++) {
			j = adapter->tx_ring[r_idx].reg_idx;
			ixgbevf_set_ivar(adapter, 1, j, v_idx);
		}

		/* if this is a tx only vector halve the interrupt rate */
		if (q_vector->txr_count && !q_vector->rxr_count)
			q_vector->eitr = (adapter->eitr_param >> 1);
		else if (q_vector->rxr_count)
			/* rx only */
			q_vector->eitr = adapter->eitr_param;

		ixgbevf_write_eitr(adapter, v_idx, q_vector->eitr);
	}

	ixgbevf_set_ivar(adapter, -1, 1, v_idx);

	/* set up to autoclear timer, and the vectors */
	mask = IXGBE_EIMS_ENABLE_MASK;
	mask &= ~(IXGBE_EIMS_OTHER | IXGBE_EIMS_LSC);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAC, mask);
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

/**
 * ixgbevf_update_itr - update the dynamic ITR value based on statistics
 * @adapter: pointer to adapter
 * @eitr: eitr setting (ints per sec) to give last timeslice
 * @itr_setting: current throttle rate in ints/second
 * @packets: the number of packets during this measurement interval
 * @bytes: the number of bytes during this measurement interval
 *
 *      Stores a new ITR value based on packets and byte
 *      counts during the last interrupt.  The advantage of per interrupt
 *      computation is faster updates and more accurate ITR for the current
 *      traffic pattern.  Constants in this function were computed
 *      based on theoretical maximum wire speed and thresholds were set based
 *      on testing data as well as attempting to minimize response time
 *      while increasing bulk throughput.
 *      this functionality is controlled by the InterruptThrottleRate module
 *      parameter (see ixgbevf_param.c)
 **/
static u8 ixgbevf_update_itr(struct ixgbevf_adapter *adapter,
			     u32 eitr, u8 itr_setting,
			     int packets, int bytes)
{
	unsigned int retval = itr_setting;
	u32 timepassed_us;
	u64 bytes_perint;

	if (packets == 0)
		goto update_itr_done;


	/* simple throttlerate management
	 *    0-20MB/s lowest (100000 ints/s)
	 *   20-100MB/s low   (20000 ints/s)
	 *  100-1249MB/s bulk (8000 ints/s)
	 */
	/* what was last interrupt timeslice? */
	timepassed_us = 1000000/eitr;
	bytes_perint = bytes / timepassed_us; /* bytes/usec */

	switch (itr_setting) {
	case lowest_latency:
		if (bytes_perint > adapter->eitr_low) {
			retval = low_latency;
		}
		break;
	case low_latency:
		if (bytes_perint > adapter->eitr_high) {
			retval = bulk_latency;
		}
		else if (bytes_perint <= adapter->eitr_low) {
			retval = lowest_latency;
		}
		break;
	case bulk_latency:
		if (bytes_perint <= adapter->eitr_high) {
			retval = low_latency;
		}
		break;
	}

update_itr_done:
	return retval;
}

/**
 * ixgbevf_write_eitr - write VTEITR register in hardware specific way
 * @adapter: pointer to adapter struct
 * @v_idx: vector index into q_vector array
 * @itr_reg: new value to be written in *register* format, not ints/s
 *
 * This function is made to be called by ethtool and by the driver
 * when it needs to update VTEITR registers at runtime.  Hardware
 * specific quirks/differences are taken care of here.
 */
static void ixgbevf_write_eitr(struct ixgbevf_adapter *adapter, int v_idx,
			       u32 itr_reg)
{
	struct ixgbe_hw *hw = &adapter->hw;

	itr_reg = EITR_INTS_PER_SEC_TO_REG(itr_reg);

	/*
	 * set the WDIS bit to not clear the timer bits and cause an
	 * immediate assertion of the interrupt
	 */
	itr_reg |= IXGBE_EITR_CNT_WDIS;

	IXGBE_WRITE_REG(hw, IXGBE_VTEITR(v_idx), itr_reg);
}

static void ixgbevf_set_itr_msix(struct ixgbevf_q_vector *q_vector)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	u32 new_itr;
	u8 current_itr, ret_itr;
	int i, r_idx, v_idx = q_vector->v_idx;
	struct ixgbevf_ring *rx_ring, *tx_ring;

	r_idx = 0;
	for (i = 0; i < 1; i++) {
		tx_ring = &(adapter->tx_ring[r_idx]);
		ret_itr = ixgbevf_update_itr(adapter, q_vector->eitr,
					     q_vector->tx_itr,
					     tx_ring->total_packets,
					     tx_ring->total_bytes);
		/* if the result for this queue would decrease interrupt
		 * rate for this vector then use that result */
		q_vector->tx_itr = ((q_vector->tx_itr > ret_itr) ?
		                    q_vector->tx_itr - 1 : ret_itr);
	}

	r_idx = 0;
	for (i = 0; i < 1; i++) {
		rx_ring = &(adapter->rx_ring[r_idx]);
		ret_itr = ixgbevf_update_itr(adapter, q_vector->eitr,
					     q_vector->rx_itr,
					     rx_ring->total_packets,
					     rx_ring->total_bytes);
		/* if the result for this queue would decrease interrupt
		 * rate for this vector then use that result */
		q_vector->rx_itr = ((q_vector->rx_itr > ret_itr) ?
		                    q_vector->rx_itr - 1 : ret_itr);
	}

	current_itr = max(q_vector->rx_itr, q_vector->tx_itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = 100000;
		break;
	case low_latency:
		new_itr = 20000; /* aka hwitr = ~200 */
		break;
	case bulk_latency:
	default:
		new_itr = 8000;
		break;
	}

	if (new_itr != q_vector->eitr) {
		u32 itr_reg;

		/* save the algorithm value here, not the smoothed one */
		q_vector->eitr = new_itr;
		/* do an exponential smoothing */
		new_itr = ((q_vector->eitr * 90)/100) + ((new_itr * 10)/100);
		itr_reg = EITR_INTS_PER_SEC_TO_REG(new_itr);
		ixgbevf_write_eitr(adapter, v_idx, itr_reg);
	}

	return;
}

static irqreturn_t ixgbevf_msix_mbx(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 eicr;

	/*
	 * Workaround of Silicon errata on 82598.  Use clear-by-write
	 * instead of clear-by-read to clear EICR , reading EICS gives the
	 * value of EICR without read-clear of EICR
	 */
	eicr = IXGBE_READ_REG(hw, IXGBE_VTEICS);
	IXGBE_WRITE_REG(hw, IXGBE_VTEICR, eicr);

	return IRQ_HANDLED;
}

static irqreturn_t ixgbevf_msix_clean_tx(struct ixgbevf_q_vector *q_vector)
{
	struct ixgbevf_adapter  *adapter = q_vector->adapter;
	struct ixgbevf_ring     *tx_ring;
	int i, r_idx;

	if (!q_vector->txr_count)
		return IRQ_HANDLED;

	r_idx = 0;
	for (i = 0; i < 1; i++) {
		tx_ring = &(adapter->tx_ring[r_idx]);
		tx_ring->total_bytes = 0;
		tx_ring->total_packets = 0;
		ixgbevf_clean_tx_irq(adapter, tx_ring);
	}

	if (adapter->itr_setting & 1)
		ixgbevf_set_itr_msix(q_vector);

	return IRQ_HANDLED;
}

/**
 * ixgbe_msix_clean_rx - single unshared vector rx clean (all queues)
 * @irq: unused
 * @data: pointer to our q_vector struct for this interrupt vector
 **/
static irqreturn_t ixgbevf_msix_clean_rx(struct ixgbevf_q_vector *q_vector)
{
	struct ixgbevf_adapter  *adapter = q_vector->adapter;
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbevf_ring  *rx_ring;
	int r_idx;
	int i;

	r_idx = 0;
	for (i = 0; i < 1; i++) {
		rx_ring = &(adapter->rx_ring[r_idx]);
		rx_ring->total_bytes = 0;
		rx_ring->total_packets = 0;
	}

	if (!q_vector->rxr_count)
		return IRQ_HANDLED;

	r_idx = 0;
	rx_ring = &(adapter->rx_ring[r_idx]);
	/* disable interrupts on this vector only */
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMC, rx_ring->v_idx);
//	napi_schedule(&q_vector->napi);


	return IRQ_HANDLED;
}

static inline void map_vector_to_rxq(struct ixgbevf_adapter *a, int v_idx,
                                     int r_idx)
{
	struct ixgbevf_q_vector *q_vector = a->q_vector[v_idx];

	set_bit(r_idx, q_vector->rxr_idx);
	q_vector->rxr_count++;
	a->rx_ring[r_idx].v_idx = 1 << v_idx;
}

static inline void map_vector_to_txq(struct ixgbevf_adapter *a, int v_idx,
                                     int t_idx)
{
	struct ixgbevf_q_vector *q_vector = a->q_vector[v_idx];

	set_bit(t_idx, q_vector->txr_idx);
	q_vector->txr_count++;
	a->tx_ring[t_idx].v_idx = 1 << v_idx;
}

/**
 * ixgbevf_map_rings_to_vectors - Maps descriptor rings to vectors
 * @adapter: board private structure to initialize
 *
 * This function maps descriptor rings to the queue-specific vectors
 * we were allotted through the MSI-X enabling code.  Ideally, we'd have
 * one vector per ring/queue, but on a constrained vector budget, we
 * group the rings as "efficiently" as possible.  You would add new
 * mapping configurations in here.
 **/
static int ixgbevf_map_rings_to_vectors(struct ixgbevf_adapter *adapter)
{
	int q_vectors;
	int v_start = 0;
	int rxr_idx = 0, txr_idx = 0;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int i, j;
	int rqpv, tqpv;
	int err = 0;

	q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;

	/*
	 * The ideal configuration...
	 * We have enough vectors to map one per queue.
	 */
	if (q_vectors == adapter->num_rx_queues + adapter->num_tx_queues) {
		for (; rxr_idx < rxr_remaining; v_start++, rxr_idx++)
			map_vector_to_rxq(adapter, v_start, rxr_idx);

		for (; txr_idx < txr_remaining; v_start++, txr_idx++)
			map_vector_to_txq(adapter, v_start, txr_idx);
		goto out;
	}

	/*
	 * If we don't have enough vectors for a 1-to-1
	 * mapping, we'll have to group them so there are
	 * multiple queues per vector.
	 */
	/* Re-adjusting *qpv takes care of the remainder. */
	for (i = v_start; i < q_vectors; i++) {
		rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors - i);
		for (j = 0; j < rqpv; j++) {
			map_vector_to_rxq(adapter, i, rxr_idx);
			rxr_idx++;
			rxr_remaining--;
		}
	}
	for (i = v_start; i < q_vectors; i++) {
		tqpv = DIV_ROUND_UP(txr_remaining, q_vectors - i);
		for (j = 0; j < tqpv; j++) {
			map_vector_to_txq(adapter, i, txr_idx);
			txr_idx++;
			txr_remaining--;
		}
	}

out:
	return err;
}

/**
 * ixgbevf_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * ixgbevf_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int ixgbevf_request_msix_irqs(struct ixgbevf_adapter *adapter)
{
	return 0;
}

static inline void ixgbevf_reset_q_vectors(struct ixgbevf_adapter *adapter)
{
	int i, q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;

	for (i = 0; i < q_vectors; i++) {
		struct ixgbevf_q_vector *q_vector = adapter->q_vector[i];
		bitmap_zero(q_vector->rxr_idx, MAX_RX_QUEUES);
		bitmap_zero(q_vector->txr_idx, MAX_TX_QUEUES);
		q_vector->rxr_count = 0;
		q_vector->txr_count = 0;
		q_vector->eitr = adapter->eitr_param;
	}
}

/**
 * ixgbevf_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int ixgbevf_request_irq(struct ixgbevf_adapter *adapter)
{
	int err = 0;

	err = ixgbevf_request_msix_irqs(adapter);

	if (err)
		DPRINTK(PROBE, ERR, "request_irq failed, Error %d\n", err);

	return err;
}

static void ixgbevf_free_irq(struct ixgbevf_adapter *adapter)
{
	int i, q_vectors;

	q_vectors = adapter->num_msix_vectors;

#ifdef notdef
	i = q_vectors - 1;

	free_irq(adapter->msix_entries[i].vector, netdev);
	i--;

	for (; i >= 0; i--) {
		free_irq(adapter->msix_entries[i].vector,
			 adapter->q_vector[i]);
	}
#endif
	for (i = 0; i < MIN_MSIX_COUNT; i++)
		close(adapter->msix[i].fd);

	ixgbevf_reset_q_vectors(adapter);
}

/**
 * ixgbevf_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static inline void ixgbevf_irq_disable(struct ixgbevf_adapter *adapter)
{
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEIMC, ~0);

	IXGBE_WRITE_FLUSH(&adapter->hw);

//	for (i = 0; i < adapter->num_msix_vectors; i++)
//		synchronize_irq(adapter->msix_entries[i].vector);
}

/**
 * ixgbevf_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static inline void ixgbevf_irq_enable(struct ixgbevf_adapter *adapter,
				      bool queues, bool flush)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 mask;
	u64 qmask;

	mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);
	qmask = ~0;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, mask);

	if (queues)
		ixgbevf_irq_enable_queues(adapter, qmask);

	if (flush)
		IXGBE_WRITE_FLUSH(hw);
}

/**
 * ixgbevf_configure_tx - Configure 82599 VF Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void ixgbevf_configure_tx(struct ixgbevf_adapter *adapter)
{
	u64 tdba;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 i, j, tdlen, txctrl;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbevf_ring *ring = &adapter->tx_ring[i];
		j = ring->reg_idx;
		tdba = ring->dma;
		tdlen = ring->count * sizeof(union ixgbe_adv_tx_desc);
		IXGBE_WRITE_REG(hw, IXGBE_VFTDBAL(j),
		                (tdba & DMA_BIT_MASK(32)));
		IXGBE_WRITE_REG(hw, IXGBE_VFTDBAH(j), (tdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_VFTDLEN(j), tdlen);
		IXGBE_WRITE_REG(hw, IXGBE_VFTDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_VFTDT(j), 0);
		adapter->tx_ring[i].head = IXGBE_VFTDH(j);
		adapter->tx_ring[i].tail = IXGBE_VFTDT(j);
		/* Disable Tx Head Writeback RO bit, since this hoses
		 * bookkeeping if things aren't delivered in order.
		 */
		txctrl = IXGBE_READ_REG(hw, IXGBE_VFDCA_TXCTRL(j));
		txctrl &= ~IXGBE_DCA_TXCTRL_TX_WB_RO_EN;
		IXGBE_WRITE_REG(hw, IXGBE_VFDCA_TXCTRL(j), txctrl);
	}
}

#define IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT	2

static void ixgbevf_configure_srrctl(struct ixgbevf_adapter *adapter, int index)
{
	struct ixgbevf_ring *rx_ring;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 srrctl;

	rx_ring = &adapter->rx_ring[index];

#ifdef notdef
	if (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED) {
		u16 bufsz = IXGBEVF_RXBUFFER_2048;
		srrctl = IXGBE_READ_REG(hw, IXGBE_VFSRRCTL(index));

		srrctl &= ~IXGBE_SRRCTL_BSIZEHDR_MASK;
		srrctl &= ~IXGBE_SRRCTL_BSIZEPKT_MASK;
		srrctl |= IXGBE_SRRCTL_DROP_EN;

		/* grow the amount we can receive on large page machines */
		if (bufsz < (PAGE_SIZE / 2))
			bufsz = (PAGE_SIZE / 2);
		/* cap the bufsz at our largest descriptor size */
		bufsz = min((u16)IXGBEVF_MAX_RXBUFFER, bufsz);

		srrctl |= bufsz >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
		srrctl |= IXGBE_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS;
		srrctl |= ((IXGBEVF_RX_HDR_SIZE <<
		            IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT) &
		           IXGBE_SRRCTL_BSIZEHDR_MASK);
	} else {
#endif
		srrctl = IXGBE_SRRCTL_DROP_EN;
		srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

		if (rx_ring->rx_buf_len == MAXIMUM_ETHERNET_VLAN_SIZE)
			srrctl |= IXGBEVF_RXBUFFER_2048 >>
			          IXGBE_SRRCTL_BSIZEPKT_SHIFT;
		else
			srrctl |= rx_ring->rx_buf_len >>
			          IXGBE_SRRCTL_BSIZEPKT_SHIFT;
#ifdef notdef
	}
#endif
	IXGBE_WRITE_REG(hw, IXGBE_VFSRRCTL(index), srrctl);
}

/**
 * ixgbevf_configure_rx - Configure 82599 VF Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void ixgbevf_configure_rx(struct ixgbevf_adapter *adapter)
{
	u64 rdba;
	struct ixgbe_hw *hw = &adapter->hw;
	int max_frame = adapter->uld->mtu + ETH_HLEN + ETH_FCS_LEN;
	int i, j;
	u32 rdlen;
	int rx_buf_len;


	/* Force single buffer mode - packet split is not supported */
	adapter->flags &= ~(IXGBE_FLAG_RX_PS_CAPABLE |
			    IXGBE_FLAG_RX_PS_ENABLED);
	adapter->flags |= IXGBE_FLAG_RX_1BUF_CAPABLE;
	/* Set the RX buffer length according to the mode */
	if (adapter->flags & IXGBE_FLAG_RX_PS_ENABLED) {
		/* PSRTYPE must be initialized in 82599 */
		u32 psrtype = IXGBE_PSRTYPE_TCPHDR |
			IXGBE_PSRTYPE_UDPHDR |
			IXGBE_PSRTYPE_IPV4HDR |
			IXGBE_PSRTYPE_IPV6HDR |
			IXGBE_PSRTYPE_L2HDR;
		IXGBE_WRITE_REG(hw, IXGBE_VFPSRTYPE, psrtype);
		rx_buf_len = IXGBEVF_RX_HDR_SIZE;
	} else {
		IXGBE_WRITE_REG(hw, IXGBE_VFPSRTYPE, 0);
		if (adapter->uld->mtu <= ETH_DATA_LEN)
			rx_buf_len = MAXIMUM_ETHERNET_VLAN_SIZE;
		else
			rx_buf_len = ALIGN(max_frame, 1024);
	}

	rdlen = adapter->rx_ring[0].count * sizeof(union ixgbe_adv_rx_desc);
	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		rdba = adapter->rx_ring[i].dma;
		j = adapter->rx_ring[i].reg_idx;
		IXGBE_WRITE_REG(hw, IXGBE_VFRDBAL(j), (rdba & DMA_BIT_MASK(32)));
		IXGBE_WRITE_REG(hw, IXGBE_VFRDBAH(j), (rdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_VFRDLEN(j), rdlen);
		IXGBE_WRITE_REG(hw, IXGBE_VFRDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_VFRDT(j), 0);
		adapter->rx_ring[i].head = IXGBE_VFRDH(j);
		adapter->rx_ring[i].tail = IXGBE_VFRDT(j);
		adapter->rx_ring[i].rx_buf_len = rx_buf_len;

		ixgbevf_configure_srrctl(adapter, j);
	}
}

#ifdef NETIF_F_HW_VLAN_TX
static void ixgbevf_vlan_rx_register(struct net_device *netdev,
				     struct vlan_group *grp)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int i, j;
	u32 ctrl;

	adapter->vlgrp = grp;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		j = adapter->rx_ring[i].reg_idx;
		ctrl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j));
		ctrl |= IXGBE_RXDCTL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(j), ctrl);
	}
}

static void ixgbevf_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
#ifndef HAVE_NETDEV_VLAN_FEATURES
	struct net_device *v_netdev;
#endif /* HAVE_NETDEV_VLAN_FEATURES */

	/* add VID to filter table */
	if (hw->mac.ops.set_vfta)
		hw->mac.ops.set_vfta(hw, vid, 0, true);
#ifndef HAVE_NETDEV_VLAN_FEATURES
	/*
	 * Copy feature flags from netdev to the vlan netdev for this vid.
	 * This allows things like TSO to bubble down to our vlan device.
	 */
	v_netdev = vlan_group_get_device(adapter->vlgrp, vid);
	v_netdev->features |= adapter->netdev->features;
	vlan_group_set_device(adapter->vlgrp, vid, v_netdev);
#endif /* HAVE_NETDEV_VLAN_FEATURES */
}

static void ixgbevf_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;

	if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
		ixgbevf_irq_disable(adapter);

	vlan_group_set_device(adapter->vlgrp, vid, NULL);

	if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
		ixgbevf_irq_enable(adapter, true, true);

	/* remove VID from filter table */
	if (hw->mac.ops.set_vfta)
		hw->mac.ops.set_vfta(hw, vid, 0, false);
}

static void ixgbevf_restore_vlan(struct ixgbevf_adapter *adapter)
{
	ixgbevf_vlan_rx_register(adapter->netdev, adapter->vlgrp);

	if (adapter->vlgrp) {
		u16 vid;
		for (vid = 0; vid < VLAN_GROUP_ARRAY_LEN; vid++) {
			if (!vlan_group_get_device(adapter->vlgrp, vid))
				continue;
			ixgbevf_vlan_rx_add_vid(adapter->netdev, vid);
		}
	}
}

#endif

#ifdef notdef
static u8 *ixgbevf_addr_list_itr(struct ixgbe_hw *hw, u8 **mc_addr_ptr, u32 *vmdq)
{
	struct dev_mc_list *mc_ptr;
	u8 *addr = *mc_addr_ptr;
	*vmdq = 0;

	mc_ptr = container_of(addr, struct dev_mc_list, dmi_addr[0]);
	if (mc_ptr->next)
		*mc_addr_ptr = mc_ptr->next->dmi_addr;
	else
		*mc_addr_ptr = NULL;

	printk("Adding MC addr: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
	       addr[0],
	       addr[1],
	       addr[2],
	       addr[3],
	       addr[4],
	       addr[5]);

	return addr;
}
#endif

#ifdef notdef
/**
 * ixgbevf_set_rx_mode - Multicast set
 * @netdev: network interface device structure
 *
 * The set_rx_method entry point is called whenever the multicast address
 * list or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper multicast mode.
 **/
static void ixgbevf_set_rx_mode(struct ixgbevf_adapter *adapter)
{
	struct uld *uld = adapter->uld;
	struct ixgbe_hw *hw = &adapter->hw;
	u8 *addr_list = NULL;
	int addr_count = 0;

	/* reprogram multicast list */
	addr_count = uld->mc_count;
	if (addr_count)
		addr_list = uld->mc_list;
	if (hw->mac.ops.update_mc_addr_list)
		hw->mac.ops.update_mc_addr_list(hw, addr_list, addr_count,
						ixgbevf_addr_list_itr);
}
#endif

#ifdef notdef
static void ixgbevf_napi_enable_all(struct ixgbevf_adapter *adapter)
{
	int q_idx;
	struct ixgbevf_q_vector *q_vector;
	int q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;

	for (q_idx = 0; q_idx < q_vectors; q_idx++) {
		struct napi_struct *napi;
		q_vector = adapter->q_vector[q_idx];
		if (!q_vector->rxr_count)
			continue;
		napi = &q_vector->napi;
		if (q_vector->rxr_count > 1)
			napi->poll = &ixgbevf_clean_rxonly_many;

		napi_enable(napi);
	}
}

static void ixgbevf_napi_disable_all(struct ixgbevf_adapter *adapter)
{
	int q_idx;
	struct ixgbevf_q_vector *q_vector;
	int q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;

	for (q_idx = 0; q_idx < q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];
		if (!q_vector->rxr_count)
			continue;
		napi_disable(&q_vector->napi);
	}
}
#endif

static void ixgbevf_configure(struct ixgbevf_adapter *adapter)
{
	int i;

//	ixgbevf_set_rx_mode(netdev);

#ifdef NETIF_F_HW_VLAN_TX
	ixgbevf_restore_vlan(adapter);

#endif
	ixgbevf_configure_tx(adapter);
	ixgbevf_configure_rx(adapter);
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ixgbevf_ring *ring = &adapter->rx_ring[i];
		ixgbevf_alloc_rx_buffers(adapter, ring, ring->count);
		ring->next_to_use = ring->count - 1;
		writel(ring->next_to_use, adapter->hw.hw_addr + ring->tail);
	}
}

#define IXGBE_MAX_RX_DESC_POLL 10
static inline void ixgbevf_rx_desc_queue_enable(struct ixgbevf_adapter *adapter,
						int rxr)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int j = adapter->rx_ring[rxr].reg_idx;
	int k;

	for (k = 0; k < IXGBE_MAX_RX_DESC_POLL; k++) {
		if (IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j)) & IXGBE_RXDCTL_ENABLE)
			break;
		else
			usleep(1000);
	}
	if (k >= IXGBE_MAX_RX_DESC_POLL) {
		DPRINTK(DRV, ERR, "RXDCTL.ENABLE on Rx queue %d "
		        "not set within the polling period\n", rxr);
	}

	ixgbevf_release_rx_desc(hw, &adapter->rx_ring[rxr],
				(adapter->rx_ring[rxr].count - 1));
}

static void ixgbevf_watchdog(void *data);
static void ixgbevf_watchdog_task(void *arg);

static int ixgbevf_up_complete(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i, j = 0;
	int num_rx_rings = adapter->num_rx_queues;
	u32 txdctl, rxdctl;

#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (adapter->num_tx_queues > 1)
		netdev->features |= NETIF_F_MULTI_QUEUE;

#endif
	for (i = 0; i < adapter->num_tx_queues; i++) {
		j = adapter->tx_ring[i].reg_idx;
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(j));
		/* enable WTHRESH=8 descriptors, to encourage burst writeback */
		txdctl |= (8 << 16);
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(j), txdctl);
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		j = adapter->tx_ring[i].reg_idx;
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(j));
		txdctl |= IXGBE_TXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(j), txdctl);
	}

	for (i = 0; i < num_rx_rings; i++) {
		j = adapter->rx_ring[i].reg_idx;
		rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j));
		rxdctl |= IXGBE_RXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(j), rxdctl);
		ixgbevf_rx_desc_queue_enable(adapter, i);
	}

	ixgbevf_configure_msix(adapter);

	if (hw->mac.ops.set_rar) {
		if (is_valid_ether_addr(hw->mac.addr))
			hw->mac.ops.set_rar(hw, 0, hw->mac.addr,
					    0, IXGBE_RAH_AV);
		else
			hw->mac.ops.set_rar(hw, 0, hw->mac.perm_addr,
					    0, IXGBE_RAH_AV);
	}

	clear_bit(__IXGBEVF_DOWN, &adapter->state);
//	ixgbevf_napi_enable_all(adapter);

	/* enable transmits */
//	netif_tx_start_all_queues(netdev);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem */
	adapter->flags |= IXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies();

	timeout_add_usec(adapter->uld, 1, ixgbevf_watchdog, (void *)adapter);
	return 0;
}

int ixgbevf_up(struct ixgbevf_adapter *adapter)
{
	int err;
	struct ixgbe_hw *hw = &adapter->hw;

	ixgbevf_configure(adapter);

	err = ixgbevf_up_complete(adapter);

	/* clear any pending interrupts, may auto mask */
	IXGBE_READ_REG(hw, IXGBE_VTEICR);

	ixgbevf_irq_enable(adapter, true, true);

	return err;
}

/**
 * ixgbevf_clean_rx_ring - Free Rx Buffers per Queue
 * @adapter: board private structure
 * @rx_ring: ring to free buffers from
 **/
static void ixgbevf_clean_rx_ring(struct ixgbevf_adapter *adapter,
				  struct ixgbevf_ring *rx_ring)
{
	unsigned long size;
	unsigned int i;

	/* Free all the Rx ring sk_buffs */

	for (i = 0; i < rx_ring->count; i++) {
		struct ixgbevf_rx_buffer *rx_buffer_info;

		rx_buffer_info = &rx_ring->rx_buffer_info[i];
		if (rx_buffer_info->dma) {
			rx_buffer_info->dma = 0;
		}
		if (rx_buffer_info->skb) {
			struct sk_buff *skb = rx_buffer_info->skb;
			rx_buffer_info->skb = NULL;
			skb_free(skb);
		}
#ifdef notdef
		if (!rx_buffer_info->page)
			continue;
  		pci_unmap_page(pdev, rx_buffer_info->page_dma, PAGE_SIZE / 2,
  		               PCI_DMA_FROMDEVICE);
		rx_buffer_info->page_dma = 0;
		put_page(rx_buffer_info->page);
		rx_buffer_info->page = NULL;
		rx_buffer_info->page_offset = 0;
#endif
	}

	size = sizeof(struct ixgbevf_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	if (rx_ring->head)
		writel(0, adapter->hw.hw_addr + rx_ring->head);
	if (rx_ring->tail)
		writel(0, adapter->hw.hw_addr + rx_ring->tail);
}

/**
 * ixgbevf_clean_tx_ring - Free Tx Buffers
 * @adapter: board private structure
 * @tx_ring: ring to be cleaned
 **/
static void ixgbevf_clean_tx_ring(struct ixgbevf_adapter *adapter,
				  struct ixgbevf_ring *tx_ring)
{
	struct ixgbevf_tx_buffer *tx_buffer_info;
	unsigned long size;
	unsigned int i;

	/* Free all the Tx ring sk_buffs */

	for (i = 0; i < tx_ring->count; i++) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		ixgbevf_unmap_and_free_tx_resource(adapter, tx_buffer_info);
	}

	size = sizeof(struct ixgbevf_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_buffer_info, 0, size);

	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	if (tx_ring->head)
		writel(0, adapter->hw.hw_addr + tx_ring->head);
	if (tx_ring->tail)
		writel(0, adapter->hw.hw_addr + tx_ring->tail);
}

/**
 * ixgbevf_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbevf_clean_all_rx_rings(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbevf_clean_rx_ring(adapter, &adapter->rx_ring[i]);
}

/**
 * ixgbevf_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbevf_clean_all_tx_rings(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbevf_clean_tx_ring(adapter, &adapter->tx_ring[i]);
}

void ixgbevf_down(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 txdctl;
	int i, j;

	/* signal that we are down to the interrupt handler */
	set_bit(__IXGBEVF_DOWN, &adapter->state);
	/* disable receives */

//	netif_tx_disable(netdev);

	usleep(10000);

//	netif_tx_stop_all_queues(netdev);

	ixgbevf_irq_disable(adapter);

//	ixgbevf_napi_disable_all(adapter);

	timeout_cancel(adapter->uld, ixgbevf_watchdog, (void *)adapter);
	timeout_cancel(adapter->uld, ixgbevf_watchdog_task, (void *)adapter);
	/* can't call flush scheduled work here because it can deadlock
	 * if linkwatch_event tries to acquire the rtnl_lock which we are
	 * holding */
	while (adapter->flags & IXGBE_FLAG_IN_WATCHDOG_TASK)
		usleep(1000);

	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		j = adapter->tx_ring[i].reg_idx;
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(j));
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(j),
		                (txdctl & ~IXGBE_TXDCTL_ENABLE));
	}

//	netif_carrier_off(netdev);
	adapter->uld->linkup = 0;

#ifdef HAVE_PCI_ERS
	if (!pci_channel_offline(adapter->pdev))
#endif
		ixgbevf_reset(adapter);

	ixgbevf_clean_all_tx_rings(adapter);
	ixgbevf_clean_all_rx_rings(adapter);
}

void ixgbevf_reinit_locked(struct ixgbevf_adapter *adapter)
{
	set_bit(__IXGBEVF_RESETTING, &adapter->state);

fprintf(stderr, "%s: resetting\n", __func__);
	ixgbevf_down(adapter);
	ixgbevf_up(adapter);

	clear_bit(__IXGBEVF_RESETTING, &adapter->state);
}

void ixgbevf_reset(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	if (hw->mac.ops.reset_hw(hw))
		DPRINTK(PROBE, ERR, "PF still resetting\n");
	else
		hw->mac.ops.init_hw(hw);

	if (is_valid_ether_addr(adapter->hw.mac.addr)) {
		memcpy(adapter->uld->mac, adapter->hw.mac.addr, 6);
	}
}

static void ixgbevf_acquire_msix_vectors(struct ixgbevf_adapter *adapter,
                                       int vectors)
{
	int msix_fds[MIN_MSIX_COUNT+1];
	int i;

	/* We'll want at least 3 (vector_threshold):
	 * 1) TxQ[0] Cleanup
	 * 2) RxQ[0] Cleanup
	 * 3) Other (Link Status Change, etc.)
	 */
	adapter->num_msix_vectors = MIN_MSIX_COUNT;
	for (i = 0; i < MIN_MSIX_COUNT; i++) {
		adapter->msix[i].fd = eventfd(0, 0);
		adapter->msix[i].events = POLLIN;
		msix_fds[i+1] = adapter->msix[i].fd;
	}
	msix_fds[0] = MIN_MSIX_COUNT;
	if (ioctl(adapter->uld->fd, VFIO_EVENTFDS_MSIX, msix_fds) < 0)
		perror("VFIO_EVENTFDS_MSIX");
}

/*
 * ixgbe_set_num_queues: Allocate queues for device, feature dependant
 * @adapter: board private structure to initialize
 *
 * This is the top level queue allocation routine.  The order here is very
 * important, starting with the "most" number of features turned on at once,
 * and ending with the smallest set of features.  This way large combinations
 * can be allocated if they're turned on, and smaller combinations are the
 * fallthrough conditions.
 *
 **/
static void ixgbevf_set_num_queues(struct ixgbevf_adapter *adapter)
{
	/* Start with base case */
	adapter->num_rx_queues = 1;
	adapter->num_tx_queues = 1;
	adapter->num_rx_pools = adapter->num_rx_queues;
	adapter->num_rx_queues_per_pool = 1;
}

/**
 * ixgbevf_alloc_queues - Allocate memory for all rings
 * @adapter: board private structure to initialize
 *
 * We allocate one ring per queue at run-time since we don't know the
 * number of queues at compile-time.  The polling_netdev array is
 * intended for Multiqueue, but should work fine with a single queue.
 **/
static int ixgbevf_alloc_queues(struct ixgbevf_adapter *adapter)
{
	int i;

	adapter->tx_ring = calloc(adapter->num_tx_queues,
	                           sizeof(struct ixgbevf_ring));
	if (!adapter->tx_ring)
		goto err_tx_ring_allocation;

	adapter->rx_ring = calloc(adapter->num_rx_queues,
	                           sizeof(struct ixgbevf_ring));
	if (!adapter->rx_ring)
		goto err_rx_ring_allocation;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		adapter->tx_ring[i].count = adapter->tx_ring_count;
		adapter->tx_ring[i].queue_index = i;
		adapter->tx_ring[i].reg_idx = i;
	}

	for (i = 0; i < adapter->num_rx_queues; i++) {
		adapter->rx_ring[i].count = adapter->rx_ring_count;
		adapter->rx_ring[i].queue_index = i;
		adapter->rx_ring[i].reg_idx = i;
	}

	return 0;

err_rx_ring_allocation:
	free(adapter->tx_ring);
err_tx_ring_allocation:
	return -ENOMEM;
}

/**
 * ixgbevf_set_interrupt_capability - set MSI-X or FAIL if not supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 **/
static int ixgbevf_set_interrupt_capability(struct ixgbevf_adapter *adapter)
{
	ixgbevf_acquire_msix_vectors(adapter, 2 + NON_Q_VECTORS);
	return 0;
}

/**
 * ixgbevf_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int ixgbevf_alloc_q_vectors(struct ixgbevf_adapter *adapter)
{
	int q_idx, num_q_vectors;
	struct ixgbevf_q_vector *q_vector;
	int napi_vectors;
//	int (*poll)(struct napi_struct *, int);

	num_q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;
	napi_vectors = adapter->num_rx_queues;
//	poll = &ixgbevf_clean_rxonly;

	for (q_idx = 0; q_idx < num_q_vectors; q_idx++) {
		q_vector = kzalloc(sizeof(struct ixgbevf_q_vector), GFP_KERNEL);
		if (!q_vector)
			goto err_out;
		q_vector->adapter = adapter;
		q_vector->v_idx = q_idx;
		q_vector->eitr = adapter->eitr_param;
#ifdef notdef
		if (q_idx < napi_vectors)
			netif_napi_add(adapter->netdev, &q_vector->napi,
			               (*poll), 64);
#endif
		adapter->q_vector[q_idx] = q_vector;
	}

	return 0;

err_out:
	while (q_idx) {
		q_idx--;
		q_vector = adapter->q_vector[q_idx];
//		netif_napi_del(&q_vector->napi);
		kfree(q_vector);
		adapter->q_vector[q_idx] = NULL;
	}
	return -ENOMEM;
}

/**
 * ixgbevf_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void ixgbevf_free_q_vectors(struct ixgbevf_adapter *adapter)
{
	int q_idx, num_q_vectors;
	int napi_vectors;

	num_q_vectors = adapter->num_msix_vectors - NON_Q_VECTORS;
	napi_vectors = adapter->num_rx_queues;

	for (q_idx = 0; q_idx < num_q_vectors; q_idx++) {
		struct ixgbevf_q_vector *q_vector = adapter->q_vector[q_idx];

		adapter->q_vector[q_idx] = NULL;
//		if (q_idx < napi_vectors)
//			netif_napi_del(&q_vector->napi);
		kfree(q_vector);
	}
}

/**
 * ixgbevf_reset_interrupt_capability - Reset MSIX setup
 * @adapter: board private structure
 *
 **/
void ixgbevf_reset_interrupt_capability(struct ixgbevf_adapter *adapter)
{
//	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;

	return;
}

/**
 * ixgbevf_init_interrupt_scheme - Determine if MSIX is supported and init
 * @adapter: board private structure to initialize
 *
 **/
int ixgbevf_init_interrupt_scheme(struct ixgbevf_adapter *adapter)
{
	int err;

	/* Number of supported queues */
	ixgbevf_set_num_queues(adapter);

	err = ixgbevf_set_interrupt_capability(adapter);
	if (err) {
		DPRINTK(PROBE, ERR, "Unable to setup interrupt capabilities\n");
		goto err_set_interrupt;
	}

	err = ixgbevf_alloc_q_vectors(adapter);
	if (err) {
		DPRINTK(PROBE, ERR, "Unable to allocate memory for queue "
		        "vectors\n");
		goto err_alloc_q_vectors;
	}

	err = ixgbevf_alloc_queues(adapter);
	if (err) {
		DPRINTK(PROBE, ERR, "Unable to allocate memory for queues\n");
		goto err_alloc_queues;
	}

	DPRINTK(DRV, INFO, "Multiqueue %s: Rx Queue count = %u, "
	                   "Tx Queue count = %u\n",
	        (adapter->num_rx_queues > 1) ? "Enabled" :
	        "Disabled", adapter->num_rx_queues, adapter->num_tx_queues);

	set_bit(__IXGBEVF_DOWN, &adapter->state);

	return 0;
err_alloc_queues:
	ixgbevf_free_q_vectors(adapter);
err_alloc_q_vectors:
	ixgbevf_reset_interrupt_capability(adapter);
err_set_interrupt:
	return err;
}

/**
 * ixgbevf_sw_init - Initialize general software structures (struct ixgbevf_adapter)
 * @adapter: board private structure to initialize
 *
 * ixgbevf_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int ixgbevf_sw_init(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int err;

	/* PCI config space info */

	hw->vendor_id = pci_read_config_word(adapter->uld->fd, PCI_VENDOR_ID);
	hw->device_id = pci_read_config_word(adapter->uld->fd, PCI_DEVICE_ID);
	hw->revision_id = pci_read_config_byte(adapter->uld->fd, PCI_REVISION_ID);
	hw->subsystem_vendor_id = pci_read_config_word(adapter->uld->fd, PCI_SUBSYSTEM_VENDOR_ID);
	hw->subsystem_device_id = pci_read_config_word(adapter->uld->fd, PCI_SUBSYSTEM_ID);

	ixgbe_init_ops_vf(hw);
	hw->mbx.ops.init_params(hw);
	hw->mac.max_tx_queues = MAX_TX_QUEUES;
	hw->mac.max_rx_queues = MAX_RX_QUEUES;
	err = hw->mac.ops.reset_hw(hw);
	if (err) {
		DPRINTK(PROBE, INFO,
		         "PF still in reset state, assigning new address\n");
		random_ether_addr(hw->mac.addr);
	} else {
		err = hw->mac.ops.init_hw(hw);
		if (err) {
			DPRINTK(PROBE, ERR, "init_shared_code failed: %d\n", err);
			goto out;
		}
	}
	memcpy(adapter->uld->mac, hw->mac.addr, 6);


	/* set defaults for eitr in MegaBytes */
	adapter->eitr_low = 10;
	adapter->eitr_high = 20;

	/* set default ring sizes */
	adapter->tx_ring_count = IXGBEVF_DEFAULT_TXD;
	adapter->rx_ring_count = IXGBEVF_DEFAULT_RXD;

	/* enable rx csum by default */
	adapter->flags |= IXGBE_FLAG_RX_CSUM_ENABLED;

	set_bit(__IXGBEVF_DOWN, &adapter->state);

out:
	return err;
}

static void ixgbevf_init_last_counter_stats(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	adapter->stats.last_vfgprc = IXGBE_READ_REG(hw, IXGBE_VFGPRC);
	adapter->stats.last_vfgorc = IXGBE_READ_REG(hw, IXGBE_VFGORC_LSB);
	adapter->stats.last_vfgorc |=
		(((u64)(IXGBE_READ_REG(hw, IXGBE_VFGORC_MSB))) << 32);
	adapter->stats.last_vfgptc = IXGBE_READ_REG(hw, IXGBE_VFGPTC);
	adapter->stats.last_vfgotc = IXGBE_READ_REG(hw, IXGBE_VFGOTC_LSB);
	adapter->stats.last_vfgotc |=
		(((u64)(IXGBE_READ_REG(hw, IXGBE_VFGOTC_MSB))) << 32);
	adapter->stats.last_vfmprc = IXGBE_READ_REG(hw, IXGBE_VFMPRC);

	adapter->stats.base_vfgprc = adapter->stats.last_vfgprc;
	adapter->stats.base_vfgorc = adapter->stats.last_vfgorc;
	adapter->stats.base_vfgptc = adapter->stats.last_vfgptc;
	adapter->stats.base_vfgotc = adapter->stats.last_vfgotc;
	adapter->stats.base_vfmprc = adapter->stats.last_vfmprc;
}

#define UPDATE_VF_COUNTER_32bit(reg, last_counter, counter)	\
	{							\
		u32 current_counter = IXGBE_READ_REG(hw, reg);	\
		if (current_counter < last_counter)		\
			counter += 0x100000000LL;		\
		last_counter = current_counter;			\
		counter &= 0xFFFFFFFF00000000LL;		\
		counter |= current_counter;			\
	}

#define UPDATE_VF_COUNTER_36bit(reg_lsb, reg_msb, last_counter, counter) \
	{								 \
		u64 current_counter_lsb = IXGBE_READ_REG(hw, reg_lsb);	 \
		u64 current_counter_msb = IXGBE_READ_REG(hw, reg_msb);	 \
		u64 current_counter = (current_counter_msb << 32) |      \
			current_counter_lsb;                             \
		if (current_counter < last_counter)			 \
			counter += 0x1000000000LL;			 \
		last_counter = current_counter;				 \
		counter &= 0xFFFFFFF000000000LL;			 \
		counter |= current_counter;				 \
	}
/**
 * ixgbevf_update_stats - Update the board statistics counters.
 * @adapter: board private structure
 **/
void ixgbevf_update_stats(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	UPDATE_VF_COUNTER_32bit(IXGBE_VFGPRC, adapter->stats.last_vfgprc,
				adapter->stats.vfgprc);
	UPDATE_VF_COUNTER_32bit(IXGBE_VFGPTC, adapter->stats.last_vfgptc,
				adapter->stats.vfgptc);
	UPDATE_VF_COUNTER_36bit(IXGBE_VFGORC_LSB, IXGBE_VFGORC_MSB,
				adapter->stats.last_vfgorc,
				adapter->stats.vfgorc);
	UPDATE_VF_COUNTER_36bit(IXGBE_VFGOTC_LSB, IXGBE_VFGOTC_MSB,
				adapter->stats.last_vfgotc,
				adapter->stats.vfgotc);
	UPDATE_VF_COUNTER_32bit(IXGBE_VFMPRC, adapter->stats.last_vfmprc,
				adapter->stats.vfmprc);

	/* Fill out the OS statistics structure */
//	adapter->net_stats.multicast = adapter->stats.vfmprc - adapter->stats.base_vfmprc;
}

/**
 * ixgbevf_watchdog - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
static void ixgbevf_watchdog(void *data)
{
	struct ixgbevf_adapter *adapter = (struct ixgbevf_adapter *)data;
	struct ixgbe_hw *hw = &adapter->hw;
	u64 eics = 0;
	int i;

	/*
	 * Do the watchdog outside of interrupt context due to the lovely
	 * delays that some of the newer hardware requires
	 */

	if (test_bit(__IXGBEVF_DOWN, &adapter->state))
		goto watchdog_short_circuit;

	/* get one bit for every active tx/rx interrupt vector */
	for (i = 0; i < adapter->num_msix_vectors - NON_Q_VECTORS; i++) {
		struct ixgbevf_q_vector *qv = adapter->q_vector[i];
		if (qv->rxr_count || qv->txr_count)
			eics |= (1 << i);
	}

	IXGBE_WRITE_REG(hw, IXGBE_VTEICS, (u32)eics);

watchdog_short_circuit:
	timeout_add_usec(adapter->uld, 1, ixgbevf_watchdog_task, (void *)adapter);
}

static void ixgbevf_reset_task(struct ixgbevf_adapter *adapter)
{

	/* If we're already down or resetting, just bail */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state))
		return;

	adapter->tx_timeout_count++;

	ixgbevf_reinit_locked(adapter);
}

/**
 * ixgbevf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void ixgbevf_tx_timeout(struct ixgbevf_adapter *adapter)
{

	ixgbevf_reset_task(adapter);
}

/**
 * ixgbevf_watchdog_task - worker thread to bring link up
 * @work: pointer to work_struct containing our data
 **/
static void ixgbevf_watchdog_task(void *arg)
{
	struct ixgbevf_adapter *adapter = arg;
	struct uld *uld = adapter->uld;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;

	adapter->flags |= IXGBE_FLAG_IN_WATCHDOG_TASK;

	if (hw->mac.ops.check_link) {
		if ((hw->mac.ops.check_link(hw, &link_speed,
					    &link_up, false)) != 0) {
			adapter->link_up = link_up;
			adapter->link_speed = link_speed;
			ixgbevf_reset_task(adapter);
			goto pf_has_reset;
		}
	} else {
		/*
		 * always assume link is up, if no check link
		 * function
		 */
		link_speed = IXGBE_LINK_SPEED_10GB_FULL;
		link_up = true;
	}
	adapter->link_up = link_up;
	adapter->link_speed = link_speed;

	if (link_up) {
		if (!uld->linkup) {
			DPRINTK(LINK, INFO, "NIC Link is Up %s, ",
			        ((link_speed == IXGBE_LINK_SPEED_10GB_FULL) ?
			         "10 Gbps" : "1 Gbps"));
			uld->linkup = 1;
		} else {
			/* Force detection of hung controller */
			adapter->detect_tx_hung = true;
		}
	} else {
		adapter->link_up = false;
		adapter->link_speed = 0;
		if (uld->linkup) {
			uld->linkup = 0;
			DPRINTK(LINK, INFO, "NIC Link is Down\n");
		}
	}

pf_has_reset:
	ixgbevf_update_stats(adapter);

	/* Force detection of hung controller every watchdog period */
	adapter->detect_tx_hung = true;

	/* Reset the timer */
	if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
		timeout_add_usec(uld, 2000000, ixgbevf_watchdog_task, (void *)adapter);

	adapter->flags &= ~IXGBE_FLAG_IN_WATCHDOG_TASK;
}

/**
 * ixgbevf_free_tx_resources - Free Tx Resources per Queue
 * @adapter: board private structure
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void ixgbevf_free_tx_resources(struct ixgbevf_adapter *adapter,
			       struct ixgbevf_ring *tx_ring)
{

	ixgbevf_clean_tx_ring(adapter, tx_ring);

	free(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

//	pci_free_consistent(pdev, tx_ring->size, tx_ring->desc, tx_ring->dma);

	tx_ring->desc = NULL;
}

/**
 * ixgbevf_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
static void ixgbevf_free_all_tx_resources(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		if (adapter->tx_ring[i].desc)
			ixgbevf_free_tx_resources(adapter,
						  &adapter->tx_ring[i]);

}

/**
 * ixgbevf_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: board private structure
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int ixgbevf_setup_tx_resources(struct ixgbevf_adapter *adapter,
                             struct ixgbevf_ring *tx_ring)
{
	struct uld *uld = adapter->uld;
	int size;

	size = sizeof(struct ixgbevf_tx_buffer) * tx_ring->count;
	tx_ring->tx_buffer_info = malloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;
	memset(tx_ring->tx_buffer_info, 0, size);

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	tx_ring->desc = uld_alloc_map_lock(uld, tx_ring->size,
	                                     &tx_ring->dma);
	if (!tx_ring->desc)
		goto err;

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->work_limit = tx_ring->count;
	return 0;

err:
	free(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	DPRINTK(PROBE, ERR, "Unable to allocate memory for the transmit "
	                    "descriptor ring\n");
	return -ENOMEM;
}

/**
 * ixgbevf_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbevf_setup_all_tx_resources(struct ixgbevf_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = ixgbevf_setup_tx_resources(adapter, &adapter->tx_ring[i]);
		if (!err)
			continue;
		DPRINTK(PROBE, ERR, "Allocation for Tx Queue %u failed\n", i);
		break;
	}

	return err;
}

/**
 * ixgbevf_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int ixgbevf_setup_rx_resources(struct ixgbevf_adapter *adapter,
                             struct ixgbevf_ring *rx_ring)
{
	struct uld *uld = adapter->uld;

	rx_ring->rx_buffer_info = calloc(sizeof(struct ixgbevf_rx_buffer), rx_ring->count);
	if (!rx_ring->rx_buffer_info) {
		DPRINTK(PROBE, ERR,
		        "Unable to malloc buffer memory for "
		        "the receive descriptor ring\n");
		goto alloc_failed;
	}

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	rx_ring->desc = uld_alloc_map_lock(uld, rx_ring->size, &rx_ring->dma);

	if (!rx_ring->desc) {
		DPRINTK(PROBE, ERR,
		        "Unable to allocate memory for "
		        "the receive descriptor ring\n");
		free(rx_ring->rx_buffer_info);
		rx_ring->rx_buffer_info = NULL;
		goto alloc_failed;
	}

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	return 0;
alloc_failed:
	return -ENOMEM;
}

/**
 * ixgbevf_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbevf_setup_all_rx_resources(struct ixgbevf_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = ixgbevf_setup_rx_resources(adapter, &adapter->rx_ring[i]);
		if (!err)
			continue;
		DPRINTK(PROBE, ERR, "Allocation for Rx Queue %u failed\n", i);
		break;
	}
	return err;
}

/**
 * ixgbevf_free_rx_resources - Free Rx Resources
 * @adapter: board private structure
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void ixgbevf_free_rx_resources(struct ixgbevf_adapter *adapter,
			       struct ixgbevf_ring *rx_ring)
{

	ixgbevf_clean_rx_ring(adapter, rx_ring);

	free(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

//	pci_free_consistent(pdev, rx_ring->size, rx_ring->desc, rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * ixgbevf_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
static void ixgbevf_free_all_rx_resources(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		if (adapter->rx_ring[i].desc)
			ixgbevf_free_rx_resources(adapter,
						  &adapter->rx_ring[i]);
}

/**
 * ixgbevf_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/
static int ixgbevf_open(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int err;

	/* disallow open during test */
	if (test_bit(__IXGBEVF_TESTING, &adapter->state))
		return -EBUSY;

	if (hw->adapter_stopped) {
		ixgbevf_reset(adapter);
		/* if adapter is still stopped then PF isn't up and
		 * the vf can't start. */
		if (hw->adapter_stopped) {
			err = IXGBE_ERR_MBX;
			DPRINTK(DRV, ERR, "Unable to start - perhaps the PF"
				"Driver isn't up yet\n");
			goto err_setup_reset;
		}
	}

	/* allocate transmit descriptors */
	err = ixgbevf_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = ixgbevf_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	ixgbevf_configure(adapter);

	/*
	 * Map the Tx/Rx rings to the vectors we were allotted.
	 * if request_irq will be called in this function map_rings
	 * must be called *before* up_complete
	 */
	ixgbevf_map_rings_to_vectors(adapter);

	err = ixgbevf_up_complete(adapter);
	if (err)
		goto err_up;

	/* clear any pending interrupts, may auto mask */
	IXGBE_READ_REG(hw, IXGBE_VTEICR);
	err = ixgbevf_request_irq(adapter);
	if (err)
		goto err_req_irq;

	ixgbevf_irq_enable(adapter, true, true);

	return 0;

err_req_irq:
	ixgbevf_down(adapter);
err_up:
	ixgbevf_free_irq(adapter);
err_setup_rx:
	ixgbevf_free_all_rx_resources(adapter);
err_setup_tx:
	ixgbevf_free_all_tx_resources(adapter);
	ixgbevf_reset(adapter);

err_setup_reset:

	return err;
}

/**
 * ixgbevf_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static int ixgbevf_close(struct ixgbevf_adapter *adapter)
{

	ixgbevf_down(adapter);
	ixgbevf_free_irq(adapter);

	ixgbevf_free_all_tx_resources(adapter);
	ixgbevf_free_all_rx_resources(adapter);

	return 0;
}

#ifdef XXX_NO_TSO
static int ixgbevf_tso(struct ixgbevf_adapter *adapter,
		       struct ixgbevf_ring *tx_ring,
		       struct sk_buff *skb, u32 tx_flags, u8 *hdr_len)
{
#ifdef NETIF_F_TSO
	struct ixgbe_adv_tx_context_desc *context_desc;
	unsigned int i;
	int err;
	struct ixgbevf_tx_buffer *tx_buffer_info;
	u32 vlan_macip_lens = 0, type_tucmd_mlhl;
	u32 mss_l4len_idx, l4len;

	if (skb_is_gso(skb)) {
		if (skb_header_cloned(skb)) {
			err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
			if (err)
				return err;
		}
		l4len = tcp_hdrlen(skb);
		*hdr_len += l4len;

		if (skb->protocol == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);
			iph->tot_len = 0;
			iph->check = 0;
			tcp_hdr(skb)->check = ~csum_tcpudp_magic(iph->saddr,
			                                         iph->daddr, 0,
			                                         IPPROTO_TCP,
			                                         0);
			adapter->hw_tso_ctxt++;
#ifdef NETIF_F_TSO6
		} else if (skb_shinfo(skb)->gso_type == SKB_GSO_TCPV6) {
			ipv6_hdr(skb)->payload_len = 0;
			tcp_hdr(skb)->check =
			    ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
			                     &ipv6_hdr(skb)->daddr,
			                     0, IPPROTO_TCP, 0);
			adapter->hw_tso6_ctxt++;
#endif
		}

		i = tx_ring->next_to_use;

		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		context_desc = IXGBE_TX_CTXTDESC_ADV(*tx_ring, i);

		/* VLAN MACLEN IPLEN */
		if (tx_flags & IXGBE_TX_FLAGS_VLAN)
			vlan_macip_lens |=
			                  (tx_flags & IXGBE_TX_FLAGS_VLAN_MASK);
		vlan_macip_lens |= ((skb_network_offset(skb)) <<
		                    IXGBE_ADVTXD_MACLEN_SHIFT);
		*hdr_len += skb_network_offset(skb);
		vlan_macip_lens |=
		          (skb_transport_header(skb) - skb_network_header(skb));
		*hdr_len +=
		          (skb_transport_header(skb) - skb_network_header(skb));
		context_desc->vlan_macip_lens = cpu_to_le32(vlan_macip_lens);
		context_desc->seqnum_seed = 0;

		/* ADV DTYP TUCMD MKRLOC/ISCSIHEDLEN */
		type_tucmd_mlhl = (IXGBE_TXD_CMD_DEXT |
				    IXGBE_ADVTXD_DTYP_CTXT);

		if (skb->protocol == htons(ETH_P_IP))
			type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_IPV4;
		type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
		context_desc->type_tucmd_mlhl = cpu_to_le32(type_tucmd_mlhl);

		/* MSS L4LEN IDX */
		mss_l4len_idx =
		          (skb_shinfo(skb)->gso_size << IXGBE_ADVTXD_MSS_SHIFT);
		mss_l4len_idx |= (l4len << IXGBE_ADVTXD_L4LEN_SHIFT);
		/* use index 1 for TSO */
		mss_l4len_idx |= (1 << IXGBE_ADVTXD_IDX_SHIFT);
		context_desc->mss_l4len_idx = cpu_to_le32(mss_l4len_idx);

		tx_buffer_info->time_stamp = jiffies;
		tx_buffer_info->next_to_watch = i;

		i++;
		if (i == tx_ring->count)
			i = 0;
		tx_ring->next_to_use = i;

		return true;
	}

#endif
	return false;
}
#endif // XXX_NO_TSO

static bool ixgbevf_tx_csum(struct ixgbevf_adapter *adapter,
			    struct ixgbevf_ring *tx_ring,
			    struct sk_buff *skb, u32 tx_flags)
{
	struct ixgbe_adv_tx_context_desc *context_desc;
	unsigned int i;
	struct ixgbevf_tx_buffer *tx_buffer_info;
	u32 vlan_macip_lens = 0, type_tucmd_mlhl = 0;

	if (skb->ip_summed == CHECKSUM_PARTIAL ||
	    (tx_flags & IXGBE_TX_FLAGS_VLAN)) {
		i = tx_ring->next_to_use;
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		context_desc = IXGBE_TX_CTXTDESC_ADV(*tx_ring, i);

		if (tx_flags & IXGBE_TX_FLAGS_VLAN)
			vlan_macip_lens |= (tx_flags &
			                    IXGBE_TX_FLAGS_VLAN_MASK);
		vlan_macip_lens |= (skb_network_offset(skb) <<
		                    IXGBE_ADVTXD_MACLEN_SHIFT);
		if (skb->ip_summed == CHECKSUM_PARTIAL)
			vlan_macip_lens |= (skb_transport_header(skb) -
			                    skb_network_header(skb));

		context_desc->vlan_macip_lens = cpu_to_le32(vlan_macip_lens);
		context_desc->seqnum_seed = 0;

		type_tucmd_mlhl |= (IXGBE_TXD_CMD_DEXT |
		                    IXGBE_ADVTXD_DTYP_CTXT);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			switch (skb_ether_protocol(skb)) {
			case ETH_P_IP:
				type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_IPV4;
				if (skb_ip_protocol(skb) == IPPROTO_TCP)
					type_tucmd_mlhl |=
					    IXGBE_ADVTXD_TUCMD_L4T_TCP;
				break;
#ifdef NETIF_F_IPV6_CSUM
			case ETH_P_IPV6:
				/* XXX what about other V6 headers?? */
				if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
					type_tucmd_mlhl |=
					         IXGBE_ADVTXD_TUCMD_L4T_TCP;
				break;
#endif
			default:
				DPRINTK(PROBE, WARNING,
					 "partial checksum but proto not ip!\n");
				break;
			}
		}

		context_desc->type_tucmd_mlhl = cpu_to_le32(type_tucmd_mlhl);
		/* use index zero for tx checksum offload */
		context_desc->mss_l4len_idx = 0;

		tx_buffer_info->time_stamp = jiffies();
		tx_buffer_info->next_to_watch = i;

		adapter->hw_csum_tx_good++;
		i++;
		if (i == tx_ring->count)
			i = 0;
		tx_ring->next_to_use = i;

		return true;
	}

	return false;
}

static int ixgbevf_tx_map(struct ixgbevf_adapter *adapter,
			  struct ixgbevf_ring *tx_ring,
			  struct sk_buff *skb, u32 tx_flags,
			  unsigned int first)
{
	struct ixgbevf_tx_buffer *tx_buffer_info;
	unsigned int len;
	unsigned int total = skb->len;
	unsigned int offset = 0, size, count = 0, i;
#ifdef MAX_SKB_FRAGS
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	unsigned int f;
#endif

	i = tx_ring->next_to_use;

	len = total;
	while (len) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		size = min(len, (unsigned int)IXGBE_MAX_DATA_PER_TXD);

		tx_buffer_info->length = size;
		tx_buffer_info->dma = skb->dma_addr + (offset + skb->data - skb->buf);
		tx_buffer_info->time_stamp = jiffies();
		tx_buffer_info->next_to_watch = i;

		len -= size;
		total -= size;
		offset += size;
		count++;
		i++;
		if (i == tx_ring->count)
			i = 0;
	}

#ifdef XXX_MAX_SKB_FRAGS
	for (f = 0; f < nr_frags; f++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = min((unsigned int)frag->size, total);
		offset = frag->page_offset;

		while (len) {
			tx_buffer_info = &tx_ring->tx_buffer_info[i];
			size = min(len, (unsigned int)IXGBE_MAX_DATA_PER_TXD);

			tx_buffer_info->length = size;
			tx_buffer_info->dma = pci_map_page(adapter->pdev,
			                                   frag->page,
			                                   offset,
			                                   size,
			                                   PCI_DMA_TODEVICE);
			tx_buffer_info->time_stamp = jiffies;
			tx_buffer_info->next_to_watch = i;

			len -= size;
			total -= size;
			offset += size;
			count++;
			i++;
			if (i == tx_ring->count)
				i = 0;
		}
		if (total == 0)
			break;
	}
#endif
	if (i == 0)
		i = tx_ring->count - 1;
	else
		i = i - 1;
	tx_ring->tx_buffer_info[i].skb = skb;
	tx_ring->tx_buffer_info[first].next_to_watch = i;

	return count;
}

static void ixgbevf_tx_queue(struct ixgbevf_adapter *adapter,
			     struct ixgbevf_ring *tx_ring, int tx_flags,
			     int count, u32 paylen, u8 hdr_len)
{
	union ixgbe_adv_tx_desc *tx_desc = NULL;
	struct ixgbevf_tx_buffer *tx_buffer_info;
	u32 olinfo_status = 0, cmd_type_len = 0;
	unsigned int i;

	u32 txd_cmd = IXGBE_TXD_CMD_EOP | IXGBE_TXD_CMD_RS | IXGBE_TXD_CMD_IFCS;

	cmd_type_len |= IXGBE_ADVTXD_DTYP_DATA;

	cmd_type_len |= IXGBE_ADVTXD_DCMD_IFCS | IXGBE_ADVTXD_DCMD_DEXT;

	if (tx_flags & IXGBE_TX_FLAGS_VLAN)
		cmd_type_len |= IXGBE_ADVTXD_DCMD_VLE;

	if (tx_flags & IXGBE_TX_FLAGS_TSO) {
		cmd_type_len |= IXGBE_ADVTXD_DCMD_TSE;

		olinfo_status |= IXGBE_TXD_POPTS_TXSM <<
		                 IXGBE_ADVTXD_POPTS_SHIFT;

		/* use index 1 context for tso */
		olinfo_status |= (1 << IXGBE_ADVTXD_IDX_SHIFT);
		if (tx_flags & IXGBE_TX_FLAGS_IPV4)
			olinfo_status |= IXGBE_TXD_POPTS_IXSM <<
			                 IXGBE_ADVTXD_POPTS_SHIFT;

	} else if (tx_flags & IXGBE_TX_FLAGS_CSUM)
		olinfo_status |= IXGBE_TXD_POPTS_TXSM <<
		                 IXGBE_ADVTXD_POPTS_SHIFT;

	olinfo_status |= ((paylen - hdr_len) << IXGBE_ADVTXD_PAYLEN_SHIFT);

	i = tx_ring->next_to_use;
	while (count--) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		tx_desc = IXGBE_TX_DESC_ADV(*tx_ring, i);
		tx_desc->read.buffer_addr = cpu_to_le64(tx_buffer_info->dma);
		tx_desc->read.cmd_type_len =
			cpu_to_le32(cmd_type_len | tx_buffer_info->length);
		tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
		i++;
		if (i == tx_ring->count)
			i = 0;
	}

	tx_desc->read.cmd_type_len |= cpu_to_le32(txd_cmd);

	/*
	 * Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();

	tx_ring->next_to_use = i;
	writel(i, adapter->hw.hw_addr + tx_ring->tail);
}

static int __ixgbevf_maybe_stop_tx(struct ixgbevf_adapter *adapter,
				   struct ixgbevf_ring *tx_ring, int size)
{
#ifdef notdef
	netif_stop_subqueue(netdev, tx_ring->queue_index);
	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it. */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available. */
	if (likely(IXGBE_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(netdev, tx_ring->queue_index);
	++adapter->restart_queue;
	return 0;
#else
	return -EBUSY;
#endif
}

static int ixgbevf_maybe_stop_tx(struct ixgbevf_adapter *adapter,
				 struct ixgbevf_ring *tx_ring, int size)
{
	if (likely(IXGBE_DESC_UNUSED(tx_ring) >= size))
		return 0;
	return __ixgbevf_maybe_stop_tx(adapter, tx_ring, size);
}

int ixvf_skb_write(struct uld *uld, struct sk_buff *skb)
{
	struct ixgbevf_adapter *adapter = uld->nicpriv;
	struct ixgbevf_ring *tx_ring;
	unsigned int first;
	unsigned int tx_flags = 0;
	u8 hdr_len = 0;
	int r_idx = 0;
	int count = 0;

#ifdef MAX_SKB_FRAGS
	unsigned int f;
#endif

#ifdef HAVE_TX_MQ
	r_idx = skb->queue_mapping;
#endif
	tx_ring = &adapter->tx_ring[r_idx];

#ifdef NETIF_F_HW_VLAN_TX
	if (adapter->vlgrp && vlan_tx_tag_present(skb)) {
		tx_flags |= vlan_tx_tag_get(skb);
		tx_flags <<= IXGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= IXGBE_TX_FLAGS_VLAN;
	}
#endif

	/* four things can cause us to need a context descriptor */
	if ( (skb->ip_summed == CHECKSUM_PARTIAL) ||
	    (tx_flags & IXGBE_TX_FLAGS_VLAN))
		count++;

	count += TXD_USE_COUNT(skb->len);
#ifdef MAX_SKB_FRAGS
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_shinfo(skb)->frags[f].size);

#endif
	if (ixgbevf_maybe_stop_tx(adapter, tx_ring, count)) {
		adapter->tx_busy++;
		return -EBUSY;
	}

	first = tx_ring->next_to_use;

	if (skb_ether_protocol(skb) == ETH_P_IP)
		tx_flags |= IXGBE_TX_FLAGS_IPV4;
#ifdef notdef
	tso = ixgbevf_tso(adapter, tx_ring, skb, tx_flags, &hdr_len);
	if (tso < 0) {
		skb_free(skb);
		return NETDEV_TX_OK;
	}

	if (tso)
		tx_flags |= IXGBE_TX_FLAGS_TSO;
	else
#endif
	if (ixgbevf_tx_csum(adapter, tx_ring, skb, tx_flags) &&
		 (skb->ip_summed == CHECKSUM_PARTIAL))
		tx_flags |= IXGBE_TX_FLAGS_CSUM;

	ixgbevf_tx_queue(adapter, tx_ring, tx_flags,
			 ixgbevf_tx_map(adapter, tx_ring, skb, tx_flags, first),
			 skb->len, hdr_len);

	ixgbevf_maybe_stop_tx(adapter, tx_ring, DESC_NEEDED);

	return 0;
}

#ifdef notdef
/**
 * ixgbevf_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the timer callback.
 **/
static struct net_device_stats *ixgbevf_get_stats(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);

	/* only return the current stats */
	return &adapter->net_stats;
}
#endif

#ifdef notdef
/**
 * ixgbevf_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbevf_set_mac(struct net_device *netdev, void *p)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);

	if (hw->mac.ops.set_rar)
		hw->mac.ops.set_rar(hw, 0, hw->mac.addr, 0, IXGBE_RAH_AV);

	return 0;
}

/**
 * ixgbevf_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbevf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	/* MTU < 68 is an error and causes problems on some kernels */
	if ((new_mtu < 68) || (max_frame > MAXIMUM_ETHERNET_VLAN_SIZE))
		return -EINVAL;

	DPRINTK(PROBE, INFO, "changing MTU from %d to %d\n",
	        netdev->mtu, new_mtu);
	/* must set new MTU before calling down or up */
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		ixgbevf_reinit_locked(adapter);

	return 0;
}
#endif

#ifdef ETHTOOL_OPS_COMPAT
/**
 * ixgbevf_ioctl -
 * @netdev:
 * @ifreq:
 * @cmd:
 **/
static int ixgbevf_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCETHTOOL:
		return ethtool_ioctl(ifr);
	default:
		return -EOPNOTSUPP;
	}
}

#endif

#ifdef notdef
static void ixgbevf_shutdown(struct ixgbevf_adapter *adapter)
{

	ixgbevf_down(adapter);
	ixgbevf_free_irq(adapter);
	ixgbevf_free_all_tx_resources(adapter);
	ixgbevf_free_all_rx_resources(adapter);

}

#endif

/**
 * ixgbevf_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ixgbevf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ixgbevf_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int ixgbevf_probe(struct uld *uld)
{
	struct ixgbevf_adapter *adapter = NULL;
	struct ixgbe_hw *hw = NULL;
	static int cards_found;
	int err;

	pci_set_master(uld->fd);

	adapter = calloc(1, sizeof(struct ixgbevf_adapter));

	adapter->uld = uld;
	uld->nicpriv = adapter;
	hw = &adapter->hw;
	hw->back = adapter;
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

#ifdef HAVE_PCI_ERS
	/*
	 * call save state here in standalone driver because it relies on
	 * adapter struct to exist, and needs to call netdev_priv
	 */
	pci_save_state(pdev);

#endif
	hw->hw_addr = pci_mmap_bar(uld->fd, 0, 1);
	if (!hw->hw_addr) {
		err = -EIO;
		goto err_ioremap;
	}

	adapter->bd_number = cards_found++;

	/* setup the private structure */
	err = ixgbevf_sw_init(adapter);

	ixgbevf_init_last_counter_stats(adapter);

	adapter->eitr_param = IXGBE_MAX_INT_RATE;
	adapter->itr_setting = 0;

	err = ixgbevf_init_interrupt_scheme(adapter);
	if (err)
		goto err_sw_init;

	/* pick up the PCI bus settings for reporting later */
	if (hw->mac.ops.get_bus_info)
		hw->mac.ops.get_bus_info(hw);

	return 0;

err_sw_init:
	ixgbevf_reset_interrupt_capability(adapter);
  	pci_munmap_bar(uld->fd, 0, (void *)adapter->hw.hw_addr);
err_ioremap:
	free(adapter);
	uld->nicpriv = NULL;
	return err;
}

/**
 * ixgbevf_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ixgbevf_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void ixgbevf_remove(struct uld *uld)
{
	struct ixgbevf_adapter *adapter = uld->nicpriv;

	set_bit(__IXGBEVF_DOWN, &adapter->state);

	timeout_cancel(uld, ixgbevf_watchdog, (void *)adapter);
	timeout_cancel(uld, ixgbevf_watchdog_task, (void *)adapter);

	ixgbevf_reset_interrupt_capability(adapter);

  	pci_munmap_bar(uld->fd, 0, (void *)adapter->hw.hw_addr);


	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);

}

void *ixvf_uld_open(struct uld *uld)
{
	if (ixgbevf_probe(uld))
		return NULL;
	if (ixgbevf_open((struct ixgbevf_adapter *)uld->nicpriv))
		return NULL;
	return uld->nicpriv;
}

void ixvf_uld_close(struct uld *uld)
{
	ixgbevf_close((struct ixgbevf_adapter *)uld->nicpriv);
	ixgbevf_remove(uld);
}


struct sk_buff *ixvf_skb_read(struct uld *uld, int sync)
{
	struct ixgbevf_adapter *adapter = uld->nicpriv;
	struct sk_buff *skb = NULL;
	unsigned long long count;
	int n;

	if (uld->threaded) {
		if (sync)
			pthread_mutex_lock(&adapter->skb_read_lock);
		else if (pthread_mutex_trylock(&adapter->skb_read_lock))
			return NULL;
	}
top:
	if (adapter->skb_recv_head) {
		skb = adapter->skb_recv_head;
		adapter->skb_recv_head = skb->next;
		skb->next = NULL;
		goto out;
	}
	(void) ixgbevf_clean_rxonly(adapter->q_vector[0], 50);
	if (adapter->skb_recv_head)
		goto top;

	n = poll(adapter->msix, 3, sync ? -1 : 0);
	if (n < 0)
		perror("ixvf_skb_read poll");
	if (n > 0) {
		if (adapter->msix[IXVF_MSIX_MBX].revents & POLLIN) {
			(void) read(adapter->msix[IXVF_MSIX_MBX].fd, &count, sizeof count);
			ixgbevf_msix_mbx(adapter);
		}
		if (adapter->msix[IXVF_MSIX_WQ].revents & POLLIN) {
			(void) read(adapter->msix[IXVF_MSIX_WQ].fd, &count, sizeof count);
			ixgbevf_msix_clean_tx(adapter->q_vector[1]);
		}
		if (adapter->msix[IXVF_MSIX_RQ].revents & POLLIN) {
			(void) read(adapter->msix[IXVF_MSIX_RQ].fd, &count, sizeof count);
			ixgbevf_msix_clean_rx(adapter->q_vector[0]);
		}
		goto top;
	}
out:
	if (uld->threaded)
		pthread_mutex_unlock(&adapter->skb_read_lock);
	return skb;
}
