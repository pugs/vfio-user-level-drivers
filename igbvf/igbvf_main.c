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

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 2009 Intel Corporation.

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/pci_regs.h>
#include <sys/eventfd.h>

#include "../uld/kcompat.h"
#include "../uld/uld.h"
#include "../uld/skbuff.h"

#include "../vfio/vfio_lib.h"
#include "igbvf.h"

#define IGBVF_MSIX_WQ		0
#define IGBVF_MSIX_RQ		1
#define IGBVF_MSIX_OTHER	2

#define DRV_VERSION "1.0.0-k0"
char igbvf_driver_name[] = "igbvf";
const char igbvf_driver_version[] = DRV_VERSION;
static const char igbvf_driver_string[] =
				"Intel(R) Virtual Function Network Driver";
static const char igbvf_copyright[] = "Copyright (c) 2009 Intel Corporation.";

// static int igbvf_poll(struct igbvf_ring *, int budget);
static void igbvf_reset(struct igbvf_adapter *);
static void igbvf_set_interrupt_capability(struct igbvf_adapter *);
static void igbvf_reset_interrupt_capability(struct igbvf_adapter *);
static void igbvf_watchdog(void *);
static void igbvf_reset_task(struct igbvf_adapter *adapter);

static struct igbvf_info igbvf_vf_info = {
	.mac                    = e1000_vfadapt,
	.flags                  = 0,
	.pba                    = 10,
	.init_ops               = e1000_init_function_pointers_vf,
};

static const struct igbvf_info *igbvf_info_tbl[] = {
	[board_vf]              = &igbvf_vf_info,
};

/**
 * igbvf_desc_unused - calculate if we have unused descriptors
 **/
static int igbvf_desc_unused(struct igbvf_ring *ring)
{
	if (ring->next_to_clean > ring->next_to_use)
		return ring->next_to_clean - ring->next_to_use - 1;

	return ring->count + ring->next_to_clean - ring->next_to_use - 1;
}

/**
 * igbvf_receive_skb - helper function to handle Rx indications
 * @adapter: board private structure
 * @status: descriptor status field as written by hardware
 * @vlan: descriptor vlan field as written by hardware (no le/be conversion)
 * @skb: pointer to sk_buff to be indicated to stack
 **/
static void igbvf_receive_skb(struct igbvf_adapter *adapter,
                              struct sk_buff *skb,
                              u32 status, u16 vlan)
{
#ifdef notdef
	if (adapter->vlgrp && (status & E1000_RXD_STAT_VP))
		vlan_hwaccel_receive_skb(skb, adapter->vlgrp,
		                         le16_to_cpu(vlan) &
		                         E1000_RXD_SPC_VLAN_MASK);
	else
#endif
	if (adapter->skb_recv_head) {
		adapter->skb_recv_tail->next = skb;
		adapter->skb_recv_tail = skb;
	} else {
		adapter->skb_recv_head = skb;
		adapter->skb_recv_tail = skb;
	}
}

static inline void igbvf_rx_checksum_adv(struct igbvf_adapter *adapter,
                                         u32 status_err, struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* Ignore Checksum bit is set or checksum is disabled through ethtool */
	if ((status_err & E1000_RXD_STAT_IXSM) ||
	    (adapter->flags & IGBVF_FLAG_RX_CSUM_DISABLED))
		return;

	/* TCP/UDP checksum error bit is set */
	if (status_err &
	    (E1000_RXDEXT_STATERR_TCPE | E1000_RXDEXT_STATERR_IPE)) {
		/* let the stack verify checksum errors */
		adapter->hw_csum_err++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	if (status_err & (E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	adapter->hw_csum_good++;
}

/**
 * igbvf_alloc_rx_buffers - Replace used receive buffers; packet split
 * @rx_ring: address of ring structure to repopulate
 * @cleaned_count: number of buffers to repopulate
 **/
static void igbvf_alloc_rx_buffers(struct igbvf_ring *rx_ring,
                                   int cleaned_count)
{
	struct igbvf_adapter *adapter = rx_ring->adapter;
	union e1000_adv_rx_desc *rx_desc;
	struct igbvf_buffer *buffer_info;
	struct sk_buff *skb;
	unsigned int i;
	int bufsz;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	if (adapter->rx_ps_hdr_size)
		bufsz = adapter->rx_ps_hdr_size;
	else
		bufsz = adapter->rx_buffer_len;

	while (cleaned_count--) {
		rx_desc = IGBVF_RX_DESC_ADV(*rx_ring, i);

#ifdef notdef
		if (adapter->rx_ps_hdr_size && !buffer_info->page_dma) {
			if (!buffer_info->page) {
				buffer_info->page = alloc_page(GFP_ATOMIC);
				if (!buffer_info->page) {
					adapter->alloc_rx_buff_failed++;
					goto no_buffers;
				}
				buffer_info->page_offset = 0;
			} else {
				buffer_info->page_offset ^= PAGE_SIZE / 2;
			}
			buffer_info->page_dma =
				pci_map_page(pdev, buffer_info->page,
				             buffer_info->page_offset,
				             PAGE_SIZE / 2,
				             PCI_DMA_FROMDEVICE);
		}
#endif

		if (!buffer_info->skb) {
			skb = skb_alloc(adapter->uld);
			if (!skb) {
				adapter->alloc_rx_buff_failed++;
				goto no_buffers;
			}
			skb_pull(skb, NET_IP_ALIGN);

			buffer_info->skb = skb;
			buffer_info->dma = skb->dma_addr + (skb->data - skb->buf);
		}
		/* Refresh the desc even if buffer_addrs didn't change because
		 * each write-back erases this info. */
		if (adapter->rx_ps_hdr_size) {
			rx_desc->read.pkt_addr =
			     cpu_to_le64(buffer_info->page_dma);
			rx_desc->read.hdr_addr = cpu_to_le64(buffer_info->dma);
		} else {
			rx_desc->read.pkt_addr =
			     cpu_to_le64(buffer_info->dma);
			rx_desc->read.hdr_addr = 0;
		}

		i++;
		if (i == rx_ring->count)
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

no_buffers:
	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;
		if (i == 0)
			i = (rx_ring->count - 1);
		else
			i--;

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64). */
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->tail);
	}
}

/**
 * igbvf_clean_rx_irq - Send received data up the network stack; legacy
 * @adapter: board private structure
 *
 * the return value indicates whether actual cleaning was done, there
 * is no guarantee that everything was cleaned
 **/
static bool igbvf_clean_rx_irq(struct igbvf_adapter *adapter,
                               int *work_done, int work_to_do)
{
	struct igbvf_ring *rx_ring = adapter->rx_ring;
	union e1000_adv_rx_desc *rx_desc, *next_rxd;
	struct igbvf_buffer *buffer_info, *next_buffer;
	struct sk_buff *skb;
	bool cleaned = false;
	int cleaned_count = 0;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int i;
	u32 length, hlen, staterr;

	i = rx_ring->next_to_clean;
	rx_desc = IGBVF_RX_DESC_ADV(*rx_ring, i);
	staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

	while (staterr & E1000_RXD_STAT_DD) {
		if (*work_done >= work_to_do)
			break;
		(*work_done)++;

		buffer_info = &rx_ring->buffer_info[i];

		/* HW will not DMA in data larger than the given buffer, even
		 * if it parses the (NFS, of course) header to be larger.  In
		 * that case, it fills the header buffer and spills the rest
		 * into the page.
		 */
		hlen = (le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.hdr_info) &
		  E1000_RXDADV_HDRBUFLEN_MASK) >> E1000_RXDADV_HDRBUFLEN_SHIFT;
		if (hlen > adapter->rx_ps_hdr_size)
			hlen = adapter->rx_ps_hdr_size;

		length = le16_to_cpu(rx_desc->wb.upper.length);
		cleaned = true;
		cleaned_count++;

		skb = buffer_info->skb;
		buffer_info->skb = NULL;
		if (!adapter->rx_ps_hdr_size) {
#ifdef notdef
			pci_unmap_single(pdev, buffer_info->dma,
			                 adapter->rx_buffer_len,
			                 PCI_DMA_FROMDEVICE);
#endif
			buffer_info->dma = 0;
			skb->len = length;
			goto send_up;
		}

#ifdef notdef
		if (!skb_shinfo(skb)->nr_frags) {
			pci_unmap_single(pdev, buffer_info->dma,
			                 adapter->rx_ps_hdr_size,
			                 PCI_DMA_FROMDEVICE);
			skb_put(skb, hlen);
		}

		if (length) {
			pci_unmap_page(pdev, buffer_info->page_dma,
			               PAGE_SIZE / 2,
			               PCI_DMA_FROMDEVICE);
			buffer_info->page_dma = 0;

			skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags++,
			                   buffer_info->page,
			                   buffer_info->page_offset,
			                   length);

			if ((adapter->rx_buffer_len > (PAGE_SIZE / 2)) ||
			    (page_count(buffer_info->page) != 1))
				buffer_info->page = NULL;
			else
				get_page(buffer_info->page);

			skb->len += length;
			skb->data_len += length;
			skb->truesize += length;
		}
#endif
send_up:
		i++;
		if (i == rx_ring->count)
			i = 0;
		next_rxd = IGBVF_RX_DESC_ADV(*rx_ring, i);
		next_buffer = &rx_ring->buffer_info[i];

		if (!(staterr & E1000_RXD_STAT_EOP)) {
			buffer_info->skb = next_buffer->skb;
			buffer_info->dma = next_buffer->dma;
			next_buffer->skb = skb;
			next_buffer->dma = 0;
			goto next_desc;
		}

		if (staterr & E1000_RXDEXT_ERR_FRAME_ERR_MASK) {
			skb_free(skb);
			goto next_desc;
		}

		total_bytes += skb->len;
		total_packets++;

		igbvf_rx_checksum_adv(adapter, staterr, skb);


		igbvf_receive_skb(adapter, skb, staterr,
		                  rx_desc->wb.upper.vlan);

next_desc:
		rx_desc->wb.upper.status_error = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IGBVF_RX_BUFFER_WRITE) {
			igbvf_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;

		staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
	}

	rx_ring->next_to_clean = i;
	cleaned_count = igbvf_desc_unused(rx_ring);

	if (cleaned_count)
		igbvf_alloc_rx_buffers(rx_ring, cleaned_count);

	adapter->total_rx_packets += total_packets;
	adapter->total_rx_bytes += total_bytes;
	return cleaned;
}

static void igbvf_put_txbuf(struct igbvf_adapter *adapter,
                            struct igbvf_buffer *buffer_info)
{
	if (buffer_info->dma) {
#ifdef notdef
		if (buffer_info->mapped_as_page)
			pci_unmap_page(adapter->pdev,
				       buffer_info->dma,
				       buffer_info->length,
				       PCI_DMA_TODEVICE);
		else
			pci_unmap_single(adapter->pdev,
					 buffer_info->dma,
					 buffer_info->length,
					 PCI_DMA_TODEVICE);
#endif
		buffer_info->dma = 0;
	}
	if (buffer_info->skb) {
		skb_free(buffer_info->skb);
		buffer_info->skb = NULL;
	}
	buffer_info->time_stamp = 0;
}

static void igbvf_print_tx_hang(struct igbvf_adapter *adapter)
{
	struct igbvf_ring *tx_ring = adapter->tx_ring;
	unsigned int i = tx_ring->next_to_clean;
	unsigned int eop = tx_ring->buffer_info[i].next_to_watch;
	union e1000_adv_tx_desc *eop_desc = IGBVF_TX_DESC_ADV(*tx_ring, eop);

	/* detected Tx unit hang */
	fprintf(stderr, "igbvf: "
	        "Detected Tx Unit Hang:\n"
	        "  TDH                  <%x>\n"
	        "  TDT                  <%x>\n"
	        "  next_to_use          <%x>\n"
	        "  next_to_clean        <%x>\n"
	        "buffer_info[next_to_clean]:\n"
	        "  time_stamp           <%lx>\n"
	        "  next_to_watch        <%x>\n"
	        "  jiffies              <%x>\n"
	        "  next_to_watch.status <%x>\n",
	        readl(adapter->hw.hw_addr + tx_ring->head),
	        readl(adapter->hw.hw_addr + tx_ring->tail),
	        tx_ring->next_to_use,
	        tx_ring->next_to_clean,
	        tx_ring->buffer_info[eop].time_stamp,
	        eop,
	        jiffies(),
	        eop_desc->wb.status);
}

/**
 * igbvf_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
int igbvf_setup_tx_resources(struct igbvf_adapter *adapter,
                             struct igbvf_ring *tx_ring)
{
	int size;

	size = sizeof(struct igbvf_buffer) * tx_ring->count;
	tx_ring->buffer_info = calloc(1, size);
	if (!tx_ring->buffer_info)
		goto err;

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(union e1000_adv_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	tx_ring->desc = uld_alloc_map_lock(adapter->uld, tx_ring->size, &tx_ring->dma);

	if (!tx_ring->desc)
		goto err;

	tx_ring->adapter = adapter;
	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	return 0;
err:
	free(tx_ring->buffer_info);
	fprintf(stderr, "igbvf: "
	        "Unable to allocate memory for the transmit descriptor ring\n");
	return -ENOMEM;
}

/**
 * igbvf_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 *
 * Returns 0 on success, negative on failure
 **/
int igbvf_setup_rx_resources(struct igbvf_adapter *adapter,
			     struct igbvf_ring *rx_ring)
{
	int size, desc_len;

	size = sizeof(struct igbvf_buffer) * rx_ring->count;
	rx_ring->buffer_info = calloc(1, size);
	if (!rx_ring->buffer_info)
		goto err;

	desc_len = sizeof(union e1000_adv_rx_desc);

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * desc_len;
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	rx_ring->desc = uld_alloc_map_lock(adapter->uld, rx_ring->size, &rx_ring->dma);

	if (!rx_ring->desc)
		goto err;

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	rx_ring->adapter = adapter;

	return 0;

err:
	free(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;
	fprintf(stderr, "igbvf: "
	        "Unable to allocate memory for the receive descriptor ring\n");
	return -ENOMEM;
}

/**
 * igbvf_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
static void igbvf_clean_tx_ring(struct igbvf_ring *tx_ring)
{
	struct igbvf_adapter *adapter = tx_ring->adapter;
	struct igbvf_buffer *buffer_info;
	unsigned long size;
	unsigned int i;

	if (!tx_ring->buffer_info)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++) {
		buffer_info = &tx_ring->buffer_info[i];
		igbvf_put_txbuf(adapter, buffer_info);
	}

	size = sizeof(struct igbvf_buffer) * tx_ring->count;
	memset(tx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	writel(0, adapter->hw.hw_addr + tx_ring->head);
	writel(0, adapter->hw.hw_addr + tx_ring->tail);
}

/**
 * igbvf_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: ring to free resources from
 *
 * Free all transmit software resources
 **/
void igbvf_free_tx_resources(struct igbvf_ring *tx_ring)
{
	igbvf_clean_tx_ring(tx_ring);

	free(tx_ring->buffer_info);
	tx_ring->buffer_info = NULL;

//	pci_free_consistent(pdev, tx_ring->size, tx_ring->desc, tx_ring->dma);

	tx_ring->desc = NULL;
}

/**
 * igbvf_clean_rx_ring - Free Rx Buffers per Queue
 * @adapter: board private structure
 **/
static void igbvf_clean_rx_ring(struct igbvf_ring *rx_ring)
{
	struct igbvf_adapter *adapter = rx_ring->adapter;
	struct igbvf_buffer *buffer_info;
	unsigned long size;
	unsigned int i;

	if (!rx_ring->buffer_info)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		if (buffer_info->dma) {
#ifdef notdef
			if (adapter->rx_ps_hdr_size){
				pci_unmap_single(pdev, buffer_info->dma,
				                 adapter->rx_ps_hdr_size,
				                 PCI_DMA_FROMDEVICE);
			} else {
				pci_unmap_single(pdev, buffer_info->dma,
				                 adapter->rx_buffer_len,
				                 PCI_DMA_FROMDEVICE);
			}
#endif
			buffer_info->dma = 0;
		}

		if (buffer_info->skb) {
			skb_free(buffer_info->skb);
			buffer_info->skb = NULL;
		}

#ifdef notdef
		if (buffer_info->page) {
			if (buffer_info->page_dma)
				pci_unmap_page(pdev, buffer_info->page_dma,
				               PAGE_SIZE / 2,
				               PCI_DMA_FROMDEVICE);
			put_page(buffer_info->page);
			buffer_info->page = NULL;
			buffer_info->page_dma = 0;
			buffer_info->page_offset = 0;
		}
#endif
	}

	size = sizeof(struct igbvf_buffer) * rx_ring->count;
	memset(rx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	writel(0, adapter->hw.hw_addr + rx_ring->head);
	writel(0, adapter->hw.hw_addr + rx_ring->tail);
}

/**
 * igbvf_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/

void igbvf_free_rx_resources(struct igbvf_ring *rx_ring)
{

	igbvf_clean_rx_ring(rx_ring);

	free(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;

//	dma_free_coherent(&pdev->dev, rx_ring->size, rx_ring->desc,
//	                  rx_ring->dma);
	rx_ring->desc = NULL;
}

#ifdef notdef
/**
 * igbvf_update_itr - update the dynamic ITR value based on statistics
 * @adapter: pointer to adapter
 * @itr_setting: current adapter->itr
 * @packets: the number of packets during this measurement interval
 * @bytes: the number of bytes during this measurement interval
 *
 *      Stores a new ITR value based on packets and byte
 *      counts during the last interrupt.  The advantage of per interrupt
 *      computation is faster updates and more accurate ITR for the current
 *      traffic pattern.  Constants in this function were computed
 *      based on theoretical maximum wire speed and thresholds were set based
 *      on testing data as well as attempting to minimize response time
 *      while increasing bulk throughput.  This functionality is controlled
 *      by the InterruptThrottleRate module parameter.
 **/
static unsigned int igbvf_update_itr(struct igbvf_adapter *adapter,
                                     u16 itr_setting, int packets,
                                     int bytes)
{
	unsigned int retval = itr_setting;

	if (packets == 0)
		goto update_itr_done;

	switch (itr_setting) {
	case lowest_latency:
		/* handle TSO and jumbo frames */
		if (bytes/packets > 8000)
			retval = bulk_latency;
		else if ((packets < 5) && (bytes > 512))
			retval = low_latency;
		break;
	case low_latency:  /* 50 usec aka 20000 ints/s */
		if (bytes > 10000) {
			/* this if handles the TSO accounting */
			if (bytes/packets > 8000)
				retval = bulk_latency;
			else if ((packets < 10) || ((bytes/packets) > 1200))
				retval = bulk_latency;
			else if ((packets > 35))
				retval = lowest_latency;
		} else if (bytes/packets > 2000) {
			retval = bulk_latency;
		} else if (packets <= 2 && bytes < 512) {
			retval = lowest_latency;
		}
		break;
	case bulk_latency: /* 250 usec aka 4000 ints/s */
		if (bytes > 25000) {
			if (packets > 35)
				retval = low_latency;
		} else if (bytes < 6000) {
			retval = low_latency;
		}
		break;
	}

update_itr_done:
	return retval;
}
#endif

#ifdef notdef
static void igbvf_set_itr(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 current_itr;
	u32 new_itr = adapter->itr;

	adapter->tx_itr = igbvf_update_itr(adapter, adapter->tx_itr,
	                                   adapter->total_tx_packets,
	                                   adapter->total_tx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->tx_itr == lowest_latency)
		adapter->tx_itr = low_latency;

	adapter->rx_itr = igbvf_update_itr(adapter, adapter->rx_itr,
	                                   adapter->total_rx_packets,
	                                   adapter->total_rx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->rx_itr == lowest_latency)
		adapter->rx_itr = low_latency;

	current_itr = max_t(u16, adapter->rx_itr, adapter->tx_itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = 70000;
		break;
	case low_latency:
		new_itr = 20000; /* aka hwitr = ~200 */
		break;
	case bulk_latency:
		new_itr = 4000;
		break;
	default:
		break;
	}

	if (new_itr != adapter->itr) {
		/*
		 * this attempts to bias the interrupt rate towards Bulk
		 * by adding intermediate steps when interrupt rate is
		 * increasing
		 */
		new_itr = new_itr > adapter->itr ?
		             min_t(u32, adapter->itr + (new_itr >> 2), new_itr) :
		             new_itr;
		adapter->itr = new_itr;
		adapter->rx_ring->itr_val = 1952;

		if (adapter->msix_entries)
			adapter->rx_ring->set_itr = 1;
		else
			ew32(ITR, 1952);
	}
}
#endif

/**
 * igbvf_clean_tx_irq - Reclaim resources after transmit completes
 * @adapter: board private structure
 * returns true if ring is completely cleaned
 **/
static bool igbvf_clean_tx_irq(struct igbvf_ring *tx_ring)
{
	struct igbvf_adapter *adapter = tx_ring->adapter;
	struct e1000_hw *hw = &adapter->hw;
	struct igbvf_buffer *buffer_info;
	struct sk_buff *skb;
	union e1000_adv_tx_desc *tx_desc, *eop_desc;
	unsigned int total_bytes = 0;
	unsigned int i, eop, count = 0;
	bool cleaned = false;

	i = tx_ring->next_to_clean;
	eop = tx_ring->buffer_info[i].next_to_watch;
	eop_desc = IGBVF_TX_DESC_ADV(*tx_ring, eop);

	while ((eop_desc->wb.status & cpu_to_le32(E1000_TXD_STAT_DD)) &&
	       (count < tx_ring->count)) {
		for (cleaned = false; !cleaned; count++) {
			tx_desc = IGBVF_TX_DESC_ADV(*tx_ring, i);
			buffer_info = &tx_ring->buffer_info[i];
			cleaned = (i == eop);
			skb = buffer_info->skb;

			if (skb) {
				unsigned int bytecount;

#ifdef notdef
				unsigned int segs;
				/* gso_segs is currently only valid for tcp */
				segs = skb_shinfo(skb)->gso_segs ?: 1;
				/* multiply data chunks by size of headers */
				bytecount = ((segs - 1) * skb_headlen(skb)) +
				            skb->len;
				total_packets += segs;
#else
				bytecount = skb->len;
#endif
				total_bytes += bytecount;
			}

			igbvf_put_txbuf(adapter, buffer_info);
			tx_desc->wb.status = 0;

			i++;
			if (i == tx_ring->count)
				i = 0;
		}
		eop = tx_ring->buffer_info[i].next_to_watch;
		eop_desc = IGBVF_TX_DESC_ADV(*tx_ring, eop);
	}

	tx_ring->next_to_clean = i;

#ifdef notdef
	if (unlikely(count &&
	             netif_carrier_ok(netdev) &&
	             igbvf_desc_unused(tx_ring) >= IGBVF_TX_QUEUE_WAKE)) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_queue_stopped(netdev) &&
		    !(test_bit(__IGBVF_DOWN, &adapter->state))) {
			netif_wake_queue(netdev);
			++adapter->restart_queue;
		}
	}

#endif
	if (adapter->detect_tx_hung) {
		/* Detect a transmit hang in hardware, this serializes the
		 * check with the clearing of time_stamp and movement of i */
		adapter->detect_tx_hung = false;
		if (tx_ring->buffer_info[i].time_stamp &&
		    jiffies() > tx_ring->buffer_info[i].time_stamp +
		               (adapter->tx_timeout_factor * HZ) &&
		    !(er32(STATUS) & E1000_STATUS_TXOFF)) {

			tx_desc = IGBVF_TX_DESC_ADV(*tx_ring, i);
			/* detected Tx unit hang */
			igbvf_print_tx_hang(adapter);

//			netif_stop_queue(netdev);
		}
	}
	return (count < tx_ring->count);
}

static irqreturn_t igbvf_msix_other(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	adapter->int_counter1++;

//??	netif_carrier_off(netdev);
	hw->mac.get_link_status = 1;
	if (!test_bit(__IGBVF_DOWN, &adapter->state))
		timeout_add_usec(adapter->uld, 1, igbvf_watchdog, (void *)adapter);  

	ew32(EIMS, adapter->eims_other);

	return IRQ_HANDLED;
}

static irqreturn_t igbvf_msix_tx(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct igbvf_ring *tx_ring = adapter->tx_ring;


	adapter->total_tx_bytes = 0;
	adapter->total_tx_packets = 0;

	/* auto mask will automatically reenable the interrupt when we write
	 * EICS */
	if (!igbvf_clean_tx_irq(tx_ring))
		/* Ring was not completely cleaned, so fire another interrupt */
		ew32(EICS, tx_ring->eims_value);
	else
		ew32(EIMS, tx_ring->eims_value);

	return IRQ_HANDLED;
}

#ifdef notdef
static irqreturn_t igbvf_msix_rx(struct igbvf_adapter *adapter)
{
	adapter->int_counter0++;

	/* Write the ITR value calculated at the end of the
	 * previous interrupt.
	 */
	if (adapter->rx_ring->set_itr) {
		writel(adapter->rx_ring->itr_val,
		       adapter->hw.hw_addr + adapter->rx_ring->itr_register);
		adapter->rx_ring->set_itr = 0;
	}

	if (napi_schedule_prep(&adapter->rx_ring->napi)) {
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->rx_ring->napi);
	}

	return IRQ_HANDLED;
}
#endif

#define IGBVF_NO_QUEUE -1

static void igbvf_assign_vector(struct igbvf_adapter *adapter, int rx_queue,
                                int tx_queue, int msix_vector)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ivar, index;

	/* 82576 uses a table-based method for assigning vectors.
	   Each queue has a single entry in the table to which we write
	   a vector number along with a "valid" bit.  Sadly, the layout
	   of the table is somewhat counterintuitive. */
	if (rx_queue > IGBVF_NO_QUEUE) {
		index = (rx_queue >> 1);
		ivar = array_er32(IVAR0, index);
		if (rx_queue & 0x1) {
			/* vector goes into third byte of register */
			ivar = ivar & 0xFF00FFFF;
			ivar |= (msix_vector | E1000_IVAR_VALID) << 16;
		} else {
			/* vector goes into low byte of register */
			ivar = ivar & 0xFFFFFF00;
			ivar |= msix_vector | E1000_IVAR_VALID;
		}
		adapter->rx_ring[rx_queue].eims_value = 1 << msix_vector;
		array_ew32(IVAR0, index, ivar);
	}
	if (tx_queue > IGBVF_NO_QUEUE) {
		index = (tx_queue >> 1);
		ivar = array_er32(IVAR0, index);
		if (tx_queue & 0x1) {
			/* vector goes into high byte of register */
			ivar = ivar & 0x00FFFFFF;
			ivar |= (msix_vector | E1000_IVAR_VALID) << 24;
		} else {
			/* vector goes into second byte of register */
			ivar = ivar & 0xFFFF00FF;
			ivar |= (msix_vector | E1000_IVAR_VALID) << 8;
		}
		adapter->tx_ring[tx_queue].eims_value = 1 << msix_vector;
		array_ew32(IVAR0, index, ivar);
	}
}

/**
 * igbvf_configure_msix - Configure MSI-X hardware
 *
 * igbvf_configure_msix sets up the hardware to properly
 * generate MSI-X interrupts.
 **/
static void igbvf_configure_msix(struct igbvf_adapter *adapter)
{
	u32 tmp;
	struct e1000_hw *hw = &adapter->hw;
	struct igbvf_ring *tx_ring = adapter->tx_ring;
	struct igbvf_ring *rx_ring = adapter->rx_ring;
	int vector = 0;

	adapter->eims_enable_mask = 0;

	igbvf_assign_vector(adapter, IGBVF_NO_QUEUE, 0, vector++);
	adapter->eims_enable_mask |= tx_ring->eims_value;
	if (tx_ring->itr_val)
		writel(tx_ring->itr_val,
		       hw->hw_addr + tx_ring->itr_register);
	else
		writel(1952, hw->hw_addr + tx_ring->itr_register);

	igbvf_assign_vector(adapter, 0, IGBVF_NO_QUEUE, vector++);
	adapter->eims_enable_mask |= rx_ring->eims_value;
	if (rx_ring->itr_val)
		writel(rx_ring->itr_val,
		       hw->hw_addr + rx_ring->itr_register);
	else
		writel(1952, hw->hw_addr + rx_ring->itr_register);

	/* set vector for other causes, i.e. link changes */

	tmp = (vector++ | E1000_IVAR_VALID);

	ew32(IVAR_MISC, tmp);

	adapter->eims_enable_mask = (1 << (vector)) - 1;
	adapter->eims_other = 1 << (vector - 1);
	e1e_flush();
}

static void igbvf_reset_interrupt_capability(struct igbvf_adapter *adapter)
{
	int i;
	if (adapter->msix_entries) {
		pci_disable_msix(adapter->uld->fd);
		for (i = 0; i < 3; i++)
			close(adapter->msix_entries[i].fd);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
	}
}

/**
 * igbvf_set_interrupt_capability - set MSI or MSI-X if supported
 *
 * Attempt to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static void igbvf_set_interrupt_capability(struct igbvf_adapter *adapter)
{
	int err = -ENOMEM;
	int i;

	/* we allocate 3 vectors, 1 for tx, 1 for rx, one for pf messages */
	adapter->msix_entries = calloc(3, sizeof(struct pollfd));
	if (adapter->msix_entries) {
		for (i = 0; i < 3; i++) {
			adapter->msix_entries[i].fd = eventfd(0, 0);
			adapter->msix_entries[i].events = POLLIN;
		}

		err = pci_enable_msix(adapter->uld->fd,
		                      adapter->msix_entries, 3);
	}

	if (err) {
		/* MSI-X failed */
		fprintf(stderr, "igbvf: "
		        "Failed to initialize MSI-X interrupts.\n");
		igbvf_reset_interrupt_capability(adapter);
	}
}

/**
 * igbvf_request_msix - Initialize MSI-X interrupts
 *
 * igbvf_request_msix allocates MSI-X vectors and requests interrupts from the
 * kernel.
 **/
static int igbvf_request_msix(struct igbvf_adapter *adapter)
{
	int vector = 0;

#ifdef notdef
	if (strlen(netdev->name) < (IFNAMSIZ - 5)) {
		sprintf(adapter->tx_ring->name, "%s-tx-0", netdev->name);
		sprintf(adapter->rx_ring->name, "%s-rx-0", netdev->name);
	} else {
		memcpy(adapter->tx_ring->name, netdev->name, IFNAMSIZ);
		memcpy(adapter->rx_ring->name, netdev->name, IFNAMSIZ);
	}

	err = request_irq(adapter->msix_entries[vector].vector,
	                  igbvf_intr_msix_tx, 0, adapter->tx_ring->name,
	                  netdev);
	if (err)
		goto out;
#endif

	adapter->tx_ring->itr_register = E1000_EITR(vector);
	adapter->tx_ring->itr_val = 1952;
	vector++;

#ifdef notdef
	err = request_irq(adapter->msix_entries[vector].vector,
	                  igbvf_intr_msix_rx, 0, adapter->rx_ring->name,
	                  netdev);
	if (err)
		goto out;
#endif

	adapter->rx_ring->itr_register = E1000_EITR(vector);
	adapter->rx_ring->itr_val = 1952;
	vector++;

#ifdef notdef
	err = request_irq(adapter->msix_entries[vector].vector,
	                  igbvf_msix_other, 0, netdev->name, netdev);
	if (err)
		return err;
#endif

	igbvf_configure_msix(adapter);
	return 0;
}

/**
 * igbvf_alloc_queues - Allocate memory for all rings
 * @adapter: board private structure to initialize
 **/
static int igbvf_alloc_queues(struct igbvf_adapter *adapter)
{

	adapter->tx_ring = calloc(1, sizeof(struct igbvf_ring));
	if (!adapter->tx_ring)
		return -ENOMEM;

	adapter->rx_ring = calloc(1, sizeof(struct igbvf_ring));
	if (!adapter->rx_ring) {
		kfree(adapter->tx_ring);
		return -ENOMEM;
	}

//	netif_napi_add(netdev, &adapter->rx_ring->napi, igbvf_poll, 64);

	return 0;
}

/**
 * igbvf_request_irq - initialize interrupts
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int igbvf_request_irq(struct igbvf_adapter *adapter)
{
	int err = -1;

	/* igbvf supports msi-x only */
	if (adapter->msix_entries)
		err = igbvf_request_msix(adapter);

	if (!err)
		return err;

	fprintf(stderr, "igbvf: "
	        "Unable to allocate interrupt, Error: %d\n", err);

	return err;
}

static void igbvf_free_irq(struct igbvf_adapter *adapter)
{
//	int vector;

	if (adapter->msix_entries) {
//		for (vector = 0; vector < 3; vector++)
//			free_irq(adapter->msix_entries[vector].vector, netdev);
	}
}

/**
 * igbvf_irq_disable - Mask off interrupt generation on the NIC
 **/
static void igbvf_irq_disable(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(EIMC, ~0);

	if (adapter->msix_entries)
		ew32(EIAC, 0);
}

/**
 * igbvf_irq_enable - Enable default interrupt generation settings
 **/
static void igbvf_irq_enable(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(EIAC, adapter->eims_enable_mask);
	ew32(EIAM, adapter->eims_enable_mask);
	ew32(EIMS, adapter->eims_enable_mask);
fprintf(stderr, "%s:\n", __func__);
}

#ifdef notdef
/**
 * igbvf_poll - NAPI Rx polling callback
 * @napi: struct associated with this polling callback
 * @budget: amount of packets driver is allowed to process this poll
 **/
static int igbvf_poll(struct igbvf_ring *rx_ring, int budget)
{
	struct igbvf_adapter *adapter = rx_ring->adapter;
	struct e1000_hw *hw = &adapter->hw;
	int work_done = 0;

	igbvf_clean_rx_irq(adapter, &work_done, budget);

	/* If not enough Rx work done, exit the polling mode */
	if (work_done < budget) {
//		napi_complete(napi);

		if (adapter->itr_setting & 3)
			igbvf_set_itr(adapter);

		if (!test_bit(__IGBVF_DOWN, &adapter->state))
			ew32(EIMS, adapter->rx_ring->eims_value);
	}

	return work_done;
}
#endif

/**
 * igbvf_set_rlpml - set receive large packet maximum length
 * @adapter: board private structure
 *
 * Configure the maximum size of packets that will be received
 */
static void igbvf_set_rlpml(struct igbvf_adapter *adapter)
{
	int max_frame_size = adapter->max_frame_size;
	struct e1000_hw *hw = &adapter->hw;

	if (adapter->vlgrp)
		max_frame_size += VLAN_TAG_SIZE;

	e1000_rlpml_set_vf(hw, max_frame_size);
}

#ifdef notdef
static void igbvf_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	if (hw->mac.ops.set_vfta(hw, vid, true))
		fprintf(stderr, "igbvf: " "Failed to add vlan id %d\n", vid);
}

static void igbvf_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	igbvf_irq_disable(adapter);
	vlan_group_set_device(adapter->vlgrp, vid, NULL);

	if (!test_bit(__IGBVF_DOWN, &adapter->state))
		igbvf_irq_enable(adapter);

	if (hw->mac.ops.set_vfta(hw, vid, false))
		fprintf(stderr, "igbvf: "
		        "Failed to remove vlan id %d\n", vid);
}

static void igbvf_vlan_rx_register(struct net_device *netdev,
                                   struct vlan_group *grp)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	adapter->vlgrp = grp;
}
#endif

#ifdef notdef
static void igbvf_restore_vlan(struct igbvf_adapter *adapter)
{
	if (!adapter->vlgrp)
		return;

	for (vid = 0; vid < VLAN_GROUP_ARRAY_LEN; vid++) {
		if (!vlan_group_get_device(adapter->vlgrp, vid))
			continue;
		igbvf_vlan_rx_add_vid(adapter->netdev, vid);
	}

	igbvf_set_rlpml(adapter);
}
#endif

/**
 * igbvf_configure_tx - Configure Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void igbvf_configure_tx(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct igbvf_ring *tx_ring = adapter->tx_ring;
	u64 tdba;
	u32 txdctl, dca_txctrl;

	/* disable transmits */
	txdctl = er32(TXDCTL(0));
	ew32(TXDCTL(0), txdctl & ~E1000_TXDCTL_QUEUE_ENABLE);
	usleep(10000);

	/* Setup the HW Tx Head and Tail descriptor pointers */
	ew32(TDLEN(0), tx_ring->count * sizeof(union e1000_adv_tx_desc));
	tdba = tx_ring->dma;
	ew32(TDBAL(0), (tdba & DMA_BIT_MASK(32)));
	ew32(TDBAH(0), (tdba >> 32));
	ew32(TDH(0), 0);
	ew32(TDT(0), 0);
	tx_ring->head = E1000_TDH(0);
	tx_ring->tail = E1000_TDT(0);

	/* Turn off Relaxed Ordering on head write-backs.  The writebacks
	 * MUST be delivered in order or it will completely screw up
	 * our bookeeping.
	 */
	dca_txctrl = er32(DCA_TXCTRL(0));
	dca_txctrl &= ~E1000_DCA_TXCTRL_TX_WB_RO_EN;
	ew32(DCA_TXCTRL(0), dca_txctrl);

	/* enable transmits */
	txdctl |= E1000_TXDCTL_QUEUE_ENABLE;
	ew32(TXDCTL(0), txdctl);

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd = E1000_ADVTXD_DCMD_EOP | E1000_ADVTXD_DCMD_IFCS;

	/* enable Report Status bit */
	adapter->txd_cmd |= E1000_ADVTXD_DCMD_RS;

}

/**
 * igbvf_setup_srrctl - configure the receive control registers
 * @adapter: Board private structure
 **/
static void igbvf_setup_srrctl(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 srrctl = 0;

	srrctl &= ~(E1000_SRRCTL_DESCTYPE_MASK |
	            E1000_SRRCTL_BSIZEHDR_MASK |
	            E1000_SRRCTL_BSIZEPKT_MASK);

	/* Enable queue drop to avoid head of line blocking */
	srrctl |= E1000_SRRCTL_DROP_EN;

	/* Setup buffer sizes */
	srrctl |= ALIGN(adapter->rx_buffer_len, 1024) >>
	          E1000_SRRCTL_BSIZEPKT_SHIFT;

	if (adapter->rx_buffer_len < 2048) {
		adapter->rx_ps_hdr_size = 0;
		srrctl |= E1000_SRRCTL_DESCTYPE_ADV_ONEBUF;
	} else {
		adapter->rx_ps_hdr_size = 128;
		srrctl |= adapter->rx_ps_hdr_size <<
		          E1000_SRRCTL_BSIZEHDRSIZE_SHIFT;
		srrctl |= E1000_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS;
	}

	ew32(SRRCTL(0), srrctl);
}

/**
 * igbvf_configure_rx - Configure Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void igbvf_configure_rx(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct igbvf_ring *rx_ring = adapter->rx_ring;
	u64 rdba;
	u32 rdlen, rxdctl;

	/* disable receives */
	rxdctl = er32(RXDCTL(0));
	ew32(RXDCTL(0), rxdctl & ~E1000_RXDCTL_QUEUE_ENABLE);
	usleep(10000);

	rdlen = rx_ring->count * sizeof(union e1000_adv_rx_desc);

	/*
	 * Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	rdba = rx_ring->dma;
	ew32(RDBAL(0), (rdba & DMA_BIT_MASK(32)));
	ew32(RDBAH(0), (rdba >> 32));
	ew32(RDLEN(0), rx_ring->count * sizeof(union e1000_adv_rx_desc));
	rx_ring->head = E1000_RDH(0);
	rx_ring->tail = E1000_RDT(0);
	ew32(RDH(0), 0);
	ew32(RDT(0), 0);

	rxdctl |= E1000_RXDCTL_QUEUE_ENABLE;
	rxdctl &= 0xFFF00000;
	rxdctl |= IGBVF_RX_PTHRESH;
	rxdctl |= IGBVF_RX_HTHRESH << 8;
	rxdctl |= IGBVF_RX_WTHRESH << 16;

	igbvf_set_rlpml(adapter);

	/* enable receives */
	ew32(RXDCTL(0), rxdctl);
}

#ifdef notdef
/**
 * igbvf_set_multi - Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_multi entry point is called whenever the multicast address
 * list or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper multicast,
 * promiscuous mode, and all-multi behavior.
 **/
static void igbvf_set_multi(struct net_device *netdev)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct dev_mc_list *mc_ptr;
	u8  *mta_list = NULL;
	int i;

	if (netdev->mc_count) {
		mta_list = kmalloc(netdev->mc_count * 6, GFP_ATOMIC);
		if (!mta_list) {
			fprintf(stderr, "igbvf: "
			        "failed to allocate multicast filter list\n");
			return;
		}
	}

	/* prepare a packed array of only addresses. */
	mc_ptr = netdev->mc_list;

	for (i = 0; i < netdev->mc_count; i++) {
		if (!mc_ptr)
			break;
		memcpy(mta_list + (i*ETH_ALEN), mc_ptr->dmi_addr,
		       ETH_ALEN);
		mc_ptr = mc_ptr->next;
	}

	hw->mac.ops.update_mc_addr_list(hw, mta_list, i, 0, 0);
	kfree(mta_list);
}
#endif

/**
 * igbvf_configure - configure the hardware for Rx and Tx
 * @adapter: private board structure
 **/
static void igbvf_configure(struct igbvf_adapter *adapter)
{
//	igbvf_set_multi(adapter->netdev);

//	igbvf_restore_vlan(adapter);

	igbvf_configure_tx(adapter);
	igbvf_setup_srrctl(adapter);
	igbvf_configure_rx(adapter);
	igbvf_alloc_rx_buffers(adapter->rx_ring,
	                       igbvf_desc_unused(adapter->rx_ring));
}

/* igbvf_reset - bring the hardware into a known good state
 *
 * This function boots the hardware and enables some settings that
 * require a configuration cycle of the hardware - those cannot be
 * set/changed during runtime. After reset the device needs to be
 * properly configured for Rx, Tx etc.
 */
static void igbvf_reset(struct igbvf_adapter *adapter)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_hw *hw = &adapter->hw;

	/* Allow time for pending master requests to run */
	if (mac->ops.reset_hw(hw))
		fprintf(stderr, "igbvf: " "PF still resetting\n");

	mac->ops.init_hw(hw);

#ifdef notdef
	if (is_valid_ether_addr(adapter->hw.mac.addr)) {
		memcpy(netdev->dev_addr, adapter->hw.mac.addr,
		       netdev->addr_len);
		memcpy(netdev->perm_addr, adapter->hw.mac.addr,
		       netdev->addr_len);
	}
#endif

	adapter->last_reset = jiffies();
}

int igbvf_up(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	/* hardware has been reset, we need to reload some things */
	igbvf_configure(adapter);

	clear_bit(__IGBVF_DOWN, &adapter->state);

//	napi_enable(&adapter->rx_ring->napi);
	if (adapter->msix_entries)
		igbvf_configure_msix(adapter);

	/* Clear any pending interrupts. */
	er32(EICR);
	igbvf_irq_enable(adapter);

	/* start the watchdog */
	hw->mac.get_link_status = 1;
	timeout_add_usec(adapter->uld, 1, igbvf_watchdog, (void *)adapter);  

	return 0;
}

void igbvf_down(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rxdctl, txdctl;

	/*
	 * signal that we're down so the interrupt handler does not
	 * reschedule our watchdog timer
	 */
	set_bit(__IGBVF_DOWN, &adapter->state);

	/* disable receives in the hardware */
	rxdctl = er32(RXDCTL(0));
	ew32(RXDCTL(0), rxdctl & ~E1000_RXDCTL_QUEUE_ENABLE);

//	netif_stop_queue(netdev);

	/* disable transmits in the hardware */
	txdctl = er32(TXDCTL(0));
	ew32(TXDCTL(0), txdctl & ~E1000_TXDCTL_QUEUE_ENABLE);

	/* flush both disables and wait for them to finish */
	e1e_flush();
	usleep(10000);

//	napi_disable(&adapter->rx_ring->napi);

	igbvf_irq_disable(adapter);

	timeout_cancel(adapter->uld, igbvf_watchdog, (void *)adapter);

	adapter->uld->linkup = 0;

	/* record the stats before reset*/
	igbvf_update_stats(adapter);

	adapter->link_speed = 0;
	adapter->link_duplex = 0;

	igbvf_reset(adapter);
	igbvf_clean_tx_ring(adapter->tx_ring);
	igbvf_clean_rx_ring(adapter->rx_ring);
}

void igbvf_reinit_locked(struct igbvf_adapter *adapter)
{
	set_bit(__IGBVF_RESETTING, &adapter->state);
	igbvf_down(adapter);
	igbvf_up(adapter);
	clear_bit(__IGBVF_RESETTING, &adapter->state);
}

/**
 * igbvf_sw_init - Initialize general software structures (struct igbvf_adapter)
 * @adapter: board private structure to initialize
 *
 * igbvf_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int igbvf_sw_init(struct igbvf_adapter *adapter)
{
	s32 rc;

	adapter->rx_buffer_len = ETH_FRAME_LEN + 4 + ETH_FCS_LEN;
	adapter->rx_ps_hdr_size = 0;
	adapter->max_frame_size = adapter->uld->mtu + ETH_HLEN + ETH_FCS_LEN;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	adapter->tx_int_delay = 8;
	adapter->tx_abs_int_delay = 32;
	adapter->rx_int_delay = 0;
	adapter->rx_abs_int_delay = 8;
	adapter->itr_setting = lowest_latency;
	adapter->itr = 70000;

	/* Set various function pointers */
	adapter->ei->init_ops(&adapter->hw);

	rc = adapter->hw.mac.ops.init_params(&adapter->hw);
	if (rc)
		return rc;

	rc = adapter->hw.mbx.ops.init_params(&adapter->hw);
	if (rc)
		return rc;

	igbvf_set_interrupt_capability(adapter);

	if (igbvf_alloc_queues(adapter))
		return -ENOMEM;

	spin_lock_init(&adapter->tx_queue_lock);

	/* Explicitly disable IRQ since the NIC can be in any state. */
	igbvf_irq_disable(adapter);

	spin_lock_init(&adapter->stats_lock);

	set_bit(__IGBVF_DOWN, &adapter->state);
	return 0;
}

static void igbvf_initialize_last_counter_stats(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	adapter->stats.last_gprc = er32(VFGPRC);
	adapter->stats.last_gorc = er32(VFGORC);
	adapter->stats.last_gptc = er32(VFGPTC);
	adapter->stats.last_gotc = er32(VFGOTC);
	adapter->stats.last_mprc = er32(VFMPRC);
	adapter->stats.last_gotlbc = er32(VFGOTLBC);
	adapter->stats.last_gptlbc = er32(VFGPTLBC);
	adapter->stats.last_gorlbc = er32(VFGORLBC);
	adapter->stats.last_gprlbc = er32(VFGPRLBC);

	adapter->stats.base_gprc = er32(VFGPRC);
	adapter->stats.base_gorc = er32(VFGORC);
	adapter->stats.base_gptc = er32(VFGPTC);
	adapter->stats.base_gotc = er32(VFGOTC);
	adapter->stats.base_mprc = er32(VFMPRC);
	adapter->stats.base_gotlbc = er32(VFGOTLBC);
	adapter->stats.base_gptlbc = er32(VFGPTLBC);
	adapter->stats.base_gorlbc = er32(VFGORLBC);
	adapter->stats.base_gprlbc = er32(VFGPRLBC);
}

/**
 * igbvf_open - Called when a network interface is made active
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
static int igbvf_open(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	int err;

	/* disallow open during test */
	if (test_bit(__IGBVF_TESTING, &adapter->state))
		return -EBUSY;

	/* allocate transmit descriptors */
	err = igbvf_setup_tx_resources(adapter, adapter->tx_ring);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = igbvf_setup_rx_resources(adapter, adapter->rx_ring);
	if (err)
		goto err_setup_rx;

	/*
	 * before we allocate an interrupt, we must be ready to handle it.
	 * Setting DEBUG_SHIRQ in the kernel makes it fire an interrupt
	 * as soon as we call pci_request_irq, so we have to setup our
	 * clean_rx handler before we do so.
	 */
	igbvf_configure(adapter);

	err = igbvf_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* From here on the code is the same as igbvf_up() */
	clear_bit(__IGBVF_DOWN, &adapter->state);

//	napi_enable(&adapter->rx_ring->napi);

	/* clear any pending interrupts */
	er32(EICR);

	igbvf_irq_enable(adapter);

	/* start the watchdog */
	hw->mac.get_link_status = 1;
	timeout_add_usec(adapter->uld, 1, igbvf_watchdog, (void *)adapter);  

	return 0;

err_req_irq:
	igbvf_free_rx_resources(adapter->rx_ring);
err_setup_rx:
	igbvf_free_tx_resources(adapter->tx_ring);
err_setup_tx:
	igbvf_reset(adapter);

	return err;
}

/**
 * igbvf_close - Disables a network interface
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static int igbvf_close(struct igbvf_adapter *adapter)
{

	igbvf_down(adapter);

	igbvf_free_irq(adapter);

	igbvf_free_tx_resources(adapter->tx_ring);
	igbvf_free_rx_resources(adapter->rx_ring);

	return 0;
}

#ifdef notdef
/**
 * igbvf_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int igbvf_set_mac(struct net_device *netdev, void *p)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);

	hw->mac.ops.rar_set(hw, hw->mac.addr, 0);

	if (memcmp(addr->sa_data, hw->mac.addr, 6))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);

	return 0;
}
#endif

#define UPDATE_VF_COUNTER(reg, name)                                    \
	{                                                               \
		u32 current_counter = er32(reg);                        \
		if (current_counter < adapter->stats.last_##name)       \
			adapter->stats.name += 0x100000000LL;           \
		adapter->stats.last_##name = current_counter;           \
		adapter->stats.name &= 0xFFFFFFFF00000000LL;            \
		adapter->stats.name |= current_counter;                 \
	}

/**
 * igbvf_update_stats - Update the board statistics counters
 * @adapter: board private structure
**/
void igbvf_update_stats(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	/*
	 * Prevent stats update while adapter is being reset, link is down
	 * or if the pci connection is down.
	 */
	if (adapter->link_speed == 0)
		return;

	if (test_bit(__IGBVF_RESETTING, &adapter->state))
		return;

	UPDATE_VF_COUNTER(VFGPRC, gprc);
	UPDATE_VF_COUNTER(VFGORC, gorc);
	UPDATE_VF_COUNTER(VFGPTC, gptc);
	UPDATE_VF_COUNTER(VFGOTC, gotc);
	UPDATE_VF_COUNTER(VFMPRC, mprc);
	UPDATE_VF_COUNTER(VFGOTLBC, gotlbc);
	UPDATE_VF_COUNTER(VFGPTLBC, gptlbc);
	UPDATE_VF_COUNTER(VFGORLBC, gorlbc);
	UPDATE_VF_COUNTER(VFGPRLBC, gprlbc);
}

static void igbvf_print_link_info(struct igbvf_adapter *adapter)
{
	fprintf(stderr, "igbvf: " "Link is Up %d Mbps %s\n",
	         adapter->link_speed,
	         ((adapter->link_duplex == FULL_DUPLEX) ?
	          "Full Duplex" : "Half Duplex"));
}

static bool igbvf_has_link(struct igbvf_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	s32 ret_val = E1000_SUCCESS;
	bool link_active;

	/* If interface is down, stay link down */
	if (test_bit(__IGBVF_DOWN, &adapter->state))
		return false;

	ret_val = hw->mac.ops.check_for_link(hw);
	link_active = !hw->mac.get_link_status;

	/* if check for link returns error we will need to reset */
	if (ret_val && jiffies() > adapter->last_reset + (10 * HZ))
		igbvf_reset_task(adapter);

	return link_active;
}

static void igbvf_watchdog(void *handle)
{
	struct igbvf_adapter *adapter = handle;
	struct uld *uld = adapter->uld;
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct igbvf_ring *tx_ring = adapter->tx_ring;
	struct e1000_hw *hw = &adapter->hw;
	u32 link;
	int tx_pending = 0;

	link = igbvf_has_link(adapter);

	if (link) {
		if (!uld->linkup) {
			bool txb2b = 1;

			mac->ops.get_link_up_info(&adapter->hw,
			                          &adapter->link_speed,
			                          &adapter->link_duplex);
			igbvf_print_link_info(adapter);

			/*
			 * tweak tx_queue_len according to speed/duplex
			 * and adjust the timeout factor
			 */
			adapter->tx_timeout_factor = 1;
			switch (adapter->link_speed) {
			case SPEED_10:
				txb2b = 0;
				adapter->tx_timeout_factor = 16;
				break;
			case SPEED_100:
				txb2b = 0;
				/* maybe add some timeout factor ? */
				break;
			}

			uld->linkup = 1;
		}
	} else {
		if (uld->linkup) {
			adapter->link_speed = 0;
			adapter->link_duplex = 0;
			fprintf(stderr, "igbvf: " "Link is Down\n");
			uld->linkup = 0;
		}
	}

	if (uld->linkup) {
		igbvf_update_stats(adapter);
	} else {
		tx_pending = (igbvf_desc_unused(tx_ring) + 1 <
		              tx_ring->count);
		if (tx_pending) {
			/*
			 * We've lost link, so the controller stops DMA,
			 * but we've got queued Tx work that's never going
			 * to get done, so reset controller to flush Tx.
			 * (Do the reset outside of interrupt context).
			 */
			adapter->tx_timeout_count++;
			igbvf_reset_task(adapter);
		}
	}

	/* Cause software interrupt to ensure Rx ring is cleaned */
	ew32(EICS, adapter->rx_ring->eims_value);

	/* Force detection of hung controller every watchdog period */
	adapter->detect_tx_hung = 1;

	/* Reset the timer */
	if (!test_bit(__IGBVF_DOWN, &adapter->state))
		timeout_add_usec(adapter->uld, 2000000, igbvf_watchdog, (void *)adapter);  
}

#define IGBVF_TX_FLAGS_CSUM             0x00000001
#define IGBVF_TX_FLAGS_VLAN             0x00000002
#define IGBVF_TX_FLAGS_TSO              0x00000004
#define IGBVF_TX_FLAGS_IPV4             0x00000008
#define IGBVF_TX_FLAGS_VLAN_MASK        0xffff0000
#define IGBVF_TX_FLAGS_VLAN_SHIFT       16

#ifdef notdef
static int igbvf_tso(struct igbvf_adapter *adapter,
                     struct igbvf_ring *tx_ring,
                     struct sk_buff *skb, u32 tx_flags, u8 *hdr_len)
{
	struct e1000_adv_tx_context_desc *context_desc;
	unsigned int i;
	int err;
	struct igbvf_buffer *buffer_info;
	u32 info = 0, tu_cmd = 0;
	u32 mss_l4len_idx, l4len;
	*hdr_len = 0;

	if (skb_header_cloned(skb)) {
		err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (err) {
			fprintf(stderr, "igbvf: "
			        "igbvf_tso returning an error\n");
			return err;
		}
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
	} else if (skb_is_gso_v6(skb)) {
		ipv6_hdr(skb)->payload_len = 0;
		tcp_hdr(skb)->check = ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
		                                       &ipv6_hdr(skb)->daddr,
		                                       0, IPPROTO_TCP, 0);
	}

	i = tx_ring->next_to_use;

	buffer_info = &tx_ring->buffer_info[i];
	context_desc = IGBVF_TX_CTXTDESC_ADV(*tx_ring, i);
	/* VLAN MACLEN IPLEN */
	if (tx_flags & IGBVF_TX_FLAGS_VLAN)
		info |= (tx_flags & IGBVF_TX_FLAGS_VLAN_MASK);
	info |= (skb_network_offset(skb) << E1000_ADVTXD_MACLEN_SHIFT);
	*hdr_len += skb_network_offset(skb);
	info |= (skb_transport_header(skb) - skb_network_header(skb));
	*hdr_len += (skb_transport_header(skb) - skb_network_header(skb));
	context_desc->vlan_macip_lens = cpu_to_le32(info);

	/* ADV DTYP TUCMD MKRLOC/ISCSIHEDLEN */
	tu_cmd |= (E1000_TXD_CMD_DEXT | E1000_ADVTXD_DTYP_CTXT);

	if (skb->protocol == htons(ETH_P_IP))
		tu_cmd |= E1000_ADVTXD_TUCMD_IPV4;
	tu_cmd |= E1000_ADVTXD_TUCMD_L4T_TCP;

	context_desc->type_tucmd_mlhl = cpu_to_le32(tu_cmd);

	/* MSS L4LEN IDX */
	mss_l4len_idx = (skb_shinfo(skb)->gso_size << E1000_ADVTXD_MSS_SHIFT);
	mss_l4len_idx |= (l4len << E1000_ADVTXD_L4LEN_SHIFT);

	context_desc->mss_l4len_idx = cpu_to_le32(mss_l4len_idx);
	context_desc->seqnum_seed = 0;

	buffer_info->time_stamp = jiffies();
	buffer_info->next_to_watch = i;
	buffer_info->dma = 0;
	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	return true;
}
#endif

static inline bool igbvf_tx_csum(struct igbvf_adapter *adapter,
                                 struct igbvf_ring *tx_ring,
                                 struct sk_buff *skb, u32 tx_flags)
{
	struct e1000_adv_tx_context_desc *context_desc;
	unsigned int i;
	struct igbvf_buffer *buffer_info;
	u32 info = 0, tu_cmd = 0;

	if ((skb->ip_summed == CHECKSUM_PARTIAL) ||
	    (tx_flags & IGBVF_TX_FLAGS_VLAN)) {
		i = tx_ring->next_to_use;
		buffer_info = &tx_ring->buffer_info[i];
		context_desc = IGBVF_TX_CTXTDESC_ADV(*tx_ring, i);

		if (tx_flags & IGBVF_TX_FLAGS_VLAN)
			info |= (tx_flags & IGBVF_TX_FLAGS_VLAN_MASK);

		info |= (skb_network_offset(skb) << E1000_ADVTXD_MACLEN_SHIFT);
		if (skb->ip_summed == CHECKSUM_PARTIAL)
			info |= (skb_transport_header(skb) -
			         skb_network_header(skb));


		context_desc->vlan_macip_lens = cpu_to_le32(info);

		tu_cmd |= (E1000_TXD_CMD_DEXT | E1000_ADVTXD_DTYP_CTXT);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			switch (skb_ether_protocol(skb)) {
			case ETH_P_IP:
				tu_cmd |= E1000_ADVTXD_TUCMD_IPV4;
				if (skb_ip_protocol(skb) == IPPROTO_TCP)
					tu_cmd |= E1000_ADVTXD_TUCMD_L4T_TCP;
				break;
			case ETH_P_IPV6:
				if (skb_ip_protocol(skb) == IPPROTO_TCP)
					tu_cmd |= E1000_ADVTXD_TUCMD_L4T_TCP;
				break;
			default:
				break;
			}
		}

		context_desc->type_tucmd_mlhl = cpu_to_le32(tu_cmd);
		context_desc->seqnum_seed = 0;
		context_desc->mss_l4len_idx = 0;

		buffer_info->time_stamp = jiffies();
		buffer_info->next_to_watch = i;
		buffer_info->dma = 0;
		i++;
		if (i == tx_ring->count)
			i = 0;
		tx_ring->next_to_use = i;

		return true;
	}

	return false;
}

static int igbvf_maybe_stop_tx(struct igbvf_adapter *adapter, int size)
{

	/* there is enough descriptors then we don't need to worry  */
	if (igbvf_desc_unused(adapter->tx_ring) >= size)
		return 0;

//	netif_stop_queue(netdev);

//	smp_mb();

	/* We need to check again just in case room has been made available */
	if (igbvf_desc_unused(adapter->tx_ring) < size)
		return -EBUSY;

//	netif_wake_queue(netdev);

	++adapter->restart_queue;
	return 0;
}

#define IGBVF_MAX_TXD_PWR       16
#define IGBVF_MAX_DATA_PER_TXD  (1 << IGBVF_MAX_TXD_PWR)

static inline int igbvf_tx_map_adv(struct igbvf_adapter *adapter,
                                   struct igbvf_ring *tx_ring,
                                   struct sk_buff *skb,
                                   unsigned int first)
{
	struct igbvf_buffer *buffer_info;
	unsigned int len = skb->len;
	unsigned int count = 0, i;

	i = tx_ring->next_to_use;

	buffer_info = &tx_ring->buffer_info[i];
	BUG_ON(len >= IGBVF_MAX_DATA_PER_TXD);
	buffer_info->length = len;
	/* set time_stamp *before* dma to help avoid a possible race */
	buffer_info->time_stamp = jiffies();
	buffer_info->next_to_watch = i;
	buffer_info->mapped_as_page = false;
	buffer_info->dma = skb->dma_addr + (skb->data - skb->buf);

#ifdef notdef
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++) {
		struct skb_frag_struct *frag;

		count++;
		i++;
		if (i == tx_ring->count)
			i = 0;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;

		buffer_info = &tx_ring->buffer_info[i];
		BUG_ON(len >= IGBVF_MAX_DATA_PER_TXD);
		buffer_info->length = len;
		buffer_info->time_stamp = jiffies();
		buffer_info->next_to_watch = i;
		buffer_info->mapped_as_page = true;
		buffer_info->dma = pci_map_page(pdev,
						frag->page,
						frag->page_offset,
						len,
						PCI_DMA_TODEVICE);
		if (pci_dma_mapping_error(pdev, buffer_info->dma))
			goto dma_error;
	}
#endif

	tx_ring->buffer_info[i].skb = skb;
	tx_ring->buffer_info[first].next_to_watch = i;

	return ++count;

#ifdef notdef
dma_error:
	fprintf(stderr, "igbvf: " "TX DMA map failed\n");

	/* clear timestamp and dma mappings for failed buffer_info mapping */
	buffer_info->dma = 0;
	buffer_info->time_stamp = 0;
	buffer_info->length = 0;
	buffer_info->next_to_watch = 0;
	buffer_info->mapped_as_page = false;
	if (count)
		count--;

	/* clear timestamp and dma mappings for remaining portion of packet */
	while (count--) {
		if (i==0)
			i += tx_ring->count;
		i--;
		buffer_info = &tx_ring->buffer_info[i];
		igbvf_put_txbuf(adapter, buffer_info);
	}

	return 0;
#endif
}

static inline void igbvf_tx_queue_adv(struct igbvf_adapter *adapter,
                                      struct igbvf_ring *tx_ring,
                                      int tx_flags, int count, u32 paylen,
                                      u8 hdr_len)
{
	union e1000_adv_tx_desc *tx_desc = NULL;
	struct igbvf_buffer *buffer_info;
	u32 olinfo_status = 0, cmd_type_len;
	unsigned int i;

	cmd_type_len = (E1000_ADVTXD_DTYP_DATA | E1000_ADVTXD_DCMD_IFCS |
	                E1000_ADVTXD_DCMD_DEXT);

	if (tx_flags & IGBVF_TX_FLAGS_VLAN)
		cmd_type_len |= E1000_ADVTXD_DCMD_VLE;

	if (tx_flags & IGBVF_TX_FLAGS_TSO) {
		cmd_type_len |= E1000_ADVTXD_DCMD_TSE;

		/* insert tcp checksum */
		olinfo_status |= E1000_TXD_POPTS_TXSM << 8;

		/* insert ip checksum */
		if (tx_flags & IGBVF_TX_FLAGS_IPV4)
			olinfo_status |= E1000_TXD_POPTS_IXSM << 8;

	} else if (tx_flags & IGBVF_TX_FLAGS_CSUM) {
		olinfo_status |= E1000_TXD_POPTS_TXSM << 8;
	}

	olinfo_status |= ((paylen - hdr_len) << E1000_ADVTXD_PAYLEN_SHIFT);

	i = tx_ring->next_to_use;
	while (count--) {
		buffer_info = &tx_ring->buffer_info[i];
		tx_desc = IGBVF_TX_DESC_ADV(*tx_ring, i);
		tx_desc->read.buffer_addr = cpu_to_le64(buffer_info->dma);
		tx_desc->read.cmd_type_len =
		         cpu_to_le32(cmd_type_len | buffer_info->length);
		tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
		i++;
		if (i == tx_ring->count)
			i = 0;
	}

	tx_desc->read.cmd_type_len |= cpu_to_le32(adapter->txd_cmd);
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64). */
	wmb();

	tx_ring->next_to_use = i;
	writel(i, adapter->hw.hw_addr + tx_ring->tail);
#ifdef notdef
	/* we need this if more than one processor can write to our tail
	 * at a time, it syncronizes IO on IA64/Altix systems */
	mmiowb();
#endif
}

static int igbvf_xmit_frame_ring_adv(struct sk_buff *skb,
		struct igbvf_adapter *adapter,
		struct igbvf_ring *tx_ring)
{
	unsigned int first, tx_flags = 0;
	u8 hdr_len = 0;
	int count = 0;

	if (test_bit(__IGBVF_DOWN, &adapter->state)) {
		skb_free(skb);
		return 0;
	}

	if (skb->len <= 0) {
		skb_free(skb);
		return 0;
	}

	/*
	 * need: count + 4 desc gap to keep tail from touching
         *       + 2 desc gap to keep tail from touching head,
         *       + 1 desc for skb->data,
         *       + 1 desc for context descriptor,
	 * head, otherwise try next time
	 */
	if (igbvf_maybe_stop_tx(adapter, 5)) {
		/* this is a hard error */
		return -EBUSY;
	}

#ifdef notdef
	if (adapter->vlgrp && vlan_tx_tag_present(skb)) {
		tx_flags |= IGBVF_TX_FLAGS_VLAN;
		tx_flags |= (vlan_tx_tag_get(skb) << IGBVF_TX_FLAGS_VLAN_SHIFT);
	}
#endif

	if (skb_ether_protocol(skb) == ETH_P_IP)
		tx_flags |= IGBVF_TX_FLAGS_IPV4;

	first = tx_ring->next_to_use;

#ifdef notdef
	tso = skb_is_gso(skb) ?
		igbvf_tso(adapter, tx_ring, skb, tx_flags, &hdr_len) : 0;
	if (unlikely(tso < 0)) {
		skb_free(skb);
		return 0;
	}

	if (tso)
		tx_flags |= IGBVF_TX_FLAGS_TSO;
	else
#endif
	if (igbvf_tx_csum(adapter, tx_ring, skb, tx_flags) &&
	         (skb->ip_summed == CHECKSUM_PARTIAL))
		tx_flags |= IGBVF_TX_FLAGS_CSUM;

	/*
	 * count reflects descriptors mapped, if 0 then mapping error
	 * has occured and we need to rewind the descriptor queue
	 */
	count = igbvf_tx_map_adv(adapter, tx_ring, skb, first);

	if (count) {
		igbvf_tx_queue_adv(adapter, tx_ring, tx_flags, count,
		                   skb->len, hdr_len);
		/* Make sure there is space in the ring for the next send. */
		igbvf_maybe_stop_tx(adapter, 1 + 4);
	} else {
		skb_free(skb);
		tx_ring->buffer_info[first].time_stamp = 0;
		tx_ring->next_to_use = first;
	}

	return 0;
}

int igbvf_skb_write(struct uld *uld, struct sk_buff *skb)
{
	struct igbvf_adapter *adapter = uld->nicpriv;
	struct igbvf_ring *tx_ring;

	if (test_bit(__IGBVF_DOWN, &adapter->state)) {
		skb_free(skb);
		return 0;
	}

	tx_ring = &adapter->tx_ring[0];

	return igbvf_xmit_frame_ring_adv(skb, adapter, tx_ring);
}

#ifdef notdef
/**
 * igbvf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void igbvf_tx_timeout(struct net_device *netdev)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	/* Do the reset outside of interrupt context */
	adapter->tx_timeout_count++;
	schedule_work(&adapter->reset_task);
}
#endif

static void igbvf_reset_task(struct igbvf_adapter *adapter)
{

	igbvf_reinit_locked(adapter);
}

#ifdef notdef
/**
 * igbvf_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the timer callback.
 **/
static struct net_device_stats *igbvf_get_stats(struct net_device *netdev)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	/* only return the current stats */
	return &adapter->net_stats;
}
#endif

#ifdef notdef
/**
 * igbvf_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int igbvf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	if ((new_mtu < 68) || (max_frame > MAX_JUMBO_FRAME_SIZE)) {
		fprintf(stderr, "igbvf: " "Invalid MTU setting\n");
		return -EINVAL;
	}

#define MAX_STD_JUMBO_FRAME_SIZE 9234
	if (max_frame > MAX_STD_JUMBO_FRAME_SIZE) {
		fprintf(stderr, "igbvf: " "MTU > 9216 not supported.\n");
		return -EINVAL;
	}

	while (test_and_set_bit(__IGBVF_RESETTING, &adapter->state))
		msleep(1);
	/* igbvf_down has a dependency on max_frame_size */
	adapter->max_frame_size = max_frame;
	if (netif_running(netdev))
		igbvf_down(adapter);

	/*
	 * NOTE: netdev_alloc_skb reserves 16 bytes, and typically NET_IP_ALIGN
	 * means we reserve 2 more, this pushes us to allocate from the next
	 * larger slab size.
	 * i.e. RXBUFFER_2048 --> size-4096 slab
	 * However with the new *_jumbo_rx* routines, jumbo receives will use
	 * fragmented skbs
	 */

	if (max_frame <= 1024)
		adapter->rx_buffer_len = 1024;
	else if (max_frame <= 2048)
		adapter->rx_buffer_len = 2048;
	else
#if (PAGE_SIZE / 2) > 16384
		adapter->rx_buffer_len = 16384;
#else
		adapter->rx_buffer_len = PAGE_SIZE / 2;
#endif


	/* adjust allocation if LPE protects us, and we aren't using SBP */
	if ((max_frame == ETH_FRAME_LEN + ETH_FCS_LEN) ||
	     (max_frame == ETH_FRAME_LEN + VLAN_HLEN + ETH_FCS_LEN))
		adapter->rx_buffer_len = ETH_FRAME_LEN + VLAN_HLEN +
		                         ETH_FCS_LEN;

	fprintf(stderr, "igbvf: " "changing MTU from %d to %d\n",
	         netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		igbvf_up(adapter);
	else
		igbvf_reset(adapter);

	clear_bit(__IGBVF_RESETTING, &adapter->state);

	return 0;
}
#endif

#ifdef notdef
static int igbvf_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct igbvf_adapter *adapter = netdev_priv(netdev);
#ifdef CONFIG_PM
	int retval = 0;
#endif

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		WARN_ON(test_bit(__IGBVF_RESETTING, &adapter->state));
		igbvf_down(adapter);
		igbvf_free_irq(adapter);
	}

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;
#endif

	pci_disable_device(pdev);

	return 0;
}
#endif

#ifdef notdef
#ifdef CONFIG_PM
static int igbvf_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct igbvf_adapter *adapter = netdev_priv(netdev);
	u32 err;

	pci_restore_state(pdev);
	err = pci_enable_device_mem(pdev);
	if (err) {
		fprintf(stderr, "igbvf: " "Cannot enable PCI device from suspend\n");
		return err;
	}

	pci_set_master(pdev);

	if (netif_running(netdev)) {
		err = igbvf_request_irq(adapter);
		if (err)
			return err;
	}

	igbvf_reset(adapter);

	if (netif_running(netdev))
		igbvf_up(adapter);

	netif_device_attach(netdev);

	return 0;
}
#endif
#endif

#ifdef notdef
static void igbvf_shutdown(struct pci_dev *pdev)
{
	igbvf_suspend(pdev, PMSG_SUSPEND);
}
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void igbvf_netpoll(struct net_device *netdev)
{
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	disable_irq(adapter->pdev->irq);

	igbvf_clean_tx_irq(adapter->tx_ring);

	enable_irq(adapter->pdev->irq);
}
#endif

#ifdef notdef
/**
 * igbvf_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t igbvf_io_error_detected(struct pci_dev *pdev,
                                                pci_channel_state_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	if (netif_running(netdev))
		igbvf_down(adapter);
	pci_disable_device(pdev);

	/* Request a slot slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * igbvf_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the igbvf_resume routine.
 */
static pci_ers_result_t igbvf_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	if (pci_enable_device_mem(pdev)) {
		fprintf(stderr, "igbvf: "
			"Cannot re-enable PCI device after reset.\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}
	pci_set_master(pdev);

	igbvf_reset(adapter);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * igbvf_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the igbvf_resume routine.
 */
static void igbvf_io_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct igbvf_adapter *adapter = netdev_priv(netdev);

	if (netif_running(netdev)) {
		if (igbvf_up(adapter)) {
			fprintf(stderr, "igbvf: "
				"can't bring device back up after reset\n");
			return;
		}
	}

	netif_device_attach(netdev);
}
#endif

static void igbvf_print_device_info(struct igbvf_adapter *adapter)
{
	fprintf(stderr, "igbvf: " "Intel(R) 82576 Virtual Function\n");
	fprintf(stderr, "igbvf: " "Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	         /* MAC address */
	         adapter->hw.mac.addr[0], adapter->hw.mac.addr[1],
	         adapter->hw.mac.addr[2], adapter->hw.mac.addr[3],
	         adapter->hw.mac.addr[4], adapter->hw.mac.addr[5]);
}

/**
 * igbvf_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in igbvf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * igbvf_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int igbvf_probe(struct uld *uld)
{
	struct igbvf_adapter *adapter;
	struct e1000_hw *hw;
	const struct igbvf_info *ei = igbvf_info_tbl[0];

	static int cards_found;
	int err;

	pci_set_master(uld->fd);

	err = -ENOMEM;

	adapter = calloc(1, sizeof *adapter);
	if (adapter == NULL)
		goto err_dma;

	hw = &adapter->hw;
	adapter->uld = uld;
	uld->nicpriv = adapter;
	adapter->ei = ei;
	adapter->pba = ei->pba;
	adapter->flags = ei->flags;
	adapter->hw.back = adapter;
	adapter->hw.mac.type = ei->mac;

	/* PCI config space info */

	hw->vendor_id = pci_read_config_word(adapter->uld->fd, PCI_VENDOR_ID);
	hw->device_id = pci_read_config_word(adapter->uld->fd, PCI_DEVICE_ID);
	hw->revision_id = pci_read_config_byte(adapter->uld->fd, PCI_REVISION_ID);
	hw->subsystem_vendor_id = pci_read_config_word(adapter->uld->fd, PCI_SUBSYSTEM_VENDOR_ID);
	hw->subsystem_device_id = pci_read_config_word(adapter->uld->fd, PCI_SUBSYSTEM_ID);

	err = -EIO;
	adapter->hw.hw_addr = pci_mmap_bar(uld->fd, 0, 1);

	if (!adapter->hw.hw_addr)
		goto err_ioremap;

	if (ei->get_variants) {
		err = ei->get_variants(adapter);
		if (err)
			goto err_ioremap;
	}

	/* setup adapter struct */
	err = igbvf_sw_init(adapter);
	if (err)
		goto err_sw_init;

	adapter->bd_number = cards_found++;

	/*reset the controller to put the device in a known good state */
	err = hw->mac.ops.reset_hw(hw);
	if (err) {
		fprintf(stderr, "igbvf: "
			 "PF still in reset state, assigning new address."
			 " Is the PF interface up?\n");
		random_ether_addr(hw->mac.addr);
	} else {
		err = hw->mac.ops.read_mac_addr(hw);
		if (err) {
			fprintf(stderr, "igbvf: " "Error reading MAC address\n");
			goto err_hw_init;
		}
	}

	memcpy(uld->mac, adapter->hw.mac.addr, 6);

	if (!is_valid_ether_addr(uld->mac)) {
		fprintf(stderr, "igbvf: " "Invalid MAC Address: "
		        "%02x:%02x:%02x:%02x:%02x:%02x\n",
		        uld->mac[0], uld->mac[1],
		        uld->mac[2], uld->mac[3],
		        uld->mac[4], uld->mac[5]);
		err = -EIO;
		goto err_hw_init;
	}

	/* ring size defaults */
	adapter->rx_ring->count = 1024;
	adapter->tx_ring->count = 1024;

	/* reset the hardware with the new settings */
	igbvf_reset(adapter);

	igbvf_print_device_info(adapter);

	igbvf_initialize_last_counter_stats(adapter);

	return 0;

err_hw_init:
	free(adapter->tx_ring);
	free(adapter->rx_ring);
err_sw_init:
	igbvf_reset_interrupt_capability(adapter);
	pci_munmap_bar(uld->fd, 0, (void *)adapter->hw.hw_addr);
err_ioremap:
//	pci_release_regions(pdev);
err_dma:
//	pci_disable_device(pdev);
	return err;
}

/**
 * igbvf_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * igbvf_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void igbvf_remove(struct igbvf_adapter *adapter)
{

	set_bit(__IGBVF_DOWN, &adapter->state);
	timeout_cancel(adapter->uld, igbvf_watchdog, (void *)adapter);

	igbvf_reset_interrupt_capability(adapter);

	/*
	 * it is important to delete the napi struct prior to freeing the
	 * rx ring so that you do not end up with null pointer refs
	 */
//	netif_napi_del(&adapter->rx_ring->napi);
	free(adapter->tx_ring);
	free(adapter->rx_ring);

	pci_munmap_bar(adapter->uld->fd, 0, (void *)adapter->hw.hw_addr);
}

void *igbvf_uld_open(struct uld *uld)
{
	int err;
	struct igbvf_adapter *adapter;

	err = igbvf_probe(uld);
	if (err)
		return NULL;
	adapter = uld->nicpriv;
	err = igbvf_open(adapter);
	if (err)
		return NULL;
	return adapter;
}

void igbvf_uld_close(struct uld *uld)
{
	struct igbvf_adapter *adapter = uld->nicpriv;

	igbvf_close(adapter);
	igbvf_remove(adapter);
}

struct sk_buff *igbvf_skb_read(struct uld *uld, int sync)
{

	struct igbvf_adapter *adapter = uld->nicpriv;
	struct e1000_hw *hw = &adapter->hw;
	struct sk_buff *skb = NULL;
	int work_done;
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
	work_done = 0;
	(void) igbvf_clean_rx_irq(adapter, &work_done, 50);
	if (adapter->skb_recv_head)
		goto top;
	ew32(EIMS, adapter->rx_ring->eims_value);

	n = poll(adapter->msix_entries, 3, sync ? -1 : 0);
	if (n < 0)
		perror("igbvf_skb_read poll");
	if (n > 0) {
		if (adapter->msix_entries[IGBVF_MSIX_OTHER].revents & POLLIN) {
			(void) read(adapter->msix_entries[IGBVF_MSIX_OTHER].fd,
					&count, sizeof count);
			igbvf_msix_other(adapter);
		}
		if (adapter->msix_entries[IGBVF_MSIX_WQ].revents & POLLIN) {
			(void) read(adapter->msix_entries[IGBVF_MSIX_WQ].fd,
					&count, sizeof count);
			igbvf_msix_tx(adapter);
		}
		if (adapter->msix_entries[IGBVF_MSIX_RQ].revents & POLLIN) {
			(void) read(adapter->msix_entries[IGBVF_MSIX_RQ].fd,
					&count, sizeof count);
		}
		goto top;
	}
out:
	if (uld->threaded)
		pthread_mutex_unlock(&adapter->skb_read_lock);
	return skb;
}
