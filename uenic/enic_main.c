/*
 * Copyright 2008-2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
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

#include <errno.h>
#include <poll.h>
#include <string.h>

#include "../uld/kcompat.h"
#include "../uld/skbuff.h"
#include "../uld/uld.h"

#include "wq_enet_desc.h"
#include "rq_enet_desc.h"
#include "cq_enet_desc.h"
#include "vnic_resource.h"
#include "vnic_enet.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_nic.h"
#include "vnic_rss.h"
#include "enic_res.h"
#include "enic.h"
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/types.h>

#include <sys/time.h>
#include <netlink/netlink.h>

#include "../vfio/vfio_lib.h"

#ifdef notdef
static void enic_free_rq_buf(struct vnic_rq *rq, struct vnic_rq_buf *buf)
{
	struct enic *enic = vnic_dev_priv(rq->vdev);
	struct sk_buff *skb = buf->os_buf;

	if (!skb)
		return;

	skb_free(skb);
}
#endif

static inline struct sk_buff *enic_rq_alloc_skb(struct uld *uld, unsigned int size)
{
	struct sk_buff *skb;

	skb = skb_alloc(uld);

	if (skb) {
		skb_pull(skb, NET_IP_ALIGN);
	}

	return skb;
}

static int enic_rq_alloc_buf(struct vnic_rq *rq)
{
	struct enic *enic = vnic_dev_priv(rq->vdev);
	struct sk_buff *skb;
	unsigned int len;
	unsigned int os_buf_index = 0;
	dma_addr_t dma_addr;

	len = enic->mtu + ETH_HLEN;
	skb = enic_rq_alloc_skb(enic->uld, len);
	if (!skb)
		return -ENOMEM;

	dma_addr = (skb->data - skb->buf) + skb->dma_addr;
	enic_queue_rq_desc(rq, skb, os_buf_index,
		dma_addr, len);

	return 0;
}

static int enic_rq_alloc_buf_a1(struct vnic_rq *rq)
{
	struct rq_enet_desc *desc = vnic_rq_next_desc(rq);

	if (vnic_rq_posting_soon(rq)) {

		/* SW workaround for A0 HW erratum: if we're just about
		 * to write posted_index, insert a dummy desc
		 * of type resvd
		 */

		rq_enet_desc_enc(desc, 0, RQ_ENET_TYPE_RESV2, 0);
		vnic_rq_post(rq, 0, 0, 0, 0);
	} else {
		return enic_rq_alloc_buf(rq);
	}

	return 0;
}

static int enic_set_rq_alloc_buf(struct enic *enic)
{
	enum vnic_dev_hw_version hw_ver;
	int err;

	err = vnic_dev_hw_version(enic->vdev, &hw_ver);
	if (err)
		return err;

	switch (hw_ver) {
	case VNIC_DEV_HW_VER_A1:
		enic->rq_alloc_buf = enic_rq_alloc_buf_a1;
		break;
	case VNIC_DEV_HW_VER_A2:
	case VNIC_DEV_HW_VER_UNKNOWN:
		enic->rq_alloc_buf = enic_rq_alloc_buf;
		break;
	default:
		return -ENODEV;
	}

	return 0;
}

static void enic_rq_indicate_buf(struct vnic_rq *rq,
	struct cq_desc *cq_desc, struct vnic_rq_buf *buf,
	int skipped, void *opaque)
{
	struct enic *enic = vnic_dev_priv(rq->vdev);
	struct sk_buff *skb;

	u8 type, color, eop, sop, ingress_port, vlan_stripped;
	u8 fcoe, fcoe_sof, fcoe_fc_crc_ok, fcoe_enc_error, fcoe_eof;
	u8 tcp_udp_csum_ok, udp, tcp, ipv4_csum_ok;
	u8 ipv6, ipv4, ipv4_fragment, fcs_ok, rss_type, csum_not_calc;
	u8 packet_error;
	u16 q_number, completed_index, bytes_written, vlan, checksum;
	u32 rss_hash;

	if (skipped)
		return;

	skb = buf->os_buf;

	cq_enet_rq_desc_dec((struct cq_enet_rq_desc *)cq_desc,
		&type, &color, &q_number, &completed_index,
		&ingress_port, &fcoe, &eop, &sop, &rss_type,
		&csum_not_calc, &rss_hash, &bytes_written,
		&packet_error, &vlan_stripped, &vlan, &checksum,
		&fcoe_sof, &fcoe_fc_crc_ok, &fcoe_enc_error,
		&fcoe_eof, &tcp_udp_csum_ok, &udp, &tcp,
		&ipv4_csum_ok, &ipv6, &ipv4, &ipv4_fragment,
		&fcs_ok);

	if (packet_error) {
fprintf(stderr, "enic_rq_indicate err bytes %d fcs_ok %d\n", bytes_written, fcs_ok);
		if (bytes_written > 0 && !fcs_ok)
			enic->rq_bad_fcs++;

		skb_free(skb);
		return;
	}

	if (eop && bytes_written > 0) {

		/* Good receive
		 */

		skb->len = bytes_written;

		if (enic->csum_rx_enabled && !csum_not_calc) {
			skb->csum = htons(checksum);
			skb->ip_summed = CHECKSUM_COMPLETE;
		}

		clock_gettime(CLOCK_REALTIME, &skb->tstamp);

		if (enic->skb_recv_head) {
			enic->skb_recv_tail->next = skb;
			enic->skb_recv_tail = skb;
		} else {
			enic->skb_recv_head = skb;
			enic->skb_recv_tail = skb;
		}

	} else {

		/* Buffer overflow
		 */

		skb_free(skb);
	}
}

static int enic_rq_service(struct vnic_dev *vdev, struct cq_desc *cq_desc,
	u8 type, u16 q_number, u16 completed_index, void *opaque)
{
	struct enic *enic = vnic_dev_priv(vdev);

	vnic_rq_service(&enic->rq[q_number], cq_desc,
		completed_index, VNIC_RQ_RETURN_DESC,
		enic_rq_indicate_buf, opaque);

	return 0;
}

static void enic_free_wq_buf(struct vnic_wq *wq, struct vnic_wq_buf *buf)
{
//	struct enic *enic = vnic_dev_priv(wq->vdev);

if (buf->dma_addr == 0 || !buf->os_buf)
printk(KERN_ERR "enic_free_wq_buf bad \n");

	if (buf->os_buf) {
		skb_free(buf->os_buf);
		buf->os_buf = NULL;
	}
}

static void enic_wq_free_buf(struct vnic_wq *wq,
	struct cq_desc *cq_desc, struct vnic_wq_buf *buf, void *opaque)
{
	enic_free_wq_buf(wq, buf);
}

static int enic_wq_service(struct vnic_dev *vdev, struct cq_desc *cq_desc,
	u8 type, u16 q_number, u16 completed_index, void *opaque)
{
	struct enic *enic = vnic_dev_priv(vdev);

#ifdef notdef
	spin_lock(&enic->wq_lock[q_number]);
#endif

	vnic_wq_service(&enic->wq[q_number], cq_desc,
		completed_index, enic_wq_free_buf,
		opaque);
#ifdef notyet
	if (netif_queue_stopped(enic->netdev) &&
	    vnic_wq_desc_avail(&enic->wq[q_number]) >=
	    (MAX_SKB_FRAGS + ENIC_DESC_MAX_SPLITS))
		netif_wake_queue(enic->netdev);
#endif
#ifdef notdef
	spin_unlock(&enic->wq_lock[q_number]);
#endif

	return 0;
}

static void enic_link_check(struct enic *enic)
{
	int link_status = vnic_dev_link_status(enic->vdev);
	int carrier_ok = enic->uld->linkup;
	int speed;

	if (link_status && !carrier_ok) {
		speed = vnic_dev_port_speed(enic->vdev);
		printk(KERN_INFO PFX "%s: Link UP, Speed %d\n", enic->uld->pciname, speed);
		enic->uld->linkup = 1;
	} else if (!link_status && carrier_ok) {
		printk(KERN_INFO PFX "%s: Link DOWN\n", enic->uld->pciname);
		enic->uld->linkup = 0;
	}
}

static void enic_notify_check(struct enic *enic)
{
	enic_link_check(enic);
}

static void enic_notify_timeout(void *arg)
{
	struct enic *enic = (struct enic *)arg;

	enic_notify_check(enic);
	timeout_add_usec(enic->uld, 500000, enic_notify_timeout, arg);
}

static int enic_poll_wq(struct enic *enic, int budget)
{
	unsigned int  work_done;

	work_done = vnic_cq_service(&enic->cq[ENIC_CQ_WQ],
		budget, enic_wq_service, NULL);

	if (work_done > 0)
		vnic_intr_return_credits(&enic->intr[ENIC_INTX_WQ_RQ],
			work_done,
			0 /* don't unmask intr */,
			0 /* don't reset intr timer */);

	return work_done;
}

static void enic_isr_msix_err(struct enic *enic)
{
	vnic_intr_return_all_credits(&enic->intr[ENIC_MSIX_ERR]);

	fprintf(stderr, "enic: received error interrupt\n");
}

static void enic_isr_msix_notify(struct enic *enic)
{

	vnic_intr_return_all_credits(&enic->intr[ENIC_MSIX_NOTIFY]);
	enic_notify_check(enic);
}

static int enic_poll(struct enic *enic, int budget)
{
	unsigned int rq_work_to_do = budget;
	unsigned int  work_done, rq_work_done;

	/* Service RQ (first) and WQ
	 */

	rq_work_done = vnic_cq_service(&enic->cq[ENIC_CQ_RQ],
		rq_work_to_do, enic_rq_service, NULL);

#ifdef notdef
	wq_work_done = vnic_cq_service(&enic->cq[ENIC_CQ_WQ],
		wq_work_to_do, enic_wq_service, NULL);
	/* Accumulate intr event credits for this polling
	 * cycle.  An intr event is the completion of a
	 * a WQ or RQ packet.
	 */

	work_done = rq_work_done + wq_work_done;
#else
	work_done = rq_work_done;
#endif

	if (work_done > 0)
		vnic_intr_return_credits(&enic->intr[ENIC_INTX_WQ_RQ],
			work_done,
			0 /* don't unmask intr */,
			0 /* don't reset intr timer */);

	if (rq_work_done > 0) {

		/* Replenish RQ
		 */

		vnic_rq_fill(&enic->rq[0], enic->rq_alloc_buf);
	}

	return rq_work_done;
}

struct sk_buff *enic_skb_read(struct uld *uld, int sync)
{
	struct enic *enic = uld->nicpriv;
	struct sk_buff *skb = NULL;

	if (uld->threaded) {
		if (sync)
			pthread_mutex_lock(&enic->skb_read_lock);
		else if (pthread_mutex_trylock(&enic->skb_read_lock))
			return NULL;
	}
top:
	if (enic->skb_recv_head) {
		skb = enic->skb_recv_head;
		enic->skb_recv_head = skb->next;
		skb->next = NULL;
		goto out;
	}
	if (enic_poll(enic, -1))
		goto top;
	if (sync) {
		unsigned long long count;
		int n;

		vnic_intr_unmask(&enic->intr[ENIC_MSIX_RQ]);
		vnic_intr_unmask(&enic->intr[ENIC_MSIX_WQ]);

		if (uld->nl_handle) {
			enic->pollfds[ENIC_POLLFD_NETLINK].fd = nl_socket_get_fd(uld->nl_handle);
			enic->pollfds[ENIC_POLLFD_NETLINK].events = POLLIN;
			n = poll(enic->pollfds, ENIC_POLLFDS, -1);
		} else {
			n = poll(enic->pollfds, ENIC_POLLFDS-1, -1);
		}
		if (n < 0)
			perror("enic_skb_read poll");
		if (enic->pollfds[ENIC_POLLFD_NETLINK].revents & POLLIN) {
			if (uld->nl_handle)
				nl_recvmsgs_default(uld->nl_handle);
		}
		if (enic->pollfds[ENIC_POLLFD_ERR].revents & POLLIN) {
			(void) read(enic->pollfds[ENIC_POLLFD_ERR].fd, &count, sizeof count);
			enic_isr_msix_err(enic);
		}
		if (enic->pollfds[ENIC_POLLFD_NOTIFY].revents & POLLIN) {
			(void) read(enic->pollfds[ENIC_POLLFD_NOTIFY].fd, &count, sizeof count);
			enic_isr_msix_notify(enic);
		}
		if (enic->pollfds[ENIC_POLLFD_WQ].revents & POLLIN) {
			(void) read(enic->pollfds[ENIC_POLLFD_WQ].fd, &count, sizeof count);
			enic_poll_wq(enic, (unsigned)-1);
		}
		if (enic->pollfds[ENIC_POLLFD_RQ].revents & POLLIN) {
			(void) read(enic->pollfds[ENIC_POLLFD_RQ].fd, &count, sizeof count);
		}
		goto top;
	}
out:
	if (uld->threaded)
		pthread_mutex_unlock(&enic->skb_read_lock);
	return skb;
}

static inline void enic_queue_wq_skb_vlan(struct enic *enic,
	struct vnic_wq *wq, struct sk_buff *skb,
	int vlan_tag_insert, unsigned int vlan_tag)
{
	int eop = 1;
	dma_addr_t dma_addr;

	dma_addr = skb->dma_addr + (skb->data - skb->buf);
	enic_queue_wq_desc(wq, skb, dma_addr, skb->len,
			vlan_tag_insert, vlan_tag, eop);
}

static inline void enic_queue_wq_skb_csum_l4(struct enic *enic,
	struct vnic_wq *wq, struct sk_buff *skb,
	int vlan_tag_insert, unsigned int vlan_tag)
{
	unsigned int hdr_len = (skb->transport_hdr - skb->data);
	unsigned int csum_offset = hdr_len + skb->csum_offset;
	int eop = 1;
	dma_addr_t dma_addr;

	dma_addr = skb->dma_addr + (skb->data - skb->buf);
	enic_queue_wq_desc_csum_l4(wq, skb,
		dma_addr,
		skb->len,
		csum_offset, hdr_len,
		vlan_tag_insert, vlan_tag,
		eop);

}

static inline void enic_queue_wq_skb(struct enic *enic,
	struct vnic_wq *wq, struct sk_buff *skb)
{
	unsigned int vlan_tag = 0;
	int vlan_tag_insert = 0;

#ifdef notdef
	if (enic->vlan_group && vlan_tx_tag_present(skb)) {
		/* VLAN tag from trunking driver */
		vlan_tag_insert = 1;
		vlan_tag = vlan_tx_tag_get(skb);
	}
#endif

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		enic_queue_wq_skb_csum_l4(enic, wq, skb,
			vlan_tag_insert, vlan_tag);
	} else {
		enic_queue_wq_skb_vlan(enic, wq, skb,
			vlan_tag_insert, vlan_tag);
	}
}

int enic_skb_write(struct uld *uld, struct sk_buff *skb)
{
	struct enic *enic = uld->nicpriv;
	struct vnic_wq *wq = &enic->wq[0];
	int ret = 0;
	int count;
	struct sk_buff *s, *next;

	for (s = skb, count=0; s; s = s->next)
		count++;
	spin_lock(&enic->wq_lock[0]);
	if (vnic_wq_desc_avail(wq) < count) {
		enic_poll_wq(enic, count+10);
		if (vnic_wq_desc_avail(wq) < count) {
			ret = -EBUSY;
			goto out;
		}
	}
	for (count=0; skb; count++) {
		next = skb->next;
		skb->next = 0;
		if (skb->len <= 0)
			skb_free(skb);
		else
			enic_queue_wq_skb(enic, wq, skb);
		skb = next;
	}
out:
	spin_unlock(&enic->wq_lock[0]);
	return ret;
}

static int enic_dev_wait(struct vnic_dev *vdev,
	int (*start)(struct vnic_dev *, int),
	int (*finished)(struct vnic_dev *, int *),
	int arg)
{
	unsigned long time;
	int done;
	int err;
	struct timeval tv;
	int nsleep = 10;

///	BUG_ON(in_interrupt());

	err = start(vdev, arg);
	if (err)
		return err;

	/* Wait for func to complete...2 seconds max
	 */
	gettimeofday(&tv, NULL);

	time = tv.tv_sec + 2;
	do {

		err = finished(vdev, &done);
		if (err)
			return err;

		if (done)
			return 0;

		nsleep *= 2;
		if (nsleep > 100000)
			nsleep = 100000;
		udelay(nsleep);
		gettimeofday(&tv, NULL);
	} while (time >= tv.tv_sec);

	return -ETIMEDOUT;
}

static int enic_dev_open(struct enic *enic)
{
	int err;

	err = enic_dev_wait(enic->vdev, vnic_dev_open,
		vnic_dev_open_done, 0);
	if (err)
		printk(KERN_ERR PFX
			"vNIC device open failed, err %d.\n", err);

	return err;
}

static int enic_set_intr_mode(struct enic *enic)
{
	unsigned int i;
	int *arg;

	/* Set interrupt mode (INTx, MSI, MSI-X) depending
	 * system capabilities.
	 *
	 * Try MSI-X first
	 *
	 * We need n RQs, m WQs, n+m CQs, and n+m+2 INTRs
	 * (the second to last INTR is used for WQ/RQ errors)
	 * (the last INTR is used for notifications)
	 */
	if (enic->config.intr_mode < 1 &&
	    enic->rq_count >= 1 &&
	    enic->wq_count >= 1 &&
	    enic->cq_count >= 2 &&
	    enic->intr_count >= 4) {
		enic->rq_count = 1;
		enic->wq_count = 1;
		enic->cq_count = 2;
		enic->intr_count = 4;

		arg = calloc(enic->intr_count + 1, sizeof(int));
		arg[0] = enic->intr_count;
		for (i=0; i<enic->intr_count; i++)
			arg[i+1] = eventfd(0, 0);

		if (ioctl(enic->uld->fd, VFIO_EVENTFDS_MSIX, arg) < 0)
			perror("VFIO_EVENTFDS_MSIX");

		enic->pollfds[ENIC_POLLFD_RQ].fd = arg[1];
		enic->pollfds[ENIC_POLLFD_RQ].events = POLLIN;
		enic->pollfds[ENIC_POLLFD_WQ].fd = arg[2];
		enic->pollfds[ENIC_POLLFD_WQ].events = POLLIN;
		enic->pollfds[ENIC_POLLFD_ERR].fd = arg[3];
		enic->pollfds[ENIC_POLLFD_ERR].events = POLLIN;
		enic->pollfds[ENIC_POLLFD_NOTIFY].fd = arg[4];
		enic->pollfds[ENIC_POLLFD_NOTIFY].events = POLLIN;

		vnic_dev_set_intr_mode(enic->vdev, VNIC_DEV_INTR_MODE_MSIX);
		return 0;
	}

#ifdef UENIC_INTX_MSI

	/* Next try MSI
	 *
	 * We need 1 RQ, 1 WQ, 2 CQs, and 1 INTR
	 */

	if (enic->config.intr_mode < 2 &&
	    enic->rq_count >= 1 &&
	    enic->wq_count >= 1 &&
	    enic->cq_count >= 2 &&
	    enic->intr_count >= 1) {

		enic->rq_count = 1;
		enic->wq_count = 1;
		enic->cq_count = 2;
		enic->intr_count = 1;

		vnic_dev_set_intr_mode(enic->vdev, VNIC_DEV_INTR_MODE_MSI);

		return 0;
	}
#endif
#ifdef UENIC_INTX_IRQ
	/* Next try INTx
	 *
	 * We need 1 RQ, 1 WQ, 2 CQs, and 3 INTRs
	 * (the first INTR is used for WQ/RQ)
	 * (the second INTR is used for WQ/RQ errors)
	 * (the last INTR is used for notifications)
	 */

	if (enic->config.intr_mode < 3 &&
	    enic->rq_count >= 1 &&
	    enic->wq_count >= 1 &&
	    enic->cq_count >= 2 &&
	    enic->intr_count >= 3) {

		enic->rq_count = 1;
		enic->wq_count = 1;
		enic->cq_count = 2;
		enic->intr_count = 3;

		vnic_dev_set_intr_mode(enic->vdev, VNIC_DEV_INTR_MODE_INTX);

		return 0;
	}
#endif
fprintf(stderr, "enic_set_intr_mode: fail\n");

	vnic_dev_set_intr_mode(enic->vdev, VNIC_DEV_INTR_MODE_UNKNOWN);

	return -EINVAL;
}

static int enic_set_niccfg(struct enic *enic)
{
	const u8 rss_default_cpu = 0;
	const u8 rss_hash_type = 0;
	const u8 rss_hash_bits = 0;
	const u8 rss_base_cpu = 0;
	const u8 rss_enable = 0;
	const u8 tso_ipid_split_en = 0;
	const u8 ig_vlan_strip_en = 0;

	/* NO VLAN tag stripping.  RSS not enabled (yet).
	 */

	return enic_set_nic_cfg(enic,
		 rss_default_cpu, rss_hash_type,
		 rss_hash_bits, rss_base_cpu,
		 rss_enable, tso_ipid_split_en,
		 ig_vlan_strip_en);
}

static int enic_notify_set(struct enic *enic)
{
	int err;

	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		err = vnic_dev_notify_set(enic->vdev, ENIC_INTX_NOTIFY);
		break;
	case VNIC_DEV_INTR_MODE_MSIX:
		err = vnic_dev_notify_set(enic->vdev, ENIC_MSIX_NOTIFY);
		break;
	default:
		err = vnic_dev_notify_set(enic->vdev, -1 /* no intr */);
		break;
	}

	return err;
}

void enic_close(struct uld *uld)
{
	struct enic *enic = uld->nicpriv;
	if (enic->vdev) {
		vnic_dev_close(enic->vdev);
		vnic_dev_disable(enic->vdev);
		enic->vdev = NULL;
	}
}

void *enic_open(struct uld *uld)
{
	struct enic *enic;
	void *vregs;
	int barlen;
	int err;
	int i;

	barlen = pci_resource_len(uld->fd, 0);
	vregs = pci_mmap_bar(uld->fd, 0, 1);
	if (vregs == NULL)
		return NULL;
	enic = calloc(1, sizeof(struct enic));
	if (!enic)
		return NULL;
	pci_set_master(uld->fd);
	enic->fd = uld->fd;
	enic->uld = uld;
	enic->vdev = vnic_dev_register(NULL, enic, (void *)uld, vregs, barlen);
	pthread_mutex_init(&enic->skb_read_lock, NULL);
	enic_get_vnic_config(enic);
	memcpy(uld->mac, enic->mac_addr, 6);
	if (uld->mtu)
		enic->mtu = uld->mtu;
	else
		uld->mtu = enic->mtu = enic->config.mtu;
	if (uld->mtu > enic->config.mtu)
		fprintf(stderr,
			"enic_open: warning: requested mtu %d larger than network mtu %d\n",
				uld->mtu, enic->config.mtu);
	enic_get_res_counts(enic);
	err = enic_dev_open(enic);
	if (err)
		return NULL;

	err = vnic_dev_init(enic->vdev, 0);
	if (err) {
		printk(KERN_ERR PFX
			"vNIC dev init failed, aborting.\n");
		goto err_out_dev_close;
	}
	/* Set interrupt mode based on resource counts and system
	 * capabilities
	 */
	err = enic_set_intr_mode(enic);
	if (err) {
		printk(KERN_ERR PFX
			"Failed to set intr mode, aborting.\n");
		goto err_out_dev_close;
	}

	/* Allocate and configure vNIC resources
	 */
	err = enic_alloc_vnic_resources(enic);
	if (err) {
		printk(KERN_ERR PFX
			"Failed to alloc vNIC resources, aborting.\n");
		goto err_out_free_vnic_resources;
	}

	enic_init_vnic_resources(enic);

	enic->legacy_pba = vnic_dev_get_res(enic->vdev, 
				RES_TYPE_INTR_PBA_LEGACY, 0);
        for (i = 0; i < enic->intr_count; i++)
                vnic_intr_mask(&enic->intr[i]);

	enic->csum_rx_enabled = 1;

	err = enic_set_rq_alloc_buf(enic);
	if (err) {
		printk(KERN_ERR PFX
			"Failed to set RQ buffer allocator, aborting.\n");
		goto err_out_free_vnic_resources;
	}

	err = enic_set_niccfg(enic);
	if (err) {
		printk(KERN_ERR PFX
			"Failed to config nic, aborting.\n");
		goto err_out_free_vnic_resources;
	}

	err = enic_notify_set(enic);
	if (err) {
		printk(KERN_ERR PFX
			"enic_open: Failed to alloc notify buffer, aborting.\n");
		goto err_out_free_intr;
	}

	for (i = 0; i < enic->wq_count; i++)
		spin_lock_init(&enic->wq_lock[i]);

	for (i = 0; i < enic->rq_count; i++) {
		err = vnic_rq_fill(&enic->rq[i], enic->rq_alloc_buf);
		if (err) {
			printk(KERN_ERR PFX
				"enic_open: Unable to alloc receive buffers.\n");
			goto err_out_notify_unset;
		}
	}

	for (i = 0; i < enic->wq_count; i++)
		vnic_wq_enable(&enic->wq[i]);
	for (i = 0; i < enic->rq_count; i++)
		vnic_rq_enable(&enic->rq[i]);

	enic_add_station_addr(enic);
	/* recv promiscuous! */
	vnic_dev_packet_filter(enic->vdev, 1, 1, 1, 1, 1);
	vnic_dev_enable(enic->vdev);

	enic_notify_timeout(enic);

	uld->nicpriv = enic;
	uld->nl_handle = vfio_register_nl_callback(uld->pciname,
			1<<VFIO_MSG_REMOVE, enic_nl_event, (void *)uld);
	return enic;

err_out_notify_unset:
	vnic_dev_notify_unset(enic->vdev);
err_out_free_intr:
	// enic_free_intr(enic);
err_out_free_vnic_resources:
	enic_free_vnic_resources(enic);
err_out_dev_close:
	vnic_dev_close(enic->vdev);

	return NULL;
}

void enic_nl_event(void *arg, int event)
{
	struct uld *uld = arg;

	switch (event) {
	case VFIO_MSG_REMOVE:
		enic_close(uld);
		fprintf(stderr, "%s: removed\n", uld->pciname);
		exit(1);
	}
}
