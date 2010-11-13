/*
 * Copyright 2008 Cisco Systems, Inc.  All rights reserved.
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
// #ident "$Id: enic.h 28213 2009-06-09 21:35:33Z sfeldma $"

#ifndef _UENIC_H_
#define _UENIC_H_

#include "vnic_enet.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_rss.h"


#define ENIC_LRO_MAX_DESC	8
#define ENIC_LRO_MAX_AGGR	64

enum enic_cq_index {
	ENIC_CQ_RQ,
	ENIC_CQ_WQ,
	ENIC_CQ_MAX,
};

enum enic_intx_intr_index {
	ENIC_INTX_WQ_RQ,
	ENIC_INTX_ERR,
	ENIC_INTX_NOTIFY,
	ENIC_INTX_MAX,
};

enum enic_msix_intr_index {
	ENIC_MSIX_RQ,
	ENIC_MSIX_WQ,
	ENIC_MSIX_ERR,
	ENIC_MSIX_NOTIFY,
	ENIC_MSIX_MAX,
};

#define ENIC_POLLFD_RQ		ENIC_MSIX_RQ
#define ENIC_POLLFD_WQ		ENIC_MSIX_WQ
#define ENIC_POLLFD_ERR		ENIC_MSIX_ERR
#define ENIC_POLLFD_NOTIFY	ENIC_MSIX_NOTIFY
#define	ENIC_POLLFD_NETLINK	ENIC_MSIX_MAX
#define	ENIC_POLLFDS		(ENIC_MSIX_MAX+1)

struct uld;
/* Per-instance private data structure */
struct enic {
	struct vnic_enet_config config;
	struct vnic_dev *vdev;
	struct uld *uld;
	int fd;
#ifdef xxx
	struct net_device_stats net_stats;
#endif
	u32 msg_enable;
	u32	mtu;
	spinlock_t devcmd_lock;
	u8 mac_addr[ETH_ALEN];
	u8 mc_addr[ENIC_MULTICAST_PERFECT_FILTERS][ETH_ALEN];
	unsigned int mc_count;
	int csum_rx_enabled;
	u32 port_mtu;
	struct sk_buff *skb_recv_head;
	struct sk_buff *skb_recv_tail;
	pthread_mutex_t skb_read_lock;
	struct pollfd pollfds[ENIC_POLLFDS];

	/* work queue cache line section */
	____cacheline_aligned struct vnic_wq wq[1];
	spinlock_t wq_lock[1];
	unsigned int wq_count;

	/* receive queue cache line section */
	____cacheline_aligned struct vnic_rq rq[1];
	unsigned int rq_count;
	int (*rq_alloc_buf)(struct vnic_rq *rq);
	u64 rq_bad_fcs;

	/* interrupt resource cache line section */
	____cacheline_aligned struct vnic_intr intr[ENIC_MSIX_MAX];
	unsigned int intr_count;
	u32 __iomem *legacy_pba;		/* memory-mapped */

	/* completion queue cache line section */
	____cacheline_aligned struct vnic_cq cq[ENIC_CQ_MAX];
	unsigned int cq_count;
};

void *enic_open(struct uld *);
void enic_close(struct uld *);
struct sk_buff *enic_skb_read(struct uld *, int);
int enic_skb_write(struct uld *, struct sk_buff *);
void enic_nl_event(void *, int);

#endif /* _ENIC_H_ */
