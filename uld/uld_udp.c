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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#define __FAVOR_BSD 1
#include <netinet/udp.h>

#include "skbuff.h"
#include "uld.h"

#define	UDP_PORT_HASH	97

#define	uld_mutex_lock(X) 	if(uld->threaded) pthread_mutex_lock(X)
#define	uld_mutex_unlock(X) 	if(uld->threaded) pthread_mutex_unlock(X)

struct udp_pkt {
	struct udp_pkt *next;
	unsigned int src;
	unsigned int dst;
	unsigned short oport;
	struct sk_buff *skb;
};
	
struct udp_port {
	struct udp_port *next;
	struct uld *uld;
	unsigned short	port_no;
	int noblock;
#define	MAX_IN_QUEUE	1000
	unsigned int	pkt_queued;
	struct	udp_pkt *head;
	struct	udp_pkt *tail;
	pthread_mutex_t plock;
	pthread_cond_t pcond;
};

struct udp_state {
	struct	udp_port *port_hash[UDP_PORT_HASH];
	long long incount;
	long long outcount;
};

static inline struct udp_port *find_port(struct uld *uld, unsigned short port_no)
{
	struct udp_port *p;

	uld_spin_lock(&uld->ulock);
	if (uld->udp_state == NULL) {
		uld->udp_state = (struct udp_state *)calloc(1, sizeof(struct udp_state));
	}
	p = uld->udp_state->port_hash[port_no % UDP_PORT_HASH];
	while (p) {
		if (p->port_no == port_no)
			break;
		p = p->next;
	}
	uld_spin_unlock(&uld->ulock);
	return p;
}

void uld_handle_udp(struct uld *uld, struct sk_buff *skb)
{
	struct ip *ip = (struct ip *)skb->data;
	struct sk_buff *s;
	struct udphdr *uh;
	struct udp_port *p;
	struct udp_pkt *pk;
	int len, ulen;
	int sum;

	len = 4 * ip->ip_hl;
	skb->data += len;
	skb->len -= len;

	uh = (struct udphdr *)skb->data;
	p = find_port(uld, ntohs(uh->uh_dport));
	if (p == NULL)
		goto bad;
	uld->udp_state->incount++;

	
	for (len = 0, s = skb; s; s = s->next)
		len += s->len;
	ulen = ntohs(uh->uh_ulen);
	if (ulen < sizeof(struct udphdr) || ulen > len) {
		fprintf(stderr, "udp: bad len %d %d\n", ulen, len);
		goto bad;
	}
	if (uh->uh_sum == 0)
		fprintf(stderr, "udp: no csum!\n");
	if (skb->ip_summed != CHECKSUM_UNNECESSARY) {
		/* checksum udp pseudo-header */
		sum = ntohl(ip->ip_src.s_addr) >> 16;
		sum += ntohl(ip->ip_src.s_addr) & 0xFFFF;
		sum += ntohl(ip->ip_dst.s_addr) >> 16;
		sum += ntohl(ip->ip_dst.s_addr) & 0xFFFF;
		sum += IPPROTO_UDP;
		sum += ntohs(uh->uh_ulen);
		sum += (sum >> 16);
		sum = htons(sum);
		if (skb->ip_summed == CHECKSUM_COMPLETE) {
#ifndef noHWCKSUM
			sum += skb->csum;
#else
			sum = ip_csum_cont(sum, skb->data, ulen);
#endif
		} else {
			for (s = skb; s; s = s->next) {
				len = s->len;
				if (len > ulen)
					len = ulen;
				sum = ip_csum_cont(sum, s->data, len);
				ulen -= len;
			}
		}
		if (sum != 0xFFFF) {
			fprintf(stderr, "udp - bad cksum (%d)\n", skb->ip_summed);
			goto bad;
		}
	}

	pk = (struct udp_pkt *)calloc(1, sizeof(struct udp_pkt));
	pk->src = ntohl(ip->ip_src.s_addr);
	pk->dst = ntohl(ip->ip_dst.s_addr);
	pk->oport = ntohs(uh->uh_sport);
	skb->data += sizeof(struct udphdr);
	skb->len -= sizeof(struct udphdr);
	pk->skb = skb;

	uld_mutex_lock(&p->plock);
	if (p->pkt_queued >= MAX_IN_QUEUE) {
		free(pk);
fprintf(stderr, "udp in: q full\n");
		uld_mutex_unlock(&p->plock);
		goto bad;
	}
	if (p->head) {
		p->tail->next = pk;
		p->tail = pk;
	} else {
		p->head = p->tail = pk;
	}
	p->pkt_queued++;
	if (uld->threaded) pthread_cond_signal(&p->pcond);
	uld_mutex_unlock(&p->plock);
	return;

bad:
fprintf(stderr, "bad udp in\n");
	skb_free(skb);
}

void *udp_open_port(struct uld *uld, unsigned short port_no, int noblock)
{
	struct udp_port *p;

	p = find_port(uld, port_no);
	if (p)
		return p;

	p = (struct udp_port *)calloc(1, sizeof (struct udp_port));
	p->port_no = port_no;
	p->noblock = noblock;
	p->uld = uld;
	if (uld->threaded) pthread_mutex_init(&p->plock, NULL);

	uld_spin_lock(&uld->ulock);
	p->next = uld->udp_state->port_hash[port_no % UDP_PORT_HASH]; 
	uld->udp_state->port_hash[port_no % UDP_PORT_HASH] = p; 
	uld_spin_unlock(&uld->ulock);
	return p;
}

static struct sk_buff *udp_recv_common(struct udp_port *p, unsigned int *srcp, unsigned short *sportp)
{
	struct udp_pkt *pk;
	struct sk_buff *skb;

	pk = p->head;
	p->head = pk->next;
	p->pkt_queued--;

	if (srcp)
		*srcp = pk->src;
	if (sportp)
		*sportp = pk->oport;
	skb = pk->skb;
	free(pk);
	return skb;
}

struct sk_buff *udp_recv_timed(void *porthandle, unsigned int *srcp, unsigned short *sportp, struct timespec *reltime)
{
	struct udp_port *p = (struct udp_port *)porthandle;
	struct sk_buff *skb = NULL;
	struct timespec abstime, now;
	struct uld *uld = p->uld;
	int ret;

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_nsec += reltime->tv_nsec;
	abstime.tv_sec += reltime->tv_sec;
	if (abstime.tv_nsec > 1000000000) {
		abstime.tv_nsec -= 1000000000;
		abstime.tv_sec++;
	}
	uld_mutex_lock(&p->plock);
	if (p->head == NULL) {
		if (p->noblock) {
			uld_mutex_unlock(&p->plock);
			return NULL;
		}
		while (p->head == NULL) {
			if (uld->threaded) {
				ret = pthread_cond_timedwait(&p->pcond, &p->plock, &abstime);
				if (ret) {
					skb = NULL;
					goto out;
				}
			} else {
				uld_dispatch(uld, !uld->spin);
				clock_gettime(CLOCK_REALTIME, &now);
				if (now.tv_sec > abstime.tv_sec ||
				   ((now.tv_sec == abstime.tv_sec) && now.tv_nsec > abstime.tv_nsec)) {
					skb = NULL;
					goto out;
				}
			}
		}
	}

	skb = udp_recv_common(p, srcp, sportp);
out:
	uld_mutex_unlock(&p->plock);
	return skb;
}

struct sk_buff *udp_recv(void *porthandle, unsigned int *srcp, unsigned short *sportp)
{
	struct udp_port *p = (struct udp_port *)porthandle;
	struct sk_buff *skb;
	struct uld *uld = p->uld;

	uld_mutex_lock(&p->plock);
	if (p->head == NULL) {
		if (p->noblock) {
			uld_mutex_unlock(&p->plock);
			return NULL;
		}
		while (p->head == NULL) {
			if (uld->threaded)
				pthread_cond_wait(&p->pcond, &p->plock);
			else
				uld_dispatch(uld, !uld->spin);
		}
	}

	skb = udp_recv_common(p, srcp, sportp);
	uld_mutex_unlock(&p->plock);
	return skb;
}

#define SLOP	(2 + ETH_HLEN + sizeof(struct ip) + sizeof(struct udphdr)) 
void udp_send(void *porthandle, struct sk_buff *skb, unsigned int dst, unsigned short dport)
{
	struct udp_port *p = (struct udp_port *)porthandle;
	struct udphdr *uh;
	struct ip *ip;
	int sum;
	int totlen;
	struct sk_buff *s;

	if (p == NULL || p != find_port(p->uld, p->port_no)) {
		skb_free(skb);
		return;
	}
	if (skb->data - skb->buf < SLOP) {
		struct sk_buff *nskb;

		if (skb->len + SLOP > p->uld->mtu+ETH_HLEN+2) {
			fprintf(stderr, "udp_send: packet too big\n");
			skb_free(skb);
			return;
		}
		nskb = skb_alloc(p->uld);
		nskb->data += SLOP;
		memcpy(nskb->data, skb->data, skb->len);
		nskb->len = skb->len;
		nskb->frag = skb->frag;
		nskb->next = skb->next;
		skb->next = 0;
		skb_free(skb);
		skb = nskb;
	}
	uh = (struct udphdr *)(skb->data - sizeof(struct udphdr));
	ip = (struct ip *)((void *)uh - sizeof(struct ip));
	memset((void *)ip, 0, sizeof(struct ip) + sizeof(struct udphdr));

	uh->uh_sport = htons(p->port_no);
	uh->uh_dport = htons(dport);
	if (skb->frag) {
		for (totlen = 0, s = skb; s; s = s->next)
			totlen += s->len;
	} else
		totlen = skb->len;
	totlen += sizeof(struct udphdr);
	uh->uh_ulen = htons(totlen);
	skb->data = (void *)uh;
	skb->len += sizeof(struct udphdr);

	/* checksum udp pseudo-header */
	sum = p->uld->ip >> 16;
	sum += p->uld->ip & 0xFFFF;
	sum += dst >> 16;
	sum += dst & 0xFFFF;
	sum += IPPROTO_UDP;
	sum += ntohs(uh->uh_ulen);
	sum += (sum >> 16);
	sum = htons(sum);
	if (skb->frag) {
		for (s = skb; s; s = s->next) {
			sum = ip_csum_cont(sum, s->data, s->len);
		}
		uh->uh_sum = ~sum;
		if (uh->uh_sum == 0)
			uh->uh_sum = 0xFFFF;
	} else {
		uh->uh_sum = sum;	/* we do the ps-hdr, hw does the rest */
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_offset = 6;	/* offset of uh_sum in hdr */
		skb->transport_hdr = (unsigned char *)uh;
	}

	totlen += sizeof(struct ip);
	skb->data = (void *)ip;
	skb->len += sizeof(struct ip);
	
	ip->ip_p = IPPROTO_UDP;
	ip->ip_src.s_addr = htonl(p->uld->ip);
	ip->ip_dst.s_addr = htonl(dst);
	ip->ip_len = htons(totlen);
	ip_send(p->uld, skb);
}

int udp_write(void *porthandle, void *data, int totlen, unsigned int dst, unsigned short dport) 
{
	struct sk_buff *skb, *start, **prev = &start;
	struct udp_port *p = (struct udp_port *)porthandle;
	int udpfrag = (p->uld->mtu - 28) & ~7;
	int len;

	while (totlen > 0) {
		len = totlen;
		if (len > udpfrag)
			len = udpfrag;
		skb = skb_alloc(p->uld);
		skb->data += SLOP;
		skb->len = len;
		memcpy(skb->data, data, len);
		data += len;
		totlen -= len;
		if (totlen)
			skb->frag = IP_MF;
		*prev = skb;
		prev = &skb->next;
	}
	udp_send((void *)p, start, dst, dport);
	return len;
}

int udp_read(void *porthandle, void *data, int totlen, unsigned int *srcp, unsigned short *sportp)
{
	struct sk_buff *skb, *oskb;
	int done = 0;
	int len;

	oskb = skb = udp_recv(porthandle, srcp, sportp);
	if (skb == NULL)
		return 0;
	do {
		len = skb->len;
		if (len > totlen)
			len = totlen;
		memcpy(data, skb->data, len);
		totlen -= len;
		data += len;
		done += len;
	} while (skb->frag && (skb = skb->next));
	skb_free(oskb);
	return done;
}
