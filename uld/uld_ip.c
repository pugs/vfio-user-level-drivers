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
#include <pthread.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <sys/time.h>

#include "uld.h"
#include "skbuff.h"


#define	IP_TTL_OUT	27

/* selected by lower bits of IP address */
#define ARP_TABLE_SIZE	64
struct arptab {
	unsigned int ip;
	unsigned int time;
	unsigned int rtime;
	struct sk_buff  *hold;
	unsigned short status;
	unsigned char mac[ETH_ALEN];
} arp_table[ARP_TABLE_SIZE];
pthread_spinlock_t arp_lock;

#define	ARP_INCOMP	0
#define	ARP_COMP	1
#define	ARP_MAX_LIFE	(3*60)
#define	ARP_MAX_HOLD	5

#define FRAG_TAB_SIZE	64
struct sk_buff *frag_tab[FRAG_TAB_SIZE];
pthread_spinlock_t frag_lock[FRAG_TAB_SIZE];

struct etharp {
	unsigned short	ar_hrd;
	unsigned short	ar_pro;
	unsigned char	ar_hln;
	unsigned char	ar_pln;
	unsigned short	ar_op;
	unsigned char  	ar_sha[ETH_ALEN];
	unsigned char  	ar_sip[4];
	unsigned char  	ar_tha[ETH_ALEN];
	unsigned char  	ar_tip[4];
};

void arp_init()
{
	static int first = 1;
	int i;

	if (first) {
		pthread_spin_init(&arp_lock, PTHREAD_PROCESS_PRIVATE);
		for (i=0; i<FRAG_TAB_SIZE; i++)
			pthread_spin_init(&frag_lock[i], PTHREAD_PROCESS_PRIVATE);
	}
	first = 0;
}

void skb_dump(char *s, struct sk_buff *skb)
{
	int i;

	printf("%s:\n", s);
	for (i=0; i<skb->len; i++) {
		printf(" %2.2x", skb->data[i]);
		if ((i%64) == 63) printf("\n");
	}
	printf("\n");
}

void uld_handle_arp(struct uld *uld, struct sk_buff *skb)
{
	struct ethhdr *eh = (struct ethhdr *)skb->data;
	struct etharp *ar = (struct etharp *)(skb->data + ETH_HLEN);
	unsigned int tip, sip;
	struct arptab *a;
	struct timeval tv;

	if (skb->len < ETH_HLEN + sizeof (struct etharp))
		goto bad;
	if (ar->ar_hrd != htons(ARPHRD_ETHER) || ar->ar_pro != htons(ETHERTYPE_IP) 
		|| ar->ar_hln != ETH_ALEN || ar->ar_pln != 4)
			goto bad;
	switch(ntohs(ar->ar_op)) {

	case ARPOP_REQUEST:
		tip = *(unsigned int *)ar->ar_tip;
		sip = *(unsigned int *)ar->ar_sip;
		if (ntohl(tip) != uld->ip)
			return;
		ar->ar_op = htons(ARPOP_REPLY);
		*(unsigned int *)ar->ar_sip = htonl(uld->ip);
		memcpy(ar->ar_sha, uld->mac, ETH_ALEN);
		*(unsigned int *)ar->ar_tip = sip;
		memcpy(ar->ar_tha, eh->h_source, ETH_ALEN);
		memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
		memcpy(eh->h_source, uld->mac, ETH_ALEN);
		skb->ip_summed = 0;
		(void) uld_skb_write(uld, skb);
		break;

	case ARPOP_REPLY:
		sip = ntohl(*(unsigned int *)ar->ar_sip);
		tip = ntohl(*(unsigned int *)ar->ar_tip);
		uld_spin_lock(&arp_lock);
		a = &arp_table[sip % ARP_TABLE_SIZE];
		skb_free(skb);
		if (a->ip == sip && uld->ip == tip) {
			if (ar->ar_sha[0] & 1) {	// naughty multicast
				goto unlock_bad;
			}
			memcpy(a->mac, ar->ar_sha, ETH_ALEN);
			gettimeofday(&tv, NULL);
			if (a->hold && (tv.tv_sec - a->time > ARP_MAX_HOLD)) {
				skb_free(a->hold);
				a->hold = NULL;
			}
			a->time = tv.tv_sec;
			a->status = ARP_COMP;	
			if ((skb = a->hold)) {
				struct ethhdr *eh = (struct ethhdr *)skb->data;

				a->hold = NULL;
				memcpy(eh->h_dest, a->mac, ETH_ALEN);
				uld_spin_unlock(&arp_lock);
				if (skb->frag) {
					struct sk_buff *s;
fprintf(stderr, "%s: skb frag!\n", __func__);

					skb->frag = 0;
					for (s = skb->next; s; s = s->next) {
						s->data -= ETH_HLEN;
						s->len += ETH_HLEN;
						s->frag = 0;
						memcpy(s->data, (void *)eh, ETH_HLEN);
					}
				}
				uld_skb_write(uld, skb);
			} else
				uld_spin_unlock(&arp_lock);
		} else 
			goto unlock_bad;
		break;
	default:
		skb_free(skb);
		goto bad;
	}
	return;
unlock_bad:
	uld_spin_unlock(&arp_lock);
bad:
	fprintf(stderr, "got bad arp pkt\n");
}

void arp_req_out(struct uld *uld, unsigned int dest)
{
	struct sk_buff *skb;
	struct ethhdr *eh;
	struct etharp *ea;
	
	skb = skb_alloc(uld);
	eh = (struct ethhdr *)skb->data;
	ea = (struct etharp *)(skb->data + ETH_HLEN);
	skb->len = ETH_HLEN + sizeof (struct etharp);

	ea->ar_hrd = htons(ARPHRD_ETHER);
	ea->ar_pro = htons(ETHERTYPE_IP); 
	ea->ar_hln = ETH_ALEN;
	ea->ar_pln = 4;
	ea->ar_op = htons(ARPOP_REQUEST);
	memcpy(ea->ar_sha, uld->mac, ETH_ALEN);
	*(unsigned int *)ea->ar_sip = htonl(uld->ip);
	memset(ea->ar_tha, 0, ETH_ALEN);
	*(unsigned int *)ea->ar_tip = htonl(dest);
	eh->h_proto = htons(ETHERTYPE_ARP);
	memcpy(eh->h_source, uld->mac, ETH_ALEN);
	memset(eh->h_dest, 0xFF, ETH_ALEN);	/* broadcast */
	uld_skb_write(uld, skb);
}

static void arp_ip_send(struct uld *uld, struct sk_buff *skb, unsigned int dest)
{
	struct sk_buff *nskb, *s;
	struct ip *ip;
	struct timeval tv;
	struct arptab *a;
	struct ethhdr *eh;

	if ((skb->data - skb->buf) < ETH_HLEN) {
		nskb = skb_alloc(uld);
		nskb->data += ETH_HLEN;
		memcpy(nskb->data, skb->data, skb->len);
		nskb->len = skb->len;
		skb_free(skb);
		skb = nskb;
	}
	ip = (struct ip *)skb->data;
	skb->data -= ETH_HLEN;
	skb->len += ETH_HLEN;
// if (skb->len < 60) skb->len = 60;
	eh = (struct ethhdr *)skb->data;
	eh->h_proto = htons(ETHERTYPE_IP); 
	memcpy(eh->h_source, uld->mac, ETH_ALEN);
	memset(eh->h_dest, 0, ETH_ALEN);

	if (dest == INADDR_BROADCAST) {
		memset(eh->h_dest, 0xFF, ETH_ALEN);
		goto do_write;
	}
	if (IN_MULTICAST(dest)) {
		eh->h_dest[0] = 0x01;
		eh->h_dest[1] = 0x00;
		eh->h_dest[2] = 0xBC;
		eh->h_dest[3] = (dest >> 16) & 0x7F;
		eh->h_dest[4] = (dest >> 8) & 0xFF;
		eh->h_dest[5] = (dest) & 0xFF;
		goto do_write;
	}

	uld_spin_lock(&arp_lock);
	a = &arp_table[dest % ARP_TABLE_SIZE];

	gettimeofday(&tv, NULL);
	if (a->ip == dest && a->status == ARP_COMP &&
	    (tv.tv_sec - a->time) < ARP_MAX_LIFE) {	// use it!
		memcpy(eh->h_dest, a->mac, ETH_ALEN);
		uld_spin_unlock(&arp_lock);
		if ((tv.tv_sec - a->time) > ARP_MAX_LIFE/2 && a->rtime != tv.tv_sec) {
			/* refresh arp */
			a->rtime = tv.tv_sec;
			arp_req_out(uld, dest);
		} 
		goto do_write;
	}
	    
	a->ip = dest;
	memset(a->mac, 0, ETH_ALEN);
	if (a->hold) {
		skb_free(a->hold);
	}
	a->hold = skb;
	a->time = tv.tv_sec;
	a->status = ARP_INCOMP;
	uld_spin_unlock(&arp_lock);
	arp_req_out(uld, dest);
	return;

do_write:
	if (skb->frag) {
		skb->frag = 0;
		for (s = skb->next; s; s = s->next) {
			s->data -= ETH_HLEN;
			s->len += ETH_HLEN;
			s->frag = 0;
			memcpy(s->data, (void *)eh, ETH_HLEN);
		}
	}
	(void) uld_skb_write(uld, skb);
	return;
}

#define IPV4_DEFAULT_TTL 37
void ip_send(struct uld *uld, struct sk_buff *skb)
{
	struct ip *ip = (struct ip *)skb->data;
	static int ip_id = 1;
	unsigned int dest;

	if (ip->ip_hl == 0)
		ip->ip_hl = 5;
	ip->ip_v = 4;
	if (ip->ip_ttl == 0)
		ip->ip_ttl = IPV4_DEFAULT_TTL;
	ip->ip_id = htons(ip_id++);

	if (skb->frag) {
		int off, totlen, len;
		struct sk_buff *s;

if (ip->ip_hl!=5) fprintf(stderr, "aarg - ip options w frags\n");
		off = 0;
		totlen = ntohs(ip->ip_len);
		totlen -= ip->ip_hl*4;
		for (s = skb; s; s = s->next) {
			struct ip *nip;

			if (s != skb) {
				s->data -= ip->ip_hl*4;
				s->len += ip->ip_hl*4;
				nip = (struct ip *)s->data;
				memcpy(nip, ip, ip->ip_hl*4);
				nip->ip_sum = 0;
			} else
				nip = ip;
			len = s->len - ip->ip_hl*4;
			nip->ip_len = htons(len + ip->ip_hl*4);
			nip->ip_off = htons(off/8);
			off += len;
			totlen -= len;
			if (s->next)
				nip->ip_off |= htons(IP_MF);
			nip->ip_sum = ip_hdr_csum((void *)nip, nip->ip_hl);
		}
		if (totlen) fprintf(stderr, "ip_send frag totlen %d\n", totlen);
	} else
		ip->ip_sum = ip_hdr_csum((void *)ip, ip->ip_hl);

	dest = ntohl(ip->ip_dst.s_addr);
	if (dest == INADDR_ANY || dest == INADDR_BROADCAST)
		dest = INADDR_BROADCAST;
	else if (IN_MULTICAST(dest))
		;
	else if ((uld->ip & uld->netmask) != (dest & uld->netmask))	// remote
		dest = uld->gw;
	arp_ip_send(uld, skb, dest);
}

static void reverse_ip(struct ip *oip, struct ip *nip)
{
	nip->ip_v = 4;
	nip->ip_hl = 5;
	nip->ip_tos = oip->ip_tos;
	nip->ip_len = 20 + (oip->ip_len - 4*oip->ip_hl);
	nip->ip_id = 0; // tbd
	nip->ip_off = 0;
	nip->ip_ttl = 0; // tbd
	nip->ip_p = oip->ip_p;
	nip->ip_sum = 0; // tbd
	nip->ip_src = oip->ip_dst;
	nip->ip_dst = oip->ip_src;
}

static void handle_icmp(struct uld *uld, struct sk_buff *skb)
{
	struct ip *ip = (struct ip *)skb->data;
	struct icmp *ic = (struct icmp *)((void *)ip + 4*ip->ip_hl);
	int icmplen;
	unsigned int dest;
	struct ip nip;

	icmplen = skb->len - (4*ip->ip_hl);
	if (ip_csum((void *)ic, icmplen)) {
		fprintf(stderr, "Bad ICMP checksum\n");
		goto bad;
	}

	dest = ntohl(ip->ip_dst.s_addr);
	if (dest != uld->ip) 	/* avoid all mc/bc/bogus */
		goto bad;

	switch(ic->icmp_type) {
	default:
		break;
	case ICMP_ECHO:
		ic->icmp_type = ICMP_ECHOREPLY;
		ic->icmp_cksum = 0;
		ic->icmp_cksum = ip_csum((void *)ic, icmplen);
		reverse_ip(ip, &nip);
		skb->data += 4*ip->ip_hl;
		skb->len -= 4*ip->ip_hl;
		skb->data -= 4*nip.ip_hl;
		skb->len += 4*nip.ip_hl;
		memcpy(skb->data, (void *)&nip, 4*nip.ip_hl);
		ip_send(uld, skb);
		skb = NULL;
		break;
	}
bad:
	if (skb)
		skb_free(skb);
}

void uld_handle_ip(struct uld *uld, struct sk_buff *skb)
{
	struct ethhdr *eh = (struct ethhdr *)skb->data;
	struct ip *ip = (struct ip *)(skb->data + ETH_HLEN);
	unsigned int dest;
	
	/* look for multicast or unicast to us */
	if ((eh->h_dest[0] & 1) == 0 && memcmp(eh->h_dest, uld->mac, ETH_ALEN))
		goto bad;
	/* done with ethernet header */
	skb->data += ETH_HLEN;
	skb->len -= ETH_HLEN;

	if (ip->ip_hl < 5 || ip->ip_v != 4) {
		fprintf(stderr, "bad ip hdr\n");
		goto bad;
	}
	if (ip_hdr_csum((unsigned int *)ip, ip->ip_hl)) {
		fprintf(stderr, "bad hdr csum\n");
		goto bad;
	}
	if (ntohs(ip->ip_len) > skb->len || ntohs(ip->ip_len) < ip->ip_hl*4) {
		fprintf(stderr, "bad ip len\n");
		goto bad;
	}
	skb->len = ntohs(ip->ip_len);

	if (ip->ip_hl > 5) 	// no options for now
		fprintf(stderr, "unhandled IP options\n");

	dest = ntohl(ip->ip_dst.s_addr);
	if (!IN_MULTICAST(dest) && dest != uld->ip) {
		fprintf(stderr, "bad ip dest %x\n", dest);
		goto bad;
	}

	if (ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) {		/* fragment */
		unsigned int hash;
		unsigned short off;
		struct sk_buff *oskb;

		skb->frag = ntohs(ip->ip_off);
		off = skb->frag & IP_OFFMASK;
		hash = dest + ntohl(ip->ip_src.s_addr) + ip->ip_id + ip->ip_p;
		uld_spin_lock(&frag_lock[hash % FRAG_TAB_SIZE]);
		oskb = frag_tab[hash % FRAG_TAB_SIZE];
		if (oskb) {
			struct ip *oip;

			oip = (struct ip *)oskb->data;
			if (oip->ip_src.s_addr == ip->ip_src.s_addr &&
			    oip->ip_dst.s_addr == ip->ip_dst.s_addr &&
			    oip->ip_id == ip->ip_id && oip->ip_p == ip->ip_p)
			{	/* match */
				int len = -(int)sizeof(struct ip);

				while (oskb) {
					len += oskb->len;
					if (len == off*8)
						break;
					oskb = oskb->next;
				}
				if (oskb == NULL) {	/* out of order frag */
					skb_free(skb);
					oskb = frag_tab[hash % FRAG_TAB_SIZE];
					if (oskb)
						skb_free(oskb);
					frag_tab[hash % FRAG_TAB_SIZE] = NULL;
fprintf(stderr, "ooo frag\n");
					goto badfrag;
				}
				skb_pull(skb, ip->ip_hl * 4);
				oskb->next = skb;
				if (skb->frag & IP_MF)
					goto badfrag;

				skb = frag_tab[hash % FRAG_TAB_SIZE];
				skb->ip_summed = 0;
				frag_tab[hash % FRAG_TAB_SIZE] = NULL;
				ip = (struct ip *)skb->data;
				uld_spin_unlock(&frag_lock[hash % FRAG_TAB_SIZE]);
				goto whole;
			} else {
				/* new replaces old */
fprintf(stderr, "frag repl\n");
				skb_free(oskb);
				if (off == 0)
					frag_tab[hash % FRAG_TAB_SIZE] = skb;
				else
					skb_free(skb);
			}
		} else {	//	frag_tab slot empty
			if (off == 0)
				frag_tab[hash % FRAG_TAB_SIZE] = skb;
			else
				skb_free(skb);
		}
badfrag:
		uld_spin_unlock(&frag_lock[hash % FRAG_TAB_SIZE]);
		return;
	}

whole:
	switch(ip->ip_p) {
	case IPPROTO_ICMP:
		handle_icmp(uld, skb);
		break;
	case IPPROTO_IGMP:
		igmp_handle(uld, skb);
		break;
	case IPPROTO_UDP:
		uld_handle_udp(uld, skb);
		break;
	default:
		skb_free(skb);
		break;
	}
	return;
bad:
	fprintf(stderr, "Bad IP ip len %d, skb len %d\n",  ntohs(ip->ip_len), skb->len);
	skb_free(skb);
}
