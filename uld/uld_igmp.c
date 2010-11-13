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
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <linux/if_ether.h>

#include "skbuff.h"
#include "uld.h"

#define IgmpUnsolicitedReportInterval	10

struct mc_group {
	struct	mc_group	*next;
	struct uld 	*uld;
	unsigned int	mcgroup;
	int	delaying;
};

static struct mc_group *mc_lookup(struct uld *uld, unsigned int mcgroup)
{
	struct mc_group *m;

	uld_spin_lock(&uld->mlock);
	for (m = uld->mclist; m; m = m->next) 
		if (m->mcgroup == mcgroup)
			break;
	uld_spin_unlock(&uld->mlock);
	return m;
}

static void igmp_send_report(struct uld *uld, unsigned int mcgroup)
{
	struct sk_buff *skb;
	struct ip *ip;
	unsigned int *opt;
	struct igmp *ig;

	skb = skb_alloc(uld);
	skb->data += ETH_HLEN+2;
	ip = (struct ip *)(skb->data);
	memset((void *)ip, 0, sizeof (struct ip));
	ip->ip_hl = 5+1;	/* extra for router alert */
	ip->ip_v = 4;
	ip->ip_ttl = 1;	/* 1 hop only for igmp */
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_dst.s_addr = htonl(mcgroup);
	ip->ip_src.s_addr = htonl(uld->ip);
	opt = (unsigned int *)(sizeof (struct ip) + (void *)ip);
	*opt = htonl(0x94040000);	/* router alert */

	ig = (struct igmp *)(++opt);
	ig->igmp_type = IGMP_V2_MEMBERSHIP_REPORT;
	ig->igmp_code = 0;
	ig->igmp_cksum = 0;
	ig->igmp_group.s_addr = htonl(mcgroup);
	ig->igmp_cksum = ip_csum((unsigned char *)ig, sizeof (struct igmp));
	
	skb->len = (4 * ip->ip_hl) + sizeof(struct igmp);
	ip->ip_len = htons(skb->len);
	
	ip_send(uld, skb);
}

static void igmp_join_again(void *work)
{
	struct mc_group *m = (struct mc_group *)work;
	
	m->delaying = 0;
	igmp_send_report(m->uld, m->mcgroup);
}

static void delayed_report(struct uld *uld, struct mc_group *m, int maxdelay)
{
	double drand48();
	int usec;

	if (m->delaying)
		return;
	usec = maxdelay * drand48();
	m->delaying = 1;
	timeout_add_usec(uld, usec, igmp_join_again, (void *)m);
}

void igmp_join(struct uld *uld, unsigned int mcgroup)
{
	struct mc_group *m;

	igmp_send_report(uld, mcgroup);

	m = mc_lookup(uld, mcgroup);
	if (m)
		return;

	m = calloc(1, sizeof(struct mc_group));
	m->uld = uld;
	m->mcgroup = mcgroup;

	uld_spin_lock(&uld->mlock);
	m->next = uld->mclist;
	uld->mclist = m;
	uld_spin_unlock(&uld->mlock);

	delayed_report(uld, m, 1000000 * IgmpUnsolicitedReportInterval);
}

void igmp_handle(struct uld *uld, struct sk_buff *skb)
{
	struct ip *ip = (struct ip *)skb->data;
	struct igmp *ig;
	struct mc_group *m;
	int len;

	len = 4 * ip->ip_hl;
	skb->data += len;
	skb->len -= len;
	ig = (struct igmp *)skb->data;
	if (skb->len < 8) {
		fprintf(stderr, "igmp: runt\n");
		goto bad;
	}

	if (ip_csum((unsigned char *)ig, skb->len))
		fprintf(stderr, "bad igmp cksum\n");
fprintf(stderr, "rcvd IGMP %d\n", ig->igmp_type);
	switch (ig->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
		if (ig->igmp_code == 0)
			ig->igmp_code = 10;
		if (ig->igmp_group.s_addr) {
			m = mc_lookup(uld, ntohl(ig->igmp_group.s_addr));
			if (m)
				delayed_report(uld, m, ig->igmp_code * 100000);
		} else  {
			uld_spin_lock(&uld->mlock);
			for (m = uld->mclist; m; m = m->next) {
				delayed_report(uld, m, ig->igmp_code * 100000);
			}
			uld_spin_unlock(&uld->mlock);
		}
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
		if (ig->igmp_group.s_addr &&
		    (m = mc_lookup(uld, ntohl(ig->igmp_group.s_addr))) &&
		    m->delaying) {
			timeout_cancel(uld, igmp_join_again, (void *)m);
			m->delaying = 0;
		}
		break;
	default:
		break;
	}
bad:
	skb_free(skb);
}
