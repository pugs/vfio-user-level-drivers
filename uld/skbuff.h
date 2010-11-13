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

#include <pthread.h>
#include <time.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct sk_buff {
	struct sk_buff *next;
	struct timespec tstamp;
	int	buf_size;
	int	len;
	unsigned short frag;
	unsigned short csum;
	unsigned short ip_summed;
	unsigned short csum_offset;
	unsigned long long	dma_addr;
	unsigned char	*buf;
	unsigned char	*data;
	unsigned char	*transport_hdr;
};
#define	CHECKSUM_NONE 0
#define	CHECKSUM_COMPLETE 1
#define	CHECKSUM_PARTIAL 2
#define	CHECKSUM_UNNECESSARY 3

extern __thread struct sk_buff *skb_local_free;
extern __thread int skb_local_count;
struct sk_buff *skb_global_free;
pthread_spinlock_t skb_global_lock;

struct uld;

#define	SKB_LOCAL_THRESH	50

struct sk_buff *skb_alloc_new(struct uld *);

static inline struct sk_buff *skb_alloc(struct uld *uld)
{
	struct sk_buff *skb;

	if (skb_local_free) {
		skb = skb_local_free;
		skb_local_free = skb->next;
		skb->next = NULL;
		skb_local_count--;
		return skb;
	}
	pthread_spin_lock(&skb_global_lock);
	if (skb_global_free) {
		skb = skb_global_free;
		skb_global_free = skb->next;
		skb->next = NULL;
		pthread_spin_unlock(&skb_global_lock);
		return skb;
	}
	skb = skb_alloc_new(uld);
	pthread_spin_unlock(&skb_global_lock);
	return skb;
}

static void inline skb_free(struct sk_buff *skb)
{
	int i; 
	struct sk_buff *nskb;

	while (skb) {
		nskb = skb->next;
		skb->data = skb->buf;
		skb->csum = skb->ip_summed = 0;
		skb->frag = skb->len = 0;
		skb->next = skb_local_free;
		skb_local_free = skb;
		skb_local_count++;
		skb = nskb;
	}
	if (skb_local_count > SKB_LOCAL_THRESH) {
		pthread_spin_lock(&skb_global_lock);
		for (i=0; i<SKB_LOCAL_THRESH/2; i++) {
			skb = skb_local_free;
			if (!skb)
				break;
			skb_local_free = skb->next;
			skb_local_count--;
			skb->next = skb_global_free;
			skb_global_free = skb;
		}
		pthread_spin_unlock(&skb_global_lock);
	}
}

static inline unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
        skb->len -= len;
        return skb->data += len;
}

static inline unsigned short skb_ether_protocol(struct sk_buff *skb)
{
	struct ethhdr *h = (struct ethhdr *)skb->data;
	unsigned short *p;

	p = &h->h_proto;
	while (*p == htons(ETH_P_8021Q))
		p += 2;
	return ntohs(*p);
}

static inline unsigned int skb_network_offset(struct sk_buff *skb)
{
	struct ethhdr *h = (struct ethhdr *)skb->data;
	unsigned short *p;

	p = &h->h_proto;
	while (*p == htons(ETH_P_8021Q))
		p += 2;
	return ((unsigned char *)p) + 2 - skb->data;
}

static inline unsigned char *skb_network_header(struct sk_buff *skb)
{
	return skb->data + skb_network_offset(skb);
}

static inline int skb_ip_protocol(struct sk_buff *skb)
{
	if (skb_ether_protocol(skb) == ETH_P_IP)
		return skb_network_header(skb)[9];
	if (skb_ether_protocol(skb) == ETH_P_IPV6)
		return skb_network_header(skb)[6];
	return 0;
}

static inline unsigned char *skb_transport_header(struct sk_buff *skb)
{
	unsigned char *h = skb_network_header(skb);

	if (skb_ether_protocol(skb) == ETH_P_IP)
		return h + 4 * ((*h) & 0xF);	/* ihl */
	if (skb_ether_protocol(skb) == ETH_P_IPV6)
		return h + 20;
	return NULL;
}
