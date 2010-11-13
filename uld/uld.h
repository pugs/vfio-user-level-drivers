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
 * User level network device state
 */
struct tentry;
struct udp_state;
struct mc_group;
struct nic;
#ifndef DMA_ADDR_T
typedef unsigned long long dma_addr_t;
#define	DMA_ADDR_T	1
#endif

struct uld {
	int	fd;	/* device fd */
	int	tfd;	/* timer fd */
	int	efd;	/* event fd for intrs */
	struct nic *nic;
	void	*nicpriv;	/* nic handle */
	struct	tentry *tlist;	/* timeout chain */
	struct	uld *uldnext;
	int	threaded;
	pthread_spinlock_t tlock;
	unsigned int	ip;		/* ip address */
	unsigned int 	netmask;	/* netmask */
	unsigned int 	gw;		/* gateway */
	unsigned char	mac[6];		/* hw mac addr */
	char		*pciname;
	int 	linkup;
	int	mtu;
	int	spin;
	int	p_left;		/* how much left in huge page */
	void	*p_virt_free;	/* virtual free pointer */
	unsigned long p_phys_free;	/* physical free pointer */
#define	CHUNKSIZE	(2*1024*1024)
	struct udp_state 	*udp_state;
	pthread_spinlock_t ulock;
	struct	mc_group	*mclist;
	pthread_spinlock_t mlock;
	struct nl_handle *nl_handle;
};

struct nic {
	unsigned short	vendor;
	unsigned short	device;
	char		*name;
	void		*(*open)(struct uld *);
	void		(*close)(struct uld *);
	struct sk_buff	*(*read_skb)(struct uld *, int);
	int		(*skb_write)(struct uld *, struct sk_buff *);
};


struct sk_buff *uld_skb_read(struct uld *, int);
int uld_skb_write(struct uld *, struct sk_buff *);
struct uld *uld_open(char *, unsigned int ip, unsigned int netmask, unsigned int gw, int mtu);
void uld_allow_threads(struct uld *);

static inline unsigned char *uld_mac_addr(struct uld *uld)
{
	return uld->mac;
}

void uld_dispatch(struct uld *, int);
void igmp_handle(struct uld *, struct sk_buff *);
void uld_handle_udp(struct uld *, struct sk_buff *);
void uld_handle_ip(struct uld *, struct sk_buff *);
void uld_handle_arp(struct uld *, struct sk_buff *);
void arp_req_out(struct uld *, unsigned int);
void arp_init();
void ip_send(struct uld *, struct sk_buff *);

void *udp_open_port(struct uld *, unsigned short, int);
struct sk_buff *udp_recv(void *, unsigned int *, unsigned short *);
struct sk_buff *udp_recv_timed(void *, unsigned int *, unsigned short *, struct timespec *);
void udp_send(void *, struct sk_buff *, unsigned int, unsigned short);
int udp_write(void *, void *, int, unsigned int, unsigned short); 
int udp_read(void *, void *, int, unsigned int *, unsigned short *);

void timeout_check(struct uld *uld);
void timeout_add(struct uld *uld, struct timespec *ts, void (*fun)(void *), void *arg);
void timeout_add_usec(struct uld *uld, int usec, void (*fun)(void *), void *arg);
void timeout_cancel(struct uld *uld, void (*fun)(void *), void *arg);

#define uld_spin_lock(X)  if(uld->threaded) pthread_spin_lock(X)
#define uld_spin_unlock(X)  if(uld->threaded) pthread_spin_unlock(X)

static inline unsigned short ip_csum_cont(int sum, unsigned char *cp, int len)
{
	while (len >= 2) {
		sum += cp[0];
		sum += cp[1] << 8;
		len -= 2;
		cp += 2;
	}
	if (len)
		sum += *cp;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return sum;
}

static inline unsigned short ip_csum(unsigned char *cp, int len)
{
	return ~ip_csum_cont(0, cp, len);
}

static inline unsigned short ip_hdr_csum(unsigned int *ip, int len)
{
	unsigned int sum=0;
	int i;
#ifdef oldworking

	if (len == 5) {
		sum += (ip[0] & 0xFFFF) + (ip[0] >> 16);
		sum += (ip[1] & 0xFFFF) + (ip[1] >> 16);
		sum += (ip[2] & 0xFFFF) + (ip[2] >> 16);
		sum += (ip[3] & 0xFFFF) + (ip[3] >> 16);
		sum += (ip[4] & 0xFFFF) + (ip[4] >> 16);
	} else {
		for (i=0; i<len; i++)
			sum += (ip[i] & 0xFFFF) + (ip[i] >> 16);
	}
#else
	unsigned short *sp = (unsigned short *)ip;

	if (len == 5) {
		sum = sp[0] + sp[1] + sp[2] + sp[3] + sp[4]
		    + sp[5] + sp[6] + sp[7] + sp[8] + sp[9];
	} else {
		for (i=0; i<2*len; i++)
			sum += sp[i];
	}
#endif
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}
