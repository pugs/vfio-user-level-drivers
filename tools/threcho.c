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
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>

#include "../uld/uld.h"
#include "../uld/skbuff.h"

int maxudp;
int count;
struct uld *uld;
unsigned int hisip = 0;

void * doit(void *arg)
{
	int instance = (long)arg;
	unsigned char *buf;
	void *port;
	int i, c;
	struct sk_buff *skb;
	int off, len;
	double drand48();
	unsigned int src;
	unsigned short sport;
	struct timespec timeo = { 3, 0 };
	int totlen;
	struct sk_buff *s;

	buf = malloc(2*maxudp);
	port = udp_open_port(uld, 1234+instance, 0);
	srand48(getpid() + instance);
	for (i=0; i<2*maxudp; i++)
		buf[i] = drand48() * 256;

	for (c=0; c<count; c++) {
		off = drand48() * maxudp;
		len = drand48() * maxudp;
		if (len == 0) len = 1;
		do {
			udp_write(port, buf+off, len, hisip, 7);
			do {
				skb = udp_recv_timed(port, &src, &sport, &timeo);
				for (totlen=0, s=skb; s; s=s->next)
					totlen += s->len;
			} while (skb && totlen != len);
		} while (skb == NULL);
		if (memcmp(buf+off, skb->data, skb->len))
			fprintf(stderr, "!%d %d\n", len, skb->len);
		skb_free(skb);
	}
	return NULL;
}

main(int argc, char **argv)
{
	struct hostent *h;
	char *ifname;
	int i;
	int threads;
	pthread_t *thrids;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <hisip> <threads> <packets>\n", argv[0]);
		exit(1);
	}

	uld = uld_open(NULL, 0, 0, 0, 0);
	if (uld == NULL) {
		fprintf(stderr, "uld_open failed\n");
		exit(1);
	}
	threads = atoi(argv[2]);
	if (threads != 1)
		uld_allow_threads(uld);

	fprintf(stderr, "my ip %x, my mac %s\n\n", uld->ip,
		ether_ntoa((struct ether_addr *)uld->mac)); 

	thrids = calloc(sizeof(pthread_t), threads);
	count = atoi(argv[3]);
	h = gethostbyname(argv[1]);
	if (h == NULL) {
		fprintf(stderr, "Can't parse %s for remote ip\n", argv[2]);
		exit(1);
	}
	hisip = ntohl(*(int *)h->h_addr);
	maxudp = uld->mtu - 28;
// maxudp = 2800;

	for (i=0; i<threads; i++) 
		pthread_create(&thrids[i], NULL, doit, (void *)(long)i);
	for (i=0; i<threads; i++) 
		pthread_join(thrids[i], NULL);
}
