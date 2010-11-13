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
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>

#include "../uld/uld.h"
#include "../uld/skbuff.h"


main(int argc, char **argv)
{
	struct hostent *h;
	int pcount = 0;
	struct uld *uld;
	char *ifname;
	unsigned int myip, mymask=0, mygw=0;
	void *port;
	unsigned int hisip = 0;
	unsigned int src;
	unsigned short sport;
	struct sk_buff *skb;
	int c, i, len;
	int count = 100;
	unsigned char *buf;
	int maxudp;
	double intvl;
	struct timespec begin_ts, end_ts;
	double drand48();
	int maxlen;
	int off;
	struct timespec timeo = { 3, 0};

	if (argc != 1 && argc != 3) {
		fprintf(stderr, "Usage: %s <hisip> <count>\n", argv[0]);
		exit(1);
	}

	uld = uld_open(NULL, 0, 0, 0, 0);
	if (uld == NULL) {
		fprintf(stderr, "uld_open failed\n");
		exit(1);
	}

	fprintf(stderr, "my ip %x, my mac %s\n\n", uld->ip,
		ether_ntoa((struct ether_addr *)uld->mac)); 

	if (argc == 1) {	/* target */
		port = udp_open_port(uld, 7, 0);
		for (;;) {
			skb = udp_recv(port, &src, &sport);
			if (skb) {
				udp_send(port, skb, src, sport);
			}
		}
	} else {		/* initiator */
		maxudp = uld->mtu - 28;
fprintf(stderr, "MTU %d maxUDP %d\n", uld->mtu, maxudp);
		buf = malloc(2*maxudp);
		count = atoi(argv[2]);
		h = gethostbyname(argv[1]);
                if (h == NULL) {
                        fprintf(stderr, "Can't parse %s for remote ip\n", argv[2]);
                        exit(1);
                }
                hisip = ntohl(*(int *)h->h_addr);
		port = udp_open_port(uld, 1234, 0);
		srand48(getpid());
		for (i=0; i<2*maxudp; i++)
			buf[i] = drand48() * 256;
	    for (maxlen=4; maxlen < maxudp; maxlen += 12) {
again:
		clock_gettime(CLOCK_MONOTONIC, &begin_ts);
		len = maxlen;
		for (c=0; c<count; c++) {
			off = drand48() * maxudp;
			udp_write(port, buf+off, len, hisip, 7);
			do {
				skb = udp_recv_timed(port, &src, &sport, &timeo);
			} while (skb && skb->len != len);
			if (skb == NULL)
				goto again;
			if (skb->len != len || memcmp(buf+off, skb->data, len))
				fprintf(stderr, "!%d %d\n", len, skb->len);
			skb_free(skb);
		}
		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		intvl = end_ts.tv_nsec - begin_ts.tv_nsec;
		intvl += 1000000000*(end_ts.tv_sec - begin_ts.tv_sec);
		intvl /= count;
		fprintf(stderr, "len %d: rtt %.02f usec\n", maxlen, intvl/1000);
	    }
	}
}
