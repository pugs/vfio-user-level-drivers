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
#include <pcap.h>

#include "../uld/skbuff.h"
#include "../uld/uld.h"

main(int argc, char **argv)
{
	struct uld *uld;
	struct sk_buff *skb;
	int i;
	pcap_t *p;
	pcap_dumper_t *pd;
	struct pcap_pkthdr ph;
	char *ifname;
	
	ifname = NULL;
	if (argc == 2) {
		ifname = argv[1];
	}
	uld = uld_open(ifname, 0, 0, 0, 0);
	if (uld == NULL)
		exit(1);

	p = pcap_open_dead(DLT_EN10MB, 65535);
	if (!p) fprintf(stderr, "pcap_open_dead failed\n");
	pd = pcap_dump_open(p, "-");
	if (!pd) fprintf(stderr, "pcap_dump_open failed\n");
	for(;;) {
		skb = uld_skb_read(uld, 1);
		if (skb == NULL)
			continue;
		ph.ts.tv_sec = skb->tstamp.tv_sec;
		ph.ts.tv_usec = skb->tstamp.tv_nsec/1000;
		ph.len = ph.caplen = skb->len;
		pcap_dump((void *)pd, &ph, skb->data);
		pcap_dump_flush(pd);
		skb_free(skb);
	}
}
