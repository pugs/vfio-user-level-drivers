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
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/pci_regs.h>

#include "kcompat.h"

#include "uld.h"
#include "skbuff.h"
#include "../uenic/enic_res.h"
#include "../uenic/enic.h"
#include "../ixvf/ixvf_uld.h"
#include "../igbvf/igbvf_uld.h"
#include "../vfio/vfio_lib.h"

struct nic nictable[] = {
	{ 0x1137, 0x0043, "enic", enic_open, enic_close, enic_skb_read, enic_skb_write, },
	{ 0x8086, 0x10ed, "ixvf", ixvf_uld_open, ixvf_uld_close, ixvf_skb_read, ixvf_skb_write, },
	{ 0x8086, 0x10ca, "igbvf", igbvf_uld_open, igbvf_uld_close, igbvf_skb_read, igbvf_skb_write, },
	{ 0, },
};

void *uld_dispatch_thread(void *arg)
{
	struct uld *uld = (struct uld *)arg;

	for (;;) {
		uld_dispatch(uld, !uld->spin);
	}
}

static struct uld *uldlist;

void sig_handle(int signum)
{
	struct uld *uld;

	for (uld = uldlist; uld; uld = uld->uldnext) {
		if (uld->nic) {
fprintf(stderr, "Closing nic\n");
			uld->nic->close(uld);
			uld->nic = NULL;
		}
	}
	exit(1);
}

struct sigaction sigact = {
	.sa_handler = sig_handle,
	.sa_flags = SA_RESETHAND,
};

int get_num(char *file)
{
	int fd;
	char buf[20];
	int n;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror(file);
		return -1;
	}
	n = read(fd, buf, 20);
	if (n <= 0) {
		perror(file);
		return -1;
	}
	close(fd);
	if (n < 20)
		buf[n] = 0;
	else
		buf[19] = 0;
	return (int)strtol(buf, NULL, 0);
}


struct uld *uld_open(char *argname,
			unsigned int ip,
			unsigned int mask,
			unsigned int gw,
			int mtu)
{
	int fd;
	struct uld *uld;
	struct hostent *h;
	static int first = 1;
	int pci_ven, pci_dev, pci_subsys_ven, pci_subsys_dev;
	struct nic *nic;
	char *pciname = argname;

	if (first) {
		first = 0;
		pthread_spin_init(&skb_global_lock, PTHREAD_PROCESS_PRIVATE);
		arp_init();
		srand48(getpid());
	}
	if (pciname == NULL) {
		pciname = getenv("ULD_PCI");
		if (pciname == NULL) {
			fprintf(stderr, "uld_open: no ULD_PCI\n");
			return NULL;
		}
	}
	fd = vfio_open(&pciname);
	if (fd < 0)
		return NULL;
	pci_set_domain(fd, uiommu_fd());
	pci_ven =	pci_read_config_word(fd, PCI_VENDOR_ID);
	pci_dev =	pci_read_config_word(fd, PCI_DEVICE_ID);
	pci_subsys_ven = pci_read_config_word(fd, PCI_SUBSYSTEM_VENDOR_ID);
	pci_subsys_dev = pci_read_config_word(fd, PCI_SUBSYSTEM_ID);
	fprintf(stderr, "%s: device type: %04x:%04x (%04x:%04x)\n", pciname,
			pci_ven, pci_dev, pci_subsys_ven, pci_subsys_dev);

	for (nic = nictable; nic->vendor; nic++) {
		if (nic->vendor == pci_ven && nic->device == pci_dev)
			break;
	}
	if (nic->vendor == 0) {
		fprintf(stderr, "unsupported device type\n");
		return NULL;
	}

	uld = calloc(1, sizeof (struct uld));
	if (!uld)
		return NULL;
	uld->fd = fd;

	uld->nic = nic;
	uld->pciname = pciname;

	if (ip == 0) {
		if (getenv("ULD_IP")) {
			h = gethostbyname(getenv("ULD_IP"));
			if (h == NULL) {
				fprintf(stderr, "Bad IP '%s'\n", getenv("ULD_IP"));
				return NULL;
			}
			ip = ntohl(*(int *)h->h_addr);
		}
	}
	uld->ip = ip;
	if (mask)
		uld->netmask = mask;
	else {
		uld->netmask = 0xFFFFFF00;
		if (getenv("ULD_NETMASK")) {
			h = gethostbyname(getenv("ULD_NETMASK"));
			if (h == NULL) {
				fprintf(stderr, "Bad ULD_NETMASK '%s'\n", getenv("ULD_NETMASK"));
				return NULL;
			}
			uld->netmask = ntohl(*(int *)h->h_addr);
		}
	}
	if (gw) 
		uld->gw = gw;
	else {
		if (getenv("ULD_GW")) {
			h = gethostbyname(getenv("ULD_GW"));
			if (h == NULL) {
				fprintf(stderr, "Bad ULD_GW '%s'\n", getenv("ULD_GW"));
				return NULL;
			}
			uld->gw = ntohl(*(int *)h->h_addr);
		} else
			uld->gw = (uld->ip & uld->netmask) + 1;
	}
	if (mtu == 0) {
		if (getenv("ULD_MTU"))
			mtu = atoi(getenv("ULD_MTU"));
		else
			mtu = 1500;
	}
	uld->mtu = mtu;

	if (getenv("ULD_SPIN"))
		uld->spin = 1;

	sigaction(SIGHUP, &sigact, NULL); 
	sigaction(SIGINT, &sigact, NULL); 
	sigaction(SIGTERM, &sigact, NULL); 

	if (uld->nic->open(uld) == NULL) {
		fprintf(stderr, "nic open failed\n");
		close(fd);
		free(uld);
		return NULL;
	}
	uld->uldnext = uldlist;
	uldlist = uld;

	while (!uld->linkup)
		uld_dispatch(uld, 0);
fprintf(stderr, "link up!\n");
	sleep(1); /* we need this, but why? */
	/* send gratuitous arp */
	if (uld->ip) {
		arp_req_out(uld, uld->ip);
		arp_req_out(uld, uld->ip);
	}
	return uld;
}

void uld_allow_threads(struct uld *uld)
{
	pthread_t threadid;

	pthread_spin_init(&uld->tlock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&uld->mlock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&uld->ulock, PTHREAD_PROCESS_PRIVATE);
	uld->threaded = 1;
	pthread_create(&threadid, NULL, uld_dispatch_thread, (void *)uld);
}

struct sk_buff *uld_skb_read(struct uld *uld, int sync)
{
	if (uld->nic == NULL) {
		fprintf(stderr, "Bad call to uld_skb_read\n");
		exit(1);
	}
	return uld->nic->read_skb(uld, sync);
}

int uld_skb_write(struct uld *uld, struct sk_buff *skb)
{
	int ret;
	int wait = 1;

	if (uld->nic == NULL) {
		fprintf(stderr, "Bad call to uld_skb_write\n");
		exit(1);
	}
	ret = uld->nic->skb_write(uld, skb);
	while (ret == -EBUSY) {
		uld_dispatch(uld, 0);
		usleep(wait);
		wait *= 2;
		if (wait > 100000) wait = 100000;
		ret = uld->nic->skb_write(uld, skb);
	}
	if (ret)
		fprintf(stderr, "uld_skb_write err %d\n", ret);
	return ret;
}

void uld_dispatch(struct uld *uld, int wait)
{
	struct sk_buff *skb;
	struct ethhdr *eh;

	timeout_check(uld);
	skb = uld_skb_read(uld, wait);
	if (skb == NULL)
		return;
	eh = (struct ethhdr *)skb->data;
	switch (ntohs(eh->h_proto)) {
	case ETHERTYPE_ARP:
		if (uld->ip) uld_handle_arp(uld, skb);
		else skb_free(skb);
		break;
	case ETHERTYPE_IP:
		if (uld->ip) uld_handle_ip(uld, skb);
		else skb_free(skb);
		break;
	default:
		skb_free(skb);
		break;
	}
}
