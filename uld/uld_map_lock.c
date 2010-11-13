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
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>

#include "uld.h"
#include "skbuff.h"
#include "kcompat.h"
#include "../vfio/vfio_lib.h"

static void new_chunk(struct uld *uld)
{
	int err;
	int slop;
	unsigned long pa;

	uld->p_left = 0;
	uld->p_virt_free = malloc(CHUNKSIZE);
	if (!uld->p_virt_free) {
		perror("chunk buf alloc");
		exit(1);
	}
	uld->p_left = CHUNKSIZE;
	slop = 4096 - (0xFFF & (long)uld->p_virt_free);
	if (slop != 4096) {
		uld->p_virt_free += slop;
		uld->p_left -= 4096;
	}
	err = vfio_map_lock(uld->fd, uld->p_virt_free, uld->p_left, &pa);
	if (err) {
		fprintf(stderr, "uld_map_lock failed\n");
		exit(1);
	}
	uld->p_phys_free = pa;
}

void *uld_alloc_map_lock(struct uld *uld, int size, dma_addr_t *pa)
{
	void *va;

	size += 127;	/* need 128B alignment for ixvf rings */
	size &= ~127;

	if (uld->p_left < size)
		new_chunk(uld);

	uld->p_left -= size;
	va = uld->p_virt_free;
	uld->p_virt_free += size;
	*pa = uld->p_phys_free;
	uld->p_phys_free += size;

	return va;
}

void uld_free_map_lock(struct uld *uld, int size, void *va, dma_addr_t pa)
{
	/* nada */
}

/* skb_global_lock is held */
struct sk_buff *skb_alloc_new(struct uld *uld)
{
	struct sk_buff *skb;
	int size;

	size = uld->mtu + ETH_HLEN + 2;
	skb = calloc(1, sizeof *skb);
	skb->buf = uld_alloc_map_lock(uld, size, &skb->dma_addr); 
	skb->buf_size = size;
	skb->data = skb->buf;

	return skb;
}

__thread struct sk_buff *skb_local_free;
__thread int skb_local_count;
