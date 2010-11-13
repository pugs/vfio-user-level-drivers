/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
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

#include "../uld/kcompat.h"
#include "vfio_lib.h"

unsigned long top = 0xF0000000;

int vfio_map_lock(int fd, void *va, int size, unsigned long *pa)
{
	struct vfio_dma_map ml;

	ml.vaddr = (unsigned long)va;
	ml.size = size;
	top -= size;
	ml.dmaaddr = top;
	ml.flags = VFIO_FLAG_WRITE;
	if (ioctl(fd, VFIO_DMA_MAP_IOVA, (void *)&ml) < 0) {
		fprintf(stderr, "vaddr %llx size %x daddr %llx\n",
				ml.vaddr, size, ml.dmaaddr);
		perror("uld_map_lock ioctl");
		return -errno;
	}
	*pa = ml.dmaaddr;
fprintf(stderr, "map_lock ok va %lx pa %lx\n", (long)va, *pa);
	return 0;
}

int vfio_un_map_lock(int fd, void *va, int size, unsigned long pa)
{
	struct vfio_dma_map ml;

	ml.vaddr = (unsigned long)va;
	ml.size = size;
	ml.dmaaddr = pa;
	ml.flags = VFIO_FLAG_WRITE;
	if (ioctl(fd, VFIO_DMA_UNMAP, (void *)&ml)) {
		perror("uld_un_map_lock ioctl");
		return -errno;
	}
	return 0;
}
