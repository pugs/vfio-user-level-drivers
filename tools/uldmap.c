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

#include "../uld/kcompat.h"
#include "../uld/skbuff.h"
#include "../uld/uld.h"

main(int argc, char **argv)
{
	struct uld *uld;
	struct sk_buff *skb;
	int i;
	char *ifname;
	dma_addr_t pa;
	char *va;
	int err;
	
	ifname = NULL;
	if (argc == 2) {
		ifname = argv[1];
	}
	uld = uld_open(ifname, 0, 0, 0, 0);
	if (uld == NULL)
		exit(1);
#define	SIZE 512*4096
	va = uld_alloc_map_lock(uld, SIZE, &pa);
	printf("va %lx pa %lx\n", (long)va, (long)pa);
	sleep(99999);
}
