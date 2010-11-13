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

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#ifndef DMA_ADDR_T
typedef unsigned long long dma_addr_t;
#define	DMA_ADDR_T	1
#endif
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef unsigned int bool;
#define	irqreturn_t	int
#define	IRQ_HANDLED	1
enum { false=0, true=1, };
#define	DMA_ADDR_T_DEFINED 1
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
typedef	u16 __le16;
typedef	u32 __le32;
typedef	u64 __le64;
#define	cpu_to_le16(x)	((unsigned short)(x))
#define	cpu_to_le32(x)	((unsigned int)(x))
#define	cpu_to_le64(x)	((unsigned long long)(x))
#define	le16_to_cpu(x)	((unsigned short)(x))
#define	le32_to_cpu(x)	((unsigned int)(x))
#define	le64_to_cpu(x)	((unsigned long long)(x))

#define	__iomem	volatile
#define	printk	fprintf
#define	KERN_ERR	stderr,
#define	KERN_INFO	stderr,
#define	KERN_WARNING	stderr,
#define	PFX	""

#define ____cacheline_aligned __attribute__((__aligned__(64)))
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define	ETH_ALEN	6
#define	ETH_HLEN	14
#define	NET_IP_ALIGN	2

#define	spinlock_t	pthread_spinlock_t
#define	spin_lock	pthread_spin_lock
#define	spin_unlock	pthread_spin_unlock
#define	spin_lock_init(x)	pthread_spin_init((x), PTHREAD_PROCESS_PRIVATE)

/*
 * Kernel backward-compatibility defintions
 */

#ifndef ioread8
#define ioread8 readb
#endif

#ifndef ioread16
#define ioread16 readw
#endif

#ifndef ioread32
#define ioread32 readl
#endif

#ifndef iowrite8
#define iowrite8 writeb
#endif

#ifndef iowrite16
#define iowrite16 writew
#endif

#ifndef iowrite32
#define iowrite32 writel
#endif

#define	readl(a)	(*(unsigned volatile int *)(a))
#define	readw(a)	(*(unsigned volatile short *)(a))
#define	readb(a)	(*(unsigned volatile char *)(a))
#define	writel(v, a)	*(unsigned volatile int *)(a) = (v)
#define	writew(v, a)	*(unsigned volatile short *)(a) = (v)
#define	writeb(v, a)	*(unsigned volatile char *)(a) = (v)

#define	HZ	1000
u32 jiffies();

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, 8*sizeof(long))

#define	DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

static inline void bitmap_zero(unsigned long *b, int n)
{
	int i;

	for (i=0; i<DIV_ROUND_UP(n, 8*sizeof(long)); i++)
		(b)[i] = 0;
}

static inline void clear_bit(unsigned long bit, unsigned long *b)
{
	(b)[bit / (8 * sizeof(long))] &= ~(1 << (bit % (8 * sizeof(long))));
}

static inline void set_bit(unsigned long bit, unsigned long *b)
{
	(b)[bit / (8 * sizeof(long))] |= (1 << (bit % (8 * sizeof(long))));
}

static inline int test_bit(unsigned long bit, unsigned long *b)
{
	return ((b)[bit / (8 * sizeof(long))] & (1 << (bit % (8 * sizeof(long))))) ? 1 : 0;
}

#define	pci_alloc_consistent	uld_alloc_map_lock
#define	pci_free_consistent	uld_free_map_lock
struct uld;
void *uld_alloc_map_lock(struct uld *uld, int size, dma_addr_t *pa);
void uld_free_map_lock(struct uld *uld, int size, void *va, dma_addr_t pa);
#define	kzalloc(sz, x)	calloc(1, (sz))
#define	kfree		free

#define	wmb	mfence
#define	rmb	mfence
// #define	mfence	__sync_synchronize
// static inline void mfence() { asm("mfence"); }
static inline void mfence() { }

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

#define BUG() do { \
        fprintf(stderr, "BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __FUNCTION__); \
        abort(); \
} while (0)
#define	BUG_ON(x)	if(x) BUG()

static inline void udelay(int t)
{
	struct timespec tv;
	unsigned long long ns;

	ns = (long long)t * 1000;
	tv.tv_nsec = ns % 1000000000;
	tv.tv_sec = ns / 1000000000;
	nanosleep(&tv, NULL);
}
	

#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
	unsigned long data;
	work_func_t func;
};

static inline int is_valid_ether_addr(u8 *addr)
{
	const char zaddr[6] = { 0, };

	return !(addr[0] & 1) && memcmp(addr, zaddr, 6);
}

static inline void random_ether_addr(u8 *addr)
{
	int fd = open("/dev/urandom", 0);
	read(fd, addr, 6);
	close(fd);
	addr [0] &= 0xfe;	/* clear multicast bit */
	addr [0] |= 0x02;	/* set local assignment bit (IEEE802) */
}
#endif /* _KCOMPAT_H_ */
