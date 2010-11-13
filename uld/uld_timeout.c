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
#include <time.h>
#include <pthread.h>

#include "uld.h"
#include "kcompat.h"

struct tentry {
	struct tentry *next;
	struct timespec time;
	void	(*fun)(void *);
	void	*arg;
};

#define	CLOCK_LT(a, b) ((a.tv_sec < b.tv_sec) || (a.tv_sec == b.tv_sec && a.tv_nsec < b.tv_nsec))

void timeout_check(struct uld *uld)
{
	struct tentry *e;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
top:
	uld_spin_lock(&uld->tlock);
	while ((e = uld->tlist)) {
		if (CLOCK_LT(ts, e->time))
			break;
		/* something to do */
		uld->tlist = e->next;
		e->next = NULL;
		uld_spin_unlock(&uld->tlock);
		(e->fun)(e->arg);
		free(e);
		goto top;
	}
	uld_spin_unlock(&uld->tlock);
}

void timeout_add(struct uld *uld, struct timespec *ts, void (*fun)(void *), void *arg)
{
	struct tentry *e, *new, **prev;

	new = calloc(1, sizeof(struct tentry));
	new->time = *ts;
	new->fun = fun;
	new->arg = arg;

	uld_spin_lock(&uld->tlock);
	prev = &uld->tlist;
	for (e = uld->tlist; e; e = e->next) {
		if (CLOCK_LT(new->time, e->time)) {
			new->next = e;
			break;
		}
		prev = &e->next;
	}
	*prev = new;
	uld_spin_unlock(&uld->tlock);
}

void timeout_add_usec(struct uld *uld, int usec, void (*fun)(void *), void *arg)
{
	struct timespec ts;
	long long nsec ;

	nsec = usec;
	nsec *= 1000;
#define Billion 1000000000
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += nsec / Billion;
	ts.tv_nsec += (nsec % Billion);
	if (ts.tv_nsec >= Billion) {
		ts.tv_nsec -= Billion;
		ts.tv_sec += 1;
	}
	timeout_add(uld, &ts, fun, arg);
}

void timeout_cancel(struct uld *uld, void (*fun)(void *), void *arg)
{
	struct tentry *e, *next, **prev;

	uld_spin_lock(&uld->tlock);
	prev = &uld->tlist;
	for (e = uld->tlist; e; e = next) {
		next = e->next;
		if (e->fun == fun && e->arg == arg) {
			*prev = next;
			free(e);
		} else
			prev = &e->next;
	}
	uld_spin_unlock(&uld->tlock);
}

u32 jiffies()
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	
	return (u32)(ts.tv_sec*HZ + (ts.tv_nsec * (long long)HZ / Billion));
}

#ifdef notdef
void foo(void *t)
{
	unsigned int nsec = (int)t;
	printf("%d\n", nsec);
}

struct uld uld;
main()
{
	double drand48();
	double x;
	struct timespec now, ts;
	int i;
	unsigned long long inc;

	clock_gettime(CLOCK_MONOTONIC, &now);
	for (i=0; i<1000; i++) {
		x = drand48();
		inc = 200000000000 * x;
		ts.tv_sec = now.tv_sec + (inc/1000000000);
		ts.tv_nsec = now.tv_nsec + (inc%1000000000);
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000000000;
		}
		timeout_add(&uld, &ts, foo, (void *)(inc/1000));
	}
	for (;;)
		timeout_check(&uld);
}
#endif
