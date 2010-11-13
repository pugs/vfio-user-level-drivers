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
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "../uld/kcompat.h"

#include "vfio_lib.h"

static struct nl_handle *global_nl_handle;
static int nl_family;

struct vfio_reg_entry {
	struct	vfio_reg_entry *next;
	u64		mask;
	vfio_eventfn_t	handler;
	void		*arg;
	u16		domain;
	u8		bus;
	u8		slot;
	u8		fn;
};
struct vfio_reg_entry *vfio_reg_head;

static int vfio_parse_netlink(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *genl;
	struct nlattr *attrs[VFIO_NL_ATTR_MAX+1];
	int cmd, domain, bus, slot, fn;
	struct vfio_reg_entry *e;

	genl = nlmsg_data(nlh);
	cmd = genl->cmd;
// Validate message and parse attributes
	genlmsg_parse(nlh, 0, attrs, VFIO_NL_ATTR_MAX, NULL);
	if (attrs[VFIO_ATTR_PCI_DOMAIN])
		domain = nla_get_u32(attrs[VFIO_ATTR_PCI_DOMAIN]);
	if (attrs[VFIO_ATTR_PCI_BUS])
		bus = nla_get_u16(attrs[VFIO_ATTR_PCI_BUS]);
	if (attrs[VFIO_ATTR_PCI_SLOT])
		slot = nla_get_u8(attrs[VFIO_ATTR_PCI_SLOT]);
	if (attrs[VFIO_ATTR_PCI_FUNC])
		fn = nla_get_u8(attrs[VFIO_ATTR_PCI_FUNC]);

	for (e = vfio_reg_head; e; e = e->next) {
		if (e->domain != domain)
			continue;
		if (e->bus != bus)
			continue;
		if (e->slot != slot)
			continue;
		if (e->fn != fn)
			continue;
		if ((e->mask & (1 << cmd)) == 0)
			continue;
		(e->handler)(e->arg, cmd);
	}
	return 0;
}

struct nl_handle *vfio_register_nl_callback(char *pciname, u64 mask,
					vfio_eventfn_t handler, void *arg)
{
	int domain, bus, slot, fn;
	struct nl_msg *msg;
	struct vfio_reg_entry *e;

	if (sscanf(pciname, "%x:%x:%x.%x", &domain, &bus, &slot, &fn) != 4) {
		fprintf(stderr, "vfio_register_nl_callback: bad pciname %s\n", pciname);
		return NULL;
	}

	for (e = vfio_reg_head; e; e = e->next) {
		if (e->domain != domain)
			continue;
		if (e->bus != bus)
			continue;
		if (e->slot != slot)
			continue;
		if (e->fn != fn)
			continue;
		break;
	}
	if (!e) {
		if (mask == 0)
			return NULL;
		e = calloc(1, sizeof(struct vfio_reg_entry));
		e->next = vfio_reg_head;
		vfio_reg_head = e;
	}
	e->mask = mask;
	e->handler = handler;
	e->arg = arg;
	e->domain = domain;
	e->bus = bus;
	e->slot = slot;
	e->fn = fn;

	if (global_nl_handle == NULL) {
		global_nl_handle = nl_handle_alloc();
		if (global_nl_handle == NULL) {
			fprintf(stderr, "can't alloc netlink handle\n");
			exit(1);
		}
		genl_connect(global_nl_handle);
		nl_family = genl_ctrl_resolve(global_nl_handle, "VFIO");
		if (nl_family < 0) {
			fprintf(stderr, "can't connect to VFIO netlink\n");
			exit(1);
		}
	}

	/* send registration message */
	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
			nl_family, 0, NLM_F_REQUEST,
			VFIO_MSG_REGISTER, 1);
	nla_put_u64(msg, VFIO_ATTR_MSGCAP, mask);
	nla_put_u32(msg, VFIO_ATTR_PCI_DOMAIN, domain);
	nla_put_u16(msg, VFIO_ATTR_PCI_BUS, bus);
	nla_put_u8(msg, VFIO_ATTR_PCI_SLOT, slot);
	nla_put_u8(msg, VFIO_ATTR_PCI_FUNC, fn);
	nl_send_auto_complete(global_nl_handle, msg);

	/* setup to receive callbacks */
	nl_disable_sequence_check(global_nl_handle);	/* needed for events */
	nl_socket_modify_cb(global_nl_handle, NL_CB_VALID, NL_CB_CUSTOM,
			vfio_parse_netlink, NULL);
	return global_nl_handle;
}	      
