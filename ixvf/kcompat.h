/*******************************************************************************

  Intel 82599 Virtual Function driver
  Copyright(c) 1999 - 2009 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBEVF_KCOMPAT_H_
#define _IXGBEVF_KCOMPAT_H_

#define adapter_struct ixgbevf_adapter
#define adapter_q_vector ixgbevf_q_vector
#define CONFIG_IXGBEVF_MSIX

#undef CONFIG_PM

#undef CONFIG_NET_POLL_CONTROLLER

#define PMSG_SUSPEND 3

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif


#define mmiowb()

#ifdef CONFIG_PCI_IOV
#define VMDQ_P(p)   ((p) + adapter->num_vfs)
#else
#define VMDQ_P(p)   (p)
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef HAVE_NETIF_MSG
#define HAVE_NETIF_MSG 1
enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#else
#define NETIF_MSG_HW	0x2000
#define NETIF_MSG_WOL	0x4000
#endif /* HAVE_NETIF_MSG */

#ifndef unlikely
#define unlikely(_x) _x
#define likely(_x) _x
#endif

#ifndef WARN_ON
#define WARN_ON(x)
#endif

#ifndef DECLARE_BITMAP
#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#endif
#define DECLARE_BITMAP(name,bits) long name[BITS_TO_LONGS(bits)]
#endif

#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#ifndef VLAN_ETH_HLEN
#define VLAN_ETH_HLEN 18
#endif

#ifndef VLAN_ETH_FRAME_LEN
#define VLAN_ETH_FRAME_LEN 1518
#endif

#undef min
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#undef max
#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#ifndef min_t
#define min_t(type,x,y) ({ \
	type _x = (x); \
	type _y = (y); \
	_x < _y ? _x : _y; })
#endif

#ifndef max_t
#define max_t(type,x,y) ({ \
	type _x = (x); \
	type _y = (y); \
	_x > _y ? _x : _y; })
#endif


#endif
