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


/* glue for the OS independent part of ixgbe
 * includes register access macros
 */

#ifndef _IXGBEVF_OSDEP_H_
#define _IXGBEVF_OSDEP_H_

#include "kcompat.h"

#ifdef DBG
#define hw_dbg(hw, S, A...)	fprintf(stderr, KERN_DEBUG S, ## A)
#else
#define hw_dbg(hw, S, A...)      do {} while (0)
#endif

#ifdef DBG
#define IXGBE_WRITE_REG(a, reg, value) do {\
	switch (reg) { \
	case IXGBE_EIMS: \
	case IXGBE_EIMC: \
	case IXGBE_EIAM: \
	case IXGBE_EIAC: \
	case IXGBE_EICR: \
	case IXGBE_EICS: \
		printk("%s: Reg - 0x%05X, value - 0x%08X\n", __FUNCTION__, \
		       reg, (u32)(value)); \
	default: \
		break; \
	} \
	writel((value), ((a)->hw_addr + (reg))); \
} while (0)
#else
#define IXGBE_WRITE_REG(a, reg, value) writel((value), ((a)->hw_addr + (reg)))
#endif

#define IXGBE_READ_REG(a, reg) readl((a)->hw_addr + (reg))

#define IXGBE_WRITE_REG_ARRAY(a, reg, offset, value) ( \
    writel((value), ((a)->hw_addr + (reg) + ((offset) << 2))))

#define IXGBE_READ_REG_ARRAY(a, reg, offset) ( \
    readl((a)->hw_addr + (reg) + ((offset) << 2)))

#ifndef writeq
#define writeq(val, addr) writel((u32) (val), addr); \
	writel((u32) (val >> 32), (addr + 4));
#endif

#define IXGBE_WRITE_REG64(a, reg, value) writeq((value), ((a)->hw_addr + (reg)))

#define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_STATUS)
#define IXGBE_EEPROM_GRANT_ATTEMPS 100
#define IXGBE_HTONL(_i) htonl(_i)
#define IXGBE_HTONS(_i) htons(_i)

#endif /* _IXGBE_OSDEP_H_ */
