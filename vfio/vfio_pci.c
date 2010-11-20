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

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#define __USE_UNIX98 1
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/pci_regs.h>

#include "../uld/kcompat.h"
#include "../uld/uld.h"
#include "vfio_lib.h"

#define DRIVER	"/sys/bus/pci/drivers/vfio"

int vfio_open(char **namep)
{
	int domain, bus, device, function;
	char *pciname, *canonname;
	char devname[100];
	DIR *dirp;
	struct dirent *de;
	struct stat statbuf;
	int fd;

	pciname = *namep;
	if (sscanf(pciname, "%x:%x:%x.%x", &domain, &bus, &device, &function) != 4) {
		domain = 0;
		if (sscanf(pciname, "%x:%x.%x", &bus, &device, &function) != 3) {
			function = 0;
			if (sscanf(pciname, "%x:%x", &bus, &device) != 2) {
				fprintf(stderr, "pci_dev_open: %s - bad format\n", pciname);
				return -1;
			}
		}
	}
	canonname = malloc(16);
	sprintf(canonname, "%04x:%02x:%02x.%x", domain, bus, device, function);
	pciname = canonname;
	*namep = canonname;

	sprintf(devname, DRIVER "/%s", pciname);
	if (stat(devname, &statbuf) < 0) {
		perror(devname);
		fprintf(stderr, "pci_dev_open: PCI device %s not bound to vfio driver\n", pciname);
		return -1;
	}
	sprintf(devname, DRIVER "/%s/vfio", pciname);
	dirp = opendir(devname);
	if (dirp == NULL) {
		perror(devname);
		return -1;
	}
	while ((de = readdir(dirp)) != NULL) {
		if (strncmp(de->d_name, "vfio", 4) == 0)
			break;
	}
	if (de == NULL) {
		fprintf(stderr, "cant find name in %s\n", devname);
		closedir(dirp);
		return -1;
	}
	sprintf(devname, "/dev/%s", de->d_name);
	closedir(dirp);
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		perror(devname);
		return -1;
	}
	return fd;
}

u8 pci_read_config_byte(int pci_fd, u16 off)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;
	u8 wd = 0;

	if (pread64(pci_fd, &wd, 1, cfg_off) != 1)
		perror("pread config_byte");
	return wd;
}

u16 pci_read_config_word(int pci_fd, u16 off)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;
	u16 wd = 0;

	if (pread64(pci_fd, &wd, 2, cfg_off) != 2)
		perror("pread config_word");
	return le16toh(wd);
}

u32 pci_read_config_dword(int pci_fd, u16 off)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;
	u32 wd = 0;

	if (pread64(pci_fd, &wd, 4, cfg_off) != 4)
		perror("pread config_dword");
	return le32toh(wd);
}

void pci_write_config_byte(int pci_fd, u16 off, u8 wd)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;

	if (pwrite64(pci_fd, &wd, 1, cfg_off) != 1)
		perror("pwrite config_dword");
}

void pci_write_config_word(int pci_fd, u16 off, u16 wd)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;

	wd = htole16(wd);
	if (pwrite64(pci_fd, &wd, 2, cfg_off) != 2)
		perror("pwrite config_dword");
}

void pci_write_config_dword(int pci_fd, u16 off, u32 wd)
{
	off64_t cfg_off = VFIO_PCI_CONFIG_OFF + off;

	wd = htole32(wd);
	if (pwrite64(pci_fd, &wd, 4, cfg_off) != 4)
		perror("pwrite config_dword");
}

u32 pci_resource_len(int pci_fd, int bar)
{
	if (ioctl(pci_fd, VFIO_BAR_LEN, &bar))
		return -errno;
	return bar;
}

void *pci_mmap_bar(int pci_fd, int bar, int rw)
{
	void *foo;
	u32 barlen;

	barlen = pci_resource_len(pci_fd, bar);
	foo = mmap64(NULL,
			barlen,
			rw ? PROT_READ+PROT_WRITE : PROT_READ,
			MAP_SHARED,
			pci_fd,
			vfio_pci_space_to_offset(bar));
	if (foo == (void *)-1) {
		perror("pci_mmap_bar");
		return NULL;
	}
	return foo;
}

void pci_munmap_bar(int pci_fd, int bar, void *foo)
{
	u32 barlen;

	barlen = pci_resource_len(pci_fd, bar);
	(void) munmap(foo, barlen);
}

int pci_enable_msix(int pci_fd, struct pollfd *vecs, int nvec)
{
	int *msix_fds;
	int i;

	msix_fds = calloc(sizeof(int), 1 + nvec);
	if (msix_fds == NULL)
		return -ENOMEM;
	msix_fds[0] = nvec;
	for (i = 0; i < nvec; i++)
		msix_fds[i + 1] = vecs[i].fd;
	if (ioctl(pci_fd, VFIO_EVENTFDS_MSIX, msix_fds) < 0) {
		perror("VFIO_EVENTFDS_MSIX");
		return -errno;
	}
	return 0;
}

int pci_disable_msix(int pci_fd)
{
	int msix = 0;

	if (ioctl(pci_fd, VFIO_EVENTFDS_MSIX, &msix) < 0)
		return -errno;
	return 0;
}

int pci_enable_irq(int pci_fd, int event_fd)
{
	if (ioctl(pci_fd, VFIO_EVENTFD_IRQ, &event_fd))
		return -errno;
	pci_unmask_irq(pci_fd);
	return 0;
}

void pci_unmask_irq(int pci_fd)
{
	u16 cmd;

	cmd = pci_read_config_word(pci_fd, PCI_COMMAND);
	cmd &= ~PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word(pci_fd, PCI_COMMAND, cmd);
}

void pci_set_master(int pci_fd)
{
	u16 cmd;

	cmd = pci_read_config_word(pci_fd, PCI_COMMAND);
	cmd |= PCI_COMMAND_MASTER;
	pci_write_config_word(pci_fd, PCI_COMMAND, cmd);
}


int uiommu_fd(void)
{
	int fd;

	fd = open("/dev/uiommu", 0);
	if (fd < 0)
		perror("/dev/uiommu");
	return fd;
}

int pci_set_domain(int pci_fd, int mmu_fd)
{
	if (ioctl(pci_fd, VFIO_DOMAIN_SET, &mmu_fd) < 0) {
		perror("pci_set_domain");
		return -errno;
	}
	return 0;
}
