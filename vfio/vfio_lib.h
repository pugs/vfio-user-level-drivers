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
#include "vfio.h"

int vfio_open(char **);

typedef void (*vfio_eventfn_t)(void *, int);
struct nl_handle *vfio_register_nl_callback(char *, u64, vfio_eventfn_t, void *);
int vfio_map_lock(int, void *, int, unsigned long *);
int vfio_un_map_lock(int, void *, int, unsigned long);

int pci_dev_open(char **);
unsigned char pci_read_config_byte(int, unsigned short);
unsigned short pci_read_config_word(int, unsigned short);
unsigned int pci_read_config_dword(int, unsigned short);
void pci_write_config_byte(int, unsigned short, unsigned char);
void pci_write_config_word(int, unsigned short, unsigned short);
void pci_write_config_dword(int, unsigned short, unsigned int);
unsigned int pci_resource_len(int, int);
void *pci_mmap_bar(int, int, int);
void pci_munmap_bar(int, int, void *);
void pci_set_master(int);
struct pollfd;
int pci_enable_msix(int, struct pollfd *, int);
int pci_disable_msix(int);
void pci_unmask_irq(int);
int pci_enable_irq(int, int);
int pci_set_domain(int pci_fd, int mmu_fd);
int uiommu_fd(void);
