// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019,2020 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/msi.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "mdev.h"

void vidxd_send_interrupt(struct vdcm_idxd *vidxd, int vector)
{
	struct mdev_device *mdev = vidxd->mdev;
	u8 *bar0 = vidxd->bar0;
	u8 *msix_entry = &bar0[VIDXD_MSIX_TABLE_OFFSET + vector * 0x10];
	u64 *pba = (u64 *)(bar0 + VIDXD_MSIX_PBA_OFFSET);
	u8 ctrl;

	ctrl = msix_entry[MSIX_ENTRY_CTRL_BYTE];
	if (ctrl & MSIX_ENTRY_MASK_INT)
		set_bit(vector, (unsigned long *)pba);
	else
		mdev_msix_send_signal(mdev, vector);
}

static void vidxd_set_swerr(struct vdcm_idxd *vidxd, unsigned int error)
{
	union sw_err_reg *swerr = (union sw_err_reg *)(vidxd->bar0 + IDXD_SWERR_OFFSET);

	if (!swerr->valid) {
		memset(swerr, 0, sizeof(*swerr));
		swerr->valid = 1;
		swerr->error = error;
	} else if (!swerr->overflow) {
		swerr->overflow = 1;
	}
}

static inline void send_swerr_interrupt(struct vdcm_idxd *vidxd)
{
	union genctrl_reg *genctrl = (union genctrl_reg *)(vidxd->bar0 + IDXD_GENCTRL_OFFSET);
	u32 *intcause = (u32 *)(vidxd->bar0 + IDXD_INTCAUSE_OFFSET);

	if (!genctrl->softerr_int_en)
		return;

	*intcause |= IDXD_INTC_ERR;
	vidxd_send_interrupt(vidxd, 0);
}

static inline void send_halt_interrupt(struct vdcm_idxd *vidxd)
{
	union genctrl_reg *genctrl = (union genctrl_reg *)(vidxd->bar0 + IDXD_GENCTRL_OFFSET);
	u32 *intcause = (u32 *)(vidxd->bar0 + IDXD_INTCAUSE_OFFSET);

	if (!genctrl->halt_int_en)
		return;

	*intcause |= IDXD_INTC_HALT;
	vidxd_send_interrupt(vidxd, 0);
}

static void vidxd_report_pci_error(struct vdcm_idxd *vidxd)
{
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);

	vidxd_set_swerr(vidxd, DSA_ERR_PCI_CFG);
	/* set device to halt */
	gensts->reset_type = IDXD_DEVICE_RESET_FLR;
	gensts->state = IDXD_DEVICE_STATE_HALT;

	send_halt_interrupt(vidxd);
}

int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count)
{
	u32 offset = pos & 0xfff;
	struct device *dev = &vidxd->mdev->dev;

	memcpy(buf, &vidxd->cfg[offset], count);

	dev_dbg(dev, "vidxd pci R %d %x %x: %llx\n",
		vidxd->wq->id, count, offset, get_reg_val(buf, count));

	return 0;
}

/*
 * Much of the emulation code has been borrowed from Intel i915 cfg space
 * emulation code.
 * drivers/gpu/drm/i915/gvt/cfg_space.c:
 */

/*
 * Bitmap for writable bits (RW or RW1C bits, but cannot co-exist in one
 * byte) byte by byte in standard pci configuration space. (not the full
 * 256 bytes.)
 */
static const u8 pci_cfg_space_rw_bmp[PCI_INTERRUPT_LINE + 4] = {
	[PCI_COMMAND]		= 0xff, 0x07,
	[PCI_STATUS]		= 0x00, 0xf9, /* the only one RW1C byte */
	[PCI_CACHE_LINE_SIZE]	= 0xff,
	[PCI_BASE_ADDRESS_0 ... PCI_CARDBUS_CIS - 1] = 0xff,
	[PCI_ROM_ADDRESS]	= 0x01, 0xf8, 0xff, 0xff,
	[PCI_INTERRUPT_LINE]	= 0xff,
};

static void _pci_cfg_mem_write(struct vdcm_idxd *vidxd, unsigned int off, u8 *src,
			       unsigned int bytes)
{
	u8 *cfg_base = vidxd->cfg;
	u8 mask, new, old;
	int i = 0;

	for (; i < bytes && (off + i < sizeof(pci_cfg_space_rw_bmp)); i++) {
		mask = pci_cfg_space_rw_bmp[off + i];
		old = cfg_base[off + i];
		new = src[i] & mask;

		/**
		 * The PCI_STATUS high byte has RW1C bits, here
		 * emulates clear by writing 1 for these bits.
		 * Writing a 0b to RW1C bits has no effect.
		 */
		if (off + i == PCI_STATUS + 1)
			new = (~new & old) & mask;

		cfg_base[off + i] = (old & ~mask) | new;
	}

	/* For other configuration space directly copy as it is. */
	if (i < bytes)
		memcpy(cfg_base + off + i, src + i, bytes - i);
}

static inline void _write_pci_bar(struct vdcm_idxd *vidxd, u32 offset, u32 val, bool low)
{
	u32 *pval;

	/* BAR offset should be 32 bits algiend */
	offset = rounddown(offset, 4);
	pval = (u32 *)(vidxd->cfg + offset);

	if (low) {
		/*
		 * only update bit 31 - bit 4,
		 * leave the bit 3 - bit 0 unchanged.
		 */
		*pval = (val & GENMASK(31, 4)) | (*pval & GENMASK(3, 0));
	} else {
		*pval = val;
	}
}

static int _pci_cfg_bar_write(struct vdcm_idxd *vidxd, unsigned int offset, void *p_data,
			      unsigned int bytes)
{
	u32 new = *(u32 *)(p_data);
	bool lo = IS_ALIGNED(offset, 8);
	u64 size;
	unsigned int bar_id;

	/*
	 * Power-up software can determine how much address
	 * space the device requires by writing a value of
	 * all 1's to the register and then reading the value
	 * back. The device will return 0's in all don't-care
	 * address bits.
	 */
	if (new == 0xffffffff) {
		switch (offset) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
		case PCI_BASE_ADDRESS_2:
		case PCI_BASE_ADDRESS_3:
			bar_id = (offset - PCI_BASE_ADDRESS_0) / 8;
			size = vidxd->bar_size[bar_id];
			_write_pci_bar(vidxd, offset, size >> (lo ? 0 : 32), lo);
			break;
		default:
			/* Unimplemented BARs */
			_write_pci_bar(vidxd, offset, 0x0, false);
		}
	} else {
		switch (offset) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
		case PCI_BASE_ADDRESS_2:
		case PCI_BASE_ADDRESS_3:
			_write_pci_bar(vidxd, offset, new, lo);
			break;
		default:
			break;
		}
	}
	return 0;
}

int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size)
{
	struct device *dev = &vidxd->idxd->pdev->dev;

	if (size > 4)
		return -EINVAL;

	if (pos + size > VIDXD_MAX_CFG_SPACE_SZ)
		return -EINVAL;

	dev_dbg(dev, "vidxd pci W %d %x %x: %llx\n", vidxd->wq->id, size, pos,
		get_reg_val(buf, size));

	/* First check if it's PCI_COMMAND */
	if (IS_ALIGNED(pos, 2) && pos == PCI_COMMAND) {
		bool new_bme;
		bool bme;

		if (size > 2)
			return -EINVAL;

		new_bme = !!(get_reg_val(buf, 2) & PCI_COMMAND_MASTER);
		bme = !!(vidxd->cfg[pos] & PCI_COMMAND_MASTER);
		_pci_cfg_mem_write(vidxd, pos, buf, size);

		/* Flag error if turning off BME while device is enabled */
		if ((bme && !new_bme) && vidxd_state(vidxd) == IDXD_DEVICE_STATE_ENABLED)
			vidxd_report_pci_error(vidxd);
		return 0;
	}

	switch (pos) {
	case PCI_BASE_ADDRESS_0 ... PCI_BASE_ADDRESS_5:
		if (!IS_ALIGNED(pos, 4))
			return -EINVAL;
		return _pci_cfg_bar_write(vidxd, pos, buf, size);

	default:
		_pci_cfg_mem_write(vidxd, pos, buf, size);
	}
	return 0;
}

MODULE_LICENSE("GPL v2");
