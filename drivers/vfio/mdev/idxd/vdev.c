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

static u64 idxd_pci_config[] = {
	0x0010000000008086ULL,
	0x0080000008800000ULL,
	0x000000000000000cULL,
	0x000000000000000cULL,
	0x0000000000000000ULL,
	0x2010808600000000ULL,
	0x0000004000000000ULL,
	0x000000ff00000000ULL,
	0x0000060000015011ULL, /* MSI-X capability, hardcoded 2 entries, Encoded as N-1 */
	0x0000070000000000ULL,
	0x0000000000920010ULL, /* PCIe capability */
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
};

static void vidxd_do_command(struct vdcm_idxd *vidxd, u32 val);

static void vidxd_reset_config(struct vdcm_idxd *vidxd)
{
	u16 *devid = (u16 *)(vidxd->cfg + PCI_DEVICE_ID);
	struct idxd_device *idxd = vidxd->idxd;

	memset(vidxd->cfg, 0, VIDXD_MAX_CFG_SPACE_SZ);
	memcpy(vidxd->cfg, idxd_pci_config, sizeof(idxd_pci_config));

	if (idxd->data->type == IDXD_TYPE_DSA)
		*devid = PCI_DEVICE_ID_INTEL_DSA_SPR0;
	else if (idxd->data->type == IDXD_TYPE_IAX)
		*devid = PCI_DEVICE_ID_INTEL_IAX_SPR0;
}

static inline void vidxd_reset_mmio(struct vdcm_idxd *vidxd)
{
	memset(&vidxd->bar0, 0, VIDXD_MAX_MMIO_SPACE_SZ);
}

void vidxd_init(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	vidxd_reset_config(vidxd);
	vidxd_reset_mmio(vidxd);

	vidxd->bar_size[0] = VIDXD_BAR0_SIZE;
	vidxd->bar_size[1] = VIDXD_BAR2_SIZE;

	vidxd_mmio_init(vidxd);

	if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED) {
		idxd_wq_disable(wq);
		wq->state = IDXD_WQ_LOCKED;
	}
}

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

static void vidxd_report_swerror(struct vdcm_idxd *vidxd, unsigned int error)
{
	vidxd_set_swerr(vidxd, error);
	send_swerr_interrupt(vidxd);
}

int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	u32 offset = pos & (vidxd->bar_size[0] - 1);
	u8 *bar0 = vidxd->bar0;
	struct device *dev = &vidxd->mdev->dev;

	dev_dbg(dev, "vidxd mmio W %d %x %x: %llx\n", vidxd->wq->id, size,
		offset, get_reg_val(buf, size));

	if (((size & (size - 1)) != 0) || (offset & (size - 1)) != 0)
		return -EINVAL;

	/* If we don't limit this, we potentially can write out of bound */
	if (size > sizeof(u32))
		return -EINVAL;

	switch (offset) {
	case IDXD_GENCFG_OFFSET ... IDXD_GENCFG_OFFSET + 3:
		/* Write only when device is disabled. */
		if (vidxd_state(vidxd) == IDXD_DEVICE_STATE_DISABLED) {
			dev_warn(dev, "Guest writes to unsupported GENCFG register\n");
			memcpy(bar0 + offset, buf, size);
		}
		break;

	case IDXD_GENCTRL_OFFSET:
		memcpy(bar0 + offset, buf, size);
		break;

	case IDXD_INTCAUSE_OFFSET:
		bar0[offset] &= ~(get_reg_val(buf, 1) & GENMASK(4, 0));
		break;

	case IDXD_CMD_OFFSET: {
		u32 *cmdsts = (u32 *)(bar0 + IDXD_CMDSTS_OFFSET);
		u32 val = get_reg_val(buf, size);

		if (size != sizeof(u32))
			return -EINVAL;

		/* Check and set command in progress */
		if (test_and_set_bit(IDXD_CMDS_ACTIVE_BIT, (unsigned long *)cmdsts) == 0)
			vidxd_do_command(vidxd, val);
		else
			vidxd_report_swerror(vidxd, DSA_ERR_CMD_REG);
		break;
	}

	case IDXD_SWERR_OFFSET:
		/* W1C */
		bar0[offset] &= ~(get_reg_val(buf, 1) & GENMASK(1, 0));
		break;

	case VIDXD_MSIX_TABLE_OFFSET ...  VIDXD_MSIX_TABLE_OFFSET + VIDXD_MSIX_TBL_SZ - 1: {
		int index = (offset - VIDXD_MSIX_TABLE_OFFSET) / 0x10;
		u8 *msix_entry = &bar0[VIDXD_MSIX_TABLE_OFFSET + index * 0x10];
		u64 *pba = (u64 *)(bar0 + VIDXD_MSIX_PBA_OFFSET);
		u8 ctrl, new_mask;
		int ims_index, ims_off;
		u32 ims_ctrl, ims_mask;
		struct idxd_device *idxd = vidxd->idxd;

		memcpy(bar0 + offset, buf, size);
		ctrl = msix_entry[MSIX_ENTRY_CTRL_BYTE];

		new_mask = ctrl & MSIX_ENTRY_MASK_INT;
		if (!new_mask && test_and_clear_bit(index, (unsigned long *)pba))
			vidxd_send_interrupt(vidxd, index);

		if (index == 0)
			break;

		ims_index = dev_msi_hwirq(dev, index - 1);
		ims_off = idxd->ims_offset + ims_index * 16 + sizeof(u64);
		ims_ctrl = ioread32(idxd->reg_base + ims_off);
		ims_mask = ims_ctrl & MSIX_ENTRY_MASK_INT;

		if (new_mask == ims_mask)
			break;

		if (new_mask)
			ims_ctrl |= MSIX_ENTRY_MASK_INT;
		else
			ims_ctrl &= ~MSIX_ENTRY_MASK_INT;

		iowrite32(ims_ctrl, idxd->reg_base + ims_off);
		/* readback to flush */
		ims_ctrl = ioread32(idxd->reg_base + ims_off);
		break;
	}

	case VIDXD_MSIX_PERM_OFFSET ...  VIDXD_MSIX_PERM_OFFSET + VIDXD_MSIX_PERM_TBL_SZ - 1:
		memcpy(bar0 + offset, buf, size);
		break;
	} /* offset */

	return 0;
}

int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	u32 offset = pos & (vidxd->bar_size[0] - 1);
	struct device *dev = &vidxd->mdev->dev;

	memcpy(buf, vidxd->bar0 + offset, size);

	dev_dbg(dev, "vidxd mmio R %d %x %x: %llx\n",
		vidxd->wq->id, size, offset, get_reg_val(buf, size));
	return 0;
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

static void vidxd_mmio_init_grpcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union group_cap_reg *grp_cap = (union group_cap_reg *)(bar0 + IDXD_GRPCAP_OFFSET);

	/* single group for current implementation */
	grp_cap->num_groups = 1;
}

static void vidxd_mmio_init_grpcfg(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	struct grpcfg *grpcfg = (struct grpcfg *)(bar0 + VIDXD_GRPCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_group *group = wq->group;
	int i;

	/*
	 * At this point, we are only exporting a single workqueue for
	 * each mdev.
	 */
	grpcfg->wqs[0] = BIT(0);
	for (i = 0; i < group->num_engines; i++)
		grpcfg->engines |= BIT(i);
	grpcfg->flags.bits = group->grpcfg.flags.bits;
}

static void vidxd_mmio_init_wqcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	struct idxd_wq *wq = vidxd->wq;
	union wq_cap_reg *wq_cap = (union wq_cap_reg *)(bar0 + IDXD_WQCAP_OFFSET);

	wq_cap->total_wq_size = wq->size;
	wq_cap->num_wqs = 1;
	wq_cap->dedicated_mode = 1;
}

static void vidxd_mmio_init_wqcfg(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	struct idxd_wq *wq = vidxd->wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *wqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);

	wqcfg->wq_size = wq->size;
	wqcfg->wq_thresh = wq->threshold;
	wqcfg->mode = WQCFG_MODE_DEDICATED;
	wqcfg->priority = wq->priority;
	wqcfg->max_xfer_shift = idxd->hw.gen_cap.max_xfer_shift;
	wqcfg->max_batch_shift = idxd->hw.gen_cap.max_batch_shift;
}

static void vidxd_mmio_init_engcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union engine_cap_reg *engcap = (union engine_cap_reg *)(bar0 + IDXD_ENGCAP_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_group *group = wq->group;

	engcap->num_engines = group->num_engines;
}

static void vidxd_mmio_init_gencap(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u8 *bar0 = vidxd->bar0;
	union gen_cap_reg *gencap = (union gen_cap_reg *)(bar0 + IDXD_GENCAP_OFFSET);

	gencap->overlap_copy = idxd->hw.gen_cap.overlap_copy;
	gencap->cache_control_mem = idxd->hw.gen_cap.cache_control_mem;
	gencap->cache_control_cache = idxd->hw.gen_cap.cache_control_cache;
	gencap->cmd_cap = 1;
	gencap->dest_readback = idxd->hw.gen_cap.dest_readback;
	gencap->drain_readback = idxd->hw.gen_cap.drain_readback;
	gencap->max_xfer_shift = idxd->hw.gen_cap.max_xfer_shift;
	gencap->max_batch_shift = idxd->hw.gen_cap.max_batch_shift;
	gencap->max_descs_per_engine = idxd->hw.gen_cap.max_descs_per_engine;
}

static void vidxd_mmio_init_cmdcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmdcap = (u32 *)(bar0 + IDXD_CMDCAP_OFFSET);

	*cmdcap |= BIT(IDXD_CMD_ENABLE_DEVICE) | BIT(IDXD_CMD_DISABLE_DEVICE) |
		   BIT(IDXD_CMD_DRAIN_ALL) | BIT(IDXD_CMD_ABORT_ALL) |
		   BIT(IDXD_CMD_RESET_DEVICE) | BIT(IDXD_CMD_ENABLE_WQ) |
		   BIT(IDXD_CMD_DISABLE_WQ) | BIT(IDXD_CMD_DRAIN_WQ) |
		   BIT(IDXD_CMD_ABORT_WQ) | BIT(IDXD_CMD_RESET_WQ) |
		   BIT(IDXD_CMD_DRAIN_PASID) | BIT(IDXD_CMD_ABORT_PASID) |
		   BIT(IDXD_CMD_REQUEST_INT_HANDLE) | BIT(IDXD_CMD_RELEASE_INT_HANDLE);
}

static void vidxd_mmio_init_opcap(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u64 opcode;
	u8 *bar0 = vidxd->bar0;
	u64 *opcap = (u64 *)(bar0 + IDXD_OPCAP_OFFSET);

	if (idxd->data->type == IDXD_TYPE_DSA) {
		opcode = BIT_ULL(DSA_OPCODE_NOOP) | BIT_ULL(DSA_OPCODE_BATCH) |
			 BIT_ULL(DSA_OPCODE_DRAIN) | BIT_ULL(DSA_OPCODE_MEMMOVE) |
			 BIT_ULL(DSA_OPCODE_MEMFILL) | BIT_ULL(DSA_OPCODE_COMPARE) |
			 BIT_ULL(DSA_OPCODE_COMPVAL) | BIT_ULL(DSA_OPCODE_CR_DELTA) |
			 BIT_ULL(DSA_OPCODE_AP_DELTA) | BIT_ULL(DSA_OPCODE_DUALCAST) |
			 BIT_ULL(DSA_OPCODE_CRCGEN) | BIT_ULL(DSA_OPCODE_COPY_CRC) |
			 BIT_ULL(DSA_OPCODE_DIF_CHECK) | BIT_ULL(DSA_OPCODE_DIF_INS) |
			 BIT_ULL(DSA_OPCODE_DIF_STRP) | BIT_ULL(DSA_OPCODE_DIF_UPDT) |
			 BIT_ULL(DSA_OPCODE_CFLUSH);
		*opcap = opcode;
	} else if (idxd->data->type == IDXD_TYPE_IAX) {
		opcode = BIT_ULL(IAX_OPCODE_NOOP) | BIT_ULL(IAX_OPCODE_DRAIN) |
			 BIT_ULL(IAX_OPCODE_MEMMOVE);
		*opcap = opcode;
		opcap++;
		opcode = OPCAP_BIT(IAX_OPCODE_DECOMPRESS) |
			 OPCAP_BIT(IAX_OPCODE_COMPRESS);
		*opcap = opcode;
	}
}

static void vidxd_mmio_init_version(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u32 *version;

	version = (u32 *)(vidxd->bar0 + VIDXD_VERSION_OFFSET);
	*version = idxd->hw.version;
}

void vidxd_mmio_init(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union offsets_reg *offsets;

	memset(vidxd->bar0, 0, VIDXD_BAR0_SIZE);

	vidxd_mmio_init_version(vidxd);
	vidxd_mmio_init_gencap(vidxd);
	vidxd_mmio_init_wqcap(vidxd);
	vidxd_mmio_init_grpcap(vidxd);
	vidxd_mmio_init_engcap(vidxd);
	vidxd_mmio_init_opcap(vidxd);

	offsets = (union offsets_reg *)(bar0 + IDXD_TABLE_OFFSET);
	offsets->grpcfg = VIDXD_GRPCFG_OFFSET / 0x100;
	offsets->wqcfg = VIDXD_WQCFG_OFFSET / 0x100;
	offsets->msix_perm = VIDXD_MSIX_PERM_OFFSET / 0x100;

	vidxd_mmio_init_cmdcap(vidxd);
	memset(bar0 + VIDXD_MSIX_PERM_OFFSET, 0, VIDXD_MSIX_PERM_TBL_SZ);
	vidxd_mmio_init_grpcfg(vidxd);
	vidxd_mmio_init_wqcfg(vidxd);
}

static void idxd_complete_command(struct vdcm_idxd *vidxd, enum idxd_cmdsts_err val)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmd = (u32 *)(bar0 + IDXD_CMD_OFFSET);
	u32 *cmdsts = (u32 *)(bar0 + IDXD_CMDSTS_OFFSET);
	u32 *intcause = (u32 *)(bar0 + IDXD_INTCAUSE_OFFSET);
	struct device *dev = &vidxd->mdev->dev;

	*cmdsts = val;
	dev_dbg(dev, "%s: cmd: %#x  status: %#x\n", __func__, *cmd, val);

	if (*cmd & IDXD_CMD_INT_MASK) {
		*intcause |= IDXD_INTC_CMD;
		vidxd_send_interrupt(vidxd, 0);
	}
}

static void vidxd_enable(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);

	if (gensts->state == IDXD_DEVICE_STATE_ENABLED)
		return idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_ENABLED);

	/* Check PCI configuration */
	if (!(vidxd->cfg[PCI_COMMAND] & PCI_COMMAND_MASTER))
		return idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_BUSMASTER_EN);

	gensts->state = IDXD_DEVICE_STATE_ENABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_disable(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq;
	union wqcfg *vwqcfg;
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);
	struct mdev_device *mdev = vidxd->mdev;
	struct device *dev = &mdev->dev;
	int rc;

	if (gensts->state == IDXD_DEVICE_STATE_DISABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DIS_DEV_EN);
		return;
	}

	vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	wq = vidxd->wq;

	rc = idxd_wq_disable(wq);
	if (rc < 0) {
		dev_warn(dev, "vidxd disable (wq disable) failed.\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	vwqcfg->wq_state = IDXD_WQ_DISABLED;
	gensts->state = IDXD_DEVICE_STATE_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_drain_all(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	idxd_wq_drain(wq);
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_drain(struct vdcm_idxd *vidxd, int val)
{
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;

	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOT_EN);
		return;
	}

	idxd_wq_drain(wq);
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_abort_all(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;
	int rc;

	rc = idxd_wq_abort(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_abort(struct vdcm_idxd *vidxd, int val)
{
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	int rc;

	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOT_EN);
		return;
	}

	rc = idxd_wq_abort(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

void vidxd_reset(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq;
	int rc;

	gensts->state = IDXD_DEVICE_STATE_DRAIN;
	wq = vidxd->wq;

	if (wq->state == IDXD_WQ_ENABLED) {
		rc = idxd_wq_abort(wq);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}

		rc = idxd_wq_disable(wq);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}
	}

	vidxd_mmio_init(vidxd);
	vwqcfg->wq_state = IDXD_WQ_DISABLED;
	gensts->state = IDXD_DEVICE_STATE_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_reset(struct vdcm_idxd *vidxd, int wq_id_mask)
{
	struct idxd_wq *wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	int rc;

	wq = vidxd->wq;
	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOT_EN);
		return;
	}

	rc = idxd_wq_abort(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	rc = idxd_wq_disable(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	vwqcfg->wq_state = IDXD_WQ_DEV_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_alloc_int_handle(struct vdcm_idxd *vidxd, int operand)
{
	bool ims = !!(operand & CMD_INT_HANDLE_IMS);
	u32 cmdsts;
	struct mdev_device *mdev = vidxd->mdev;
	struct device *dev = &mdev->dev;
	int ims_idx, vidx;

	vidx = operand & GENMASK(15, 0);

	/* vidx cannot be 0 since that's emulated and does not require IMS handle */
	if (vidx <= 0 || vidx >= VIDXD_MAX_MSIX_VECS) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX);
		return;
	}

	if (ims) {
		dev_warn(dev, "IMS allocation is not implemented yet\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_NO_HANDLE);
		return;
	}

	/*
	 * The index coming from the guest driver will start at 1. Vector 0 is
	 * the command interrupt and is emulated by the vdcm. Here we are asking
	 * for the IMS index that's backing the I/O vectors from the relative
	 * index to the mdev device. This index would start at 0. So for a
	 * passed in vidx that is 1, we pass 0 to dev_msi_hwirq() and so forth.
	 */
	ims_idx = dev_msi_hwirq(dev, vidx - 1);
	cmdsts = ims_idx << IDXD_CMDSTS_RES_SHIFT;
	dev_dbg(dev, "requested index %d handle %d\n", vidx, ims_idx);
	idxd_complete_command(vidxd, cmdsts);
}

static void vidxd_release_int_handle(struct vdcm_idxd *vidxd, int operand)
{
	struct mdev_device *mdev = vidxd->mdev;
	struct device *dev = &mdev->dev;
	bool ims = !!(operand & CMD_INT_HANDLE_IMS);
	int handle, i;
	bool found = false;

	handle = operand & GENMASK(15, 0);
	if (ims) {
		dev_dbg(dev, "IMS allocation is not implemented yet\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX_RELEASE);
		return;
	}

	/* IMS backed entry start at 1, 0 is emulated vector */
	for (i = 1; i < VIDXD_MAX_MSIX_VECS; i++) {
		if (dev_msi_hwirq(dev, i) == handle) {
			found = true;
			break;
		}
	}

	if (!found) {
		dev_dbg(dev, "Freeing unallocated int handle.\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX_RELEASE);
	}

	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_enable(struct vdcm_idxd *vidxd, int wq_id)
{
	struct idxd_wq *wq;
	u8 *bar0 = vidxd->bar0;
	union wq_cap_reg *wqcap;
	struct mdev_device *mdev = vidxd->mdev;
	struct device *dev = &mdev->dev;
	struct idxd_device *idxd;
	union wqcfg *vwqcfg;
	unsigned long flags;
	u32 wq_pasid;
	int priv, rc;

	if (wq_id >= VIDXD_MAX_WQS) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_WQIDX);
		return;
	}

	idxd = vidxd->idxd;
	wq = vidxd->wq;

	vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET + wq_id * 32);
	wqcap = (union wq_cap_reg *)(bar0 + IDXD_WQCAP_OFFSET);

	if (vidxd_state(vidxd) != IDXD_DEVICE_STATE_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOTEN);
		return;
	}

	if (vwqcfg->wq_state != IDXD_WQ_DEV_DISABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_ENABLED);
		return;
	}

	if (wq_dedicated(wq) && wqcap->dedicated_mode == 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_MODE);
		return;
	}

	priv = 1;
	rc = idxd_mdev_get_pasid(mdev, &vidxd->vdev, &wq_pasid);
	if (rc < 0) {
		dev_warn(dev, "idxd pasid setup failed wq %d: %d\n", wq->id, rc);
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_PASID_EN);
		return;
	}

	dev_dbg(dev, "program pasid %d in wq %d\n", wq_pasid, wq->id);
	spin_lock_irqsave(&idxd->dev_lock, flags);
	idxd_wq_setup_pasid(wq, wq_pasid);
	idxd_wq_setup_priv(wq, priv);
	spin_unlock_irqrestore(&idxd->dev_lock, flags);
	rc = idxd_wq_enable(wq);
	if (rc < 0) {
		dev_dbg(dev, "vidxd enable wq %d failed\n", wq->id);
		spin_lock_irqsave(&idxd->dev_lock, flags);
		idxd_wq_clear_pasid(wq);
		idxd_wq_setup_priv(wq, 0);
		spin_unlock_irqrestore(&idxd->dev_lock, flags);
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	vwqcfg->wq_state = IDXD_WQ_DEV_ENABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_disable(struct vdcm_idxd *vidxd, int wq_id_mask)
{
	struct idxd_wq *wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	int rc;

	wq = vidxd->wq;
	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOT_EN);
		return;
	}

	rc = idxd_wq_disable(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	vwqcfg->wq_state = IDXD_WQ_DEV_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static bool command_supported(struct vdcm_idxd *vidxd, u32 cmd)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmd_cap = (u32 *)(bar0 + IDXD_CMDCAP_OFFSET);

	return !!(*cmd_cap & BIT(cmd));
}

static void vidxd_do_command(struct vdcm_idxd *vidxd, u32 val)
{
	union idxd_command_reg *reg = (union idxd_command_reg *)(vidxd->bar0 + IDXD_CMD_OFFSET);
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);
	struct mdev_device *mdev = vidxd->mdev;
	struct device *dev = &mdev->dev;

	reg->bits = val;

	dev_dbg(dev, "%s: cmd code: %u reg: %x\n", __func__, reg->cmd, reg->bits);
	if (!command_supported(vidxd, reg->cmd)) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_CMD);
		return;
	}

	if (gensts->state == IDXD_DEVICE_STATE_HALT) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	switch (reg->cmd) {
	case IDXD_CMD_ENABLE_DEVICE:
		vidxd_enable(vidxd);
		break;
	case IDXD_CMD_DISABLE_DEVICE:
		vidxd_disable(vidxd);
		break;
	case IDXD_CMD_DRAIN_ALL:
		vidxd_drain_all(vidxd);
		break;
	case IDXD_CMD_ABORT_ALL:
		vidxd_abort_all(vidxd);
		break;
	case IDXD_CMD_RESET_DEVICE:
		vidxd_reset(vidxd);
		break;
	case IDXD_CMD_ENABLE_WQ:
		vidxd_wq_enable(vidxd, reg->operand);
		break;
	case IDXD_CMD_DISABLE_WQ:
		vidxd_wq_disable(vidxd, reg->operand);
		break;
	case IDXD_CMD_DRAIN_WQ:
		vidxd_wq_drain(vidxd, reg->operand);
		break;
	case IDXD_CMD_ABORT_WQ:
		vidxd_wq_abort(vidxd, reg->operand);
		break;
	case IDXD_CMD_RESET_WQ:
		vidxd_wq_reset(vidxd, reg->operand);
		break;
	case IDXD_CMD_REQUEST_INT_HANDLE:
		vidxd_alloc_int_handle(vidxd, reg->operand);
		break;
	case IDXD_CMD_RELEASE_INT_HANDLE:
		vidxd_release_int_handle(vidxd, reg->operand);
		break;
	default:
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_CMD);
		break;
	}
}
