/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2020 Intel Corporation. All rights rsvd. */

#ifndef _IDXD_MDEV_H_
#define _IDXD_MDEV_H_

/* two 64-bit BARs implemented */
#define VIDXD_MAX_BARS			2
#define VIDXD_MAX_CFG_SPACE_SZ		4096
#define VIDXD_MAX_MMIO_SPACE_SZ		8192
#define VIDXD_MSIX_TBL_SZ_OFFSET	0x42
#define VIDXD_CAP_CTRL_SZ		0x100
#define VIDXD_GRP_CTRL_SZ		0x100
#define VIDXD_WQ_CTRL_SZ		0x100
#define VIDXD_WQ_OCPY_INT_SZ		0x20
#define VIDXD_MSIX_TBL_SZ		0x90
#define VIDXD_MSIX_PERM_TBL_SZ		0x48

#define VIDXD_MSIX_PERM_OFFSET		0x300
#define VIDXD_GRPCFG_OFFSET		0x400
#define VIDXD_WQCFG_OFFSET		0x500
#define VIDXD_MSIX_TABLE_OFFSET		0x600
#define VIDXD_MSIX_PBA_OFFSET		0x700
#define VIDXD_IMS_OFFSET		0x1000

#define VIDXD_BAR0_SIZE			0x2000
#define VIDXD_BAR2_SIZE			0x2000
#define VIDXD_MAX_MSIX_VECS		2
#define VIDXD_MAX_MSIX_ENTRIES		VIDXD_MAX_MSIX_VECS
#define VIDXD_MAX_WQS			1

struct vdcm_idxd {
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct mdev_device *mdev;
	int num_wqs;

	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];
	struct mutex dev_lock; /* lock for vidxd resources */
};

static inline u64 get_reg_val(void *buf, int size)
{
	u64 val = 0;

	switch (size) {
	case 8:
		val = *(u64 *)buf;
		break;
	case 4:
		val = *(u32 *)buf;
		break;
	case 2:
		val = *(u16 *)buf;
		break;
	case 1:
		val = *(u8 *)buf;
		break;
	}

	return val;
}

static inline u8 vidxd_state(struct vdcm_idxd *vidxd)
{
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);

	return gensts->state;
}

int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count);
int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size);
#endif
