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

#define VIDXD_VERSION_OFFSET		0
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

#define IDXD_MDEV_NAME_LEN		64
#define IDXD_MDEV_TYPES			2

enum idxd_mdev_type {
	IDXD_MDEV_TYPE_DSA_1_DWQ = 0,
	IDXD_MDEV_TYPE_IAX_1_DWQ,
};

struct vdcm_idxd_type {
	const char *name;
	enum idxd_mdev_type type;
	unsigned int avail_instance;
};

struct vdcm_idxd {
	struct vfio_device vdev;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct mdev_device *mdev;
	struct vdcm_idxd_type *type;
	int num_wqs;

	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];
	struct mutex dev_lock; /* lock for vidxd resources */
};

enum idxd_vdcm_rw {
	IDXD_VDCM_READ = 0,
	IDXD_VDCM_WRITE,
};

static inline struct vdcm_idxd *vdev_to_vidxd(struct vfio_device *vdev)
{
	return container_of(vdev, struct vdcm_idxd, vdev);
}

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

int idxd_mdev_get_pasid(struct mdev_device *mdev, struct vfio_device *vdev, u32 *pasid);

void vidxd_init(struct vdcm_idxd *vidxd);
void vidxd_reset(struct vdcm_idxd *vidxd);
void vidxd_mmio_init(struct vdcm_idxd *vidxd);
int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count);
int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size);
int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);
int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);

#endif
