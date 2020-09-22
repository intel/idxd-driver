// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Intel Corporation. All rights rsvd. */
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
#include <linux/irqchip/irq-ims-msi.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "mdev.h"

static const char idxd_dsa_1dwq_name[] = "dsa-1dwq-v1";
static const char idxd_iax_1dwq_name[] = "iax-1dwq-v1";

static int idxd_vdcm_set_irqs(struct vdcm_idxd *vidxd, uint32_t flags,
			      unsigned int index, unsigned int start,
			      unsigned int count, void *data);

int idxd_mdev_get_pasid(struct mdev_device *mdev, struct vfio_device *vdev, u32 *pasid)
{
	struct vfio_group *vfio_group = vdev->group;
	struct iommu_domain *iommu_domain;
	struct device *iommu_device = mdev_get_iommu_device(mdev);
	int rc;

	iommu_domain = vfio_group_iommu_domain(vfio_group);
	if (IS_ERR_OR_NULL(iommu_domain))
		return -ENODEV;

	rc = iommu_aux_get_pasid(iommu_domain, iommu_device);
	if (rc < 0)
		return -ENODEV;

	*pasid = (u32)rc;
	return 0;
}

static int idxd_vdcm_get_irq_count(struct vfio_device *vdev, int type)
{
	if (type == VFIO_PCI_MSIX_IRQ_INDEX)
		return VIDXD_MAX_MSIX_VECS;

	return 0;
}

static struct idxd_wq *find_any_dwq(struct idxd_device *idxd, struct vdcm_idxd_type *type)
{
	int i;
	struct idxd_wq *wq;
	unsigned long flags;

	switch (type->type) {
	case IDXD_MDEV_TYPE_DSA_1_DWQ:
		if (idxd->data->type != IDXD_TYPE_DSA)
			return NULL;
		break;
	case IDXD_MDEV_TYPE_IAX_1_DWQ:
		if (idxd->data->type != IDXD_TYPE_IAX)
			return NULL;
		break;
	default:
		return NULL;
	}

	spin_lock_irqsave(&idxd->dev_lock, flags);
	for (i = 0; i < idxd->max_wqs; i++) {
		wq = idxd->wqs[i];

		if (wq->state != IDXD_WQ_ENABLED)
			continue;

		if (!wq_dedicated(wq))
			continue;

		if (!is_idxd_wq_mdev(wq))
			continue;

		if (idxd_wq_refcount(wq) != 0)
			continue;

		spin_unlock_irqrestore(&idxd->dev_lock, flags);
		mutex_lock(&wq->wq_lock);
		if (idxd_wq_refcount(wq)) {
			spin_lock_irqsave(&idxd->dev_lock, flags);
			continue;
		}

		idxd_wq_get(wq);
		mutex_unlock(&wq->wq_lock);
		return wq;
	}

	spin_unlock_irqrestore(&idxd->dev_lock, flags);
	return NULL;
}

static struct vdcm_idxd *vdcm_vidxd_create(struct idxd_device *idxd, struct mdev_device *mdev,
					   struct vdcm_idxd_type *type)
{
	struct vdcm_idxd *vidxd;
	struct device *dev = &mdev->dev;
	struct idxd_wq *wq = NULL;
	int rc;

	wq = find_any_dwq(idxd, type);
	if (!wq)
		return ERR_PTR(-ENODEV);

	vidxd = kzalloc(sizeof(*vidxd), GFP_KERNEL);
	if (!vidxd) {
		rc = -ENOMEM;
		goto err;
	}

	mutex_init(&vidxd->dev_lock);
	vidxd->idxd = idxd;
	vidxd->mdev = mdev;
	vidxd->type = type;
	vidxd->num_wqs = VIDXD_MAX_WQS;
	dev_set_msi_domain(dev, idxd->ims_domain);

	mutex_lock(&wq->wq_lock);
	idxd_wq_get(wq);
	wq->vidxd = vidxd;
	vidxd->wq = wq;
	mutex_unlock(&wq->wq_lock);
	vidxd_init(vidxd);

	return vidxd;

 err:
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
	return ERR_PTR(rc);
}

static struct vdcm_idxd_type idxd_mdev_types[IDXD_MDEV_TYPES] = {
	{
		.name = idxd_dsa_1dwq_name,
		.type = IDXD_MDEV_TYPE_DSA_1_DWQ,
	},
	{
		.name = idxd_iax_1dwq_name,
		.type = IDXD_MDEV_TYPE_IAX_1_DWQ,
	},
};

static struct vdcm_idxd_type *idxd_vdcm_get_type(struct mdev_device *mdev)
{
	return &idxd_mdev_types[mdev_get_type_group_id(mdev)];
}

static const struct vfio_device_ops idxd_mdev_ops;

static int idxd_vdcm_probe(struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd;
	struct vdcm_idxd_type *type;
	struct device *dev, *parent;
	struct idxd_device *idxd;
	bool ims_map[VIDXD_MAX_MSIX_VECS];
	int rc;

	parent = mdev_parent_dev(mdev);
	idxd = dev_get_drvdata(parent);
	dev = &mdev->dev;
	mdev_set_iommu_device(mdev, parent);
	type = idxd_vdcm_get_type(mdev);

	vidxd = vdcm_vidxd_create(idxd, mdev, type);
	if (IS_ERR(vidxd)) {
		dev_err(dev, "failed to create vidxd: %ld\n", PTR_ERR(vidxd));
		return PTR_ERR(vidxd);
	}

	vfio_init_group_dev(&vidxd->vdev, &mdev->dev, &idxd_mdev_ops);

	ims_map[0] = 0;
	ims_map[1] = 1;
	rc = mdev_irqs_init(mdev, VIDXD_MAX_MSIX_VECS, ims_map);
	if (rc < 0)
		goto err;

	rc = vfio_register_group_dev(&vidxd->vdev);
	if (rc < 0)
		goto err_group_register;
	dev_set_drvdata(dev, vidxd);

	return 0;

err_group_register:
	mdev_irqs_free(mdev);
err:
	kfree(vidxd);
	return rc;
}

static void idxd_vdcm_remove(struct mdev_device *mdev)
{
	struct vdcm_idxd *vidxd = dev_get_drvdata(&mdev->dev);
	struct idxd_wq *wq = vidxd->wq;

	vfio_unregister_group_dev(&vidxd->vdev);
	mdev_irqs_free(mdev);
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);

	kfree(vidxd);
}

static int idxd_vdcm_open(struct vfio_device *vdev)
{
	return 0;
}

static void idxd_vdcm_close(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	idxd_vdcm_set_irqs(vidxd, VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
			   VFIO_PCI_MSIX_IRQ_INDEX, 0, 0, NULL);

	/* Re-initialize the VIDXD to a pristine state for re-use */
	vidxd_init(vidxd);
	mutex_unlock(&vidxd->dev_lock);
}

static ssize_t idxd_vdcm_rw(struct vfio_device *vdev, char *buf, size_t count, loff_t *ppos,
			    enum idxd_vdcm_rw mode)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	struct device *dev = vdev->dev;
	int rc = -EINVAL;

	if (index >= VFIO_PCI_NUM_REGIONS) {
		dev_err(dev, "invalid index: %u\n", index);
		return -EINVAL;
	}

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_cfg_write(vidxd, pos, buf, count);
		else
			rc = vidxd_cfg_read(vidxd, pos, buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_mmio_write(vidxd, vidxd->bar_val[0] + pos, buf, count);
		else
			rc = vidxd_mmio_read(vidxd, vidxd->bar_val[0] + pos, buf, count);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
	default:
		dev_err(dev, "unsupported region: %u\n", index);
	}

	return rc == 0 ? count : rc;
}

static ssize_t idxd_vdcm_read(struct vfio_device *vdev, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val), ppos,
					  IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

 read_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static ssize_t idxd_vdcm_write(struct vfio_device *vdev, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val,
					  sizeof(val), ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

write_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static int idxd_vdcm_mmap(struct vfio_device *vdev, struct vm_area_struct *vma)
{
	unsigned int wq_idx;
	unsigned long req_size, pgoff = 0, offset;
	pgprot_t pg_prot;
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_device *idxd = vidxd->idxd;
	enum idxd_portal_prot virt_portal, phys_portal;
	phys_addr_t base = pci_resource_start(idxd->pdev, IDXD_WQ_BAR);
	struct device *dev = vdev->dev;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	req_size = vma->vm_end - vma->vm_start;
	if (req_size > PAGE_SIZE)
		return -EINVAL;

	vma->vm_flags |= VM_DONTCOPY;

	offset = (vma->vm_pgoff << PAGE_SHIFT) &
		 ((1ULL << VFIO_PCI_OFFSET_SHIFT) - 1);

	wq_idx = offset >> (PAGE_SHIFT + 2);
	if (wq_idx >= 1) {
		dev_err(dev, "mapping invalid wq %d off %lx\n",
			wq_idx, offset);
		return -EINVAL;
	}

	/*
	 * Check and see if the guest wants to map to the limited or unlimited portal.
	 * The driver will allow mapping to unlimited portal only if the wq is a
	 * dedicated wq. Otherwise, it goes to limited.
	 */
	virt_portal = ((offset >> PAGE_SHIFT) & 0x3) == 1;
	phys_portal = IDXD_PORTAL_LIMITED;
	if (virt_portal == IDXD_PORTAL_UNLIMITED && wq_dedicated(wq))
		phys_portal = IDXD_PORTAL_UNLIMITED;

	/* We always map IMS portals to the guest */
	pgoff = (base + idxd_get_wq_portal_offset(wq->id, phys_portal,
						  IDXD_IRQ_IMS)) >> PAGE_SHIFT;

	dev_dbg(dev, "mmap %lx %lx %lx %lx\n", vma->vm_start, pgoff, req_size,
		pgprot_val(pg_prot));
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = pgoff;

	return remap_pfn_range(vma, vma->vm_start, pgoff, req_size, pg_prot);
}

static void vidxd_vdcm_reset(struct vdcm_idxd *vidxd)
{
	vidxd_reset(vidxd);
}

static int idxd_vdcm_set_irqs(struct vdcm_idxd *vidxd, uint32_t flags,
			      unsigned int index, unsigned int start,
			      unsigned int count, void *data)
{
	struct mdev_device *mdev = vidxd->mdev;

	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSI_IRQ_INDEX:
		break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			return mdev_set_msix_trigger(mdev, index, start, count, flags, data);
		}
		break;
	}

	return -ENOTTY;
}

static long idxd_vdcm_ioctl(struct vfio_device *vdev, unsigned int cmd, unsigned long arg)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned long minsz;
	int rc = -EINVAL;
	struct device *dev = vdev->dev;

	dev_dbg(dev, "vidxd %p ioctl, cmd: %d\n", vidxd, cmd);

	mutex_lock(&vidxd->dev_lock);
	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz) {
			rc = -EINVAL;
			goto out;
		}

		info.flags = VFIO_DEVICE_FLAGS_PCI;
		info.flags |= VFIO_DEVICE_FLAGS_RESET;
		info.num_regions = VFIO_PCI_NUM_REGIONS;
		info.num_irqs = VFIO_PCI_NUM_IRQS;

		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct vfio_region_info info;
		struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
		struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
		size_t size;
		int nr_areas = 1;
		int cap_type_id = 0;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz) {
			rc = -EINVAL;
			goto out;
		}

		switch (info.index) {
		case VFIO_PCI_CONFIG_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = VIDXD_MAX_CFG_SPACE_SZ;
			info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR0_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = vidxd->bar_size[info.index];
			if (!info.size) {
				info.flags = 0;
				break;
			}

			info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR1_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;
			info.flags = 0;
			break;
		case VFIO_PCI_BAR2_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.flags = VFIO_REGION_INFO_FLAG_CAPS | VFIO_REGION_INFO_FLAG_MMAP |
				     VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
			info.size = vidxd->bar_size[1];

			/*
			 * Every WQ has two areas for unlimited and limited
			 * MSI-X portals. IMS portals are not reported
			 */
			nr_areas = 2;

			size = sizeof(*sparse) + (nr_areas * sizeof(*sparse->areas));
			sparse = kzalloc(size, GFP_KERNEL);
			if (!sparse) {
				rc = -ENOMEM;
				goto out;
			}

			sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
			sparse->header.version = 1;
			sparse->nr_areas = nr_areas;
			cap_type_id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;

			/* Unlimited portal */
			sparse->areas[0].offset = 0;
			sparse->areas[0].size = PAGE_SIZE;

			/* Limited portal */
			sparse->areas[1].offset = PAGE_SIZE;
			sparse->areas[1].size = PAGE_SIZE;
			break;

		case VFIO_PCI_BAR3_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;
			info.flags = 0;
			dev_dbg(dev, "get region info bar:%d\n", info.index);
			break;

		case VFIO_PCI_ROM_REGION_INDEX:
		case VFIO_PCI_VGA_REGION_INDEX:
			dev_dbg(dev, "get region info index:%d\n", info.index);
			break;
		default: {
			if (info.index >= VFIO_PCI_NUM_REGIONS)
				rc = -EINVAL;
			else
				rc = 0;
			goto out;
		} /* default */
		} /* info.index switch */

		if ((info.flags & VFIO_REGION_INFO_FLAG_CAPS) && sparse) {
			if (cap_type_id == VFIO_REGION_INFO_CAP_SPARSE_MMAP) {
				rc = vfio_info_add_capability(&caps, &sparse->header,
							      sizeof(*sparse) + (sparse->nr_areas *
							      sizeof(*sparse->areas)));
				kfree(sparse);
				if (rc)
					goto out;
			}
		}

		if (caps.size) {
			if (info.argsz < sizeof(info) + caps.size) {
				info.argsz = sizeof(info) + caps.size;
				info.cap_offset = 0;
			} else {
				vfio_info_cap_shift(&caps, sizeof(info));
				if (copy_to_user((void __user *)arg + sizeof(info),
						 caps.buf, caps.size)) {
					kfree(caps.buf);
					rc = -EFAULT;
					goto out;
				}
				info.cap_offset = sizeof(info);
			}

			kfree(caps.buf);
		}
		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;
		u32 pasid;

		rc = idxd_mdev_get_pasid(vidxd->mdev, vdev, &pasid);
		if (rc < 0)
			goto out;
		mdev_irqs_set_pasid(vidxd->mdev, pasid);

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS) {
			rc = -EINVAL;
			goto out;
		}

		info.flags = VFIO_IRQ_INFO_EVENTFD;

		switch (info.index) {
		case VFIO_PCI_MSIX_IRQ_INDEX:
			info.flags |= VFIO_IRQ_INFO_NORESIZE;
			break;
		default:
			rc = -EINVAL;
			goto out;
		} /* switch(info.index) */

		info.flags = VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE;
		info.count = idxd_vdcm_get_irq_count(vdev, info.index);

		if (copy_to_user((void __user *)arg, &info, minsz))
			rc = -EFAULT;
		else
			rc = 0;
		goto out;
	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz)) {
			rc = -EFAULT;
			goto out;
		}

		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
			int max = idxd_vdcm_get_irq_count(vdev, hdr.index);

			rc = vfio_set_irqs_validate_and_prepare(&hdr, max, VFIO_PCI_NUM_IRQS,
								&data_size);
			if (rc) {
				dev_err(dev, "intel:vfio_set_irqs_validate_and_prepare failed\n");
				rc = -EINVAL;
				goto out;
			}

			if (data_size) {
				data = memdup_user((void __user *)(arg + minsz), data_size);
				if (IS_ERR(data)) {
					rc = PTR_ERR(data);
					goto out;
				}
			}
		}

		if (!data) {
			rc = -EINVAL;
			goto out;
		}

		rc = idxd_vdcm_set_irqs(vidxd, hdr.flags, hdr.index, hdr.start, hdr.count, data);
		kfree(data);
		goto out;
	} else if (cmd == VFIO_DEVICE_RESET) {
		vidxd_vdcm_reset(vidxd);
	}

 out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static const struct vfio_device_ops idxd_mdev_ops = {
	.name = "vfio-mdev",
	.open = idxd_vdcm_open,
	.release = idxd_vdcm_close,
	.read = idxd_vdcm_read,
	.write = idxd_vdcm_write,
	.mmap = idxd_vdcm_mmap,
	.ioctl = idxd_vdcm_ioctl,
};

static ssize_t name_show(struct mdev_type *mtype, struct mdev_type_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", idxd_mdev_types[mtype_get_type_group_id(mtype)].name);
}
static MDEV_TYPE_ATTR_RO(name);

static int find_available_mdev_instances(struct idxd_device *idxd, struct vdcm_idxd_type *type)
{
	int count = 0, i;
	unsigned long flags;

	switch (type->type) {
	case IDXD_MDEV_TYPE_DSA_1_DWQ:
		if (idxd->data->type != IDXD_TYPE_DSA)
			return 0;
		break;
	case IDXD_MDEV_TYPE_IAX_1_DWQ:
		if (idxd->data->type != IDXD_TYPE_IAX)
			return 0;
		break;
	default:
		return 0;
	}

	spin_lock_irqsave(&idxd->dev_lock, flags);
	for (i = 0; i < idxd->max_wqs; i++) {
		struct idxd_wq *wq;

		wq = idxd->wqs[i];
		if (!is_idxd_wq_mdev(wq) || !wq_dedicated(wq) || idxd_wq_refcount(wq))
			continue;

		count++;
	}
	spin_unlock_irqrestore(&idxd->dev_lock, flags);

	return count;
}

static ssize_t available_instances_show(struct mdev_type *mtype,
					struct mdev_type_attribute *attr,
					char *buf)
{
	struct device *dev = mtype_get_parent_dev(mtype);
	struct idxd_device *idxd = dev_get_drvdata(dev);
	int count;
	struct vdcm_idxd_type *type;

	type = &idxd_mdev_types[mtype_get_type_group_id(mtype)];
	count = find_available_mdev_instances(idxd, type);

	return sysfs_emit(buf, "%d\n", count);
}
static MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct mdev_type *mtype, struct mdev_type_attribute *attr,
			       char *buf)
{
	return sysfs_emit(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *idxd_mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group idxd_mdev_type_dsa_group0 = {
	.name = idxd_dsa_1dwq_name,
	.attrs = idxd_mdev_types_attrs,
};

static struct attribute_group idxd_mdev_type_iax_group0 = {
	.name = idxd_iax_1dwq_name,
	.attrs = idxd_mdev_types_attrs,
};

static struct attribute_group *idxd_mdev_type_groups[] = {
	&idxd_mdev_type_dsa_group0,
	&idxd_mdev_type_iax_group0,
	NULL,
};

static struct mdev_driver idxd_vdcm_driver = {
	.driver = {
		.name = "idxd-mdev",
		.owner = THIS_MODULE,
		.mod_name = KBUILD_MODNAME,
	},
	.probe = idxd_vdcm_probe,
	.remove = idxd_vdcm_remove,
	.supported_type_groups = idxd_mdev_type_groups,
};

static int idxd_mdev_drv_probe(struct device *dev)
{
	struct idxd_wq *wq = confdev_to_wq(dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (!is_idxd_wq_mdev(wq))
		return -ENODEV;

	rc = drv_enable_wq(wq);
	if (rc < 0)
		return rc;

	/*
	 * The kref count starts at 1 on initialization. So the first device gets
	 * probed, we want to setup the mdev and do the host initialization. The
	 * follow on probes the driver want to just take a kref. On the remove side, once
	 * the kref hits 0, the driver will do the host cleanup and unregister from the
	 * mdev framework.
	 */
	mutex_lock(&idxd->kref_lock);
	if (!idxd->mdev_host_init) {
		rc = idxd_mdev_host_init(idxd, &idxd_vdcm_driver);
		if (rc < 0) {
			mutex_unlock(&idxd->kref_lock);
			drv_disable_wq(wq);
			dev_warn(dev, "mdev device init failed!\n");
			return -ENXIO;
		}
		idxd->mdev_host_init = true;
	} else {
		kref_get(&idxd->mdev_kref);
	}
	mutex_unlock(&idxd->kref_lock);

	get_device(dev);
	dev_info(dev, "wq %s enabled\n", dev_name(dev));
	return 0;
}

static void idxd_mdev_drv_remove(struct device *dev)
{
	struct idxd_wq *wq = confdev_to_wq(dev);
	struct idxd_device *idxd = wq->idxd;

	drv_disable_wq(wq);
	mutex_lock(&wq->wq_lock);
	if (wq->state == IDXD_WQ_LOCKED)
		wq->state = IDXD_WQ_DISABLED;
	mutex_unlock(&wq->wq_lock);

	dev_info(dev, "wq %s disabled\n", dev_name(dev));
	kref_put_mutex(&idxd->mdev_kref, idxd_mdev_host_release, &idxd->kref_lock);
	put_device(dev);
}

static struct idxd_device_ops mdev_wq_ops = {
	.notify_error = idxd_wq_vidxd_send_errors,
};

static struct idxd_device_driver idxd_mdev_driver = {
	.probe = idxd_mdev_drv_probe,
	.remove = idxd_mdev_drv_remove,
	.name = idxd_mdev_drv_name,
	.ops = &mdev_wq_ops,
};

static int __init idxd_mdev_init(void)
{
	int rc;

	rc = idxd_driver_register(&idxd_mdev_driver);
	if (rc < 0)
		return rc;

	rc = mdev_register_driver(&idxd_vdcm_driver);
	if (rc < 0) {
		idxd_driver_unregister(&idxd_mdev_driver);
		return rc;
	}

	return 0;
}

static void __exit idxd_mdev_exit(void)
{
	mdev_unregister_driver(&idxd_vdcm_driver);
	idxd_driver_unregister(&idxd_mdev_driver);
}

module_init(idxd_mdev_init);
module_exit(idxd_mdev_exit);

MODULE_IMPORT_NS(IDXD);
MODULE_SOFTDEP("pre: idxd");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS_IDXD_DEVICE(0);
