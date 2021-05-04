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
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "mdev.h"

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

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
