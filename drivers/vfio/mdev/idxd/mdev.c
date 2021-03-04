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

static struct mdev_driver idxd_vdcm_driver = {
	.driver = {
		.name = "idxd-mdev",
		.owner = THIS_MODULE,
		.mod_name = KBUILD_MODNAME,
	},
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
	dev_info(dev, "wq %s disabled\n", dev_name(dev));
	kref_put_mutex(&idxd->mdev_kref, idxd_mdev_host_release, &idxd->kref_lock);
	put_device(dev);
}

static struct idxd_device_driver idxd_mdev_driver = {
	.probe = idxd_mdev_drv_probe,
	.remove = idxd_mdev_drv_remove,
	.name = idxd_mdev_drv_name,
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
