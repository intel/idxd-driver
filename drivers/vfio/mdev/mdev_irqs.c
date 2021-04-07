// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mediate device IMS library code
 *
 * Copyright (c) 2021 Intel Corp. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/irqchip/irq-ims-msi.h>
#include <linux/eventfd.h>
#include <linux/irqreturn.h>
#include <linux/msi.h>
#include <linux/vfio.h>
#include <linux/irqbypass.h>
#include <linux/mdev.h>

static irqreturn_t mdev_irq_handler(int irq, void *arg)
{
	struct eventfd_ctx *trigger = arg;

	eventfd_signal(trigger, 1);
	return IRQ_HANDLED;
}

/*
 * Common helper routine to send signal to the eventfd that has been setup.
 *
 * @mdev_irq [in]		: struct mdev_irq context
 * @vector [in]			: vector index for eventfd
 *
 * No return value.
 */
void mdev_msix_send_signal(struct mdev_device *mdev, int vector)
{
	struct mdev_irq *mdev_irq = &mdev->mdev_irq;
	struct eventfd_ctx *trigger = mdev_irq->irq_entries[vector].trigger;

	if (!mdev_irq->irq_entries || !trigger) {
		dev_warn(&mdev->dev, "EventFD %d trigger not setup, can't send!\n", vector);
		return;
	}
	mdev_irq_handler(0, (void *)trigger);
}
EXPORT_SYMBOL_GPL(mdev_msix_send_signal);

static int mdev_msix_set_vector_signal(struct mdev_irq *mdev_irq, int vector, int fd)
{
	int rc, irq;
	struct mdev_device *mdev = irq_to_mdev(mdev_irq);
	struct mdev_irq_entry *entry;
	struct device *dev = &mdev->dev;
	struct eventfd_ctx *trigger;
	char *name;
	bool pasid_en;
	u32 auxval;

	if (vector < 0 || vector >= mdev_irq->num)
		return -EINVAL;

	entry = &mdev_irq->irq_entries[vector];

	if (entry->ims)
		irq = dev_msi_irq_vector(dev, entry->ims_id);
	else
		irq = 0;

	pasid_en = mdev_irq->pasid != INVALID_IOASID ? true : false;

	/* IMS and invalid pasid is not a valid configuration */
	if (entry->ims && !pasid_en)
		return -EINVAL;

	if (entry->trigger) {
		if (irq) {
			irq_bypass_unregister_producer(&entry->producer);
			free_irq(irq, entry->trigger);
			if (pasid_en) {
				auxval = ims_ctrl_pasid_aux(0, false);
				irq_set_auxdata(irq, IMS_AUXDATA_CONTROL_WORD, auxval);
			}
		}
		kfree(entry->name);
		eventfd_ctx_put(entry->trigger);
		entry->trigger = NULL;
	}

	if (fd < 0)
		return 0;

	name = kasprintf(GFP_KERNEL, "vfio-mdev-irq[%d](%s)", vector, dev_name(dev));
	if (!name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		kfree(name);
		return PTR_ERR(trigger);
	}

	entry->name = name;
	entry->trigger = trigger;

	if (!irq)
		return 0;

	if (pasid_en) {
		auxval = ims_ctrl_pasid_aux(mdev_irq->pasid, true);
		rc = irq_set_auxdata(irq, IMS_AUXDATA_CONTROL_WORD, auxval);
		if (rc < 0)
			goto err;
	}

	rc = request_irq(irq, mdev_irq_handler, 0, name, trigger);
	if (rc < 0)
		goto irq_err;

	entry->producer.token = trigger;
	entry->producer.irq = irq;
	rc = irq_bypass_register_producer(&entry->producer);
	if (unlikely(rc)) {
		dev_warn(dev, "irq bypass producer (token %p) registration fails: %d\n",
			 &entry->producer.token, rc);
		entry->producer.token = NULL;
	}

	return 0;

 irq_err:
	if (pasid_en) {
		auxval = ims_ctrl_pasid_aux(0, false);
		irq_set_auxdata(irq, IMS_AUXDATA_CONTROL_WORD, auxval);
	}
 err:
	kfree(name);
	eventfd_ctx_put(trigger);
	entry->trigger = NULL;
	return rc;
}

static int mdev_msix_set_vector_signals(struct mdev_irq *mdev_irq, unsigned int start,
					unsigned int count, int *fds)
{
	int i, j, rc = 0;

	if (start >= mdev_irq->num || start + count > mdev_irq->num)
		return -EINVAL;

	for (i = 0, j = start; j < count && !rc; i++, j++) {
		int fd = fds ? fds[i] : -1;

		rc = mdev_msix_set_vector_signal(mdev_irq, j, fd);
	}

	if (rc) {
		for (--j; j >= (int)start; j--)
			mdev_msix_set_vector_signal(mdev_irq, j, -1);
	}

	return rc;
}

static int mdev_msix_enable(struct mdev_irq *mdev_irq, int nvec)
{
	struct mdev_device *mdev = irq_to_mdev(mdev_irq);
	struct device *dev;
	int rc;

	if (nvec != mdev_irq->num)
		return -EINVAL;

	if (mdev_irq->ims_num) {
		dev = &mdev->dev;
		rc = msi_domain_alloc_irqs(dev_get_msi_domain(dev), dev, mdev_irq->ims_num);
		if (rc < 0)
			return rc;
	}

	mdev_irq->irq_type = VFIO_PCI_MSIX_IRQ_INDEX;
	return 0;
}

static int mdev_msix_disable(struct mdev_irq *mdev_irq)
{
	struct mdev_device *mdev = irq_to_mdev(mdev_irq);
	struct device *dev = &mdev->dev;
	struct irq_domain *irq_domain;

	mdev_msix_set_vector_signals(mdev_irq, 0, mdev_irq->num, NULL);
	irq_domain = dev_get_msi_domain(&mdev->dev);
	if (irq_domain)
		msi_domain_free_irqs(irq_domain, dev);
	mdev_irq->irq_type = VFIO_PCI_NUM_IRQS;
	return 0;
}

/*
 * Common helper function that sets up the MSIX vectors for the mdev device that are
 * Interrupt Message Store (IMS) backed. Certain mdev devices can have the first
 * vector emulated rather than backed by IMS.
 *
 *  @mdev [in]		: mdev device
 *  @index [in]		: type of VFIO vectors to setup
 *  @start [in]		: start position of the vector index
 *  @count [in]		: number of vectors
 *  @flags [in]		: VFIO_IRQ action to be taken
 *  @data [in]		: data accompanied for the call
 *  Return error code on failure or 0 on success.
 */

int mdev_set_msix_trigger(struct mdev_device *mdev, unsigned int index,
			  unsigned int start, unsigned int count, u32 flags,
			  void *data)
{
	struct mdev_irq *mdev_irq = &mdev->mdev_irq;
	int i, rc = 0;

	if (count > mdev_irq->num)
		count = mdev_irq->num;

	if (!count && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		mdev_msix_disable(mdev_irq);
		return 0;
	}

	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		int *fds = data;

		if (mdev_irq->irq_type == index)
			return mdev_msix_set_vector_signals(mdev_irq, start, count, fds);

		rc = mdev_msix_enable(mdev_irq, start + count);
		if (rc < 0)
			return rc;

		rc = mdev_msix_set_vector_signals(mdev_irq, start, count, fds);
		if (rc < 0)
			mdev_msix_disable(mdev_irq);

		return rc;
	}

	if (start + count > mdev_irq->num)
		return -EINVAL;

	for (i = start; i < start + count; i++) {
		if (!mdev_irq->irq_entries[i].trigger)
			continue;
		if (flags & VFIO_IRQ_SET_DATA_NONE) {
			eventfd_signal(mdev_irq->irq_entries[i].trigger, 1);
		} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
			u8 *bools = data;

			if (bools[i - start])
				eventfd_signal(mdev_irq->irq_entries[i].trigger, 1);
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mdev_set_msix_trigger);

void mdev_irqs_set_pasid(struct mdev_device *mdev, u32 pasid)
{
	mdev->mdev_irq.pasid = pasid;
}
EXPORT_SYMBOL_GPL(mdev_irqs_set_pasid);

/*
 * Initialize and setup the mdev_irq context under mdev.
 *
 * @mdev [in]		: mdev device
 * @num [in]		: number of vectors
 * @ims_map [in]	: bool array that indicates whether a guest MSIX vector is
 *			  backed by an IMS vector or emulated
 * Return error code on failure or 0 on success.
 */
int mdev_irqs_init(struct mdev_device *mdev, int num, bool *ims_map)
{
	struct mdev_irq *mdev_irq = &mdev->mdev_irq;
	int i;

	if (num < 1)
		return -EINVAL;

	mdev_irq->irq_type = VFIO_PCI_NUM_IRQS;
	mdev_irq->num = num;
	mdev_irq->pasid = INVALID_IOASID;

	mdev_irq->irq_entries = kcalloc(num, sizeof(*mdev_irq->irq_entries), GFP_KERNEL);
	if (!mdev_irq->irq_entries)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		mdev_irq->irq_entries[i].ims = ims_map[i];
		if (ims_map[i]) {
			mdev_irq->irq_entries[i].ims_id = mdev_irq->ims_num;
			mdev_irq->ims_num++;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mdev_irqs_init);

/*
 * Free allocated memory in mdev_irq
 *
 * @mdev [in]		: mdev device
 */
void mdev_irqs_free(struct mdev_device *mdev)
{
	kfree(mdev->mdev_irq.irq_entries);
	memset(&mdev->mdev_irq, 0, sizeof(mdev->mdev_irq));
}
EXPORT_SYMBOL_GPL(mdev_irqs_free);
