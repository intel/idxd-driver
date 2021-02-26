// SPDX-License-Identifier: GPL-2.0
// (C) Copyright 2021 Thomas Gleixner <tglx@linutronix.de>
/*
 * Shared interrupt chips and irq domains for IMS devices
 */
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>

#include <linux/irqchip/irq-ims-msi.h>

struct ims_array_data {
	struct ims_array_info	info;
	unsigned long		map[0];
};

static inline void iowrite32_and_flush(u32 value, void __iomem *addr)
{
	iowrite32(value, addr);
	ioread32(addr);
}

static void ims_array_mask_irq(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->device_msi.priv_iomem;
	u32 __iomem *ctrl = &slot->ctrl;

	iowrite32_and_flush(ioread32(ctrl) | IMS_CTRL_VECTOR_MASKBIT, ctrl);
}

static void ims_array_unmask_irq(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->device_msi.priv_iomem;
	u32 __iomem *ctrl = &slot->ctrl;

	iowrite32_and_flush(ioread32(ctrl) & ~IMS_CTRL_VECTOR_MASKBIT, ctrl);
}

static void ims_array_write_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->device_msi.priv_iomem;

	iowrite32(msg->address_lo, &slot->address_lo);
	iowrite32(msg->address_hi, &slot->address_hi);
	iowrite32_and_flush(msg->data, &slot->data);
}

static int ims_array_set_auxdata(struct irq_data *data, unsigned int which,
				 u64 auxval)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->device_msi.priv_iomem;
	u32 val, __iomem *ctrl = &slot->ctrl;

	if (which != IMS_AUXDATA_CONTROL_WORD)
		return -EINVAL;
	if (auxval & ~(u64)IMS_CONTROL_WORD_AUXMASK)
		return -EINVAL;

	val = ioread32(ctrl) & IMS_CONTROL_WORD_IRQMASK;
	iowrite32_and_flush(val | (u32)auxval, ctrl);
	return 0;
}

static const struct irq_chip ims_array_msi_controller = {
	.name			= "IMS",
	.irq_mask		= ims_array_mask_irq,
	.irq_unmask		= ims_array_unmask_irq,
	.irq_write_msi_msg	= ims_array_write_msi_msg,
	.irq_set_auxdata	= ims_array_set_auxdata,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static void ims_array_reset_slot(struct ims_slot __iomem *slot)
{
	iowrite32(0, &slot->address_lo);
	iowrite32(0, &slot->address_hi);
	iowrite32(0, &slot->data);
	iowrite32_and_flush(IMS_CTRL_VECTOR_MASKBIT, &slot->ctrl);
}

static void ims_array_free_msi_store(struct irq_domain *domain,
				     struct device *dev)
{
	struct msi_domain_info *info = domain->host_data;
	struct ims_array_data *ims = info->data;
	struct msi_desc *entry;

	for_each_msi_entry(entry, dev) {
		if (entry->device_msi.priv_iomem) {
			clear_bit(entry->device_msi.hwirq, ims->map);
			ims_array_reset_slot(entry->device_msi.priv_iomem);
			entry->device_msi.priv_iomem = NULL;
			entry->device_msi.hwirq = 0;
		}
	}
}

static int ims_array_alloc_msi_store(struct irq_domain *domain,
				     struct device *dev, int nvec)
{
	struct msi_domain_info *info = domain->host_data;
	struct ims_array_data *ims = info->data;
	struct msi_desc *entry;

	for_each_msi_entry(entry, dev) {
		unsigned int idx;

		idx = find_first_zero_bit(ims->map, ims->info.max_slots);
		if (idx >= ims->info.max_slots)
			goto fail;
		set_bit(idx, ims->map);
		entry->device_msi.priv_iomem = &ims->info.slots[idx];
		ims_array_reset_slot(entry->device_msi.priv_iomem);
		entry->device_msi.hwirq = idx;
	}
	return 0;

fail:
	ims_array_free_msi_store(domain, dev);
	return -ENOSPC;
}

struct ims_array_domain_template {
	struct msi_domain_ops	ops;
	struct msi_domain_info	info;
};

static void ims_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	arg->desc = desc;
	arg->hwirq = desc->device_msi.hwirq;
}

static const struct ims_array_domain_template ims_array_domain_template = {
	.ops = {
		.msi_alloc_store	= ims_array_alloc_msi_store,
		.msi_free_store		= ims_array_free_msi_store,
		.set_desc               = ims_set_desc,
	},
	.info = {
		.flags		= MSI_FLAG_USE_DEF_DOM_OPS |
				  MSI_FLAG_USE_DEF_CHIP_OPS,
		.handler	= handle_edge_irq,
		.handler_name	= "edge",
	},
};

struct irq_domain *
pci_ims_array_create_msi_irq_domain(struct pci_dev *pdev,
				    struct ims_array_info *ims_info)
{
	struct ims_array_domain_template *info;
	struct ims_array_data *data;
	struct irq_domain *domain;
	struct irq_chip *chip;
	unsigned int size;

	/* Allocate new domain storage */
	info = kmemdup(&ims_array_domain_template,
		       sizeof(ims_array_domain_template), GFP_KERNEL);
	if (!info)
		return NULL;
	/* Link the ops */
	info->info.ops = &info->ops;

	/* Allocate ims_info along with the bitmap */
	size = sizeof(*data);
	size += BITS_TO_LONGS(ims_info->max_slots) * sizeof(unsigned long);
	data = kzalloc(size, GFP_KERNEL);
	if (!data)
		goto err_info;

	data->info = *ims_info;
	info->info.data = data;

	/*
	 * Allocate an interrupt chip because the core needs to be able to
	 * update it with default callbacks.
	 */
	chip = kmemdup(&ims_array_msi_controller,
		       sizeof(ims_array_msi_controller), GFP_KERNEL);
	if (!chip)
		goto err_data;
	info->info.chip = chip;

	domain = pci_subdevice_msi_create_irq_domain(pdev, &info->info);
	if (!domain)
		goto err_chip;

	return domain;

err_chip:
	kfree(chip);
err_data:
	kfree(data);
err_info:
	kfree(info);
	return NULL;
}
EXPORT_SYMBOL_GPL(pci_ims_array_create_msi_irq_domain);
