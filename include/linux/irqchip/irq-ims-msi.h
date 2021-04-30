/* SPDX-License-Identifier: GPL-2.0 */
/* (C) Copyright 2021 Thomas Gleixner <tglx@linutronix.de> */

#ifndef _LINUX_IRQCHIP_IRQ_IMS_MSI_H
#define _LINUX_IRQCHIP_IRQ_IMS_MSI_H

#include <linux/types.h>
#include <linux/bits.h>

/**
 * ims_hw_slot - The hardware layout of an IMS based MSI message
 * @address_lo:	Lower 32bit address
 * @address_hi:	Upper 32bit address
 * @data:	Message data
 * @ctrl:	Control word
 *
 * This structure is used by both the device memory array and the queue
 * memory variants of IMS.
 */
struct ims_slot {
	u32	address_lo;
	u32	address_hi;
	u32	data;
	u32	ctrl;
} __packed;

/*
 * The IMS control word utilizes bit 0-2 for interrupt control. The remaining
 * bits can contain auxiliary data.
 */
#define IMS_CONTROL_WORD_IRQMASK	GENMASK(2, 0)
#define IMS_CONTROL_WORD_AUXMASK	GENMASK(31, 3)

/* Auxiliary control word data related defines */
enum {
	IMS_AUXDATA_CONTROL_WORD,
};

/* Bit to mask the interrupt in ims_hw_slot::ctrl */
#define IMS_CTRL_VECTOR_MASKBIT		BIT(0)
#define IMS_CTRL_PASID_ENABLE           BIT(3)
#define IMS_CTRL_PASID_SHIFT            12

/* Set pasid and enable bit for the IMS entry */
static inline u32 ims_ctrl_pasid_aux(unsigned int pasid, bool enable)
{
	u32 auxval = pasid << IMS_CTRL_PASID_SHIFT;

	return enable ? auxval | IMS_CTRL_PASID_ENABLE : auxval;
}

/**
 * struct ims_array_info - Information to create an IMS array domain
 * @slots:	Pointer to the start of the array
 * @max_slots:	Maximum number of slots in the array
 */
struct ims_array_info {
	struct ims_slot		__iomem *slots;
	unsigned int		max_slots;
};

struct pci_dev;
struct irq_domain;

struct irq_domain *pci_ims_array_create_msi_irq_domain(struct pci_dev *pdev,
						       struct ims_array_info *ims_info);

#endif
