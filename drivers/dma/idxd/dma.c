// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/dmaengine.h>
#include <uapi/linux/idxd.h>
#include "../dmaengine.h"
#include "registers.h"
#include "idxd.h"


#define DMA_COOKIE_BITS (sizeof(dma_cookie_t) * 8)
/*
 * The descriptor id takes the lower 16 bits of the cookie.
 */
#define DESC_ID_BITS 16
#define DESC_ID_MASK ((1 << DESC_ID_BITS) - 1)
/*
 * The 'generation' is in the upper half of the cookie. But dma_cookie_t
 * is signed, so we leave the upper-most bit for the sign. Further, we
 * need to flag whether a cookie corresponds to an operation that is
 * being completed via interrupt to avoid polling it, which takes
 * the second most upper bit. So we subtract two bits from the upper half.
 */
#define DESC_GEN_MAX ((1 << (DMA_COOKIE_BITS - DESC_ID_BITS - 2)) - 1)
#define DESC_INTERRUPT_FLAG (1 << (DMA_COOKIE_BITS - 2))

static inline struct idxd_wq *to_idxd_wq(struct dma_chan *c)
{
	struct idxd_dma_chan *idxd_chan;

	idxd_chan = container_of(c, struct idxd_dma_chan, chan);
	return idxd_chan->wq;
}

void idxd_dma_complete_txd(struct idxd_desc *desc,
			   enum idxd_complete_type comp_type,
			   bool free_desc)
{
	struct idxd_device *idxd = desc->wq->idxd;
	struct dma_async_tx_descriptor *tx;
	struct dmaengine_result res;
	int complete = 1;

	if (desc->completion->status == DSA_COMP_SUCCESS) {
		res.result = DMA_TRANS_NOERROR;
	} else if (desc->completion->status) {
		if (idxd->request_int_handles && comp_type != IDXD_COMPLETE_ABORT &&
		    desc->completion->status == DSA_COMP_INT_HANDLE_INVAL &&
		    idxd_queue_int_handle_resubmit(desc))
			return;
		res.result = DMA_TRANS_WRITE_FAILED;
	} else if (comp_type == IDXD_COMPLETE_ABORT) {
		res.result = DMA_TRANS_ABORTED;
	} else {
		complete = 0;
	}

	tx = &desc->txd;
	if (complete && tx->cookie) {
		dma_cookie_complete(tx);
		dma_descriptor_unmap(tx);
		dmaengine_desc_get_callback_invoke(tx, &res);
		tx->callback = NULL;
		tx->callback_result = NULL;
	}

	if (free_desc)
		idxd_free_desc(desc->wq, desc);
}

static void op_flag_setup(unsigned long flags, u32 *desc_flags)
{
	*desc_flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		*desc_flags |= IDXD_OP_FLAG_RCI;
}

static inline void set_completion_address(struct idxd_desc *desc,
					  u64 *compl_addr)
{
		*compl_addr = desc->compl_dma;
}

static inline void idxd_prep_desc_common(struct idxd_wq *wq,
					 struct dsa_hw_desc *hw, char opcode,
					 u64 addr_f1, u64 addr_f2, u64 len,
					 u64 compl, u32 flags)
{
	hw->flags = flags;
	hw->opcode = opcode;
	hw->src_addr = addr_f1;
	hw->dst_addr = addr_f2;
	hw->xfer_size = len;
	/*
	 * For dedicated WQ, this field is ignored and HW will use the WQCFG.priv
	 * field instead. This field should be set to 1 for kernel descriptors.
	 */
	hw->priv = 1;
	hw->completion_addr = compl;
}

static inline struct idxd_desc *
dmachan_alloc_desc(struct dma_chan *chan, enum idxd_op_type optype)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct idxd_desc *desc;

	desc = idxd_alloc_desc(wq, optype);
	if (!desc)
		return NULL;
	dma_async_tx_descriptor_init(&desc->txd, chan);
	return desc;
}


static struct dma_async_tx_descriptor *
idxd_dma_submit_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
		       dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_device *idxd = wq->idxd;
	struct idxd_desc *desc;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	if (len > idxd->max_xfer_bytes)
		return NULL;

	op_flag_setup(flags, &desc_flags);
	desc = dmachan_alloc_desc(c, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_MEMMOVE,
			      dma_src, dma_dest, len, desc->compl_dma,
			      desc_flags);

	desc->txd.flags = flags;

	return &desc->txd;
}

static int idxd_dma_alloc_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_get(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
	return 0;
}

static void idxd_dma_free_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_put(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
}


static enum dma_status idxd_dma_tx_status(struct dma_chan *dma_chan,
					  dma_cookie_t cookie,
					  struct dma_tx_state *txstate)
{
	u8 status;
	struct idxd_wq *wq;
	struct idxd_desc *desc;
	u32 idx;

	memset(txstate, 0, sizeof(*txstate));

	if (dma_submit_error(cookie))
		return DMA_ERROR;

	wq = to_idxd_wq(dma_chan);

	idx = cookie & DESC_ID_MASK;
	if (idx >= wq->num_descs)
		return DMA_ERROR;

	desc = wq->descs[idx];

	if (desc->txd.cookie != cookie) {
		/*
		 * The user asked about an old transaction
		 */
		return DMA_COMPLETE;
	}

	/*
	 * For descriptors completed via interrupt, we can't go
	 * look at the completion status directly because it races
	 * with the IRQ handler recyling the descriptor. However,
	 * since in this case we can rely on the interrupt handler
	 * to invalidate the cookie when the command completes we
	 * know that if we get here, the command is still in
	 * progress.
	 */
	if ((cookie & DESC_INTERRUPT_FLAG) != 0)
		return DMA_IN_PROGRESS;

	status = desc->completion->status & DSA_COMP_STATUS_MASK;

	if (status) {
		/*
		 * Check against the original status as ABORT is software defined
		 * and 0xff, which DSA_COMP_STATUS_MASK can mask out.
		 */
		if (unlikely(desc->completion->status == IDXD_COMP_DESC_ABORT))
			idxd_dma_complete_txd(desc, IDXD_COMPLETE_ABORT, true);
		else
			idxd_dma_complete_txd(desc, IDXD_COMPLETE_NORMAL, true);

		return DMA_COMPLETE;
	}

	return DMA_IN_PROGRESS;
}


/*
 * issue_pending() does not need to do anything since tx_submit() does the job
 * already.
 */
static void idxd_dma_issue_pending(struct dma_chan *dma_chan)
{
}

static dma_cookie_t idxd_dma_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *c = tx->chan;
	struct idxd_wq *wq = to_idxd_wq(c);
	dma_cookie_t cookie;
	int rc;
	struct idxd_desc *desc = container_of(tx, struct idxd_desc, txd);

	cookie = (desc->gen << DESC_ID_BITS) | (desc->id & DESC_ID_MASK);

	if ((desc->hw->flags & IDXD_OP_FLAG_RCI) != 0)
		cookie |= DESC_INTERRUPT_FLAG;

	if (desc->gen == DESC_GEN_MAX)
		desc->gen = 1;
	else
		desc->gen++;

	tx->cookie = cookie;

	rc = idxd_submit_desc(wq, desc);
	if (rc < 0) {
		idxd_free_desc(wq, desc);
		return rc;
	}

	return cookie;
}

static void idxd_dma_release(struct dma_device *device)
{
	struct idxd_dma_dev *idxd_dma = container_of(device, struct idxd_dma_dev, dma);

	kfree(idxd_dma);
}

int idxd_register_dma_device(struct idxd_device *idxd)
{
	struct idxd_dma_dev *idxd_dma;
	struct dma_device *dma;
	struct device *dev = &idxd->pdev->dev;
	int rc;

	idxd_dma = kzalloc_node(sizeof(*idxd_dma), GFP_KERNEL, dev_to_node(dev));
	if (!idxd_dma)
		return -ENOMEM;

	dma = &idxd_dma->dma;
	INIT_LIST_HEAD(&dma->channels);
	dma->dev = dev;

	dma_cap_set(DMA_PRIVATE, dma->cap_mask);
	dma_cap_set(DMA_COMPLETION_NO_ORDER, dma->cap_mask);
	dma->device_release = idxd_dma_release;

	if (idxd->hw.opcap.bits[0] & IDXD_OPCAP_MEMMOVE) {
		dma_cap_set(DMA_MEMCPY, dma->cap_mask);
		dma->device_prep_dma_memcpy = idxd_dma_submit_memcpy;
	}

	dma->device_tx_status = idxd_dma_tx_status;
	dma->device_issue_pending = idxd_dma_issue_pending;
	dma->device_alloc_chan_resources = idxd_dma_alloc_chan_resources;
	dma->device_free_chan_resources = idxd_dma_free_chan_resources;

	rc = dma_async_device_register(dma);
	if (rc < 0) {
		kfree(idxd_dma);
		return rc;
	}

	idxd_dma->idxd = idxd;
	/*
	 * This pointer is protected by the refs taken by the dma_chan. It will remain valid
	 * as long as there are outstanding channels.
	 */
	idxd->idxd_dma = idxd_dma;
	return 0;
}

void idxd_unregister_dma_device(struct idxd_device *idxd)
{
	dma_async_device_unregister(&idxd->idxd_dma->dma);
}

int idxd_register_dma_channel(struct idxd_dma_chan *ichan)
{
	struct idxd_wq *wq = ichan->wq;
	struct idxd_device *idxd = wq->idxd;
	struct dma_device *dma = &idxd->idxd_dma->dma;
	struct dma_chan *chan;
	int rc, i;

	chan = &ichan->chan;
	chan->device = dma;
	list_add_tail(&chan->device_node, &dma->channels);

	for (i = 0; i < wq->num_descs; i++) {
		struct idxd_desc *desc = wq->descs[i];

		desc->txd.tx_submit = idxd_dma_tx_submit;
	}

	rc = dma_async_device_channel_register(dma, chan);
	if (rc < 0) {
		list_del(&chan->device_node);
		return rc;
	}

	get_device(wq_confdev(wq));

	return 0;
}

void idxd_unregister_dma_channel(struct idxd_dma_chan *ichan)
{
	struct idxd_wq *wq = ichan->wq;
	struct dma_chan *chan = &ichan->chan;
	struct idxd_dma_dev *idxd_dma = wq->idxd->idxd_dma;

	dma_async_device_channel_unregister(&idxd_dma->dma, chan);
	list_del(&chan->device_node);
	put_device(wq_confdev(wq));
}

static int idxd_setup_dma_channels(struct idxd_wq *wq)
{
	struct device *dev = &wq->idxd->pdev->dev;
	struct idxd_dma_chan *ichans;
	int i, rc;

	ichans = kcalloc_node(wq->chan_count, sizeof(struct idxd_dma_chan), GFP_KERNEL,
			      dev_to_node(dev));
	if (!ichans)
		return -ENOMEM;

	for (i = 0; i < wq->chan_count; i++) {
		ichans[i].wq = wq;
		rc = idxd_register_dma_channel(&ichans[i]);
		if (rc < 0)
			goto err;
	}

	wq->ichans = ichans;

	return 0;

err:
	while (--i >= 0)
		idxd_unregister_dma_channel(&ichans[i]);
	kfree(ichans);
	return rc;
}

static void idxd_release_dma_channels(struct idxd_wq *wq)
{
	struct idxd_dma_chan *ichan;
	int i;

	for (i = 0; i < wq->chan_count; i++) {
		ichan = &wq->ichans[i];

		idxd_unregister_dma_channel(ichan);
	}

	kfree(wq->ichans);
	wq->ichans = NULL;
}

static int idxd_dmaengine_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	mutex_lock(&wq->wq_lock);
	if (!idxd_wq_driver_name_match(wq, dev)) {
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		rc = -ENODEV;
		goto err_drv_name;
	}

	wq->type = IDXD_WQT_KERNEL;

	rc = drv_enable_wq(wq);
	if (rc < 0) {
		dev_dbg(dev, "Enable wq %d failed: %d\n", wq->id, rc);
		rc = -ENXIO;
		goto err;
	}

	rc = idxd_setup_dma_channels(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_DMA_CHAN_ERR;
		dev_dbg(dev, "Failed to register dma channel\n");
		goto err_dma;
	}

	idxd->cmd_status = 0;
	mutex_unlock(&wq->wq_lock);
	return 0;

err_dma:
	drv_disable_wq(wq);
err:
err_drv_name:
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_dmaengine_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	__idxd_wq_quiesce(wq);
	idxd_release_dma_channels(wq);
	drv_disable_wq(wq);
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE,
};

struct idxd_device_driver idxd_dmaengine_drv = {
	.probe = idxd_dmaengine_drv_probe,
	.remove = idxd_dmaengine_drv_remove,
	.name = "dmaengine",
	.type = dev_types,
};
EXPORT_SYMBOL_GPL(idxd_dmaengine_drv);
