// SPDX-License-Identifier: GPL-2.0-only
/*
 * DMA Engine test module
 *
 * Copyright (C) 2021 Intel Corporation
 */
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/intel-svm.h>

struct dmautest_ctx {
	struct dma_chan		*chan;
	void			*buf;
	struct iommu_sva	*sva;
	unsigned int		pasid;
};

#define BUFFER_SIZE 0x20000

static int dmautest_open(struct inode *inode, struct file *file)
{
	dma_cap_mask_t mask;
	struct dmautest_ctx *ctx;
	struct device *dev;
	int rc = 0;
	struct dma_chan_attr_params param;
	int flags = IOMMU_SVA_BIND_KERNEL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!ctx->buf) {
		pr_warn("Failed to allocate context\n");
		rc = -ENOMEM;
		goto failed;
	}

	/* Initialize the buffer content */
	memset(ctx->buf, 0xb, BUFFER_SIZE);

	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);
	dma_cap_set(DMA_KERNEL_USER, mask);

	ctx->chan = dma_request_chan_by_mask(&mask);
	if (IS_ERR(ctx->chan)) {
		pr_warn("Failed to allocate dma channel!");
		rc = PTR_ERR(ctx->chan);
		goto failed;
	}

	dev = ctx->chan->device->dev;

	ctx->sva = iommu_sva_bind_device(dev, current->mm, flags);
	if (IS_ERR(ctx->sva)) {
		pr_warn("Failed to perform SVA bind\n");
		rc = PTR_ERR(ctx->sva);
		goto failed;
	}

	ctx->pasid = iommu_sva_get_pasid(ctx->sva);
	if (ctx->pasid == IOMMU_PASID_INVALID) {
		rc = -EINVAL;
		goto failed;
	}

	param.p.pasid = ctx->pasid;
	param.p.priv = true;

	if (dmaengine_chan_set_attr(ctx->chan, DMA_CHAN_SET_PASID, &param)) {
		rc = -EINVAL;
		goto failed;
	}

	file->private_data = ctx;

	return 0;

failed:
	if (ctx) {
		if (ctx->buf)
			kfree(ctx->buf);
		if (ctx->sva && !IS_ERR(ctx->sva))
			iommu_sva_unbind_device(ctx->sva);
		if (ctx->chan && !IS_ERR(ctx->chan))
			dma_release_channel(ctx->chan);
		kfree(ctx);
	}

	return rc;
}

static int dmautest_release(struct inode *inodep, struct file *file)
{
	struct dmautest_ctx *ctx = file->private_data;

	if (!ctx)
		return 0;

	dma_release_channel(ctx->chan);
	if (ctx->sva)
		iommu_sva_unbind_device(ctx->sva);

	kfree(ctx->buf);
	kfree(ctx);

	return 0;
}

#define MAX_IOVECS 8

static ssize_t dmautest_read_iter_uring(struct kiocb *kiocb,
					struct iov_iter *dst)
{
	ssize_t offset, total_len, len;
	struct file *file = kiocb->ki_filp;
	struct dmautest_ctx *ctx = file->private_data;
	struct iov_iter k;
	struct kvec k_vecs[MAX_IOVECS] = {0};
	int i, rc;

	len = iov_iter_count(dst);

	total_len = 0;
	for (i = 0; i < MAX_IOVECS; i++) {
		k_vecs[i].iov_base = ctx->buf;
		k_vecs[i].iov_len = BUFFER_SIZE;
		total_len += BUFFER_SIZE;
	}

	offset = 0;
	while (offset < len) {
		iov_iter_kvec(&k, READ, k_vecs, MAX_IOVECS, total_len);

		rc = kiocb->ki_copy_to_iter(kiocb, dst, &k, NULL, NULL, 0);
		/* TODO: Need to somehow handle an error and cancel the other stuff?? */
		if (rc <= 0) {
			return rc;
		}

		offset += rc;
	}

	return offset;
}

static ssize_t dmautest_read_iter(struct kiocb *kiocb, struct iov_iter *u)
{
	struct file *file = kiocb->ki_filp;
	struct dmautest_ctx *ctx = file->private_data;
	struct device *dev = ctx->chan->device->dev;
	struct iov_iter k;
	ssize_t offset, total_len, len;
	struct kvec k_vecs[MAX_IOVECS] = {0};
	int i;

	if (kiocb->ki_flags & IOCB_DMA_COPY) {
		/* io_uring has already set up an offload context for this
		 * operation, so use that. */
		return dmautest_read_iter_uring(kiocb, u);
	}

	len = iov_iter_count(u);

	if (!dma_map_sva_sg(dev, u, u->nr_segs, DMA_FROM_DEVICE)) {
	       return -EINVAL;
	}

	total_len = 0;

	for (i = 0; i < MAX_IOVECS; i++) {
		k_vecs[i].iov_base = ctx->buf;
		k_vecs[i].iov_len = 0x1000;
		total_len += 0x1000;
	}

	iov_iter_kvec(&k, READ, k_vecs, MAX_IOVECS, total_len);

	if (!dma_map_sva_sg(dev, &k, k.nr_segs, DMA_TO_DEVICE)) {
		dma_unmap_sva_sg(dev, u, u->nr_segs, DMA_FROM_DEVICE);
		return -EINVAL;
	}

	offset = 0;
	while (offset < len) {
		dma_cookie_t cookie;
		size_t tx_len;
		int status;
		struct dma_async_tx_descriptor *tx;
		unsigned long dma_sync_wait_timeout = jiffies + msecs_to_jiffies(5000);

		iov_iter_kvec(&k, READ, k_vecs, MAX_IOVECS, total_len);

		tx_len = len - offset;
		if (tx_len > MAX_IOVECS * 0x1000)
			tx_len = MAX_IOVECS * 0x1000;

		tx = dmaengine_prep_memcpy_sva_kernel_user(ctx->chan,
				u, &k, 0);

		if (!tx)
			return -EFAULT;

		cookie = dmaengine_submit(tx);
		if (dma_submit_error(cookie)) {
			return offset;
		}

		dma_async_issue_pending(ctx->chan);
		do {
			status = dmaengine_async_is_tx_complete(ctx->chan, cookie);
			if (time_after_eq(jiffies, dma_sync_wait_timeout)) {
				return -ETIMEDOUT;
			}
			if (status == DMA_COMPLETE || status == DMA_ERROR)
				break;
			cpu_relax();
		} while (1);

		if (status == DMA_ERROR)
			break;

		offset += tx_len;
	}

	dma_unmap_sva_sg(dev, u, u->nr_segs, DMA_FROM_DEVICE);
	dma_unmap_sva_sg(dev, &k, k.nr_segs, DMA_TO_DEVICE);

	return offset;
}

static ssize_t dmautest_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	void *src;
	void __user *dst;
	size_t offset;
	struct dmautest_ctx *ctx = file->private_data;
	struct device *dev = ctx->chan->device->dev;

	src = dma_map_sva_single(dev, ctx->buf, 0x1000, DMA_TO_DEVICE, false);
	if (src == NULL)
		return -ENOMEM;

	dst = dma_map_sva_single(dev, buf, len, DMA_FROM_DEVICE, true);
	if (dst == NULL) {
		dma_unmap_sva_single(dev, ctx->buf, 0x1000, DMA_TO_DEVICE, false);
		return -ENOMEM;
	}

	/* TODO: ppos needs to be taken into account */
	offset = 0;
	while (offset < len) {
		dma_cookie_t cookie;
		size_t tx_len;
		int status;
		struct dma_async_tx_descriptor *tx;
		unsigned long dma_sync_wait_timeout = jiffies + msecs_to_jiffies(5000);

		tx_len = len - offset;
		if (tx_len > 0x1000)
			tx_len = 0x1000;

		tx = dmaengine_prep_memcpy_sva_single_kernel_user(ctx->chan,
				dst + offset, src, tx_len, 0);

		if (!tx)
			return -EFAULT;

		cookie = dmaengine_submit(tx);
		if (dma_submit_error(cookie)) {
			return offset;
		}

		dma_async_issue_pending(ctx->chan);
		do {
			status = dmaengine_async_is_tx_complete(ctx->chan, cookie);
			if (time_after_eq(jiffies, dma_sync_wait_timeout)) {
				return -ETIMEDOUT;
			}
			if (status == DMA_COMPLETE || status == DMA_ERROR)
				break;
			cpu_relax();
		} while (1);

		if (status == DMA_ERROR)
			break;

		offset += tx_len;
	}

	dma_unmap_sva_single(dev, ctx->buf, 0x1000, DMA_TO_DEVICE, false);
	dma_unmap_sva_single(dev, buf, len, DMA_FROM_DEVICE, true);

	return offset;
}

static ssize_t dmautest_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	return len;
}

static ssize_t dmautest_write_iter(struct kiocb *kiocb, struct iov_iter *u)
{
	return iov_iter_count(u);
}

static const struct file_operations dmautest_fops = {
	.owner			= THIS_MODULE,
	.write			= dmautest_write,
	.read			= dmautest_read,
	.write_iter		= dmautest_write_iter,
	.read_iter		= dmautest_read_iter,
	.open			= dmautest_open,
	.release		= dmautest_release,
	.llseek 		= no_llseek,
};

struct miscdevice dmautest_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "dmautest",
	.fops = &dmautest_fops,
};

static int __init dmautest_init(void)
{
	int error;

	error = misc_register(&dmautest_device);
	if (error) {
		return error;
	}

	return 0;
}

static void __exit dmautest_exit(void)
{
	misc_deregister(&dmautest_device);
}

module_init(dmautest_init)
module_exit(dmautest_exit)

MODULE_DESCRIPTION("DMA engine copy-to-user tester");
MODULE_AUTHOR("Ben Walker <benjamin.walker@intel.com>");
MODULE_LICENSE("GPL");
