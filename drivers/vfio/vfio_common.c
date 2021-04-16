// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Intel, Corp. All rights reserved.
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 * VFIO common helper functions
 */

#include <linux/eventfd.h>
#include <linux/vfio.h>

/*
 * Common helper to set single eventfd trigger
 *
 * @ctx [out]		: address of eventfd ctx to be written to
 * @count [in]		: number of vectors (should be 1)
 * @flags [in]		: VFIO IRQ flags
 * @data [in]		: data from ioctl
 */
int vfio_set_ctx_trigger_single(struct eventfd_ctx **ctx,
				unsigned int count, u32 flags,
				void *data)
{
	/* DATA_NONE/DATA_BOOL enables loopback testing */
	if (flags & VFIO_IRQ_SET_DATA_NONE) {
		if (*ctx) {
			if (count) {
				eventfd_signal(*ctx, 1);
			} else {
				eventfd_ctx_put(*ctx);
				*ctx = NULL;
			}
			return 0;
		}
	} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
		u8 trigger;

		if (!count)
			return -EINVAL;

		trigger = *(uint8_t *)data;
		if (trigger && *ctx)
			eventfd_signal(*ctx, 1);

		return 0;
	} else if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		s32 fd;

		if (!count)
			return -EINVAL;

		fd = *(s32 *)data;
		if (fd == -1) {
			if (*ctx)
				eventfd_ctx_put(*ctx);
			*ctx = NULL;
		} else if (fd >= 0) {
			struct eventfd_ctx *efdctx;

			efdctx = eventfd_ctx_fdget(fd);
			if (IS_ERR(efdctx))
				return PTR_ERR(efdctx);

			if (*ctx)
				eventfd_ctx_put(*ctx);

			*ctx = efdctx;
		}
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(vfio_set_ctx_trigger_single);
