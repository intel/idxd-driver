ccflags-y += -I$(srctree)/drivers/dma/idxd -DDEFAULT_SYMBOL_NAMESPACE=IDXD

obj-$(CONFIG_VFIO_MDEV_IDXD) += idxd_mdev.o
idxd_mdev-y := mdev.o vdev.o
