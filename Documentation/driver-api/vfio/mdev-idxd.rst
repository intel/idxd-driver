.. SPDX-License-Identifier: GPL-2.0

=============
IDXD Overview
=============
IDXD (Intel Data Accelerator Driver) is the driver for the Intel Data
Streaming Accelerator (DSA).  Intel DSA is a high performance data copy
and transformation accelerator. In addition to data move operations,
the device also supports data fill, CRC generation, Data Integrity Field
(DIF), and memory compare and delta generation. Intel DSA supports
a variety of PCI-SIG defined capabilities such as Address Translation
Services (ATS), Process address Space ID (PASID), Page Request Interface
(PRI), Message Signalled Interrupts Extended (MSI-X), and Advanced Error
Reporting (AER). Some of those capabilities enable the device to support
Shared Virtual Memory (SVM), or also known as Shared Virtual Addressing
(SVA). Intel DSA also supports Intel Scalable I/O Virtualization (SIOV)
to improve scalability of device assignment.


The Intel DSA device contains the following basic components:
* Work queue (WQ)

  A WQ is an on device storage to queue descriptors to the
  device. Requests are added to a WQ by using new CPU instructions
  (MOVDIR64B and ENQCMD(S)) to write the memory mapped “portal”
  associated with each WQ.

* Engine

  Operation unit that pulls descriptors from WQs and processes them.

* Group

  Abstract container to associate one or more engines with one or more WQs.


Two types of WQs are supported:
* Dedicated WQ (DWQ)

  Usually a single client owns this exclusively and can submit work
  to it. The MOVDIR64B instruction is used to submit descriptors to
  this type of WQ. The instruction is a posted write, therefore the
  submitter must ensure not exceed the WQ length for submission. The
  use of PASID is optional with DWQ. Multiple clients can submit to
  a DWQ, but sychronization is required due to when the WQ is full,
  the submission is silently dropped.

* Shared WQ (SWQ)

  Multiple clients can submit work to this WQ. The submitter must use
  ENQMCDS (from supervisor mode) or ENQCMD (from user mode). These
  instructions are non-posted writes. That means a response is
  expected from the issued instruction. The EFLAGS.ZF bit will be set
  when a failure (busy or fail) has occurred from the command.
  The use of PASID is mandatory to identify the address space
  of each client.


For more information about the new instructions [1][2].

The IDXD driver is broken down into following usages:
* In kernel interface through dmaengine subsystem API.
* Userspace DMA support through character device. mmap(2) is utilized
  to map directly to mmio address (or portals) for descriptor submission.
* VFIO Mediated device (mdev) supporting device passthrough usages.

This document is only for the mdev usage.


=================================
Assignable Device Interface (ADI)
=================================
The term ADI is used to represent the minimal unit of assignment for
Intel Scalable IOV device. Each ADI instance refers to the set of device
backend resources that are allocated, configured and organized as an
isolated unit.

Intel DSA defines each WQ as an ADI. The MMIO registers of each work queue
are partitioned into two categories:
* MMIO registers accessed for data-path operations.
* MMIO registers accessed for control-path operations.

Data-path MMIO registers of each WQ are contained within
one or more system page size aligned regions and can be mapped in the
CPU page table for direct access from the guest. Control-path MMIO
registers of all WQs are located together but segregated from data-path
MMIO regions. Therefore, guest updates to control-path registers must
be intercepted and then go through the host driver to be reflected in
the device.

Data-path MMIO registers of DSA WQ are portals for submitting descriptors
to the device. There are four portals per WQ, each being 64 bytes
in size and located on a separate 4KB page in BAR2. Each portal has
different implications regarding interrupt message type (MSI vs. IMS)
and occupancy control (limited vs. unlimited). It is not necessary to
map all portals to the guest.

Control-path MMIO registers of DSA WQ include global configurations
(shared by all WQs) and WQ-specific configurations. The owner
(e.g. the guest) of the WQ is expected to only change WQ-specific
configurations. Intel DSA spec introduces a “Configuration Support”
capability which, if cleared, indicates that some fields of WQ
configuration registers are read-only thus pre-configured by the host.


Interrupt Message Store (IMS)
-----------------------------
The ADI utilizes Interrupt Message Store (IMS), a device-specific MSI
implementation, instead of MSIX for interrupts for the guest. This
preserves MSIX for host usages and also allows a significantly larger
number of interrupt vectors for large number of guests usage.

Intel DSA device implements IMS as on-device memory mapped unified
storage. Each interrupt message is stored as a DWORD size data payload
and a 64-bit address (same as MSI-X). Access to the IMS is through the
host idxd driver.


ADI Isolation
-------------
Operations or functioning of one ADI must not affect the functioning
of another ADI or the physical device. Upstream memory requests from
different ADIs are distinguished using a Process Address Space Identifier
(PASID). With the support of PASID-granular address translation in Intel
VT-d, the address space targeted by a request from ADI can be a Host
Virtual Address (HVA), Host I/O Virtual Address (HIOVA), Guest Physical
Address (GPA), Guest Virtual Address (GVA), Guest I/O Virtual Address
(GIOVA), etc. The PASID identity for an ADI is expected to be accessed
or modified by privileged software through the host driver.

=========================
Virtual DSA (vDSA) Device
=========================
The DSA WQ itself is not a PCI device thus must be composed into a
virtual DSA device to the guest.

The composition logic needs to handle four main requirements:
* Emulate PCI config space.
* Map data-path portals for direct access from the guest.
* Emulate control-path MMIO registers and selectively forward WQ
  configuration requests through host driver to the device.
* Forward and emulate WQ interrupts to the guest.

The composition logic tells the guest which aspects of WQ are configurable
through a combination of capability fields, e.g.:
* Configuration Support (if cleared, most aspects are not modifiable).
* WQ Mode Support (if cleared, cannot change between dedicated and
  shared mode).
* Dedicated Mode Support.
* Shared Mode Support.
* ...

The virtual capability fields are set according to the vDSA
type. Following is an example of vDSA types and related WQ configurability:
* Type ‘1dwq-v1’
   * One DSA gen1 dedicated WQ
   * Guest cannot share the WQ between its clients (no guest SVA)
   * Guest cannot change any WQ configuration

Besides, the composition logic also needs to serve administrative commands
(thru virtual CMD register) through host driver, including:
* Drain/abort all descriptors submitted by this guest.
* Drain/abort descriptors associated with a PASID.
* Enable/disable/reset the WQ (when it’s not shared by multiple VMs).
* Request interrupt handle.

With this design, vDSA emulation is **greatly simplified**. Only limited
configurability is handled with most registers emulated in simple
READ-ONLY flavor.

=======================================
Mdev Framework Registration and Release
=======================================

Intel DSA reports support for Intel Scalable IOV via a PCI Express
Designated Vendor Specific Extended Capability (DVSEC). In addition,
PASID-granular address translation capability is required in the
IOMMU. During host initialization, the IDXD driver should check the
presence of both capabilities before calling mdev_register_device()
to register with the VFIO mdev framework and provide a set of ops
(struct vfio_device_ops). The IOMMU capability is indicated by the
IOMMU_DEV_FEAT_AUX feature flag with iommu_dev_has_feature() and enabled
with iommu_dev_enable_feature().

On release, iommu_dev_disable_feature() is called after
mdev_unregister_device() to disable the IOMMU_DEV_FEAT_AUX flag that
the driver enabled during host initialization.

The vfio_device_ops data structure is filled out by the driver to provide
a number of ops called by VFIO core::

        struct vfio_device_ops {
                .open
                .release
                .read
                .write
                .mmap
                .ioctl
        };

The mdev driver provides supported type group attributes. It also
registers the mdev driver with probe and remove calls::

        struct mdev_driver {
                .probe
                .remove
                .supported_type_groups
        };


Supported_type_groups
---------------------
At the moment only one vDSA type is supported.

“1dwq-v1”:
  Single dedicated WQ (DSA 1.0) with read-only configuration exposed to
  the guest. On the guest kernel, a vDSA device shows up with a single
  WQ that is pre-configured by the host. The configuration for the WQ
  is entirely read-only and cannot be reconfigured. There is no support
  of guest SVA on this WQ.

  PCI MSI-X vectors are surfaced from the mdev device to the guest kernel.
  In the current implementation 2 vectors are supported. Vector 0 is used for
  device misc operations (admin command completion, error report, etc.) just
  like on the host. Vector 1 is used for descriptor completion. The vector 0
  is emulated by the host driver. The second interrupt vector is backed by
  an IMS vector on the host.

probe
------
API function to create the mdev. mdev_set_iommu_device() is called to
associate the mdev device to the parent PCI device. This function is
where the driver sets up and initializes the resources to support a single
mdev device. vfio_init_group_dev() and vfio_register_group_dev() are called
in order to associate the 'struct vfio_device' with the 'struct device' from
the mdev and the vfio_device_ops.

remove
------
API function that mirrors the create() function and releases all the
resources backing the mdev.  vfio_unregister_group_dev() is called.

open
----
API function that is called down from VFIO userspace when it is ready to claim
and utilize the mdev.

release
-------
The mirror function to open that releases the mdev by VFIO userspace.

read / write
------------
This is where the Intel IDXD driver provides read/write emulation of
the "slow" path of the mdev, including PCI config space and control-path
MMIO registers. Typically configuration and administrative commands go
through this path. This allows the mdev to show up as a virtual PCI
device in the guest kernel.

The emulation of PCI config space is nothing special, which is simply
copied from kvmgt. In the future this part might be consolidated to
reduce duplication.

Emulating MMIO reads are simply memory copies. There is no side-effect
to be emulated upon guest read.

Emulating MMIO writes are required only for a few registers, due to
read-only configuration on the ‘1dwq-v1’ type. Majority of composition
logic is hooked in the CMD register for performing administrative commands
such as WQ drain, abort, enable, disable and reset operations. The rest of
the emulation is about handling errors (GENCTRL/SWERROR) and interrupts
(INTCAUSE/MSIXPERM) on the vDSA device. Future mdev types might allow
limited WQ configurability, which then requires additional emulation of
the WQCFG register.

mmap
----
This is the function that provides the setup to expose a portion of the
hardware, also known as portals, for direct access for “fast” path
operations through the mmap() syscall. A limited region of the hardware
is mapped to the guest for direct I/O submission.

There are four portals per WQ: unlimited MSI-X, limited MSI-X, unlimited
IMS, limited IMS.  Descriptors submitted to limited portals are subject
to threshold configuration limitations for shared WQs. The MSI-X portals
are used for host submissions, and the IMS portals are mapped to vm for
guest submission. The host driver provides IMS portal through the mmap
function to be mapped to the user space in order to expose it directly
to the guest kernel.

ioctl
-----
This API function does several things
* Provides general device information to VFIO userspace.
* Provides device region information (PCI, mmio, etc).
* Get interrupts information
* Setup interrupts for the mediated device.
* Mdev device reset

The PCI device presented by VFIO to the guest kernel will show that it
supports MSIX vectors. The Intel idxd driver will support two vectors
per mdev to back those MSIX vectors. The first vector is emulated by
the host driver via eventfd in order to support various non I/O operations just
like the actual device. The second vector is backed by IMS. IMS provides
additional interrupt vectors on the device outside of PCI MSIX specification
in order to support significantly more vectors. Eventfd is also used by
the second vector to notify the guest kernel. However irq bypass manager is
used to directly inject the interrupt in the guest. When the guest submits
a descriptor through the IMS portal directly to the device, an IMS interrupt
is triggered on completion and routed to the guest as an MSIX interrupt.

The idxd driver makes use of the generic IMS irq chip and domain which
stores the interrupt messages in an array in device memory. Allocation and
freeing of interrupts happens via the generic msi_domain_alloc/free_irqs()
interface. Driver only needs to ensure the interrupt domain is stored in
the underlying device struct.

To allocate IMS, we utilize the IMS array APIs. On host init, we need
to create the MSI domain::

        struct ims_array_info ims_info;
        struct device *dev = &pci_dev->dev;

        /* assign the device IMS size */
        ims_info.max_slots = max_ims_size;
        /* assign the MMIO base address for the IMS table */
        ims_info.slots = mmio_base + ims_offset;
        /* assign the MSI domain to the device */
        dev->msi_domain = pci_ims_array_create_msi_irq_domain(pci_dev, &ims_info);

When we are ready to allocate the interrupts via the mdev IMS common lib code::

        struct device *dev = &mdev->dev;

        irq_domain = dev_get_msi_domain(dev);
        /* the irqs are allocated against device of mdev */
        rc = msi_domain_alloc_irqs(irq_domain, dev, num_vecs);


        /* we can retrieve the slot index from msi_entry */
        irq = dev_msi_irq_vector(dev, vector);

        request_irq(irq, interrupt_handler_function, 0, “ims”, context);


The DSA device is structured such that MSI-X table entry 0 is used for
admin commands completion, error reporting, and other misc commands. The
remaining MSI-X table entries are used for WQ completion. For vm support,
the virtual device also presents a similar layout. Therefore, vector 0
is emulated by the software. Additional vector(s) are associated with IMS.

The index (slot) for the per device IMS entry is managed by the MSI
core. The index is the “interrupt handle” that the guest kernel
needs to program into a DMA descriptor. That interrupt handle tells the
hardware which IMS vector to trigger the interrupt on for the host.

The virtual device presents an admin command called “request interrupt
handle” that is not supported by the physical device. On probe of
the DSA device on the guest kernel, the guest driver will issue the
“request interrupt handle” command in order to get the interrupt
handle for descriptor programming. The host driver will return the
assigned slot for the IMS entry table to the guest.

reset
-----

Device reset is emulated through the mdev. With mdev being a wq rather
than the whole device, we would not reset the entire device on a reset
request. The host driver will simulate a reset of the device by
aborting all the outstanding descriptors on the wq and then disabling
the wq. All MMIO registers are reset to pre-programmed values.

==========
References
==========
[1] https://software.intel.com/content/www/us/en/develop/download/intel-architecture-instruction-set-extensions-programming-reference.html
[2] https://software.intel.com/en-us/articles/intel-sdm
[3] https://software.intel.com/sites/default/files/managed/cc/0e/intel-scalable-io-virtualization-technical-specification.pdf
[4] https://software.intel.com/en-us/download/intel-data-streaming-accelerator-preliminary-architecture-specification
