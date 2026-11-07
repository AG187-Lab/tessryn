# NVMe VT-d setup in QEMU

This opt-in [IO01](https://github.com/AG187-Lab/tessryn/issues/9) and
[IO02](https://github.com/AG187-Lab/tessryn/issues/10) experiment extends the
[admin queue profile](io02-nvme-admin-queues.md). Both cases use the same
pinned q35 machine and namespace-less NVMe endpoint behind `00:02.0`. The
guest validates the firmware DMAR and the live bridge before selecting the
single segment-zero remapper at `0xfed90000`. The first register page uses a
supervisor uncached, non-executable mapping.

The earlier admin queue cycle retires the firmware state, sets up and clears
the guest's empty queues, and verifies that PCI bus mastering is disabled.
The VT-d step keeps bus mastering off. In the supported case it reserves five
image-owned table pages for legacy 39-bit second-level translation and admits
only requester `01:00.0`, domain 1. IOVA `0x01000000` maps the submission
queue page read-only. IOVA `0x01001000` maps the completion queue page
write-only. All other entries are absent. The kernel latches the root,
invalidates context and IOTLB caches, verifies translation enablement, and
retains the pages until the disposable VM exits.
[Intel VT-d architecture specification](https://cdrdv2-public.intel.com/831418/vt-directed-io-spec.pdf) ·
[Pinned QEMU VT-d implementation](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/hw/i386/intel_iommu.c)

The blocked case changes only QEMU's `dma-translation` property. The remapper
advertises no supported address width for second-level translation. The
kernel refuses before writing any VT-d registers or preparing tables. Its
root address and global status must remain zero.

The runner pauses the same QEMU process and retains the prior NVMe register
and queue snapshots, plus the fixed VT-d register snapshot for each case.
For the supported case it also validates the reported table range against
the guest's image and queue page bounds before capturing exactly five pages.
Replay checks the complete table contents, including absent entries, against
the expected root, context, and two leaf mappings. QMP samples guest
physical memory and register state. The BME readback is a guest observation.

Tessryn submits no commands and initiates no device DMA during these probes.
Actual allowed and denied DMA, revocation after device activity, interrupt
remapping, namespace I/O, and physical or cloud qualification remain open.
No performance samples are collected.

## Reproduce offline

Use a clean checkout with the [pinned tools and Rust host libraries](io01-pci-discovery.md#reproduce-offline).
Each output directory must be new and under `build/`.

```sh
python3 -B -m unittest discover -s tests -p 'test_io02_nvme_dma_trace.py' -v
build/toolchain/bin/rustc --edition=2024 --test -D warnings kernel/io02_vtd.rs -o build/io02-vtd-host-tests
build/io02-vtd-host-tests
build/toolchain/bin/rustc --edition=2024 --test -D warnings kernel/io02_vtd_acpi.rs -o build/io02-vtd-acpi-tests
build/io02-vtd-acpi-tests
build/toolchain/bin/rustc --edition=2024 --test -D warnings --cfg io02_nvme_registers --cfg io02_nvme_admin_queues --cfg io02_nvme_dma_isolation kernel/paging.rs -o build/io02-vtd-paging-tests
build/io02-vtd-paging-tests
python3 tools/build_io01_pci.py --nvme-dma-isolation --out build/io02-vtd/a
python3 tools/build_io01_pci.py --nvme-dma-isolation --out build/io02-vtd/b
python3 tools/build_io01_pci.py --nvme-dma-isolation --compare build/io02-vtd/a/manifest.json build/io02-vtd/b/manifest.json
for case in present blocked; do
  python3 tools/run_io01_pci.py --nvme-dma-isolation --manifest build/io02-vtd/a/manifest.json \
    --case "$case" --out "build/io02-vtd/$case" --allow-qemu
  python3 tools/run_io01_pci.py --nvme-dma-isolation --manifest build/io02-vtd/a/manifest.json \
    --case "$case" --out "build/io02-vtd/$case" --verify
done
```

Keep both manifests, results, original serial and QMP transcripts and the
named snapshots. Only the supported case retains `vtd-tables.bin`.
