# IO02 NVMe register probe in QEMU

The first [IO02](https://github.com/AG187-Lab/tessryn/issues/10) storage
experiment extends the [IO01 q35 profile](io01-pci-discovery.md) with an
opt-in `io02_nvme_registers` image. The original kernel reads the modeled NVMe
controller after firmware exit and CPU ownership. Firmware still loads the
image from the disposable virtual IDE disk. The emulated NVMe controller has
no namespace attached.

The probe admits only the modeled endpoint at `01:00.0` with PCI ID
`1b36:0010`, class and programming interface `010802`, a type-0 header and
memory decoding enabled. It reads the assigned 64-bit non-prefetchable BAR0
through PCI configuration space. The fixed q35 profile expects base
`0x81000000` and an aperture of `0x4000` bytes. The guest does not size or
reprogram the BAR. It checks that the aperture is disjoint from the final
firmware descriptors and the kernel's live ranges, then replaces the existing
identity translation of only the first 4 KiB with a supervisor-only,
uncached, read-only and non-executable mapping. Neighboring translations
retain their permissions and addresses.

The guest performs three aligned volatile 32-bit reads at offsets `0x00`,
`0x04` and `0x08`. These yield the low and high halves of CAP and the VS
register. The pinned QEMU model predicts CAP `0x004008200f0107ff` and VS
`0x00010400`. This prediction comes from the model source and is checked
against both observations. [NVMe Base Specification 1.4c](https://nvmexpress.org/wp-content/uploads/NVM-Express-1_4c-2021.06.28-Ratified.pdf) ·
[Pinned QEMU controller model](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/hw/nvme/ctrl.c#L9368-L9378)

The runner pauses the same QEMU process and independently checks the PCI
inventory and assigned BAR geometry. For the present case it takes a fixed
12-byte QMP snapshot of the three register dwords. Offline replay checks
the original command, snapshot bytes and serial results. The empty-port
control must report zero guest register reads and produces no host snapshot.
An invalid endpoint, overlapping aperture, mapping failure or mismatched
observation rejects the run. Capture uses the existing bounded QEMU runner.

This experiment supplies emulator evidence for register admission and early
serial diagnostics. The probe leaves PCI configuration data and controller
registers intact. The separate [admin queue experiment](io02-nvme-admin-queues.md)
exercises setup and teardown in QEMU with bus mastering disabled. DMA authority,
namespace I/O, persistence, service diagnostics and
[CLOUD01](https://github.com/AG187-Lab/tessryn/issues/35)
qualification remain open. No performance samples are collected.

## Reproduce offline

Use a clean checkout with the [pinned IO01 tools and host test libraries](io01-pci-discovery.md#reproduce-offline).
Each build and capture directory must be new. Only disposable emulator media
is used.

```sh
python3 -B -m unittest discover -s tests -p 'test_io02_nvme*.py' -v
build/toolchain/bin/rustc --edition=2024 --test -D warnings --cfg io02_nvme_registers kernel/io01_pci.rs -o build/io02-nvme-host-tests
build/io02-nvme-host-tests
build/toolchain/bin/rustc --edition=2024 --test -D warnings --cfg io02_nvme_registers kernel/paging.rs -o build/io02-nvme-paging-tests
build/io02-nvme-paging-tests
python3 tools/build_io01_pci.py --nvme-registers --out build/io02-nvme/a
python3 tools/build_io01_pci.py --nvme-registers --out build/io02-nvme/b
python3 tools/build_io01_pci.py --nvme-registers --compare build/io02-nvme/a/manifest.json build/io02-nvme/b/manifest.json
for case in present absent; do
  python3 tools/run_io01_pci.py --nvme-registers --manifest build/io02-nvme/a/manifest.json \
    --case "$case" --out "build/io02-nvme/$case" --allow-qemu
  python3 tools/run_io01_pci.py --nvme-registers --manifest build/io02-nvme/a/manifest.json \
    --case "$case" --out "build/io02-nvme/$case" --verify
done
```

Keep the source-bound manifests, both results and serial and QMP logs, and the
present case's `nvme-registers.bin`. Replaying the packet establishes evidence
consistency. Host fixtures exercise refusal and mapping boundaries.
