# IO02 NVMe admin queues in QEMU

This separate [IO02](https://github.com/AG187-Lab/tessryn/issues/10) experiment
builds on the [read-only register probe](io02-nvme-registers.md). It uses the
same pinned q35 machine, firmware and namespace-less NVMe controller. Firmware
loads the original Tessryn image from disposable virtual IDE media. This
profile admits writes to the first BAR page through a supervisor uncached,
non-executable identity mapping. The existing register-only image keeps the
read-only mapping.

The queue probe validates two disjoint, 4 KiB-aligned pages inside the loaded
kernel image. It accepts an inactive controller or the exact READY state
observed after the pinned OVMF boot. It clears PCI Bus Master Enable if set,
using a 16-bit write to the Command register, and verifies the result. The
pinned QEMU PCI model gates the endpoint's bus-master address space on that bit.
For the READY handoff, Tessryn clears CC.EN and waits for RDY to clear before
publishing its own queue addresses. The firmware's old pages are untouched.
Both Tessryn pages are zeroed and remain reserved until the VM exits.
[Pinned QEMU PCI model](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/hw/pci/pci.c#L138-L168)

With bus mastering disabled, Tessryn programs AQA for two entries per queue
and ASQ and ACQ for the two owned pages. It verifies readback, sets CC to
`0x00460001`, and polls for CSTS.RDY with a fixed iteration budget. It clears
CC.EN after observing readiness, waits for RDY to clear, then clears and
checks the queue registers. An unresolved transition causes the guest to
halt with the pages retained, and the bounded host runner terminates the
emulator. The iteration budget applies to this pinned model. [NVMe Base Specification 1.4c, §3.1.5–§3.1.10](https://nvmexpress.org/wp-content/uploads/NVM-Express-1_4c-2021.06.28-Ratified.pdf) ·
[Pinned QEMU start and stop logic](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/hw/nvme/ctrl.c#L8131-L8319)

Readiness, firmware reset and PCI Command readback are guest observations. The runner checks
the paused QEMU topology and records the same CAP/VS snapshot as the
register-only experiment. It also captures a fixed 36-byte snapshot to
independently verify the final zero CC, CSTS, AQA, ASQ and ACQ. The
empty-port control must report zero queue writes and produces no snapshots.
No doorbell is rung and no command is submitted. Command execution,
DMA authority, namespace I/O, persistence and cloud qualification remain open.
The separate [VT-d setup experiment](io02-nvme-vtd.md) uses these reserved
queue pages to test remapper configuration with bus mastering still disabled.

## Reproduce offline

Use a clean checkout with the [pinned tools and Rust host libraries](io01-pci-discovery.md#reproduce-offline).
Build and capture directories must be new and under `build/`.

```sh
python3 -B -m unittest discover -s tests -p 'test_io02_nvme_admin_trace.py' -v
build/toolchain/bin/rustc --edition=2024 --test -D warnings --cfg io02_nvme_registers --cfg io02_nvme_admin_queues kernel/io01_pci.rs -o build/io02-admin-host-tests
build/io02-admin-host-tests
build/toolchain/bin/rustc --edition=2024 --test -D warnings --cfg io02_nvme_registers --cfg io02_nvme_admin_queues kernel/paging.rs -o build/io02-admin-paging-tests
build/io02-admin-paging-tests
python3 tools/build_io01_pci.py --nvme-admin-queues --out build/io02-admin/a
python3 tools/build_io01_pci.py --nvme-admin-queues --out build/io02-admin/b
python3 tools/build_io01_pci.py --nvme-admin-queues --compare build/io02-admin/a/manifest.json build/io02-admin/b/manifest.json
for case in present absent; do
  python3 tools/run_io01_pci.py --nvme-admin-queues --manifest build/io02-admin/a/manifest.json \
    --case "$case" --out "build/io02-admin/$case" --allow-qemu
  python3 tools/run_io01_pci.py --nvme-admin-queues --manifest build/io02-admin/a/manifest.json \
    --case "$case" --out "build/io02-admin/$case" --verify
done
```

Keep both manifests, case results and raw serial and QMP transcripts. The
present case also retains `nvme-registers.bin` and `nvme-admin-final.bin`.
Offline replay checks those bytes without launching QEMU.
