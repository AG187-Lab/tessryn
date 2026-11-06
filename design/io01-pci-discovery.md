# IO01 PCI discovery in QEMU

This is the first offline discovery slice for [IO01 #9](https://github.com/AG187-Lab/tessryn/issues/9)
and a prerequisite for the storage and diagnostic work in [CLOUD01 #35](https://github.com/AG187-Lab/tessryn/issues/35).
It exercises original Tessryn code in QEMU. Native storage, persistence and
service diagnostics still require [IO02 #10](https://github.com/AG187-Lab/tessryn/issues/10)
and [K05 #8](https://github.com/AG187-Lab/tessryn/issues/8).

The dedicated `io01_pci` image runs one boot CPU on `pc-q35-11.1` with TCG,
`qemu64`, 256 MiB RAM and the pinned OVMF pair. It starts the scan only after
`ExitBootServices`, CPU ownership and the K01 owned-memory readback. It emits
bounded COM1 records and halts. This profile is separate from normal K01,
AWS boot media and the SMP/benchmark profiles.

For this fixed emulator only, the kernel selects conventional PCI configuration
dwords through `0xcf8` and reads them from `0xcfc`. It probes segment zero, buses
0–7, all 32 slots and all eight functions. The three allowed dword offsets are
`0x00` (vendor/device), `0x08` (class, subclass, programming interface, revision)
and `0x0c` (header). It skips absent vendors, rejects invalid vendors and header
types, and admits at most 64 records in BDF order. The probe leaves PCI
configuration data intact. It does not size BARs, map PCI device registers,
configure device interrupts, enable DMA, or send storage commands. The existing
K01 framebuffer is unchanged.

The runner boots the same firmware-loaded disposable IDE disk in two fresh guests.
Both have an explicit PCIe root port and K01's emulated VGA for firmware graphics
admission, with host display disabled. `present` attaches a QEMU NVMe controller
with no namespace; `absent` leaves that port empty. After the complete guest
record, the runner pauses QEMU and retrieves `query-pci` from the same process.
The verifier compares the complete scoped sets of BDFs, vendor/device IDs, and
class/subclass, including devices behind the bridge. Programming-interface and
revision bytes are guest observations; QMP does not independently return them.
The absent control must contain no NVMe controller. Missing records, mismatches,
process failures and timeouts do not pass.

QMP observes the emulated PCI topology independently of the guest code, but
both observations concern the same device model. This does not qualify EC2,
physical hardware, native device authority, an NVMe driver, persistence, network
devices, GPU execution, inference or performance. ECAM/MCFG and safe MMIO
admission remain separate work. Discovery is not a grant to use a device.

## Reproduce offline

Use the [pinned setup](first-kernel.md) in a clean checkout. The build output and
both capture directories must be new, under ignored `build/`. The emulator has
no network, host-device passthrough or physical-disk access. Its firmware variable
store and disk working state are disposable. The scanner unit tests also require
the pinned Rust host libraries.

```sh
python3 -B -m unittest discover -s tests -p 'test_io01_pci*.py' -v
python3 tools/setup_k02_toolchain.py
python3 tools/setup_uefi.py
build/toolchain/bin/rustc --edition=2024 --test -D warnings kernel/io01_pci.rs -o build/io01-pci-host-tests
build/io01-pci-host-tests
python3 tools/build_io01_pci.py --out build/io01-pci/a
python3 tools/build_io01_pci.py --out build/io01-pci/b
python3 tools/build_io01_pci.py --compare build/io01-pci/a/manifest.json build/io01-pci/b/manifest.json
for case in present absent; do
  python3 tools/run_io01_pci.py --manifest build/io01-pci/a/manifest.json \
    --case "$case" --out "build/io01-pci/$case" --allow-qemu
  python3 tools/run_io01_pci.py --manifest build/io01-pci/a/manifest.json \
    --case "$case" --out "build/io01-pci/$case" --verify
done
```

Build manifests bind the revision and source snapshot, compiler and firmware
provenance, exact opt-in flags, EFI and reconstructed boot-media bytes and
notices. Preserve the manifests, case results, serial and both directions of the
QMP transcript. `--verify` rechecks those bytes without starting a new guest;
its result is evidence consistency, not capture authentication. Host tests
and fabricated transcript tests validate the tooling; only actual QEMU runs
establish the emulator observations. There are no performance samples.

Primary references: [Intel Q35 chipset datasheet](https://www.intel.com/Assets/PDF/datasheet/316966.pdf)
§§4.3 and 4.5, [QEMU q35 topology guide](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/docs/pcie.txt),
and the [pinned QEMU QAPI PCI schema](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/qapi/pci.json).
