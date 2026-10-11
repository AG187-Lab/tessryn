# Initial platform qualification record (G01)

Status: research and inventory tooling, dated 2026-10-11. No supported native
profile has been selected. No machine has been rented, no firmware or compiler
binary has been acquired for G01, and no Tessryn boot, GPU or inference experiment has
run. The intended first product still requires three stable nodes and an exact
wired, mains-powered notebook; a cloud rental cannot replace the notebook gate.

This record prepares a short bare-metal laboratory session when no physical
machine is available. Its [candidate data](../planning/platform-candidates.json)
separates vendor specifications, analytical costs and missing observations.
[Rental sources](../evidence/g01-research/rental-source-notes.md) and
[GPU sources](../evidence/g01-research/gpu-source-notes.md) retain the research
references. These are original summaries of public sources, not imported
drivers or redistributed firmware. [Tooling verification](../evidence/g01-verification/README.md)
retains actual synthetic CLI results, test logs and evaluated source hashes.

## Decisions and unresolved acceptance

| G01 requirement | Present evidence | Remaining gate |
| --- | --- | --- |
| CPU/UEFI, PCIe, IOMMU, interrupts, storage, NIC, GPU and notebook power | Vendor candidate descriptions; read-only inventory collector; explicit inventory checklist below | Exact delivered-machine inventory, firmware versions and native-access experiments; notebook absent |
| Acquisition, provenance and redistribution constraints | Versioned NVIDIA source/firmware/compiler reference terms, provider boot/recovery sources | Exact acquired artifacts, hashes, notices, applicable distribution permissions and successful native initialization |
| Select initial profiles and device/compiler targets after native-access evidence | Conditional laboratory candidate and GPU research targets | No supported SKU or compiler/device execution target frozen; critical native-access questions unanswered |
| Per-profile support status | Every candidate is unqualified; boot/GPU/inference unavailable | Future evidence from K01, IO01–IO05, GPU01–GPU03 and inference work |

G01 remains open. Passing the collector tests establishes behavior of the
collector, not hardware support. A Linux reference inventory identifies what
Linux exposes; it does not prove the original kernel can initialize, isolate or
recover that hardware. A provider catalog's topology is not an observed PCIe
tree. Emulated boot must remain separate from physical native boot.

## Candidate laboratory and GPU profiles

For early GPU work, investigate the [inexpensive rental shortlist](../evidence/g01-research/early-gpu-rentals.md)
before AWS. GPU Mart's anonymous RTX 2060 dedicated preview shows USD 0.22/hour
and zero setup; exact UEFI/IPMI/RAM-only access and account terms remain gates.
A Hetzner Ada auction is the documented RAM-rescue fallback. These additional
price observations are unqualified research, not frozen supported profiles.

The conditional CPU laboratory choice is **Scaleway Elastic Metal
EM-A610R-NVMe in `fr-par-1`**, hourly billing: Ryzen PRO 3600, 6 cores/12 threads,
32 GiB catalog RAM, two approximately 1.02 TB NVMe drives, and no listed GPU.
The public catalog includes normal/rescue boot and a custom remote-install
option. Board, BIOS/UEFI, NIC and storage controller identities remain unknown;
the offer name cannot select native drivers. Catalog RAM is not measured usable
memory. [Public pricing](https://www.scaleway.com/en/pricing/elastic-metal/)
and [ordering guide](https://www.scaleway.com/en/docs/elastic-metal/quickstart/).

The displayed server rate is €0.11/hour before tax. **24-hour arithmetic**, not
a checkout quote: €2.64 server plus €0.12 for an optional €0.005/hour flexible
IPv4 address gives €2.76 **before setup fees, remote-access charges, other
services, tax and currency conversion**. Current documentation announces that
the EM-A610R fee promotion ended in October 2026, while the pricing page still
shows a waiver and generic hourly-no-commitment language. The public catalog
does not resolve this conflict. A hypothetical €39.99 fee would make this
scenario €42.75 before tax; that is neither an observed fee nor a price cap.
Obtain the actual order quote before spending. [October changelog](https://www.scaleway.com/en/docs/elastic-metal/).

Two further prerequisites prevent a rental decision today. The rescue guide
describes Ubuntu running entirely in RAM but requires an installed server;
the order guide permits no image. Confirm a no-install route into rescue.
Remote access is optional according to the operational guide even though the
pricing page describes it as free for all machines. Confirm the actual SKU's
console, UEFI mode and virtual media access. Do not infer arbitrary iPXE or
firmware-menu control. [Rescue prerequisites](https://www.scaleway.com/en/docs/elastic-metal/how-to/use-rescue-mode/),
[remote access](https://www.scaleway.com/en/docs/elastic-metal/how-to/activate-remote-access/).

**Hetzner Server Auction** is an alternative to quote at booking time. Its RAM
rescue and out-of-band reset are documented; exact offer, modern CPU, devices,
hourly charge and console availability have not been selected. A scheduled KVM
console supports custom media; availability is limited and mounting can fail.
Its older free-console statement conflicts with the current EUR 10/three-hour
addon price including 19% VAT; confirm charges. A stale auction listing cannot
freeze a hardware profile. [Current console fee](https://docs.hetzner.com/de/robot/dedicated-server/dedicated-server-hardware/price-server-addons/),
[Auction](https://www.hetzner.com/sb/),
[RAM rescue](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system/),
[KVM limits](https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console/).

**AWS `g4dn.metal`, `us-east-1`** is a separate GPU bare-metal research
candidate, not the default CPU lab. AWS lists a Xeon P-8259L, 384 GiB RAM and
eight T4 GPUs, each 16 GiB. The observed official Linux price feed quotes
$7.824/hour, or **$187.776 for 24 compute hours**, excluding other charges;
the [dated price observation](../evidence/g01-research/aws-price-observation.json)
records the source and rate code. Original-OS billing and regional capacity
remain unverified. A rented eight-GPU host is not evidence for the intended
four-participant product. [G4 specifications](https://aws.amazon.com/ec2/instance-types/g4/).

The documented T4 compute capability is 7.5, making `sm_75` a research target.
No cubin has been compiled or executed. Do not assume this bare-metal SKU
supports UEFI from AWS's generic Nitro rule; obtain exact supported-boot-mode
metadata first. Console screenshots exclude metal, serial access has account
and guest prerequisites, and managed root-volume replacement excludes non-Mac
metal. Recovery would need a verified external termination/relaunch path,
not a promised BIOS console. [Boot modes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instance-boot-mode.html),
[console limitations](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshoot-unreachable-instance.html),
[root-replacement limits](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/replace-root.html).

If AWS account access is preferred, the [AWS access plan](../evidence/g01-research/aws-access-notes.md)
recommends `c7i.metal-24xl` as the first conditional CPU trial and records
Paid Plan, regional quota, serial/recovery and exact boot-mode prerequisites.
Its Linux reference rate is $4.284/hour; 24 compute hours are $102.816 before
other charges. This adds a cloud laboratory candidate, not a supported
original-kernel profile or a verified RAM-only UEFI boot path.

AWS `g5.xlarge` is a **virtualized** A10G comparison candidate, not bare metal.
AWS reports 24 GB on its product page and 22 GiB in its technical table; neither
is a measured Tessryn admission limit. Its Linux reference quote is
$1.006/hour. GPU passthrough marketing does not establish native reset,
firmware, interrupt or IOMMU authority. [G5](https://aws.amazon.com/ec2/instance-types/g5/),
[technical table](https://docs.aws.amazon.com/ec2/latest/instancetypes/ac.html).

The exact notebook research record is **ThinkPad P15 Gen 2 `20YQ003FUS`**:
i9-11950H, RTX A2000 4 GB, 32 GB RAM, NVMe, wired RJ-45 and 170 W mains
adapter. This withdrawn SKU illustrates the exact-profile inventory required;
it is not a purchase recommendation or a selected worker. No unit is available
for UEFI/EC, GPU subsystem, ACPI power, topology or thermal testing.
[Exact Lenovo record](https://psref.lenovo.com/Detail/ThinkPad_P15_Gen_2?M=20YQ003FUS).

## Native-access and artifact gates

Before choosing native drivers or freezing G02's device-dependent contracts,
record these observations for the delivered laboratory machine:

| Area | Required record and later native check |
| --- | --- |
| CPU and firmware | CPUID/features, cores/threads, UEFI boot mode, board identity, BIOS/UEFI version/date, memory-map handoff and recovery authority |
| PCIe | Endpoint and bridge BDFs, vendor/device/subsystem/revision IDs, parent relationships, BAR capabilities, ACS/reset domains and exact GPU multifunction layout |
| Memory and DMA | Reported physical capacity versus usable map/reserves; IVRS/DMAR and IOMMU groups as Linux reference only; native translation, revocation and isolation tests later |
| Interrupts | APIC/interrupt-remapping prerequisites and MSI/MSI-X capability; native routing, masking, faults and teardown later |
| Storage and NIC | Exact controller PCI IDs, model and firmware versions, NVMe namespaces/capacity and NIC interfaces; no disk writes or driver reset during this session |
| GPU | Exact board/subsystem/ISA, BAR/mapping/reset authority, firmware versions and source/license/hash of every acquired artifact; native verified compute later |
| Notebook | Exact SKU/UEFI/EC, ACPI `_PR0`/`_PR3` and multifunction power/reset behavior, wired NIC, mains/sleep policy; sustained thermal/load measurements later |

The collector deliberately does not dump PCI configuration space, ACPI table
contents or device firmware. Its PCI IDs and Linux group memberships are an
initial inventory, not the entire list above. Bridge/BAR/ACS/MSI-X details,
controller firmware and native DMA safety stay unavailable until separate
authorized probes and implementation tests provide them.

NVIDIA open-module source and binary firmware have separate terms. The pinned
580.95.05 research reference requires matching Linux userspace/GSP components;
it is not a native Tessryn driver or a stable GSP contract. CUDA 13.1.1 is only
a versioned compiler research input. Device-only cubin generation does not
grant permission to redistribute the toolkit or every vendor runtime portion
embedded in an output. Record applicable notices, versions/hashes and rights
before acquiring or distributing artifacts. The [GPU research notes](../evidence/g01-research/gpu-source-notes.md)
link the exact terms. No vendor code, firmware, `nvcc` or cubin is included here.

An analytical memory ledger must keep total hardware bytes separate from
firmware reservations, original-kernel/service reserves, DMA/staging buffers,
device workspace, weights and KV/recurrent state. For the CPU candidate the
vendor total is 34,359,738,368 bytes; every reserve and admitted capacity is
currently unknown. For the GPU candidate, eight separate 16 GiB devices must
not be represented as one contiguous 128 GiB allocation. No model-fit or
inference-capacity result can be calculated without measured budgets.

## Bounded 24-hour session

The first rental should be an inventory/recovery session, not a GPU benchmark.
Before authorizing a booking, obtain an exact dated quote, available SKU/zone,
all setup/IP/console fees, RAM-only rescue route, out-of-band recovery and
deletion procedure. Account access, a spending limit and permission for that
specific booking are still required. No cloud account was inspected here.

| Time budget | Action | Retained evidence |
| --- | --- | --- |
| Before clock starts | Freeze collector revision/hash; run tests; confirm quote and rescue/console access; arrange deletion deadline | Source revision, test log, redacted quote and provider answers |
| Hours 0–2 | Start directly into verified RAM rescue; confirm no physical filesystem is mounted or used for swap; inspect available console/recovery controls | Linux reference inventory, public firmware identities; private access details remain private |
| Hours 2–4 | Run the collector; review and redact before public upload; correlate NIC/NVMe/GPU IDs and missing topology | Hashed public report plus manual unknowns; zero native/performance samples |
| Hours 4–6 | If ready, run G03's original fixtures under QEMU TCG wholly in RAM, with no physical drives attached | Emulator fixture records only; use the G03 workflow now on main |
| Remaining time | Resolve inventory questions or end early; rehearse return to known-good RAM rescue if authorized; export sanitized evidence | Recovery observation or explicit unavailable result |
| By hour 24 | Delete rented resources and release separately billed IP/console services; verify removal in provider control plane | Redacted deletion/billing record, no credentials or account identifiers |

Powering off is not a deletion strategy. Scaleway bills an allocated Elastic
Metal server until deletion and a reserved flexible IP until its reservation
is cancelled. [Billing rules](https://www.scaleway.com/en/docs/billing/faq/).
Do not install an OS, mount or format disks, enable disk swap, write an AMI,
flash firmware, reset a device, change firmware/UEFI settings or select custom
boot targets in this inventory-only session. Only the preverified provider
RAM-rescue selection and its authorized recovery rehearsal are included.
Later original UEFI RAM/virtual-media boot is K01 work
and needs its payload and the provider's exact boot authority first.

GitHub Actions can continue exercising software-emulated profiles without a
bare-metal rental using the [G03 workflow](build-and-evaluation.md). Original-OS EC2 image
registration is a separate future cloud qualification path: VM Import has an
OS allowlist; a direct snapshot/UEFI AMI route is documented but does not make
an absent kernel boot. Neither route belongs to this inventory session.
[Import prerequisites](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html),
[AMI boot-mode registration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html).

## Inventory reproduction and public evidence

From a clean checkout of the implementation revision recorded in the PR:

```sh
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
```

On an authorized Linux RAM rescue host with Python 3.12 or later, copy the
reviewed collector into RAM and run it from there:

```sh
timeout --signal=TERM --kill-after=2s 30s python3 collect_platform_inventory.py --out inventory.json
sha256sum collect_platform_inventory.py inventory.json
```

The output file must be new. GNU `timeout` bounds the operator's wait for
reference collection; status 124 is a timeout, not an inventory result, and
must be retained as such. No successful report is inferred from an interrupted
collection. Confirm the working directory is RAM-backed
before running; the collector does not choose or mount a filesystem. It reads
whitelisted Linux reference data and writes only the requested report. It
does not read hostname, serial, UUID, network-address, credential or cloud
account fields. It screens known sensitive patterns in whitelisted identity
strings. Arbitrary host-provided model/firmware text still needs manual public
review. Bounded missing/malformed input is reported as unavailable.

For automatic publication, `--public-summary` omits all host-provided free-form
CPU/DMI/driver/storage/power identity strings. CI uploads only this derived
numeric inventory, never a full unreviewed identity report. It preserves
parsed PCI IDs/group membership, numeric capacities, fixed status fields and
the collector hash; it cannot establish the omitted model or firmware identity.

`--root` selects a test filesystem and always marks the report
`synthetic_fixture` unless it is the real system root. Such fixtures can test
privacy, parsing and topology correlation but cannot identify an actual rental.
Actual collection is `linux_reference_inventory`; original-kernel boot, GPU
execution and model inference always remain unavailable. Measured admission
and sustained performance remain unknown in both cases. There is no privileged
probe, cloud metadata request, module loading or hardware-writing command.

Publish only the reviewed inventory, source/script hash, exact command, Python
version, evidence basis and observed failures. Keep booking IDs, IPs, account
details, keys and console credentials out of public records. No actual physical
inventory or rental recovery result accompanies this initial packet.
