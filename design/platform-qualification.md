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
| CPU/UEFI, PCIe, IOMMU, interrupts, storage, NIC, GPU and notebook power | Vendor candidate descriptions; read-only inventory collector; explicit inventory checklist below | Exact physical stable-node/laboratory and notebook inventories, firmware versions, topology diagrams and access prerequisites; notebook absent |
| Acquisition, provenance and redistribution constraints | Versioned NVIDIA source/firmware/compiler reference terms, provider boot/recovery sources | Artifact requirements and applicable acquisition/distribution constraints for the chosen targets; hashes and notices for any artifacts actually acquired |
| Select initial profiles and device/compiler targets after native-access evidence | Conditional laboratory candidate and GPU research targets | Evidence-backed engineering-target decision after critical boot-authority, device-access, recovery and artifact questions are resolved; no target selected |
| Per-profile support status | Every candidate is unqualified; boot/GPU/inference unavailable | Maintain separate engineering-target and capability statuses in the initial decision; no execution claim follows from G01 completion |

G01 remains open. Passing the collector tests establishes behavior of the
collector, not hardware support. A Linux reference inventory identifies what
Linux exposes; it does not prove the original kernel can initialize, isolate or
recover that hardware. A provider catalog's topology is not an observed PCIe
tree. Emulated boot must remain separate from physical native boot.

### G01 exit boundary

G01 supplies the hardware and access evidence needed to begin implementation.
It requires exact physical candidate inventories for the initial stable-node
and wired mains-powered notebook profiles, plus a recoverable laboratory
target; observed topology and firmware identities; memory estimates with
declared reserves and unknowns; and a recorded initial profile/device/compiler
decision. Critical native-access questions concern permission and feasibility:
available UEFI boot routes, console and independent recovery controls,
device/BAR/interrupt/IOMMU exposure, notebook power prerequisites and artifact
acquisition constraints. Record which answers are documented, observed on the
exact machine or still assumptions. An unresolved critical question prevents
selecting that target.

An engineering target may be selected for implementation while its Tessryn
boot, drivers, GPU execution and inference remain unavailable. G01 does not
require an original kernel boot, GPU initialization, native DMA isolation,
inference, measured admission or sustained thermal performance: those tests
belong to K01, IO01–IO05, GPU01–GPU03, inference/cluster work and DEMO01.
Advertised support still requires their exact-profile execution evidence.
Acquiring a binary solely to complete this research gate is unnecessary; if
one is acquired, preserve its exact hash, notices and applicable rights.

The current blockers are missing exact physical inventories and notebook
access, incomplete topology/firmware and access evidence, unresolved artifact
constraints for the eventual targets, and the absent engineering-target
decision. The candidate data separates these `g01_gates` from
`later_qualification` requirements. Collector fixtures and virtual CI reference
inventories do not resolve the physical qualification gates.

## Candidate laboratory and GPU profiles

The conditional CPU laboratory choice is **Scaleway Elastic Metal
EM-A610R-NVMe in `fr-par-1`**, hourly billing: Ryzen PRO 3600, 6 cores/12 threads,
32 GiB catalog RAM, two approximately 1.02 TB NVMe drives, and no listed GPU.
The public catalog includes normal/rescue boot and a custom remote-install
option. Board, BIOS/UEFI, NIC and storage controller identities remain unknown;
the offer name cannot select native drivers. Catalog RAM is not measured usable
memory. [Public pricing](https://www.scaleway.com/en/pricing/elastic-metal/)
and [ordering guide](https://www.scaleway.com/en/docs/elastic-metal/quickstart/).

The dated research observed a displayed server rate of €0.11/hour before tax.
**24-hour arithmetic**, not
a checkout quote: €2.64 server plus €0.12 for an optional €0.005/hour flexible
IPv4 address gives €2.76 **before setup fees, remote-access charges, other
services, tax and currency conversion**. The dated documentation records that
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
console supports custom media; the first three hours are free, availability is
limited, and virtual-media mounting can fail. A stale auction listing cannot
freeze a hardware profile. [Auction](https://www.hetzner.com/sb/),
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

| Area | G01 record | Later implementation qualification |
| --- | --- | --- |
| CPU and firmware | CPUID/features, cores/threads, UEFI boot mode and permitted boot route, board identity, BIOS/UEFI version/date, console and recovery authority | Original-kernel boot and memory-map handoff |
| PCIe | Endpoint and bridge BDFs, vendor/device/subsystem/revision IDs, parent relationships, BAR capabilities, ACS/reset-domain metadata and exact GPU multifunction layout | Native enumeration, mapping, reset and teardown behavior |
| Memory and DMA | Reported physical capacity and reference reservations; analytical reserve estimates; IVRS/DMAR and IOMMU groups as Linux reference only | Native usable memory, translation, revocation and isolation tests |
| Interrupts | APIC/interrupt-remapping prerequisites and MSI/MSI-X capabilities | Native routing, masking, faults and teardown |
| Storage and NIC | Exact controller PCI IDs, model and firmware versions, NVMe namespaces/capacity, wired NIC identity and access constraints | Native storage/network execution and link measurements |
| GPU | Exact board/subsystem/ISA, BAR/mapping/reset authority and constraints, firmware identities, acquisition terms and hashes of acquired artifacts | Native firmware initialization, DMA safety and verified compute |
| Notebook | Exact SKU/UEFI/EC, reference ACPI `_PR0`/`_PR3` and multifunction power/reset prerequisites, wired NIC, mains/sleep policy and available thermal sensors | Native power restoration, sleep/reset behavior and sustained thermal/load measurements |

The collector deliberately does not dump PCI configuration space, ACPI table
contents or device firmware. Its PCI IDs and Linux group memberships are an
initial inventory, not the entire G01 list above. Bridge/BAR/ACS/MSI-X details,
controller firmware and notebook ACPI metadata require separate authorized
read-only reference probes and source records. Exercise of reset, firmware
startup and DMA safety belongs to later implementation tests, with their own
authority and recovery plan. No disk write or driver/device reset is included
in the inventory session.

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
not be represented as one contiguous 128 GiB allocation. G01 may publish
analytical memory estimates with explicit assumptions and unknown reserves;
native usable/admitted capacity and model-fit claims require later measured
budgets. Missing inference measurements do not prevent recording the initial
hardware estimate.

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

Validate a retained numeric report before publication:

```sh
python3 tools/verify_platform_inventory.py inventory.json --expected-kind linux_reference_inventory
```

The verifier requires the complete v1 numeric-summary contract, the current
collector source hash, bounded numeric values, fixed diagnostic labels,
consistent retained PCI/IOMMU records and unavailable native capabilities.
It rejects extra identity fields, malformed or duplicate-key JSON, symlinks,
nonregular inputs and reports larger than 16 MiB. Historical reports can use
`--collector-sha256` with the independently retained original source hash.
Supply `--expected-kind synthetic_fixture` for invented fixture inputs.
Validation checks structure, bytes and consistency; it does not authenticate
physical custody or turn a declared Linux reference into native evidence.
Full identity reports still require manual review and are not accepted by this
numeric publication verifier. Collection is partial: rejected/missing facts
remain unavailable, and `record_limit` diagnostics identify truncated lists.
Linux IOMMU groups are reference observations, not a proof of Tessryn DMA safety.

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
