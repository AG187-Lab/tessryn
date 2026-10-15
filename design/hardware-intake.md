# Physical laboratory intake and CPU boot/recovery

Prepared October 14, 2026 (America/Los_Angeles), against K01 main
`d6bf5e82dad6e6347238e1d6c683f5a6cdb1a5f6`. No server is available yet.
This is a requirements packet, not a rental, physical inventory or qualification
result. [G01 #1](https://github.com/AG187-Lab/tessryn/issues/1) remains open.
Use it with the [G01 record](platform-qualification.md) and
[K01 implementation/run instructions](first-kernel.md).

## Provider-neutral admission requirements

For each answer retain its date, exact product/machine scope and evidence basis:
provider documentation, provider confirmation, exact-machine observation or
unknown. A catalog specification cannot replace an observed delivered profile.
Use a public profile label; keep account, host, IP and credential details private.

| Required answer | Evidence needed before a CPU boot trial |
| --- | --- |
| Exact machine and authority | Dedicated physical x86-64 machine, quoted configuration/location, operator permission and session owner; no shared GPU VPS |
| Boot route | x64 UEFI can load the unsigned `deployment/boot.iso` through virtual CD/removable media; one-time selection and restoration steps recorded |
| Firmware fallback | A rejected image or missing virtual CD stays at a boot manager or enters confirmed RAM-only recovery; automatic boot from physical storage is prevented for this session |
| Firmware policy | Current boot mode and Secure Boot policy; permission for the proposed image; any required setting change documented and separately authorized |
| Console | Working firmware-stage KVM, usable client and access window; virtual media can actually attach; console remains reachable after the CPU halts |
| Visible diagnostics | Console-associated UEFI GOP with a linear RGBX/BGRX framebuffer; determine whether BMC video and accelerator video differ |
| Recovery | Independent power/reset control and a known-good boot environment, media and steps; usable even if Tessryn never returns; recovery deadline and operator recorded |
| Disk-free route | Provider-confirmed RAM-only reference/rescue boot, no physical filesystem mounts or disk swap, and no installer/reload requirement |
| Costs and end of service | Exact quote, minimum charge/deposit, setup/console/media fees, taxes, rounding, stock, billing start and deletion/cancellation procedure; explicit approved spending cap before a booking |
| CPU and platform | CPU/board model, UEFI/BMC versions, CPUID/physical-address width and reference memory map; current K01 uses one active CPU and four-level paging |
| Device prerequisites | PCI vendor/device/subsystem/revision IDs and bridge topology; IOMMU/interrupt resources, BAR/reset access, NIC/storage identities and firmware; GPU board/ISA/firmware constraints |
| Artifacts | Image source revision, pinned compiler/media manifest, notices and SHA-256; exact firmware/compiler requirements and acquisition/redistribution terms for later devices |
| Time and evidence | Bounded trial window, abort/recovery deadlines, capture operator, private evidence destination and public review owner |

Unknown boot/fallback, console, unsigned-image authority, disk-free or independent recovery
answers block a disk-free CPU trial. Missing GPU initialization evidence does not
block an inventory-only session. Missing critical device-access information blocks
selecting that device as an engineering target; it does not require implementing
the driver to complete G01. Preserve the separate
[G01 exit boundary](platform-qualification.md#g01-exit-boundary).

The notebook needs its own exact SKU and available unit, mains adapter and wired
NIC; UEFI/EC identities; GPU multifunction/ACPI power and reset prerequisites;
sensor availability and an independent recovery route. A rental server cannot
fill this record. Nameplate RAM/VRAM remains separate from analytical reserves,
native usable memory and later measured admission.

## GPU Mart fit and unresolved questions

The following official public pages were rechecked October 14, 2026. These are
catalog/documentation observations; no account, checkout, support conversation,
machine access or availability was inspected. Earlier anonymous checkout research
is dated separately in [the rental shortlist](../evidence/g01-research/early-gpu-rentals.md).

| Source | Observed fact | Exact-machine question still open |
| --- | --- | --- |
| [Hourly offer](https://www.gpu-mart.com/pricing-hourly) | RTX 2060 dedicated option at USD 0.22/hour; table lists dual E5-2660, 128 GB RAM, 120+960 GB SSD and 100 Mbps; page conflicts between 6 GB and 12 GB GPU memory | Delivered GPU/board, complete quote, stock and eligibility? |
| [Dedicated catalog](https://www.gpu-mart.com/gpu-dedicated-server) | Advertises physical dedicated resources and included IPMI | Does this exact hourly allocation include working KVM, virtual CD and independent reset? |
| [Technical FAQ](https://www.databasemart.com/faq/technical-questions) | Custom ISO via IPMI or provider FTP applies to dedicated servers; IPMI account creation requires the operator's local IP; BIOS access is described | Can the exact machine boot unsigned x64 UEFI media entirely in RAM, and expose the GOP through KVM? |
| [General FAQ](https://www.databasemart.com/faq/general-questions) | Dedicated-server IPMI includes remote power/reboot; iKVM is stated only for some plans | Which BMC/client, access restrictions and known-good recovery route apply? |
| [Billing FAQ](https://www.databasemart.com/faq/billing-questions) | Says minimum billing is monthly | Which terms govern this exact hourly dedicated offer? |

The hourly page says charging begins after deployment and destruction ends future
charges; its FAQ says pausing does not stop billing, while another section says
stopping does. Obtain the actual termination rule with the quote. At the displayed
rate, 24 compute hours are **USD 5.28 arithmetic**, before any unresolved minimum,
deposit, fees or tax; this is not a payable quote or spending authorization.
Free-trial eligibility and refundability of credit are unknown.

Decision: retain GPU Mart as a conditional laboratory candidate. Public evidence
does not establish x64 UEFI, unsigned loading, a RAM-only rescue/custom-boot route,
console-visible GOP, exact device authority or successful recovery for its hourly
machine. No target selection or supported platform follows from this packet.
Do not send the questions or place an order without the user's instruction.

## Intake record to complete

Copy this record into the trial's private notes. Replace `unknown` only with a
dated answer and a retained evidence reference; retain contradictory answers.

```text
Public profile label / candidate role: unknown
Exact offer, delivered configuration, location / observation date: unknown
CPU / board / UEFI / BMC / GPU / NIC / storage identities: unknown
UEFI unsigned virtual-CD route / safe fallback / GOP visible through KVM: unknown
RAM-only reference boot / physical mounts and disk swap absent: unknown
Independent power/reset / known-good recovery route: unknown
Operator authority / permitted actions / access window: unknown
Quote / minimum / fees / deposit / spending cap / termination rule: unknown
Image commit / workflow run / manifest SHA-256 / deployment ISO SHA-256: unknown
Trial duration / abort point / recovery deadline / operator: unknown
Native boot observation / independent recovery / cleanup disposition: not run
G01 missing facts / initial engineering-target decision: unresolved
```

## Ready runbook once a machine and access are authorized

1. Complete the admission record. Agree on the precise actions: read-only reference
   inventory, virtual-CD boot, independent reset/recovery and rental termination if
   applicable. An inventory-only authorization does not authorize custom boot.
   Set the recovery deadline before touching the boot route; do not start if the
   console/media window cannot accommodate recovery.
2. Freeze a clean K01 source revision and passing workflow run. The
   [exact-main K01 run](https://github.com/AG187-Lab/tessryn/actions/runs/38589025114)
   passed for the revision above. Its `k01-kernel-and-evidence` artifact includes
   `kernel-a/deployment/boot.iso`, manifests and notices; download that exact run
   or build twice with the [K01 commands](first-kernel.md#build-and-reproduce).
   Artifact availability expires; a missing artifact requires a fresh verified
   build rather than substituting an unidentified image.
3. Check the complete local build/artifact packet and ISO SHA-256 against the
   manifest. Retain the source revision, workflow URL, manifest hash, ISO hash and
   notices beside the trial record. Use **`deployment/boot.iso`** for physical
   boot. `normal/boot.iso` has emulator I/O; the AWS serial image has a different
   hardware profile. The generic deployment image emits GOP output and no UART
   output, so a serial-only console is insufficient.
4. Establish the known-good environment and independently usable console/reset
   controls before changing the boot route. For a disk-free session the recovery
   environment must also be RAM-only: booting an installed OS can write disks.
   Record its successful baseline and planned restoration steps. Preserve this
   recovery evidence separately from Tessryn's own runtime reset tests.
5. In the authorized RAM-only reference environment, confirm no physical mounts or
   disk swap and a RAM-backed working directory. Follow the
   [inventory reproduction procedure](platform-qualification.md#inventory-reproduction-and-public-evidence)
   with the frozen collector and Python 3.12+. Retain numeric publication output
   separately from manually reviewed identity/topology/firmware notes. The
   collector omits detailed BAR/ACPI/firmware probes; mark missing facts unknown.
6. Start a private time-stamped console capture before selecting the virtual CD.
   Attach the verified deployment ISO, record its identity in the media interface
   and choose the one-time **UEFI** entry only after confirming its failure fallback
   cannot boot a physical-disk OS. If changing boot settings is required, include
   those exact changes and their restoration in the authorization. Do not install,
   partition, format, flash or mount physical storage. Keep the independent
   recovery session available.
7. Observe the original kernel's GOP status, firmware exit, CPU ownership and
   memory readback, followed by `TESSRYN_K01_PASS` and terminal halt. Capture the
   transition as well as terminal status; record expected versus observed output.
   A loader screen, black screen, timeout or stale terminal image is not a pass.
   A physical halt has no QEMU exit code. If GOP is unsupported or ambiguous,
   preserve the failure and recover; do not substitute a GPU driver claim.
8. At terminal halt, failure or the agreed abort point, use independent recovery.
   Detach virtual media, restore the known-good boot route and observe a fresh
   recovery boot. Record completion time and any changed settings. If recovery
   fails, preserve evidence and invoke the prearranged recovery owner; no further
   experiments follow a failed recovery.
9. Retain raw private captures first. Prepare a public record with source/artifact
   hashes, exact public hardware/firmware identities, ordered observations,
   operator disposition and recovery outcome; remove account IDs, addresses,
   credentials, tokens, machine serials/UUIDs and unrelated console content.
   Hash the final reviewed files and document redactions. Evidence hashing binds
   retained bytes; it does not independently authenticate the physical machine.
10. Complete the agreed rental termination and verify the control-plane/billing
    outcome if applicable. Report boot, recovery and cleanup independently,
    including unavailable or failed results. G01 closes only after its complete
    stable-node/notebook records, access/artifact gates and initial target decision.

This runbook has not been executed. A future accepted pass covers CPU boot and
independent recovery for the exact observed physical profile. K02 isolation,
SMP, native storage/NIC/DMA, GPU initialization/cubin execution, inference and
performance require their own implementation and evidence gates. The existing
AWS CPU proof neither fills the physical inventory nor qualifies a GPU.
