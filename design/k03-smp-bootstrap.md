# Two-CPU kernel bootstrap and interrupt ownership

Status: implementation contract; clean original-kernel execution acceptance pending.
This bounded step advances [K03 issue #6](https://github.com/AG187-Lab/tessryn/issues/6)
from the [single-CPU timer baseline](k03-timer-preemption.md) into original-kernel
AP startup and cross-CPU interrupt ownership. [ADR 0020](decisions/0020-two-cpu-bootstrap.md)
records the decision. It does not integrate a second CPU with the CPL3 service
runtime or scheduler.

## Admitted profile and topology

The opt-in `k03_smp` profile boots the original x86-64 UEFI kernel under pinned
QEMU/OVMF with `q35,hpet=on`, `tcg,thread=multi`, 256 MiB RAM and exactly two virtual
CPUs: one socket, two cores and one thread per core. It admits legacy xAPIC at
`0xfee00000`, HPET at `0xfed00000` and the checked 10,000,000-femtosecond counter
period. x2APIC and unsupported CPU-state extensions are excluded by the profile.
The existing single-CPU K01/K02, region-service, timer and benchmark profiles keep
their own admission, execution and evidence contracts.

Before ExitBootServices, the loader obtains the ACPI 2.0 configuration entry
through the UEFI system table. Fresh memory-map coverage, checked address spans
and the low identity-map limit precede every table view. No checksum grants pointer
authority. The allocation-free `smp_acpi` module consumes bounded byte slices:

- Exact 36-byte revision-2-or-later RSDP with both checksums, bounded XSDT and
  checksummed SDTs no larger than 64 KiB.
- Exactly two enabled type-0 processor entries, distinct APIC IDs, fixed LAPIC
  base and no LAPIC override. Duplicate IDs include disabled/x2APIC entries;
  enabled x2APIC, broadcast ID 255, reserved flags and Enabled+OnlineCapable are
  rejected. Disabled entries supply no AP-start authority.
- The fixed HPET table profile. Its GAS width may be zero, as emitted by pinned
  QEMU, or 64; that metadata does not prove the main counter width or period.
  The BSP independently checks the actual MMIO capability register.

The native loader additionally caps its retained MADT copy at 512 bytes and
requires one MADT and one HPET table. It retains owned topology values and the
raw MADT, without ACPI pointers surviving ExitBootServices. Table views are borrowed
only while firmware services remain live; the handoff retains owned values and
the MADT copy. A fresh-map-validated
LoaderData page below 1 MiB holds the trampoline and remains reserved in the
final handoff. ExitBootServices retries do not allocate or repeat ACPI traversal.

The 26 host tests cover copied-table bounds, checksums, lengths, flags, duplicate
IDs, unsupported topology and the actual QEMU HPET table shape. They establish
parser behavior; original guest evidence must establish AP execution.

## CPU and memory ownership

The BSP takes the existing original-kernel CPU handoff. It identifies itself
from actual CPU/APIC state and chooses the other admitted APIC ID; sorted MADT
order does not identify the BSP. The BSP prepares UC/NX LAPIC and HPET mappings
before releasing the AP. Both CPUs use one common CR3; software does not mutate
its page tables after AP release. There is no cross-core TLB invalidation or
reclamation protocol in this profile.

The AP receives an image-owned normal stack and fault stack, private GDT, IDT
and TSS. It installs those tables before publishing readiness. Actual SGDT,
SIDT, STR, RSP, RIP and CR3 observations must agree with their owned ranges and
the common root. Only the BSP writes the console and emits the combined trace.
AP readiness/facts and commands/acknowledgments use explicit Release/Acquire
publication; a status string alone is not an online acknowledgment.

The 4096-byte original trampoline is bound to the compiled object and linked
EFI image. Its copied template has no relocations; only the declared CR3, entry,
stack, GDT-base and far-transfer patch fields may change. INIT is not treated as
a complete state sanitizer. The AP explicitly establishes segment/control state
and a clean legacy FP environment before Rust, and checks the admitted PAT/UC
contract. Its private DPL0 interrupt gates do not reuse the single-CPU service
runtime's global saved context or trap stack.

Targeted INIT is followed by at least 10 milliseconds and a SIPI carrying the
reserved page vector. After at least 200 microseconds, a second SIPI is allowed
only if readiness has not arrived. ICR delivery completion is checked before
and after each command; it is not AP readiness. BSP waits use checked actual HPET
differences, a two-second bound and a finite poll limit. Clock regression,
overflow, stall, an unexpected AP fault or an invalid interrupt source fails
instead of manufacturing progress.

## Original-kernel scenarios

| Case | Required execution |
| --- | --- |
| `rendezvous` | The admitted AP enters the original kernel with private CPU tables/stacks and the common root. BSP and AP each perform 4096 atomic additions to the same counter, producing exactly 8192. AP heartbeats advance during a BSP heartbeat interval of at least 20 milliseconds. Three generation-bound vector-64 IPIs interrupt actual AP kernel execution, acknowledge their LAPIC source and return to continued AP progress. A vector-65 stop acknowledges generation 4 and parks permanently. |
| `missing_ap` | The BSP sends targeted INIT and deliberately omits every SIPI. A bounded readiness timeout is the expected rejection. It produces no invented AP CPU facts, work, IPI acknowledgment or successful two-CPU completion. |

Every accepted IPI requires the actual AP ID/root, owned stack/frame, kernel CS
8, interrupted IF=1, and the exact generation. The LAPIC in-service word must
contain only the owned vector bit before EOI and be zero after EOI. The BSP reads
the published raw RIP/CS/RFLAGS/RSP/frame/root only after acquiring the matching
acknowledgment. Heartbeat progress after each ordinary IPI demonstrates return
to AP work; issuing an ICR command alone does not.

The terminal stop publishes all observed interrupt fields before its final
Release acknowledgment. Assembly then executes CLI/HLT without a Rust epilogue,
IRET or later AP RAM writes. The BSP acquires generation 4 and observes a stable
AP heartbeat over at least 20 milliseconds. All RAM remains retained, including
the acknowledgment cache line, trampoline, CPU tables and both AP stacks. This
terminal protocol supplies no authority to reclaim or reuse them and does not
acknowledge DMA or device quiescence.

## Acceptance and reproduction

Clean acceptance remains pending. Require a committed clean source snapshot,
pinned compiler/emulator/firmware, independent matching builds of both cases,
all 26 parser host tests and fresh original-kernel captures of both scenarios.
The independent verifier must bind the source/toolchain/descriptor/trampoline/heartbeat loop,
replay raw topology, CPU ranges, clock bounds, work, interrupt generations and
terminal ordering, and reject capture-only results or marker-shaped substitutes.
Also require passing earlier K01, memory-isolation matrix/slice, resumable service,
timer and benchmark regressions. Preserve their original single-CPU claims.

With the existing pinned toolchain installed, use fresh output directories:

```sh
python3 tools/check_k03_smp_host.py --out build/k03-smp/host
python3 tools/build_k03_smp.py --out build/k03-smp/a
python3 tools/build_k03_smp.py --out build/k03-smp/b
python3 tools/run_k03_smp.py --manifest build/k03-smp/a/manifest.json --case rendezvous --out build/k03-smp/rendezvous --allow-qemu
python3 tools/run_k03_smp.py --manifest build/k03-smp/a/manifest.json --case missing_ap --out build/k03-smp/missing_ap --allow-qemu
python3 tools/verify_k03_smp.py --first build/k03-smp/a/manifest.json --second build/k03-smp/b/manifest.json --host-result build/k03-smp/host/result.json --result build/k03-smp/rendezvous/result.json --result build/k03-smp/missing_ap/result.json --out build/k03-smp/verification.json
```

Successful public evidence retains portable original logs, receipts, notices and
hash bindings. Full retained media and source closure have a separate artifact
boundary. Raw failed host diagnostics remain private. Offline consistency checking
does not independently authenticate who executed a capture; full verification
also needs the reviewed source and admitted current-host toolchain.

## Remaining K03 and performance gates

This experiment does not run isolated CPL3 tasks on both cores, integrate SMP
scheduler leases or shared budgets, supply per-CPU timers/general idle-wakeup,
or establish contended accounting, TLB shootdown, reusable cross-core quiescence,
NUMA/hotplug, physical platform support or GPU/DMA isolation. K03's broader
acceptance remains open. Its next integration needs protected per-CPU contexts
and interrupt ownership before concurrent service mutation or task admission.

The simple single-CPU policy and correctness profiles remain references under
the [inference performance contract](inference-performance.md). A preregistered
native same-hardware comparison with qualified clocks and complete-path costs,
including startup, synchronization, interrupt and accounting work, is an explicit
pending gate. Two virtual CPUs, atomic totals and heartbeat intervals establish
neither physical parallel speedup nor latency, throughput or inference gains.

## Primary architecture references

- [UEFI 2.11 configuration tables](https://uefi.org/specs/UEFI/2.11/04_EFI_System_Table.html#efi-configuration-table-properties-table)
  supplies the ACPI entry/address contract before firmware services end.
- [ACPI 6.6, chapter 5](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html)
  defines RSDP/XSDT/SDT validation and MADT processor records.
- [Intel SDM volume 3A](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf),
  section 10.4.4.1 and Table 10-1, supplies the targeted INIT/SIPI startup contract;
  its APIC and interrupt chapters define ICR, ISR and EOI behavior.

These are architecture sources, separate from source-bound execution evidence.
