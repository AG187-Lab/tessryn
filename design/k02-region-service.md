# Single-CPU region service and resumable tasks

Status: bounded single-CPU emulated execution accepted on October 15, 2026.
The [original execution packet](../evidence/k02-region-service/README.md) binds
clean implementation `bf9c82528f83e25814334c696a02aff86120fa21` and source
snapshot `3bf0016316e5aafac1527eb854de169a3370a956f17cda2ccab5be222dadf592`.
This acceptance covers the declared two image programs and CPU profile. [K02 issue #5](https://github.com/AG187-Lab/tessryn/issues/5)
remains open. [ADR 0018](decisions/0018-resumable-region-service.md) records this
bounded integration decision.

The [ten-case matrix](k02-native-matrix.md) runs known probes and kernel-selected
request recipes. This step adds a reusable region dispatcher and two separately
bound CPL3 programs that construct requests, consume replies and continue from
saved instruction pointers. Initial capabilities and task admission remain
kernel controlled. It supplies the execution-context boundary needed before
native integration of the [K03 policy](k03-preparation.md).

## Admitted execution

Use the existing pinned original x86-64 UEFI kernel and QEMU/OVMF profile, one
boot CPU, masked interrupts, four-level paging and fixed task/mapping capacities.
Each program has its own protected task record, root, read-only executable code,
writable NX stack and request page. The kernel keeps its image, policy, saved
contexts and page tables supervisor-only. Data mappings are NX and retain exact
page authority; a byte capability cannot be rounded outward into a page map.

Scheduling is cooperative. An ordinary request resumes its submitting task;
yield returns control to the kernel, which can select the peer. Exit is terminal.
Only the exact declared B read-only-write or revoked-read page fault permits the
fixture to stop B and continue A; any other fault fails the experiment. A stopped
task cannot resume and is not proof of released memory: mapping and capability
lifetimes end separately.
There is no timer or guarantee that a program which never traps yields the CPU.

A starts with a kernel-provisioned owner capability. After A delegates, trusted
bootstrap code delivers that delegated capability in B's initial registers. This
does not implement an IPC service. A retires its writable mapping lease before
remapping read-only and sharing. The protected backend capability journal grants
service access only to adopted or service-created capabilities; knowing the
correct domain/slot/generation for a private baseline stack or request capability
does not grant service authority, even within its own domain.

## Request and reply boundary

The experimental request is exactly 96 little-endian bytes. It is separate from
the existing native ABI and does not create a production compatibility promise.

| Offset | Field | Required interpretation |
| --- | --- | --- |
| 0 | 8-byte magic | `TESSRGN1` |
| 8 | `u16` version | 1 |
| 10 | `u16` size | 96 |
| 12 | `u32` flags | 0 |
| 16 | `u64` request ID | Nonzero, strictly increasing per caller; never authority |
| 24 | `u32` operation | Declared operation only |
| 28 | `u32` reserved | 0 |
| 32 | capability | Slot, generation and domain in the declared 16-byte representation |
| 48 | `u64` argument | Delegation target domain or unmap token; never the submitting identity |
| 56 | `u64` offset | Checked exact byte offset |
| 64 | `u64` length | Checked exact byte length |
| 72 | `u64` virtual address | Validated user mapping target |
| 80 | `u64` rights | Only the operation's permitted rights |
| 88 | `u64` reserved | 0 |

Operations are `1 allocate`, `2 map`, `3 delegate_readonly`, `4 revoke`,
`5 unmap`, `6 release`, `7 accounting`, `8 yield` and `9 exit`. Every operation
rejects unsupported fields or authority. Allocation obeys the caller's admitted
domain quota and returns one erased page; it does not expose physical allocator
administration. Map accepts READ+MAP or READ+WRITE+MAP, while delegation retains
only READ+MAP and exact parent bounds. No request
constructs an internal lease, installs executable data, acknowledges quiescence
or completes a trusted backend operation.

Replies use registers: RAX carries status, RDX the operation's packed capability
or mapping token, RCX a returned capability domain, and R8/R9/R10 charged,
committed and reserved pages when defined. Unused outputs are zero. Returned
mapping tokens pack a nonwrapping generation in the high 32 bits and slot-plus-one
in the low 32 bits. They are generation-checked service identities, distinct from
trusted internal leases. Other saved general registers and admitted FP state
survive an ordinary reply.

Request ID gaps are allowed. Every fresh ID in a completely copied 96-byte
descriptor is consumed, even if header, operation or operand validation rejects
it. Zero, repeated or decreasing IDs return InvalidDescriptor without repeating
the operation. Pointer/length rejection before copying can leave a gap; request
IDs do not authenticate the caller or replace capability generation checks.

| Status | Meaning | Status | Meaning | Status | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0 | Ok | 1 | InvalidDescriptor | 2 | UnsupportedVersion |
| 3 | UnsupportedOperation | 4 | InvalidAuthority | 5 | StaleHandle |
| 6 | Revoked | 7 | Bounds | 8 | Alignment |
| 9 | InsufficientRights | 10 | Capacity | 11 | Budget |
| 12 | Busy | 13 | Overflow | 14 | BackendRejected |

The protected active task supplies caller identity. The trap must match its
current root, CPL3 selectors, user stack and bound executable range, and lie
within the kernel's dedicated trap stack. Submitted domain or handle fields
cannot replace that context. Check pointer arithmetic, exact descriptor length,
canonical user range and complete single-page containment before reading bytes.
An unmapped, supervisor, overflowed or cross-page buffer returns a bounded
descriptor error without a kernel page fault or partial service mutation.

The kernel translates the admitted user buffer through that task's page tables,
checks the resulting backing against retained ownership and copies once into
initialized kernel storage. It never dereferences an unchecked user VA or treats
an input integer as a physical address. Only the stopped task could have written
its buffer, and no second CPU or device accesses it in this profile. These facts
are the copy's concurrency assumption, not a future SMP/DMA solution.

## Trap, resume and CPU state

First entry initializes task registers and legacy FP data, retaining only the
declared startup inputs. Each later trap saves all 15 general registers, RIP,
RSP, RFLAGS and the admitted legacy FP image into protected task-owned storage.
The assembly wrapper captures FP before Rust, diagnostics or dispatch can change
it. Kernel state is restored before the outer kernel loop uses it. Kernel Rust
references must not alias a task, root or policy while a trap path accesses the
same storage; mutable borrows end before entering user execution.

On resumption the kernel validates the protected saved context, applies only the
defined reply-register changes and restores that task's own state. RFLAGS cannot
grant I/O privilege, enable interrupts or enter unsupported task/debug modes.
An ordinary service error resumes the task with a status; a declared expected B
protection fault is a distinct terminal observation. Any undeclared exception or
invalid supervisor frame fails the experiment, rather than becoming a descriptor
error or a claim of general fault recovery.

The following are admission requirements, not claims of completed qualification:

| State or mechanism | Boundary for this profile |
| --- | --- |
| x87/MMX/SSE and MXCSR | Save/restore the admitted 512-byte FXSAVE image; initialize capture holes and validate supported MXCSR bits. Verify actual task and kernel state after transitions. |
| AVX, AVX-512, AMX and other XSAVE state | OSXSAVE is disabled; extended state is not admitted or claimed preserved. |
| FS/GS bases, LDT and TLS | No TLS or LDT service. FSGSBASE is disabled; FS/GS/KERNEL_GS bases and LDTR are zero. Entry nulls FS/GS selectors; the admitted image programs do not mutate segment state. Selector values alone do not prove base values. |
| Debug registers and tracing | No task debugger, breakpoints, watchpoints, tracing or PMU API. DR7 enables and GD are inactive; PCE is disabled. TF/RF are forbidden in resumed flags. General debug/trace context preservation is unsupported. |
| Protection keys | PKE/PKS are disabled; PKRU/PKRS switching is unsupported. |
| CET, SGX and additional stateful extensions | Excluded by the declared CPU feature/control profile; no shadow-stack or enclave context is supported. |
| Alternate privileged entry | INT80 is the declared gate. EFER.SCE and SYSENTER_CS are zero; unconfigured SYSCALL/SYSENTER entry must not be inherited as a second user entry path. |
| Paging lifetime | PCID, global translations and LA57 are excluded; use actual CR3 reloads for the single-CPU invalidation contract. |
| IRQs, SMP and devices | No timer preemption, AP execution, DMA or device completion; none can supply implicit quiescence. |

These exclusions must be enforced and reported by the runtime, rather than
inferred from the two programs avoiding an instruction. This experiment does not
qualify arbitrary executable loading, all architectural state or side-channel
isolation. Intel's [FSGSBASE guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/guidance-enabling-fsgsbase.html)
explains why base values require separate context management. The
[Intel architecture manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
are the primary reference for privilege frames, FXSAVE/FXRSTOR, control registers,
debug state and paging invalidation. Source interpretation and this profile's
exclusions are project decisions; primary references do not establish execution.

## Ownership and teardown

The dispatcher uses the existing owned-memory policy as its correctness
reference. Protected mapping records bind domain, root, VA, backing and live
lease. Ordinary descriptor/authority rejection paths preserve ownership policy,
PTEs and accounting; per-domain request/rejection counters still record the call.
Mapping installation must either publish both the PTE and its protected record,
or roll back its acquired lease before returning an error.

The pure service and its trusted backend distinguish a rejected operation from
failed rollback or teardown. An unrecoverable backend failure permanently blocks
the service, retains outstanding ownership and prevents all task resumption.
It cannot be converted into an ordinary status followed by continued execution.

Read-only delegation cannot increase rights or change the parent's charge owner.
Owner revocation denies new descendant use and retires every retained affected
mapping before its backing can be released. Trusted teardown orders fencing,
PTE removal, real CR3 invalidation and quiescence. User statuses and supplied
tokens never acknowledge those steps. The service owns its mapping registry;
the protected backend journal owns capability cleanup. A stopped domain's
capability can remain Busy while a live peer retains a lease on the same region.
It stays journaled and charged until that peer unmaps and release actually
succeeds. Each domain's two baseline stack/request pages remain retained until
global cleanup. Erasure precedes exposing released backing to a new owner.

## Acceptance evidence

Three separately captured case images passed the independent raw-trace verifier:
`sharing` submitted 14 requests through 15 actual CPL3 traps, `revocation` 14
through 15, and `authority` 38 through 38. Each observed four context switches,
continued user execution after replies and final zero leaves, mappings,
allocations and charged/committed/reserved pages. Both complete service builds
matched all ten artifacts, with 22 compiler dependencies, 27 reviewed runtime
files and 49 retained inputs per twin. The original host receipt binds 21 policy
tests. All 658 Python tests, 97 original memory/mapper/adapter/digest host tests,
ten matrix boots, four earlier slice boots, seven K01 boots and the 13-case,
208-sample guest benchmark regression passed on the same clean implementation.
Host tests remain separate from CPU enforcement; raw benchmark ticks do not
establish frequency, hardware latency or performance gains.

[The verification report](../evidence/k02-region-service/verification.json)
has SHA-256 `ac0a72dcb4ebdf4fed6e566180e23855795a7edaeaa7276af3ab5d4cedfdcbf9`.
The public packet retains byte-preserved successful text records and notices,
source-bound regression reports and a complete text hash index. Executables,
media, firmware and source snapshots stay in the complete ignored local/CI
packets. Offline records do not independently authenticate capture. The packet
README gives complete reproduction commands and historical checkout/toolchain
requirements, and separately records the failed sandbox launcher and approved
fresh retry without publishing failed raw host diagnostics.

The admitted cases establish these bounded observations:

| Case | Required original-kernel observations |
| --- | --- |
| `sharing` | Both programs make and consume multiple requests. A retires its writable lease, remaps read-only and grants read-only access. B's actual read succeeds and its exact declared write faults without changing the complete backing payload. A remains able to finish. |
| `revocation` | B first exercises a valid mapping, then yields. A revokes it; trusted teardown retires the old translation. B's stale access faults, and release/reuse cannot precede proven quiescence. |
| `authority` | User-built forged/stale handles, private baseline capabilities, stale/cross-domain mapping IDs and invalid lengths/pointers, including cross-page and overflow cases, return errors with unchanged mappings and charges. The program continues after those errors and actually verifies an erased page after reuse. |

At least one observed A-to-B-to-A sequence must preserve distinct nonzero GPR,
x87 and XMM patterns, while first-entry evidence shows reset state. Task status
logs alone do not prove this: retained code bindings, actual raw privilege/fault
frames, user continuation/results and backing/accounting observations must agree.
A task stopped by a declared expected fault must never re-enter. Pending Busy
capabilities stay charged until the live peer retires its leases; service cleanup
returns to the two-pages-per-domain baseline, then global cleanup reaches zero
retained allocation, committed and reserved charges.

Release requires clean committed source, exact retained dependencies and pinned
tools, twin artifacts, bounded fresh guest captures, an independent verifier and
the original K01, four-probe and ten-case regressions. Host policy tests challenge
codec, bounds, identity, failure atomicity and teardown ordering; synthetic traces
validate rejection behavior and cannot replace guest execution. Public evidence
must contain required notices and complete hash coverage without credentials,
workspace paths or raw failed host diagnostics.

Tooling is available as `tools/build_k02_region_service.py`,
`tools/run_k02_region_service.py` and `tools/verify_k02_region_service.py` with
the `sharing`, `revocation` and `authority` cases. After building both twins,
running `tools/check_k02_region_host.py --out build/k02-region-service/host`
and capturing the three cases, full verification also requires the host receipt:

```sh
python3 tools/verify_k02_region_service.py \
  --first build/k02-region-service/a/manifest.json \
  --second build/k02-region-service/b/manifest.json \
  --host-result build/k02-region-service/host/result.json \
  --result build/k02-region-service/sharing/result.json \
  --result build/k02-region-service/revocation/result.json \
  --result build/k02-region-service/authority/result.json \
  --out build/k02-region-service/verification.json
```

The host receipt binds the original policy test inputs, pinned compiler and
retained test/build logs; it cannot substitute for any guest capture. Use the
[packet reproduction commands](../evidence/k02-region-service/README.md#reproduce-the-executed-source)
in a fresh checkout/output tree to reproduce the executed source. The text
packet alone omits binary artifacts needed for complete artifact verification.

This is correctness preparation under the
[inference performance contract](inference-performance.md). The conservative
ownership/CR3/scrub path remains the reference. Qualified clocks, hardware
measurements, SMP, arbitrary service loading, device/DMA isolation, GPU execution
and inference performance retain their separate gates.
