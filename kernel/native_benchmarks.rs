//! Opt-in original-kernel observations on one QEMU boot CPU. No native ns,
//! context-switch, DMA, GPU, or inference-performance qualification is claimed.
use crate::{
    benchmark_clock::{Clock, checked_delta},
    diagnostics::{finish, print},
    uefi::Handoff,
};
use core::{hint::black_box, mem::size_of, ptr};
use tessryn_owned_memory::{Error as MemoryError, FrameRange, MemoryPolicy, PAGE_SIZE, Rights};
use tessryn_scheduler::{Scheduler, StopOutcome, TaskSpec, TaskState};

const SAMPLES: usize = 16;
const WARMUP: usize = 4;
const ITERATIONS: u64 = 128;
const SEED: u64 = 1;
const CASES: usize = 13;
const FRAME_BASE: u64 = 0x10_0000;
type Policy = MemoryPolicy<2, 8, 16, 16, 32>;
type Schedule = Scheduler<2, 32, 1>;

#[derive(Clone, Copy)]
struct Record {
    start: u64,
    end: u64,
    ticks: u64,
    checksum: u64,
}
const EMPTY: Record = Record {
    start: 0,
    end: 0,
    ticks: 0,
    checksum: 0,
};
static mut RECORDS: [[Record; SAMPLES]; CASES] = [[EMPTY; SAMPLES]; CASES];

#[repr(C, align(4096))]
struct SourcePage([u8; 4096]);
const fn source_bytes() -> [u8; 4096] {
    let mut bytes = [0; 4096];
    let mut index = 0;
    while index < 4096 {
        bytes[index] = ((index as u64 + SEED) % 251) as u8;
        index += 1;
    }
    bytes
}
static COPY_SOURCE: SourcePage = SourcePage(source_bytes());

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    implementation: &'static str,
    batch: u64,
    bytes: u64,
    ops: u64,
    single: bool,
}
const PROFILE: [Case; CASES] = [
    Case {
        name: "counter_pair",
        implementation: "native_serialized_tsc_probe",
        batch: 1,
        bytes: 0,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "empty_loop",
        implementation: "native_loop_reference",
        batch: 1,
        bytes: 0,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "queue_roundtrip_batch_1",
        implementation: "bounded_ring_fixture",
        batch: 1,
        bytes: 0,
        ops: 2 * ITERATIONS,
        single: false,
    },
    Case {
        name: "queue_roundtrip_batch_8",
        implementation: "bounded_ring_fixture",
        batch: 8,
        bytes: 0,
        ops: 16 * ITERATIONS,
        single: false,
    },
    Case {
        name: "queue_roundtrip_batch_64",
        implementation: "bounded_ring_fixture",
        batch: 64,
        bytes: 0,
        ops: 128 * ITERATIONS,
        single: false,
    },
    Case {
        name: "queue_full_rejection",
        implementation: "bounded_ring_fixture",
        batch: 1,
        bytes: 0,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "queue_empty_rejection",
        implementation: "bounded_ring_fixture",
        batch: 1,
        bytes: 0,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "memory_allocate_revoke_release",
        implementation: "tessryn_memory_policy_metadata",
        batch: 1,
        bytes: 0,
        ops: 3 * ITERATIONS,
        single: false,
    },
    Case {
        name: "memory_access_check",
        implementation: "tessryn_memory_policy_metadata",
        batch: 1,
        bytes: 0,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "native_zero_4096",
        implementation: "native_owned_volatile_page",
        batch: 1,
        bytes: 4096,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "native_copy_4096",
        implementation: "native_owned_volatile_page",
        batch: 1,
        bytes: 4096,
        ops: ITERATIONS,
        single: false,
    },
    Case {
        name: "scheduler_policy_dispatch_stop_cycle",
        implementation: "tessryn_scheduler_policy",
        batch: 1,
        bytes: 0,
        ops: 2 * ITERATIONS,
        single: false,
    },
    Case {
        name: "scheduler_policy_dispatch_latency",
        implementation: "tessryn_scheduler_policy",
        batch: 1,
        bytes: 0,
        ops: 1,
        single: true,
    },
];

fn reject(reason: &'static str) -> ! {
    print(format_args!(
        "TESSRYN_NBENCH_FAIL {{\"reason\":\"{reason}\"}}\n"
    ));
    finish(false)
}
fn ensure(value: bool, reason: &'static str) {
    if !value {
        reject(reason);
    }
}
fn read(clock: &mut Clock) -> u64 {
    clock
        .read()
        .unwrap_or_else(|_| reject("counter-regression"))
}
fn measure(clock: &mut Clock, action: impl FnOnce() -> u64) -> Record {
    let start = read(clock);
    let checksum = action();
    let end = read(clock);
    Record {
        start,
        end,
        ticks: checked_delta(start, end).unwrap_or_else(|_| reject("counter-regression")),
        checksum: black_box(checksum),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Ring {
    values: [u64; 256],
    head: usize,
    length: usize,
}
impl Ring {
    fn new() -> Self {
        Self {
            values: [0; 256],
            head: 0,
            length: 0,
        }
    }
    fn push(&mut self, value: u64) -> Result<(), u64> {
        if self.length == 256 {
            return Err(value);
        }
        self.values[(self.head + self.length) % 256] = value;
        self.length += 1;
        Ok(())
    }
    fn pop(&mut self) -> Option<u64> {
        if self.length == 0 {
            return None;
        }
        let value = self.values[self.head];
        self.head = (self.head + 1) % 256;
        self.length -= 1;
        Some(value)
    }
}

fn policy() -> Policy {
    let mut state = Policy::new(36, &[]).unwrap();
    state
        .add_free_extent(FrameRange::new(FRAME_BASE, 64).unwrap())
        .unwrap();
    state.create_domain(1, 64).unwrap();
    state.create_domain(2, 64).unwrap();
    state
}
fn scheduler() -> Schedule {
    let mut state = Schedule::new().unwrap();
    for domain in [1, 2] {
        state.add_domain(domain, 320).unwrap();
    }
    for task in 0..32 {
        state
            .create_task(
                1 + task % 2,
                TaskSpec {
                    budget_ns: 320,
                    deadline_ns: 0,
                },
                0,
            )
            .unwrap();
    }
    state
}

fn self_checks() {
    let mut ring = Ring::new();
    ensure(ring.pop().is_none(), "ring-empty");
    for value in 0..256 {
        ensure(ring.push(value).is_ok(), "ring-fill");
    }
    let before = ring;
    ensure(
        ring.push(999).is_err() && ring == before,
        "ring-full-mutation",
    );
    for value in 0..256 {
        ensure(ring.pop() == Some(value), "ring-fifo");
    }
    for value in 0..1024 {
        ensure(
            ring.push(value).is_ok() && ring.pop() == Some(value),
            "ring-wrap",
        );
    }
    ensure(ring.length == 0, "ring-drain");
    let mut state = policy();
    let handle = state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap();
    ensure(
        state.authorize(2, handle, Rights::READ, 0, 1) == Err(MemoryError::InvalidAuthority),
        "foreign-authority",
    );
    ensure(
        state.authorize(1, handle, Rights::READ, PAGE_SIZE, 1) == Err(MemoryError::Bounds),
        "authority-bounds",
    );
    state.revoke(1, handle).unwrap();
    ensure(
        state.authorize(1, handle, Rights::READ, 0, 1) == Err(MemoryError::Revoked),
        "revoked-authority",
    );
    state.release_capability(1, handle).unwrap();
    ensure(
        state.accounting(1).unwrap().charged_pages == 0 && state.frames().allocated_pages() == 0,
        "memory-drain",
    );
    let mut schedule = scheduler();
    let dispatch = schedule.dispatch(0, 1, 0).unwrap();
    ensure(
        schedule.accounting(1).unwrap().budget.reserved_ns == 1,
        "scheduler-reservation",
    );
    ensure(
        schedule.dispatch(0, 1, 0) == Err(tessryn_scheduler::Error::CpuBusy),
        "scheduler-busy",
    );
    ensure(
        schedule
            .stop(dispatch.lease, 1, StopOutcome::Yield)
            .unwrap()
            == TaskState::Runnable,
        "scheduler-stop",
    );
    ensure(
        schedule.stop(dispatch.lease, 1, StopOutcome::Yield)
            == Err(tessryn_scheduler::Error::StaleLease),
        "scheduler-stale",
    );
    ensure(
        schedule.cpu_lease(0).unwrap().is_none()
            && schedule.accounting(1).unwrap().budget.reserved_ns == 0,
        "scheduler-release",
    );
}

fn disjoint(start: u64, end: u64, range: crate::uefi::Range) -> bool {
    end <= range.start || start >= range.end
}
fn descriptor_covers(handoff: &Handoff, start: u64, end: u64, loader: bool) -> bool {
    (0..handoff.descriptors()).any(|index| {
        let descriptor = handoff.descriptor(index);
        let accepted = if loader {
            matches!(descriptor.kind, 1 | 2)
        } else {
            descriptor.kind == 7
        };
        accepted
            && descriptor.attributes & crate::uefi::RUNTIME == 0
            && descriptor.start <= start
            && descriptor
                .pages
                .checked_mul(PAGE_SIZE)
                .and_then(|bytes| descriptor.start.checked_add(bytes))
                .is_some_and(|last| end <= last)
    })
}
fn owned_buffers(handoff: &Handoff) -> (*mut u8, *const u8) {
    let start = handoff.scratch;
    let end = start
        .checked_add(4096)
        .unwrap_or_else(|| reject("scratch-overflow"));
    ensure(
        start % 4096 == 0 && descriptor_covers(handoff, start, end, false),
        "scratch-ownership",
    );
    for range in [handoff.image, handoff.stack, handoff.map_allocation] {
        ensure(disjoint(start, end, range), "scratch-live-alias");
    }
    if let Some(range) = handoff.framebuffer {
        ensure(disjoint(start, end, range), "scratch-framebuffer-alias");
    }
    if let Some(range) = handoff.high_scratch {
        ensure(disjoint(start, end, range), "scratch-high-alias");
    }
    let source = ptr::addr_of!(COPY_SOURCE).cast::<u8>();
    let source_start = source as u64;
    let source_end = source_start
        .checked_add(size_of::<SourcePage>() as u64)
        .unwrap_or_else(|| reject("source-overflow"));
    ensure(
        source_start % 4096 == 0
            && source_start >= handoff.image.start
            && source_end <= handoff.image.end
            && descriptor_covers(handoff, source_start, source_end, true),
        "source-ownership",
    );
    ensure(
        end <= source_start || start >= source_end,
        "byte-buffer-alias",
    );
    (start as *mut u8, source)
}

fn queue(clock: &mut Clock, batch: u64) -> Record {
    let mut ring = Ring::new();
    let result = measure(clock, || {
        let mut checksum = SEED;
        for iteration in 0..ITERATIONS {
            for offset in 0..batch {
                black_box(&mut ring)
                    .push(black_box(SEED + iteration * batch + offset))
                    .unwrap();
            }
            for _ in 0..batch {
                checksum = checksum.wrapping_add(black_box(&mut ring).pop().unwrap());
            }
        }
        checksum
    });
    ensure(ring.length == 0, "queue-not-drained");
    result
}
fn rejected_queue(clock: &mut Clock, full: bool) -> Record {
    let mut ring = Ring::new();
    if full {
        for value in 0..256 {
            ring.push(value).unwrap();
        }
    }
    let result = measure(clock, || {
        let mut checksum = SEED;
        for iteration in 0..ITERATIONS {
            let rejected = if full {
                black_box(&mut ring).push(black_box(iteration)).is_err()
            } else {
                black_box(&mut ring).pop().is_none()
            };
            checksum += u64::from(black_box(rejected));
        }
        checksum
    });
    ensure(
        result.checksum == SEED + ITERATIONS && ring.length == if full { 256 } else { 0 },
        "queue-rejection",
    );
    if full {
        for value in 0..256 {
            ensure(ring.pop() == Some(value), "queue-full-content");
        }
    }
    result
}
fn memory(clock: &mut Clock, allocate: bool) -> Record {
    let mut state = policy();
    if allocate {
        let result = measure(clock, || {
            let mut checksum = SEED;
            for _ in 0..ITERATIONS {
                // Numerical metadata only: no memory at FRAME_BASE is accessed.
                let handle = black_box(&mut state)
                    .allocate(
                        black_box(1),
                        black_box(1),
                        0,
                        black_box(Rights::ALL),
                        |range| {
                            black_box(range);
                            Ok(())
                        },
                    )
                    .unwrap();
                checksum += u64::from(black_box(handle.generation));
                black_box(&mut state)
                    .revoke(black_box(1), black_box(handle))
                    .unwrap();
                black_box(&mut state)
                    .release_capability(black_box(1), black_box(handle))
                    .unwrap();
            }
            checksum
        });
        ensure(
            state.accounting(1).unwrap().charged_pages == 0
                && state.frames().available_pages() == 64
                && state.frames().allocated_pages() == 0,
            "memory-not-drained",
        );
        result
    } else {
        let handle = state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap();
        let result = measure(clock, || {
            let mut checksum = SEED;
            for iteration in 0..ITERATIONS {
                let view = black_box(&state)
                    .authorize(
                        black_box(1),
                        black_box(handle),
                        black_box(Rights::READ),
                        black_box(iteration % PAGE_SIZE),
                        black_box(1),
                    )
                    .unwrap();
                checksum += black_box(view.physical_start);
            }
            checksum
        });
        state.revoke(1, handle).unwrap();
        state.release_capability(1, handle).unwrap();
        ensure(
            state.accounting(1).unwrap().charged_pages == 0,
            "access-not-drained",
        );
        result
    }
}
fn bytes(clock: &mut Clock, destination: *mut u8, source: *const u8, copy: bool) -> Record {
    // Buffers were checked against the final firmware handoff. Only this boot
    // CPU runs, IRQs remain masked, and the source is immutable image memory.
    unsafe {
        for offset in 0..4096 {
            destination.add(offset).write_volatile(0xa5);
        }
    }
    let result = measure(clock, || {
        let mut checksum = SEED;
        for iteration in 0..ITERATIONS {
            unsafe {
                for offset in 0..4096 {
                    let value = if copy {
                        source.add(offset).read_volatile()
                    } else {
                        0
                    };
                    destination.add(offset).write_volatile(value);
                }
                checksum += u64::from(destination.add(iteration as usize % 4096).read_volatile());
            }
        }
        checksum
    });
    unsafe {
        for offset in 0..4096 {
            let expected = if copy {
                source.add(offset).read_volatile()
            } else {
                0
            };
            ensure(
                destination.add(offset).read_volatile() == expected,
                "volatile-page-content",
            );
        }
    }
    result
}
fn schedule(clock: &mut Clock, single: bool) -> Record {
    let mut state = scheduler();
    if single {
        let start = read(clock);
        let dispatch = black_box(&mut state)
            .dispatch(black_box(0), black_box(1), black_box(0))
            .unwrap();
        let end = read(clock);
        let checksum = SEED + u64::from(black_box(dispatch.task.slot()));
        state.stop(dispatch.lease, 1, StopOutcome::Yield).unwrap();
        ensure(
            state.cpu_lease(0).unwrap().is_none(),
            "single-dispatch-release",
        );
        Record {
            start,
            end,
            ticks: checked_delta(start, end).unwrap_or_else(|_| reject("counter-regression")),
            checksum,
        }
    } else {
        let result = measure(clock, || {
            let mut checksum = SEED;
            for iteration in 0..ITERATIONS {
                let dispatch = black_box(&mut state)
                    .dispatch(black_box(0), black_box(1), black_box(iteration))
                    .unwrap();
                checksum += u64::from(black_box(dispatch.task.slot()));
                black_box(&mut state)
                    .stop(
                        black_box(dispatch.lease),
                        black_box(iteration + 1),
                        black_box(StopOutcome::Yield),
                    )
                    .unwrap();
            }
            checksum
        });
        let a = state.accounting(1).unwrap();
        let b = state.accounting(2).unwrap();
        ensure(
            state.cpu_lease(0).unwrap().is_none()
                && a.budget.reserved_ns + b.budget.reserved_ns == 0
                && a.budget.consumed_ns + b.budget.consumed_ns == u128::from(ITERATIONS)
                && !a.halted
                && !b.halted,
            "dispatch-cycle-accounting",
        );
        result
    }
}
fn execute(case: usize, clock: &mut Clock, destination: *mut u8, source: *const u8) -> Record {
    match case {
        0 => {
            let start = read(clock);
            let mut checksum = SEED;
            for iteration in 0..ITERATIONS {
                let a = read(clock);
                let b = read(clock);
                black_box(checked_delta(a, b).unwrap_or_else(|_| reject("counter-regression")));
                checksum += black_box(iteration);
            }
            let end = read(clock);
            Record {
                start,
                end,
                ticks: checked_delta(start, end).unwrap_or_else(|_| reject("counter-regression")),
                checksum,
            }
        }
        1 => measure(clock, || {
            let mut checksum = SEED;
            for iteration in 0..ITERATIONS {
                checksum += black_box(iteration);
            }
            checksum
        }),
        2 => queue(clock, 1),
        3 => queue(clock, 8),
        4 => queue(clock, 64),
        5 => rejected_queue(clock, true),
        6 => rejected_queue(clock, false),
        7 => memory(clock, true),
        8 => memory(clock, false),
        9 => bytes(clock, destination, source, false),
        10 => bytes(clock, destination, source, true),
        11 => schedule(clock, false),
        12 => schedule(clock, true),
        _ => reject("unknown-case"),
    }
}

pub fn run(handoff: &Handoff) -> ! {
    let mut clock = Clock::probe().unwrap_or_else(|_| reject("tsc-unavailable"));
    ensure(clock.facts.interrupts_masked, "interrupts-not-masked");
    let (destination, source) = owned_buffers(handoff);
    self_checks();
    // The opt-in build starts no APs. QEMU's evaluator separately binds -smp 1.
    // All samples, including warmup work, complete before any NBENCH serial row.
    let records = unsafe { &mut *ptr::addr_of_mut!(RECORDS) };
    for (case, rows) in records.iter_mut().enumerate() {
        for ordinal in 0..WARMUP + SAMPLES {
            let result = execute(case, &mut clock, destination, source);
            if ordinal >= WARMUP {
                rows[ordinal - WARMUP] = result;
            }
        }
    }
    let facts = clock.facts;
    print(format_args!(
        "TESSRYN_NBENCH_BEGIN {{\"schema_version\":1,\"kind\":\"native_kernel_benchmark\",\"scope\":\"original_kernel_single_cpu_qemu\",\"samples\":16,\"warmup\":4,\"iterations\":128,\"seed\":1,\"cases\":13}}\n"
    ));
    print(format_args!(
        "TESSRYN_NBENCH_CLOCK {{\"counter\":\"tsc\",\"unit\":\"tsc_ticks\",\"serialization\":\"cpuid_rdtsc_cpuid\",\"tsc_supported\":{},\"invariant_tsc\":{},\"rdtscp_supported\":{},\"hypervisor_present\":{},\"interrupts_masked\":{},\"started_cpus\":1,\"frequency_hz\":null}}\n",
        facts.tsc_supported,
        facts.invariant_tsc,
        facts.rdtscp_supported,
        facts.hypervisor_present,
        facts.interrupts_masked
    ));
    for (case, rows) in records.iter().enumerate() {
        let spec = PROFILE[case];
        for (index, record) in rows.iter().enumerate() {
            print(format_args!(
                "TESSRYN_NBENCH_SAMPLE {{\"case\":\"{}\",\"implementation\":\"{}\",\"sample_unit\":\"{}\",\"sample_index\":{},\"start_ticks\":{},\"end_ticks\":{},\"elapsed_ticks\":{},\"operations\":{},\"checksum\":{},\"batch_size\":{},\"bytes_per_operation\":{}}}\n",
                spec.name,
                spec.implementation,
                if spec.single {
                    "single_operation"
                } else {
                    "timed_batch"
                },
                index,
                record.start,
                record.end,
                record.ticks,
                spec.ops,
                record.checksum,
                spec.batch,
                spec.bytes
            ));
        }
    }
    print(format_args!(
        "TESSRYN_NBENCH_CHECKS {{\"checks\":[\"ring_full_empty_wrap_fifo\",\"memory_rejects_foreign_bounds_revoked\",\"memory_lifecycle_drained\",\"native_volatile_zero_and_copy_exact\",\"benchmark_operations_exact\",\"scheduler_policy_reservations_stops_and_denials\",\"counter_deltas_no_regression\",\"owned_pages_from_final_handoff\"]}}\n"
    ));
    print(format_args!(
        "TESSRYN_NBENCH_END {{\"measured_samples\":208,\"warmup_discarded\":52}}\n"
    ));
    print(format_args!(
        "TESSRYN_NBENCH_PASS {{\"scope\":\"original_kernel_single_cpu_qemu\"}}\n"
    ));
    finish(true)
}
