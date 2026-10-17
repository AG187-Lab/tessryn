// Shared region backend and protected contexts are defined by region_runtime.
// This opt-in owner changes scheduling, never the user wire authority boundary.
use crate::preempt_policy::{Grant, HARD_QUANTUM_NS, Policy, SOFT_TARGET_NS};
use crate::preempt_timer::{self as timer, Arm, Cancellation, Capture, Sample};
use tessryn_scheduler::{StopOutcome, TaskState};

const MIN_SPIN_IRQS: u64 = 3;
const MAILBOX: u64 = 128;
const FULL_BUDGET: u64 = 2_000_000_000;
const SMALL_BUDGET: u64 = 80_000_000;
const DEADLINE_OFFSET: u64 = 100_000_000;
const fn case_id() -> u64 {
    if cfg!(k03_timer_case = "preemption") {
        0
    } else if cfg!(k03_timer_case = "budget") {
        1
    } else if cfg!(k03_timer_case = "deadline") {
        2
    } else if cfg!(k03_timer_case = "forged_irq") {
        3
    } else {
        u64::MAX
    }
}
fn case_name() -> &'static str {
    match case_id() {
        0 => "preemption",
        1 => "budget",
        2 => "deadline",
        3 => "forged_irq",
        _ => fail("timer-case"),
    }
}
#[repr(C)]
struct TimerContract {
    magic: [u8; 16],
    version: u64,
    case_id: u64,
    domains: [u64; 2],
    addresses: [u64; 4],
    request_size: u64,
    hard_quantum: u64,
    soft_target: u64,
    budgets: [u64; 2],
    deadline_offset: u64,
    mailbox: u64,
    min_spin_irqs: u64,
}
#[used]
#[unsafe(no_mangle)]
static K03_TIMER_CONTRACT: TimerContract = TimerContract {
    magic: *b"TESSRYN-TIMER1\0\0",
    version: 1,
    case_id: case_id(),
    domains: [1, 2],
    addresses: [CODE, STACK, REQUEST, DATA],
    request_size: 96,
    hard_quantum: HARD_QUANTUM_NS,
    soft_target: SOFT_TARGET_NS,
    budgets: [
        if case_id() == 1 {
            SMALL_BUDGET
        } else {
            FULL_BUDGET
        },
        FULL_BUDGET,
    ],
    deadline_offset: if case_id() == 2 { DEADLINE_OFFSET } else { 0 },
    mailbox: MAILBOX,
    min_spin_irqs: MIN_SPIN_IRQS,
};
const _: () = assert!(size_of::<TimerContract>() == 144);
unsafe extern "sysv64" {
    static timer_a_spin_start: u8;
    static timer_a_spin_end: u8;
    static timer_b_spin_start: u8;
    static timer_b_spin_end: u8;
    static timer_a_forged_irq: u8;
}
#[derive(Clone, Copy)]
enum HardwareStop {
    Irq(Capture),
    Cancel(Cancellation),
}
impl HardwareStop {
    fn sample(self) -> Sample {
        match self {
            Self::Irq(v) => v.sample,
            Self::Cancel(v) => v.sample,
        }
    }
    fn generation(self) -> u64 {
        match self {
            Self::Irq(v) => v.arm.generation,
            Self::Cancel(v) => v.generation,
        }
    }
}
#[derive(Clone, Copy)]
struct TimerTrap {
    hardware: HardwareStop,
    address: u64,
    root: u64,
    pending_probe: bool,
}
static mut TIMER_SOFT: u64 = 0;
static mut TIMER_PENDING_PROBED: bool = false;
static mut TIMER_TRAP: Option<TimerTrap> = None;
fn timer_capture_hardware(frame: &crate::cpu::ExceptionFrame, address: u64, root: u64) {
    // One declared negative fixture lets IRQ0 become pending during a syscall
    // with kernel IF0. Cancellation must drain it before another lease enters.
    let index = unsafe { ptr::addr_of!(ACTIVE).read() };
    let pending_probe = case_id() == 0
        && index == 0
        && frame.vector == 128
        && frame.registers[0] == 1
        && !unsafe { ptr::addr_of!(TIMER_PENDING_PROBED).read() };
    if pending_probe {
        let until = unsafe { ptr::addr_of!(TIMER_SOFT).read() }
            .checked_add(100_000_000)
            .unwrap_or_else(|| fail("timer-pending-overflow"));
        let mut observed = false;
        for _ in 0..1_000_000 {
            if checked(timer::pending_irq(), "timer-pending-status") & 1 != 0 {
                observed = true;
                break;
            }
            if checked(timer::clock(), "timer-pending-clock").ns >= until {
                break;
            }
        }
        if !observed {
            fail("timer-pending-stalled");
        }
        unsafe {
            ptr::addr_of_mut!(TIMER_PENDING_PROBED).write(true);
        }
    }
    let hardware = if frame.vector == timer::VECTOR {
        HardwareStop::Irq(checked(timer::capture_irq(), "timer-hardware-irq"))
    } else {
        HardwareStop::Cancel(checked(timer::cancel(), "timer-hardware-cancel"))
    };
    if pending_probe && !matches!(hardware, HardwareStop::Cancel(v) if v.pending_before == 1) {
        fail("timer-pending-not-observed");
    }
    unsafe {
        if ptr::addr_of!(TIMER_TRAP).read().is_some() {
            fail("timer-capture-overwrite");
        }
        ptr::addr_of_mut!(TIMER_TRAP).write(Some(TimerTrap {
            hardware,
            address,
            root,
            pending_probe,
        }));
    }
}
fn take_timer_trap() -> TimerTrap {
    unsafe {
        let value = ptr::addr_of!(TIMER_TRAP)
            .read()
            .unwrap_or_else(|| fail("timer-capture-absent"));
        ptr::addr_of_mut!(TIMER_TRAP).write(None);
        value
    }
}
fn wide(key: &str, value: u128) {
    print(format_args!(" {key}={value}"));
}
fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Runnable => "runnable",
        TaskState::Blocked => "blocked",
        TaskState::Running => "running",
        TaskState::Stopping(_) => "stopping",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Exhausted => "exhausted",
        TaskState::DeadlineExpired => "deadline",
    }
}
fn spin_range(index: usize) -> (u64, u64) {
    let (start, end) = if index == 0 {
        (
            ptr::addr_of!(timer_a_spin_start),
            ptr::addr_of!(timer_a_spin_end),
        )
    } else {
        (
            ptr::addr_of!(timer_b_spin_start),
            ptr::addr_of!(timer_b_spin_end),
        )
    };
    (
        CODE + start as u64 - code(index),
        CODE + end as u64 - code(index),
    )
}
fn gap(start: Sample, end: Sample) {
    let elapsed = end
        .ns
        .checked_sub(start.ns)
        .unwrap_or_else(|| fail("timer-gap-regression"));
    record("KERNEL_GAP", || {
        x("start_raw", start.raw);
        x("end_raw", end.raw);
        n("start_ns", start.ns);
        n("end_ns", end.ns);
        n("elapsed_ns", elapsed);
    });
}
fn ledger(policy: &Policy, index: usize, phase: &str) {
    let ti = checked(policy.task(index), "timer-ledger-task");
    let di = checked(policy.accounting(index), "timer-ledger-domain");
    let id = checked(policy.task_id(index), "timer-task-id");
    record("LEDGER", || {
        s("phase", phase);
        n("task", index as u64);
        n("domain", index as u64 + 1);
        n("task_slot", id.slot() as u64);
        n("task_generation", id.generation() as u64);
        s("state", state_name(ti.state));
        n("task_limit", ti.budget.limit_ns);
        wide("task_consumed", ti.budget.consumed_ns);
        n("task_reserved", ti.budget.reserved_ns);
        n("domain_limit", di.budget.limit_ns);
        wide("domain_consumed", di.budget.consumed_ns);
        n("domain_reserved", di.budget.reserved_ns);
        n("halted", di.halted as u64);
        n("deadline_ns", ti.deadline_ns);
        n("cpu_owned", ti.cpu.is_some() as u64);
    });
}
fn resume_record(index: usize, t: Task) {
    record("RESUME", || {
        n("task", index as u64);
        n("domain", t.domain);
        n("generation", 1);
        x("root", t.root);
        x("rip", t.saved.rip);
        x("rsp", t.saved.rsp);
        x("cs", t.saved.cs);
        x("ss", t.saved.ss);
        x("rflags", t.saved.rflags);
        n("first", (t.resumes == 0) as u64);
        n("resumes", t.resumes);
        for (i, v) in t.saved.registers.iter().enumerate() {
            print(format_args!(" r{i}={v:#x}"));
        }
        hash("fp_sha256", crate::k02_sha256::digest(&t.saved.fp));
    });
}
fn trap_record(index: usize, t: Task, trap: TimerTrap) {
    let stack = crate::k02_cpu::trap_stack();
    // These are the original normalized hardware-frame fields, copied before
    // returning from the privileged assembly path. No program supplies them.
    print(format_args!(
        "TESSRYN_K01_EXCEPTION vector={} error={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} cr2={:#x}\n",
        t.saved.vector, t.saved.error, t.saved.rip, t.saved.cs, t.saved.rflags, t.saved.rsp, t.cr2
    ));
    record("TRAP", || {
        n("task", index as u64);
        n("domain", t.domain);
        x("root", trap.root);
        n("vector", t.saved.vector);
        x("error", t.saved.error);
        x("rip", t.saved.rip);
        x("rsp", t.saved.rsp);
        x("cs", t.saved.cs);
        x("ss", t.saved.ss);
        x("rflags", t.saved.rflags);
        x("frame", trap.address);
        x("trap_start", stack.start);
        x("trap_end", stack.end);
        x("cr2", t.cr2);
        for (i, v) in t.saved.registers.iter().enumerate() {
            print(format_args!(" r{i}={v:#x}"));
        }
        hash("fp_sha256", crate::k02_sha256::digest(&t.saved.fp));
    });
    match trap.hardware {
        HardwareStop::Irq(v) => record("IRQ", || {
            n("task", index as u64);
            n("generation", v.arm.generation);
            x("capture_raw", v.sample.raw);
            n("capture_ns", v.sample.ns);
            x("target_raw", v.arm.target_raw);
            n("isr_before", v.isr_before as u64);
            n("isr_after", v.isr_after as u64);
            n("irr_after", v.irr_after as u64);
            n("eoi", v.eoi as u64);
        }),
        HardwareStop::Cancel(v) => record("CANCEL", || {
            n("task", index as u64);
            n("generation", v.generation);
            x("capture_raw", v.sample.raw);
            n("capture_ns", v.sample.ns);
            n("pending_probe", trap.pending_probe as u64);
            n("pending_before", v.pending_before as u64);
            n("isr_before", v.isr_before as u64);
            n("pending_after", v.pending_after as u64);
            n("isr_after", v.isr_after as u64);
        }),
    }
}
fn terminal(policy: &Policy, index: usize, reason: &str) {
    let mut t = task(index);
    if t.state == 3 {
        fail("timer-duplicate-terminal");
    }
    if !checked(policy.terminal(index), "timer-terminal-state") {
        fail("timer-policy-not-terminal");
    }
    t.state = 3;
    save(index, t);
    record("TERMINAL", || {
        n("task", index as u64);
        n("domain", t.domain);
        s("reason", reason);
        s(
            "state",
            state_name(checked(policy.task(index), "timer-terminal-info").state),
        );
        n("resumes", t.resumes);
    });
}
fn mailboxes(spin: [u64; 2], b_read_confirmed: bool) {
    for index in 0..2 {
        let t = task(index);
        let peer_stopped = (task(1 - index).state == 3) as u64;
        unsafe {
            ((t.request_physical + MAILBOX) as *mut u64).write_volatile(spin[index]);
            ((t.request_physical + MAILBOX + 8) as *mut u64).write_volatile(peer_stopped);
            ((t.request_physical + MAILBOX + 16) as *mut u64)
                .write_volatile(b_read_confirmed as u64);
        }
        record("MAILBOX", || {
            n("task", index as u64);
            n("spin_irqs", spin[index]);
            n("peer_stopped", peer_stopped);
            n("b_read_confirmed", b_read_confirmed as u64);
        });
    }
}

fn dispatch_record(policy: &Policy, grant: Grant, start: Sample, last: Sample, t: Task) {
    let index = grant.index;
    gap(last, start);
    record("DISPATCH", || {
        n("task", index as u64);
        n("domain", t.domain);
        n("cpu", 0);
        n("lease_generation", grant.dispatch.lease.generation() as u64);
        n("task_slot", grant.dispatch.task.slot() as u64);
        n("task_generation", grant.dispatch.task.generation() as u64);
        x("start_raw", start.raw);
        n("start_ns", start.ns);
        n("grant_ns", grant.dispatch.grant_ns);
        n("hard_ns", grant.dispatch.stop_by_ns);
        n("soft_ns", grant.soft_ns);
    });
    ledger(policy, index, "dispatch");
}

pub fn run(handoff: &crate::uefi::Handoff) -> ! {
    if case_id() > 3 {
        fail("timer-case");
    }
    crate::k02_cpu::initialize(handoff);
    unsafe {
        crate::cpu::prepare_timer_mmio();
        crate::cpu::install_timer_boundary();
    }
    record("BEGIN", || {
        s("case", case_name());
        n("version", 1);
        n("programs", 2);
        n("request_bytes", 96);
    });
    admit();
    let facts = checked(timer::initialize(), "timer-initialize");
    record("CLOCK", || {
        s("source", "hpet64");
        x("base", timer::HPET_BASE);
        x("capability", facts.capability);
        n("period_fs", facts.period_fs);
        x("epoch_raw", facts.epoch_raw);
        n("timers", facts.timer_count);
        x("apic_before", facts.apic_before);
        x("apic_after", facts.apic_after);
        x("pat", facts.pat);
        n("master_mask", facts.master_mask as u64);
        n("slave_mask", facts.slave_mask as u64);
        n("vector", timer::VECTOR);
        n("kernel_if", 0);
        n("user_if", 1);
        s("qualification", "emulator_only");
    });
    if code(0) % 4096 != 0
        || code(1) % 4096 != 0
        || ptr::addr_of!(region_program_a_end) as u64 != code(0) + 4096
        || ptr::addr_of!(region_program_b_end) as u64 != code(1) + 4096
    {
        fail("timer-program-pages");
    }
    let memory = checked(
        unsafe { crate::k02_memory::initialize(handoff) },
        "service-memory",
    );
    for domain in 1..=2 {
        checked(memory.create_domain(domain, 16), "service-create-domain");
        crate::k02::seed_root(root(domain), handoff);
        checked(root(domain).set_hpet_uncached(), "timer-user-mmio-map");
        if !checked(root(domain).hpet_uncached(), "timer-user-mmio-flags") {
            fail("timer-user-mmio-flags");
        }
        checked(
            root(domain).map_trusted_code(CODE, code(domain as usize - 1)),
            "service-code-map",
        );
    }
    let baseline = [baseline(memory, 1), baseline(memory, 2)];
    let owner = checked(
        memory.allocate_initialized_page(1, SEED),
        "service-provision-owner",
    );
    let physical = checked(memory.region_info(1, owner), "service-owner-info")
        .backing
        .start();
    cap_record("provision", owner);
    backing("ready", physical);
    let memory_ptr = memory as *mut NativeMemory;
    let mut journal = Journal { caps: [None; 32] };
    journal.caps[0] = Some(owner);
    let mut service = checked(Service::<NativeMapping>::new([1, 2]), "service-policy");
    for (index, b) in baseline.iter().enumerate() {
        let domain = index as u64 + 1;
        let mut t = EMPTY_TASK;
        t.domain = domain;
        t.root = root(domain).root();
        t.request_physical = b.pages[1].physical;
        t.request_cap = b.caps[1];
        t.saved.registers[2] = case_id();
        if index == 0 {
            t.saved.registers[3] = packed(owner);
        }
        save(index, t);
        record("TASK", || {
            n("domain", domain);
            x("root", t.root);
            x("code_physical", code(index));
            x("entry", CODE);
            x("stack", STACK);
            x("stack_physical", b.pages[0].physical);
            n("stack_lease_slot", b.pages[0].lease.slot() as u64);
            n(
                "stack_lease_generation",
                b.pages[0].lease.generation() as u64,
            );
            x("request", REQUEST);
            x("request_physical", t.request_physical);
            n("request_lease_slot", b.pages[1].lease.slot() as u64);
            n(
                "request_lease_generation",
                b.pages[1].lease.generation() as u64,
            );
            n("generation", 1);
        });
    }

    let admitted = checked(timer::clock(), "timer-admission-clock");
    let limits = K03_TIMER_CONTRACT.budgets;
    let deadlines = [
        if case_id() == 2 {
            admitted
                .ns
                .checked_add(DEADLINE_OFFSET)
                .unwrap_or_else(|| fail("timer-deadline-overflow"))
        } else {
            0
        },
        0,
    ];
    let mut policy = checked(Policy::new(admitted.ns, limits, deadlines), "timer-policy");
    checked(policy.block(1, admitted.ns), "timer-bootstrap-block");
    record("ADMIT", || {
        x("raw", admitted.raw);
        n("now_ns", admitted.ns);
        n("hard_quantum_ns", HARD_QUANTUM_NS);
        n("soft_target_ns", SOFT_TARGET_NS);
        n("budget_a", limits[0]);
        n("budget_b", limits[1]);
        n("deadline_a", deadlines[0]);
        n("deadline_b", 0);
        n("b_blocked", 1);
    });
    ledger(&policy, 0, "admit");
    ledger(&policy, 1, "admit");
    let mut last = Sample {
        raw: facts.epoch_raw,
        ns: 0,
    };
    let mut spin_irqs = [0u64; 2];
    let mut irqs = [0u64; 2];
    let mut previous = 2usize;
    let mut switches = 0u64;
    let mut steps = 0u64;
    let mut requests = 0u64;
    let mut b_read_confirmed = false;
    let mut forged_irq = false;
    while task(0).state != 3 || task(1).state != 3 {
        if steps >= 128 {
            fail("timer-step-bound");
        }
        steps += 1;
        let advanced = checked(timer::clock(), "timer-advance-clock");
        checked(policy.advance(advanced.ns), "timer-advance");
        record("ADVANCE", || {
            x("raw", advanced.raw);
            n("now_ns", advanced.ns);
        });
        for i in 0..2 {
            if task(i).state != 3 && checked(policy.terminal(i), "timer-idle-terminal") {
                terminal(&policy, i, "clock");
                ledger(&policy, i, "terminal");
            }
        }
        {
            let mut adapter = Adapter {
                memory: unsafe { &mut *memory_ptr },
                journal: &mut journal,
                kernel_root: handoff.cr3,
            };
            reap(&mut service, &mut adapter);
        }
        mailboxes(spin_irqs, b_read_confirmed);
        if task(0).state == 3 && task(1).state == 3 {
            break;
        }
        let start = checked(timer::clock(), "timer-dispatch-clock");
        let grant = checked(policy.dispatch(start.ns), "timer-dispatch");
        let index = grant.index;
        let mut t = task(index);
        if t.state == 3 || index == 1 && t.saved.registers[3] == 0 {
            fail("timer-invalid-selection");
        }
        checked(root(t.domain).validate(), "timer-preentry-tables");
        if !checked(root(t.domain).hpet_uncached(), "timer-preentry-mmio") {
            fail("timer-preentry-mmio");
        }
        // Do not print after sampling/arming until capture. This prevents serial
        // instrumentation from consuming the early delivery window before IRET.
        let before = t;
        unsafe {
            ptr::addr_of_mut!(TIMER_SOFT).write(grant.soft_ns);
        }
        let arm = checked(
            timer::arm(grant.soft_ns, grant.dispatch.lease.generation() as u64),
            "timer-arm",
        );
        let Some(arm) = arm else {
            let missed = checked(timer::clock(), "timer-arm-missed-clock");
            if missed.ns < grant.soft_ns {
                fail("timer-arm-missed-early");
            }
            dispatch_record(&policy, grant, start, last, t);
            record("ARM_MISSED", || {
                n("task", index as u64);
                n("generation", grant.dispatch.lease.generation() as u64);
                x("raw", missed.raw);
                n("now_ns", missed.ns);
                n("soft_ns", grant.soft_ns);
                n("hard_ns", grant.dispatch.stop_by_ns);
            });
            let end = checked(timer::clock(), "timer-unstarted-stop-clock");
            let state = checked(
                policy.stop(grant, end.ns, StopOutcome::Fail),
                "timer-unstarted-stop",
            );
            record("ACCOUNT", || {
                n("task", index as u64);
                n("domain", t.domain);
                n("lease_generation", grant.dispatch.lease.generation() as u64);
                s("reason", "arm_missed");
                s("outcome", "fail");
                x("start_raw", start.raw);
                x("capture_raw", missed.raw);
                x("stop_raw", end.raw);
                n("start_ns", start.ns);
                n("capture_ns", missed.ns);
                n("stop_ns", end.ns);
                n("elapsed_ns", end.ns - start.ns);
                n("grant_ns", grant.dispatch.grant_ns);
                n("hard_ns", grant.dispatch.stop_by_ns);
                n("late", (end.ns > grant.dispatch.stop_by_ns) as u64);
                s("state", state_name(state));
                n("irqs", irqs[index]);
                n("spin_irqs", spin_irqs[index]);
            });
            last = end;
            ledger(&policy, index, "stop");
            terminal(&policy, index, "arm_missed");
            {
                let mut adapter = Adapter {
                    memory: unsafe { &mut *memory_ptr },
                    journal: &mut journal,
                    kernel_root: handoff.cr3,
                };
                reap(&mut service, &mut adapter);
            }
            continue;
        };
        t.state = 1;
        t.resumes += 1;
        save(index, t);
        unsafe {
            ptr::addr_of_mut!(ACTIVE).write(index);
        }
        let result = unsafe {
            region_resume_user(
                t.root,
                ptr::addr_of!(TASKS)
                    .cast::<Task>()
                    .add(index)
                    .cast::<Saved>(),
            )
        };
        if result != 1 {
            fail("timer-entry-return");
        }
        t = task(index);
        if t.state != 2 {
            fail("timer-missing-capture");
        }
        let trap = take_timer_trap();
        if trap.hardware.generation() != grant.dispatch.lease.generation() as u64 {
            fail("timer-stale-arm");
        }
        if previous < 2 && previous != index {
            switches += 1;
        }
        previous = index;
        dispatch_record(&policy, grant, start, last, t);
        resume_record(index, before);
        record("ARM", || {
            n("task", index as u64);
            n("generation", arm.generation);
            x("armed_raw", arm.armed.raw);
            n("armed_ns", arm.armed.ns);
            n("soft_ns", arm.soft_ns);
            x("target_raw", arm.target_raw);
            x("readback_raw", arm.readback_raw);
            n("vector", timer::VECTOR);
        });
        trap_record(index, t, trap);
        let mut outcome = StopOutcome::Yield;
        let mut why = "irq";
        if t.saved.vector == timer::VECTOR {
            if t.saved.error != 0 {
                fail("timer-irq-error");
            }
            irqs[index] += 1;
            let (lo, hi) = spin_range(index);
            if t.saved.rip >= lo && t.saved.rip < hi {
                spin_irqs[index] += 1;
            }
        } else if t.saved.vector == 128 {
            why = "syscall";
            requests += 1;
            let mut adapter = Adapter {
                memory: unsafe { &mut *memory_ptr },
                journal: &mut journal,
                kernel_root: handoff.cr3,
            };
            let response = request(index, &mut service, &mut adapter);
            // In these bound programs B's second successful request follows
            // both actual data reads and comparisons. Only this trusted reply
            // releases A's forged-interrupt fixture handshake.
            if index == 1 && t.saved.registers[0] == 2 && response.status == Status::Ok {
                b_read_confirmed = true;
            }
            if response.capability.domain == 2 && task(1).resumes == 0 {
                let mut b = task(1);
                b.saved.registers[3] = packed(response.capability);
                save(1, b);
                let woke = checked(timer::clock(), "timer-wake-clock");
                checked(policy.wake(1, woke.ns), "timer-bootstrap-wake");
                record("WAKE", || {
                    n("task", 1);
                    x("raw", woke.raw);
                    n("now_ns", woke.ns);
                });
            }
            reply(&mut t, response);
            save(index, t);
            if response.control == Control::Exit {
                outcome = StopOutcome::Complete;
                why = "exit";
            }
        } else {
            let expected = ptr::addr_of!(timer_a_forged_irq) as u64 - code(0) + CODE;
            if case_id() != 3
                || index != 0
                || t.saved.vector != 13
                || t.saved.error != 0x102
                || t.saved.rip != expected
            {
                fail("timer-unexpected-user-fault");
            }
            outcome = StopOutcome::Fail;
            why = "forged_irq";
            forged_irq = true;
        }
        let end = checked(timer::clock(), "timer-stop-clock");
        let elapsed = end
            .ns
            .checked_sub(start.ns)
            .unwrap_or_else(|| fail("timer-charge-regression"));
        if end.ns < trap.hardware.sample().ns {
            fail("timer-capture-clock-order");
        }
        let stopped = checked(policy.stop(grant, end.ns, outcome), "timer-policy-stop");
        last = end;
        record("ACCOUNT", || {
            n("task", index as u64);
            n("domain", t.domain);
            n("lease_generation", grant.dispatch.lease.generation() as u64);
            s("reason", why);
            s(
                "outcome",
                match outcome {
                    StopOutcome::Yield => "yield",
                    StopOutcome::Complete => "complete",
                    StopOutcome::Fail => "fail",
                    StopOutcome::Block => "block",
                },
            );
            x("start_raw", start.raw);
            x("capture_raw", trap.hardware.sample().raw);
            x("stop_raw", end.raw);
            n("start_ns", start.ns);
            n("capture_ns", trap.hardware.sample().ns);
            n("stop_ns", end.ns);
            n("elapsed_ns", elapsed);
            n("grant_ns", grant.dispatch.grant_ns);
            n("hard_ns", grant.dispatch.stop_by_ns);
            n("late", (end.ns > grant.dispatch.stop_by_ns) as u64);
            s("state", state_name(stopped));
            n("irqs", irqs[index]);
            n("spin_irqs", spin_irqs[index]);
        });
        ledger(&policy, index, "stop");
        if stopped.terminal() {
            terminal(&policy, index, why);
        }
        {
            let mut adapter = Adapter {
                memory: unsafe { &mut *memory_ptr },
                journal: &mut journal,
                kernel_root: handoff.cr3,
            };
            reap(&mut service, &mut adapter);
        }
    }
    let a = checked(policy.task(0), "timer-a-final");
    let a_domain = checked(policy.accounting(0), "timer-a-domain-final");
    let a_proof = match case_id() {
        0 => spin_irqs[0] >= MIN_SPIN_IRQS && a.state == TaskState::Completed,
        1 => {
            spin_irqs[0] > 0
                && a.budget.consumed_ns >= u128::from(SMALL_BUDGET)
                && (a.state == TaskState::Exhausted
                    || a.state == TaskState::Failed && a_domain.halted)
        }
        2 => {
            spin_irqs[0] > 0
                && policy.clock() >= deadlines[0]
                && (a.state == TaskState::DeadlineExpired
                    || a.state == TaskState::Failed && a_domain.halted)
        }
        3 => b_read_confirmed && forged_irq && a.state == TaskState::Failed,
        _ => false,
    };
    if !a_proof
        || spin_irqs[1] < MIN_SPIN_IRQS
        || !matches!(
            checked(policy.task(1), "timer-b-final").state,
            TaskState::Completed
        )
    {
        fail("timer-case-not-established");
    }
    if checked(policy.cpu_lease(), "timer-final-cpu").is_some() || policy.active().is_some() {
        fail("timer-final-lease");
    }
    {
        let mut adapter = Adapter {
            memory: unsafe { &mut *memory_ptr },
            journal: &mut journal,
            kernel_root: handoff.cr3,
        };
        reap(&mut service, &mut adapter);
        if adapter.journal.caps.iter().any(Option::is_some) || service.mapping_count() != 0 {
            fail("service-final-journal");
        }
        for (index, b) in baseline.into_iter().enumerate() {
            let domain = index as u64 + 1;
            for (i, va) in [STACK, REQUEST].into_iter().enumerate() {
                let p = b.pages[i];
                checked(
                    adapter.retire(
                        NativeMapping {
                            domain,
                            va,
                            page: RegionLease {
                                physical: p.physical,
                                length: 4096,
                                lease: p.lease,
                                writable: true,
                            },
                        },
                        true,
                    ),
                    "service-baseline-retire",
                );
                checked(
                    adapter.memory.release(domain, b.caps[i]),
                    "service-baseline-release",
                );
            }
            checked(root(domain).unmap_user(CODE), "service-code-retire");
            unsafe {
                crate::k02_cpu::reload(root(domain).root());
                crate::k02_cpu::reload(handoff.cr3);
            }
            let a = checked(
                adapter.memory.accounting(domain),
                "service-final-accounting",
            );
            let leaves = root(domain).user_leaf_count();
            if a.charged_pages != 0
                || a.committed_pages != 0
                || a.reserved_pages != 0
                || leaves != 0
            {
                fail("service-final-owned-state");
            }
            record("FINAL", || {
                n("domain", domain);
                n("leaves", leaves as u64);
                n("charged", a.charged_pages);
                n("committed", a.committed_pages);
                n("reserved", a.reserved_pages);
            });
        }
        if adapter.memory.allocated_pages() != 0 {
            fail("service-final-allocation");
        }
    }

    for i in 0..2 {
        ledger(&policy, i, "final");
    }
    let shutdown = checked(timer::shutdown(), "timer-shutdown");
    gap(last, shutdown.sample);
    let tenant = checked(policy.accounting(0), "timer-final-a")
        .budget
        .consumed_ns
        + checked(policy.accounting(1), "timer-final-b")
            .budget
            .consumed_ns;
    let kernel = u128::from(shutdown.sample.ns)
        .checked_sub(tenant)
        .unwrap_or_else(|| fail("timer-double-charge"));
    record("CLOCK_END", || {
        x("raw", shutdown.sample.raw);
        n("now_ns", shutdown.sample.ns);
        wide("tenant_ns", tenant);
        wide("kernel_ns", kernel);
        n("pending_after", shutdown.pending_after as u64);
        n("isr_after", shutdown.isr_after as u64);
        n("generation", shutdown.generation);
    });
    record("PASS", || {
        s("case", case_name());
        n("allocated_pages", 0);
        n("mappings", 0);
        n("cpu_leases", 0);
        n("context_switches", switches);
        n("requests", requests);
        n("irqs_a", irqs[0]);
        n("irqs_b", irqs[1]);
        n("spin_irqs_a", spin_irqs[0]);
        n("spin_irqs_b", spin_irqs[1]);
        s("qualification", "emulator_only");
    });
    crate::diagnostics::finish(true)
}
