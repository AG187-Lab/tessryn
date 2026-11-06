//! Two CPU-local countdowns with BSP-owned policy. Every lease survives until
//! the BSP consumes the exact CPU's protected retirement sample.
use super::{asm, clock, context, elapsed, ensure, fence, finish, heartbeat, id, marker, print,
    print_capture, print_payload, print_space, print_walks, progress, ptr, read, user_address, wait,
    wait_ns, write, AtomicU64, Capture, Ordering, Saved, CAPTURES, CODE, SEED, TIMEOUT, WINDOW,
    smp_user_loop_end, smp_user_loop_start};
use tessryn_scheduler::{CpuLease, Dispatch, Error, Scheduler, StopOutcome, TaskId, TaskState, TaskSpec};

const DOMAIN: u64 = 1;
const LATE: bool = cfg!(smp_budget_case = "late");
const LIMIT: u64 = if LATE { 60_000_000 } else { 1_200_000_000 };
const QUANTUM: u64 = if LATE { 40_000_000 } else { 800_000_000 };
const TARGET: u64 = if LATE { 60_000_000 } else { 20_000_000 };
const AP_MULTIPLIER: u64 = 4;
const ROUNDS: u64 = if LATE { 1 } else { 2 };
const LAPIC: u64 = 0xfee0_0000;
const VECTOR: u64 = 67;
const BIT: u32 = 1 << (VECTOR % 32);
const LVT: u64 = 0x320;
const INITIAL: u64 = 0x380;
const CURRENT: u64 = 0x390;
const DIVIDE: u64 = 0x3e0;
const DCR: u32 = 3;
const DIVISOR: u64 = 16;
const MASKED: u32 = (1 << 16) | VECTOR as u32;
const CAL_INITIAL: u32 = u32::MAX;
const ROUNDING_NS: u64 = 20;
fn count(cpu: usize) -> u32 {
    let target = if cpu == 0 { TARGET } else { TARGET * AP_MULTIPLIER };
    target.div_ceil(DIVISOR) as u32
}
#[repr(C)]
pub struct Contract { magic: [u8; 16], words: [u64; 15] }
#[used]
#[unsafe(no_mangle)]
pub static K03_SMP_BUDGET_CONTRACT: Contract = Contract {
    magic: *b"TESSRYN-SMPBUD1\0",
    words: [1, LATE as u64, 2, DOMAIN, VECTOR, DCR as u64, DIVISOR, LIMIT, QUANTUM,
        TARGET, ROUNDS, 10_000_000, WINDOW, TIMEOUT, AP_MULTIPLIER],
};

#[derive(Clone, Copy)]
struct Calibration { first_before: u64, first_after: u64, first_count: u32,
    last_before: u64, last_after: u64, last_count: u32, stopped_count: u32, irr: u32, isr: u32 }
const EMPTY_CAL: Calibration = Calibration { first_before: 0, first_after: 0, first_count: 0,
    last_before: 0, last_after: 0, last_count: 0, stopped_count: 0, irr: 0, isr: 0 };
#[derive(Clone, Copy)]
struct Run { lease: u64, arm_before: u64, arm_after: u64, entry: u64, capture: u64, retired: u64,
    initial: u32, current: u32, irr_before: u32, isr_before: u32, irr_after: u32, isr_after: u32,
    lvt_before: u32, lvt_after: u32, retire_count: u32, peer_heartbeat: u64, resume_rip: u64,
    heartbeat_before: u64, heartbeat_after: u64 }
const EMPTY_RUN: Run = Run { lease: 0, arm_before: 0, arm_after: 0, entry: 0, capture: 0, retired: 0,
    initial: 0, current: 0, irr_before: 0, isr_before: 0, irr_after: 0, isr_after: 0,
    lvt_before: 0, lvt_after: 0, retire_count: 0, peer_heartbeat: 0, resume_rip: 0,
    heartbeat_before: 0, heartbeat_after: 0 };
// Each CPU writes only its own slots. BSP acquires completion before reading
// the AP slots and does not publish the next round until those reads finish.
static mut CALIBRATION: [Calibration; 2] = [EMPTY_CAL; 2];
static mut RUNS: [Run; 2] = [EMPTY_RUN; 2];
static EPOCH: AtomicU64 = AtomicU64::new(0);
static CALIBRATED: AtomicU64 = AtomicU64::new(0);
static COMMAND: AtomicU64 = AtomicU64::new(0);
static PREPARED: AtomicU64 = AtomicU64::new(0);
static GO: AtomicU64 = AtomicU64::new(0);
static STOPPED: AtomicU64 = AtomicU64::new(0);
static PARK: AtomicU64 = AtomicU64::new(0);
static PARKED: AtomicU64 = AtomicU64::new(0);
static LEASES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static HARD: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
const IOAPIC: u64 = 0xfec0_0000;
const IOAPIC_VERSION: u32 = 0x0017_0020;
const REDIRECTIONS: usize = 24;
static mut RTE: [u32; REDIRECTIONS] = [0; REDIRECTIONS];
static IOAPIC_FACT: AtomicU64 = AtomicU64::new(0);

pub(super) fn prepare_interrupts() {
    // Only the BSP accesses IOREGSEL/IOWIN, before SIPI, through the admitted
    // UC/NX HPET-containing supervisor leaf. Preserve unrelated RTE fields.
    let select = IOAPIC as *mut u32;
    let window = (IOAPIC + 0x10) as *mut u32;
    unsafe {
        select.write_volatile(1);
        let version = window.read_volatile();
        ensure(version == IOAPIC_VERSION);
        IOAPIC_FACT.store(u64::from(version), Ordering::Relaxed);
        for pin in 0..REDIRECTIONS {
            select.write_volatile(0x10 + 2 * pin as u32);
            window.write_volatile(window.read_volatile() | (1 << 16));
            let masked = window.read_volatile();
            ensure(masked & (1 << 16) != 0);
            ptr::addr_of_mut!(RTE).cast::<u32>().add(pin).write(masked);
        }
    }
}
fn log_interrupt_admission() {
    print(format_args!("TESSRYN_K03_SMP_BUDGET_IRQS version={:#x} redirections={REDIRECTIONS} rtes=", IOAPIC_FACT.load(Ordering::Relaxed)));
    for pin in 0..REDIRECTIONS {
        let word = unsafe { ptr::addr_of!(RTE).cast::<u32>().add(pin).read() };
        print(format_args!("{word:08x}"));
    }
    print(format_args!("\n"));
}
fn expiry_ns(initial: u32) -> u64 { (u64::from(initial) + 1) * DIVISOR }

fn run_ptr(cpu: usize) -> *mut Run { unsafe { ptr::addr_of_mut!(RUNS).cast::<Run>().add(cpu) } }
fn cal_ptr(cpu: usize) -> *mut Calibration { unsafe { ptr::addr_of_mut!(CALIBRATION).cast::<Calibration>().add(cpu) } }
fn local(offset: u64) -> u32 { read(LAPIC, offset) }
fn banks(base: u64, expected: u32) -> u32 {
    let mut vector_word = 0;
    for word in 0..8 {
        let value = local(base + word * 16);
        ensure(value == if word == VECTOR / 32 { expected } else { 0 });
        if word == VECTOR / 32 { vector_word = value; }
    }
    vector_word
}
fn idle() {
    ensure(local(LVT) == MASKED && local(INITIAL) == 0 && local(CURRENT) == 0);
    banks(0x100, 0); banks(0x200, 0);
}
fn calibrate(cpu: usize) {
    write(LVT, MASKED); write(INITIAL, 0); write(DIVIDE, DCR);
    idle(); ensure(local(DIVIDE) == DCR);
    // The masked long countdown cannot authorize an interrupt.
    write(INITIAL, CAL_INITIAL);
    let first_before = clock(); let first_count = local(CURRENT); let first_after = clock();
    wait_ns(5_000_000);
    let last_before = clock(); let last_count = local(CURRENT); let last_after = clock();
    ensure(first_before <= first_after && first_after < last_before && last_before <= last_after
        && first_count > last_count && last_count > 0);
    let count_ns = u64::from(first_count - last_count) * DIVISOR;
    // HPET brackets and two ticks of rounding validate the pinned emulator
    // rate. This tolerance does not apply to any policy hard-stop timestamp.
    ensure(count_ns + ROUNDING_NS >= elapsed(first_after, last_before)
        && count_ns <= elapsed(first_before, last_after) + ROUNDING_NS);
    write(INITIAL, 0); idle();
    unsafe { cal_ptr(cpu).write(Calibration { first_before, first_after, first_count, last_before,
        last_after, last_count, stopped_count: local(CURRENT), irr: banks(0x200, 0), isr: banks(0x100, 0) }); }
}

fn execute(cpu: usize, round: u64) {
    idle(); ensure(local(DIVIDE) == DCR);
    let epoch = EPOCH.load(Ordering::Relaxed);
    let hard = HARD[cpu].load(Ordering::Relaxed);
    ensure(elapsed(epoch, clock()) < hard);
    let mut row = EMPTY_RUN;
    row.lease = LEASES[cpu].load(Ordering::Relaxed);
    ensure(row.lease == round);
    row.resume_rip = unsafe { (*context(cpu)).saved.rip };
    row.heartbeat_before = heartbeat(cpu);
    write(LVT, VECTOR as u32);
    row.arm_before = clock();
    write(INITIAL, count(cpu));
    row.arm_after = clock();
    ensure(local(LVT) == VECTOR as u32 && local(INITIAL) == count(cpu));
    if !LATE {
        let latest_expiry = row.arm_after.checked_add(expiry_ns(count(cpu)).div_ceil(10) + 2).unwrap();
        if elapsed(epoch, latest_expiry) >= hard {
            write(LVT, MASKED); write(INITIAL, 0); ensure(false);
        }
    }
    banks(0x100, 0); banks(0x200, 0);
    row.entry = clock();
    unsafe { run_ptr(cpu).write(row); }
    // An already expired kernel-side arm cannot produce accepted entry.
    // A race after this read still requires a bound CPL3 loop RIP and work.
    if elapsed(epoch, row.entry) >= hard || local(CURRENT) == 0 {
        write(LVT, MASKED); write(INITIAL, 0); ensure(false);
    }
    super::enter(cpu);
    row = unsafe { run_ptr(cpu).read() };
    idle();
    row.retire_count = local(CURRENT);
    row.retired = clock();
    ensure(row.capture >= row.entry && row.retired >= row.capture && row.heartbeat_after > row.heartbeat_before);
    unsafe { run_ptr(cpu).write(row); }
}

pub(super) fn capture(cpu: usize, saved: Saved, frame: u64, fp: u64, root: u64, cr2: u64) {
    let mut row = unsafe { run_ptr(cpu).read() };
    ensure(row.capture == 0);
    row.capture = clock();
    row.peer_heartbeat = heartbeat(cpu ^ 1);
    row.heartbeat_after = heartbeat(cpu);
    let start = user_address(ptr::addr_of!(smp_user_loop_start));
    ensure(saved.vector == VECTOR && saved.error == 0 && row.lease != 0
        && row.lease == LEASES[cpu].load(Ordering::Relaxed)
        && saved.rip < user_address(ptr::addr_of!(smp_user_loop_end))
        && saved.rip.checked_sub(start).is_some_and(|offset| matches!(offset, 0 | 4 | 6)));
    ensure(row.capture >= row.entry
        && elapsed(row.arm_before, row.capture) + ROUNDING_NS >= u64::from(count(cpu)) * DIVISOR);
    row.lvt_before = local(LVT); row.initial = local(INITIAL); row.current = local(CURRENT);
    ensure(row.lvt_before == VECTOR as u32 && row.initial == count(cpu) && row.current == 0 && local(DIVIDE) == DCR);
    row.irr_before = banks(0x200, 0); row.isr_before = banks(0x100, BIT);
    write(LVT, MASKED); write(INITIAL, 0); write(0xb0, 0);
    row.irr_after = banks(0x200, 0); row.isr_after = banks(0x100, 0); row.lvt_after = local(LVT);
    ensure(row.lvt_after == MASKED && local(CURRENT) == 0);
    let c = context(cpu);
    unsafe {
        ptr::addr_of_mut!((*c).saved).write(saved);
        ptr::addr_of_mut!(CAPTURES).cast::<Capture>().add(cpu).write(Capture { saved, cr2, frame, fp,
            root, apic: id(), before: u64::from(row.isr_before), after: u64::from(row.isr_after),
            generation: row.lease, heartbeat: row.heartbeat_after, kernel_rsp: (*c).kernel_rsp,
            kernel_cr3: (*c).kernel_root });
        run_ptr(cpu).write(row);
    }
}

pub(super) fn ap_run() -> ! {
    calibrate(1);
    CALIBRATED.store(1, Ordering::Release);
    for round in 1..=ROUNDS {
        wait(&COMMAND, round);
        PREPARED.store(round, Ordering::Release);
        wait(&GO, round);
        execute(1, round);
        STOPPED.store(round, Ordering::Release);
    }
    wait(&PARK, 1);
    idle();
    // The acknowledgment is the AP's final RAM write. All RAM is retained.
    fence(Ordering::Release);
    unsafe { asm!("mov qword ptr [{ack}], 1", "2: cli", "hlt", "jmp 2b", ack = in(reg) &PARKED, options(noreturn)); }
}

type Policy = Scheduler<1, 2, 2>;
fn checked<T>(r: Result<T, Error>) -> T { r.unwrap_or_else(|_| { ensure(false); unreachable!() }) }
fn reserve(policy: &mut Policy, tasks: [TaskId; 2], start: u64, round: u64) -> [Dispatch; 2] {
    let mut candidate = policy.clone();
    let grants = core::array::from_fn(|cpu| checked(candidate.dispatch(cpu, QUANTUM, start)));
    for cpu in 0..2 {
        let lease = grants[cpu].lease;
        ensure(grants[cpu].task == tasks[cpu] && lease.task() == tasks[cpu]
            && lease.cpu() as usize == cpu && u64::from(lease.generation()) == round);
    }
    let ledger = checked(candidate.accounting(DOMAIN));
    ensure(ledger.budget.reserved_ns == grants[0].grant_ns + grants[1].grant_ns
        && ledger.budget.consumed_ns + u128::from(ledger.budget.reserved_ns) <= u128::from(LIMIT)
        && !ledger.halted);
    *policy = candidate;
    grants
}
fn log_calibration(cpu: usize) {
    let c = unsafe { cal_ptr(cpu).read() };
    print(format_args!("TESSRYN_K03_SMP_BUDGET_CAL cpu={cpu} divider={DIVISOR} divide_cfg={DCR} initial={CAL_INITIAL} first_before={} first_after={} first_count={} last_before={} last_after={} last_count={} stopped_count={} irr={} isr={}\n",
        c.first_before, c.first_after, c.first_count, c.last_before, c.last_after, c.last_count, c.stopped_count, c.irr, c.isr));
}
fn log_timer(cpu: usize, round: u64, r: Run) {
    print(format_args!("TESSRYN_K03_SMP_BUDGET_TIMER round={round} cpu={cpu} lease={} arm_before={} arm_after={} entry={} capture={} retired={} initial={} current={} irr_before={} isr_before={} irr_after={} isr_after={} lvt_before={:#x} lvt_after={:#x} retire_count={} peer_heartbeat={} resume_rip={:#x} heartbeat_before={} heartbeat_after={}\n",
        r.lease, r.arm_before, r.arm_after, r.entry, r.capture, r.retired, r.initial, r.current, r.irr_before, r.isr_before,
        r.irr_after, r.isr_after, r.lvt_before, r.lvt_after, r.retire_count, r.peer_heartbeat, r.resume_rip, r.heartbeat_before, r.heartbeat_after));
    print_capture(cpu, "timer", cpu);
}
fn peer(policy: &Policy, lease: CpuLease, grant: Dispatch) -> (u32, u64) {
    if let Some(current) = checked(policy.cpu_lease(lease.cpu() as usize)) {
        ensure(current == lease && grant.lease == lease);
        let info = checked(policy.task(DOMAIN, lease.task()));
        ensure(info.budget.reserved_ns == grant.grant_ns);
        (lease.generation(), info.budget.reserved_ns)
    } else { (0, 0) }
}

pub(super) fn run() -> ! {
    ensure((cfg!(smp_budget_case = "preempt") ^ LATE) && super::case_id() == 0);
    calibrate(0);
    wait(&CALIBRATED, 1);
    let epoch = clock();
    EPOCH.store(epoch, Ordering::Relaxed);
    let case = if LATE { "late" } else { "preempt" };
    print(format_args!("TESSRYN_K03_SMP_BUDGET_BEGIN case={case} cpus=2 domain={DOMAIN} vector={VECTOR} epoch={epoch}\n"));
    log_interrupt_admission();
    for cpu in 0..2 { print_space(cpu); print_walks(cpu); print_payload(cpu, "before"); }
    for cpu in 0..2 { log_calibration(cpu); }
    let mut policy = checked(Policy::new());
    checked(policy.add_domain(DOMAIN, LIMIT));
    let tasks = core::array::from_fn(|_| checked(policy.create_task(DOMAIN, TaskSpec { budget_ns: LIMIT, deadline_ns: 0 }, 0)));
    let mut last_rip = [CODE; 2];
    let mut last_heartbeat = [0; 2];
    for round in 1..=ROUNDS {
        let start = clock();
        let grants = reserve(&mut policy, tasks, elapsed(epoch, start), round);
        let ledger = checked(policy.accounting(DOMAIN));
        for cpu in 0..2 {
            LEASES[cpu].store(u64::from(grants[cpu].lease.generation()), Ordering::Relaxed);
            HARD[cpu].store(grants[cpu].stop_by_ns, Ordering::Relaxed);
        }
        COMMAND.store(round, Ordering::Release);
        wait(&PREPARED, round);
        GO.store(round, Ordering::Release);
        let ap_ready_heartbeat = progress(1, last_heartbeat[1]);
        execute(0, round);
        wait(&STOPPED, round);
        let rows: [Run; 2] = core::array::from_fn(|cpu| unsafe { run_ptr(cpu).read() });
        // AP has done user work before BSP's arm. The authentic BSP trap
        // predates the earliest possible AP timer expiry in this clock model.
        // No other accepted trap can take the AP out of its unbounded loop.
        let ap_earliest = rows[1].arm_before.checked_add(expiry_ns(rows[1].initial) / 10 - 2).unwrap();
        ensure(rows[1].entry <= rows[0].arm_before && rows[0].capture < ap_earliest
            && rows[0].entry.max(rows[1].entry) < rows[0].capture.min(rows[1].capture)
            && ap_ready_heartbeat <= rows[0].peer_heartbeat);
        // No policy mutation or diagnostics delayed either local retirement.
        // Both local samples are fixed before the BSP reconciles them in order.
        print(format_args!("TESSRYN_K03_SMP_BUDGET_BATCH round={round} start={start} reserved={} consumed={} available={} ap_ready_heartbeat={ap_ready_heartbeat}\n",
            ledger.budget.reserved_ns, ledger.budget.consumed_ns, ledger.budget.available_ns()));
        for cpu in 0..2 {
            let g = grants[cpu];
            print(format_args!("TESSRYN_K03_SMP_BUDGET_GRANT round={round} cpu={cpu} task={} task_generation={} lease={} grant_ns={} hard_ns={}\n",
                g.task.slot(), g.task.generation(), g.lease.generation(), g.grant_ns, g.stop_by_ns));
        }
        for cpu in 0..2 {
            let r = rows[cpu];
            ensure(r.arm_before >= start && r.resume_rip == last_rip[cpu] && r.heartbeat_before == last_heartbeat[cpu]
                && r.peer_heartbeat > rows[cpu ^ 1].heartbeat_before && r.peer_heartbeat <= rows[cpu ^ 1].heartbeat_after);
            log_timer(cpu, round, r);
            last_rip[cpu] = unsafe { ptr::addr_of!(CAPTURES).cast::<Capture>().add(cpu).read().saved.rip };
            last_heartbeat[cpu] = r.heartbeat_after;
        }
        let first = usize::from(rows[1].retired < rows[0].retired);
        for (index, cpu) in [first, first ^ 1].into_iter().enumerate() {
            let r = rows[cpu]; let g = grants[cpu]; let now = elapsed(epoch, r.retired);
            ensure((now > g.stop_by_ns) == LATE);
            let outcome = if !LATE && round == ROUNDS { StopOutcome::Complete } else { StopOutcome::Yield };
            let state = checked(policy.stop(g.lease, now, outcome));
            let label = match state { TaskState::Runnable if !LATE && round < ROUNDS => "runnable",
                TaskState::Completed if !LATE && round == ROUNDS => "completed", TaskState::Failed if LATE => "failed",
                _ => { ensure(false); unreachable!() } };
            let d = checked(policy.accounting(DOMAIN));
            ensure(d.halted == LATE);
            let (peer_lease, peer_reserved) = peer(&policy, grants[cpu ^ 1].lease, grants[cpu ^ 1]);
            ensure((peer_lease != 0) == (index == 0));
            print(format_args!("TESSRYN_K03_SMP_BUDGET_ACCOUNT round={round} cpu={cpu} lease={} retired={} elapsed_ns={} consumed={} reserved={} available={} halted={} state={label} peer_lease={peer_lease} peer_reserved={peer_reserved}\n",
                r.lease, r.retired, elapsed(start, r.retired), d.budget.consumed_ns, d.budget.reserved_ns,
                d.budget.available_ns(), d.halted as u8));
            if LATE && index == 0 {
                ensure(matches!(policy.dispatch(cpu, QUANTUM, now), Err(Error::NoRunnableTask))
                    && checked(policy.accounting(DOMAIN)) == d
                    && peer(&policy, grants[cpu ^ 1].lease, grants[cpu ^ 1]) == (peer_lease, peer_reserved));
                print(format_args!("TESSRYN_K03_SMP_BUDGET_DENY round={round} cpu={cpu} reason=no-runnable-task consumed={} reserved={} available={} halted=1 peer_lease={peer_lease} peer_reserved={peer_reserved}\n",
                    d.budget.consumed_ns, d.budget.reserved_ns, d.budget.available_ns()));
            }
        }
    }
    let d = checked(policy.accounting(DOMAIN));
    ensure(d.budget.reserved_ns == 0 && checked(policy.cpu_lease(0)).is_none() && checked(policy.cpu_lease(1)).is_none());
    PARK.store(1, Ordering::Release);
    wait(&PARKED, 1);
    idle();
    let start = clock(); wait_ns(WINDOW); let end = clock();
    let stable = [heartbeat(0), heartbeat(1)]; ensure(stable == last_heartbeat);
    print(format_args!("TESSRYN_K03_SMP_BUDGET_STOP ap_ack=1 start={start} end={end} cpu0={} stable0={} cpu1={} stable1={}\n",
        last_heartbeat[0], stable[0], last_heartbeat[1], stable[1]));
    for cpu in 0..2 { print_payload(cpu, "after"); ensure(marker(cpu) == SEED + cpu as u64); }
    print(format_args!("TESSRYN_K03_SMP_BUDGET_PASS cpus=2 rounds={ROUNDS} irqs={} consumed={} reserved=0 halted={} retained=all\n",
        ROUNDS * 2, d.budget.consumed_ns, d.halted as u8));
    finish(true)
}
