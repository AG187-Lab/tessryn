//! Native worker and authenticated timer/completion path for scheduled arrivals.
//! The BSP owns policy. The AP owns the only CPL3 worker and its saved contexts.
use super::{asm, clock, context, elapsed, ensure, enter, fence, id, initial, print,
    ptr, read, wait, wait_ns, write, AtomicU64, Data, Ordering, Page, Saved, Tables,
    UserAccess, CODE, DATA, SEED, SENTINEL, STACK};

#[path = "smp_workload_policy.rs"]
mod policy;

pub(super) const TICK_NS: u64 = 10_000_000;
pub(super) const HPET_TICK_NS: u64 = 10;
pub(super) const QUANTUM_UNIT_NS: u64 = 20_000_000;
pub(super) const WORK_ITERATIONS: u64 = 64_000;
pub(super) const RUN_LIMIT_NS: u64 = 24_000_000_000;
pub(super) const MAX_JOBS: usize = 30;
const LAPIC: u64 = 0xfee0_0000;
const IOAPIC: u64 = 0xfec0_0000;
const VECTOR: u32 = 67;
const TIMER_BIT: u32 = 1 << (VECTOR % 32);
const LVT: u64 = 0x320;
const INITIAL: u64 = 0x380;
const CURRENT: u64 = 0x390;
const DIVIDE: u64 = 0x3e0;
const DIVIDE_CONFIG: u32 = 3;
const DIVIDER: u64 = 16;
const SOFT_FRACTION: u64 = 4;
const MASKED: u32 = (1 << 16) | VECTOR;
const ROUNDING_NS: u64 = 2 * HPET_TICK_NS;
const REDIRECTIONS: usize = 24;

#[used]
#[unsafe(no_mangle)]
pub static K03_SMP_WORKLOAD_PROFILE: [u8; 319] = *include_bytes!("smp_workload_profile.bin");

#[derive(Clone, Copy)]
pub(super) struct Offer {
    pub id: u8,
    pub domain: u8,
    pub arrival: u8,
    pub work: u8,
    pub cancel: u8,
    pub class: u8,
}
const EMPTY_OFFER: Offer = Offer { id: 0, domain: 0, arrival: 0, work: 0, cancel: 0, class: 0 };
const DIRECTED: [Offer; 3] = [
    Offer { id: 1, domain: 1, arrival: 0, work: 64, cancel: 1, class: 2 },
    Offer { id: 2, domain: 2, arrival: 0, work: 1, cancel: 1, class: 1 },
    Offer { id: 3, domain: 3, arrival: 4, work: 1, cancel: 0, class: 3 },
];
static mut OFFERS: [Offer; MAX_JOBS] = [EMPTY_OFFER; MAX_JOBS];
static mut SELECTED: [u8; 3] = [0; 3];

unsafe extern "sysv64" {
    static smp_workload_program_start: u8;
    static smp_workload_program_end: u8;
    static smp_workload_user_start: u8;
    static smp_workload_loop: u8;
    static smp_workload_after_inc: u8;
    static smp_workload_after_sum: u8;
    static smp_workload_before_dec: u8;
    static smp_workload_after_dec: u8;
    static smp_workload_complete: u8;
    static smp_workload_complete_return: u8;
}

static mut ROOTS: [Tables<16>; MAX_JOBS] = [const { Tables::empty() }; MAX_JOBS];
static mut STACKS: [Page; MAX_JOBS] = [const { Page([0; 4096]) }; MAX_JOBS];
static DATA_PAGES: [Data; MAX_JOBS] = [const { Data([const { AtomicU64::new(0) }; 512]) }; MAX_JOBS];

struct JobContext { root: u64, total: u64, saved: Saved }
static mut JOBS: [JobContext; MAX_JOBS] =
    [const { JobContext { root: 0, total: 0, saved: initial() } }; MAX_JOBS];

#[derive(Clone, Copy)]
pub(super) struct Command {
    pub job: usize,
    pub task_slot: u32,
    pub task_generation: u32,
    pub lease_generation: u32,
    pub start: u64,
    pub hard: u64,
    pub grant_ns: u64,
}
const EMPTY_COMMAND: Command =
    Command { job: 0, task_slot: 0, task_generation: 0, lease_generation: 0, start: 0, hard: 0, grant_ns: 0 };
#[derive(Clone, Copy)]
pub(super) struct Receipt {
    pub command: Command,
    pub arm_before: u64,
    pub arm_after: u64,
    pub entry: u64,
    pub trap: u64,
    pub eoi: u64,
    pub retired: u64,
    pub progress_before: u64,
    pub progress_after: u64,
    pub checksum: u64,
    pub rip: u64,
    pub resume_rip: u64,
    pub root: u64,
    pub initial: u32,
    pub isr_before: u32,
    pub isr_after: u32,
    pub vector: u32,
    pub drained: u32,
}
const EMPTY_RECEIPT: Receipt = Receipt { command: EMPTY_COMMAND, arm_before: 0, arm_after: 0,
    entry: 0, trap: 0, eoi: 0, retired: 0, progress_before: 0, progress_after: 0,
    checksum: 0, rip: 0, resume_rip: 0, root: 0, initial: 0, isr_before: 0, isr_after: 0,
    vector: 0, drained: 0 };

const IDLE: u64 = 0;
const RUNNING: u64 = 1;
const CLOSING: u64 = 2;
const READY: u64 = 3;
const PARK: u64 = 4;
static PHASE: AtomicU64 = AtomicU64::new(IDLE);
static CALIBRATED: AtomicU64 = AtomicU64::new(0);
static PARKED: AtomicU64 = AtomicU64::new(0);
static AP_ERROR: AtomicU64 = AtomicU64::new(0);
static AP_ERROR_LEN: AtomicU64 = AtomicU64::new(0);
static mut COMMAND: Command = EMPTY_COMMAND;
static mut RECEIPT: Receipt = EMPTY_RECEIPT;
// AP-local. Outside CPL3 and the one drain window, the AP keeps IRQs disabled.
static mut ACTIVE: Receipt = EMPTY_RECEIPT;
static mut DRAIN_EXPECTED: bool = false;
static mut CALIBRATION: [u64; 6] = [0; 6];
static mut RTE: [u32; REDIRECTIONS] = [0; REDIRECTIONS];

pub(super) enum WorkerState { Idle, Running, Closing, Retired(Receipt) }

fn fail(message: &'static str) -> ! {
    if id() == super::IDS[0].load(Ordering::Relaxed) { crate::diagnostics::fail(message); }
    AP_ERROR_LEN.store(message.len() as u64, Ordering::Relaxed);
    AP_ERROR.store(message.as_ptr() as u64, Ordering::Release);
    super::super::smp::smp_ap_fail()
}

fn require(condition: bool, message: &'static str) {
    if !condition { fail(message); }
}

fn fw_select(selector: u16) {
    unsafe { asm!("out dx, ax", in("dx") 0x510u16, in("ax") selector, options(nomem, nostack)); }
}

fn fw_read<const N: usize>() -> [u8; N] {
    core::array::from_fn(|_| {
        let byte: u8;
        unsafe { asm!("in al, dx", in("dx") 0x511u16, out("al") byte, options(nomem, nostack)); }
        byte
    })
}

fn selector() -> (u8, u8) {
    const NAME: &[u8] = b"opt/tessryn/scheduled-arrivals";
    fw_select(0);
    require(fw_read::<4>() == *b"QEMU", "workload-fw-signature");
    fw_select(0x19);
    let count = u32::from_be_bytes(fw_read());
    require((1..=128).contains(&count), "workload-fw-directory");
    let mut selector = None;
    for _ in 0..count {
        let item = fw_read::<64>();
        if item[8..8 + NAME.len()] == *NAME && item[8 + NAME.len()] == 0 {
            let key = u16::from_be_bytes([item[4], item[5]]);
            require(selector.is_none() && (0x20..=0x3fff).contains(&key)
                && item[..4] == 2u32.to_be_bytes() && item[6..8] == [0; 2]
                && item[8 + NAME.len()..].iter().all(|byte| *byte == 0), "workload-fw-item");
            selector = Some(key);
        }
    }
    fw_select(selector.unwrap_or_else(|| fail("workload-fw-missing")));
    let [scenario, quantum] = fw_read::<2>();
    require(scenario <= 3 && matches!(quantum, 4 | 16), "workload-fw-selector");
    (scenario, quantum)
}

fn offers(scenario: u8, rows: &mut [Offer; MAX_JOBS]) -> usize {
    let blob = &K03_SMP_WORKLOAD_PROFILE;
    require(blob[..16] == *b"TESSRYN-ARRIVE1\0" && blob[16..19] == [8, 12, 30], "workload-profile-header");
    if scenario == 3 {
        rows[..DIRECTED.len()].copy_from_slice(&DIRECTED);
        return DIRECTED.len();
    }
    let scenario = scenario as usize;
    let start = 19 + 6 * blob[16..16 + scenario].iter().map(|n| usize::from(*n)).sum::<usize>();
    let count = usize::from(blob[16 + scenario]);
    let mut last = 0;
    for (index, row) in rows[..count].iter_mut().enumerate() {
        let at = start + 6 * index;
        let [id, domain, arrival, work, cancel, class] = blob[at..at + 6].try_into().unwrap();
        require(usize::from(id) == index + 1 && (1..=4).contains(&domain) && arrival >= last
            && (1..=64).contains(&work) && (cancel == 0 || cancel >= arrival)
            && (1..=3).contains(&class), "workload-profile-row");
        *row = Offer { id, domain, arrival, work, cancel, class };
        last = arrival;
    }
    count
}

fn job_ptr(job: usize) -> *mut JobContext {
    require(job < MAX_JOBS, "workload-job-index");
    unsafe { ptr::addr_of_mut!(JOBS).cast::<JobContext>().add(job) }
}

fn stack_phys(job: usize) -> u64 {
    unsafe { ptr::addr_of!(STACKS).cast::<Page>().add(job) as u64 }
}

fn data_phys(job: usize) -> u64 { &DATA_PAGES[job] as *const Data as u64 }

fn user_address(symbol: *const u8) -> u64 {
    let offset = symbol as u64 - ptr::addr_of!(smp_workload_program_start) as u64;
    require(offset < 4096, "workload-user-offset");
    CODE + offset
}

fn prepare_space(handoff: &crate::uefi::Handoff, job: usize, row: Offer, code: u64) {
    let stack = stack_phys(job);
    let data = data_phys(job);
    let tables = unsafe { &mut *ptr::addr_of_mut!(ROOTS).cast::<Tables<16>>().add(job) };
    let base = tables as *mut _ as u64;
    require([stack, data, base].into_iter().all(|page| page % 4096 == 0 && page >= handoff.image.start
        && page + 4096 <= handoff.image.end) && base + Tables::<16>::object_bytes() <= handoff.image.end, "workload-backings");
    tables.reset(handoff.physical_bits, base).unwrap_or_else(|_| fail("workload-root-reset"));
    tables.map_supervisor_range(crate::paging::Range { start: 0, end: crate::paging::LOW_LIMIT })
        .unwrap_or_else(|_| fail("workload-root-low"));
    for range in [handoff.image, handoff.stack, handoff.map_allocation].into_iter().chain(handoff.framebuffer) {
        tables.map_supervisor_range(range).unwrap_or_else(|_| fail("workload-root-handoff"));
    }
    for index in 0..handoff.descriptors() {
        let descriptor = handoff.descriptor(index);
        if descriptor.attributes & crate::uefi::RUNTIME != 0 {
            let range = crate::paging::Range::checked(descriptor.start, descriptor.pages * 4096).unwrap();
            tables.map_supervisor_range(range).unwrap_or_else(|_| fail("workload-root-runtime"));
        }
    }
    tables.set_hpet_uncached().unwrap_or_else(|_| fail("workload-hpet-map"));
    tables.set_lapic_uncached().unwrap_or_else(|_| fail("workload-lapic-map"));
    tables.map_trusted_code(CODE, code).unwrap_or_else(|_| fail("workload-code-map"));
    tables.map_data(STACK, stack, UserAccess::ReadWrite).unwrap_or_else(|_| fail("workload-stack-map"));
    tables.map_data(DATA, data, UserAccess::ReadWrite).unwrap_or_else(|_| fail("workload-data-map"));
    tables.validate().unwrap_or_else(|_| fail("workload-root-validation"));
    require(tables.user_leaf_count() == 3, "workload-user-leaves");
    for (virtual_page, physical, writable, executable) in [(CODE, code, false, true),
        (STACK, stack, true, false), (DATA, data, true, false)]
    {
        let entry = tables.user_translation(virtual_page).unwrap_or_else(|| fail("workload-user-map"));
        require(entry.physical == physical && entry.writable == writable && entry.executable == executable
            && entry.page_bytes == 4096, "workload-user-permissions");
    }
    let marker = SEED + u64::from(row.id);
    let step = SENTINEL + u64::from(row.id);
    let total = u64::from(row.work) * WORK_ITERATIONS;
    DATA_PAGES[job].0[1].store(marker, Ordering::Relaxed);
    let mut saved = initial();
    saved.rip = user_address(ptr::addr_of!(smp_workload_user_start));
    saved.registers[2] = marker;
    saved.registers[3] = step;
    saved.registers[8] = DATA;
    saved.registers[13] = total;
    saved.fp[160..168].copy_from_slice(&step.to_le_bytes());
    saved.fp[168..176].copy_from_slice(&marker.to_le_bytes());
    unsafe { job_ptr(job).write(JobContext { root: tables.root(), total, saved }); }
}

pub(super) fn prepare(handoff: &crate::uefi::Handoff) {
    let (scenario, quantum) = selector();
    let mut rows = [EMPTY_OFFER; MAX_JOBS];
    let count = offers(scenario, &mut rows);
    let code = ptr::addr_of!(smp_workload_program_start) as u64;
    require(code % 4096 == 0 && code >= handoff.image.start && code + 4096 <= handoff.image.end
        && ptr::addr_of!(smp_workload_program_end) as u64 == code + 4096, "workload-program-page");
    for (job, row) in rows[..count].iter().copied().enumerate() {
        prepare_space(handoff, job, row, code);
    }
    unsafe {
        ptr::addr_of_mut!(OFFERS).write(rows);
        ptr::addr_of_mut!(SELECTED).write([scenario, quantum, count as u8]);
    }
    let select = IOAPIC as *mut u32;
    let window = (IOAPIC + 0x10) as *mut u32;
    unsafe {
        select.write_volatile(1);
        require(window.read_volatile() == 0x0017_0020, "workload-ioapic-version");
        for pin in 0..REDIRECTIONS {
            select.write_volatile(0x10 + 2 * pin as u32);
            window.write_volatile(window.read_volatile() | (1 << 16));
            let masked = window.read_volatile();
            require(masked & (1 << 16) != 0, "workload-ioapic-mask");
            ptr::addr_of_mut!(RTE).cast::<u32>().add(pin).write(masked);
        }
    }
}

fn local(offset: u64) -> u32 { read(LAPIC, offset) }

fn timer_bank(base: u64) -> u32 {
    let mut timer = 0;
    for bank in 0..8 {
        let bits = local(base + bank * 16);
        if bank == u64::from(VECTOR / 32) {
            require(bits & !TIMER_BIT == 0, "workload-unexpected-timer-bank");
            timer = bits;
        } else {
            require(bits == 0, "workload-unexpected-interrupt");
        }
    }
    timer
}

fn timer_idle() {
    require(local(LVT) == MASKED && local(INITIAL) == 0 && local(CURRENT) == 0
        && timer_bank(0x100) == 0 && timer_bank(0x200) == 0, "workload-timer-idle");
}

fn calibrate() {
    write(LVT, MASKED);
    write(INITIAL, 0);
    write(DIVIDE, DIVIDE_CONFIG);
    timer_idle();
    require(local(DIVIDE) == DIVIDE_CONFIG, "workload-timer-divider");
    write(INITIAL, u32::MAX);
    let first_before = clock();
    let first_count = local(CURRENT);
    let first_after = clock();
    wait_ns(5_000_000);
    let last_before = clock();
    let last_count = local(CURRENT);
    let last_after = clock();
    require(first_before <= first_after && first_after < last_before && last_before <= last_after
        && first_count > last_count && last_count > 0, "workload-calibration-order");
    let interval = u64::from(first_count - last_count) * DIVIDER;
    require(interval + ROUNDING_NS >= elapsed(first_after, last_before)
        && interval <= elapsed(first_before, last_after) + ROUNDING_NS, "workload-calibration-rate");
    write(INITIAL, 0);
    timer_idle();
    unsafe { ptr::addr_of_mut!(CALIBRATION).write([first_before, first_after, u64::from(first_count),
        last_before, last_after, u64::from(last_count)]); }
}

pub(super) fn progress(job: usize) -> u64 { DATA_PAGES[job].0[0].load(Ordering::Acquire) }

pub(super) fn publish(command: Command) {
    require(PHASE.load(Ordering::Acquire) == IDLE && command.job < MAX_JOBS
        && command.task_slot < MAX_JOBS as u32 && command.task_generation != 0
        && command.lease_generation != 0 && command.start < command.hard
        && elapsed(command.start, command.hard) == command.grant_ns, "workload-publish-command");
    unsafe { ptr::addr_of_mut!(COMMAND).write(command); }
    PHASE.store(RUNNING, Ordering::Release);
}

pub(super) fn worker_state() -> WorkerState {
    let error = AP_ERROR.load(Ordering::Acquire);
    if error != 0 {
        let len = AP_ERROR_LEN.load(Ordering::Relaxed) as usize;
        let message = unsafe { core::slice::from_raw_parts(error as *const u8, len) };
        fail(core::str::from_utf8(message).unwrap());
    }
    // A candidate event's HPET read precedes this ordered load. If the AP is
    // closing, the BSP waits for the exact retirement before advancing policy.
    fence(Ordering::SeqCst);
    match PHASE.load(Ordering::SeqCst) {
        IDLE => WorkerState::Idle,
        RUNNING => WorkerState::Running,
        CLOSING => WorkerState::Closing,
        READY => WorkerState::Retired(unsafe { ptr::addr_of!(RECEIPT).read() }),
        _ => fail("workload-worker-phase"),
    }
}

pub(super) fn release_receipt() {
    require(PHASE.compare_exchange(READY, IDLE, Ordering::AcqRel, Ordering::Acquire).is_ok(),
        "workload-release-phase");
}

pub(super) fn park() {
    require(PHASE.compare_exchange(IDLE, PARK, Ordering::AcqRel, Ordering::Acquire).is_ok(),
        "workload-park-phase");
    wait(&PARKED, 1);
    let before: [u64; MAX_JOBS] = core::array::from_fn(progress);
    wait_ns(20_000_000);
    require(before == core::array::from_fn(progress), "workload-park-progress");
}

fn execute(command: Command) -> Receipt {
    timer_idle();
    let job = job_ptr(command.job);
    let cpu_context = context(1);
    let (root, saved) = unsafe { ((*job).root, ptr::addr_of!((*job).saved).read()) };
    require(root != 0 && saved.registers[13] <= unsafe { (*job).total }, "workload-context");
    unsafe {
        ptr::addr_of_mut!((*cpu_context).root).write(root);
        ptr::addr_of_mut!((*cpu_context).saved).write(saved);
    }
    let mut row = EMPTY_RECEIPT;
    row.command = command;
    row.root = root;
    row.resume_rip = saved.rip;
    row.progress_before = progress(command.job);
    row.initial = u32::try_from((command.grant_ns / SOFT_FRACTION).div_ceil(DIVIDER)).unwrap();
    require(row.initial > 0, "workload-timer-count");
    write(LVT, VECTOR);
    row.arm_before = clock();
    write(INITIAL, row.initial);
    row.arm_after = clock();
    let expiry = (u64::from(row.initial) + 1) * DIVIDER;
    require(row.arm_after + expiry.div_ceil(HPET_TICK_NS) + 2 < command.hard
        && local(LVT) == VECTOR && local(INITIAL) == row.initial && local(DIVIDE) == DIVIDE_CONFIG
        && timer_bank(0x100) == 0 && timer_bank(0x200) == 0, "workload-arm-window");
    row.entry = clock();
    unsafe { ptr::addr_of_mut!(ACTIVE).write(row); }
    require(row.entry < command.hard && local(CURRENT) > 0, "workload-enter-window");
    enter(1);
    // The completion interrupt may race a queued APIC timer. Drain that exact
    // source on the protected continuation before acknowledging retirement.
    if unsafe { ptr::addr_of!(DRAIN_EXPECTED).read() } {
        unsafe { asm!("sti", "nop", "cli"); }
        require(!unsafe { ptr::addr_of!(DRAIN_EXPECTED).read() }, "workload-drain-missing");
    }
    timer_idle();
    row = unsafe { ptr::addr_of!(ACTIVE).read() };
    require(row.trap >= row.entry && row.vector != 0
        && (row.progress_after > row.progress_before
            || row.vector == 128 && row.progress_after == row.progress_before),
        "workload-actual-execution");
    unsafe { ptr::addr_of_mut!((*job).saved).write(ptr::addr_of!((*cpu_context).saved).read()); }
    // The AP must publish CLOSING before sampling retirement. An observed
    // RUNNING phase lets a BSP apply its already sampled event timestamp.
    require(PHASE.load(Ordering::Acquire) == CLOSING, "workload-retire-phase");
    fence(Ordering::SeqCst);
    row.retired = clock();
    require(row.retired >= row.trap && row.retired >= row.eoi, "workload-retire-order");
    row
}

fn frame_progress(saved: &Saved, job: usize) -> (u64, u64) {
    let marker = SEED + job as u64 + 1;
    let step = SENTINEL + job as u64 + 1;
    let total = unsafe { (*job_ptr(job)).total };
    let remaining = saved.registers[13];
    let progress = progress(job);
    let checksum = saved.registers[5];
    let rip = saved.rip;
    let after_increment = rip == user_address(ptr::addr_of!(smp_workload_after_inc));
    let before_decrement = after_increment || [ptr::addr_of!(smp_workload_after_sum),
        ptr::addr_of!(smp_workload_before_dec)].into_iter().any(|pc| rip == user_address(pc));
    let at_loop = [ptr::addr_of!(smp_workload_loop), ptr::addr_of!(smp_workload_after_dec),
        ptr::addr_of!(smp_workload_complete)].into_iter().any(|pc| rip == user_address(pc));
    let complete = rip == user_address(ptr::addr_of!(smp_workload_complete_return));
    require(remaining <= total && progress <= total && progress > 0
        && progress == total - remaining + u64::from(before_decrement)
        && checksum == (progress - u64::from(after_increment)).wrapping_mul(step)
        && match saved.vector {
            67 => before_decrement || at_loop,
            128 => complete && remaining == 0 && progress == total,
            _ => false,
        }, "workload-protected-progress");
    let mut registers = [0; 15];
    registers[2] = marker;
    registers[3] = step;
    registers[5] = checksum;
    registers[8] = DATA;
    registers[13] = remaining;
    registers[14] = 0x2b;
    require(saved.registers == registers && DATA_PAGES[job].0[1].load(Ordering::Acquire) == marker,
        "workload-protected-registers");
    let mut fp = initial().fp;
    let mask = u32::from_le_bytes(saved.fp[28..32].try_into().unwrap());
    fp[28..32].copy_from_slice(&mask.to_le_bytes());
    fp[160..168].copy_from_slice(&step.to_le_bytes());
    fp[168..176].copy_from_slice(&marker.to_le_bytes());
    require(mask & 0x1f80 == 0x1f80 && saved.fp == fp, "workload-protected-fp");
    (progress, checksum)
}

pub(super) fn capture(saved: Saved, root: u64, trap: u64) {
    let mut row = unsafe { ptr::addr_of!(ACTIVE).read() };
    require(row.trap == 0 && trap >= row.entry && root == row.root && saved.error == 0
        && local(LVT) == VECTOR && local(INITIAL) == row.initial && local(DIVIDE) == DIVIDE_CONFIG,
        "workload-capture-source");
    let (progress, checksum) = frame_progress(&saved, row.command.job);
    row.progress_after = progress;
    row.checksum = checksum;
    row.trap = trap;
    row.rip = saved.rip;
    row.vector = saved.vector as u32;
    row.isr_before = timer_bank(0x100);
    let current = local(CURRENT);
    write(LVT, MASKED);
    write(INITIAL, 0);
    if row.vector == VECTOR {
        require(row.isr_before == TIMER_BIT && current == 0 && timer_bank(0x200) == 0
            && elapsed(row.arm_before, trap) + ROUNDING_NS >= u64::from(row.initial) * DIVIDER,
            "workload-authentic-timer");
        write(0xb0, 0);
        row.eoi = clock();
        require(timer_bank(0x200) == 0, "workload-timer-drain");
    } else {
        require(row.isr_before == 0, "workload-completion-isr");
        unsafe { ptr::addr_of_mut!(DRAIN_EXPECTED).write(timer_bank(0x200) == TIMER_BIT); }
    }
    row.isr_after = timer_bank(0x100);
    require(row.isr_after == 0 && local(LVT) == MASKED && local(INITIAL) == 0 && local(CURRENT) == 0,
        "workload-source-disabled");
    unsafe {
        ptr::addr_of_mut!((*context(1)).saved).write(saved);
        ptr::addr_of_mut!(ACTIVE).write(row);
    }
}

pub(super) fn begin_capture() -> u64 {
    require(id() == super::IDS[1].load(Ordering::Relaxed)
        && PHASE.compare_exchange(RUNNING, CLOSING, Ordering::SeqCst, Ordering::SeqCst).is_ok(),
        "workload-capture-phase");
    clock()
}

#[unsafe(no_mangle)]
extern "sysv64" fn smp_workload_drain() {
    require(id() == super::IDS[1].load(Ordering::Relaxed)
        && PHASE.load(Ordering::Relaxed) == CLOSING
        && unsafe { ptr::addr_of!(DRAIN_EXPECTED).read() }, "workload-drain-owner");
    let mut row = unsafe { ptr::addr_of!(ACTIVE).read() };
    require(row.vector == 128 && row.eoi == 0 && local(LVT) == MASKED && local(CURRENT) == 0
        && timer_bank(0x100) == TIMER_BIT && timer_bank(0x200) == 0, "workload-drain-source");
    write(0xb0, 0);
    row.eoi = clock();
    row.drained = 1;
    timer_idle();
    unsafe {
        ptr::addr_of_mut!(ACTIVE).write(row);
        ptr::addr_of_mut!(DRAIN_EXPECTED).write(false);
    }
}

pub(super) fn ap_run() -> ! {
    calibrate();
    CALIBRATED.store(1, Ordering::Release);
    let mut last = 0u32;
    loop {
        match PHASE.load(Ordering::Acquire) {
            RUNNING => {
                let command = unsafe { ptr::addr_of!(COMMAND).read() };
                require(last.checked_add(1) == Some(command.lease_generation), "workload-lease-generation");
                last = command.lease_generation;
                let row = execute(command);
                unsafe { ptr::addr_of_mut!(RECEIPT).write(row); }
                PHASE.store(READY, Ordering::Release);
            }
            PARK => {
                timer_idle();
                fence(Ordering::Release);
                unsafe { asm!("mov qword ptr [{ack}], 1", "2: cli", "hlt", "jmp 2b",
                    ack = in(reg) &PARKED, options(noreturn)); }
            }
            IDLE | READY => core::hint::spin_loop(),
            _ => fail("workload-worker-wait"),
        }
    }
}

fn print_hardware(offers: &[Offer]) {
    let [first_before, first_after, first_count, last_before, last_after, last_count] =
        unsafe { ptr::addr_of!(CALIBRATION).read() };
    print(format_args!("TESSRYN_K03_WORKLOAD_CAL cpu=1 divider={DIVIDER} first_before={first_before} first_after={first_after} first_count={first_count} last_before={last_before} last_after={last_after} last_count={last_count}\n"));
    print(format_args!("TESSRYN_K03_WORKLOAD_IRQ version=0x170020 redirections={REDIRECTIONS} rtes="));
    for entry in unsafe { ptr::addr_of!(RTE).read() } { print(format_args!("{entry:08x}")); }
    print(format_args!("\n"));
    let code = ptr::addr_of!(smp_workload_program_start) as u64;
    for (job, offer) in offers.iter().enumerate() {
        let tables = unsafe { &*ptr::addr_of!(ROOTS).cast::<Tables<16>>().add(job) };
        let root = tables.root();
        print(format_args!("TESSRYN_K03_WORKLOAD_ROOT job={} root={root:#x} root_end={:#x} code={code:#x} stack={:#x} data={:#x} leaves=3",
            offer.id, root + Tables::<16>::object_bytes(), stack_phys(job), data_phys(job)));
        for (name, address) in [("code", CODE), ("stack", STACK), ("data", DATA)] {
            let (_, entries) = tables.raw_walk(address).unwrap_or_else(|_| fail("workload-root-walk"));
            print(format_args!(" {name}_pte={:#x}", entries[3]));
        }
        print(format_args!("\n"));
    }
    print(format_args!("TESSRYN_K03_WORKLOAD_PAYLOAD sha256="));
    for byte in super::hash_page(code) { print(format_args!("{byte:02x}")); }
    print(format_args!("\n"));
}

pub(super) fn run() -> ! {
    wait(&CALIBRATED, 1);
    let [scenario, quantum, count] = unsafe { ptr::addr_of!(SELECTED).read() };
    let all = unsafe { &*ptr::addr_of!(OFFERS) };
    let offers = &all[..usize::from(count)];
    print_hardware(offers);
    policy::run(offers, scenario, quantum, clock())
}
