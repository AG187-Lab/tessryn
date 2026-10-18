//! Fixed two-CPU kernel fixture. Raw BSP HPET batch completion, not hardware
//! cache coherence, individual-operation latency, scheduler or inference proof.
use core::hint::{black_box, spin_loop};
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

const SAMPLES: usize = 16;
const WARMUP: usize = 4;
const ITERATIONS: u64 = 1024;
const CASES: usize = 6;
const ROUNDS: usize = CASES * (SAMPLES + WARMUP);
const WAIT_TICKS: u64 = 200_000_000; // Two seconds at the admitted HPET period.
const MAX_POLLS: u64 = 20_000_000;
const HPET_COUNTER: *const u64 = 0xfed0_00f0 as *const u64;
#[repr(C)]
pub struct BenchmarkContract { magic: [u8; 16], words: [u64; 10] }
#[used]
#[unsafe(no_mangle)]
pub static CONTENTION_BENCHMARK_CONTRACT: BenchmarkContract = BenchmarkContract {
    magic: *b"TESSRYN-CBENCH1\0",
    words: [1, CASES as u64, SAMPLES as u64, WARMUP as u64, ITERATIONS, 64,
        10_000_000, WAIT_TICKS, MAX_POLLS, ROUNDS as u64],
};

#[repr(C, align(64))]
struct Line(AtomicU64);
#[repr(C, align(64))]
struct Pair { bsp: AtomicU64, ap: AtomicU64 }
const _: () = {
    assert!(size_of::<Line>() == 64 && align_of::<Line>() == 64);
    assert!(size_of::<Pair>() == 64 && align_of::<Pair>() == 64);
    assert!(core::mem::offset_of!(Pair, ap) == 8);
};
static COMMAND: Line = Line(AtomicU64::new(0));
static READY: Line = Line(AtomicU64::new(0));
static GO: Line = Line(AtomicU64::new(0));
static DONE: Line = Line(AtomicU64::new(0));
static FINISHED: Line = Line(AtomicU64::new(0));
static BSP: Line = Line(AtomicU64::new(0));
static AP: Line = Line(AtomicU64::new(0));
static FALSE: Pair = Pair { bsp: AtomicU64::new(0), ap: AtomicU64::new(0) };
static SHARED: Line = Line(AtomicU64::new(0));
static PING: Line = Line(AtomicU64::new(0));
static AP_COUNT: Line = Line(AtomicU64::new(0));

#[derive(Clone, Copy)]
struct Record { start: u64, end: u64, bsp: u64, ap: u64, shared: u64, ping: u64, checksum: u64 }
const EMPTY: Record = Record { start: 0, end: 0, bsp: 0, ap: 0, shared: 0, ping: 0, checksum: 0 };
static mut RECORDS: [[Record; SAMPLES + WARMUP]; CASES] = [[EMPTY; SAMPLES + WARMUP]; CASES];
const NAMES: [&str; CASES] = ["counter_pair", "local_atomic_reference", "separate_64b_lines", "same_64b_line", "shared_atomic_counter", "ping_pong_roundtrip"];

fn clock() -> u64 { unsafe { HPET_COUNTER.read_volatile() } }
fn reject(ap: bool) -> ! {
    if ap { crate::smp::smp_ap_fail(); }
    crate::diagnostics::fail("contention-protocol")
}
fn ensure(ok: bool, ap: bool) { if !ok { reject(ap); } }
fn wait(value: &AtomicU64, wanted: u64, error: &AtomicU64, ap: bool) {
    let start = clock();
    let mut previous = start;
    for _ in 0..MAX_POLLS {
        ensure(error.load(Ordering::Acquire) == 0, ap);
        if value.load(Ordering::Acquire) == wanted { return; }
        let now = clock();
        ensure(now >= previous && now.checked_sub(start).is_some_and(|ticks| ticks < WAIT_TICKS), ap);
        previous = now;
        spin_loop();
    }
    // A stopped counter cannot turn a stalled peer into an unbounded wait.
    reject(ap)
}

fn work(case: usize, ap: bool, error: &AtomicU64) -> u64 {
    if case == 0 || case == 1 && ap { return 0; }
    let mut completed = 0u64;
    for index in 0..ITERATIONS {
        match case {
            1 | 2 => (if ap { &AP.0 } else { &BSP.0 }).fetch_add(1, Ordering::SeqCst),
            3 => (if ap { &FALSE.ap } else { &FALSE.bsp }).fetch_add(1, Ordering::SeqCst),
            4 => SHARED.0.fetch_add(1, Ordering::SeqCst),
            5 => {
                let odd = 2 * index + 1;
                if ap {
                    wait(&PING.0, odd, error, true);
                    PING.0.store(odd + 1, Ordering::Release);
                } else {
                    PING.0.store(odd, Ordering::Release);
                    wait(&PING.0, odd + 1, error, false);
                }
                0
            }
            _ => reject(ap),
        };
        completed += 1;
    }
    black_box(completed)
}

/// AP remains on its already owned kernel stack; it never writes serial or
/// non-atomic sample storage and performs exactly the fixed command schedule.
pub fn ap_run(error: &AtomicU64) {
    for ordinal in 0..ROUNDS {
        let generation = ordinal as u64 + 1;
        let case = ordinal / (SAMPLES + WARMUP);
        wait(&COMMAND.0, generation, error, true);
        READY.0.store(generation, Ordering::Release);
        wait(&GO.0, generation, error, true);
        AP_COUNT.0.store(work(case, true, error), Ordering::Relaxed);
        DONE.0.store(generation, Ordering::Release);
    }
    FINISHED.0.store(ROUNDS as u64, Ordering::Release);
}

pub fn bsp_run(error: &AtomicU64) {
    let records = unsafe { &mut *ptr::addr_of_mut!(RECORDS) };
    let mut previous = 0;
    for (case, rows) in records.iter_mut().enumerate() {
        for ordinal in 0..WARMUP + SAMPLES {
            let generation = (case * (WARMUP + SAMPLES) + ordinal + 1) as u64;
            // The preceding acquired DONE gives exclusive reset ownership.
            for counter in [&BSP.0, &AP.0, &FALSE.bsp, &FALSE.ap, &SHARED.0, &PING.0, &AP_COUNT.0] {
                counter.store(0, Ordering::Relaxed);
            }
            let mut start = clock();
            ensure(start >= previous, false);
            COMMAND.0.store(generation, Ordering::Release);
            wait(&READY.0, generation, error, false);
            GO.0.store(generation, Ordering::Release);
            let bsp_count = work(case, false, error);
            wait(&DONE.0, generation, error, false);
            // The counter reference excludes the already completed command
            // handshake. Its two adjacent MMIO reads have no payload work.
            if case == 0 { start = clock(); }
            let end = clock();
            ensure(start >= previous && end >= start && end - start < WAIT_TICKS, false);
            previous = end;
            let ap_count = AP_COUNT.0.load(Ordering::Relaxed);
            let (bsp, ap) = match case {
                0 | 1 | 2 => (BSP.0.load(Ordering::SeqCst), AP.0.load(Ordering::SeqCst)),
                3 => (FALSE.bsp.load(Ordering::SeqCst), FALSE.ap.load(Ordering::SeqCst)),
                _ => (bsp_count, ap_count),
            };
            let shared = SHARED.0.load(Ordering::SeqCst);
            let ping = PING.0.load(Ordering::Acquire);
            ensure(bsp == if case == 0 { 0 } else { ITERATIONS }
                && bsp_count == bsp && ap == if case <= 1 { 0 } else { ITERATIONS }
                && ap_count == ap && shared == if case == 4 { 2 * ITERATIONS } else { 0 }
                && ping == if case == 5 { 2 * ITERATIONS } else { 0 }, false);
            rows[ordinal] = Record { start, end, bsp, ap, shared, ping, checksum: bsp + ap + shared + ping };
        }
    }
    wait(&FINISHED.0, ROUNDS as u64, error, false);
}

/// Called only after the unchanged original stop ACK and stable heartbeat.
pub fn emit() {
    use crate::diagnostics::print;
    print(format_args!("TESSRYN_CBENCH_BEGIN {{\"schema_version\":1,\"kind\":\"contention_benchmark\",\"samples\":16,\"warmup\":4,\"iterations\":1024,\"cases\":6,\"cpus\":2}}\n"));
    print(format_args!("TESSRYN_CBENCH_CLOCK {{\"name\":\"hpet\",\"owner\":\"bsp\",\"unit\":\"raw_ticks\",\"period_fs\":10000000,\"endpoint\":\"command_to_acquired_peer_completion\",\"cross_cpu_subtraction\":false}}\n"));
    print(format_args!("TESSRYN_CBENCH_LAYOUT {{\"assumed_line_bytes\":64,\"separate_bsp\":{},\"separate_ap\":{},\"false_bsp\":{},\"false_ap\":{},\"shared\":{},\"ping\":{}}}\n",
        ptr::addr_of!(BSP) as u64, ptr::addr_of!(AP) as u64, ptr::addr_of!(FALSE.bsp) as u64,
        ptr::addr_of!(FALSE.ap) as u64, ptr::addr_of!(SHARED) as u64, ptr::addr_of!(PING) as u64));
    let records = unsafe { &*ptr::addr_of!(RECORDS) };
    for (case, rows) in records.iter().enumerate() {
        for (index, row) in rows.iter().enumerate() {
            let generation = case * (WARMUP + SAMPLES) + index + 1;
            let operations = if case == 0 { 0 } else if case == 1 { ITERATIONS } else { 2 * ITERATIONS };
            print(format_args!("TESSRYN_CBENCH_SAMPLE {{\"case\":\"{}\",\"sample_unit\":\"{}\",\"phase\":\"{}\",\"sample_index\":{},\"generation\":{},\"start_ticks\":{},\"end_ticks\":{},\"elapsed_ticks\":{},\"operations\":{},\"round_trips\":{},\"bsp_count\":{},\"ap_count\":{},\"shared_count\":{},\"ping_turn\":{},\"checksum\":{}}}\n",
                NAMES[case], if case == 0 { "counter_pair" } else { "coordinated_batch_completion" },
                if index < WARMUP { "warmup" } else { "measured" },
                if index < WARMUP { index } else { index - WARMUP }, generation, row.start, row.end, row.end - row.start,
                operations, if case == 5 { ITERATIONS } else { 0 }, row.bsp, row.ap, row.shared, row.ping, row.checksum));
        }
    }
    print(format_args!("TESSRYN_CBENCH_CHECKS {{\"checks\":[\"exact_peer_generations\",\"exact_final_counts\",\"separate_and_shared_64b_layout\",\"bounded_waits\",\"bsp_clock_no_regression\",\"original_terminal_stop\"]}}\n"));
    print(format_args!("TESSRYN_CBENCH_END {{\"measured_samples\":96,\"warmup_samples\":24,\"warmup_excluded\":24,\"retained\":\"all\"}}\n"));
    print(format_args!("TESSRYN_CBENCH_PASS {{\"scope\":\"two_cpu_qemu_contention\",\"hardware_qualified\":false,\"inference_qualified\":false}}\n"));
}
