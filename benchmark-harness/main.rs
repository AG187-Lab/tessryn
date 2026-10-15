//! Host measurements of policy code and explicitly identified fixtures.
//! No native context switch, physical erasure, CPU isolation or device work executes.

mod ring;
#[cfg(test)]
mod tests;

use ring::Ring;
use std::{collections::VecDeque, hint::black_box, time::Instant};
use tessryn_memory::{Error, FrameRange, MemoryPolicy, PAGE_SIZE, Rights};

const QUEUE_CAPACITY: usize = 256;
const SCHEDULER_TASKS: usize = 32;
const FRAME_BASE: u64 = 0x10_0000;
type Policy = MemoryPolicy<2, 8, 16, 16, 32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Config {
    samples: u64,
    warmup: u64,
    iterations: u64,
    seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            samples: 100,
            warmup: 20,
            iterations: 1000,
            seed: 1,
        }
    }
}

fn parse_config(args: &[String]) -> Result<Config, String> {
    let mut config = Config::default();
    let mut seen = [false; 4];
    if !args.len().is_multiple_of(2) {
        return Err("each flag requires an integer value".into());
    }
    for pair in args.chunks_exact(2) {
        let index = match pair[0].as_str() {
            "--samples" => 0,
            "--warmup" => 1,
            "--iterations" => 2,
            "--seed" => 3,
            _ => return Err("unknown benchmark flag".into()),
        };
        if seen[index] {
            return Err("duplicate benchmark flag".into());
        }
        seen[index] = true;
        if pair[1].is_empty() || !pair[1].bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("benchmark values must be unsigned decimal integers".into());
        }
        let value = pair[1]
            .parse::<u64>()
            .map_err(|_| "benchmark integer overflows u64")?;
        match index {
            0 => config.samples = value,
            1 => config.warmup = value,
            2 => config.iterations = value,
            3 => config.seed = value,
            _ => unreachable!(),
        }
    }
    if !(1..=10_000).contains(&config.samples)
        || config.warmup > 10_000
        || !(1..=1_000_000).contains(&config.iterations)
    {
        return Err("benchmark configuration exceeds its registered bounds".into());
    }
    let rounds = u128::from(config.samples + config.warmup);
    let iterations = u128::from(config.iterations);
    let operations = rounds
        * (iterations * 308
            + if cfg!(scheduler_core) {
                iterations * 2 + 1
            } else {
                0
            });
    let bytes = rounds * iterations * (2 * (4096 + 65_536));
    if operations > 200_000_000 || bytes > 30_000_000_000 {
        return Err("combined benchmark work exceeds its registered bounds".into());
    }
    Ok(config)
}

#[derive(Clone, Debug)]
struct Sample {
    case: &'static str,
    implementation: &'static str,
    sample_index: u64,
    elapsed_ns: u64,
    operations: u64,
    checksum: u64,
    batch_size: u64,
    bytes_per_operation: u64,
    sample_unit: &'static str,
}

fn measured(action: impl FnOnce() -> u64) -> (u64, u64) {
    let start = Instant::now();
    let checksum = action();
    let end = Instant::now();
    let elapsed = end
        .checked_duration_since(start)
        .expect("host clock regressed")
        .as_nanos();
    (
        u64::try_from(elapsed).expect("a batch duration must fit u64"),
        black_box(checksum),
    )
}

fn policy() -> Policy {
    let mut policy = Policy::new(36, &[]).expect("fixed physical-width fixture");
    policy
        .add_free_extent(FrameRange::new(FRAME_BASE, 64).unwrap())
        .unwrap();
    policy.create_domain(1, 64).unwrap();
    policy.create_domain(2, 64).unwrap();
    policy
}

fn next_random(state: &mut u64) -> u64 {
    // SplitMix64 works for seed zero and never depends on host randomness.
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn ring_self_check() {
    let mut ring = Ring::<QUEUE_CAPACITY>::new();
    assert_eq!(ring.pop(), None);
    for value in 0..QUEUE_CAPACITY as u64 {
        ring.push(value).unwrap();
    }
    let before = ring.clone();
    assert_eq!(ring.push(999), Err(999));
    assert_eq!(ring, before, "full rejection must not mutate the queue");
    for value in 0..QUEUE_CAPACITY as u64 {
        assert_eq!(ring.pop(), Some(value));
    }
    for value in 0..1000 {
        ring.push(value).unwrap();
        assert_eq!(ring.pop(), Some(value));
    }
    assert_eq!(ring.len(), 0);
    let before = ring.clone();
    assert_eq!(ring.pop(), None);
    assert_eq!(ring, before, "empty rejection must not mutate the queue");

    let mut reference = VecDeque::new();
    let mut random = 0x5eed;
    for _ in 0..8192 {
        let value = next_random(&mut random);
        if value & 1 == 0 {
            let expected = if reference.len() == QUEUE_CAPACITY {
                Err(value)
            } else {
                reference.push_back(value);
                Ok(())
            };
            assert_eq!(ring.push(value), expected);
        } else {
            assert_eq!(ring.pop(), reference.pop_front());
        }
        assert_eq!(ring.len(), reference.len());
    }
    while let Some(value) = reference.pop_front() {
        assert_eq!(ring.pop(), Some(value));
    }
    assert_eq!(ring.pop(), None);
}

fn memory_self_check() {
    let mut state = policy();
    let handle = state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap();
    assert_eq!(
        state.authorize(2, handle, Rights::READ, 0, 1),
        Err(Error::InvalidAuthority)
    );
    assert_eq!(
        state.authorize(1, handle, Rights::READ, PAGE_SIZE, 1),
        Err(Error::Bounds)
    );
    assert_eq!(
        state
            .authorize(1, handle, Rights::READ, 0, 1)
            .unwrap()
            .physical_start,
        FRAME_BASE
    );
    state.revoke(1, handle).unwrap();
    assert_eq!(
        state.authorize(1, handle, Rights::READ, 0, 1),
        Err(Error::Revoked)
    );
    state.release_capability(1, handle).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    assert_eq!(state.frames().available_pages(), 64);
    assert_eq!(state.frames().allocated_pages(), 0);
}

fn byte_self_check() {
    for length in [4096, 65_536] {
        let source: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
        let mut destination = vec![0xa5; length];
        destination.fill(0);
        assert!(destination.iter().all(|byte| *byte == 0));
        destination.copy_from_slice(&source);
        assert_eq!(destination, source);
    }
}

fn self_checks() -> Vec<&'static str> {
    ring_self_check();
    memory_self_check();
    byte_self_check();
    let checks = vec![
        "ring_full_empty_wrap_fifo",
        "ring_matches_vecdeque_replay",
        "memory_rejects_foreign_bounds_revoked",
        "memory_lifecycle_drained",
        "host_zero_and_copy_exact",
        "benchmark_operations_exact",
        "scheduler_reference_round_robin",
    ];
    #[cfg(scheduler_core)]
    {
        scheduler_policy_self_check();
        let mut checks = checks;
        checks.push("scheduler_policy_reservations_stops_and_denials");
        checks.push("scheduler_logical_replay_exact");
        checks
    }
    #[cfg(not(scheduler_core))]
    {
        checks
    }
}

fn sample(
    case: &'static str,
    implementation: &'static str,
    index: u64,
    operations: u64,
    batch: u64,
    bytes: u64,
    result: (u64, u64),
) -> Sample {
    Sample {
        case,
        implementation,
        sample_index: index,
        elapsed_ns: result.0,
        operations,
        checksum: result.1,
        batch_size: batch,
        bytes_per_operation: bytes,
        sample_unit: "timed_batch",
    }
}

fn timer_samples(config: Config, index: u64, output: &mut Vec<Sample>) {
    let empty = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            checksum = checksum.wrapping_add(black_box(iteration));
        }
        checksum
    });
    output.push(sample(
        "empty_harness",
        "host_loop_reference",
        index,
        config.iterations,
        1,
        0,
        empty,
    ));
    let clock = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            let start = black_box(Instant::now());
            let end = black_box(Instant::now());
            black_box(
                end.checked_duration_since(start)
                    .expect("host clock regressed"),
            );
            checksum = checksum.wrapping_add(black_box(iteration));
        }
        checksum
    });
    output.push(sample(
        "timer_pair",
        "host_clock_probe",
        index,
        config.iterations,
        1,
        0,
        clock,
    ));
}

fn scheduler_reference(config: Config, index: u64) -> Sample {
    let mut ready = Ring::<QUEUE_CAPACITY>::new();
    for task in 0..SCHEDULER_TASKS as u64 {
        ready.push(task).unwrap();
    }
    let result = measured(|| {
        let mut checksum = config.seed;
        for _ in 0..config.iterations {
            let task = black_box(&mut ready).pop().expect("ready fixture task");
            checksum = checksum.wrapping_add(black_box(task));
            black_box(&mut ready).push(black_box(task)).unwrap();
        }
        checksum
    });
    assert_eq!(ready.len(), SCHEDULER_TASKS);
    for offset in 0..SCHEDULER_TASKS as u64 {
        assert_eq!(
            ready.pop(),
            Some((config.iterations + offset) % SCHEDULER_TASKS as u64)
        );
    }
    sample(
        "scheduler_reference_dispatch_cycle",
        "bounded_round_robin_fixture",
        index,
        config.iterations * 2,
        1,
        0,
        result,
    )
}

fn queue_roundtrip(config: Config, index: u64, batch: usize, reference: bool) -> Sample {
    let mut ring = Ring::<QUEUE_CAPACITY>::new();
    let mut deque = VecDeque::with_capacity(QUEUE_CAPACITY);
    let result = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            for offset in 0..batch as u64 {
                let value = black_box(config.seed.wrapping_add(iteration * batch as u64 + offset));
                if reference {
                    black_box(&mut deque).push_back(value);
                } else {
                    black_box(&mut ring).push(value).unwrap();
                }
            }
            for _ in 0..batch {
                let value = if reference {
                    black_box(&mut deque).pop_front().unwrap()
                } else {
                    black_box(&mut ring).pop().unwrap()
                };
                checksum = checksum.wrapping_add(black_box(value));
            }
        }
        checksum
    });
    assert_eq!(ring.len(), 0);
    assert!(deque.is_empty());
    let case = match batch {
        1 => "queue_roundtrip_batch_1",
        8 => "queue_roundtrip_batch_8",
        64 => "queue_roundtrip_batch_64",
        _ => unreachable!(),
    };
    sample(
        case,
        if reference {
            "vec_deque_reference"
        } else {
            "bounded_ring"
        },
        index,
        config.iterations * 2 * batch as u64,
        batch as u64,
        0,
        result,
    )
}

fn queue_rejection(config: Config, index: u64, full: bool, reference: bool) -> Sample {
    let mut ring = Ring::<QUEUE_CAPACITY>::new();
    let mut deque = VecDeque::with_capacity(QUEUE_CAPACITY);
    if full {
        for value in 0..QUEUE_CAPACITY as u64 {
            ring.push(value).unwrap();
            deque.push_back(value);
        }
    }
    let result = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            let rejected = if full {
                let value = black_box(iteration);
                if reference {
                    let queue = black_box(&mut deque);
                    if queue.len() == QUEUE_CAPACITY {
                        true
                    } else {
                        queue.push_back(value);
                        false
                    }
                } else {
                    black_box(&mut ring).push(value).is_err()
                }
            } else if reference {
                black_box(&mut deque).pop_front().is_none()
            } else {
                black_box(&mut ring).pop().is_none()
            };
            checksum = checksum.wrapping_add(u64::from(black_box(rejected)));
        }
        checksum
    });
    assert_eq!(result.1, config.seed.wrapping_add(config.iterations));
    assert_eq!(ring.len(), if full { QUEUE_CAPACITY } else { 0 });
    assert_eq!(deque.len(), if full { QUEUE_CAPACITY } else { 0 });
    if full {
        for value in 0..QUEUE_CAPACITY as u64 {
            assert_eq!(ring.pop(), Some(value));
            assert_eq!(deque.pop_front(), Some(value));
        }
    }
    sample(
        if full {
            "queue_full_rejection"
        } else {
            "queue_empty_rejection"
        },
        if reference {
            "vec_deque_reference"
        } else {
            "bounded_ring"
        },
        index,
        config.iterations,
        1,
        0,
        result,
    )
}

fn memory_samples(config: Config, index: u64, output: &mut Vec<Sample>) {
    let mut state = policy();
    let lifecycle = measured(|| {
        let mut checksum = config.seed;
        for _ in 0..config.iterations {
            // Metadata-only fixture. No physical memory exists at FRAME_BASE.
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
            checksum = checksum.wrapping_add(u64::from(black_box(handle).generation));
            black_box(&mut state)
                .revoke(black_box(1), black_box(handle))
                .unwrap();
            black_box(&mut state)
                .release_capability(black_box(1), black_box(handle))
                .unwrap();
        }
        checksum
    });
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    assert_eq!(state.frames().available_pages(), 64);
    assert_eq!(state.frames().allocated_pages(), 0);
    output.push(sample(
        "memory_allocate_revoke_release",
        "tessryn_memory_policy_metadata",
        index,
        config.iterations * 3,
        1,
        0,
        lifecycle,
    ));

    let mut state = policy();
    let handle = state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap();
    let access = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            let view = black_box(&state)
                .authorize(
                    black_box(1),
                    black_box(handle),
                    black_box(Rights::READ),
                    black_box(iteration % PAGE_SIZE),
                    black_box(1),
                )
                .unwrap();
            checksum = checksum.wrapping_add(black_box(view.physical_start));
        }
        checksum
    });
    state.revoke(1, handle).unwrap();
    state.release_capability(1, handle).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    output.push(sample(
        "memory_access_check",
        "tessryn_memory_policy_metadata",
        index,
        config.iterations,
        1,
        0,
        access,
    ));
}

fn byte_sample(config: Config, index: u64, bytes: usize, copy: bool) -> Sample {
    let source: Vec<u8> = (0..bytes)
        .map(|offset| ((offset as u64 + config.seed % 251) % 251) as u8)
        .collect();
    let mut destination = vec![0xa5; bytes];
    let result = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            if copy {
                black_box(destination.as_mut_slice()).copy_from_slice(black_box(source.as_slice()));
            } else {
                black_box(destination.as_mut_slice()).fill(black_box(0));
            }
            checksum = checksum.wrapping_add(u64::from(black_box(
                destination[(iteration as usize) % bytes],
            )));
        }
        checksum
    });
    if copy {
        assert_eq!(destination, source);
    } else {
        assert!(destination.iter().all(|byte| *byte == 0));
    }
    let case = match (copy, bytes) {
        (false, 4096) => "host_zero_4096",
        (false, 65_536) => "host_zero_65536",
        (true, 4096) => "host_copy_4096",
        (true, 65_536) => "host_copy_65536",
        _ => unreachable!(),
    };
    sample(
        case,
        "host_byte_buffer",
        index,
        config.iterations,
        1,
        bytes as u64,
        result,
    )
}

fn run_benchmarks(config: Config) -> Vec<Sample> {
    let mut samples = Vec::with_capacity(config.samples as usize * cases_per_round());
    for ordinal in 0..config.warmup + config.samples {
        let mut round = Vec::with_capacity(cases_per_round());
        let index = ordinal.saturating_sub(config.warmup);
        timer_samples(config, index, &mut round);
        round.push(scheduler_reference(config, index));
        #[cfg(scheduler_core)]
        {
            round.push(scheduler_policy_dispatch(config, index));
            round.push(scheduler_policy_cycle(config, index));
        }
        for batch in [1, 8, 64] {
            // Alternate paired implementation order to reduce a consistent order bias.
            for reference in if (ordinal ^ config.seed) & 1 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                round.push(queue_roundtrip(config, index, batch, reference));
            }
        }
        for full in [false, true] {
            for reference in [false, true] {
                round.push(queue_rejection(config, index, full, reference));
            }
        }
        memory_samples(config, index, &mut round);
        for bytes in [4096, 65_536] {
            for copy in [false, true] {
                round.push(byte_sample(config, index, bytes, copy));
            }
        }
        if ordinal >= config.warmup {
            samples.extend(round);
        }
    }
    samples
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadyEpisode {
    task: &'static str,
    ready_ns: u64,
    dispatch_ns: u64,
    delay_ns: u64,
    dispatch_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalOutcome {
    task: &'static str,
    status: &'static str,
    completed_ns: Option<u64>,
    consumed_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalReplay {
    episodes: Vec<ReadyEpisode>,
    outcomes: Vec<LogicalOutcome>,
}

fn render_json(
    config: Config,
    samples: &[Sample],
    checks: &[&str],
    replay: Option<&LogicalReplay>,
) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    write!(output, "{{\"schema_version\":1,\"kind\":\"kernel_benchmark_raw\",\"clock\":\"std::time::Instant\",\"config\":{{\"samples\":{},\"warmup\":{},\"iterations\":{},\"seed\":{}}},\"samples\":[",
        config.samples, config.warmup, config.iterations, config.seed).unwrap();
    for (index, item) in samples.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(output, "{{\"case\":\"{}\",\"implementation\":\"{}\",\"sample_index\":{},\"elapsed_ns\":{},\"operations\":{},\"checksum\":{},\"batch_size\":{},\"bytes_per_operation\":{},\"sample_unit\":\"{}\"}}",
            item.case, item.implementation, item.sample_index, item.elapsed_ns, item.operations,
            item.checksum, item.batch_size, item.bytes_per_operation, item.sample_unit).unwrap();
    }
    output.push_str("],\"checks\":[");
    for (index, check) in checks.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(output, "\"{check}\"").unwrap();
    }
    output.push_str("],\"logical_replay\":");
    if let Some(replay) = replay {
        output.push_str("{\"kind\":\"scheduler_logical_replay\",\"clock\":\"synthetic_logical_ns\",\"quantum_ns\":2,\"episodes\":[");
        for (index, episode) in replay.episodes.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            write!(output, "{{\"task\":\"{}\",\"ready_ns\":{},\"dispatch_ns\":{},\"delay_ns\":{},\"dispatch_index\":{}}}",
                episode.task, episode.ready_ns, episode.dispatch_ns, episode.delay_ns, episode.dispatch_index).unwrap();
        }
        output.push_str("],\"outcomes\":[");
        for (index, outcome) in replay.outcomes.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            write!(
                output,
                "{{\"task\":\"{}\",\"status\":\"{}\",\"completed_ns\":",
                outcome.task, outcome.status
            )
            .unwrap();
            if let Some(time) = outcome.completed_ns {
                write!(output, "{time}").unwrap();
            } else {
                output.push_str("null");
            }
            write!(output, ",\"consumed_ns\":{}}}", outcome.consumed_ns).unwrap();
        }
        output.push_str("]}");
    } else {
        output.push_str("null");
    }
    output.push_str("}\n");
    output
}

const fn cases_per_round() -> usize {
    #[cfg(scheduler_core)]
    {
        21
    }
    #[cfg(not(scheduler_core))]
    {
        19
    }
}

#[cfg(scheduler_core)]
type Scheduler = tessryn_scheduler::Scheduler<2, SCHEDULER_TASKS, 1>;

#[cfg(scheduler_core)]
fn scheduler_policy(iterations: u64) -> Scheduler {
    let mut policy = Scheduler::new().unwrap();
    let budget = iterations.checked_mul(2).unwrap().checked_add(64).unwrap();
    policy.add_domain(1, budget).unwrap();
    policy.add_domain(2, budget).unwrap();
    for task in 0..SCHEDULER_TASKS {
        policy
            .create_task(
                1 + task as u64 % 2,
                tessryn_scheduler::TaskSpec {
                    budget_ns: budget,
                    deadline_ns: 0,
                },
                0,
            )
            .unwrap();
    }
    policy
}

#[cfg(scheduler_core)]
fn scheduler_policy_self_check() {
    use tessryn_scheduler::{Error, StopOutcome, TaskState};
    let mut policy = scheduler_policy(64);
    for iteration in 0..64 {
        let dispatch = policy.dispatch(0, 1, iteration).unwrap();
        assert_eq!(
            dispatch.task.slot(),
            (iteration % SCHEDULER_TASKS as u64) as u32
        );
        assert_eq!(dispatch.grant_ns, 1);
        assert_eq!(
            policy
                .accounting(dispatch.task.domain())
                .unwrap()
                .budget
                .reserved_ns,
            1
        );
        assert_eq!(policy.dispatch(0, 1, iteration), Err(Error::CpuBusy));
        assert_eq!(
            policy
                .stop(dispatch.lease, iteration + 1, StopOutcome::Yield)
                .unwrap(),
            TaskState::Runnable
        );
        assert_eq!(
            policy.stop(dispatch.lease, iteration + 1, StopOutcome::Yield),
            Err(Error::StaleLease)
        );
        assert_eq!(policy.cpu_lease(0).unwrap(), None);
        assert_eq!(
            policy
                .accounting(dispatch.task.domain())
                .unwrap()
                .budget
                .reserved_ns,
            0
        );
    }
    for domain in [1, 2] {
        assert_eq!(policy.accounting(domain).unwrap().budget.consumed_ns, 32);
        assert!(!policy.accounting(domain).unwrap().halted);
    }
}

#[cfg(scheduler_core)]
fn scheduler_policy_dispatch(config: Config, index: u64) -> Sample {
    let mut policy = scheduler_policy(1);
    let start = Instant::now();
    let dispatch = black_box(&mut policy)
        .dispatch(black_box(0), black_box(1), black_box(0))
        .unwrap();
    let end = Instant::now();
    let elapsed = end
        .checked_duration_since(start)
        .expect("host clock regressed")
        .as_nanos();
    let checksum = config
        .seed
        .wrapping_add(u64::from(black_box(dispatch.task.slot())));
    policy
        .stop(dispatch.lease, 1, tessryn_scheduler::StopOutcome::Yield)
        .unwrap();
    assert_eq!(policy.cpu_lease(0).unwrap(), None);
    let mut sample = sample(
        "scheduler_policy_dispatch_latency",
        "tessryn_scheduler_policy",
        index,
        1,
        1,
        0,
        (u64::try_from(elapsed).unwrap(), checksum),
    );
    sample.sample_unit = "single_operation";
    sample
}

#[cfg(scheduler_core)]
fn scheduler_policy_cycle(config: Config, index: u64) -> Sample {
    let mut policy = scheduler_policy(config.iterations);
    let result = measured(|| {
        let mut checksum = config.seed;
        for iteration in 0..config.iterations {
            let dispatch = black_box(&mut policy)
                .dispatch(black_box(0), black_box(1), black_box(iteration))
                .unwrap();
            checksum = checksum.wrapping_add(u64::from(black_box(dispatch.task.slot())));
            black_box(&mut policy)
                .stop(
                    black_box(dispatch.lease),
                    black_box(iteration + 1),
                    black_box(tessryn_scheduler::StopOutcome::Yield),
                )
                .unwrap();
        }
        checksum
    });
    assert_eq!(policy.cpu_lease(0).unwrap(), None);
    let first = policy.accounting(1).unwrap();
    let second = policy.accounting(2).unwrap();
    assert_eq!(first.budget.reserved_ns + second.budget.reserved_ns, 0);
    assert_eq!(
        first.budget.consumed_ns + second.budget.consumed_ns,
        u128::from(config.iterations)
    );
    assert!(!first.halted && !second.halted);
    sample(
        "scheduler_policy_dispatch_stop_cycle",
        "tessryn_scheduler_policy",
        index,
        config.iterations * 2,
        1,
        0,
        result,
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_config(&args).unwrap_or_else(|error| {
        eprintln!("kernel benchmark: {error}");
        std::process::exit(2);
    });
    let checks = self_checks();
    #[cfg(scheduler_core)]
    let replay = Some(scheduler_logical_replay());
    #[cfg(not(scheduler_core))]
    let replay = None;
    let samples = run_benchmarks(config);
    print!(
        "{}",
        render_json(config, &samples, &checks, replay.as_ref())
    );
}

#[cfg(scheduler_core)]
struct ReplayJob {
    name: &'static str,
    domain: u64,
    arrival: u64,
    work: u64,
    deadline: u64,
    remaining: u64,
    task: Option<tessryn_scheduler::TaskId>,
    ready: Option<u64>,
    outcome: Option<LogicalOutcome>,
}

#[cfg(scheduler_core)]
impl ReplayJob {
    fn new(name: &'static str, domain: u64, arrival: u64, work: u64, deadline: u64) -> Self {
        Self {
            name,
            domain,
            arrival,
            work,
            deadline,
            remaining: work,
            task: None,
            ready: None,
            outcome: None,
        }
    }
}

#[cfg(scheduler_core)]
fn admit_replay_arrival(policy: &mut Scheduler, job: &mut ReplayJob) {
    assert!(job.task.is_none());
    job.task = Some(
        policy
            .create_task(
                job.domain,
                tessryn_scheduler::TaskSpec {
                    budget_ns: job.work + 16,
                    deadline_ns: job.deadline,
                },
                job.arrival,
            )
            .unwrap(),
    );
    job.ready = Some(job.arrival);
}

#[cfg(scheduler_core)]
fn observe_replay_expiry(policy: &Scheduler, jobs: &mut [ReplayJob]) {
    for job in jobs
        .iter_mut()
        .filter(|job| job.task.is_some() && job.outcome.is_none())
    {
        let info = policy.task(job.domain, job.task.unwrap()).unwrap();
        if info.state == tessryn_scheduler::TaskState::DeadlineExpired {
            assert_eq!(info.cpu, None);
            assert_eq!(info.budget.reserved_ns, 0);
            job.ready = None;
            job.outcome = Some(LogicalOutcome {
                task: job.name,
                status: "deadline_expired",
                completed_ns: None,
                consumed_ns: u64::try_from(info.budget.consumed_ns).unwrap(),
            });
        }
    }
}

#[cfg(scheduler_core)]
fn scheduler_logical_replay() -> LogicalReplay {
    use tessryn_scheduler::{StopOutcome, TaskState};
    let mut policy = Scheduler::new().unwrap();
    for domain in [1, 2] {
        policy.add_domain(domain, 64).unwrap();
    }
    let mut jobs = [
        ReplayJob::new("short", 1, 0, 3, 0),
        ReplayJob::new("long", 2, 0, 8, 0),
        ReplayJob::new("burst", 1, 3, 2, 0),
        ReplayJob::new("expires", 2, 7, 5, 8),
    ];
    let mut episodes = Vec::new();
    let mut now = 0;
    loop {
        // A completed stop precedes admission at the same timestamp. Arrivals
        // strictly inside a slice are admitted while the CPU lease is retained.
        for job in jobs
            .iter_mut()
            .filter(|job| job.task.is_none() && job.arrival <= now)
        {
            admit_replay_arrival(&mut policy, job);
        }
        policy.advance(now).unwrap();
        observe_replay_expiry(&policy, &mut jobs);
        if jobs.iter().all(|job| job.outcome.is_some()) {
            break;
        }
        let dispatch = policy.dispatch(0, 2, now).unwrap();
        let job_index = jobs
            .iter()
            .position(|job| job.task == Some(dispatch.task))
            .unwrap();
        let ready = jobs[job_index]
            .ready
            .take()
            .expect("selected task must have a readiness episode");
        episodes.push(ReadyEpisode {
            task: jobs[job_index].name,
            ready_ns: ready,
            dispatch_ns: now,
            delay_ns: now.checked_sub(ready).unwrap(),
            dispatch_index: episodes.len() as u64,
        });
        let used = dispatch.grant_ns.min(jobs[job_index].remaining);
        let stopped_at = now + used;
        for job in jobs
            .iter_mut()
            .filter(|job| job.task.is_none() && job.arrival < stopped_at)
        {
            assert!(job.arrival >= now);
            assert_eq!(policy.cpu_lease(0).unwrap(), Some(dispatch.lease));
            admit_replay_arrival(&mut policy, job);
            assert_eq!(policy.cpu_lease(0).unwrap(), Some(dispatch.lease));
        }
        jobs[job_index].remaining -= used;
        let finished = jobs[job_index].remaining == 0;
        let state = policy
            .stop(
                dispatch.lease,
                stopped_at,
                if finished {
                    StopOutcome::Complete
                } else {
                    StopOutcome::Yield
                },
            )
            .unwrap();
        assert_eq!(policy.cpu_lease(0).unwrap(), None);
        assert_eq!(
            policy
                .accounting(jobs[job_index].domain)
                .unwrap()
                .budget
                .reserved_ns,
            0
        );
        if finished {
            assert_eq!(state, TaskState::Completed);
            let job = &mut jobs[job_index];
            let consumed = policy
                .task(job.domain, job.task.unwrap())
                .unwrap()
                .budget
                .consumed_ns;
            assert_eq!(consumed, u128::from(job.work));
            job.outcome = Some(LogicalOutcome {
                task: job.name,
                status: "completed",
                completed_ns: Some(stopped_at),
                consumed_ns: u64::try_from(consumed).unwrap(),
            });
        } else {
            assert_eq!(state, TaskState::Runnable);
            jobs[job_index].ready = Some(stopped_at);
        }
        now = stopped_at;
        observe_replay_expiry(&policy, &mut jobs);
    }
    for (domain, expected_consumed) in [(1, 5), (2, 8)] {
        let account = policy.accounting(domain).unwrap();
        assert_eq!(account.budget.consumed_ns, expected_consumed);
        assert_eq!(account.budget.reserved_ns, 0);
        assert!(!account.halted);
    }
    assert_eq!(now, 13);
    LogicalReplay {
        episodes,
        outcomes: jobs.into_iter().map(|job| job.outcome.unwrap()).collect(),
    }
}
