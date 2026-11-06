//! Scheduled arrivals on the unchanged serialized scheduler policy.
//! All timestamps are supplied virtual ticks, not elapsed host measurements.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use tessryn_scheduler::{
    CpuLease, Error, Scheduler, StopCause, StopOutcome, TaskId, TaskSpec, TaskState,
};

const MAX_INPUT_BYTES: u64 = 4096;
const MAX_JOBS: usize = 64;
const MAX_TICK: u64 = 100_000;
const MAX_WORK: u64 = 1024;
const DOMAIN_BUDGET: u64 = MAX_JOBS as u64 * MAX_WORK + 1;
type Policy = Scheduler<4, MAX_JOBS, 1>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Future,
    Ready(u64),
    Running,
    Canceling,
    Completed,
    Canceled,
}

struct Job {
    domain: u64,
    arrival: u64,
    work: u64,
    cancel: Option<u64>,
    remaining: u64,
    task: Option<TaskId>,
    phase: Phase,
}

struct Slice {
    job: usize,
    lease: CpuLease,
    start: u64,
    stop: u64,
    grant: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn integer(value: &str, minimum: u64, maximum: u64) -> io::Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("expected an unsigned decimal integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|number| (minimum..=maximum).contains(number))
        .ok_or_else(|| invalid("integer outside fixture limits"))
}

fn workload(path: &Path) -> io::Result<(u64, Vec<Job>)> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(invalid("input must be a bounded regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES || !bytes.is_ascii() {
        return Err(invalid("input must be bounded ASCII TSV"));
    }
    let input = std::str::from_utf8(&bytes).expect("validated ASCII");
    let mut lines = input.lines();
    let quantum = integer(lines.next().unwrap_or(""), 1, 64)?;
    let mut jobs = Vec::new();
    let mut previous_arrival = 0;
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        let [id, domain, arrival, work, cancel] = fields.as_slice() else {
            return Err(invalid("expected five TSV job fields"));
        };
        let id = integer(id, 1, MAX_JOBS as u64)?;
        let domain = integer(domain, 1, 4)?;
        let arrival = integer(arrival, previous_arrival, MAX_TICK)?;
        let work = integer(work, 1, MAX_WORK)?;
        let cancel = integer(cancel, 0, MAX_TICK)?;
        if id != jobs.len() as u64 + 1 || (cancel != 0 && cancel < arrival) {
            return Err(invalid("invalid job order or cancellation time"));
        }
        jobs.push(Job {
            domain,
            arrival,
            work,
            cancel: (cancel != 0).then_some(cancel),
            remaining: work,
            task: None,
            phase: Phase::Future,
        });
        previous_arrival = arrival;
    }
    if jobs.is_empty() {
        return Err(invalid("at least one job is required"));
    }
    Ok((quantum, jobs))
}

fn assert_accounting(policy: &Policy, jobs: &[Job], running: Option<&Slice>, tick: u64) {
    assert_eq!(policy.clock(), tick);
    assert_eq!(
        policy.cpu_lease(0).unwrap(),
        running.map(|slice| slice.lease)
    );
    let mut consumed = [0_u128; 4];
    let mut reserved = [0_u64; 4];
    for (index, job) in jobs.iter().enumerate() {
        if job.phase == Phase::Future {
            assert_eq!(job.task, None);
            assert_eq!(job.remaining, job.work);
            continue;
        }
        let slice = running.filter(|slice| slice.job == index);
        let state = match job.phase {
            Phase::Future => unreachable!(),
            Phase::Ready(_) => TaskState::Runnable,
            Phase::Running => TaskState::Running,
            Phase::Canceling => TaskState::Stopping(StopCause::FailureRequested),
            Phase::Completed => TaskState::Completed,
            Phase::Canceled => TaskState::Failed,
        };
        let owns_cpu = matches!(job.phase, Phase::Running | Phase::Canceling);
        assert_eq!(slice.is_some(), owns_cpu);
        let used = u128::from(job.work - job.remaining);
        let grant = slice.map_or(0, |slice| slice.grant);
        let info = policy.task(job.domain, job.task.unwrap()).unwrap();
        assert_eq!(info.state, state);
        assert_eq!(info.cpu, owns_cpu.then_some(0));
        assert_eq!(info.deadline_ns, 0);
        assert_eq!(info.budget.limit_ns, job.work);
        assert_eq!(info.budget.consumed_ns, used);
        assert_eq!(info.budget.reserved_ns, grant);
        consumed[(job.domain - 1) as usize] += used;
        reserved[(job.domain - 1) as usize] += grant;
    }
    for domain in 1..=4 {
        let info = policy.accounting(domain).unwrap();
        assert!(!info.halted);
        assert_eq!(info.budget.limit_ns, DOMAIN_BUDGET);
        assert_eq!(info.budget.consumed_ns, consumed[(domain - 1) as usize]);
        assert_eq!(info.budget.reserved_ns, reserved[(domain - 1) as usize]);
    }
}

fn replay(quantum: u64, jobs: &mut [Job], out: &mut impl Write) -> io::Result<()> {
    let mut policy = Policy::new().unwrap();
    for domain in 1..=4 {
        policy.add_domain(domain, DOMAIN_BUDGET).unwrap();
    }
    let mut cancels: Vec<_> = jobs
        .iter()
        .enumerate()
        .filter_map(|(index, job)| job.cancel.map(|tick| (tick, index)))
        .collect();
    cancels.sort_unstable();
    let bound =
        jobs.len() + cancels.len() + jobs.iter().map(|job| job.work as usize).sum::<usize>();
    let (mut next_job, mut next_cancel, mut ticks) = (0, 0, 0);
    let mut now = 0;
    let mut running: Option<Slice> = None;

    loop {
        let Some(tick) = [
            running.as_ref().map(|slice| slice.stop),
            jobs.get(next_job).map(|job| job.arrival),
            cancels.get(next_cancel).map(|&(tick, _)| tick),
        ]
        .into_iter()
        .flatten()
        .min() else {
            break;
        };
        ticks += 1;
        assert!(ticks <= bound && tick >= now);
        now = tick;

        // Stops, admissions and cancellations are processed in that order at a
        // shared timestamp. An in-slice event never acknowledges a CPU stop.
        if running.as_ref().is_some_and(|slice| slice.stop == now) {
            let slice = running.take().unwrap();
            let job = &mut jobs[slice.job];
            let elapsed = now - slice.start;
            assert_eq!(elapsed, slice.grant.min(job.remaining));
            job.remaining -= elapsed;
            let (outcome, state, phase, label) = if job.phase == Phase::Canceling {
                (
                    StopOutcome::Fail,
                    TaskState::Failed,
                    Phase::Canceled,
                    "canceled",
                )
            } else if job.remaining == 0 {
                (
                    StopOutcome::Complete,
                    TaskState::Completed,
                    Phase::Completed,
                    "completed",
                )
            } else {
                (
                    StopOutcome::Yield,
                    TaskState::Runnable,
                    Phase::Ready(now),
                    "yield",
                )
            };
            assert_eq!(policy.stop(slice.lease, now, outcome).unwrap(), state);
            job.phase = phase;
            writeln!(out, "stop\t{now}\t{}\t{label}\t{elapsed}", slice.job + 1)?;
        }
        policy.advance(now).unwrap();
        while let Some(job) = jobs.get_mut(next_job).filter(|job| job.arrival == now) {
            assert_eq!(job.phase, Phase::Future);
            job.task = Some(
                policy
                    .create_task(
                        job.domain,
                        TaskSpec {
                            budget_ns: job.work,
                            deadline_ns: 0,
                        },
                        now,
                    )
                    .unwrap(),
            );
            job.phase = Phase::Ready(now);
            next_job += 1;
            writeln!(out, "arrive\t{now}\t{next_job}")?;
        }
        while let Some(&(_, index)) = cancels.get(next_cancel).filter(|&&(tick, _)| tick == now) {
            let job = &mut jobs[index];
            let label = match job.phase {
                Phase::Ready(_) => {
                    policy.fail(job.domain, job.task.unwrap(), now).unwrap();
                    job.phase = Phase::Canceled;
                    "queued"
                }
                Phase::Running => {
                    policy.fail(job.domain, job.task.unwrap(), now).unwrap();
                    job.phase = Phase::Canceling;
                    "running"
                }
                Phase::Completed | Phase::Canceled => "terminal",
                Phase::Future | Phase::Canceling => unreachable!("invalid cancellation phase"),
            };
            next_cancel += 1;
            writeln!(out, "cancel\t{now}\t{}\t{label}", index + 1)?;
        }

        assert_accounting(&policy, jobs, running.as_ref(), now);
        if running.is_none() {
            match policy.dispatch(0, quantum, now) {
                Ok(dispatch) => {
                    let index = jobs
                        .iter()
                        .position(|job| job.task == Some(dispatch.task))
                        .unwrap();
                    let job = &mut jobs[index];
                    let Phase::Ready(ready) = job.phase else {
                        panic!("dispatch selected a non-ready job")
                    };
                    let grant = dispatch.grant_ns;
                    assert!(ready <= now && grant > 0);
                    assert_eq!(grant, quantum.min(job.remaining));
                    assert_eq!(dispatch.lease.task(), dispatch.task);
                    assert_eq!(dispatch.lease.cpu(), 0);
                    let stop = now + grant.min(job.remaining);
                    assert_eq!(dispatch.stop_by_ns, stop);
                    job.phase = Phase::Running;
                    running = Some(Slice {
                        job: index,
                        lease: dispatch.lease,
                        start: now,
                        stop,
                        grant,
                    });
                    writeln!(out, "dispatch\t{now}\t{}\t{ready}\t{grant}", index + 1)?;
                    assert_accounting(&policy, jobs, running.as_ref(), now);
                }
                Err(Error::NoRunnableTask) => {
                    assert!(jobs.iter().all(|job| !matches!(job.phase, Phase::Ready(_))))
                }
                Err(error) => panic!("unexpected dispatch error: {error:?}"),
            }
        }
    }
    assert_eq!(next_job, jobs.len());
    assert_eq!(next_cancel, cancels.len());
    assert!(running.is_none());
    assert!(
        jobs.iter()
            .all(|job| matches!(job.phase, Phase::Completed | Phase::Canceled))
    );
    assert_accounting(&policy, jobs, None, now);
    writeln!(out, "end\t{now}")
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .ok_or_else(|| invalid("expected one workload path"))?;
    if args.next().is_some() {
        return Err(invalid("expected one workload path"));
    }
    let (quantum, mut jobs) = workload(Path::new(&path))?;
    let mut out = BufWriter::new(io::stdout().lock());
    replay(quantum, &mut jobs, &mut out)?;
    out.flush()
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scheduled-arrivals fixture rejected: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
