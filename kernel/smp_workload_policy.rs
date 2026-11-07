//! BSP-owned scheduler adapter for the fixed scheduled-arrival workload.
//! The AP owns the hardware continuation and publishes protected stop receipts.
use super::{Command, Offer, Receipt, WorkerState, clock, elapsed, ensure, park,
    print, progress, publish, release_receipt, worker_state, HPET_TICK_NS, MAX_JOBS, RUN_LIMIT_NS,
    QUANTUM_UNIT_NS, TICK_NS, WORK_ITERATIONS};
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};
use crate::diagnostics::{fail, finish};
use tessryn_scheduler::{CpuLease, Dispatch, Error, Scheduler, StopCause, StopOutcome, TaskId,
    TaskSpec, TaskState};

const DOMAIN_COUNT: usize = 4;
const WORKER_SLOT: usize = 0;
const WORKER_CPU: usize = 1;
const DOMAIN_LIMIT_NS: u64 = 30_000_000_000;
const MAX_EVENTS: usize = 3072;
type Policy = Scheduler<DOMAIN_COUNT, MAX_JOBS, 1>;

#[derive(Clone, Copy)]
struct Job {
    task: Option<TaskId>,
    dispatches: u64,
    progress: u64,
}
const EMPTY_JOB: Job = Job { task: None, dispatches: 0, progress: 0 };

#[derive(Clone, Copy)]
enum Disposition { Queued, Running, Terminal }
impl Disposition {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Clone, Copy)]
enum Event {
    Offer { job: usize, due: u64, observed: u64, task: TaskId, lease: u32, progress: u64 },
    Cancel { job: usize, due: u64, observed: u64, disposition: Disposition,
        lease: u32, reserved: u64, progress: u64 },
    Dispatch { job: usize, command: Command, select_start: u64, select_done: u64 },
    Stop { job: usize, receipt: Receipt, seen: u64, reconcile_start: u64, reconciled: u64,
        outcome: &'static str, charge: u64, consumed: u128, reserved: u64 },
}

// The BSP is the sole writer and reader. Keep buffered logging off the worker
// and outside timed execution, without consuming firmware stack space.
static mut EVENTS: [Option<Event>; MAX_EVENTS] = [None; MAX_EVENTS];

struct Trace { len: usize }
impl Trace {
    fn push(&mut self, event: Event) {
        ensure(self.len < MAX_EVENTS);
        unsafe { ptr::addr_of_mut!(EVENTS).cast::<Option<Event>>().add(self.len).write(Some(event)); }
        self.len += 1;
    }

    fn print(&self, workload: &[Offer]) {
        for index in 0..self.len {
            let event = unsafe { ptr::addr_of!(EVENTS).cast::<Option<Event>>().add(index).read() };
            match event.unwrap() {
                Event::Offer { job, due, observed, task, lease, progress } => {
                    let offer = &workload[job];
                    print(format_args!("TESSRYN_K03_WORKLOAD_OFFER id={} domain={} arrival={} due={due} observed={observed} work={} cancel={} class={} slot={} task_gen={} lease={lease} progress={progress}\n",
                        offer.id, offer.domain, offer.arrival, offer.work, offer.cancel, offer.class, task.slot(), task.generation()));
                }
                Event::Cancel { job, due, observed, disposition, lease, reserved, progress } => {
                    let offer = &workload[job];
                    print(format_args!("TESSRYN_K03_WORKLOAD_CANCEL id={} domain={} tick={} due={due} observed={observed} disposition={} lease={lease} reserved_ns={reserved} progress={progress}\n",
                        offer.id, offer.domain, offer.cancel, disposition.label()));
                }
                Event::Dispatch { job, command, select_start, select_done } => {
                    let offer = &workload[job];
                    print(format_args!("TESSRYN_K03_WORKLOAD_DISPATCH id={} domain={} slot={} task_gen={} cpu={WORKER_CPU} lease={} start={} select_start={select_start} select_done={select_done} grant_ns={} hard={}\n",
                        offer.id, offer.domain, command.task_slot, command.task_generation, command.lease_generation,
                        command.start, command.grant_ns, command.hard));
                }
                Event::Stop { job, receipt: r, seen, reconcile_start, reconciled, outcome, charge, consumed, reserved } => {
                    let offer = &workload[job];
                    let c = r.command;
                    print(format_args!("TESSRYN_K03_WORKLOAD_STOP id={} domain={} slot={} task_gen={} cpu={WORKER_CPU} lease={} start={} grant_ns={} hard={} arm_before={} arm_after={} initial={} entry={} trap={} eoi={} retired={} seen={seen} reconcile_start={reconcile_start} reconciled={reconciled} progress_before={} progress_after={} checksum={} rip={} resume_rip={} root={} isr_before={} isr_after={} vector={} drained={} outcome={outcome} charged_ns={charge} consumed_ns={consumed} reserved_ns={reserved}\n",
                        offer.id, offer.domain, c.task_slot, c.task_generation, c.lease_generation, c.start,
                        c.grant_ns, c.hard, r.arm_before, r.arm_after, r.initial, r.entry, r.trap, r.eoi, r.retired,
                        r.progress_before, r.progress_after, r.checksum, r.rip, r.resume_rip, r.root,
                        r.isr_before, r.isr_after, r.vector, r.drained));
                }
            }
        }
    }
}

fn checked<T>(result: Result<T, Error>) -> T {
    result.unwrap_or_else(|error| {
        print(format_args!("TESSRYN_K03_WORKLOAD_POLICY_FAILURE error={error:?}\n"));
        ensure(false);
        unreachable!()
    })
}

fn due(epoch: u64, tick: u8) -> u64 {
    epoch.checked_add(u64::from(tick) * (TICK_NS / HPET_TICK_NS)).unwrap()
}

fn next_tick(offer: Option<&Offer>, cancel: Option<&(u8, usize)>) -> Option<u8> {
    offer.map(|offer| offer.arrival).into_iter().chain(cancel.map(|&(tick, _)| tick)).min()
}

// Keep the actual policy mutations inside the timed brackets after optimizing.
#[inline(never)]
fn reserve(policy: &mut Policy, quantum_ns: u64, now: u64) -> Result<Dispatch, Error> {
    policy.dispatch(WORKER_SLOT, quantum_ns, now)
}

#[inline(never)]
fn reconcile(policy: &mut Policy, lease: CpuLease, now: u64, outcome: StopOutcome) -> Result<TaskState, Error> {
    policy.stop(lease, now, outcome)
}

fn arrive(policy: &mut Policy, jobs: &mut [Job], workload: &[Offer], trace: &mut Trace,
    job: usize, deadline: u64, observed: u64, now_ns: u64, progress: u64,
) {
    let offer = &workload[job];
    ensure(jobs[job].task.is_none());
    let task = checked(policy.create_task(u64::from(offer.domain),
        TaskSpec { budget_ns: DOMAIN_LIMIT_NS, deadline_ns: 0 }, now_ns));
    ensure(task.slot() as usize == job && task.generation() == 1);
    jobs[job].task = Some(task);
    let lease = checked(policy.cpu_lease(WORKER_SLOT)).map_or(0, |lease| lease.generation());
    trace.push(Event::Offer { job, due: deadline, observed, task, lease, progress });
}

fn cancel(policy: &mut Policy, jobs: &[Job], workload: &[Offer], trace: &mut Trace,
    job: usize, deadline: u64, observed: u64, now_ns: u64, worker_progress: u64,
) -> Disposition {
    let domain = u64::from(workload[job].domain);
    let task = jobs[job].task.unwrap();
    let before = checked(policy.task(domain, task));
    let lease_before = checked(policy.cpu_lease(WORKER_SLOT));
    let (disposition, lease) = match before.state {
        TaskState::Runnable => {
            ensure(before.cpu.is_none() && before.budget.reserved_ns == 0);
            checked(policy.fail(domain, task, now_ns));
            ensure(checked(policy.task(domain, task)).state == TaskState::Failed);
            (Disposition::Queued, 0)
        }
        TaskState::Running => {
            let lease = lease_before.unwrap();
            ensure(lease.task() == task && before.cpu == Some(WORKER_SLOT as u32) && before.budget.reserved_ns > 0);
            checked(policy.fail(domain, task, now_ns));
            ensure(checked(policy.task(domain, task)).state == TaskState::Stopping(StopCause::FailureRequested));
            (Disposition::Running, lease.generation())
        }
        TaskState::Completed | TaskState::Failed => (Disposition::Terminal, 0),
        _ => {
            ensure(false);
            unreachable!()
        }
    };
    let after = checked(policy.task(domain, task));
    ensure(after.budget == before.budget && checked(policy.cpu_lease(WORKER_SLOT)) == lease_before);
    let observed_progress = if matches!(disposition, Disposition::Running) {
        worker_progress
    } else {
        jobs[job].progress
    };
    trace.push(Event::Cancel {
        job, due: deadline, observed, disposition, lease,
        reserved: after.budget.reserved_ns, progress: observed_progress,
    });
    disposition
}

fn stop(policy: &mut Policy, jobs: &mut [Job], workload: &[Offer], trace: &mut Trace,
    receipt: Receipt, dispatch: Dispatch, epoch: u64, seen: u64,
) -> (TaskState, bool) {
    let command = receipt.command;
    let job = command.job;
    let domain = u64::from(workload[job].domain);
    let task = jobs[job].task.unwrap();
    ensure(command.task_slot == task.slot() && command.task_generation == task.generation()
        && dispatch.task == task && command.lease_generation == dispatch.lease.generation()
        && checked(policy.cpu_lease(WORKER_SLOT)) == Some(dispatch.lease));
    ensure(command.grant_ns == dispatch.grant_ns && elapsed(epoch, command.hard) == dispatch.stop_by_ns
        && command.start <= receipt.retired && receipt.retired <= seen
        && jobs[job].progress == receipt.progress_before);
    let before = checked(policy.task(domain, task));
    ensure(before.cpu == Some(WORKER_SLOT as u32) && before.budget.reserved_ns == dispatch.grant_ns);
    let late = receipt.retired > command.hard;
    let (outcome, expected, label) = if late {
        (StopOutcome::Fail, TaskState::Failed, "late")
    } else {
        match before.state {
            TaskState::Stopping(StopCause::FailureRequested) => (StopOutcome::Fail, TaskState::Failed, "canceled"),
            TaskState::Running if receipt.vector == 128 => (StopOutcome::Complete, TaskState::Completed, "completed"),
            TaskState::Running => (StopOutcome::Yield, TaskState::Runnable, "yield"),
            _ => {
                ensure(false);
                unreachable!()
            }
        }
    };
    let retired_ns = elapsed(epoch, receipt.retired);
    let reconcile_start = clock();
    compiler_fence(Ordering::SeqCst);
    let result = reconcile(policy, dispatch.lease, retired_ns, outcome);
    compiler_fence(Ordering::SeqCst);
    let reconciled = clock();
    let state = checked(result);
    let after = checked(policy.task(domain, task));
    let charge = elapsed(command.start, receipt.retired);
    ensure(state == expected && after.state == expected && after.cpu.is_none()
        && after.budget.reserved_ns == 0 && after.budget.consumed_ns == before.budget.consumed_ns + u128::from(charge)
        && checked(policy.cpu_lease(WORKER_SLOT)).is_none());
    jobs[job].progress = receipt.progress_after;
    trace.push(Event::Stop {
        job, receipt, seen, reconcile_start, reconciled, outcome: label, charge,
        consumed: after.budget.consumed_ns, reserved: after.budget.reserved_ns,
    });
    ensure(checked(policy.accounting(domain)).halted == late);
    (state, late)
}

fn print_start(scenario: u8, quantum: u8, epoch: u64, jobs: usize) {
    print(format_args!("TESSRYN_K03_WORKLOAD_BEGIN scenario={scenario} quantum={quantum} epoch={epoch} tick_ns={TICK_NS} quantum_unit_ns={QUANTUM_UNIT_NS} unit_iterations={WORK_ITERATIONS} worker_cpu={WORKER_CPU} worker_slot={WORKER_SLOT} jobs={jobs} limit_ns={DOMAIN_LIMIT_NS} run_limit_ns={RUN_LIMIT_NS}\n"));
}

pub(super) fn run(workload: &[Offer], scenario: u8, quantum: u8, epoch: u64) -> ! {
    ensure(!workload.is_empty() && workload.len() <= MAX_JOBS && matches!(quantum, 4 | 16)
        && TICK_NS % HPET_TICK_NS == 0);
    let mut policy = checked(Policy::new());
    for domain in 1..=DOMAIN_COUNT {
        checked(policy.add_domain(domain as u64, DOMAIN_LIMIT_NS));
    }
    let mut jobs = [EMPTY_JOB; MAX_JOBS];
    let mut cancellation_order = [(0_u8, 0_usize); MAX_JOBS];
    let mut cancel_count = 0;
    for (job, offer) in workload.iter().enumerate() {
        ensure(usize::from(offer.id) == job + 1 && (1..=DOMAIN_COUNT).contains(&usize::from(offer.domain))
            && (job == 0 || workload[job - 1].arrival <= offer.arrival));
        if offer.cancel != 0 {
            ensure(offer.arrival <= offer.cancel);
            cancellation_order[cancel_count] = (offer.cancel, job);
            cancel_count += 1;
        }
    }
    let cancellations = &mut cancellation_order[..cancel_count];
    cancellations.sort_unstable();

    let mut trace = Trace { len: 0 };
    let (mut next_offer, mut next_cancel, mut ready, mut terminal, mut stops) = (0, 0, 0, 0, 0);
    let mut active: Option<Dispatch> = None;
    while terminal != workload.len() || next_cancel != cancel_count {
        // Observe the shared HPET before the worker's closing/receipt state.
        // The AP publishes CLOSING before taking its retirement sample. If we
        // see Running, that sample cannot precede this policy timestamp.
        let candidate = clock();
        let scheduled = next_tick(workload.get(next_offer), cancellations.get(next_cancel));
        let (observed, worker_progress) = match active {
            Some(dispatch) if scheduled.is_some_and(|tick| due(epoch, tick) <= candidate) => {
                let worker_progress = progress(dispatch.task.slot() as usize);
                (clock(), worker_progress)
            }
            _ => (candidate, 0),
        };
        let now_ns = elapsed(epoch, observed);
        if now_ns >= RUN_LIMIT_NS {
            print_start(scenario, quantum, epoch, workload.len());
            trace.print(workload);
            fail("workload-trial-limit");
        }
        match worker_state() {
            WorkerState::Closing => {
                core::hint::spin_loop();
                continue;
            }
            WorkerState::Retired(receipt) => {
                let dispatch = active.take().unwrap();
                let (state, late) = stop(&mut policy, &mut jobs, workload, &mut trace,
                    receipt, dispatch, epoch, clock());
                ready += usize::from(state == TaskState::Runnable);
                terminal += usize::from(state.terminal());
                stops += 1;
                release_receipt();
                if late {
                    park();
                    print_start(scenario, quantum, epoch, workload.len());
                    trace.print(workload);
                    fail("workload-late-retirement");
                }
                continue;
            }
            WorkerState::Running => {
                let dispatch = active.unwrap();
                if now_ns >= dispatch.stop_by_ns {
                    // The AP still owns this lease. Await its actual sample
                    // so any late stop is charged and halts its domain.
                    core::hint::spin_loop();
                    continue;
                }
            }
            WorkerState::Idle => ensure(active.is_none()),
        }

        while let Some(tick) = next_tick(workload.get(next_offer), cancellations.get(next_cancel)) {
            let deadline = due(epoch, tick);
            if deadline > observed { break; }
            while workload.get(next_offer).is_some_and(|offer| offer.arrival == tick) {
                arrive(&mut policy, &mut jobs, workload, &mut trace, next_offer, deadline, observed, now_ns, worker_progress);
                ready += 1;
                next_offer += 1;
            }
            while let Some(&(_, job)) = cancellations.get(next_cancel).filter(|&&(at, _)| at == tick) {
                let disposition = cancel(&mut policy, &jobs, workload, &mut trace,
                    job, deadline, observed, now_ns, worker_progress);
                if matches!(disposition, Disposition::Queued) {
                    ready = ready.checked_sub(1).unwrap();
                    terminal += 1;
                }
                next_cancel += 1;
            }
        }

        if active.is_none() && ready != 0 {
            let quantum_ns = u64::from(quantum) * QUANTUM_UNIT_NS;
            let select_start = clock();
            if next_tick(workload.get(next_offer), cancellations.get(next_cancel))
                .is_some_and(|tick| due(epoch, tick) <= select_start)
            {
                continue;
            }
            let start_ns = elapsed(epoch, select_start);
            compiler_fence(Ordering::SeqCst);
            let result = reserve(&mut policy, quantum_ns, start_ns);
            compiler_fence(Ordering::SeqCst);
            let select_done = clock();
            let dispatch = checked(result);
            let job = dispatch.task.slot() as usize;
            ensure(jobs[job].task == Some(dispatch.task) && dispatch.lease.cpu() as usize == WORKER_SLOT
                && checked(policy.cpu_lease(WORKER_SLOT)) == Some(dispatch.lease));
            let command = Command {
                job, task_slot: dispatch.task.slot(), task_generation: dispatch.task.generation(),
                lease_generation: dispatch.lease.generation(), start: select_start,
                hard: epoch.checked_add(dispatch.stop_by_ns / HPET_TICK_NS).unwrap(),
                grant_ns: dispatch.grant_ns,
            };
            let task = checked(policy.task(dispatch.task.domain(), dispatch.task));
            let domain = checked(policy.accounting(dispatch.task.domain()));
            ensure(select_done < command.hard && command.grant_ns == quantum_ns
                && task.budget.reserved_ns == command.grant_ns && domain.budget.reserved_ns == command.grant_ns);
            jobs[job].dispatches += 1;
            ready -= 1;
            trace.push(Event::Dispatch { job, command, select_start, select_done });
            active = Some(dispatch);
            publish(command);
        } else {
            core::hint::spin_loop();
        }
    }

    ensure(next_offer == workload.len() && checked(policy.cpu_lease(WORKER_SLOT)).is_none()
        && active.is_none() && ready == 0);
    park();
    let end = clock();
    print_start(scenario, quantum, epoch, workload.len());
    trace.print(workload);
    if elapsed(epoch, end) >= RUN_LIMIT_NS {
        fail("workload-trial-limit");
    }
    let mut completed = 0;
    let mut domain_charges = [0_u128; DOMAIN_COUNT];
    for (job, offer) in workload.iter().enumerate() {
        let local = jobs[job];
        let info = checked(policy.task(u64::from(offer.domain), local.task.unwrap()));
        ensure(info.cpu.is_none() && info.budget.reserved_ns == 0);
        let label = match info.state {
            TaskState::Completed => { completed += 1; "completed" }
            TaskState::Failed => { ensure(offer.cancel != 0); "canceled" }
            _ => { ensure(false); unreachable!() }
        };
        domain_charges[usize::from(offer.domain) - 1] += info.budget.consumed_ns;
        print(format_args!("TESSRYN_K03_WORKLOAD_TASK id={} domain={} state={label} consumed_ns={} dispatches={} progress={}\n",
            offer.id, offer.domain, info.budget.consumed_ns, local.dispatches, local.progress));
    }
    for (index, consumed) in domain_charges.into_iter().enumerate() {
        let domain = index + 1;
        let info = checked(policy.accounting(domain as u64));
        ensure(!info.halted && info.budget.consumed_ns == consumed && info.budget.reserved_ns == 0);
        print(format_args!("TESSRYN_K03_WORKLOAD_DOMAIN id={domain} consumed_ns={consumed} reserved_ns=0\n"));
    }
    print(format_args!("TESSRYN_K03_WORKLOAD_PASS offers={} cancels={cancel_count} completions={completed} canceled={} stops={stops} end={end}\n",
        workload.len(), workload.len() - completed));
    finish(true)
}
