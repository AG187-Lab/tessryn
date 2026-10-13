//! Fixed-capacity scheduling and CPU-time policy for a future trusted adapter.
//!
//! This code selects and accounts numerical tasks; it executes no task, reads no
//! clock, authenticates no caller, and performs no interrupt or context switch.
//! Every mutation requires exclusive access. A native adapter must serialize
//! cross-CPU access, supply one synchronized node-local monotonic clock, and
//! acknowledge a stop only after that execution context can no longer run.
#![no_std]
#![forbid(unsafe_code)]

pub const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCapacity,
    InvalidDomain,
    DuplicateDomain,
    UnknownDomain,
    InvalidBudget,
    Capacity,
    InvalidAuthority,
    StaleTask,
    StaleLease,
    GenerationExhausted,
    InvalidCpu,
    CpuBusy,
    InvalidQuantum,
    NoRunnableTask,
    State,
    DeadlineExpired,
    DomainHalted,
    TimeRegression,
    Overflow,
}

/// An internal identity, not a native wire descriptor or authenticated caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId {
    slot: u32,
    generation: u32,
    domain: u64,
}
impl TaskId {
    pub const fn slot(self) -> u32 { self.slot }
    pub const fn generation(self) -> u32 { self.generation }
    pub const fn domain(self) -> u64 { self.domain }
}

/// An internal, one-use execution identity retained until a trusted stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuLease {
    cpu: u32,
    generation: u32,
    task: TaskId,
}
impl CpuLease {
    pub const fn cpu(self) -> u32 { self.cpu }
    pub const fn generation(self) -> u32 { self.generation }
    pub const fn task(self) -> TaskId { self.task }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accounting {
    pub limit_ns: u64,
    /// Full observed CPU time, including late stops; never clamped to a grant.
    pub consumed_ns: u128,
    pub reserved_ns: u64,
}
impl Accounting {
    pub fn available_ns(self) -> u64 {
        let occupied = self.consumed_ns.saturating_add(u128::from(self.reserved_ns));
        u128::from(self.limit_ns).saturating_sub(occupied) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    SliceElapsed,
    DeadlineExpired,
    FailureRequested,
    DomainHalted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Blocked,
    Running,
    /// Observing expiry/failure never releases CPU ownership by itself.
    Stopping(StopCause),
    Completed,
    Failed,
    Exhausted,
    DeadlineExpired,
}
impl TaskState {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Exhausted | Self::DeadlineExpired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOutcome { Yield, Block, Complete, Fail }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskSpec {
    pub budget_ns: u64,
    /// Zero means absent. Nonzero deadlines share the adapter's local clock.
    pub deadline_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskInfo {
    pub state: TaskState,
    pub budget: Accounting,
    pub deadline_ns: u64,
    pub cpu: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainInfo {
    pub budget: Accounting,
    pub halted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub lease: CpuLease,
    pub task: TaskId,
    pub grant_ns: u64,
    pub stop_by_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Domain {
    id: u64,
    budget: Accounting,
    halted: bool,
    task_cursor: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Task {
    id: TaskId,
    state: TaskState,
    budget: Accounting,
    deadline_ns: u64,
    cpu: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TaskSlot {
    generation: u32,
    task: Option<Task>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Running {
    lease: CpuLease,
    start_ns: u64,
    grant_ns: u64,
    stop_by_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuSlot {
    generation: u32,
    running: Option<Running>,
}

/// Serialized policy model, with domain-then-task round-robin selection.
///
/// Lifetime budgets are immutable. Domain IDs never recycle, and reaping tasks
/// never refunds consumed domain time. No automatic refill, period/rate promise,
/// native task ABI, or real SMP synchronization is implemented here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheduler<const D: usize, const T: usize, const C: usize> {
    domains: [Option<Domain>; D],
    tasks: [TaskSlot; T],
    cpus: [CpuSlot; C],
    time_ns: u64,
    domain_cursor: usize,
}

impl<const D: usize, const T: usize, const C: usize> Scheduler<D, T, C> {
    pub fn new() -> Result<Self, Error> {
        if [D, T, C].iter().any(|&n| n == 0 || n > MAX_ENTRIES) {
            return Err(Error::InvalidCapacity);
        }
        Ok(Self {
            domains: [None; D],
            tasks: [TaskSlot { generation: 0, task: None }; T],
            cpus: [CpuSlot { generation: 0, running: None }; C],
            time_ns: 0,
            domain_cursor: 0,
        })
    }

    /// Trusted admission. Numbers presented by a descriptor grant no authority.
    pub fn add_domain(&mut self, domain: u64, budget_ns: u64) -> Result<(), Error> {
        if domain == 0 { return Err(Error::InvalidDomain); }
        if budget_ns == 0 { return Err(Error::InvalidBudget); }
        if self.domains.iter().flatten().any(|d| d.id == domain) {
            return Err(Error::DuplicateDomain);
        }
        let slot = self.domains.iter().position(Option::is_none).ok_or(Error::Capacity)?;
        self.domains[slot] = Some(Domain {
            id: domain,
            budget: Accounting { limit_ns: budget_ns, consumed_ns: 0, reserved_ns: 0 },
            halted: false,
            task_cursor: 0,
        });
        Ok(())
    }

    pub const fn clock(&self) -> u64 { self.time_ns }

    pub fn accounting(&self, domain: u64) -> Result<DomainInfo, Error> {
        let d = self.domains[self.domain_index(domain)?].unwrap();
        Ok(DomainInfo { budget: d.budget, halted: d.halted })
    }

    pub fn task(&self, caller: u64, id: TaskId) -> Result<TaskInfo, Error> {
        let t = self.tasks[self.task_index(caller, id)?].task.unwrap();
        Ok(TaskInfo { state: t.state, budget: t.budget, deadline_ns: t.deadline_ns, cpu: t.cpu })
    }

    pub fn cpu_lease(&self, cpu: usize) -> Result<Option<CpuLease>, Error> {
        Ok(self.cpus.get(cpu).ok_or(Error::InvalidCpu)?.running.map(|r| r.lease))
    }

    pub fn create_task(&mut self, caller: u64, spec: TaskSpec, now: u64) -> Result<TaskId, Error> {
        let di = self.domain_index(caller)?;
        let d = self.domains[di].unwrap();
        self.check_time(now)?;
        if d.halted || self.overdue(caller, now) { return Err(Error::DomainHalted); }
        if spec.budget_ns == 0 || spec.budget_ns > d.budget.limit_ns {
            return Err(Error::InvalidBudget);
        }
        if expired(spec.deadline_ns, now) { return Err(Error::DeadlineExpired); }
        let slot = self.tasks.iter().position(|s| s.task.is_none() && s.generation < u32::MAX)
            .ok_or(Error::Capacity)?;
        let generation = self.tasks[slot].generation + 1;
        let id = TaskId { slot: slot as u32, generation, domain: caller };
        self.tasks[slot] = TaskSlot { generation, task: Some(Task {
            id, state: TaskState::Runnable,
            budget: Accounting { limit_ns: spec.budget_ns, consumed_ns: 0, reserved_ns: 0 },
            deadline_ns: spec.deadline_ns, cpu: None,
        }) };
        self.advance_internal(now);
        Ok(id)
    }

    pub fn wake(&mut self, caller: u64, id: TaskId, now: u64) -> Result<(), Error> {
        let ti = self.idle_transition(caller, id, now, TaskState::Blocked)?;
        self.advance_internal(now);
        self.tasks[ti].task.as_mut().unwrap().state = TaskState::Runnable;
        Ok(())
    }

    pub fn block(&mut self, caller: u64, id: TaskId, now: u64) -> Result<(), Error> {
        let ti = self.idle_transition(caller, id, now, TaskState::Runnable)?;
        self.advance_internal(now);
        self.tasks[ti].task.as_mut().unwrap().state = TaskState::Blocked;
        Ok(())
    }

    /// A running failure requests a stop; its CPU and reservation stay owned.
    pub fn fail(&mut self, caller: u64, id: TaskId, now: u64) -> Result<(), Error> {
        let ti = self.task_index(caller, id)?;
        self.check_time(now)?;
        let t = self.tasks[ti].task.unwrap();
        if t.state.terminal() { return Err(Error::State); }
        self.advance_internal(now);
        self.tasks[ti].task.as_mut().unwrap().state = if t.cpu.is_some() {
            TaskState::Stopping(StopCause::FailureRequested)
        } else {
            TaskState::Failed
        };
        Ok(())
    }

    /// Only stopped terminal tasks can recycle their slot, never their budget.
    pub fn reap(&mut self, caller: u64, id: TaskId, now: u64) -> Result<(), Error> {
        let ti = self.task_index(caller, id)?;
        self.check_time(now)?;
        let t = self.tasks[ti].task.unwrap();
        if !t.state.terminal() || t.cpu.is_some() { return Err(Error::State); }
        self.advance_internal(now);
        self.tasks[ti].task = None;
        Ok(())
    }

    /// Poll numerical expiry. This neither stops a CPU nor refunds its grant.
    pub fn advance(&mut self, now: u64) -> Result<(), Error> {
        self.check_time(now)?;
        self.advance_internal(now);
        Ok(())
    }

    /// Trusted dispatch selection. Reserve the shared domain grant before use.
    pub fn dispatch(&mut self, cpu: usize, quantum_ns: u64, now: u64) -> Result<Dispatch, Error> {
        let cs = *self.cpus.get(cpu).ok_or(Error::InvalidCpu)?;
        self.check_time(now)?;
        if quantum_ns == 0 { return Err(Error::InvalidQuantum); }
        if cs.running.is_some() { return Err(Error::CpuBusy); }
        if cs.generation == u32::MAX { return Err(Error::GenerationExhausted); }
        let (di, ti, grant) = self.select(quantum_ns, now).ok_or(Error::NoRunnableTask)?;
        let stop_by = now.checked_add(grant).ok_or(Error::Overflow)?;
        let task = self.tasks[ti].task.unwrap();
        let domain = self.domains[di].unwrap();
        let task_reserved = task.budget.reserved_ns.checked_add(grant).ok_or(Error::Overflow)?;
        let domain_reserved = domain.budget.reserved_ns.checked_add(grant).ok_or(Error::Overflow)?;
        let lease = CpuLease { cpu: cpu as u32, generation: cs.generation + 1, task: task.id };
        // All rejection guards precede even clock/cursor updates.
        self.advance_internal(now);
        let t = self.tasks[ti].task.as_mut().unwrap();
        t.state = TaskState::Running;
        t.cpu = Some(cpu as u32);
        t.budget.reserved_ns = task_reserved;
        let d = self.domains[di].as_mut().unwrap();
        d.budget.reserved_ns = domain_reserved;
        d.task_cursor = (ti + 1) % T;
        self.domain_cursor = (di + 1) % D;
        self.cpus[cpu] = CpuSlot { generation: lease.generation, running: Some(Running {
            lease, start_ns: now, grant_ns: grant, stop_by_ns: stop_by,
        }) };
        Ok(Dispatch { lease, task: task.id, grant_ns: grant, stop_by_ns: stop_by })
    }

    /// A trusted adapter calls this only after this exact context has stopped.
    /// Charge *all* elapsed CPU time. Late stops halt new domain dispatch and
    /// request peer stops while retaining each peer's CPU and reservation.
    pub fn stop(&mut self, lease: CpuLease, now: u64, outcome: StopOutcome) -> Result<TaskState, Error> {
        let cpu = lease.cpu as usize;
        let running = self.cpus.get(cpu).and_then(|c| c.running).ok_or(Error::StaleLease)?;
        if running.lease != lease { return Err(Error::StaleLease); }
        let ti = self.task_index(lease.task.domain, lease.task)?;
        let t = self.tasks[ti].task.unwrap();
        let di = self.domain_index(t.id.domain)?;
        let d = self.domains[di].unwrap();
        self.check_time(now)?;
        let elapsed = u128::from(now.checked_sub(running.start_ns).ok_or(Error::TimeRegression)?);
        let task_consumed = t.budget.consumed_ns.checked_add(elapsed).ok_or(Error::Overflow)?;
        let domain_consumed = d.budget.consumed_ns.checked_add(elapsed).ok_or(Error::Overflow)?;
        let domain_reserved = d.budget.reserved_ns.checked_sub(running.grant_ns).ok_or(Error::Overflow)?;
        if t.budget.reserved_ns != running.grant_ns || t.cpu != Some(lease.cpu) {
            return Err(Error::State);
        }
        let overdue_domain = self.overdue(t.id.domain, now);
        let failed = overdue_domain || d.halted || outcome == StopOutcome::Fail ||
            matches!(t.state, TaskState::Stopping(StopCause::FailureRequested | StopCause::DomainHalted));
        let state = if failed { TaskState::Failed }
            else if expired(t.deadline_ns, now) { TaskState::DeadlineExpired }
            else if outcome == StopOutcome::Complete { TaskState::Completed }
            else if task_consumed >= u128::from(t.budget.limit_ns) ||
                    domain_consumed >= u128::from(d.budget.limit_ns) { TaskState::Exhausted }
            else if outcome == StopOutcome::Block { TaskState::Blocked }
            else { TaskState::Runnable };
        let domain = self.domains[di].as_mut().unwrap();
        domain.budget.consumed_ns = domain_consumed;
        domain.budget.reserved_ns = domain_reserved;
        domain.halted |= overdue_domain;
        let task = self.tasks[ti].task.as_mut().unwrap();
        task.budget.consumed_ns = task_consumed;
        task.budget.reserved_ns = 0;
        task.cpu = None;
        task.state = state;
        self.cpus[cpu].running = None;
        self.advance_internal(now);
        Ok(state)
    }

    fn domain_index(&self, domain: u64) -> Result<usize, Error> {
        self.domains.iter().position(|d| d.is_some_and(|d| d.id == domain)).ok_or(Error::UnknownDomain)
    }

    fn task_index(&self, caller: u64, id: TaskId) -> Result<usize, Error> {
        if caller == 0 || caller != id.domain { return Err(Error::InvalidAuthority); }
        self.domain_index(caller)?;
        let slot = self.tasks.get(id.slot as usize).ok_or(Error::StaleTask)?;
        if slot.generation != id.generation || !slot.task.is_some_and(|t| t.id == id) {
            return Err(Error::StaleTask);
        }
        Ok(id.slot as usize)
    }

    fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.time_ns { Err(Error::TimeRegression) } else { Ok(()) }
    }

    fn idle_transition(&self, caller: u64, id: TaskId, now: u64, from: TaskState) -> Result<usize, Error> {
        let ti = self.task_index(caller, id)?;
        let t = self.tasks[ti].task.unwrap();
        let d = self.domains[self.domain_index(caller)?].unwrap();
        self.check_time(now)?;
        if d.halted || self.overdue(caller, now) { return Err(Error::DomainHalted); }
        if expired(t.deadline_ns, now) { return Err(Error::DeadlineExpired); }
        if t.state != from || t.cpu.is_some() ||
                t.budget.consumed_ns >= u128::from(t.budget.limit_ns) ||
                d.budget.consumed_ns >= u128::from(d.budget.limit_ns) { return Err(Error::State); }
        Ok(ti)
    }

    fn select(&self, quantum: u64, now: u64) -> Option<(usize, usize, u64)> {
        for offset in 0..D {
            let di = (self.domain_cursor + offset) % D;
            let Some(d) = self.domains[di] else { continue; };
            if d.halted || self.overdue(d.id, now) || d.budget.available_ns() == 0 { continue; }
            for task_offset in 0..T {
                let ti = (d.task_cursor + task_offset) % T;
                let Some(t) = self.tasks[ti].task else { continue; };
                if t.id.domain != d.id || t.state != TaskState::Runnable || t.cpu.is_some() ||
                        expired(t.deadline_ns, now) { continue; }
                let mut grant = quantum.min(t.budget.available_ns()).min(d.budget.available_ns());
                if t.deadline_ns != 0 { grant = grant.min(t.deadline_ns - now); }
                if grant != 0 { return Some((di, ti, grant)); }
            }
        }
        None
    }

    fn advance_internal(&mut self, now: u64) {
        self.time_ns = now;
        // With no stop acknowledgment, observed lateness is enough to halt new
        // admission conservatively. Each existing lease still needs its own
        // trusted stop and full runtime charge; expiry alone refunds nothing.
        for di in 0..D {
            if let Some(d) = self.domains[di] {
                if self.overdue(d.id, now) { self.domains[di].as_mut().unwrap().halted = true; }
            }
        }
        for ti in 0..T {
            let Some(t) = self.tasks[ti].task else { continue; };
            if t.state.terminal() { continue; }
            let d = self.domains[self.domain_index(t.id.domain).unwrap()].unwrap();
            let state = if let Some(cpu) = t.cpu {
                let running = self.cpus[cpu as usize].running.unwrap();
                if d.halted { TaskState::Stopping(StopCause::DomainHalted) }
                else if matches!(t.state, TaskState::Stopping(StopCause::FailureRequested)) { t.state }
                else if expired(t.deadline_ns, now) { TaskState::Stopping(StopCause::DeadlineExpired) }
                else if now >= running.stop_by_ns { TaskState::Stopping(StopCause::SliceElapsed) }
                else { t.state }
            } else if d.halted { TaskState::Failed }
            else if expired(t.deadline_ns, now) { TaskState::DeadlineExpired }
            else if t.budget.consumed_ns >= u128::from(t.budget.limit_ns) ||
                    d.budget.consumed_ns >= u128::from(d.budget.limit_ns) { TaskState::Exhausted }
            else { t.state };
            self.tasks[ti].task.as_mut().unwrap().state = state;
        }
    }

    fn overdue(&self, domain: u64, now: u64) -> bool {
        self.cpus.iter().filter_map(|c| c.running)
            .any(|r| r.lease.task.domain == domain && now > r.stop_by_ns)
    }
}

fn expired(deadline: u64, now: u64) -> bool { deadline != 0 && now >= deadline }

#[cfg(test)]
mod tests;
