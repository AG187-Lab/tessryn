//! Protected single-CPU adapter for the unchanged K03 lifetime-budget policy.
//!
//! The native owner supplies checked absolute monotonic nanoseconds from its
//! admitted clock, serializes mutations with interrupts masked, and calls stop
//! only after the exact CPL3 context has actually stopped. No user descriptor
//! supplies an index, task identity, lease, timestamp or stop acknowledgment.
//! Grant identities belong to this one boot-local adapter, never a wire ABI.
use tessryn_scheduler::{
    CpuLease, Dispatch, DomainInfo, Scheduler, StopOutcome, TaskId, TaskInfo, TaskSpec, TaskState,
};

pub const HARD_QUANTUM_NS: u64 = 250_000_000;
pub const SOFT_TARGET_NS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIndex,
    StaleGrant,
    ForeignTask,
    Scheduler(tessryn_scheduler::Error),
}
impl From<tessryn_scheduler::Error> for Error {
    fn from(error: tessryn_scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Grant {
    pub dispatch: Dispatch,
    pub index: usize,
    /// Advisory early hardware-timer target, not a timestamp to charge at stop.
    pub soft_ns: u64,
}
impl Grant {
    fn matches(self, other: Self) -> bool {
        self.index == other.index
            && self.soft_ns == other.soft_ns
            && self.dispatch.lease == other.dispatch.lease
            && self.dispatch.task == other.dispatch.task
            && self.dispatch.grant_ns == other.dispatch.grant_ns
            && self.dispatch.stop_by_ns == other.dispatch.stop_by_ns
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    scheduler: Scheduler<2, 2, 1>,
    tasks: [TaskId; 2],
    active: Option<Grant>,
}
impl Policy {
    /// Trusted admission of exactly one task in each permanent domain1 and2.
    /// There is deliberately no subsequent create/reap/reset/refill interface.
    pub fn new(now_ns: u64, limits_ns: [u64; 2], deadlines_ns: [u64; 2]) -> Result<Self, Error> {
        let mut scheduler = Scheduler::new()?;
        scheduler.add_domain(1, limits_ns[0])?;
        scheduler.add_domain(2, limits_ns[1])?;
        let first = scheduler.create_task(
            1,
            TaskSpec { budget_ns: limits_ns[0], deadline_ns: deadlines_ns[0] },
            now_ns,
        )?;
        let second = scheduler.create_task(
            2,
            TaskSpec { budget_ns: limits_ns[1], deadline_ns: deadlines_ns[1] },
            now_ns,
        )?;
        Ok(Self { scheduler, tasks: [first, second], active: None })
    }

    pub fn task_id(&self, index: usize) -> Result<TaskId, Error> {
        self.tasks.get(index).copied().ok_or(Error::InvalidIndex)
    }

    pub fn task(&self, index: usize) -> Result<TaskInfo, Error> {
        let id = self.task_id(index)?;
        Ok(self.scheduler.task(id.domain(), id)?)
    }

    pub fn accounting(&self, index: usize) -> Result<DomainInfo, Error> {
        Ok(self.scheduler.accounting(self.task_id(index)?.domain())?)
    }

    pub fn terminal(&self, index: usize) -> Result<bool, Error> {
        Ok(self.task(index)?.state.terminal())
    }

    pub const fn clock(&self) -> u64 {
        self.scheduler.clock()
    }

    pub const fn active(&self) -> Option<Grant> {
        self.active
    }

    pub fn cpu_lease(&self) -> Result<Option<CpuLease>, Error> {
        Ok(self.scheduler.cpu_lease(0)?)
    }

    /// The early target leaves headroom inside the STRICT unchanged hard grant.
    /// Full actual elapsed time is still charged, including bounded service,
    /// entry, interrupt and attributable logging work under the native rule.
    pub fn dispatch(&mut self, now_ns: u64) -> Result<Grant, Error> {
        // A small fixed-capacity candidate keeps all adapter checks rejection
        // atomic, including an impossible foreign policy identity or overflow.
        let mut candidate = self.scheduler.clone();
        let dispatch = candidate.dispatch(0, HARD_QUANTUM_NS, now_ns)?;
        let index = self.tasks.iter().position(|id| *id == dispatch.task).ok_or(Error::ForeignTask)?;
        let distance = (dispatch.grant_ns / 2).clamp(1, SOFT_TARGET_NS);
        let soft_ns = now_ns.checked_add(distance).ok_or(tessryn_scheduler::Error::Overflow)?;
        if soft_ns > dispatch.stop_by_ns || dispatch.lease.task() != self.tasks[index] {
            return Err(Error::ForeignTask);
        }
        let grant = Grant { dispatch, index, soft_ns };
        self.scheduler = candidate;
        self.active = Some(grant);
        Ok(grant)
    }

    /// `now_ns` is the actual trusted stop/accounting sample, never soft_ns,
    /// stop_by_ns, an interrupt count, or a user-reported elapsed interval.
    /// Beyond-hard stops retain the core's full charge and sticky domain halt.
    pub fn stop(&mut self, grant: Grant, now_ns: u64, outcome: StopOutcome) -> Result<TaskState, Error> {
        if !self.active.is_some_and(|active| active.matches(grant)) {
            return Err(Error::StaleGrant);
        }
        let state = self.scheduler.stop(grant.dispatch.lease, now_ns, outcome)?;
        self.active = None;
        Ok(state)
    }

    pub fn advance(&mut self, now_ns: u64) -> Result<(), Error> {
        Ok(self.scheduler.advance(now_ns)?)
    }

    /// Trusted bootstrap blocks B until its delegated capability is installed.
    /// A running/stopping context cannot be blocked or woken through this API.
    pub fn block(&mut self, index: usize, now_ns: u64) -> Result<(), Error> {
        let id = self.task_id(index)?;
        Ok(self.scheduler.block(id.domain(), id, now_ns)?)
    }

    pub fn wake(&mut self, index: usize, now_ns: u64) -> Result<(), Error> {
        let id = self.task_id(index)?;
        Ok(self.scheduler.wake(id.domain(), id, now_ns)?)
    }

    /// Failure of a running context requests its stop and retains its lease.
    pub fn fail(&mut self, index: usize, now_ns: u64) -> Result<(), Error> {
        let id = self.task_id(index)?;
        Ok(self.scheduler.fail(id.domain(), id, now_ns)?)
    }
}
