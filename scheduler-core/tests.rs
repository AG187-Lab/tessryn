//! Host adversarial timelines for the same allocation-free policy compiled
//! freestanding. These tests are simulations, without native CPU execution.

use crate::{Accounting, Error, Scheduler, StopCause, StopOutcome, TaskId, TaskSpec, TaskState};

type Policy = Scheduler<3, 12, 4>;

fn policy() -> Policy {
    let mut state = Policy::new().unwrap();
    state.add_domain(1, 100).unwrap();
    state.add_domain(2, 100).unwrap();
    state.add_domain(3, 100).unwrap();
    state
}

fn task<const D: usize, const T: usize, const C: usize>(
    state: &mut Scheduler<D, T, C>, caller: u64, budget_ns: u64,
    deadline_ns: u64, now: u64,
) -> TaskId {
    state.create_task(caller, TaskSpec { budget_ns, deadline_ns }, now).unwrap()
}

/// All rejected mutations preserve tables, clocks, identities and RR cursors.
fn denied<const D: usize, const T: usize, const C: usize, R: core::fmt::Debug>(
    state: &mut Scheduler<D, T, C>,
    action: impl FnOnce(&mut Scheduler<D, T, C>) -> Result<R, Error>,
) -> Error {
    let before = state.clone();
    let error = action(state).expect_err("an adversarial mutation succeeded");
    assert_eq!(*state, before, "rejection partially changed trusted state");
    error
}

fn account(budget: Accounting, limit: u64, consumed: u128, reserved: u64, available: u64) {
    assert_eq!((budget.limit_ns, budget.consumed_ns, budget.reserved_ns,
                budget.available_ns()), (limit, consumed, reserved, available));
}

#[test]
fn zero_capacity_configurations_are_rejected() {
    assert_eq!(Scheduler::<0, 1, 1>::new().unwrap_err(), Error::InvalidCapacity);
    assert_eq!(Scheduler::<1, 0, 1>::new().unwrap_err(), Error::InvalidCapacity);
    assert_eq!(Scheduler::<1, 1, 0>::new().unwrap_err(), Error::InvalidCapacity);
    assert_eq!(Scheduler::<4097, 1, 1>::new().unwrap_err(), Error::InvalidCapacity);
    assert_eq!(Scheduler::<1, 4097, 1>::new().unwrap_err(), Error::InvalidCapacity);
    assert_eq!(Scheduler::<1, 1, 4097>::new().unwrap_err(), Error::InvalidCapacity);
}

#[test]
fn permanent_domains_have_bounded_validated_registry() {
    let mut state = Scheduler::<2, 2, 1>::new().unwrap();
    assert_eq!(denied(&mut state, |s| s.add_domain(0, 1)), Error::InvalidDomain);
    assert_eq!(denied(&mut state, |s| s.add_domain(1, 0)), Error::InvalidBudget);
    state.add_domain(1, 8).unwrap();
    assert_eq!(denied(&mut state, |s| s.add_domain(1, 4)), Error::DuplicateDomain);
    state.add_domain(2, 8).unwrap();
    assert_eq!(denied(&mut state, |s| s.add_domain(3, 8)), Error::Capacity);
    assert_eq!(state.accounting(99).unwrap_err(), Error::UnknownDomain);
    account(state.accounting(1).unwrap().budget, 8, 0, 0, 8);
    assert!(!state.accounting(1).unwrap().halted);
}

#[test]
fn task_admission_rejects_bad_identity_budget_and_expired_deadline_atomically() {
    let mut state = policy();
    assert_eq!(denied(&mut state, |s| s.create_task(99,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 0)), Error::UnknownDomain);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 0, deadline_ns: 0 }, 0)), Error::InvalidBudget);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 101, deadline_ns: 0 }, 0)), Error::InvalidBudget);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 5 }, 5)), Error::DeadlineExpired);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 4 }, 5)), Error::DeadlineExpired);
    let id = task(&mut state, 1, 10, 6, 5);
    let info = state.task(1, id).unwrap();
    assert_eq!(info.state, TaskState::Runnable);
    assert_eq!(info.deadline_ns, 6);
    assert_eq!(info.cpu, None);
    account(info.budget, 10, 0, 0, 10);
}

#[test]
fn fixed_task_capacity_rejects_without_publishing_time_or_identity() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 100).unwrap();
    let first = task(&mut state, 1, 10, 0, 0);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 5)), Error::Capacity);
    assert_eq!(state.clock(), 0);
    assert_eq!(state.task(1, first).unwrap().state, TaskState::Runnable);
}

#[test]
fn numeric_domain_in_task_identity_cannot_authenticate_a_caller() {
    let mut state = policy();
    let id = task(&mut state, 1, 10, 0, 0);
    assert_eq!(id.domain(), 1);
    assert!(id.generation() > 0);
    assert_eq!(state.task(2, id).unwrap_err(), Error::InvalidAuthority);
    assert_eq!(denied(&mut state, |s| s.block(2, id, 5)), Error::InvalidAuthority);
    assert_eq!(denied(&mut state, |s| s.wake(2, id, 5)), Error::InvalidAuthority);
    assert_eq!(denied(&mut state, |s| s.fail(2, id, 5)), Error::InvalidAuthority);
    assert_eq!(denied(&mut state, |s| s.reap(2, id, 5)), Error::InvalidAuthority);
    let spoofed = TaskId { slot: id.slot(), generation: id.generation(), domain: 2 };
    assert_eq!(state.task(2, spoofed).unwrap_err(), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.fail(2, spoofed, 5)), Error::StaleTask);
    assert_eq!(state.clock(), 0);
}

#[test]
fn dispatch_is_exclusive_for_both_cpu_and_task() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 0, 0);
    let run = state.dispatch(0, 5, 0).unwrap();
    assert_eq!(run.task, id);
    assert_eq!(run.lease.cpu(), 0);
    assert_eq!(run.lease.task(), id);
    assert!(run.lease.generation() > 0);
    assert_eq!((run.grant_ns, run.stop_by_ns), (5, 5));
    assert_eq!(state.task(1, id).unwrap().cpu, Some(0));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(run.lease));
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 5, 1)), Error::CpuBusy);
    assert_eq!(denied(&mut state, |s| s.dispatch(1, 5, 1)), Error::NoRunnableTask);
    assert_eq!(denied(&mut state, |s| s.block(1, id, 1)), Error::State);
    assert_eq!(denied(&mut state, |s| s.wake(1, id, 1)), Error::State);
    assert_eq!(denied(&mut state, |s| s.reap(1, id, 1)), Error::State);
}

#[test]
fn invalid_cpu_zero_quantum_and_empty_selection_preserve_clock_and_cursors() {
    let mut state = policy();
    assert_eq!(denied(&mut state, |s| s.dispatch(4, 1, 7)), Error::InvalidCpu);
    assert_eq!(state.cpu_lease(4).unwrap_err(), Error::InvalidCpu);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 0, 7)), Error::InvalidQuantum);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 1, 7)), Error::NoRunnableTask);
    assert_eq!(state.clock(), 0);
    let first = task(&mut state, 1, 10, 0, 0);
    let second = task(&mut state, 2, 10, 0, 0);
    assert_eq!(state.dispatch(0, 1, 0).unwrap().task, first);
    assert_eq!(state.dispatch(1, 1, 0).unwrap().task, second);
}

#[test]
fn multicore_dispatch_reserves_once_against_shared_domain_ceiling() {
    let mut state = Scheduler::<1, 3, 3>::new().unwrap();
    state.add_domain(1, 12).unwrap();
    let first = task(&mut state, 1, 12, 0, 0);
    let second = task(&mut state, 1, 12, 0, 0);
    let third = task(&mut state, 1, 12, 0, 0);
    let a = state.dispatch(0, 8, 0).unwrap();
    let b = state.dispatch(1, 8, 0).unwrap();
    assert_eq!((a.task, a.grant_ns), (first, 8));
    assert_eq!((b.task, b.grant_ns), (second, 4));
    account(state.accounting(1).unwrap().budget, 12, 0, 12, 0);
    account(state.task(1, first).unwrap().budget, 12, 0, 8, 4);
    account(state.task(1, second).unwrap().budget, 12, 0, 4, 8);
    assert_eq!(denied(&mut state, |s| s.dispatch(2, 8, 0)), Error::NoRunnableTask);
    // Capacity occupied by other leases is transient, not permanent exhaustion.
    assert_eq!(state.task(1, third).unwrap().state, TaskState::Runnable);
    assert_eq!(state.stop(a.lease, 3, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    account(state.accounting(1).unwrap().budget, 12, 3, 4, 5);
    let c = state.dispatch(0, 8, 3).unwrap();
    assert_eq!((c.task, c.grant_ns, c.stop_by_ns), (third, 5, 8));
    account(state.accounting(1).unwrap().budget, 12, 3, 9, 0);
    assert_eq!(state.stop(b.lease, 4, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    assert_eq!(state.stop(c.lease, 8, StopOutcome::Yield).unwrap(), TaskState::Exhausted);
    account(state.accounting(1).unwrap().budget, 12, 12, 0, 0);
}

#[test]
fn overlapping_cpu_intervals_count_as_sum_of_cpu_time_not_wall_time() {
    let mut state = Scheduler::<1, 2, 2>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    let first = task(&mut state, 1, 10, 0, 0);
    let second = task(&mut state, 1, 10, 0, 0);
    let a = state.dispatch(0, 10, 0).unwrap();
    let b = state.dispatch(1, 10, 0).unwrap();
    assert_eq!(state.stop(a.lease, 7, StopOutcome::Block).unwrap(), TaskState::Blocked);
    assert_eq!(state.stop(b.lease, 7, StopOutcome::Complete).unwrap(), TaskState::Completed);
    assert_eq!(state.clock(), 7);
    account(state.accounting(1).unwrap().budget, 20, 14, 0, 6);
    account(state.task(1, first).unwrap().budget, 10, 7, 0, 3);
    account(state.task(1, second).unwrap().budget, 10, 7, 0, 3);
}

#[test]
fn domain_round_robin_prevents_task_splitting_from_buying_turns() {
    let mut state = policy();
    let first = task(&mut state, 1, 10, 0, 0);
    let next = task(&mut state, 1, 10, 0, 0);
    for _ in 0..4 { task(&mut state, 1, 10, 0, 0); }
    let other = task(&mut state, 2, 10, 0, 0);
    let a = state.dispatch(0, 1, 0).unwrap();
    let b = state.dispatch(1, 1, 0).unwrap();
    assert_eq!((a.task, b.task), (first, other));
    state.stop(a.lease, 1, StopOutcome::Complete).unwrap();
    state.stop(b.lease, 1, StopOutcome::Yield).unwrap();
    let c = state.dispatch(0, 1, 1).unwrap();
    let d = state.dispatch(1, 1, 1).unwrap();
    assert_eq!((c.task, d.task), (next, other));
}

#[test]
fn blocked_and_idle_failed_tasks_do_not_prevent_other_tenant_dispatch() {
    let mut state = policy();
    let blocked = task(&mut state, 1, 10, 0, 0);
    let failed = task(&mut state, 1, 10, 0, 0);
    let other = task(&mut state, 2, 10, 0, 0);
    state.block(1, blocked, 1).unwrap();
    state.fail(1, failed, 1).unwrap();
    assert_eq!(state.task(1, blocked).unwrap().state, TaskState::Blocked);
    assert_eq!(state.task(1, failed).unwrap().state, TaskState::Failed);
    assert_eq!(state.dispatch(0, 2, 1).unwrap().task, other);
    state.wake(1, blocked, 2).unwrap();
    assert_eq!(state.task(1, blocked).unwrap().state, TaskState::Runnable);
    assert_eq!(denied(&mut state, |s| s.wake(1, failed, 2)), Error::State);
}

#[test]
fn budget_caps_slice_and_yield_exhaustion_is_permanent() {
    let mut state = policy();
    let id = task(&mut state, 1, 10, 0, 0);
    let first = state.dispatch(0, 6, 0).unwrap();
    assert_eq!(state.stop(first.lease, 6, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    let last = state.dispatch(0, 6, 6).unwrap();
    assert_eq!((last.grant_ns, last.stop_by_ns), (4, 10));
    assert_eq!(state.stop(last.lease, 10, StopOutcome::Yield).unwrap(), TaskState::Exhausted);
    account(state.task(1, id).unwrap().budget, 10, 10, 0, 0);
    assert_eq!(denied(&mut state, |s| s.wake(1, id, 10)), Error::State);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 1, 10)), Error::NoRunnableTask);
}

#[test]
fn explicit_completion_at_exact_budget_limit_remains_successful() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 5).unwrap();
    let id = task(&mut state, 1, 5, 0, 0);
    let run = state.dispatch(0, 20, 0).unwrap();
    assert_eq!(run.grant_ns, 5);
    assert_eq!(state.stop(run.lease, 5, StopOutcome::Complete).unwrap(), TaskState::Completed);
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Completed);
    account(state.accounting(1).unwrap().budget, 5, 5, 0, 0);
}

#[test]
fn deadline_caps_grant_and_expires_at_inclusive_boundary() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 8, 3);
    let run = state.dispatch(0, 20, 3).unwrap();
    assert_eq!((run.grant_ns, run.stop_by_ns), (5, 8));
    assert_eq!(state.stop(run.lease, 8, StopOutcome::Complete).unwrap(), TaskState::DeadlineExpired);
    assert_eq!(state.task(1, id).unwrap().state, TaskState::DeadlineExpired);
    account(state.task(1, id).unwrap().budget, 20, 5, 0, 15);
    assert!(!state.accounting(1).unwrap().halted);
}

#[test]
fn advance_expires_runnable_and_blocked_tasks_without_cpu_runtime_charge() {
    let mut state = policy();
    let runnable = task(&mut state, 1, 10, 5, 0);
    let blocked = task(&mut state, 2, 10, 5, 0);
    state.block(2, blocked, 0).unwrap();
    state.advance(4).unwrap();
    assert_eq!(state.task(1, runnable).unwrap().state, TaskState::Runnable);
    assert_eq!(state.task(2, blocked).unwrap().state, TaskState::Blocked);
    state.advance(5).unwrap();
    assert_eq!(state.task(1, runnable).unwrap().state, TaskState::DeadlineExpired);
    assert_eq!(state.task(2, blocked).unwrap().state, TaskState::DeadlineExpired);
    account(state.accounting(1).unwrap().budget, 100, 0, 0, 100);
    account(state.accounting(2).unwrap().budget, 100, 0, 0, 100);
    assert_eq!(denied(&mut state, |s| s.wake(2, blocked, 5)), Error::DeadlineExpired);
}

#[test]
fn slice_elapsed_is_stop_request_until_acknowledgment() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 0, 0);
    let run = state.dispatch(0, 5, 0).unwrap();
    state.advance(5).unwrap();
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Stopping(StopCause::SliceElapsed));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(run.lease));
    account(state.accounting(1).unwrap().budget, 100, 0, 5, 95);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 1, 5)), Error::CpuBusy);
    assert_eq!(denied(&mut state, |s| s.dispatch(1, 1, 5)), Error::NoRunnableTask);
    assert_eq!(denied(&mut state, |s| s.reap(1, id, 5)), Error::State);
    assert_eq!(state.stop(run.lease, 5, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    assert_eq!(state.cpu_lease(0).unwrap(), None);
    account(state.accounting(1).unwrap().budget, 100, 5, 0, 95);
}

#[test]
fn running_deadline_preserves_lease_and_reservation_until_stop() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 5, 0);
    let run = state.dispatch(0, 10, 0).unwrap();
    state.advance(5).unwrap();
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Stopping(StopCause::DeadlineExpired));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(run.lease));
    account(state.task(1, id).unwrap().budget, 20, 0, 5, 15);
    assert_eq!(state.stop(run.lease, 5, StopOutcome::Yield).unwrap(), TaskState::DeadlineExpired);
}

#[test]
fn requested_failure_keeps_running_task_owned_and_dominates_completion() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 0, 0);
    let run = state.dispatch(0, 10, 0).unwrap();
    state.fail(1, id, 3).unwrap();
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Stopping(StopCause::FailureRequested));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(run.lease));
    account(state.accounting(1).unwrap().budget, 100, 0, 10, 90);
    assert_eq!(denied(&mut state, |s| s.reap(1, id, 3)), Error::State);
    assert_eq!(state.stop(run.lease, 4, StopOutcome::Complete).unwrap(), TaskState::Failed);
    account(state.accounting(1).unwrap().budget, 100, 4, 0, 96);
    assert!(!state.accounting(1).unwrap().halted);
}

#[test]
fn explicit_failure_and_block_acknowledgments_have_distinct_lifecycles() {
    let mut state = policy();
    let first = task(&mut state, 1, 10, 0, 0);
    let second = task(&mut state, 2, 10, 0, 0);
    let a = state.dispatch(0, 10, 0).unwrap();
    let b = state.dispatch(1, 10, 0).unwrap();
    assert_eq!(state.stop(a.lease, 2, StopOutcome::Fail).unwrap(), TaskState::Failed);
    assert_eq!(state.stop(b.lease, 2, StopOutcome::Block).unwrap(), TaskState::Blocked);
    assert_eq!(state.task(1, first).unwrap().state, TaskState::Failed);
    assert_eq!(state.task(2, second).unwrap().state, TaskState::Blocked);
    state.wake(2, second, 2).unwrap();
    assert_eq!(state.task(2, second).unwrap().state, TaskState::Runnable);
}

#[test]
fn overrun_charges_actual_runtime_halts_domain_and_retains_peer_lease() {
    let mut state = Scheduler::<2, 3, 3>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    state.add_domain(2, 20).unwrap();
    let first = task(&mut state, 1, 20, 0, 0);
    let peer = task(&mut state, 1, 20, 0, 0);
    let other = task(&mut state, 2, 20, 0, 0);
    let a = state.dispatch(0, 10, 0).unwrap();
    let b = state.dispatch(1, 15, 0).unwrap();
    let c = state.dispatch(2, 10, 0).unwrap();
    assert_eq!((a.task, b.task, c.task), (first, other, peer));
    assert_eq!(state.stop(a.lease, 11, StopOutcome::Yield).unwrap(), TaskState::Failed);
    assert!(state.accounting(1).unwrap().halted);
    account(state.accounting(1).unwrap().budget, 20, 11, 10, 0);
    assert_eq!(state.task(1, peer).unwrap().state, TaskState::Stopping(StopCause::DomainHalted));
    assert_eq!(state.cpu_lease(2).unwrap(), Some(c.lease));
    assert_eq!(denied(&mut state, |s| s.reap(1, peer, 11)), Error::State);
    assert_eq!(state.stop(c.lease, 11, StopOutcome::Complete).unwrap(), TaskState::Failed);
    account(state.accounting(1).unwrap().budget, 20, 22, 0, 0);
    // Other tenant remains owned and unaffected by the first tenant's halt.
    assert!(!state.accounting(2).unwrap().halted);
    assert_eq!(state.cpu_lease(1).unwrap(), Some(b.lease));
}

#[test]
fn stale_cpu_lease_cannot_stop_a_replacement_dispatch() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 0, 0);
    let first = state.dispatch(0, 5, 0).unwrap();
    state.stop(first.lease, 2, StopOutcome::Yield).unwrap();
    let replacement = state.dispatch(0, 5, 2).unwrap();
    assert_eq!(replacement.task, id);
    assert!(replacement.lease.generation() > first.lease.generation());
    assert_eq!(denied(&mut state, |s| s.stop(first.lease, 3, StopOutcome::Complete)), Error::StaleLease);
    assert_eq!(state.cpu_lease(0).unwrap(), Some(replacement.lease));
    assert_eq!(state.stop(replacement.lease, 3, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    assert_eq!(denied(&mut state, |s| s.stop(replacement.lease, 3, StopOutcome::Yield)), Error::StaleLease);
}

#[test]
fn task_reaping_reuses_generation_without_refunding_tenant_consumption() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 10).unwrap();
    let old = task(&mut state, 1, 10, 0, 0);
    let run = state.dispatch(0, 5, 0).unwrap();
    state.stop(run.lease, 4, StopOutcome::Complete).unwrap();
    state.reap(1, old, 4).unwrap();
    let new = task(&mut state, 1, 10, 0, 4);
    assert_eq!(new.slot(), old.slot());
    assert!(new.generation() > old.generation());
    assert_eq!(state.task(1, old).unwrap_err(), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.fail(1, old, 5)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.reap(1, old, 5)), Error::StaleTask);
    account(state.accounting(1).unwrap().budget, 10, 4, 0, 6);
    let last = state.dispatch(0, 10, 4).unwrap();
    assert_eq!((last.task, last.grant_ns), (new, 6));
    assert_eq!(state.stop(last.lease, 10, StopOutcome::Yield).unwrap(), TaskState::Exhausted);
    account(state.accounting(1).unwrap().budget, 10, 10, 0, 0);
}

#[test]
fn global_time_regression_is_rejected_across_all_mutation_families() {
    let mut state = policy();
    let id = task(&mut state, 1, 20, 0, 5);
    assert_eq!(state.clock(), 5);
    assert_eq!(denied(&mut state, |s| s.advance(4)), Error::TimeRegression);
    assert_eq!(denied(&mut state, |s| s.create_task(2,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 4)), Error::TimeRegression);
    assert_eq!(denied(&mut state, |s| s.block(1, id, 4)), Error::TimeRegression);
    assert_eq!(denied(&mut state, |s| s.fail(1, id, 4)), Error::TimeRegression);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 1, 4)), Error::TimeRegression);
    state.block(1, id, 5).unwrap();
    assert_eq!(denied(&mut state, |s| s.wake(1, id, 4)), Error::TimeRegression);
    state.wake(1, id, 5).unwrap();
    let run = state.dispatch(0, 5, 5).unwrap();
    assert_eq!(denied(&mut state, |s| s.stop(run.lease, 4, StopOutcome::Yield)), Error::TimeRegression);
    state.stop(run.lease, 6, StopOutcome::Complete).unwrap();
    assert_eq!(denied(&mut state, |s| s.reap(1, id, 5)), Error::TimeRegression);
}

#[test]
fn failed_foreign_request_cannot_advance_time_to_expire_another_task() {
    let mut state = policy();
    let id = task(&mut state, 1, 10, 5, 0);
    assert_eq!(denied(&mut state, |s| s.fail(2, id, 10)), Error::InvalidAuthority);
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Runnable);
    assert_eq!(state.clock(), 0);
    let run = state.dispatch(0, 2, 0).unwrap();
    assert_eq!(run.task, id);
}

#[test]
fn overflowing_stop_timestamp_is_rejected_without_reserving_or_advancing() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, u64::MAX).unwrap();
    let id = task(&mut state, 1, u64::MAX, 0, 1);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, u64::MAX, 1)), Error::Overflow);
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Runnable);
    account(state.accounting(1).unwrap().budget, u64::MAX, 0, 0, u64::MAX);
}

#[test]
fn deadline_subtraction_caps_large_grant_without_overflow() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, u64::MAX).unwrap();
    let id = task(&mut state, 1, u64::MAX, u64::MAX, 1);
    let run = state.dispatch(0, u64::MAX, 1).unwrap();
    assert_eq!((run.grant_ns, run.stop_by_ns), (u64::MAX - 1, u64::MAX));
    assert_eq!(state.stop(run.lease, u64::MAX, StopOutcome::Yield).unwrap(), TaskState::DeadlineExpired);
    account(state.task(1, id).unwrap().budget, u64::MAX, u128::from(u64::MAX - 1), 0, 1);
}

#[test]
fn simultaneous_long_cpu_overruns_use_wide_counters_without_budget_wrap() {
    let mut state = Scheduler::<1, 2, 2>::new().unwrap();
    state.add_domain(1, u64::MAX).unwrap();
    let first = task(&mut state, 1, u64::MAX, 0, 0);
    let second = task(&mut state, 1, u64::MAX, 0, 0);
    let a = state.dispatch(0, 1, 0).unwrap();
    let b = state.dispatch(1, 1, 0).unwrap();
    assert_eq!(state.stop(a.lease, u64::MAX, StopOutcome::Complete).unwrap(), TaskState::Failed);
    assert_eq!(state.stop(b.lease, u64::MAX, StopOutcome::Complete).unwrap(), TaskState::Failed);
    let sum = u128::from(u64::MAX) * 2;
    account(state.accounting(1).unwrap().budget, u64::MAX, sum, 0, 0);
    account(state.task(1, first).unwrap().budget, u64::MAX, u128::from(u64::MAX), 0, 0);
    account(state.task(1, second).unwrap().budget, u64::MAX, u128::from(u64::MAX), 0, 0);
    assert!(state.accounting(1).unwrap().halted);
}

#[test]
fn permanently_exhausted_domain_cannot_reset_consumption_by_recreating_tasks() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 3).unwrap();
    let old = task(&mut state, 1, 3, 0, 0);
    let run = state.dispatch(0, 3, 0).unwrap();
    state.stop(run.lease, 3, StopOutcome::Complete).unwrap();
    state.reap(1, old, 3).unwrap();
    let replacement = task(&mut state, 1, 3, 0, 3);
    assert_eq!(state.task(1, replacement).unwrap().state, TaskState::Exhausted);
    account(state.accounting(1).unwrap().budget, 3, 3, 0, 0);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 3, 3)), Error::NoRunnableTask);
    assert_eq!(denied(&mut state, |s| s.add_domain(1, 30)), Error::DuplicateDomain);
}

#[test]
fn task_generation_last_identity_retires_slot_instead_of_wrapping() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 10).unwrap();
    let old = task(&mut state, 1, 10, 0, 0);
    // Reach the final identity without billions of simulated admissions.
    let last = TaskId { slot: old.slot(), generation: u32::MAX, domain: 1 };
    state.tasks[old.slot() as usize].generation = u32::MAX;
    state.tasks[old.slot() as usize].task.as_mut().unwrap().id = last;
    assert_eq!(state.task(1, old).unwrap_err(), Error::StaleTask);
    state.fail(1, last, 0).unwrap();
    state.reap(1, last, 0).unwrap();
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 1)), Error::Capacity);
    assert_eq!(state.tasks[old.slot() as usize].generation, u32::MAX);
}

#[test]
fn cpu_generation_last_lease_retires_cpu_instead_of_wrapping() {
    let mut state = Scheduler::<1, 1, 2>::new().unwrap();
    state.add_domain(1, 10).unwrap();
    let id = task(&mut state, 1, 10, 0, 0);
    state.cpus[0].generation = u32::MAX - 1;
    let last = state.dispatch(0, 2, 0).unwrap();
    assert_eq!(last.lease.generation(), u32::MAX);
    state.stop(last.lease, 1, StopOutcome::Yield).unwrap();
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 2, 1)), Error::GenerationExhausted);
    assert_eq!(state.cpus[0].generation, u32::MAX);
    let other_cpu = state.dispatch(1, 2, 1).unwrap();
    assert_eq!(other_cpu.task, id);
    assert_eq!(denied(&mut state, |s| s.stop(last.lease, 2, StopOutcome::Complete)), Error::StaleLease);
    assert_eq!(state.cpu_lease(1).unwrap(), Some(other_cpu.lease));
}

#[test]
fn both_wide_accounting_additions_are_checked_before_stop_publishes_anything() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 10).unwrap();
    let id = task(&mut state, 1, 10, 0, 0);
    let run = state.dispatch(0, 2, 0).unwrap();
    // Defensive arithmetic checks even artificial states that ordinary
    // admitted histories cannot reach are rejection-atomic.
    state.domains[0].as_mut().unwrap().budget.consumed_ns = u128::MAX;
    assert_eq!(denied(&mut state, |s| s.stop(run.lease, 1, StopOutcome::Yield)), Error::Overflow);
    state.domains[0].as_mut().unwrap().budget.consumed_ns = 0;
    state.tasks[id.slot() as usize].task.as_mut().unwrap().budget.consumed_ns = u128::MAX;
    assert_eq!(denied(&mut state, |s| s.stop(run.lease, 1, StopOutcome::Yield)), Error::Overflow);
    assert_eq!(state.cpu_lease(0).unwrap(), Some(run.lease));
    assert_eq!(state.clock(), 0);
}

#[test]
fn fabricated_task_slot_and_generation_never_name_a_live_task() {
    let mut state = policy();
    let id = task(&mut state, 1, 10, 0, 0);
    let absent = TaskId { slot: u32::MAX, generation: id.generation(), domain: 1 };
    let future = TaskId { slot: id.slot(), generation: id.generation() + 1, domain: 1 };
    assert_eq!(state.task(1, absent).unwrap_err(), Error::StaleTask);
    assert_eq!(state.task(1, future).unwrap_err(), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.fail(1, absent, 10)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.fail(1, future, 10)), Error::StaleTask);
    assert_eq!(state.task(1, id).unwrap().state, TaskState::Runnable);
}

#[test]
fn malformed_cpu_lease_cannot_release_any_execution_or_advance_time() {
    let mut state = policy();
    let first = task(&mut state, 1, 10, 0, 0);
    let second = task(&mut state, 2, 10, 0, 0);
    let a = state.dispatch(0, 5, 0).unwrap();
    let b = state.dispatch(1, 5, 0).unwrap();
    assert_eq!((a.task, b.task), (first, second));
    let wrong_cpu = crate::CpuLease { cpu: u32::MAX, ..a.lease };
    let wrong_task = crate::CpuLease { task: second, ..a.lease };
    let wrong_generation = crate::CpuLease { generation: a.lease.generation() + 1, ..a.lease };
    for malformed in [wrong_cpu, wrong_task, wrong_generation] {
        assert_eq!(denied(&mut state, |s| s.stop(malformed, 10, StopOutcome::Complete)), Error::StaleLease);
    }
    assert_eq!(state.cpu_lease(0).unwrap(), Some(a.lease));
    assert_eq!(state.cpu_lease(1).unwrap(), Some(b.lease));
    assert_eq!(state.clock(), 0);
}

#[test]
fn failure_dominates_deadline_and_budget_boundary_while_complete_does_not() {
    let mut state = Scheduler::<1, 2, 2>::new().unwrap();
    state.add_domain(1, 10).unwrap();
    let failed = task(&mut state, 1, 5, 5, 0);
    let expired = task(&mut state, 1, 5, 5, 0);
    let a = state.dispatch(0, 5, 0).unwrap();
    let b = state.dispatch(1, 5, 0).unwrap();
    assert_eq!(state.stop(a.lease, 5, StopOutcome::Fail).unwrap(), TaskState::Failed);
    assert_eq!(state.stop(b.lease, 5, StopOutcome::Complete).unwrap(), TaskState::DeadlineExpired);
    assert_eq!(state.task(1, failed).unwrap().state, TaskState::Failed);
    assert_eq!(state.task(1, expired).unwrap().state, TaskState::DeadlineExpired);
    assert!(!state.accounting(1).unwrap().halted);
    account(state.accounting(1).unwrap().budget, 10, 10, 0, 0);
}

#[test]
fn halted_domain_cannot_create_new_work_or_wake_idle_work() {
    let mut state = Scheduler::<1, 3, 1>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    let failed = task(&mut state, 1, 10, 0, 0);
    let idle = task(&mut state, 1, 10, 0, 0);
    state.block(1, idle, 0).unwrap();
    let run = state.dispatch(0, 1, 0).unwrap();
    assert_eq!(run.task, failed);
    state.stop(run.lease, 2, StopOutcome::Complete).unwrap();
    assert_eq!(state.task(1, idle).unwrap().state, TaskState::Failed);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 3)), Error::DomainHalted);
    assert_eq!(denied(&mut state, |s| s.wake(1, idle, 3)), Error::DomainHalted);
    assert_eq!(denied(&mut state, |s| s.dispatch(0, 10, 3)), Error::NoRunnableTask);
}

#[test]
fn known_late_lease_denies_fresh_dispatch_and_admission_before_advance() {
    let mut state = Scheduler::<1, 3, 2>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    let running = task(&mut state, 1, 10, 0, 0);
    let idle = task(&mut state, 1, 10, 0, 0);
    let lease = state.dispatch(0, 3, 0).unwrap();
    assert_eq!(lease.task, running);
    // No prior advance or stop is necessary to recognize known lateness.
    assert_eq!(denied(&mut state, |s| s.dispatch(1, 5, 4)), Error::NoRunnableTask);
    assert_eq!(denied(&mut state, |s| s.create_task(1,
        TaskSpec { budget_ns: 10, deadline_ns: 0 }, 4)), Error::DomainHalted);
    assert_eq!(state.clock(), 0);
    assert!(!state.accounting(1).unwrap().halted);
    account(state.accounting(1).unwrap().budget, 20, 0, 3, 17);
    assert_eq!(state.task(1, idle).unwrap().state, TaskState::Runnable);
    assert_eq!(state.cpu_lease(0).unwrap(), Some(lease.lease));
    assert_eq!(state.cpu_lease(1).unwrap(), None);
}

#[test]
fn advance_of_known_lateness_halts_domain_and_retains_all_outstanding_grants() {
    let mut state = Scheduler::<1, 4, 2>::new().unwrap();
    state.add_domain(1, 30).unwrap();
    let late = task(&mut state, 1, 10, 0, 0);
    let peer = task(&mut state, 1, 10, 0, 0);
    let runnable = task(&mut state, 1, 10, 0, 0);
    let blocked = task(&mut state, 1, 10, 0, 0);
    state.block(1, blocked, 0).unwrap();
    let a = state.dispatch(0, 3, 0).unwrap();
    let b = state.dispatch(1, 8, 0).unwrap();
    assert_eq!((a.task, b.task), (late, peer));
    state.advance(4).unwrap();
    assert!(state.accounting(1).unwrap().halted);
    for id in [late, peer] {
        assert_eq!(state.task(1, id).unwrap().state, TaskState::Stopping(StopCause::DomainHalted));
    }
    for id in [runnable, blocked] {
        assert_eq!(state.task(1, id).unwrap().state, TaskState::Failed);
    }
    assert_eq!(state.cpu_lease(0).unwrap(), Some(a.lease));
    assert_eq!(state.cpu_lease(1).unwrap(), Some(b.lease));
    account(state.accounting(1).unwrap().budget, 30, 0, 11, 19);
    assert_eq!(state.stop(a.lease, 4, StopOutcome::Yield).unwrap(), TaskState::Failed);
    account(state.accounting(1).unwrap().budget, 30, 4, 8, 18);
    assert_eq!(state.stop(b.lease, 4, StopOutcome::Complete).unwrap(), TaskState::Failed);
    account(state.accounting(1).unwrap().budget, 30, 8, 0, 22);
}

#[test]
fn on_time_peer_stop_observes_late_lease_and_halts_before_clearing_itself() {
    let mut state = Scheduler::<1, 3, 2>::new().unwrap();
    state.add_domain(1, 30).unwrap();
    let late = task(&mut state, 1, 10, 0, 0);
    let peer = task(&mut state, 1, 10, 0, 0);
    let idle = task(&mut state, 1, 10, 0, 0);
    let a = state.dispatch(0, 3, 0).unwrap();
    let b = state.dispatch(1, 8, 0).unwrap();
    assert_eq!((a.task, b.task), (late, peer));
    assert!(4 <= b.stop_by_ns);
    assert_eq!(state.stop(b.lease, 4, StopOutcome::Complete).unwrap(), TaskState::Failed);
    assert!(state.accounting(1).unwrap().halted);
    assert_eq!(state.task(1, idle).unwrap().state, TaskState::Failed);
    assert_eq!(state.task(1, late).unwrap().state, TaskState::Stopping(StopCause::DomainHalted));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(a.lease));
    assert_eq!(state.cpu_lease(1).unwrap(), None);
    account(state.accounting(1).unwrap().budget, 30, 4, 3, 23);
}

#[test]
fn exact_stop_boundary_is_not_overdue_and_does_not_halt_peer_completion() {
    let mut state = Scheduler::<1, 3, 2>::new().unwrap();
    state.add_domain(1, 30).unwrap();
    let boundary = task(&mut state, 1, 10, 0, 0);
    let peer = task(&mut state, 1, 10, 0, 0);
    let idle = task(&mut state, 1, 10, 0, 0);
    let a = state.dispatch(0, 3, 0).unwrap();
    let b = state.dispatch(1, 8, 0).unwrap();
    assert_eq!((a.task, b.task), (boundary, peer));
    assert_eq!(state.stop(b.lease, 3, StopOutcome::Complete).unwrap(), TaskState::Completed);
    assert!(!state.accounting(1).unwrap().halted);
    assert_eq!(state.task(1, boundary).unwrap().state, TaskState::Stopping(StopCause::SliceElapsed));
    assert_eq!(state.cpu_lease(0).unwrap(), Some(a.lease));
    let fresh = state.dispatch(1, 5, 3).unwrap();
    assert_eq!(fresh.task, idle);
    account(state.accounting(1).unwrap().budget, 30, 3, 8, 19);
}

#[test]
fn wake_and_block_cannot_overwrite_failure_from_known_lateness() {
    let mut state = Scheduler::<1, 3, 1>::new().unwrap();
    state.add_domain(1, 30).unwrap();
    let running = task(&mut state, 1, 10, 0, 0);
    let runnable = task(&mut state, 1, 10, 0, 0);
    let blocked = task(&mut state, 1, 10, 0, 0);
    state.block(1, blocked, 0).unwrap();
    assert_eq!(state.dispatch(0, 3, 0).unwrap().task, running);
    assert_eq!(denied(&mut state, |s| s.wake(1, blocked, 4)), Error::DomainHalted);
    assert_eq!(denied(&mut state, |s| s.block(1, runnable, 4)), Error::DomainHalted);
    assert_eq!(state.task(1, blocked).unwrap().state, TaskState::Blocked);
    assert_eq!(state.task(1, runnable).unwrap().state, TaskState::Runnable);
    assert_eq!(state.clock(), 0);
    state.advance(4).unwrap();
    assert_eq!(state.task(1, blocked).unwrap().state, TaskState::Failed);
    assert_eq!(state.task(1, runnable).unwrap().state, TaskState::Failed);
    assert_eq!(denied(&mut state, |s| s.wake(1, blocked, 4)), Error::DomainHalted);
    assert_eq!(denied(&mut state, |s| s.block(1, runnable, 4)), Error::DomainHalted);
}

#[test]
fn stale_requests_at_late_timestamp_cannot_halt_a_domain_or_advance_time() {
    let mut state = Scheduler::<1, 1, 1>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    let old = task(&mut state, 1, 10, 0, 0);
    state.fail(1, old, 0).unwrap();
    state.reap(1, old, 0).unwrap();
    let live = task(&mut state, 1, 10, 0, 0);
    let old_run = state.dispatch(0, 3, 0).unwrap();
    state.stop(old_run.lease, 0, StopOutcome::Yield).unwrap();
    let live_run = state.dispatch(0, 3, 0).unwrap();
    assert_eq!(live_run.task, live);
    assert_eq!(denied(&mut state, |s| s.fail(1, old, 4)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.wake(1, old, 4)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.block(1, old, 4)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.reap(1, old, 4)), Error::StaleTask);
    assert_eq!(denied(&mut state, |s| s.stop(old_run.lease, 4, StopOutcome::Complete)), Error::StaleLease);
    assert_eq!(state.clock(), 0);
    assert!(!state.accounting(1).unwrap().halted);
    assert_eq!(state.task(1, live).unwrap().state, TaskState::Running);
    assert_eq!(state.cpu_lease(0).unwrap(), Some(live_run.lease));
}

#[test]
fn healthy_domain_can_dispatch_at_timestamp_that_reveals_other_domain_lateness() {
    let mut state = Scheduler::<2, 3, 2>::new().unwrap();
    state.add_domain(1, 20).unwrap();
    state.add_domain(2, 20).unwrap();
    let late = task(&mut state, 1, 10, 0, 0);
    let failed_idle = task(&mut state, 1, 10, 0, 0);
    let healthy = task(&mut state, 2, 10, 0, 0);
    let a = state.dispatch(0, 3, 0).unwrap();
    assert_eq!(a.task, late);
    let b = state.dispatch(1, 5, 4).unwrap();
    assert_eq!((b.task, b.grant_ns, b.stop_by_ns), (healthy, 5, 9));
    assert_eq!(state.clock(), 4);
    assert!(state.accounting(1).unwrap().halted);
    assert!(!state.accounting(2).unwrap().halted);
    assert_eq!(state.task(1, failed_idle).unwrap().state, TaskState::Failed);
    assert_eq!(state.task(1, late).unwrap().state, TaskState::Stopping(StopCause::DomainHalted));
    assert_eq!(state.task(2, healthy).unwrap().state, TaskState::Running);
    assert_eq!(state.cpu_lease(0).unwrap(), Some(a.lease));
    account(state.accounting(1).unwrap().budget, 20, 0, 3, 17);
    account(state.accounting(2).unwrap().budget, 20, 0, 5, 15);
}
