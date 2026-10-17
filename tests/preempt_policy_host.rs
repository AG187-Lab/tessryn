//! Actual unchanged scheduler policy, numerical adapter tests only.
//! These tests execute no interrupt, HPET, CPL3 program or context switch.
#[path = "../kernel/preempt_policy.rs"]
mod preempt_policy;
use preempt_policy::{Error, Grant, HARD_QUANTUM_NS, Policy, SOFT_TARGET_NS};
use tessryn_scheduler::{Error as CoreError, StopCause, StopOutcome, TaskState};

fn policy() -> Policy {
    Policy::new(0, [2_000_000_000; 2], [0; 2]).unwrap()
}
fn snapshot(p: &Policy) -> String {
    format!("{p:?}")
}
fn denied<T: core::fmt::Debug>(p: &mut Policy, f: impl FnOnce(&mut Policy) -> Result<T, Error>) -> Error {
    let before = snapshot(p);
    let error = f(p).expect_err("rejected adapter call succeeded");
    assert_eq!(snapshot(p), before, "adapter rejection changed protected state");
    error
}
fn actual(p: &Policy, index: usize, consumed: u128, reserved: u64) {
    let task = p.task(index).unwrap();
    let domain = p.accounting(index).unwrap();
    assert_eq!(task.budget.consumed_ns, consumed);
    assert_eq!(task.budget.reserved_ns, reserved);
    assert_eq!(domain.budget, task.budget);
}
fn mismatch(p: &mut Policy, grant: Grant) {
    assert_eq!(denied(p, |p| p.stop(grant, u64::MAX, StopOutcome::Complete)), Error::StaleGrant);
}

#[test]
fn exactly_two_permanent_protected_task_mappings() {
    let p = policy();
    assert_eq!(p.task_id(0).unwrap().domain(), 1);
    assert_eq!(p.task_id(1).unwrap().domain(), 2);
    assert_ne!(p.task_id(0).unwrap(), p.task_id(1).unwrap());
    assert_eq!(p.task_id(2), Err(Error::InvalidIndex));
    assert_eq!(p.task_id(usize::MAX), Err(Error::InvalidIndex));
    assert_eq!(p.task(2), Err(Error::InvalidIndex));
    assert_eq!(p.accounting(2), Err(Error::InvalidIndex));
    assert_eq!(p.terminal(2), Err(Error::InvalidIndex));
    assert_eq!(p.clock(), 0);
    assert!(p.active().is_none() && p.cpu_lease().unwrap().is_none());
}

#[test]
fn admission_rejects_zero_limits_and_expired_deadlines() {
    for limits in [[0, 1], [1, 0]] {
        assert!(matches!(Policy::new(0, limits, [0; 2]), Err(Error::Scheduler(CoreError::InvalidBudget))));
    }
    for deadlines in [[5, 0], [0, 5], [4, 0]] {
        assert!(matches!(Policy::new(5, [10; 2], deadlines), Err(Error::Scheduler(CoreError::DeadlineExpired))));
    }
}

#[test]
fn hard_grant_and_early_soft_target_use_actual_remaining_budget() {
    for (limit, distance) in [(1, 1), (2, 1), (3, 1), (19_000_000, 9_500_000),
                             (20_000_000, 10_000_000), (80_000_000, 10_000_000),
                             (2_000_000_000, 10_000_000)] {
        let mut p = Policy::new(7, [limit, 2_000_000_000], [0; 2]).unwrap();
        let g = p.dispatch(7).unwrap();
        assert_eq!(g.index, 0);
        assert_eq!(g.dispatch.grant_ns, limit.min(HARD_QUANTUM_NS));
        assert_eq!(g.dispatch.stop_by_ns, 7 + limit.min(HARD_QUANTUM_NS));
        assert_eq!(g.soft_ns, 7 + distance);
        assert!(g.soft_ns <= g.dispatch.stop_by_ns);
        assert_eq!(p.cpu_lease().unwrap(), Some(g.dispatch.lease));
        actual(&p, 0, 0, limit.min(HARD_QUANTUM_NS));
    }
    assert_eq!(SOFT_TARGET_NS, 10_000_000);
}

#[test]
fn deadline_caps_hard_grant_and_soft_target_without_rounding_it_up() {
    let mut p = Policy::new(40, [100; 2], [47, 0]).unwrap();
    let g = p.dispatch(40).unwrap();
    assert_eq!((g.dispatch.grant_ns, g.soft_ns, g.dispatch.stop_by_ns), (7, 43, 47));
    assert_eq!(p.stop(g, 47, StopOutcome::Complete).unwrap(), TaskState::DeadlineExpired);
    actual(&p, 0, 7, 0);
    assert!(!p.accounting(0).unwrap().halted);
}

#[test]
fn early_timer_target_does_not_clamp_actual_charged_runtime() {
    let mut p = policy();
    let g = p.dispatch(0).unwrap();
    assert_eq!(g.soft_ns, 10_000_000);
    assert_eq!(p.stop(g, 17_000_000, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    actual(&p, 0, 17_000_000, 0);
    assert_eq!(p.clock(), 17_000_000);
    assert!(p.active().is_none() && p.cpu_lease().unwrap().is_none());
    assert!(!p.accounting(0).unwrap().halted);
}

#[test]
fn strict_hard_overrun_is_fully_charged_and_domain_halt_is_sticky() {
    let mut p = Policy::new(0, [80_000_000, 2_000_000_000], [0; 2]).unwrap();
    let g = p.dispatch(0).unwrap();
    assert_eq!(p.stop(g, 80_000_001, StopOutcome::Yield).unwrap(), TaskState::Failed);
    actual(&p, 0, 80_000_001, 0);
    assert!(p.accounting(0).unwrap().halted);
    assert!(p.terminal(0).unwrap());
    assert_eq!(denied(&mut p, |p| p.wake(0, 80_000_002)), Error::Scheduler(CoreError::DomainHalted));
    let other = p.dispatch(80_000_001).unwrap();
    assert_eq!(other.index, 1);
    assert!(!p.accounting(1).unwrap().halted);
    assert_eq!(p.stop(other, 80_000_002, StopOutcome::Complete).unwrap(), TaskState::Completed);
}

#[test]
fn exact_budget_stop_exhausts_without_halt_and_never_refills() {
    let mut p = Policy::new(0, [80; 2], [0; 2]).unwrap();
    p.block(1, 0).unwrap();
    let first = p.dispatch(0).unwrap();
    assert_eq!(p.stop(first, 30, StopOutcome::Yield).unwrap(), TaskState::Runnable);
    let last = p.dispatch(30).unwrap();
    assert_eq!((last.dispatch.grant_ns, last.soft_ns, last.dispatch.stop_by_ns), (50, 55, 80));
    assert_eq!(p.stop(last, 80, StopOutcome::Yield).unwrap(), TaskState::Exhausted);
    actual(&p, 0, 80, 0);
    assert!(!p.accounting(0).unwrap().halted);
    p.advance(1_000_000).unwrap();
    assert_eq!(denied(&mut p, |p| p.wake(0, 1_000_000)), Error::Scheduler(CoreError::State));
    assert_eq!(denied(&mut p, |p| p.dispatch(1_000_000)), Error::Scheduler(CoreError::NoRunnableTask));
    actual(&p, 0, 80, 0);
    p.wake(1, 1_000_000).unwrap();
    assert_eq!(p.dispatch(1_000_000).unwrap().index, 1);
}

#[test]
fn completion_at_budget_cap_succeeds_but_deadline_boundary_expires() {
    let mut p = Policy::new(0, [10; 2], [0, 10]).unwrap();
    let a = p.dispatch(0).unwrap();
    assert_eq!(p.stop(a, 10, StopOutcome::Complete).unwrap(), TaskState::Completed);
    assert!(matches!(p.dispatch(10), Err(Error::Scheduler(CoreError::NoRunnableTask))));
    p.advance(10).unwrap();
    assert_eq!(p.task(1).unwrap().state, TaskState::DeadlineExpired);
    actual(&p, 1, 0, 0);
}

#[test]
fn trusted_bootstrap_block_wake_and_domain_round_robin() {
    let mut p = policy();
    p.block(1, 0).unwrap();
    let a = p.dispatch(0).unwrap();
    assert_eq!(a.index, 0);
    p.stop(a, 5, StopOutcome::Yield).unwrap();
    let a = p.dispatch(5).unwrap();
    assert_eq!(a.index, 0);
    p.stop(a, 9, StopOutcome::Yield).unwrap();
    p.wake(1, 9).unwrap();
    let b = p.dispatch(9).unwrap();
    assert_eq!(b.index, 1);
    p.stop(b, 12, StopOutcome::Yield).unwrap();
    assert_eq!(p.dispatch(12).unwrap().index, 0);
    actual(&p, 0, 9, HARD_QUANTUM_NS);
    actual(&p, 1, 3, 0);
}

#[test]
fn blocked_idle_advance_charges_no_task_and_wake_refunds_nothing() {
    let mut p = policy();
    p.block(0, 0).unwrap();
    p.block(1, 0).unwrap();
    p.advance(500_000_000).unwrap();
    assert_eq!(denied(&mut p, |p| p.dispatch(500_000_000)), Error::Scheduler(CoreError::NoRunnableTask));
    for index in 0..2 { actual(&p, index, 0, 0); }
    p.wake(1, 500_000_000).unwrap();
    let b = p.dispatch(500_000_000).unwrap();
    p.stop(b, 510_000_000, StopOutcome::Block).unwrap();
    p.advance(900_000_000).unwrap();
    p.wake(1, 900_000_000).unwrap();
    actual(&p, 1, 10_000_000, 0);
    assert_eq!(p.task(1).unwrap().budget.available_ns(), 1_990_000_000);
}

#[test]
fn blocked_deadline_is_terminal_without_fictitious_cpu_consumption() {
    let mut p = Policy::new(0, [100; 2], [5, 7]).unwrap();
    p.block(0, 0).unwrap(); p.block(1, 0).unwrap();
    p.advance(5).unwrap();
    assert_eq!(p.task(0).unwrap().state, TaskState::DeadlineExpired);
    assert_eq!(denied(&mut p, |p| p.wake(0, 5)), Error::Scheduler(CoreError::DeadlineExpired));
    assert!(!p.terminal(1).unwrap());
    p.advance(7).unwrap();
    assert!(p.terminal(1).unwrap());
    actual(&p, 0, 0, 0); actual(&p, 1, 0, 0);
}

#[test]
fn advance_requests_stop_but_keeps_exact_cpu_reservation_owned() {
    let mut p = Policy::new(0, [100; 2], [0; 2]).unwrap();
    let g = p.dispatch(0).unwrap();
    p.advance(100).unwrap();
    assert_eq!(p.task(0).unwrap().state, TaskState::Stopping(StopCause::SliceElapsed));
    assert_eq!(p.cpu_lease().unwrap(), Some(g.dispatch.lease));
    assert!(p.active().unwrap().dispatch.lease == g.dispatch.lease);
    actual(&p, 0, 0, 100);
    assert_eq!(denied(&mut p, |p| p.dispatch(100)), Error::Scheduler(CoreError::CpuBusy));
    assert_eq!(denied(&mut p, |p| p.block(0, 100)), Error::Scheduler(CoreError::State));
    assert_eq!(denied(&mut p, |p| p.wake(0, 100)), Error::Scheduler(CoreError::State));
    assert_eq!(p.stop(g, 100, StopOutcome::Yield).unwrap(), TaskState::Exhausted);
}

#[test]
fn failure_keeps_cpu_owned_until_real_stop_and_overrides_completion() {
    let mut p = policy();
    let g = p.dispatch(0).unwrap();
    p.fail(0, 3).unwrap();
    assert_eq!(p.task(0).unwrap().state, TaskState::Stopping(StopCause::FailureRequested));
    assert_eq!(p.cpu_lease().unwrap(), Some(g.dispatch.lease));
    assert_eq!(p.stop(g, 5, StopOutcome::Complete).unwrap(), TaskState::Failed);
    assert!(!p.accounting(0).unwrap().halted);
    actual(&p, 0, 5, 0);
}

#[test]
fn invalid_indices_are_rejected_before_any_clock_or_policy_mutation() {
    let mut p = policy();
    for index in [2, usize::MAX] {
        assert_eq!(denied(&mut p, |p| p.block(index, 10)), Error::InvalidIndex);
        assert_eq!(denied(&mut p, |p| p.wake(index, 10)), Error::InvalidIndex);
        assert_eq!(denied(&mut p, |p| p.fail(index, 10)), Error::InvalidIndex);
    }
}

#[test]
fn stale_and_foreign_grant_fields_cannot_stop_or_charge_another_context() {
    let mut p = policy();
    let g = p.dispatch(0).unwrap();
    mismatch(&mut p, Grant { index: 1, ..g });
    mismatch(&mut p, Grant { index: usize::MAX, ..g });
    mismatch(&mut p, Grant { soft_ns: g.soft_ns + 1, ..g });
    let mut forged = g; forged.dispatch.grant_ns += 1; mismatch(&mut p, forged);
    let mut forged = g; forged.dispatch.stop_by_ns += 1; mismatch(&mut p, forged);
    let mut forged = g; forged.dispatch.task = p.task_id(1).unwrap(); mismatch(&mut p, forged);
    p.stop(g, 1, StopOutcome::Yield).unwrap();
    let replacement = p.dispatch(1).unwrap();
    mismatch(&mut p, g);
    assert_eq!(p.cpu_lease().unwrap(), Some(replacement.dispatch.lease));
    p.stop(replacement, 2, StopOutcome::Complete).unwrap();
    mismatch(&mut p, replacement);
}

#[test]
fn backwards_stop_and_all_mutations_leave_exact_adapter_snapshot_unchanged() {
    let mut p = Policy::new(5, [100; 2], [0; 2]).unwrap();
    assert_eq!(denied(&mut p, |p| p.advance(4)), Error::Scheduler(CoreError::TimeRegression));
    assert_eq!(denied(&mut p, |p| p.block(0, 4)), Error::Scheduler(CoreError::TimeRegression));
    assert_eq!(denied(&mut p, |p| p.wake(0, 4)), Error::Scheduler(CoreError::TimeRegression));
    assert_eq!(denied(&mut p, |p| p.fail(0, 4)), Error::Scheduler(CoreError::TimeRegression));
    assert_eq!(denied(&mut p, |p| p.dispatch(4)), Error::Scheduler(CoreError::TimeRegression));
    let g = p.dispatch(5).unwrap();
    assert_eq!(denied(&mut p, |p| p.stop(g, 4, StopOutcome::Yield)), Error::Scheduler(CoreError::TimeRegression));
    assert_eq!(p.cpu_lease().unwrap(), Some(g.dispatch.lease));
    p.stop(g, 6, StopOutcome::Block).unwrap();
    assert_eq!(denied(&mut p, |p| p.wake(0, 5)), Error::Scheduler(CoreError::TimeRegression));
}

#[test]
fn hard_deadline_overflow_rejects_without_publishing_dispatch_or_cursor() {
    let mut p = Policy::new(u64::MAX - 10, [u64::MAX; 2], [0; 2]).unwrap();
    assert_eq!(denied(&mut p, |p| p.dispatch(u64::MAX - 10)), Error::Scheduler(CoreError::Overflow));
    assert!(p.active().is_none() && p.cpu_lease().unwrap().is_none());
    let mut capped = Policy::new(u64::MAX - 10, [u64::MAX; 2], [u64::MAX, 0]).unwrap();
    let g = capped.dispatch(u64::MAX - 10).unwrap();
    assert_eq!((g.soft_ns, g.dispatch.stop_by_ns), (u64::MAX - 5, u64::MAX));
    assert_eq!(capped.stop(g, u64::MAX, StopOutcome::Yield).unwrap(), TaskState::DeadlineExpired);
}
