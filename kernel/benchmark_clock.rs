//! Single-boot-CPU counter observations. TSC ticks are never CPU cycles or ns.
#[cfg(target_arch = "x86_64")]
use core::arch::{asm, x86_64::__cpuid};
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{Ordering, compiler_fence};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Regression,
}

#[derive(Clone, Copy)]
pub struct Facts {
    pub tsc_supported: bool,
    pub invariant_tsc: bool,
    pub rdtscp_supported: bool,
    pub hypervisor_present: bool,
    pub interrupts_masked: bool,
}

#[cfg(target_arch = "x86_64")]
pub struct Clock {
    last: Option<u64>,
    pub facts: Facts,
}

pub fn checked_delta(start: u64, end: u64) -> Result<u64, Error> {
    end.checked_sub(start).ok_or(Error::Regression)
}

fn decode_features(
    basic_edx: u32,
    basic_ecx: u32,
    extended_edx: u32,
    power_edx: u32,
    flags: u64,
) -> Facts {
    Facts {
        tsc_supported: basic_edx & (1 << 4) != 0,
        invariant_tsc: power_edx & (1 << 8) != 0,
        rdtscp_supported: extended_edx & (1 << 27) != 0,
        hypervisor_present: basic_ecx & (1 << 31) != 0,
        interrupts_masked: flags & (1 << 9) == 0,
    }
}

#[cfg(target_arch = "x86_64")]
impl Clock {
    pub fn probe() -> Result<Self, Error> {
        let basic_max = __cpuid(0).eax;
        let basic = if basic_max >= 1 {
            __cpuid(1)
        } else {
            __cpuid(0)
        };
        let extended_max = __cpuid(0x8000_0000).eax;
        let extended = if extended_max >= 0x8000_0001 {
            __cpuid(0x8000_0001).edx
        } else {
            0
        };
        let power = if extended_max >= 0x8000_0007 {
            __cpuid(0x8000_0007).edx
        } else {
            0
        };
        let flags: u64;
        // Read the actual boot CPU's IF state without enabling interrupts.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        let facts = decode_features(
            if basic_max >= 1 { basic.edx } else { 0 },
            if basic_max >= 1 { basic.ecx } else { 0 },
            extended,
            power,
            flags,
        );
        if !facts.tsc_supported {
            return Err(Error::Unsupported);
        }
        Ok(Self { last: None, facts })
    }

    pub fn read(&mut self) -> Result<u64, Error> {
        // Compiler fences and memory-clobbering asm keep guest work inside its
        // brackets. CPUID serializes the processor on both sides of RDTSC.
        // This conservatively includes counter/serialization overhead.
        compiler_fence(Ordering::SeqCst);
        let _ = __cpuid(0);
        compiler_fence(Ordering::SeqCst);
        let low: u32;
        let high: u32;
        unsafe {
            asm!("rdtsc", out("eax") low, out("edx") high, options(nostack, preserves_flags));
        }
        compiler_fence(Ordering::SeqCst);
        let _ = __cpuid(0);
        compiler_fence(Ordering::SeqCst);
        let value = (u64::from(high) << 32) | u64::from(low);
        if let Some(previous) = self.last {
            checked_delta(previous, value)?;
        }
        self.last = Some(value);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deltas_preserve_zero_and_reject_regression_without_wrapping() {
        assert_eq!(checked_delta(7, 7), Ok(0));
        assert_eq!(checked_delta(7, 12), Ok(5));
        assert_eq!(checked_delta(12, 7), Err(Error::Regression));
        assert_eq!(checked_delta(u64::MAX, 0), Err(Error::Regression));
        assert_eq!(checked_delta(0, u64::MAX), Ok(u64::MAX));
    }
    #[test]
    fn feature_facts_do_not_invent_frequency_or_invariance() {
        let absent = decode_features(0, 0, 0, 0, 1 << 9);
        assert!(!absent.tsc_supported && !absent.rdtscp_supported && !absent.invariant_tsc);
        assert!(!absent.hypervisor_present && !absent.interrupts_masked);
        let present = decode_features(1 << 4, 1 << 31, 1 << 27, 1 << 8, 0);
        assert!(present.tsc_supported && present.rdtscp_supported && present.invariant_tsc);
        assert!(present.hypervisor_present && present.interrupts_masked);
    }
}
