// Original controlled CPL3 protection cases. The parent owns domain context,
// entry/trap validation and the twelve baseline mapping leases.
use super::*;

pub(super) fn run(memory: &mut NativeMemory, handoff: &crate::uefi::Handoff, case: u64) {
    match case {
        2 => unauthorized(memory, handoff.cr3),
        3 => readonly(memory, handoff.cr3),
        5 => kernel_isolation(memory, handoff),
        6 => data_nx(memory, handoff.cr3),
        _ => fail("matrix-protection-case"),
    }
}

fn target(memory: &mut NativeMemory) -> (CapabilityRef, u64) {
    // Baseline pages already exist. The target is the final new A allocation;
    // initialization and publication use the parent's checked private callback.
    let capability = ok(memory.allocate_initialized_page(1, VICTIM), "matrix-protection-allocation");
    let physical = ok(memory.region_info(1, capability), "matrix-protection-info").backing.start();
    owned(memory, 1, capability, physical);
    (capability, physical)
}

fn readonly_child(memory: &mut NativeMemory, parent: CapabilityRef) -> CapabilityRef {
    let rights = Rights::READ | Rights::MAP;
    let child = ok(memory.delegate(1, parent, 2, rights, 0, 4096), "matrix-protection-delegation");
    delegated(parent, child, rights);
    child
}

fn read_observed(domain: u64, page: u64, physical: u64) -> [u8; 32] {
    // The exact load must return through the compiled INT80 gate with VICTIM
    // in the preserved RAX. Hash the whole retained backing after that control.
    read(domain, page, VICTIM, "protection_read");
    let observed = unsafe { digest(physical) };
    event("read_observed", || {
        n("domain", domain);
        x("page", page);
        hash("sha256", observed);
    });
    observed
}

fn unchanged(page: u64, physical: u64, before: [u8; 32]) {
    let after = unsafe { digest(physical) };
    if before != after { fail("matrix-protection-bytes-changed"); }
    event("sentinel_unchanged", || {
        x("page", page);
        hash("before_sha256", before);
        hash("after_sha256", after);
    });
}

fn unauthorized(memory: &mut NativeMemory, kernel_root: u64) {
    let (capability, physical) = target(memory);
    let mapping = install(memory, 1, capability, UNAUTHORIZED, Access::Read);
    if mapping.page.physical != physical { fail("matrix-unauthorized-map-identity"); }
    if root(2).translation(UNAUTHORIZED).is_some() { fail("matrix-unauthorized-pte-present"); }
    let before = read_observed(1, UNAUTHORIZED, physical);
    fault(2, UNAUTHORIZED, ptr::addr_of!(crate::k02_cpu::k02_probe_unauthorized_read), 4,
          "unauthorized_read");
    if before != unsafe { digest(physical) } { fail("matrix-unauthorized-bytes-changed"); }
    remove(memory, mapping, kernel_root);
    ok(memory.release(1, capability), "matrix-unauthorized-release");
}

fn readonly(memory: &mut NativeMemory, kernel_root: u64) {
    let (owner, physical) = target(memory);
    let child = readonly_child(memory, owner);
    let mapping = install(memory, 2, child, READONLY, Access::Read);
    if mapping.page.physical != physical { fail("matrix-readonly-map-identity"); }
    let before = read_observed(2, READONLY, physical);
    fault(2, READONLY, ptr::addr_of!(crate::k02_cpu::k02_probe_readonly_write), 7,
          "readonly_write");
    unchanged(READONLY, physical, before);
    remove(memory, mapping, kernel_root);
    ok(memory.release(2, child), "matrix-readonly-child-release");
    ok(memory.release(1, owner), "matrix-readonly-owner-release");
}

fn supervisor_page(handoff: &crate::uefi::Handoff, physical: u64) {
    let end = physical.checked_add(4096).unwrap_or_else(|| fail("matrix-supervisor-page-overflow"));
    if physical % 4096 != 0 || physical < handoff.image.start || end > handoff.image.end
        || physical == crate::k02_cpu::code_page()
    { fail("matrix-supervisor-page-ownership"); }
    let translation = ok(root(2).translate(physical), "matrix-supervisor-translation");
    if translation.physical != physical || translation.user {
        fail("matrix-supervisor-page-permissions");
    }
}

fn kernel_isolation(memory: &mut NativeMemory, handoff: &crate::uefi::Handoff) {
    // Warm the real B root before hashing PML4 entries. This sets the hardware
    // Accessed state for the shared low/code ancestor without changing policy.
    read(2, OWN, VICTIM ^ 2, "supervisor_prime");
    let kernel = handoff.image.start; // Immutable, loaded PE-header page.
    let policy = memory.protected_state_address();
    let table = ok(root(2).protected_page_physical(), "matrix-supervisor-table");
    if kernel == policy || kernel == table || policy == table {
        fail("matrix-supervisor-page-alias");
    }
    for page in [kernel, policy, table] { supervisor_page(handoff, page); }
    let probes = [
        (kernel, "kernel_read", "kernel_write",
         ptr::addr_of!(crate::k02_cpu::k02_probe_kernel_read),
         ptr::addr_of!(crate::k02_cpu::k02_probe_kernel_write)),
        (policy, "policy_read", "policy_write",
         ptr::addr_of!(crate::k02_cpu::k02_probe_policy_read),
         ptr::addr_of!(crate::k02_cpu::k02_probe_policy_write)),
        (table, "page_table_read", "page_table_write",
         ptr::addr_of!(crate::k02_cpu::k02_probe_page_table_read),
         ptr::addr_of!(crate::k02_cpu::k02_probe_page_table_write)),
    ];
    for (page, read_name, write_name, read_probe, write_probe) in probes {
        let before = unsafe { digest(page) };
        fault(2, page, read_probe, 5, read_name);
        fault(2, page, write_probe, 7, write_name);
        unchanged(page, page, before);
    }
}

fn data_nx(memory: &mut NativeMemory, kernel_root: u64) {
    let (owner, physical) = target(memory);
    let child = readonly_child(memory, owner);
    let mapping = install(memory, 2, child, NX, Access::Read);
    if mapping.page.physical != physical { fail("matrix-nx-map-identity"); }
    // A present supervisor-only target can also cause #PF21 on a user fetch.
    // This actual successful CPL3 data read removes that alternative cause.
    read(2, NX, VICTIM, "nx_data_read");
    let supported = core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 20) != 0;
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low,
                         out("edx") high, options(nostack));
    }
    let _ = high;
    let enabled = low & (1 << 11) != 0;
    let translation = ok(root(2).translate(NX), "matrix-nx-translation");
    if !supported || !enabled || !translation.user || translation.executable
        || translation.physical != mapping.page.physical
    { fail("matrix-nx-admission"); }
    event("nx_confirmed", || { n("supported", supported as u64); n("enabled", enabled as u64); });
    // Parent admits a null code-label pointer only for this exact NX fetch,
    // using NX itself as both the instruction and expected fault RIP.
    fault(2, NX, ptr::null(), 21, "nx_fetch");
    remove(memory, mapping, kernel_root);
    ok(memory.release(2, child), "matrix-nx-child-release");
    ok(memory.release(1, owner), "matrix-nx-owner-release");
}
