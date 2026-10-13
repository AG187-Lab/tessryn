// Original first native owned-memory/protection slice. Single boot CPU only.
// Test programs are image-bound probes, not a service syscall implementation.
use core::mem::size_of;
use core::ptr;
use crate::diagnostics::{fail, finish, print};
use crate::k02_memory::{Access, DOMAIN_A, DOMAIN_B, DOMAIN_BUDGET_PAGES, PageLease};
use crate::k02_paging::{Tables, UserAccess};

pub const USER_CODE: u64 = 0x1_0000_0000;
pub const USER_OWN: u64 = USER_CODE + 0x1000;
pub const USER_STACK: u64 = USER_CODE + 0x2000;
pub const USER_FOREIGN: u64 = USER_CODE + 0x3000;
pub const USER_READONLY: u64 = USER_CODE + 0x4000;
const OWN_SEED: u64 = 0x5445_5353_4f57_4e42;
const VICTIM_SEED: u64 = 0x5445_5353_5649_4354;
const FOREIGN_SEED: u64 = 0x5445_5353_464f_524e;
const WRITE_VALUE: u64 = 0x5445_5353_5752_4954;

static mut ROOT_A: Tables<16> = Tables::empty();
static mut ROOT_B: Tables<16> = Tables::empty();

#[derive(Clone, Copy)]
struct Probe {
    active: bool, domain: u64, vector: u64, error: u64, rip: u64,
    target: u64, own: bool, returned: bool,
}
static mut PROBE: Probe = Probe { active: false, domain: 0, vector: 0, error: 0,
    rip: 0, target: 0, own: false, returned: false };

fn checked<T, E>(result: Result<T, E>, reason: &'static str) -> T {
    result.unwrap_or_else(|_| fail(reason))
}

fn case() -> &'static str {
    if cfg!(k02_case = "own_page") { "own_page" }
    else if cfg!(k02_case = "foreign_read") { "foreign_read" }
    else if cfg!(k02_case = "kernel_read") { "kernel_read" }
    else if cfg!(k02_case = "readonly_write") { "readonly_write" }
    else { fail("k02-unknown-case") }
}

fn pattern(seed: u64, index: usize) -> u64 { seed ^ index as u64 }
unsafe fn fill_page(physical: u64, seed: u64) {
    for index in 0..512 {
        // SAFETY: caller holds an exclusive checked operation/mapping lease.
        unsafe { (physical as *mut u64).add(index).write_volatile(pattern(seed, index)); }
    }
}
unsafe fn page_matches(physical: u64, seed: u64, own_write: bool) -> bool {
    for index in 0..512 {
        let expected = if own_write && index == 1 { WRITE_VALUE } else { pattern(seed, index) };
        if unsafe { (physical as *const u64).add(index).read_volatile() } != expected { return false; }
    }
    true
}
unsafe fn page_zero(physical: u64) -> bool {
    for index in 0..512 {
        if unsafe { (physical as *const u64).add(index).read_volatile() } != 0 { return false; }
    }
    true
}

fn seed_root(root: &mut Tables<16>, handoff: &crate::uefi::Handoff) {
    let base = root as *const Tables<16> as u64;
    let end = base.checked_add(size_of::<Tables<16>>() as u64).unwrap_or_else(|| fail("k02-root-pool-overflow"));
    if base < handoff.image.start || end > handoff.image.end { fail("k02-root-pool-ownership"); }
    checked(root.reset(handoff.physical_bits, base), "k02-root-reset");
    checked(root.map_supervisor_range(crate::paging::Range { start: 0, end: crate::paging::LOW_LIMIT }), "k02-low-map");
    for range in [handoff.image, handoff.stack, handoff.map_allocation] {
        checked(root.map_supervisor_range(range), "k02-live-map");
    }
    for range in [handoff.high_scratch, handoff.framebuffer].into_iter().flatten() {
        checked(root.map_supervisor_range(range), "k02-optional-map");
    }
    for index in 0..handoff.descriptors() {
        let descriptor = handoff.descriptor(index);
        if descriptor.attributes & crate::uefi::RUNTIME != 0 {
            let bytes = descriptor.pages.checked_mul(4096).unwrap_or_else(|| fail("k02-runtime-size"));
            checked(root.map_supervisor_range(checked(crate::paging::Range::checked(descriptor.start, bytes),
                "k02-runtime-range")), "k02-runtime-map");
        }
    }
    checked(root.validate(), "k02-root-validation");
}

fn map(root: &mut Tables<16>, role: &str, va: u64, page: PageLease, domain: u64) {
    let access = if page.writable { UserAccess::ReadWrite } else { UserAccess::ReadOnly };
    checked(root.map_data(va, page.physical, access), "k02-data-map");
    print(format_args!("TESSRYN_K02_MAPPING role={role} domain={domain} virtual={va:#x} physical={:#x} page_bytes=4096 writable={} nx=1\n", page.physical, page.writable as u8));
}

pub fn run(handoff: &crate::uefi::Handoff) -> ! {
    let case = case();
    crate::k02_cpu::initialize(handoff);
    // All policy publication follows successful firmware exit and K01 CPU
    // ownership. The map is copied; no earlier retry plan can grant authority.
    let memory = checked(unsafe { crate::k02_memory::initialize(handoff) }, "k02-inventory");
    checked(memory.create_domain(DOMAIN_A, DOMAIN_BUDGET_PAGES), "k02-domain-a");
    checked(memory.create_domain(DOMAIN_B, DOMAIN_BUDGET_PAGES), "k02-domain-b");
    print(format_args!("TESSRYN_K02_INVENTORY descriptors={} available_pages={} protected_state={:#x} source=final_successful_handoff\n",
        handoff.descriptors(), memory.available_pages(), memory.protected_state_address()));

    let cap_a = checked(memory.allocate_page(DOMAIN_A), "k02-victim-allocation");
    // Keep the inaccessible foreign page distinct from the page intentionally
    // delegated read-only. B receives no authority for this allocation.
    let cap_foreign = checked(memory.allocate_page(DOMAIN_A), "k02-foreign-allocation");
    let cap_b = checked(memory.allocate_page(DOMAIN_B), "k02-own-allocation");
    let cap_stack = checked(memory.allocate_page(DOMAIN_B), "k02-stack-allocation");
    let operation = checked(memory.acquire_page(DOMAIN_A, cap_a, Access::Write), "k02-victim-fill-authority");
    if !unsafe { page_zero(operation.physical) } { fail("k02-victim-not-scrubbed"); }
    unsafe { fill_page(operation.physical, VICTIM_SEED); }
    checked(memory.complete(DOMAIN_A, operation.lease), "k02-fill-complete");
    // A synchronous privileged fill has ended. Unlike mappings, this operation
    // exposed no user PTE; no translation teardown is required to acknowledge it.
    checked(unsafe { memory.quiesce(operation.lease) }, "k02-fill-quiescence");
    let victim = operation.physical;
    let foreign_fill = checked(memory.acquire_page(DOMAIN_A, cap_foreign, Access::Write), "k02-foreign-fill-authority");
    if !unsafe { page_zero(foreign_fill.physical) } { fail("k02-foreign-not-scrubbed"); }
    unsafe { fill_page(foreign_fill.physical, FOREIGN_SEED); }
    checked(memory.complete(DOMAIN_A, foreign_fill.lease), "k02-foreign-fill-complete");
    checked(unsafe { memory.quiesce(foreign_fill.lease) }, "k02-foreign-fill-quiescence");
    let foreign = foreign_fill.physical;
    if foreign == victim { fail("k02-foreign-share-alias"); }
    let own = checked(memory.map_page(DOMAIN_B, cap_b, Access::Write), "k02-own-map-authority");
    let stack = checked(memory.map_page(DOMAIN_B, cap_stack, Access::Write), "k02-stack-map-authority");
    if !unsafe { page_zero(own.physical) && page_zero(stack.physical) } { fail("k02-pages-not-scrubbed"); }
    unsafe { fill_page(own.physical, OWN_SEED); }
    let cap_read = checked(memory.delegate_readonly(DOMAIN_A, cap_a, DOMAIN_B), "k02-readonly-delegation");
    let readonly = checked(memory.map_page(DOMAIN_B, cap_read, Access::Read), "k02-readonly-map-authority");
    if readonly.physical != victim || readonly.writable { fail("k02-readonly-identity"); }
    if checked(memory.accounting(DOMAIN_A), "k02-accounting-a").charged_pages != 2 {
        fail("k02-share-charged-twice");
    }

    let root_a = unsafe { &mut *ptr::addr_of_mut!(ROOT_A) };
    let root_b = unsafe { &mut *ptr::addr_of_mut!(ROOT_B) };
    seed_root(root_a, handoff); seed_root(root_b, handoff);
    checked(root_a.map_trusted_code(USER_CODE, crate::k02_cpu::code_page()), "k02-code-a");
    checked(root_b.map_trusted_code(USER_CODE, crate::k02_cpu::code_page()), "k02-code-b");
    map(root_b, "own", USER_OWN, own, DOMAIN_B);
    map(root_b, "stack", USER_STACK, stack, DOMAIN_B);
    map(root_b, "readonly", USER_READONLY, readonly, DOMAIN_B);
    // A's page exists only in A's root. B has neither a PTE at this virtual
    // address nor user authority at the coarse supervisor physical alias.
    let foreign_a = checked(memory.map_page(DOMAIN_A, cap_foreign, Access::Read), "k02-foreign-map-authority");
    if foreign_a.physical != foreign { fail("k02-foreign-map-identity"); }
    map(root_a, "foreign", USER_FOREIGN, foreign_a, DOMAIN_A);
    if root_b.translation(USER_FOREIGN).is_some() || root_b.root() == root_a.root() { fail("k02-domain-roots"); }
    checked(root_a.validate(), "k02-final-root-a"); checked(root_b.validate(), "k02-final-root-b");

    let (entry, expected_rip, target, vector, error) = if case == "own_page" {
        (ptr::addr_of!(crate::k02_cpu::k02_probe_own_write),
         USER_CODE + crate::k02_cpu::probe_offset(ptr::addr_of!(crate::k02_cpu::k02_probe_own_return)) + 2,
         USER_OWN, 128, 0)
    } else if case == "foreign_read" {
        let symbol = ptr::addr_of!(crate::k02_cpu::k02_probe_foreign_read);
        (symbol, USER_CODE + crate::k02_cpu::probe_offset(symbol), USER_FOREIGN, 14, 4)
    } else if case == "kernel_read" {
        let symbol = ptr::addr_of!(crate::k02_cpu::k02_probe_kernel_read);
        (symbol, USER_CODE + crate::k02_cpu::probe_offset(symbol), memory.protected_state_address(), 14, 5)
    } else {
        let symbol = ptr::addr_of!(crate::k02_cpu::k02_probe_readonly_write);
        (symbol, USER_CODE + crate::k02_cpu::probe_offset(symbol), USER_READONLY, 14, 7)
    };
    let instruction = USER_CODE + crate::k02_cpu::probe_offset(entry);
    let trap_stack = crate::k02_cpu::trap_stack();
    print(format_args!("TESSRYN_K02_USER_ENTER case={case} domain=2 root={:#x} code={USER_CODE:#x} code_physical={:#x} stack_start={USER_STACK:#x} stack_end={:#x} instruction={instruction:#x} probe_rip={expected_rip:#x} target={target:#x} trap_start={:#x} trap_end={:#x}\n",
        root_b.root(), crate::k02_cpu::code_page(), USER_STACK + 4096, trap_stack.start, trap_stack.end));
    unsafe { ptr::addr_of_mut!(PROBE).write(Probe { active: true, domain: DOMAIN_B,
        vector, error, rip: expected_rip, target, own: case == "own_page", returned: false }); }
    unsafe { crate::k02_cpu::enter(root_b.root(), instruction, USER_STACK + 4096 - 16, target, WRITE_VALUE); }
    let observed = unsafe { ptr::addr_of!(PROBE).read() };
    if !observed.returned || observed.active { fail("k02-probe-return-unobserved"); }
    let victim_ok = unsafe { page_matches(victim, VICTIM_SEED, false) };
    let foreign_ok = unsafe { page_matches(foreign, FOREIGN_SEED, false) };
    let own_ok = unsafe { page_matches(own.physical, OWN_SEED, case == "own_page") };
    if !victim_ok || !foreign_ok || !own_ok { fail("k02-victim-foreign-or-own-bytes"); }
    print(format_args!("TESSRYN_K02_SENTINELS victim_unchanged=1 foreign_unchanged=1 own_verified=1 pages_scrubbed={} victim={victim:#x} foreign={foreign:#x} own={:#x}\n", memory.scrubbed_pages(), own.physical));

    // Retain every mapping lease until PTE removal AND actual CR3 invalidation.
    for (root, va, lease) in [(root_b as *mut Tables<16>, USER_OWN, own),
        (root_b, USER_STACK, stack), (root_b, USER_READONLY, readonly), (root_a, USER_FOREIGN, foreign_a)] {
        checked(memory.fence(lease.lease), "k02-mapping-fence");
        let removed = checked(unsafe { (&mut *root).unmap_user(va) }, "k02-pte-remove");
        if removed.physical_page != lease.physical { fail("k02-removed-lease-identity"); }
        // With no PCID/global mappings and one CPU, loading each now-inactive
        // root then the kernel root completes the declared translation fence.
        unsafe { crate::k02_cpu::reload((&*root).root()); crate::k02_cpu::reload(handoff.cr3); }
        checked(unsafe { memory.quiesce(lease.lease) }, "k02-mapping-quiescence");
        print(format_args!("TESSRYN_K02_TEARDOWN virtual={va:#x} physical={:#x} order=fence_pte_remove_cr3_reload_quiesce\n", lease.physical));
    }
    checked(root_b.unmap_user(USER_CODE), "k02-code-b-remove");
    checked(root_a.unmap_user(USER_CODE), "k02-code-a-remove");
    unsafe { crate::k02_cpu::reload(root_b.root()); crate::k02_cpu::reload(root_a.root()); crate::k02_cpu::reload(handoff.cr3); }
    checked(memory.release(DOMAIN_B, cap_read), "k02-share-release");
    checked(memory.release(DOMAIN_A, cap_a), "k02-victim-release");
    checked(memory.release(DOMAIN_A, cap_foreign), "k02-foreign-release");
    checked(memory.release(DOMAIN_B, cap_b), "k02-own-release");
    checked(memory.release(DOMAIN_B, cap_stack), "k02-stack-release");
    if memory.allocated_pages() != 0 { fail("k02-frame-release"); }
    print(format_args!("TESSRYN_K02_PASS case={case} cpl3_observed=1 owned_pages_after=0 scope=single_cpu_emulated_protection_slice\n"));
    finish(true)
}

pub fn handle_exception(frame: &crate::cpu::ExceptionFrame, cr2: u64) {
    let mut expected = unsafe { ptr::addr_of!(PROBE).read() };
    if !expected.active { return; }
    let trap = crate::k02_cpu::trap_stack();
    let frame_address = frame as *const crate::cpu::ExceptionFrame as u64;
    if frame_address < trap.start || frame_address + size_of::<crate::cpu::ExceptionFrame>() as u64 > trap.end
        || expected.domain != DOMAIN_B || frame.cs != crate::k02_cpu::USER_CS || frame.ss != crate::k02_cpu::USER_SS
        || frame.rip != expected.rip || frame.vector != expected.vector || frame.error != expected.error
        || frame.rflags & ((3 << 12) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 17)) != 0
        || frame.rsp < USER_STACK || frame.rsp >= USER_STACK + 4096
        || (!expected.own && cr2 != expected.target)
        || (expected.own && frame.registers[14] != OWN_SEED)
    { fail("k02-unexpected-user-trap"); }
    print(format_args!("TESSRYN_K02_TRAP case={} domain={} vector={} error={:#x} rip={:#x} cs={:#x} ss={:#x} rflags={:#x} rsp={:#x} cr2={cr2:#x} frame={frame_address:#x} kind={}\n",
        case(), expected.domain, frame.vector, frame.error, frame.rip, frame.cs, frame.ss,
        frame.rflags, frame.rsp, if expected.own { "controlled_return" } else { "expected_page_fault" }));
    expected.active = false; expected.returned = true;
    unsafe { ptr::addr_of_mut!(PROBE).write(expected); crate::k02_cpu::return_to_kernel(); }
}
