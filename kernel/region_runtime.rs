//! One-CPU region service adapter and cooperative, image-bound task experiment.
//! No policy/MMU mutable borrow survives an entry. The trap callback only copies
//! CPU state into protected task slots and returns to the kernel continuation.
use crate::diagnostics::{fail, print};
use crate::k02_memory::{
    Access, Accounting, CapabilityRef, MemoryError, NativeMemory, PageLease, RegionLease, Rights,
};
use crate::k02_paging::{Tables, UserAccess};
use crate::region_service::{
    self as service, Backend, Control, MapError, Response, Service, Status,
};
use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};
use core::ptr;

const CODE: u64 = 0x100000000;
const STACK: u64 = 0x100002000;
const REQUEST: u64 = 0x10000f000;
const DATA: u64 = 0x100004000;
const SEED: u64 = 0x544553535245474e;
const WRITTEN: u64 = 0x1122334455667788;
const EMPTY_CAP: CapabilityRef = CapabilityRef {
    slot: 0,
    generation: 0,
    domain: 0,
};
const fn case_id() -> u64 {
    if cfg!(k02_service_case = "sharing") {
        0
    } else if cfg!(k02_service_case = "revocation") {
        1
    } else if cfg!(k02_service_case = "authority") {
        2
    } else {
        u64::MAX
    }
}
fn case_name() -> &'static str {
    match case_id() {
        0 => "sharing",
        1 => "revocation",
        2 => "authority",
        _ => fail("service-case"),
    }
}
global_asm!(include_str!("region_entry.S"));
global_asm!(include_str!("region_programs.S"));
unsafe extern "sysv64" {
    fn region_resume_user(root: u64, state: *const Saved) -> u64;
    static region_program_a_start: u8;
    static region_program_a_end: u8;
    static region_program_b_start: u8;
    static region_program_b_end: u8;
    static region_b_write_fault: u8;
    static region_b_stale_fault: u8;
}
#[repr(C)]
struct Contract {
    magic: [u8; 16],
    version: u64,
    case_id: u64,
    domains: [u64; 2],
    addresses: [u64; 4],
    request_size: u64,
}
#[used]
#[unsafe(no_mangle)]
static K02_REGION_SERVICE_CONTRACT: Contract = Contract {
    magic: *b"TESSRYN-REGION1\0",
    version: 1,
    case_id: case_id(),
    domains: [1, 2],
    addresses: [CODE, STACK, REQUEST, DATA],
    request_size: 96,
};

#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Saved {
    registers: [u64; 15],
    vector: u64,
    error: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    fp: [u8; 512],
}
const fn initial() -> Saved {
    let mut fp = [0; 512];
    fp[0] = 0x7f;
    fp[1] = 3;
    fp[24] = 0x80;
    fp[25] = 0x1f;
    Saved {
        registers: [0; 15],
        vector: 0,
        error: 0,
        rip: CODE,
        cs: 0x33,
        rflags: 2,
        rsp: STACK + 4096 - 16,
        ss: 0x2b,
        fp,
    }
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Task {
    saved: Saved,
    domain: u64,
    root: u64,
    request_physical: u64,
    request_cap: CapabilityRef,
    state: u64,
    resumes: u64,
    cr2: u64,
}
const EMPTY_TASK: Task = Task {
    saved: initial(),
    domain: 0,
    root: 0,
    request_physical: 0,
    request_cap: EMPTY_CAP,
    state: 0,
    resumes: 0,
    cr2: 0,
};
static mut TASKS: [Task; 2] = [EMPTY_TASK; 2];
static mut ACTIVE: usize = 2;
static mut ROOTS: [Tables<16>; 2] = [const { Tables::empty() }; 2];
static mut SEQUENCE: u64 = 0;
const _: () = {
    assert!(size_of::<Contract>() == 88);
    assert!(offset_of!(Saved, fp) == 176);
    assert!(size_of::<Saved>() == 688);
    assert!(offset_of!(Task, saved) == 0);
};

fn checked<T, E>(r: Result<T, E>, reason: &'static str) -> T {
    r.unwrap_or_else(|_| fail(reason))
}
fn n(key: &str, value: u64) {
    print(format_args!(" {key}={value}"));
}
fn x(key: &str, value: u64) {
    print(format_args!(" {key}={value:#x}"));
}
fn s(key: &str, value: &str) {
    print(format_args!(" {key}={value}"));
}
fn hash(key: &str, value: [u8; 32]) {
    print(format_args!(" {key}="));
    for byte in value {
        print(format_args!("{byte:02x}"));
    }
}
fn record(kind: &str, fields: impl FnOnce()) {
    let sequence = unsafe { ptr::addr_of!(SEQUENCE).read() };
    unsafe {
        ptr::addr_of_mut!(SEQUENCE).write(
            sequence
                .checked_add(1)
                .unwrap_or_else(|| fail("service-sequence")),
        );
    }
    print(format_args!(
        "TESSRYN_K02_SERVICE_{kind} sequence={sequence}"
    ));
    fields();
    print(format_args!("\n"));
}
fn root(domain: u64) -> &'static mut Tables<16> {
    if !(1..=2).contains(&domain) {
        fail("service-domain");
    }
    // Serialized CPU owner. These short references never cross user entry.
    unsafe {
        &mut *ptr::addr_of_mut!(ROOTS)
            .cast::<Tables<16>>()
            .add(domain as usize - 1)
    }
}
fn task(index: usize) -> Task {
    if index >= 2 {
        fail("service-task-index");
    }
    unsafe { ptr::addr_of!(TASKS).cast::<Task>().add(index).read() }
}
fn save(index: usize, value: Task) {
    unsafe {
        ptr::addr_of_mut!(TASKS)
            .cast::<Task>()
            .add(index)
            .write(value);
    }
}
fn code(index: usize) -> u64 {
    if index == 0 {
        ptr::addr_of!(region_program_a_start) as u64
    } else {
        ptr::addr_of!(region_program_b_start) as u64
    }
}
fn packed(cap: CapabilityRef) -> u64 {
    cap.slot as u64 | ((cap.generation as u64) << 32)
}
fn cap_record(phase: &str, cap: CapabilityRef) {
    record("CAP", || {
        n("domain", cap.domain);
        s("phase", phase);
        n("cap_slot", cap.slot as u64);
        n("cap_generation", cap.generation as u64);
        n("cap_domain", cap.domain);
    });
}
unsafe fn digest(physical: u64) -> [u8; 32] {
    let mut bytes = [0; 4096];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = unsafe { (physical as *const u8).add(i).read_volatile() };
    }
    crate::k02_sha256::digest(&bytes)
}
fn backing(phase: &str, physical: u64) {
    record("BACKING", || {
        s("phase", phase);
        x("frame", physical);
        hash("sha256", unsafe { digest(physical) });
    });
}
fn expected_payload() -> [u8; 32] {
    let mut bytes = [0; 4096];
    for i in 0..512 {
        let value = if i == 1 { WRITTEN } else { SEED ^ i as u64 };
        bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    crate::k02_sha256::digest(&bytes)
}

fn msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr",in("ecx")index,out("eax")low,out("edx")high,options(nostack));
    }
    low as u64 | ((high as u64) << 32)
}
fn admit() {
    let cr4: u64;
    let dr7: u64;
    let ldtr: u16;
    unsafe {
        asm!("mov {}, cr4",out(reg)cr4,options(nomem,nostack));
        asm!("mov {}, dr7",out(reg)dr7,options(nomem,nostack));
        asm!("sldt {0:x}",out(reg)ldtr,options(nomem,nostack));
    }
    if cr4 & ((1 << 16) | (1 << 8)) != 0
        || dr7 & (0xff | (1 << 13)) != 0
        || ldtr != 0
        || msr(0xc0000080) & 1 != 0
        || msr(0x174) != 0
        || [0xc0000100, 0xc0000101, 0xc0000102]
            .iter()
            .any(|i| msr(*i) != 0)
    {
        fail("service-cpu-state-profile");
    }
    record("PROFILE", || {
        n("cpu_count", 1);
        n("fsgsbase", 0);
        n("pce", 0);
        n("syscall", 0);
        n("sysenter", 0);
        n("fs_base", 0);
        n("gs_base", 0);
        n("kernel_gs_base", 0);
        n("ldtr", 0);
        n("debug_enabled", 0);
        n("osxsave", 0);
        s("fp", "legacy_fxsave");
    });
}

/// Called only after the common assembly stub saved legacy FP state and reset
/// the kernel FP environment. It never borrows the memory service or mapper.
pub fn capture(frame: &crate::cpu::ExceptionFrame, fp: *const u8, cr2: u64) {
    let index = unsafe { ptr::addr_of!(ACTIVE).read() };
    let mut t = task(index);
    let stack = crate::k02_cpu::trap_stack();
    let address = frame as *const _ as u64;
    let current: u64;
    unsafe {
        asm!("mov {}, cr3",out(reg)current,options(nomem,nostack));
    }
    if t.state != 1
        || current != t.root
        || frame.cs != 0x33
        || frame.ss != 0x2b
        || address < stack.start
        || address.checked_add(176).is_none_or(|end| end > stack.end)
        || (fp as u64) % 16 != 0
        || (fp as u64) < stack.start
        || (fp as u64).checked_add(512).is_none_or(|end| end > address)
        || frame.rsp < STACK
        || frame.rsp >= STACK + 4096
        || frame.rip < CODE
        || frame.rip >= CODE + 4096
        || frame.rflags & ((3 << 12) | (1 << 8) | (1 << 9) | (1 << 14) | (1 << 17)) != 0
        || (frame.vector == 128 && frame.rflags & (1 << 16) != 0)
        || !matches!(frame.vector, 128 | 14 | 6)
    {
        fail("service-trap-context");
    }
    t.saved.registers = frame.registers;
    t.saved.vector = frame.vector;
    t.saved.error = frame.error;
    t.saved.rip = frame.rip;
    t.saved.cs = frame.cs;
    t.saved.rflags = frame.rflags;
    t.saved.rsp = frame.rsp;
    t.saved.ss = frame.ss;
    unsafe {
        ptr::copy_nonoverlapping(fp, t.saved.fp.as_mut_ptr(), 512);
    }
    let mxcsr = u32::from_le_bytes(t.saved.fp[24..28].try_into().unwrap());
    if mxcsr & !crate::k02_cpu::mxcsr_mask() != 0 {
        fail("service-user-mxcsr");
    }
    t.state = 2;
    t.cr2 = cr2;
    save(index, t);
    record("TRAP", || {
        n("task", index as u64);
        n("domain", t.domain);
        x("root", current);
        n("vector", frame.vector);
        x("error", frame.error);
        x("rip", frame.rip);
        x("rsp", frame.rsp);
        x("cs", frame.cs);
        x("ss", frame.ss);
        x("rflags", frame.rflags);
        x("frame", address);
        x("trap_start", stack.start);
        x("trap_end", stack.end);
        x("cr2", cr2);
        x("rdi", frame.registers[8]);
        n("rsi", frame.registers[9]);
        n("request_counter", frame.registers[0]);
        for (i, value) in frame.registers.iter().enumerate() {
            print(format_args!(" r{i}={value:#x}"));
        }
        hash("fp_sha256", crate::k02_sha256::digest(&t.saved.fp));
    });
    unsafe {
        crate::k02_cpu::return_to_kernel();
    }
}

#[derive(Clone, Copy)]
struct NativeMapping {
    domain: u64,
    va: u64,
    page: RegionLease,
}
struct Journal {
    caps: [Option<CapabilityRef>; 32],
}
impl Journal {
    fn slot(&self) -> Result<usize, MemoryError> {
        self.caps
            .iter()
            .position(Option::is_none)
            .ok_or(MemoryError::Capacity)
    }
    fn remove(&mut self, cap: CapabilityRef) {
        let i = self
            .caps
            .iter()
            .position(|v| *v == Some(cap))
            .unwrap_or_else(|| fail("service-cap-journal"));
        self.caps[i] = None;
    }
}
struct Adapter<'a> {
    memory: &'a mut NativeMemory,
    journal: &'a mut Journal,
    kernel_root: u64,
}
fn map_record(phase: &str, m: NativeMapping, charged: u64) {
    record("MAP_EVENT", || {
        n("domain", m.domain);
        s("phase", phase);
        x("va", m.va);
        x("frame", m.page.physical);
        n("lease_slot", m.page.lease.slot() as u64);
        n("lease_generation", m.page.lease.generation() as u64);
        n("charged", charged);
    });
}
impl Adapter<'_> {
    fn public_cap(&self, caller: u64, cap: CapabilityRef) -> Result<(), MemoryError> {
        if cap.domain != caller {
            return Err(MemoryError::InvalidAuthority);
        }
        if self.journal.caps.contains(&Some(cap)) {
            return Ok(());
        }
        // Preserve stale/foreign errors, but baseline CPU stack/request caps
        // belong to the trusted task adapter and are outside this service.
        self.memory.authorize(caller, cap, Rights::READ, 0, 1)?;
        Err(MemoryError::InvalidAuthority)
    }
    fn retire(&mut self, m: NativeMapping, installed: bool) -> Result<(), MemoryError> {
        let before = self.memory.accounting(m.domain)?;
        self.memory.fence(m.page.lease)?;
        map_record("fence", m, before.charged_pages);
        if installed {
            let removed = root(m.domain)
                .unmap_user(m.va)
                .map_err(|_| MemoryError::Excluded)?;
            if removed.physical_page != m.page.physical
                || root(m.domain).translation(m.va).is_some()
            {
                return Err(MemoryError::Excluded);
            }
            map_record("clear", m, before.charged_pages);
        }
        unsafe {
            crate::k02_cpu::reload(root(m.domain).root());
            crate::k02_cpu::reload(self.kernel_root);
        }
        map_record("invalidate", m, before.charged_pages);
        unsafe {
            self.memory.quiesce(m.page.lease)?;
        }
        if self.memory.accounting(m.domain)? != before {
            return Err(MemoryError::Excluded);
        }
        map_record(
            if installed { "quiesce" } else { "rollback" },
            m,
            before.charged_pages,
        );
        Ok(())
    }
}
impl Backend for Adapter<'_> {
    type Mapping = NativeMapping;
    fn allocate(&mut self, caller: u64) -> Result<CapabilityRef, MemoryError> {
        let i = self.journal.slot()?;
        let cap = self.memory.allocate_page(caller)?;
        self.journal.caps[i] = Some(cap);
        cap_record("allocate", cap);
        let frame = self.memory.region_info(caller, cap)?.backing.start();
        backing("reused", frame);
        Ok(cap)
    }
    fn delegate_readonly(
        &mut self,
        caller: u64,
        parent: CapabilityRef,
        target: u64,
        offset: u64,
        length: u64,
    ) -> Result<CapabilityRef, MemoryError> {
        self.public_cap(caller, parent)?;
        let i = self.journal.slot()?;
        let cap = self.memory.delegate(
            caller,
            parent,
            target,
            Rights::READ | Rights::MAP,
            offset,
            length,
        )?;
        self.journal.caps[i] = Some(cap);
        cap_record("delegate", cap);
        Ok(cap)
    }
    fn map(
        &mut self,
        caller: u64,
        cap: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
        va: u64,
    ) -> Result<NativeMapping, MapError> {
        if length != 4096 {
            return Err(MemoryError::Bounds.into());
        }
        self.public_cap(caller, cap)?;
        let page = self
            .memory
            .map_intent(caller, cap, access, offset, length)?;
        let mapping = NativeMapping {
            domain: caller,
            va,
            page,
        };
        if root(caller)
            .map_data(
                va,
                page.physical,
                if page.writable {
                    UserAccess::ReadWrite
                } else {
                    UserAccess::ReadOnly
                },
            )
            .is_err()
        {
            self.retire(mapping, false).map_err(MapError::Fatal)?;
            return Err(MemoryError::Excluded.into());
        }
        let translated = root(caller)
            .user_translation(va)
            .ok_or(MapError::Fatal(MemoryError::Excluded))?;
        if translated.physical != page.physical
            || translated.writable != page.writable
            || translated.executable
        {
            return Err(MapError::Fatal(MemoryError::Excluded));
        }
        map_record(
            "install",
            mapping,
            self.memory.accounting(caller)?.charged_pages,
        );
        Ok(mapping)
    }
    fn unmap(&mut self, mapping: NativeMapping) -> Result<(), MemoryError> {
        self.retire(mapping, true)
    }
    fn authorize_mapping(
        &self,
        caller: u64,
        cap: CapabilityRef,
        offset: u64,
        length: u64,
    ) -> Result<(), MemoryError> {
        self.public_cap(caller, cap)?;
        self.memory
            .authorize(caller, cap, Rights::READ | Rights::MAP, offset, length)
            .map(|_| ())
    }
    fn revoke(&mut self, caller: u64, cap: CapabilityRef) -> Result<(), MemoryError> {
        self.public_cap(caller, cap)?;
        self.memory.revoke(caller, cap)
    }
    fn release(&mut self, caller: u64, cap: CapabilityRef) -> Result<(), MemoryError> {
        self.public_cap(caller, cap)?;
        self.memory.release(caller, cap)?;
        self.journal.remove(cap);
        cap_record("release", cap);
        Ok(())
    }
    fn accounting(&self, caller: u64) -> Result<Accounting, MemoryError> {
        self.memory.accounting(caller)
    }
}

fn reap(service: &mut Service<NativeMapping>, adapter: &mut Adapter<'_>) {
    for index in 0..2 {
        let t = task(index);
        if t.state != 3 {
            continue;
        }
        // Revoke before touching descendant mappings. Busy release is deferred
        // with backing/charge retained until the still-live peer quiesces.
        for cap in adapter
            .journal
            .caps
            .into_iter()
            .flatten()
            .filter(|cap| cap.domain == t.domain)
        {
            match adapter.memory.revoke(t.domain, cap) {
                Ok(()) | Err(MemoryError::Revoked) => {}
                Err(_) => fail("service-stop-revoke"),
            }
        }
        checked(service.drain_revoked(adapter), "service-stop-descendants");
        checked(
            service.drain_mappings(t.domain, adapter),
            "service-stop-mappings",
        );
        for cap in adapter
            .journal
            .caps
            .into_iter()
            .flatten()
            .filter(|cap| cap.domain == t.domain)
        {
            match adapter.release(t.domain, cap) {
                Ok(()) => {}
                Err(MemoryError::Busy) => cap_record("deferred", cap),
                Err(_) => fail("service-stop-release"),
            }
        }
    }
}
#[derive(Clone, Copy)]
struct Baseline {
    caps: [CapabilityRef; 2],
    pages: [PageLease; 2],
}
fn baseline(memory: &mut NativeMemory, domain: u64) -> Baseline {
    let caps = [
        checked(memory.allocate_page(domain), "service-stack-cap"),
        checked(memory.allocate_page(domain), "service-request-cap"),
    ];
    let pages = caps.map(|cap| {
        checked(
            memory.map_page(domain, cap, Access::Write),
            "service-baseline-lease",
        )
    });
    for (i, va) in [STACK, REQUEST].into_iter().enumerate() {
        checked(
            root(domain).map_data(va, pages[i].physical, UserAccess::ReadWrite),
            "service-baseline-map",
        );
    }
    Baseline { caps, pages }
}
fn reply(t: &mut Task, r: Response) {
    t.saved.registers[14] = r.status as u64;
    t.saved.registers[12] = if r.capability != EMPTY_CAP {
        packed(r.capability)
    } else {
        r.mapping
    };
    t.saved.registers[13] = r.capability.domain;
    t.saved.registers[7] = r.accounting.charged_pages;
    t.saved.registers[6] = r.accounting.committed_pages;
    t.saved.registers[5] = r.accounting.reserved_pages;
}
fn request(
    index: usize,
    service: &mut Service<NativeMapping>,
    adapter: &mut Adapter<'_>,
) -> Response {
    let t = task(index);
    let pointer = t.saved.registers[8];
    let length = t.saved.registers[9];
    let mut bytes = [0; 96];
    let offset = service::checked_request_buffer(pointer, length, REQUEST, 4096);
    if let Ok(offset) = offset {
        let entry = checked(
            root(t.domain).translate(pointer),
            "service-request-translation",
        );
        let info = checked(
            adapter
                .memory
                .authorize(t.domain, t.request_cap, Rights::READ, offset, 96),
            "service-request-capability",
        );
        if !entry.user
            || !entry.writable
            || entry.executable
            || entry.page_bytes != 4096
            || entry.physical != t.request_physical + offset
            || info.physical_start != entry.physical
            || info.length != 96
        {
            fail("service-request-map");
        }
        for (i, value) in bytes.iter_mut().enumerate() {
            *value = unsafe { (entry.physical as *const u8).add(i).read_volatile() };
        }
    }
    record("REQUEST", || {
        n("task", index as u64);
        n("caller", t.domain);
        x("pointer", pointer);
        n("length", length);
        n("valid", offset.is_ok() as u64);
        n("request_id", t.saved.registers[0]);
        print(format_args!(" bytes="));
        if offset.is_ok() {
            for byte in bytes {
                print(format_args!("{byte:02x}"));
            }
        } else {
            print(format_args!("none"));
        }
    });
    let before = [
        checked(adapter.memory.accounting(1), "service-before-a"),
        checked(adapter.memory.accounting(2), "service-before-b"),
    ];
    let leaves = [root(1).user_leaf_count(), root(2).user_leaf_count()];
    let mut response = match offset {
        Ok(_) => checked(
            service.dispatch(t.domain, &bytes, adapter),
            "service-dispatch-fatal",
        ),
        Err(status) => Response {
            request_id: t.saved.registers[0],
            opcode: 0,
            status,
            capability: EMPTY_CAP,
            mapping: 0,
            accounting: before[index],
            control: Control::Continue,
        },
    };
    if response.status != Status::Ok
        && (before
            != [
                checked(adapter.memory.accounting(1), "service-after-a"),
                checked(adapter.memory.accounting(2), "service-after-b"),
            ]
            || leaves != [root(1).user_leaf_count(), root(2).user_leaf_count()])
    {
        fail("service-denial-mutated-state");
    }
    reap(service, adapter);
    response.accounting = checked(
        adapter.memory.accounting(t.domain),
        "service-reply-accounting",
    );
    record("RESPONSE", || {
        n("task", index as u64);
        n("caller", t.domain);
        n("request_id", response.request_id);
        n("opcode", response.opcode as u64);
        n("status", response.status as u64);
        x(
            "value",
            if response.capability != EMPTY_CAP {
                packed(response.capability)
            } else {
                response.mapping
            },
        );
        n("cap_domain", response.capability.domain);
        n("charged", response.accounting.charged_pages);
        n("committed", response.accounting.committed_pages);
        n("reserved", response.accounting.reserved_pages);
        s(
            "control",
            match response.control {
                Control::Continue => "continue",
                Control::Yield => "yield",
                Control::Exit => "exit",
            },
        );
    });
    response
}

pub fn run(handoff: &crate::uefi::Handoff) -> ! {
    if case_id() > 2 {
        fail("service-case");
    }
    crate::k02_cpu::initialize(handoff);
    record("BEGIN", || {
        s("case", case_name());
        n("version", 1);
        n("programs", 2);
        n("request_bytes", 96);
    });
    admit();
    if code(0) % 4096 != 0
        || code(1) % 4096 != 0
        || ptr::addr_of!(region_program_a_end) as u64 != code(0) + 4096
        || ptr::addr_of!(region_program_b_end) as u64 != code(1) + 4096
    {
        fail("service-program-pages");
    }
    let memory = checked(
        unsafe { crate::k02_memory::initialize(handoff) },
        "service-memory",
    );
    for domain in 1..=2 {
        checked(memory.create_domain(domain, 16), "service-create-domain");
        crate::k02::seed_root(root(domain), handoff);
        checked(
            root(domain).map_trusted_code(CODE, code(domain as usize - 1)),
            "service-code-map",
        );
    }
    let baseline = [baseline(memory, 1), baseline(memory, 2)];
    let owner = checked(
        memory.allocate_initialized_page(1, SEED),
        "service-provision-owner",
    );
    let physical = checked(memory.region_info(1, owner), "service-owner-info")
        .backing
        .start();
    cap_record("provision", owner);
    backing("ready", physical);
    let memory_ptr = memory as *mut NativeMemory;
    let mut journal = Journal { caps: [None; 32] };
    journal.caps[0] = Some(owner);
    let mut service = checked(Service::<NativeMapping>::new([1, 2]), "service-policy");
    for (index, b) in baseline.iter().enumerate() {
        let domain = index as u64 + 1;
        let mut t = EMPTY_TASK;
        t.domain = domain;
        t.root = root(domain).root();
        t.request_physical = b.pages[1].physical;
        t.request_cap = b.caps[1];
        t.saved.registers[2] = case_id();
        if index == 0 {
            t.saved.registers[3] = packed(owner);
        }
        save(index, t);
        record("TASK", || {
            n("domain", domain);
            x("root", t.root);
            x("code_physical", code(index));
            x("entry", CODE);
            x("stack", STACK);
            x("stack_physical", b.pages[0].physical);
            n("stack_lease_slot", b.pages[0].lease.slot() as u64);
            n(
                "stack_lease_generation",
                b.pages[0].lease.generation() as u64,
            );
            x("request", REQUEST);
            x("request_physical", t.request_physical);
            n("request_lease_slot", b.pages[1].lease.slot() as u64);
            n(
                "request_lease_generation",
                b.pages[1].lease.generation() as u64,
            );
            n("generation", 1);
        });
    }
    let mut index = 0;
    let mut previous = 2;
    let mut switches = 0;
    let mut steps = 0;
    while task(0).state != 3 || task(1).state != 3 {
        if steps >= 128 {
            fail("service-step-bound");
        }
        steps += 1;
        if task(index).state == 3 {
            index = 1 - index;
            continue;
        }
        let mut t = task(index);
        if index == 1 && t.saved.registers[3] == 0 {
            fail("service-b-not-provisioned");
        }
        checked(root(t.domain).validate(), "service-preentry-tables");
        if previous < 2 && previous != index {
            switches += 1;
        }
        previous = index;
        record("RESUME", || {
            n("task", index as u64);
            n("domain", t.domain);
            n("generation", 1);
            x("root", t.root);
            x("rip", t.saved.rip);
            x("rsp", t.saved.rsp);
            x("cs", t.saved.cs);
            x("ss", t.saved.ss);
            x("rflags", t.saved.rflags);
            n("first", (t.resumes == 0) as u64);
            n("resumes", t.resumes);
            for (i, value) in t.saved.registers.iter().enumerate() {
                print(format_args!(" r{i}={value:#x}"));
            }
            hash("fp_sha256", crate::k02_sha256::digest(&t.saved.fp));
        });
        t.state = 1;
        t.resumes += 1;
        save(index, t);
        unsafe {
            ptr::addr_of_mut!(ACTIVE).write(index);
        }
        // Only a raw pointer to immutable protected saved state crosses entry.
        // The assembly saves/restores the kernel continuation and FP state.
        let result = unsafe {
            region_resume_user(
                t.root,
                ptr::addr_of!(TASKS)
                    .cast::<Task>()
                    .add(index)
                    .cast::<Saved>(),
            )
        };
        if result != 1 {
            fail("service-entry-return");
        }
        t = task(index);
        if t.state != 2 {
            fail("service-trap-not-captured");
        }
        {
            // This exclusive policy borrow exists only while both tasks are stopped.
            let mut adapter = Adapter {
                memory: unsafe { &mut *memory_ptr },
                journal: &mut journal,
                kernel_root: handoff.cr3,
            };
            if t.saved.vector != 128 {
                let expected = if case_id() == 0 {
                    ptr::addr_of!(region_b_write_fault) as u64 - code(1) + CODE
                } else {
                    ptr::addr_of!(region_b_stale_fault) as u64 - code(1) + CODE
                };
                if index != 1
                    || case_id() > 1
                    || t.saved.vector != 14
                    || t.saved.error != if case_id() == 0 { 7 } else { 4 }
                    || t.saved.rip != expected
                    || t.cr2 != DATA
                    || unsafe { digest(physical) } != expected_payload()
                {
                    fail("service-unexpected-user-fault");
                }
                backing("after_fault", physical);
                t.state = 3;
                save(index, t);
                record("STOP", || {
                    n("task", index as u64);
                    s("reason", "fault");
                    n("vector", t.saved.vector);
                    x("error", t.saved.error);
                    x("rip", t.saved.rip);
                    x("cr2", t.cr2);
                });
                reap(&mut service, &mut adapter);
                index = 0;
                continue;
            }
            if t.saved.error != 0 {
                fail("service-int-error");
            }
            let response = request(index, &mut service, &mut adapter);
            if response.capability.domain == 2 && task(1).resumes == 0 {
                let mut b = task(1);
                b.saved.registers[3] = packed(response.capability);
                save(1, b);
            }
            reply(&mut t, response);
            if response.control == Control::Exit {
                t.state = 3;
                save(index, t);
                record("STOP", || {
                    n("task", index as u64);
                    s("reason", "exit");
                    n("vector", 128);
                    n("error", 0);
                    x("rip", t.saved.rip);
                    x("cr2", 0);
                });
                reap(&mut service, &mut adapter);
                index = 1 - index;
            } else {
                save(index, t);
                if response.control == Control::Yield {
                    index = 1 - index;
                }
            }
        }
    }
    {
        let mut adapter = Adapter {
            memory: unsafe { &mut *memory_ptr },
            journal: &mut journal,
            kernel_root: handoff.cr3,
        };
        reap(&mut service, &mut adapter);
        if adapter.journal.caps.iter().any(Option::is_some) || service.mapping_count() != 0 {
            fail("service-final-journal");
        }
        for (index, b) in baseline.into_iter().enumerate() {
            let domain = index as u64 + 1;
            for (i, va) in [STACK, REQUEST].into_iter().enumerate() {
                let p = b.pages[i];
                checked(
                    adapter.retire(
                        NativeMapping {
                            domain,
                            va,
                            page: RegionLease {
                                physical: p.physical,
                                length: 4096,
                                lease: p.lease,
                                writable: true,
                            },
                        },
                        true,
                    ),
                    "service-baseline-retire",
                );
                checked(
                    adapter.memory.release(domain, b.caps[i]),
                    "service-baseline-release",
                );
            }
            checked(root(domain).unmap_user(CODE), "service-code-retire");
            unsafe {
                crate::k02_cpu::reload(root(domain).root());
                crate::k02_cpu::reload(handoff.cr3);
            }
            let a = checked(
                adapter.memory.accounting(domain),
                "service-final-accounting",
            );
            let leaves = root(domain).user_leaf_count();
            if a.charged_pages != 0
                || a.committed_pages != 0
                || a.reserved_pages != 0
                || leaves != 0
            {
                fail("service-final-owned-state");
            }
            record("FINAL", || {
                n("domain", domain);
                n("leaves", leaves as u64);
                n("charged", a.charged_pages);
                n("committed", a.committed_pages);
                n("reserved", a.reserved_pages);
            });
        }
        if adapter.memory.allocated_pages() != 0 || switches < 4 {
            fail("service-final-allocation");
        }
        record("PASS", || {
            s("case", case_name());
            n("allocated_pages", adapter.memory.allocated_pages());
            n("mappings", service.mapping_count() as u64);
            n("context_switches", switches);
        });
    }
    crate::diagnostics::finish(true)
}
