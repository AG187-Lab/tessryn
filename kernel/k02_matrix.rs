// Native K02 controlled execution matrix. One CPU; no scheduler or DMA claim.
use core::{mem::size_of, ptr};
use crate::diagnostics::{fail, finish, print};
use crate::k02_memory::{Access, CapabilityRef, MemoryError, NativeMemory, PageLease, Rights};
use crate::k02_paging::{Tables, UserAccess};
#[path="k02_matrix_protection.rs"]
mod protection;
#[path="k02_matrix_requests.rs"]
mod requests;

const CODE: u64 = 0x1_0000_0000;
const OWN: u64 = CODE + 0x1000;
const STACK: u64 = CODE + 0x2000;
const REQUEST: u64 = CODE + 0xf000;
const UNAUTHORIZED: u64 = CODE + 0x3000;
const READONLY: u64 = CODE + 0x4000;
const GUARD: u64 = CODE + 0x5000;
const NX: u64 = CODE + 0x6000;
const REVOKED_B: u64 = CODE + 0x7000;
const REVOKED_D: u64 = CODE + 0x8000;
const REUSE_B: u64 = CODE + 0x9000;
const REUSE_C: u64 = CODE + 0xa000;
const VICTIM: u64 = 0x5445_5353_5649_4354;
const NEW_OWNER: u64 = 0x5445_5353_4e45_5743;
const WRITE: u64 = 0x5445_5353_5752_4954;

const fn case_id() -> u64 {
    if cfg!(k02_matrix_case="caller_forgery") {0}
    else if cfg!(k02_matrix_case="trusted_operation_forgery") {1}
    else if cfg!(k02_matrix_case="unauthorized_read") {2}
    else if cfg!(k02_matrix_case="read_only_sharing") {3}
    else if cfg!(k02_matrix_case="exact_bounds") {4}
    else if cfg!(k02_matrix_case="kernel_isolation") {5}
    else if cfg!(k02_matrix_case="data_nx") {6}
    else if cfg!(k02_matrix_case="recursive_revocation") {7}
    else if cfg!(k02_matrix_case="writable_reuse") {8}
    else if cfg!(k02_matrix_case="stale_identities") {9}
    else {u64::MAX}
}
fn case_name() -> &'static str {
    ["caller_forgery","trusted_operation_forgery","unauthorized_read","read_only_sharing",
     "exact_bounds","kernel_isolation","data_nx","recursive_revocation","writable_reuse",
     "stale_identities"].get(case_id() as usize).copied().unwrap_or_else(||fail("matrix-case"))
}

#[repr(C)]
struct Contract { magic:[u8;16], version:u64, case_id:u64, domains:[u64;4], addresses:[u64;12], seeds:[u64;3] }
#[used]
#[unsafe(no_mangle)]
static K02_MATRIX_CONTRACT: Contract = Contract {
    magic:*b"TESSRYN-K02M-V1\0",version:1,case_id:case_id(),domains:[1,2,3,4],
    addresses:[CODE,OWN,STACK,REQUEST,UNAUTHORIZED,READONLY,GUARD,NX,REVOKED_B,REVOKED_D,REUSE_B,REUSE_C],
    seeds:[VICTIM,NEW_OWNER,WRITE],
};
const _: () = assert!(size_of::<Contract>() == 184);
static mut ROOTS: [Tables<16>;4] = [const {Tables::empty()};4];
static mut SEQUENCE: u64 = 0;

#[derive(Clone,Copy)]
struct Probe { active:bool, returned:bool, domain:u64, root:u64, vector:u64,error:u64,rip:u64,
               target:u64, value:u64, expected_value:Option<u64>, name:&'static str }
static mut PROBE: Probe = Probe {active:false,returned:false,domain:0,root:0,vector:0,error:0,rip:0,
    target:0,value:0,expected_value:None,name:"inactive"};

fn ok<T,E>(value:Result<T,E>, reason:&'static str)->T {value.unwrap_or_else(|_|fail(reason))}
fn n(key:&str,value:u64) {print(format_args!(" {key}={value}"));}
fn x(key:&str,value:u64) {print(format_args!(" {key}={value:#x}"));}
fn s(key:&str,value:&str) {print(format_args!(" {key}={value}"));}
fn cap(prefix:&str,value:CapabilityRef) {
    print(format_args!(" {prefix}_slot={} {prefix}_generation={} {prefix}_domain={}",value.slot,value.generation,value.domain));
}
fn lease(value:crate::k02_memory::LeaseId) {n("lease_slot",value.slot() as u64);n("lease_generation",value.generation() as u64);}
fn hash(key:&str,value:[u8;32]) {print(format_args!(" {key}="));for byte in value {print(format_args!("{byte:02x}"));}}
fn event(name:&str, fields:impl FnOnce()) {
    let seq=unsafe{ptr::addr_of!(SEQUENCE).read()};
    unsafe{ptr::addr_of_mut!(SEQUENCE).write(seq+1);}
    print(format_args!("TESSRYN_K02_MATRIX_EVENT sequence={seq} event={name}"));fields();print(format_args!("\n"));
}
fn root(domain:u64)-> &'static mut Tables<16> {
    if !(1..=4).contains(&domain) {fail("matrix-domain");}
    // SAFETY: serialized boot CPU; these objects are image-owned, disjoint and
    // used only briefly. No reference is retained across a user transition.
    unsafe{&mut *ptr::addr_of_mut!(ROOTS).cast::<Tables<16>>().add(domain as usize-1)}
}
unsafe fn zero(physical:u64)->bool {
    (0..512).all(|i|unsafe{(physical as *const u64).add(i).read_volatile()}==0)
}
unsafe fn fill(physical:u64,seed:u64) {for i in 0..512 {unsafe{(physical as *mut u64).add(i).write_volatile(seed^i as u64);}}}
unsafe fn digest(physical:u64)->[u8;32] {
    // Hardware observation may include padding in protected Rust objects.
    // Copy actual physical bytes through assembly into initialized storage,
    // rather than turning possibly uninitialized Rust padding into an &[u8].
    // Caller holds backing ownership/lease or a live image reservation.
    let mut bytes=[0u8;4096];
    for (offset,byte) in bytes.iter_mut().enumerate() {
        let value:u8;
        unsafe{core::arch::asm!("mov {value}, byte ptr [{address}]",value=out(reg_byte)value,address=in(reg)physical+offset as u64,
            options(nostack,readonly,preserves_flags));}
        *byte=value;
    }
    crate::k02_sha256::digest(&bytes)
}

#[derive(Clone,Copy)]
struct Persistent { domain:u64,caps:[CapabilityRef;3],pages:[PageLease;3] }
#[derive(Clone,Copy)]
struct Mapping {domain:u64,va:u64,page:PageLease,fenced:bool}
fn mapping_valid(mapping:Mapping) -> bool {
    root(mapping.domain).user_translation(mapping.va).is_some_and(|entry|
        entry.physical==mapping.page.physical && entry.page_bytes==4096
        && entry.writable==mapping.page.writable && !entry.executable)
}
fn accounting_snapshot(memory:&NativeMemory) -> [crate::k02_memory::Accounting;4] {
    core::array::from_fn(|index|ok(memory.accounting(index as u64+1),"matrix-accounting-snapshot"))
}
fn install(memory:&mut NativeMemory, domain:u64, capability:CapabilityRef, va:u64, access:Access)->Mapping {
    let page=ok(memory.map_page(domain,capability,access),"matrix-map-authority");
    ok(root(domain).map_data(va,page.physical,if page.writable {UserAccess::ReadWrite}else{UserAccess::ReadOnly}),"matrix-map-pte");
    let mapping=Mapping{domain,va,page,fenced:false};
    if !mapping_valid(mapping) {fail("matrix-installed-permissions");}
    event("mapping_installed",||{n("domain",domain);x("root",root(domain).root());x("page",va);x("physical_frame",page.physical);
        n("length",4096);n("readable",1);n("writable",page.writable as u64);n("executable",0);lease(page.lease);n("charge_retained",1);});
    mapping
}
fn fence(memory:&mut NativeMemory,mapping:&mut Mapping) {
    if mapping.fenced {fail("matrix-double-fence");}
    ok(memory.fence(mapping.page.lease),"matrix-fence");mapping.fenced=true;
    event("fence",||mapping_fields(*mapping));
}
fn mapping_fields(m:Mapping) {n("domain",m.domain);x("root",root(m.domain).root());x("page",m.va);
    x("physical_frame",m.page.physical);lease(m.page.lease);n("charge_retained",1);}
fn remove(memory:&mut NativeMemory,mut mapping:Mapping,kernel_root:u64) {
    if !mapping_valid(mapping) {fail("matrix-teardown-mapping");}
    let charges=accounting_snapshot(memory);let allocated=memory.allocated_pages();
    if !mapping.fenced {fence(memory,&mut mapping);}
    let removed=ok(root(mapping.domain).unmap_user(mapping.va),"matrix-clear-pte");
    if removed.physical_page!=mapping.page.physical {fail("matrix-pte-identity");}
    if root(mapping.domain).translation(mapping.va).is_some() {fail("matrix-pte-still-present");}
    event("clear_pte",||mapping_fields(mapping));
    unsafe{crate::k02_cpu::reload(root(mapping.domain).root());crate::k02_cpu::reload(kernel_root);}
    event("invalidate",||{mapping_fields(mapping);s("method","cr3_reload");});
    ok(unsafe{memory.quiesce(mapping.page.lease)},"matrix-quiesce");
    if charges!=accounting_snapshot(memory) || allocated!=memory.allocated_pages() {
        fail("matrix-teardown-released-backing");
    }
    event("quiesce",||{mapping_fields(mapping);n("trusted",1);});
}
fn persistent(memory:&mut NativeMemory,domain:u64)->Persistent {
    let caps=[ok(memory.allocate_page(domain),"matrix-own-allocate"),ok(memory.allocate_page(domain),"matrix-stack-allocate"),ok(memory.allocate_page(domain),"matrix-request-allocate")];
    let pages=[ok(memory.map_page(domain,caps[0],Access::Write),"matrix-own-lease"),ok(memory.map_page(domain,caps[1],Access::Write),"matrix-stack-lease"),ok(memory.map_page(domain,caps[2],Access::Write),"matrix-request-lease")];
    for (i,va) in [OWN,STACK,REQUEST].into_iter().enumerate() {
        if !unsafe{zero(pages[i].physical)} {fail("matrix-baseline-scrub");}
        ok(root(domain).map_data(va,pages[i].physical,UserAccess::ReadWrite),"matrix-baseline-map");
    }
    unsafe{fill(pages[0].physical,VICTIM^domain);}
    Persistent{domain,caps,pages}
}
fn owned(memory:&NativeMemory,caller:u64,capability:CapabilityRef,physical:u64) {
    let info=ok(memory.region_info(caller,capability),"matrix-owned-info");
    if info.backing.start()!=physical || info.charge_owner!=caller || info.committed_pages!=1 || info.reserved_pages!=0 {fail("matrix-owned-facts");}
    event("backing_owned",||{cap("capability",capability);x("physical_frame",physical);n("length",4096);n("charge_owner",caller);
        n("committed_pages",1);n("reserved_pages",0);n("charged_pages",1);n("domain_charged_pages",ok(memory.accounting(caller),"matrix-accounting").charged_pages);n("baseline_pages",3);});
}
fn delegated(parent:CapabilityRef,child:CapabilityRef,rights:Rights) {event("delegated",||{cap("parent",parent);cap("child",child);n("offset",0);n("length",4096);n("rights",rights.bits() as u64);});}

fn run_probe(domain:u64,entry:*const u8,trap:*const u8,target:u64,value:u64,expected_value:Option<u64>,error:Option<u64>,name:&'static str) {
    ok(root(domain).validate(),"matrix-preentry-tables");
    let code=ok(root(domain).translate(CODE),"matrix-preentry-code");
    let stack=ok(root(domain).translate(STACK),"matrix-preentry-stack");
    let ts=crate::k02_cpu::trap_stack();
    if code.physical!=crate::k02_cpu::code_page() || code.page_bytes!=4096
        || !code.user || code.writable || !code.executable || stack.page_bytes!=4096
        || !stack.user || !stack.writable || stack.executable
        || unsafe{ptr::addr_of!(PROBE).read()}.active {fail("matrix-preentry-boundary");}
    for address in [ts.start,ts.end-1,ptr::addr_of!(PROBE) as u64] {
        let translation=ok(root(domain).translate(address),"matrix-preentry-protected");
        if translation.user || translation.physical!=address {fail("matrix-preentry-supervisor");}
    }
    let kernel_root:u64;
    unsafe{core::arch::asm!("mov {}, cr3",out(reg)kernel_root,options(nomem,nostack));}
    if kernel_root==root(domain).root() {fail("matrix-preentry-active-user-root");}
    let instruction=if name=="nx_fetch" && error==Some(21) && target==NX {NX}
        else {CODE+crate::k02_cpu::probe_offset(entry)};
    let expected_rip=if error.is_some(){instruction}else{CODE+crate::k02_cpu::probe_offset(trap)};
    let state=Probe{active:true,returned:false,domain,root:root(domain).root(),vector:if error.is_some(){14}else{128},
        error:error.unwrap_or(0),rip:expected_rip,target,value,expected_value,name};
    print(format_args!("TESSRYN_K02_MATRIX_USER_ENTER probe={name} domain={domain} root={:#x} instruction={instruction:#x} probe_rip={expected_rip:#x} target={target:#x} stack_start={STACK:#x} stack_end={:#x} trap_start={:#x} trap_end={:#x} code_physical={:#x}\n",state.root,STACK+4096,ts.start,ts.end,crate::k02_cpu::code_page()));
    unsafe{ptr::addr_of_mut!(PROBE).write(state);crate::k02_cpu::enter(state.root,instruction,STACK+4096-16,target,value);}
    let returned=unsafe{ptr::addr_of!(PROBE).read()};
    if returned.active || !returned.returned {fail("matrix-probe-unobserved");}
    let restored_root:u64;
    unsafe{core::arch::asm!("mov {}, cr3",out(reg)restored_root,options(nomem,nostack));}
    if restored_root!=kernel_root {fail("matrix-kernel-root-not-restored");}
}
fn read(domain:u64,va:u64,value:u64,name:&'static str) {
    run_probe(domain,ptr::addr_of!(crate::k02_cpu::k02_probe_read),ptr::addr_of!(crate::k02_cpu::k02_probe_read_return),va,0,Some(value),None,name);
}
fn write(domain:u64,va:u64,value:u64,name:&'static str) {
    run_probe(domain,ptr::addr_of!(crate::k02_cpu::k02_probe_write),ptr::addr_of!(crate::k02_cpu::k02_probe_write_return),va,value,None,None,name);
}
fn fault(domain:u64,va:u64,symbol:*const u8,error:u64,name:&'static str) {run_probe(domain,symbol,symbol,va,WRITE,None,Some(error),name);}
fn prime(mapping:Mapping,value:u64,writable:bool) {
    if writable {write(mapping.domain,mapping.va,WRITE,"prime_write");read(mapping.domain,mapping.va,WRITE,"prime_read");}
    else {read(mapping.domain,mapping.va,value,"prime_read");}
    event("mapping_primed",||{mapping_fields(mapping);n("read_executed",1);n("write_executed",writable as u64);});
}
pub fn handle_exception(frame:&crate::cpu::ExceptionFrame,cr2:u64) {
    let mut p=unsafe{ptr::addr_of!(PROBE).read()};if !p.active {fail("matrix-inactive-trap");}
    let t=crate::k02_cpu::trap_stack();let address=frame as *const _ as u64;
    let current_root:u64;unsafe{core::arch::asm!("mov {}, cr3",out(reg)current_root,options(nomem,nostack));}
    if address<t.start || address.checked_add(size_of::<crate::cpu::ExceptionFrame>() as u64).is_none_or(|end|end>t.end)
        || frame.cs!=crate::k02_cpu::USER_CS || frame.ss!=crate::k02_cpu::USER_SS || current_root!=p.root
        || frame.rip!=p.rip || frame.vector!=p.vector || frame.error!=p.error
        || frame.rflags & ((3<<12)|(1<<9)|(1<<10)|(1<<14)|(1<<17))!=0
        || frame.rsp<STACK || frame.rsp>=STACK+4096 || (p.vector==14 && cr2!=p.target)
        || p.expected_value.is_some_and(|value|frame.registers[14]!=value) {fail("matrix-unexpected-trap");}
    // The only user instructions are the bound load/store/request/snapshot
    // probes. They retain every unused general register from entry unchanged.
    // Check actual trap registers, not an entry routine's self-report.
    for (index,observed) in frame.registers.iter().copied().enumerate() {
        let expected=match index {8=>p.target,9=>p.value,14=>p.expected_value.unwrap_or(0),_=>0};
        if observed!=expected {fail("matrix-user-register-sanitization");}
    }
    print(format_args!("TESSRYN_K02_MATRIX_TRAP probe={} domain={} root={current_root:#x} vector={} error={:#x} rip={:#x} cs={:#x} ss={:#x} rflags={:#x} rsp={:#x} cr2={cr2:#x} frame={address:#x} rax={:#x}\n",p.name,p.domain,p.vector,frame.error,frame.rip,frame.cs,frame.ss,frame.rflags,frame.rsp,frame.registers[14]));
    if p.name=="request" {requests::capture(p.domain,frame);}
    if p.vector==14 {event("page_fault",||{s("probe",p.name);n("domain",p.domain);x("root",p.root);n("vector",14);x("cs",frame.cs);x("rip",frame.rip);x("cr2",cr2);n("error_code",frame.error);n("recovered",1);});}
    p.active=false;p.returned=true;unsafe{ptr::addr_of_mut!(PROBE).write(p);crate::k02_cpu::return_to_kernel();}
}

pub fn run(handoff:&crate::uefi::Handoff)->! {
    let contract=unsafe{ptr::addr_of!(K02_MATRIX_CONTRACT).read_volatile()};
    if contract.case_id!=case_id() || contract.magic!=*b"TESSRYN-K02M-V1\0" || contract.version!=1 {fail("matrix-contract");}
    crate::k02_cpu::initialize(handoff);
    let memory=ok(unsafe{crate::k02_memory::initialize(handoff)},"matrix-inventory");
    for domain in 1..=4 {ok(memory.create_domain(domain,16),"matrix-domain-create");crate::k02::seed_root(root(domain),handoff);
        ok(root(domain).map_trusted_code(CODE,crate::k02_cpu::code_page()),"matrix-code-map");
        print(format_args!("TESSRYN_K02_MATRIX_ROOT domain={domain} root={:#x} pool_end={:#x}\n",root(domain).root(),root(domain) as *const _ as u64+size_of::<Tables<16>>() as u64));}
    print(format_args!("TESSRYN_K02_MATRIX_INVENTORY case={} descriptors={} available_pages={} protected_state={:#x} baseline_pages=12 source=final_successful_handoff\n",case_name(),handoff.descriptors(),memory.available_pages(),memory.protected_state_address()));
    let permanent=[persistent(memory,1),persistent(memory,2),persistent(memory,3),persistent(memory,4)];
    boundary_snapshot(memory,permanent[1]);
    event("fresh_boot",||{s("case",case_name());s("reset","original_kernel_entry");n("untrusted_state_retained",0);});
    match case_id() {
        0|1|4|9=>requests::run(memory,handoff,case_id(),permanent[1]),
        2|3|5|6=>protection::run(memory,handoff,case_id()),
        7=>recursive(memory,handoff.cr3,permanent),8=>reuse(memory,handoff.cr3),
        _=>fail("matrix-case-not-implemented"),
    }
    print(format_args!("TESSRYN_K02_MATRIX_CASE_COMPLETE case={} allocated_pages={}\n",case_name(),memory.allocated_pages()));
    // Baseline mappings and code are retired only after case observations. These
    // cleanup records are separate from the required case transition sequence.
    for p in permanent {
        for i in 0..3 {let va=[OWN,STACK,REQUEST][i];ok(memory.fence(p.pages[i].lease),"matrix-clean-fence");
            let removed=ok(root(p.domain).unmap_user(va),"matrix-clean-pte");if removed.physical_page!=p.pages[i].physical {fail("matrix-clean-identity");}
            unsafe{crate::k02_cpu::reload(root(p.domain).root());crate::k02_cpu::reload(handoff.cr3);}
            ok(unsafe{memory.quiesce(p.pages[i].lease)},"matrix-clean-quiesce");ok(memory.release(p.domain,p.caps[i]),"matrix-clean-cap");}
        ok(root(p.domain).unmap_user(CODE),"matrix-clean-code");unsafe{crate::k02_cpu::reload(root(p.domain).root());crate::k02_cpu::reload(handoff.cr3);}
        if root(p.domain).user_leaf_count()!=0 {fail("matrix-final-user-mapping");}
        ok(root(p.domain).validate(),"matrix-final-root");
        let a=ok(memory.accounting(p.domain),"matrix-final-accounting");
        if a.charged_pages!=0 || a.committed_pages!=0 || a.reserved_pages!=0 {fail("matrix-final-charge");}
        print(format_args!("TESSRYN_K02_MATRIX_ACCOUNTING domain={} charged_pages=0 committed_pages=0 reserved_pages=0\n",p.domain));
    }
    if memory.allocated_pages()!=0 {fail("matrix-final-allocation");}
    print(format_args!("TESSRYN_K02_MATRIX_PASS case={} owned_pages_after=0 scope=single_cpu_emulated_matrix_case\n",case_name()));finish(true)
}

fn boundary_snapshot(memory:&NativeMemory,p:Persistent) {
    let view=ok(memory.authorize(p.domain,p.caps[2],Rights::READ,0,640),"matrix-boundary-snapshot-authority");
    if view.physical_start!=p.pages[2].physical || view.length!=640
        || !unsafe{zero(p.pages[2].physical)} {fail("matrix-boundary-snapshot-page");}
    run_probe(p.domain,ptr::addr_of!(crate::k02_cpu::k02_probe_boundary_snapshot),
        ptr::addr_of!(crate::k02_cpu::k02_probe_boundary_snapshot_return),REQUEST,0,Some(0),None,"boundary_snapshot");
    let mut bytes=[0u8;512];
    for (index,byte) in bytes.iter_mut().enumerate() {
        *byte=unsafe{(view.physical_start as *const u8).add(index).read_volatile()};
    }
    let mask=crate::k02_cpu::mxcsr_mask();
    let mut expected=[0u8;512];expected[0]=0x7f;expected[1]=0x03;
    expected[24]=0x80;expected[25]=0x1f;expected[28..32].copy_from_slice(&mask.to_le_bytes());
    if bytes!=expected {fail("matrix-user-fp-sanitization");}
    for index in 0..16 {
        let word=unsafe{(view.physical_start as *const u64).add(64+index).read_volatile()};
        let expected=match index {8=>REQUEST,15=>STACK+4096-16,_=>0};
        if word!=expected {fail("matrix-user-register-snapshot");}
    }
    event("boundary_sanitized",||{n("domain",p.domain);x("root",root(p.domain).root());x("page",REQUEST);
        x("physical_frame",view.physical_start);n("length",640);n("gpr_words",16);n("gpr_zeroed",1);
        n("fp_bytes",512);n("fcw",0x37f);n("mxcsr",0x1f80);x("mxcsr_mask",mask as u64);
        hash("fp_sha256",crate::k02_sha256::digest(&bytes));n("osxsave_enabled",0);n("kernel_fp_restored",1);});
}

fn recursive(memory:&mut NativeMemory,kernel_root:u64,permanent:[Persistent;4]) {
    let a=ok(memory.allocate_initialized_page(1,VICTIM),"matrix-target-allocate");
    let physical=ok(memory.region_info(1,a),"matrix-target-info").backing.start();owned(memory,1,a,physical);
    let rights=Rights::READ|Rights::MAP|Rights::DELEGATE;
    let b=ok(memory.delegate(1,a,2,rights,0,4096),"matrix-delegate-b");delegated(a,b,rights);
    let d=ok(memory.delegate(2,b,4,Rights::READ|Rights::MAP,0,4096),"matrix-delegate-d");delegated(b,d,Rights::READ|Rights::MAP);
    let mb=install(memory,2,b,REVOKED_B,Access::Read);prime(mb,VICTIM,false);
    let md=install(memory,4,d,REVOKED_D,Access::Read);prime(md,VICTIM,false);
    let before=unsafe{digest(physical)};
    ok(memory.revoke(1,a),"matrix-revoke-descendants");
    event("descendants_revoked",||{cap("root_capability",a);cap("descendant_B",b);cap("descendant_D",d);n("charge_retained",1);});
    if memory.release(1,a)!=Err(MemoryError::Busy) {fail("matrix-premature-release");}
    for (domain,capability,m) in [(2,b,mb),(4,d,md)] {
        requests::revoked_map(memory,permanent[domain as usize-1],capability,m.page.lease);
        let charges=accounting_snapshot(memory);let allocated=memory.allocated_pages();
        if memory.complete(domain,m.page.lease)!=Err(MemoryError::Revoked) {fail("matrix-revoked-completion");}
        if charges!=accounting_snapshot(memory) || allocated!=memory.allocated_pages() || !mapping_valid(m) {
            fail("matrix-revoked-completion-mutated");
        }
        event("revoked_request_denied",||{n("domain",domain);cap("capability",capability);lease(m.page.lease);s("operation","complete_lease");s("origin","trusted_backend");n("trusted",1);s("denial_reason","Revoked");n("charge_retained",1);});
        remove(memory,m,kernel_root);
    }
    event("mapping_leases_released",||{n("B_slot",mb.page.lease.slot() as u64);n("B_generation",mb.page.lease.generation() as u64);n("D_slot",md.page.lease.slot() as u64);n("D_generation",md.page.lease.generation() as u64);n("charge_retained",1);});
    fault(2,REVOKED_B,ptr::addr_of!(crate::k02_cpu::k02_probe_recursive_B_read),4,"recursive_B_read");
    fault(2,REVOKED_B,ptr::addr_of!(crate::k02_cpu::k02_probe_recursive_B_write),6,"recursive_B_write");
    fault(4,REVOKED_D,ptr::addr_of!(crate::k02_cpu::k02_probe_recursive_D_read),4,"recursive_D_read");
    fault(4,REVOKED_D,ptr::addr_of!(crate::k02_cpu::k02_probe_recursive_D_write),6,"recursive_D_write");
    if before!=unsafe{digest(physical)} {fail("matrix-revoked-bytes");}
    ok(memory.release(4,d),"matrix-release-d");ok(memory.release(2,b),"matrix-release-b");ok(memory.release(1,a),"matrix-release-a");
    event("capabilities_released",||{cap("D",d);cap("B",b);cap("A",a);n("charge_released",1);});
}
fn reuse(memory:&mut NativeMemory,kernel_root:u64) {
    let b=ok(memory.allocate_initialized_page(2,VICTIM),"matrix-reuse-allocate");
    let physical=ok(memory.region_info(2,b),"matrix-reuse-info").backing.start();owned(memory,2,b,physical);
    let mb=install(memory,2,b,REUSE_B,Access::Write);prime(mb,VICTIM,true);
    ok(memory.revoke(2,b),"matrix-reuse-revoke");event("revoked",||{cap("capability",b);x("physical_frame",physical);n("charge_retained",1);});
    if memory.release(2,b)!=Err(MemoryError::Busy) {fail("matrix-reuse-premature-release");}
    remove(memory,mb,kernel_root);
    event("lease_released",||{lease(mb.page.lease);x("physical_frame",physical);n("charge_retained",1);});
    ok(memory.release(2,b),"matrix-reuse-release");event("capability_released",||{cap("capability",b);x("physical_frame",physical);n("charge_released",1);});
    // Target was allocated last. No other frame is released or allocated before
    // this immediate C allocation; assert the allocator actually reused it.
    let c=ok(memory.allocate_initialized_page(3,NEW_OWNER),"matrix-new-owner");
    let replacement=ok(memory.region_info(3,c),"matrix-new-owner-info").backing.start();
    if replacement!=physical {fail("matrix-exact-frame-not-reused");}
    event("scrubbed",||{x("physical_frame",physical);n("length",4096);n("trusted",1);n("zero_before_payload",1);});
    let mc=install(memory,3,c,REUSE_C,Access::Read);read(3,REUSE_C,NEW_OWNER,"new_owner_read");
    let before=unsafe{digest(physical)};
    event("reassigned",||{x("physical_frame",physical);cap("capability",c);n("domain",3);x("root",root(3).root());x("page",REUSE_C);hash("initial_sha256",before);});
    fault(2,REUSE_B,ptr::addr_of!(crate::k02_cpu::k02_probe_reuse_B_read),4,"reuse_B_read");
    fault(2,REUSE_B,ptr::addr_of!(crate::k02_cpu::k02_probe_reuse_B_write),6,"reuse_B_write");
    let after=unsafe{digest(physical)};if before!=after {fail("matrix-new-owner-bytes");}
    event("sentinel_unchanged",||{x("page",REUSE_C);hash("before_sha256",before);hash("after_sha256",after);});
    remove(memory,mc,kernel_root);ok(memory.release(3,c),"matrix-new-owner-release");
}
