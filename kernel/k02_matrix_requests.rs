// Controlled CPL3 request tests, not a production syscall or wire ABI.
// The CPU-protected context supplies the caller. RSI is an untrusted claim.
use super::*;
const REQUEST_MAGIC:u64=0x4b30_3252_4551_5631;
const fn words(operation:u64,slot:u64,generation:u64,domain:u64,length:u64,rights:u64)->[u64;8] {
    [operation,slot|(generation<<32),domain,0,length,rights,0,REQUEST_MAGIC]
}
#[repr(C)]
struct RequestContract {magic:[u8;16],rows:[[u64;8];13]}
#[used]
#[unsafe(no_mangle)]
static K02_MATRIX_REQUESTS:RequestContract=RequestContract{magic:*b"TESSRYN-K02R-V1\0",rows:[
    words(1,3,1,1,4096,5), // A handle submitted by B, with claimed caller A.
    words(2,3,1,2,4096,5), // User fence; opaque lease bits never become LeaseId.
    words(3,3,1,2,4096,5), // User quiescence.
    words(4,3,1,2,4096,5), // User allocator administration.
    words(5,3,1,2,4096,5), // User trusted completion.
    words(6,3,1,2,4096,5), // User reservation activation.
    words(1,4,1,2,4094,5), // Byte slice: mapping alignment failure.
    words(1,4,1,2,4096,5), // Byte slice: capability bounds failure.
    words(1,5,1,2,4096,6), // WRITE+MAP lacks required READ for x86 mapping.
    words(7,3,1,2,4096,1), // Release retired B generation.
    words(8,3,2,2,4096,1), // Authorize valid replacement generation.
    words(1,3,1,2,4096,5), // Revoked B map request.
    words(1,3,1,4,4096,5), // Revoked D map request.
]};
const _:()=assert!(size_of::<RequestContract>()==848);

#[derive(Clone,Copy)]
struct Pending {active:bool,seen:bool,domain:u64,physical:u64,claim:u64,words:[u64;8]}
static mut PENDING:Pending=Pending{active:false,seen:false,domain:0,physical:0,claim:0,words:[0;8]};
struct Received {caller:u64,claimed:u64,words:[u64;8]}

pub(super) fn capture(domain:u64,frame:&crate::cpu::ExceptionFrame) {
    let mut pending=unsafe{ptr::addr_of!(PENDING).read()};
    if !pending.active || pending.seen || pending.domain!=domain || frame.registers[8]!=REQUEST {
        fail("matrix-request-context");
    }
    let mapping=ok(root(domain).translate(REQUEST),"matrix-request-translation");
    if !mapping.user || !mapping.writable || mapping.executable || mapping.page_bytes!=4096 || mapping.physical!=pending.physical {
        fail("matrix-request-page-identity");
    }
    // The user is stopped on the only CPU. The pointer is a fixed, authorized
    // page selected by protected context, not an arbitrary user dereference.
    for i in 0..8 {pending.words[i]=unsafe{(pending.physical as *const u64).add(i).read_volatile()};}
    pending.claim=frame.registers[9];pending.seen=true;pending.active=false;
    unsafe{ptr::addr_of_mut!(PENDING).write(pending);}
}
fn receive(memory:&NativeMemory,p:Persistent,row:usize,claim:u64,submitted_lease:Option<crate::k02_memory::LeaseId>)->Received {
    let recipe=unsafe{ptr::addr_of!(K02_MATRIX_REQUESTS).read_volatile()};
    if recipe.magic!=*b"TESSRYN-K02R-V1\0" || row>=13 {fail("matrix-request-recipe");}
    let mut input=recipe.rows[row];
    if let Some(id)=submitted_lease {input[6]=id.slot() as u64|((id.generation() as u64)<<32);}
    let authorized=ok(memory.authorize(p.domain,p.caps[2],Rights::READ,0,64),"matrix-request-authority");
    if authorized.physical_start!=p.pages[2].physical || authorized.length!=64 {fail("matrix-request-authority-view");}
    for (i,value) in input.into_iter().enumerate() {unsafe{(p.pages[2].physical as *mut u64).add(i).write_volatile(value);}}
    unsafe{ptr::addr_of_mut!(PENDING).write(Pending{active:true,seen:false,domain:p.domain,physical:p.pages[2].physical,claim:0,words:[0;8]});}
    run_probe(p.domain,ptr::addr_of!(crate::k02_cpu::k02_probe_request),ptr::addr_of!(crate::k02_cpu::k02_probe_request_trap),REQUEST,claim,None,None,"request");
    let observed=unsafe{ptr::addr_of!(PENDING).read()};
    if observed.active || !observed.seen || observed.domain!=p.domain || observed.claim!=claim || observed.words!=input {fail("matrix-request-observation");}
    event("request_observed",||{n("recipe",row as u64);n("caller",observed.domain);n("claimed_caller",observed.claim);x("pointer",REQUEST);
        x("physical_frame",observed.physical);for (i,value) in observed.words.into_iter().enumerate(){print(format_args!(" word{i}={value:#x}"));}});
    Received{caller:observed.domain,claimed:observed.claim,words:observed.words}
}
fn handle(input:&Received)->CapabilityRef {CapabilityRef{slot:input.words[1] as u32,generation:(input.words[1]>>32) as u32,domain:input.words[2]}}
fn dispatch(memory:&mut NativeMemory,input:&Received)->Result<Option<u64>,MemoryError> {
    if input.words[7]!=REQUEST_MAGIC {return Err(MemoryError::InvalidAuthority);}
    // User data never constructs an internal LeaseId, acknowledges quiescence,
    // mutates allocator administration or activates a reserved backing range.
    match input.words[0] {
        1=>{let access=if input.words[5]&2!=0 {Access::Write}else{Access::Read};
            let result=memory.map_intent(input.caller,handle(input),access,input.words[3],input.words[4]);
            match result {Err(error)=>Err(error),Ok(_)=>fail("matrix-unexpected-user-map-authorization")}},
        2..=6=>Err(MemoryError::InvalidAuthority),
        7=>memory.release(input.caller,handle(input)).map(|()|None),
        8=>memory.authorize(input.caller,handle(input),Rights::READ,input.words[3],input.words[4]).map(|view|Some(view.physical_start)),
        _=>Err(MemoryError::InvalidAuthority),
    }
}
fn denied(memory:&mut NativeMemory,p:Persistent,row:usize,claim:u64,expected_handle:CapabilityRef,id:Option<crate::k02_memory::LeaseId>,
          operation:&str,expected:MemoryError,phase:Option<&str>) {
    let before=accounting_snapshot(memory);let allocated=memory.allocated_pages();
    let received=receive(memory,p,row,claim,id);
    if handle(&received)!=expected_handle {fail("matrix-request-wrong-capability");}
    if dispatch(memory,&received)!=Err(expected) {fail("matrix-request-not-denied");}
    if before!=accounting_snapshot(memory) || allocated!=memory.allocated_pages() {
        fail("matrix-denial-mutated-charge");
    }
    if root(p.domain).translation(GUARD).is_some() || root(p.domain).translation(UNAUTHORIZED).is_some() {fail("matrix-denial-pte-published");}
    event("dispatch_denied",||{n("caller",received.caller);n("claimed_caller",received.claimed);s("operation",operation);s("origin","CPL3");x("cs",crate::k02_cpu::USER_CS);
        cap("capability",handle(&received));n("pte_published",0);n("charge_released",0);
        if let Some(lease_id)=id {n("submitted_lease_slot",lease_id.slot() as u64);n("submitted_lease_generation",lease_id.generation() as u64);}
        if (2..=6).contains(&received.words[0]) {s("denial_reason","untrusted_origin");}else{print(format_args!(" denial_reason={expected:?}"));}
        if let Some(value)=phase{s("lease_phase",value);n("pte_installed",1);}
        if row==6 || row==7 {n("capability_offset",1);n("capability_length",4094);n("offset",0);n("length",received.words[4]);}
        if row==8 {n("rights",6);}
    });
}

pub(super) fn run(memory:&mut NativeMemory,handoff:&crate::uefi::Handoff,case:u64,p:Persistent) {
    match case {0=>caller(memory,p),1=>privileged(memory,handoff.cr3,p),4=>bounds(memory,handoff.cr3,p),9=>stale(memory,handoff.cr3,p),_=>fail("matrix-request-case")}
}
fn target(memory:&mut NativeMemory,domain:u64)->(CapabilityRef,u64) {
    let handle=ok(memory.allocate_initialized_page(domain,VICTIM),"matrix-request-target");
    let frame=ok(memory.region_info(domain,handle),"matrix-request-target-info").backing.start();owned(memory,domain,handle,frame);(handle,frame)
}
fn caller(memory:&mut NativeMemory,p:Persistent) {
    let (a,_)=target(memory,1);denied(memory,p,0,1,a,None,"map",MemoryError::InvalidAuthority,None);
    event("owner_retained",||cap("capability",a));ok(memory.release(1,a),"matrix-caller-target-release");
}
fn readonly(memory:&mut NativeMemory)->(CapabilityRef,CapabilityRef,Mapping) {
    let (a,_)=target(memory,1);let b=ok(memory.delegate_readonly(1,a,2),"matrix-request-readonly");
    delegated(a,b,Rights::READ|Rights::MAP);let mapping=install(memory,2,b,READONLY,Access::Read);(a,b,mapping)
}
fn privileged(memory:&mut NativeMemory,kernel_root:u64,p:Persistent) {
    let (a,b,mut m)=readonly(memory);
    for (row,operation) in [(1,"fence"),(2,"quiesce"),(3,"allocator_admin"),(4,"complete_lease"),(5,"activate_reserved")] {
        denied(memory,p,row,2,b,Some(m.page.lease),operation,MemoryError::InvalidAuthority,None);
    }
    fence(memory,&mut m);
    event("trusted_fence_state",||{mapping_fields(m);n("trusted",1);s("phase","fenced");n("pte_installed",1);});
    denied(memory,p,2,2,b,Some(m.page.lease),"quiesce",MemoryError::InvalidAuthority,Some("fenced"));
    if !mapping_valid(m) {fail("matrix-untrusted-quiesce-pte");}
    event("mapping_owner_retained",||{mapping_fields(m);s("phase","fenced");n("pte_installed",1);});
    event("owner_retained",||{cap("capability",a);n("charge_retained",1);});
    remove(memory,m,kernel_root);ok(memory.release(2,b),"matrix-priv-child-release");ok(memory.release(1,a),"matrix-priv-owner-release");
}
fn bounds(memory:&mut NativeMemory,kernel_root:u64,p:Persistent) {
    let (a,b,m)=readonly(memory);
    fault(2,GUARD,ptr::addr_of!(crate::k02_cpu::k02_probe_guard_read),4,"guard_read");
    let byte=ok(memory.delegate(1,a,2,Rights::READ|Rights::MAP,1,4094),"matrix-byte-delegate");
    event("delegated",||{cap("parent",a);cap("child",byte);n("offset",1);n("length",4094);n("rights",5);});
    denied(memory,p,6,2,byte,None,"map_byte_slice",MemoryError::Alignment,None);
    denied(memory,p,7,2,byte,None,"map_byte_slice",MemoryError::Bounds,None);
    remove(memory,m,kernel_root);event("lease_released",||{lease(m.page.lease);x("physical_frame",m.page.physical);n("charge_retained",1);});
    let writeonly=ok(memory.delegate(1,a,2,Rights::WRITE|Rights::MAP,0,4096),"matrix-writeonly-delegate");
    delegated(a,writeonly,Rights::WRITE|Rights::MAP);denied(memory,p,8,2,writeonly,None,"map_without_read",MemoryError::InsufficientRights,None);
    ok(memory.release(2,writeonly),"matrix-writeonly-release");ok(memory.release(2,byte),"matrix-byte-release");ok(memory.release(2,b),"matrix-bounds-child-release");ok(memory.release(1,a),"matrix-bounds-owner-release");
}
fn stale(memory:&mut NativeMemory,kernel_root:u64,p:Persistent) {
    let (old,physical)=target(memory,2);let previous=install(memory,2,old,REUSE_B,Access::Write);prime(previous,VICTIM,true);
    ok(memory.revoke(2,old),"matrix-stale-revoke");event("revoked",||{cap("capability",old);x("physical_frame",physical);n("charge_retained",1);});
    if memory.release(2,old)!=Err(MemoryError::Busy) {fail("matrix-stale-premature-release");}
    remove(memory,previous,kernel_root);event("lease_released",||{lease(previous.page.lease);x("physical_frame",physical);n("charge_retained",1);});
    ok(memory.release(2,old),"matrix-stale-retire");event("capability_released",||{cap("capability",old);x("physical_frame",physical);n("charge_released",1);});
    event("retired_generation",||{cap("capability",old);lease(previous.page.lease);n("released",1);});
    let c=ok(memory.allocate_initialized_page(3,NEW_OWNER),"matrix-stale-new-c");
    if ok(memory.region_info(3,c),"matrix-stale-c-info").backing.start()!=physical {fail("matrix-stale-not-exact-frame");}
    event("scrubbed",||{x("physical_frame",physical);n("length",4096);n("trusted",1);n("zero_before_payload",1);});owned(memory,3,c,physical);
    let replacement=ok(memory.delegate_readonly(3,c,2),"matrix-stale-new-b");
    if replacement.slot!=old.slot || replacement.generation!=old.generation+1 {fail("matrix-stale-cap-generation");}
    delegated(c,replacement,Rights::READ|Rights::MAP);let mut current=install(memory,2,replacement,REUSE_B,Access::Read);
    if current.page.lease.slot()!=previous.page.lease.slot() || current.page.lease.generation()!=previous.page.lease.generation()+1 {
        fail("matrix-stale-lease-generation");
    }
    let before=unsafe{digest(physical)};
    event("victim_initialized",||{cap("capability",c);n("domain",3);x("root",root(3).root());x("physical_frame",physical);x("page",REUSE_C);n("length",4096);hash("initial_sha256",before);});
    denied(memory,p,9,2,old,None,"release_stale_capability",MemoryError::StaleHandle,None);
    if memory.fence(previous.page.lease)!=Err(MemoryError::StaleLease) {fail("matrix-stale-lease-accepted");}
    event("backend_stale_lease_denied",||{s("operation","fence");s("origin","trusted_backend");n("trusted",1);
        n("submitted_lease_slot",previous.page.lease.slot() as u64);n("submitted_lease_generation",previous.page.lease.generation() as u64);
        n("replacement_lease_slot",current.page.lease.slot() as u64);n("replacement_lease_generation",current.page.lease.generation() as u64);
        s("denial_reason","StaleLease");s("replacement_phase","active");n("pte_installed",1);n("charge_released",0);});
    event("replacement_retained",||{cap("capability",replacement);mapping_fields(current);s("phase","active");n("pte_installed",1);});
    let input=receive(memory,p,10,2,None);
    if dispatch(memory,&input)!=Ok(Some(physical)) {fail("matrix-current-generation-not-authorized");}
    read(2,REUSE_B,NEW_OWNER,"replacement_read");
    event("replacement_read_authorized",||{n("caller",2);cap("capability",replacement);n("offset",0);n("length",4096);x("physical_frame",physical);});
    // Positive fresh-ID fence must succeed: stale-ID rejection alone cannot
    // prove that the replacement's active ownership was left untouched.
    fence(memory,&mut current);event("trusted_fence_state",||{mapping_fields(current);n("trusted",1);s("phase","fenced");n("pte_installed",1);});
    let after=unsafe{digest(physical)};if before!=after {fail("matrix-stale-victim-bytes");}
    event("sentinel_unchanged",||{x("page",REUSE_C);hash("before_sha256",before);hash("after_sha256",after);});
    remove(memory,current,kernel_root);ok(memory.release(2,replacement),"matrix-current-child-release");ok(memory.release(3,c),"matrix-current-owner-release");
}

pub(super) fn revoked_map(memory:&mut NativeMemory,p:Persistent,capability:CapabilityRef,id:crate::k02_memory::LeaseId) {
    let row=match p.domain {2=>11,4=>12,_=>fail("matrix-revoked-request-domain")};
    let before=accounting_snapshot(memory);let allocated=memory.allocated_pages();
    let input=receive(memory,p,row,p.domain,None);
    if handle(&input)!=capability || dispatch(memory,&input)!=Err(MemoryError::Revoked) {
        fail("matrix-revoked-dispatch");
    }
    if before!=accounting_snapshot(memory) || allocated!=memory.allocated_pages() {
        fail("matrix-revoked-dispatch-mutated");
    }
    event("revoked_request_denied",||{n("domain",p.domain);cap("capability",capability);lease(id);s("operation","map");
        s("origin","CPL3");x("cs",crate::k02_cpu::USER_CS);n("caller",input.caller);n("claimed_caller",input.claimed);
        s("denial_reason","Revoked");n("charge_retained",1);});
}
