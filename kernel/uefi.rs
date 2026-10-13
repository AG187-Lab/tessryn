// Original minimal definitions of the published UEFI 2.11 x64 ABI.
// Layout reference: https://uefi.org/specs/UEFI/2.11/04_EFI_System_Table.html
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;
use crate::diagnostics::{fail, print};

pub type Handle = *mut c_void;
pub type Status = usize;
pub type ResetSystem = unsafe extern "efiapi" fn(u32, Status, usize, *const u16) -> !;
const INVALID_PARAMETER: Status = (1usize << 63) | 2;
const UNSUPPORTED: Status = (1usize << 63) | 3;
const PAGE: u64 = 4096;
pub const LIMIT: u64 = crate::paging::LOW_LIMIT;
pub const STACK_PAGES: usize = 32;
const MAP_PAGES: usize = 16;
pub const RUNTIME: u64 = 1 << 63;
// Initial map discovery uses image-owned storage, never the firmware stack.
// The final retained map has its own loader allocation.
static mut EARLY_MAP: [u8; MAP_PAGES * 4096] = [0; MAP_PAGES * 4096];

#[repr(C)]
pub struct Header {
    signature: u64,
    revision: u32,
    size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    header: Header,
    vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    console_in: usize,
    console_out_handle: Handle,
    console_out: usize,
    standard_error_handle: Handle,
    standard_error: usize,
    runtime: *const RuntimeServices,
    boot: *const BootServices,
    configuration_count: usize,
    configuration: usize,
}

#[repr(C)]
struct BootServices {
    header: Header,
    tpl: [usize; 2],
    allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    free_pages: usize,
    get_memory_map: unsafe extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    pool_and_events: [usize; 8],
    protocol_mutations: [usize; 3],
    handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    protocol_registration: [usize; 2],
    locate_handle: unsafe extern "efiapi" fn(u32, *const Guid, *mut c_void, *mut usize, *mut Handle) -> Status,
    protocol_and_image: [usize; 6],
    exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
    monotonic_and_stall: [usize; 2],
    set_watchdog: unsafe extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
    connection_and_open: [usize; 7],
    locate_protocol: usize,
}

#[repr(C)]
struct RuntimeServices {
    header: Header,
    time_virtual_variable_monotonic: [usize; 10],
    reset_system: ResetSystem,
}

#[repr(C)]
struct Guid { a: u32, b: u16, c: u16, d: [u8; 8] }
const LOADED_IMAGE: Guid = Guid {
    a: 0x5b1b31a1, b: 0x9562, c: 0x11d2,
    d: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
const GOP: Guid = Guid {
    a: 0x9042a9de, b: 0x23dc, c: 0x4a38,
    d: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};
#[repr(C)]
struct Graphics { functions: [usize; 3], mode: *const GraphicsMode }
#[repr(C)]
struct GraphicsMode { maximum: u32, current: u32, info: *const GraphicsInfo, info_size: usize, base: u64, bytes: usize }
#[repr(C)]
struct GraphicsInfo { version: u32, width: u32, height: u32, format: u32, masks: [u32; 4], stride: u32 }

#[derive(Clone, Copy)]
struct Framebuffer {
    base: u64,
    bytes: usize,
    width: usize,
    height: usize,
    stride: usize,
    format: u32,
}

unsafe fn framebuffer_for_handle(boot: &BootServices, handle: Handle, physical_bits: u8) -> Option<Framebuffer> {
    if handle.is_null() { return None; }
    let mut graphics: *mut c_void = ptr::null_mut();
    // SAFETY: this is a firmware handle queried before any exit attempt. No
    // driver method changes its mode or writes a framebuffer during selection.
    let status = unsafe { (boot.handle_protocol)(handle, &GOP, &mut graphics) };
    if status != 0 || graphics.is_null() { return None; }
    let graphics = unsafe { &*graphics.cast::<Graphics>() };
    if graphics.mode.is_null() { return None; }
    let mode = unsafe { &*graphics.mode };
    if mode.info.is_null() || mode.info_size < size_of::<GraphicsInfo>()
        || mode.current >= mode.maximum { return None; }
    let info = unsafe { &*mode.info };
    let candidate = Framebuffer {
        base: mode.base, bytes: mode.bytes, width: info.width as usize,
        height: info.height as usize, stride: info.stride as usize, format: info.format,
    };
    let required = candidate.stride.checked_mul(candidate.height)?.checked_mul(4)?;
    if candidate.base == 0 || candidate.base % 4 != 0
        || candidate.width < 80 || candidate.height < 40 || candidate.stride < candidate.width
        || candidate.format > 1 || required > candidate.bytes || required > 32 * 1024 * 1024 { return None; }
    crate::paging::mapping_bounds(crate::paging::Range::checked(candidate.base, candidate.bytes as u64).ok()?, physical_bits).ok()?;
    Some(candidate)
}

unsafe fn select_framebuffer(boot: &BootServices, console: Handle, physical_bits: u8) -> Result<(Framebuffer, &'static str), Status> {
    // The firmware's console is authoritative for BMC/IPMI visibility. A
    // discrete accelerator's unrelated GOP must never win by enumeration order.
    if let Some(candidate) = unsafe { framebuffer_for_handle(boot, console, physical_bits) } {
        return Ok((candidate, "firmware-console"));
    }
    // Some consoles are aggregators without GOP. Enumerate into bounded owned
    // stack storage; an oversized/failed list is rejected instead of truncated.
    let mut handles = [ptr::null_mut(); 32];
    let mut bytes = size_of::<[Handle; 32]>();
    let status = unsafe { (boot.locate_handle)(2, &GOP, ptr::null_mut(), &mut bytes, handles.as_mut_ptr()) };
    if status != 0 || bytes == 0 || bytes > size_of::<[Handle; 32]>()
        || bytes % size_of::<Handle>() != 0 { return Err(UNSUPPORTED); }
    let mut selected: Option<Framebuffer> = None;
    for handle in &handles[..bytes / size_of::<Handle>()] {
        let Some(candidate) = (unsafe { framebuffer_for_handle(boot, *handle, physical_bits) }) else { continue; };
        match selected {
            None => selected = Some(candidate),
            Some(previous) if previous.base == candidate.base && previous.width == candidate.width
                && previous.height == candidate.height => {
                // Aliases can describe different accessible buffer lengths.
                // Conflicting layouts for the same pixels are still unsafe.
                if previous.stride != candidate.stride || previous.format != candidate.format {
                    return Err(UNSUPPORTED);
                }
            }
            Some(_) => return Err(UNSUPPORTED), // More than one distinct usable display.
        }
    }
    selected.map(|candidate| (candidate, "unique-gop")).ok_or(UNSUPPORTED)
}

#[repr(C)]
struct LoadedImage {
    revision: u32,
    parent: Handle,
    system: *const SystemTable,
    device: Handle,
    path: usize,
    reserved: usize,
    options_size: u32,
    options: usize,
    base: u64,
    size: u64,
    code_type: u32,
    data_type: u32,
    unload: usize,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Descriptor {
    pub kind: u32,
    padding: u32,
    pub start: u64,
    virtual_start: u64,
    pub pages: u64,
    pub attributes: u64,
}

const _: () = {
    assert!(size_of::<Header>() == 24);
    assert!(offset_of!(SystemTable, console_in_handle) == 40);
    assert!(offset_of!(SystemTable, console_in) == 48);
    assert!(offset_of!(SystemTable, console_out_handle) == 56);
    assert!(offset_of!(SystemTable, console_out) == 64);
    assert!(offset_of!(SystemTable, runtime) == 88);
    assert!(offset_of!(SystemTable, boot) == 96);
    assert!(offset_of!(BootServices, allocate_pages) == 40);
    assert!(offset_of!(BootServices, get_memory_map) == 56);
    assert!(offset_of!(BootServices, handle_protocol) == 152);
    assert!(offset_of!(BootServices, locate_handle) == 176);
    assert!(offset_of!(BootServices, exit_boot_services) == 232);
    assert!(offset_of!(BootServices, set_watchdog) == 256);
    assert!(offset_of!(BootServices, locate_protocol) == 320);
    assert!(offset_of!(RuntimeServices, reset_system) == 104);
    assert!(offset_of!(LoadedImage, base) == 64);
    assert!(offset_of!(LoadedImage, size) == 72);
    assert!(size_of::<Descriptor>() == 40);
};

pub use crate::paging::Range;
impl Range {
    fn new(start: u64, length: u64) -> Self {
        Self::checked(start, length).unwrap_or_else(|error| fail(error.label()))
    }
}

#[repr(C)]
pub struct Handoff {
    pub map: *const u8,
    pub map_length: usize,
    pub descriptor_size: usize,
    pub stack: Range,
    pub map_allocation: Range,
    pub image: Range,
    pub framebuffer: Option<Range>,
    pub high_scratch: Option<Range>,
    pub reset: ResetSystem,
    pub physical_bits: u8,
    pub cr3: u64,
    pub free_pages: u64,
    pub scratch: u64,
}

impl Handoff {
    pub fn descriptors(&self) -> usize { self.map_length / self.descriptor_size }
    pub fn descriptor(&self, index: usize) -> Descriptor {
        if index >= self.descriptors() { fail("descriptor-index"); }
        // SAFETY: get_memory_map initialized these bytes; stride is validated.
        unsafe { ptr::read_unaligned(self.map.add(index * self.descriptor_size).cast()) }
    }

    fn range_has_kind(&self, range: Range, allowed: &[u32]) -> bool {
        let mut cursor = range.start;
        while cursor < range.end {
            let mut next = cursor;
            for i in 0..self.descriptors() {
                let d = self.descriptor(i);
                let end = d.start + d.pages * PAGE;
                if d.start <= cursor && cursor < end && allowed.contains(&d.kind) {
                    next = core::cmp::min(end, range.end);
                    break;
                }
            }
            if next == cursor { return false; }
            cursor = next;
        }
        true
    }

    pub fn validate(&mut self) {
        if self.descriptor_size < size_of::<Descriptor>() || self.descriptor_size % 8 != 0
            || self.map_length == 0 || self.map_length % self.descriptor_size != 0
            || self.descriptors() > 4096 { fail("memory-map-layout"); }
        self.free_pages = 0;
        self.scratch = 0;
        for i in 0..self.descriptors() {
            let d = self.descriptor(i);
            let bytes = d.pages.checked_mul(PAGE).unwrap_or_else(|| fail("descriptor-overflow"));
            let end = d.start.checked_add(bytes).unwrap_or_else(|| fail("descriptor-overflow"));
            if d.pages == 0 || d.start % PAGE != 0 { fail("descriptor-range"); }
            for j in 0..i {
                let p = self.descriptor(j);
                if (Range { start: d.start, end }).overlaps(Range { start: p.start, end: p.start + p.pages * PAGE }) {
                    fail("memory-map-overlap");
                }
            }
            // This first allocator owns only conventional RAM. Loader, runtime,
            // ACPI, MMIO, reserved and boot-service ranges remain quarantined.
            if d.kind == 7 && d.attributes & RUNTIME == 0 {
                let mapped_end = core::cmp::min(end, LIMIT);
                let mapped_pages = mapped_end.saturating_sub(d.start) / PAGE;
                self.free_pages = self.free_pages.checked_add(mapped_pages).unwrap_or_else(|| fail("free-page-overflow"));
                let start = core::cmp::max(d.start, 0x10_0000);
                let candidate = Range { start, end: start + PAGE };
                if self.scratch == 0 && candidate.end <= core::cmp::min(end, LIMIT)
                    && !candidate.overlaps(self.image) && !candidate.overlaps(self.stack)
                    && !candidate.overlaps(self.map_allocation) { self.scratch = start; }
            }
        }
        if !self.range_has_kind(self.image, &[1, 2])
            || !self.range_has_kind(self.stack, &[2])
            || !self.range_has_kind(self.map_allocation, &[2]) {
            fail("live-loader-range-ownership");
        }
        for range in [self.image, self.stack, self.map_allocation] {
            crate::paging::mapping_bounds(range, self.physical_bits).unwrap_or_else(|error| fail(error.label()));
        }
        if self.image.overlaps(self.stack) || self.image.overlaps(self.map_allocation)
            || self.stack.overlaps(self.map_allocation) { fail("live-loader-range-overlap"); }
        let reset = self.reset as usize as u64;
        let reset_range = Range::new(reset, 1);
        if !self.range_has_kind(reset_range, &[5]) { fail("runtime-reset-ownership"); }
        let mut reset_is_runtime = false;
        for index in 0..self.descriptors() {
            let d = self.descriptor(index);
            if d.kind == 5 && d.attributes & RUNTIME != 0
                && d.start <= reset && reset < d.start + d.pages * PAGE { reset_is_runtime = true; }
        }
        if !reset_is_runtime { fail("runtime-reset-attribute"); }
        crate::paging::mapping_bounds(reset_range, self.physical_bits).unwrap_or_else(|error| fail(error.label()));
        if let Some(range) = self.high_scratch {
            if range.start < LIMIT || range.end - range.start != PAGE
                || !self.range_has_kind(range, &[2]) || range.overlaps(self.image)
                || range.overlaps(self.stack) || range.overlaps(self.map_allocation) {
                fail("high-scratch-loader-ownership");
            }
            crate::paging::mapping_bounds(range, self.physical_bits).unwrap_or_else(|error| fail(error.label()));
            self.scratch = range.start;
        }
        if self.scratch == 0 || self.free_pages == 0 { fail("no-conventional-memory"); }
    }
}

unsafe fn allocate(boot: &BootServices, pages: usize) -> Range {
    let mut address = LIMIT - 1;
    // SAFETY: valid firmware ABI at TPL_APPLICATION, before ExitBootServices.
    let status = unsafe { (boot.allocate_pages)(1, 2, pages, &mut address) };
    if status != 0 { fail("allocate-loader-pages"); }
    Range::new(address, pages as u64 * PAGE)
}

unsafe fn allocate_high(boot: &BootServices, pages: usize, physical_bits: u8) -> Range {
    // This fixture requests genuine conventional RAM with AllocateAddress.
    // A fresh discovery precedes each allocation; no fabricated descriptors or
    // ownership labels enter the final firmware map.
    let map = ptr::addr_of_mut!(EARLY_MAP).cast::<u8>();
    let mut length = MAP_PAGES * PAGE as usize;
    let mut key = 0;
    let mut stride = 0;
    let mut version = 0;
    let status = unsafe { (boot.get_memory_map)(&mut length, map, &mut key, &mut stride, &mut version) };
    if status != 0 || length == 0 || length > MAP_PAGES * PAGE as usize
        || stride < size_of::<Descriptor>() || stride % 8 != 0 || length % stride != 0 || version != 1 {
        fail("high-allocation-memory-map");
    }
    let bytes = pages as u64 * PAGE;
    for index in 0..length / stride {
        let d = unsafe { ptr::read_unaligned(map.add(index * stride).cast::<Descriptor>()) };
        let Some(end) = d.pages.checked_mul(PAGE).and_then(|n| d.start.checked_add(n)) else { fail("descriptor-overflow"); };
        if d.kind != 7 || d.attributes & RUNTIME != 0 || d.start % PAGE != 0 { continue; }
        let ceiling = core::cmp::min(end, core::cmp::min(1u64 << physical_bits, crate::paging::GUARD));
        let Some(candidate) = ceiling.checked_sub(bytes) else { continue; };
        if candidate < core::cmp::max(d.start, LIMIT) { continue; }
        let mut address = candidate & !(PAGE - 1);
        if address < core::cmp::max(d.start, LIMIT)
            || crate::paging::mapping_bounds(Range::new(address, bytes), physical_bits).is_err() { continue; }
        let status = unsafe { (boot.allocate_pages)(2, 2, pages, &mut address) };
        if status == 0 { return Range::new(address, bytes); }
    }
    fail("no-high-conventional-allocation")
}

pub unsafe fn leave_firmware(image: Handle, system: *const SystemTable) -> Result<Handoff, Status> {
    if system.is_null() { fail("null-system-table"); }
    // SAFETY: UEFI entry guarantees its SystemTable pointer. Layout assertions
    // and signatures limit accesses to the documented ABI.
    let system = unsafe { &*system };
    if system.header.signature != 0x5453_5953_2049_4249
        || system.header.size < size_of::<SystemTable>() as u32
        || system.boot.is_null() || system.runtime.is_null() { fail("system-table-header"); }
    let boot = unsafe { &*system.boot };
    let runtime = unsafe { &*system.runtime };
    if boot.header.signature != 0x5652_4553_544f_4f42 || boot.header.size < size_of::<BootServices>() as u32
        || runtime.header.signature != 0x5652_4553_544e_5552
        || runtime.header.size < size_of::<RuntimeServices>() as u32 { fail("service-table-header"); }
    let physical_bits = crate::cpu::physical_profile().unwrap_or_else(|reason| fail(reason));
    let framebuffer = match unsafe { select_framebuffer(boot, system.console_out_handle, physical_bits) } {
        Ok((framebuffer, selection)) => {
            let screen = crate::framebuffer::install(framebuffer.base, framebuffer.bytes, framebuffer.width,
                framebuffer.height, framebuffer.stride, framebuffer.format == 0);
            if !screen { return Err(UNSUPPORTED); }
            print(format_args!("TESSRYN ORIGINAL KERNEL\n"));
            let Some((base, width, height, stride, rgb)) = crate::framebuffer::dimensions() else { return Err(UNSUPPORTED); };
            print(format_args!("TESSRYN_K01_FRAMEBUFFER status=ready width={} height={} stride={} base={:#x} format={} selection={selection}\n",
                width, height, stride, base, if rgb { "rgbx" } else { "bgrx" }));
            Some(Range::new(framebuffer.base, framebuffer.bytes as u64))
        }
        Err(_) if cfg!(k01_aws) => {
            print(format_args!("TESSRYN_K01_FRAMEBUFFER status=unavailable-serial-only reason=optional-gop\n"));
            None
        }
        Err(status) => {
            print(format_args!("TESSRYN_K01_FRAMEBUFFER status=unsupported reason=missing-or-ambiguous-console\n"));
            return Err(status);
        }
    };
    // All handle-based work finishes before the first ExitBootServices attempt.
    let mut loaded: *mut c_void = ptr::null_mut();
    let status = unsafe { (boot.handle_protocol)(image, &LOADED_IMAGE, &mut loaded) };
    if status != 0 || loaded.is_null() { fail("loaded-image-protocol"); }
    let loaded = unsafe { &*loaded.cast::<LoadedImage>() };
    let image_range = Range::new(loaded.base, loaded.size);
    let stack = if cfg!(k01_high_handoff) && cfg!(k01_emulator) {
        unsafe { allocate_high(boot, STACK_PAGES, physical_bits) }
    } else { unsafe { allocate(boot, STACK_PAGES) } };
    let map_allocation = if cfg!(k01_high_handoff) && cfg!(k01_emulator) {
        unsafe { allocate_high(boot, MAP_PAGES, physical_bits) }
    } else { unsafe { allocate(boot, MAP_PAGES) } };
    let high_scratch = if cfg!(k01_high_handoff) && cfg!(k01_emulator) {
        Some(unsafe { allocate_high(boot, 1, physical_bits) })
    } else { None };
    if cfg!(k01_high_handoff) && !cfg!(k01_emulator) { fail("high-handoff-emulator-only"); }
    // Watchdog disabling is best effort; success also disables it at handoff.
    let _ = unsafe { (boot.set_watchdog)(0, 0, 0, ptr::null()) };
    let reset = runtime.reset_system;
    let mut handoff = Handoff {
        map: map_allocation.start as *const u8, map_length: 0,
        descriptor_size: 0, stack, map_allocation, image: image_range,
        framebuffer, high_scratch, reset, physical_bits, cr3: 0, free_pages: 0, scratch: 0,
    };
    // A failed exit may partially shut down firmware: only GetMemoryMap and
    // ExitBootServices are used on retries, without allocations or protocols.
    for attempt in 1..=8 {
        let mut length = MAP_PAGES * PAGE as usize;
        let mut key = 0;
        let mut stride = 0;
        let mut version = 0;
        let status = unsafe { (boot.get_memory_map)(&mut length, handoff.map as *mut u8, &mut key, &mut stride, &mut version) };
        if status != 0 || length > MAP_PAGES * PAGE as usize || version != 1 { fail("get-memory-map"); }
        handoff.map_length = length;
        handoff.descriptor_size = stride;
        handoff.validate();
        let paging = match unsafe { crate::cpu::prepare_mappings(&handoff) } {
            Ok(paging) => paging,
            Err(error) => {
                print(format_args!("TESSRYN_K01_PAGING_REJECT reason={}\n", error.label()));
                fail("paging-plan");
            }
        };
        handoff.cr3 = paging.root;
        let mut runtime_high = 0;
        for index in 0..handoff.descriptors() {
            let d = handoff.descriptor(index);
            if d.attributes & RUNTIME != 0 && d.start + d.pages * PAGE > LIMIT { runtime_high += 1; }
        }
        let gop = handoff.framebuffer.unwrap_or(Range { start: 0, end: 0 });
        print(format_args!("TESSRYN_K01_LIVE_RANGES image_start={:#x} image_end={:#x} stack_start={:#x} stack_end={:#x} map_start={:#x} map_end={:#x} scratch={:#x} runtime_high={runtime_high} gop_start={:#x} gop_end={:#x}\n",
            handoff.image.start, handoff.image.end, handoff.stack.start, handoff.stack.end,
            handoff.map_allocation.start, handoff.map_allocation.end, handoff.scratch, gop.start, gop.end));
        print(format_args!("TESSRYN_K01_PAGING_READY cr3={:#x} tables={} leaves={} physical_bits={} guard={:#x} free_scope=low-conventional\n",
            paging.root, paging.tables, paging.leaves, physical_bits, crate::paging::GUARD));
        print(format_args!("TESSRYN_K01_RESET_POINTER address={:#x} method=uefi-runtime\n", handoff.reset as usize));
        // These diagnostics access only owned memory, framebuffer and declared
        // ports. No firmware service is used between map acquisition and exit.
        print(format_args!("TESSRYN_K01_MEMORY_MAP_VALID descriptors={} stride={} free_pages={} attempt={}\n",
            handoff.descriptors(), stride, handoff.free_pages, attempt));
        let status = unsafe { (boot.exit_boot_services)(image, key) };
        if status == 0 {
            // SAFETY: boot services have returned ownership; firmware timer
            // handlers must not run during the assembly/descriptor transition.
            unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
            // No firmware service/table access occurs after this point.
            print(format_args!("TESSRYN_K01_EXIT_BOOT_SERVICES_OK\n"));
            return Ok(handoff);
        }
        if status != INVALID_PARAMETER { fail("exit-boot-services-status"); }
        print(format_args!("TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n"));
    }
    fail("exit-boot-services-retry-limit")
}
