// Original tiny 5x7 glyph renderer for visible IPMI/KVM boot diagnostics.
use core::ptr;

pub struct Screen {
    pub base: u64,
    pub bytes: usize,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub rgb: bool,
    row: usize,
    column: usize,
}
static mut SCREEN: Option<Screen> = None;

pub fn install(base: u64, bytes: usize, width: usize, height: usize, stride: usize, rgb: bool) -> bool {
    let Some(required) = stride.checked_mul(height).and_then(|n| n.checked_mul(4)) else { return false; };
    if base == 0 || base % 4 != 0 || width < 80 || height < 40 || stride < width
        || required > bytes || required > 32 * 1024 * 1024
        || base.checked_add(bytes as u64).is_none_or(|end| end > crate::paging::GUARD) { return false; }
    // SAFETY: GOP reports this MMIO buffer, identity mapped in the boot profile.
    // One boot CPU owns the framebuffer; interrupts remain masked after handoff.
    unsafe {
        for pixel in 0..required / 4 { ptr::write_volatile((base as *mut u32).add(pixel), 0); }
        ptr::write(ptr::addr_of_mut!(SCREEN), Some(Screen { base, bytes, width, height, stride, rgb, row: 0, column: 0 }));
    }
    true
}

pub fn write(byte: u8) {
    // SAFETY: same single-CPU ownership as install, without allocation or locks.
    let screen = unsafe { &mut *ptr::addr_of_mut!(SCREEN) };
    let Some(screen) = screen else { return; };
    if byte == b'\r' { screen.column = 0; return; }
    if byte == b'\n' { screen.column = 0; screen.row += 1; return; }
    if screen.column * 6 + 6 > screen.width { screen.column = 0; screen.row += 1; }
    if screen.row * 10 + 10 > screen.height {
        // Wrap with a clean display so the last fault/panic remains visible.
        unsafe {
            for pixel in 0..screen.stride * screen.height {
                ptr::write_volatile((screen.base as *mut u32).add(pixel), 0);
            }
        }
        screen.row = 0;
        screen.column = 0;
    }
    let glyph = glyph(byte.to_ascii_uppercase());
    let color = if screen.rgb { 0x00a0_ff80 } else { 0x0080_ffa0 };
    for (y, row) in glyph.iter().enumerate() {
        for x in 0..5 {
            let index = (screen.row * 10 + y) * screen.stride + screen.column * 6 + x;
            if index * 4 < screen.bytes {
                // SAFETY: validated dimensions, bounds and MMIO ownership.
                unsafe { ptr::write_volatile((screen.base as *mut u32).add(index), if row & (1 << (4 - x)) != 0 { color } else { 0 }); }
            }
        }
    }
    screen.column += 1;
}

pub fn dimensions() -> Option<(u64, usize, usize, usize, bool)> {
    // SAFETY: read by the same single boot CPU that installed this state.
    unsafe { (&*ptr::addr_of!(SCREEN)).as_ref().map(|screen|
        (screen.base, screen.width, screen.height, screen.stride, screen.rgb)) }
}

fn glyph(byte: u8) -> [u8; 7] {
    match byte {
        b'A' => [14,17,17,31,17,17,17], b'B' => [30,17,17,30,17,17,30],
        b'C' => [14,17,16,16,16,17,14], b'D' => [30,17,17,17,17,17,30],
        b'E' => [31,16,16,30,16,16,31], b'F' => [31,16,16,30,16,16,16],
        b'G' => [14,17,16,23,17,17,15], b'H' => [17,17,17,31,17,17,17],
        b'I' => [14,4,4,4,4,4,14], b'J' => [7,2,2,2,18,18,12],
        b'K' => [17,18,20,24,20,18,17], b'L' => [16,16,16,16,16,16,31],
        b'M' => [17,27,21,21,17,17,17], b'N' => [17,25,21,19,17,17,17],
        b'O' => [14,17,17,17,17,17,14], b'P' => [30,17,17,30,16,16,16],
        b'Q' => [14,17,17,17,21,18,13], b'R' => [30,17,17,30,20,18,17],
        b'S' => [15,16,16,14,1,1,30], b'T' => [31,4,4,4,4,4,4],
        b'U' => [17,17,17,17,17,17,14], b'V' => [17,17,17,17,17,10,4],
        b'W' => [17,17,17,21,21,21,10], b'X' => [17,17,10,4,10,17,17],
        b'Y' => [17,17,10,4,4,4,4], b'Z' => [31,1,2,4,8,16,31],
        b'0' => [14,17,19,21,25,17,14], b'1' => [4,12,4,4,4,4,14],
        b'2' => [14,17,1,2,4,8,31], b'3' => [30,1,1,14,1,1,30],
        b'4' => [2,6,10,18,31,2,2], b'5' => [31,16,16,30,1,1,30],
        b'6' => [14,16,16,30,17,17,14], b'7' => [31,1,2,4,8,8,8],
        b'8' => [14,17,17,14,17,17,14], b'9' => [14,17,17,15,1,1,14],
        b'_' => [0,0,0,0,0,0,31], b'-' => [0,0,0,31,0,0,0],
        b'=' => [0,0,31,0,31,0,0], b'.' => [0,0,0,0,0,12,12],
        b':' => [0,12,12,0,12,12,0], b'/' => [1,2,2,4,8,8,16],
        b'(' => [2,4,8,8,8,4,2], b')' => [8,4,2,2,2,4,8],
        b' ' => [0; 7], _ => [31,17,1,2,4,0,4],
    }
}
