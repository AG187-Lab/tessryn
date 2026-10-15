// Standalone host fixture for the actual native adapter module. No firmware,
// provider, physical RAM, user execution or native qualification is claimed.
#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod uefi {
    #[derive(Clone, Copy)]
    pub struct Range { pub start: u64, pub end: u64 }
    #[repr(C)]
    pub struct Descriptor { pub kind: u32, pub padding: u32, pub start: u64,
        pub virtual_start: u64, pub pages: u64, pub attributes: u64 }
    pub struct Handoff { pub map: *const u8, pub map_length: usize, pub descriptor_size: usize,
        pub stack: Range, pub map_allocation: Range, pub image: Range,
        pub framebuffer: Option<Range>, pub high_scratch: Option<Range>,
        pub physical_bits: u8, pub scratch: u64 }
    impl Handoff {
        pub fn descriptors(&self) -> usize { self.map_length / self.descriptor_size }
        pub fn descriptor(&self, index: usize) -> Descriptor {
            assert!(index < self.descriptors());
            // SAFETY: only a fixture-owned initialized descriptor buffer may
            // be passed to this stub. Production uses the actual UEFI module.
            unsafe { core::ptr::read_unaligned(self.map.add(index * self.descriptor_size).cast()) }
        }
    }
}

#[path = "k02_memory.rs"]
mod k02_memory;
