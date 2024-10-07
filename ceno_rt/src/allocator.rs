//! A bump allocator.
//! Based on https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
};

const ARENA_SIZE: usize = 128 * 1024;
const MAX_SUPPORTED_ALIGN: usize = 4096;
struct SimpleAllocator {}

static mut ARENA: [u8; ARENA_SIZE] = [0; ARENA_SIZE];
/// we allocate from the top, counting down
static mut REMAINING: usize = ARENA_SIZE;

#[global_allocator]
static ALLOCATOR: SimpleAllocator = SimpleAllocator {};

unsafe impl Sync for SimpleAllocator {}

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // `Layout` contract forbids making a `Layout` with align=0, or align not power of 2.
        // So we can safely use a mask to ensure alignment without worrying about UB.
        let align_mask_to_round_down = !(align - 1);

        if align > MAX_SUPPORTED_ALIGN {
            return null_mut();
        }

        if size > REMAINING {
            return null_mut();
        }
        REMAINING -= size;
        REMAINING &= align_mask_to_round_down;

        ARENA.as_mut_ptr().add(REMAINING)
    }

    /// Never deallocate.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
