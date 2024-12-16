//! A bump allocator.
//! Based on https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

use core::alloc::{GlobalAlloc, Layout};

struct SimpleAllocator {
    next_alloc: *mut u8,
}

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Single threaded, so nothing else can touch this while we're working.
        let mut heap_pos = HEAP.next_alloc;

        let align = layout.align();
        // `Layout` contract forbids making a `Layout` with align=0, or align not power of 2.
        core::hint::assert_unchecked(align.is_power_of_two());
        core::hint::assert_unchecked(align != 0);
        heap_pos = heap_pos.add(heap_pos.align_offset(align));

        let ptr = heap_pos;
        // We don't want to wrap around, and overwrite stack etc.
        // (We could also return a null pointer, but only malicious programs would ever hit this.)
        heap_pos = heap_pos.add(layout.size());

        HEAP.next_alloc = heap_pos;
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.alloc(layout)
    }

    /// Never deallocate.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

extern "C" {
    /// The address of this variable is the start of the heap (growing upwards).
    ///
    /// It is defined in the linker script.
    static mut _sheap: u8;
}

#[global_allocator]
static mut HEAP: SimpleAllocator = SimpleAllocator {
    next_alloc: &raw mut _sheap,
};
