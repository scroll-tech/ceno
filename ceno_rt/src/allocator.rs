//! A bump allocator.
//! Based on https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

use core::alloc::{GlobalAlloc, Layout};

struct SimpleAllocator {
    next_alloc: usize,
}

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Single threaded, so nothing else can touch this while we're working.
        let mut heap_pos = unsafe { HEAP.next_alloc };

        let align = layout.align();
        let offset = heap_pos & (align - 1);
        if offset != 0 {
            heap_pos += align - offset;
        }

        let ptr = heap_pos as *mut u8;
        // Panic on overflow.  We don't want to wrap around, and overwrite stack etc.
        // (We could also return a null pointer, but only malicious programs would ever hit this.)
        heap_pos = heap_pos.strict_add(layout.size());

        unsafe { HEAP.next_alloc = heap_pos };
        ptr
    }

    /// Never deallocate.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
// We initialize `next_alloc` to 0xFFFF_FFFF to indicate that the heap has not been initialized.
// The value is chosen to make any premature allocation fail.
static mut HEAP: SimpleAllocator = SimpleAllocator {
    next_alloc: 0xFFFF_FFFF,
};

pub unsafe fn init_heap() {
    HEAP.next_alloc = core::ptr::from_ref::<u8>(&crate::_sheap).cast::<u8>() as usize;
}
