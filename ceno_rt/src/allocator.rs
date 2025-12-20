//! A bump allocator.
//! Based on https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

use core::{
    alloc::{GlobalAlloc, Layout},
    mem,
    ptr::addr_of_mut,
};

struct SimpleAllocator;

static mut HEAP_START: *mut u8 = core::ptr::null_mut();
static mut NEXT_ALLOC: *mut u8 = core::ptr::null_mut();
static mut WATERMARK_SLOT: *mut u32 = core::ptr::null_mut();

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            ensure_initialized();
        }
        // SAFETY: Single threaded, so nothing else can touch this while we're working.
        let mut heap_pos = unsafe { NEXT_ALLOC };

        let align = layout.align();
        // `Layout` contract forbids making a `Layout` with align=0, or align not power of 2.
        unsafe {
            core::hint::assert_unchecked(align.is_power_of_two());
            core::hint::assert_unchecked(align != 0);
            heap_pos = heap_pos.add(heap_pos.align_offset(align));
        }

        let ptr = heap_pos;
        // We don't want to wrap around, and overwrite stack etc.
        // (We could also return a null pointer, but only malicious programs would ever hit this.)
        unsafe {
            heap_pos = heap_pos.add(layout.size());
            NEXT_ALLOC = heap_pos;
            write_watermark(heap_pos);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.alloc(layout) }
    }

    /// Never deallocate.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

unsafe extern "C" {
    /// The address of this variable is the start of the heap (growing upwards).
    ///
    /// It is defined in the linker script.
    static mut _sheap: u8;
}

#[inline(always)]
unsafe fn write_watermark(ptr: *mut u8) {
    WATERMARK_SLOT.write(ptr as u32);
}

#[inline(always)]
unsafe fn ensure_initialized() {
    if NEXT_ALLOC.is_null() {
        HEAP_START = addr_of_mut!(_sheap);
        WATERMARK_SLOT = HEAP_START.cast::<u32>();
        NEXT_ALLOC = HEAP_START.add(mem::size_of::<u32>());
        write_watermark(NEXT_ALLOC);
    }
}

#[global_allocator]
static HEAP: SimpleAllocator = SimpleAllocator;
