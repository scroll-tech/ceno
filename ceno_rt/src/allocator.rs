#[no_mangle]
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::borrow_as_ptr)]
pub extern "C" fn alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    // Pointer to next heap address to use, or 0 if the heap has not been
    // initialized.
    static mut HEAP_POS: usize = 0;

    // SAFETY: Single threaded, so nothing else can touch this while we're working.
    let mut heap_pos = unsafe { HEAP_POS };

    if heap_pos == 0 {
        heap_pos = unsafe { core::ptr::from_ref::<u8>(&crate::_sheap).cast::<u8>() as usize };
    }

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos += align - offset;
    }

    let ptr = heap_pos as *mut u8;
    heap_pos += bytes;

    unsafe { HEAP_POS = heap_pos };
    ptr
}

use core::alloc::{GlobalAlloc, Layout};

struct BumpPointerAlloc;

unsafe impl GlobalAlloc for BumpPointerAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc_aligned(layout.size(), layout.align())
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 { self.alloc(layout) }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        // BumpPointerAlloc never deallocates memory
    }
}

#[global_allocator]
static HEAP: BumpPointerAlloc = BumpPointerAlloc;
