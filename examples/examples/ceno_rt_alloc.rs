use core::ptr::{addr_of, read_volatile};

extern crate ceno_rt;

extern crate alloc;
use alloc::{vec, vec::Vec};

static mut OUTPUT: u32 = 0;

fn main() {
    // Test writing to a global variable.
    unsafe {
        OUTPUT = 0xf00d;
        black_box(addr_of!(OUTPUT));
    }

    // Test writing to the heap.
    let v: Vec<u32> = vec![0xbeef];
    black_box(&v[0]);

    // Test writing to a larger vector on the heap
    let mut v: Vec<u32> = vec![0; 128 * 1024];
    ceno_syscall::syscall_phantom_log_pc_cycle("finish allocation");
    v[999] = 0xdead_beef;
    black_box(&v[0]);

    ceno_syscall::syscall_phantom_log_pc_cycle("start fibonacci");
    let log_n: u32 = 12;
    let mut a = 0_u32;
    let mut b = 1_u32;
    let n = 1 << log_n;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }
    ceno_syscall::syscall_phantom_log_pc_cycle("end fibonacci");

    // write to heap which allocated earlier shard
    v[999] = 0xbeef_dead;
    let mut v: Vec<u32> = vec![0; 128 * 1024];
    // write to heap allocate in current non-first shard
    v[0] = 0xdead_beef;
}

/// Prevent compiler optimizations.
fn black_box<T>(x: *const T) -> T {
    unsafe { read_volatile(x) }
}
