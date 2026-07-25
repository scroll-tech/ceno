extern crate ceno_rt;

const BUFFER_LEN: usize = 640;
const GUARD: u8 = 0xa5;

unsafe extern "C" {
    fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8;
}

fn main() {
    const LENGTHS: &[usize] = &[
        0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 511,
    ];

    for src_align in 0..4 {
        for dst_align in 0..4 {
            for &len in LENGTHS {
                check_copy(src_align, dst_align, len);
            }
        }
    }
}

#[inline(never)]
fn check_copy(src_align: usize, dst_align: usize, len: usize) {
    let src_start = 16 + src_align;
    let dst_start = 16 + dst_align;
    let mut src = [0u8; BUFFER_LEN];
    let mut dst = [GUARD; BUFFER_LEN];

    for (i, byte) in src.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(73).wrapping_add(19);
    }
    let original_src = src;

    let returned = unsafe {
        memcpy(
            dst.as_mut_ptr().add(dst_start),
            src.as_ptr().add(src_start),
            len,
        )
    };

    assert_eq!(returned, unsafe { dst.as_mut_ptr().add(dst_start) });
    assert_eq!(src, original_src);
    assert!(dst[..dst_start].iter().all(|&byte| byte == GUARD));
    assert_eq!(
        &dst[dst_start..dst_start + len],
        &src[src_start..src_start + len]
    );
    assert!(dst[dst_start + len..].iter().all(|&byte| byte == GUARD));
}
