use crate::{INFO_OUT_ADDR, WORD_SIZE};
use core::{cell::Cell, fmt, mem::size_of, ptr::write_volatile, slice};

static INFO_OUT: IOWriter = IOWriter::new(INFO_OUT_ADDR);

pub fn info_out() -> &'static IOWriter {
    &INFO_OUT
}

pub struct IOWriter {
    cursor: Cell<*mut u32>,
}

// Safety: Only single-threaded programs are supported.
// TODO: There may be a better way to handle this.
unsafe impl Sync for IOWriter {}

impl IOWriter {
    const fn new(addr: u32) -> Self {
        assert!(addr % WORD_SIZE as u32 == 0);
        IOWriter {
            cursor: Cell::new(addr as *mut u32),
        }
    }

    pub fn alloc<T>(&self, count: usize) -> &mut [T] {
        let byte_len = count * size_of::<T>();
        let cursor = self.cursor.get();

        // Write the length of the message at the current cursor.
        unsafe {
            write_volatile(cursor, byte_len as u32);
        }

        // Bump the cursor to the next word-aligned address.
        self.cursor
            .set(unsafe { cursor.add(1 + byte_len.div_ceil(WORD_SIZE)) });

        // Return a slice of the allocated memory after the length word.
        unsafe { slice::from_raw_parts_mut(cursor.add(1) as *mut T, count) }
    }

    pub fn write(&self, msg: &[u8]) {
        let buf = self.alloc(msg.len());
        buf.copy_from_slice(msg);
    }
}

impl fmt::Write for &IOWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

mod macros {
    #[macro_export]
    macro_rules! print {
        ($($arg:tt)*) => {
            let _ = core::write!($crate::info_out(), $($arg)*);
        };
    }

    #[macro_export]
    macro_rules! println {
        ($($arg:tt)*) => {
            let _ = core::writeln!($crate::info_out(), $($arg)*);
        };
    }
}
