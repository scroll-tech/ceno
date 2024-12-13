use crate::{INFO_OUT_ADDR, WORD_SIZE};
use core::{cell::Cell, fmt, mem::size_of, slice};

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

    // TODO docs on why design mut_from_ref
    // or justify this convention by citing from other place
    #[allow(clippy::mut_from_ref)]
    pub fn alloc<T>(&self, count: usize) -> &mut [T] {
        let byte_len = count * size_of::<T>();
        let word_len = byte_len.div_ceil(WORD_SIZE);
        let cursor = self.cursor.get();

        // Bump the cursor to the next word-aligned address.
        self.cursor.set(unsafe { cursor.add(word_len) });

        // Return a slice of the allocated memory.
        unsafe { slice::from_raw_parts_mut(cursor as *mut T, count) }
    }

    pub fn write(&self, msg: &[u8]) {
        let buf = self.alloc(msg.len());
        buf.copy_from_slice(msg);
    }

    pub fn write_frame(&self, msg: &[u8]) {
        let word_len = msg.len().div_ceil(WORD_SIZE);
        let words: &mut [u32] = self.alloc(1 + word_len);
        words[0] = msg.len() as u32;
        let bytes =
            unsafe { slice::from_raw_parts_mut(words[1..].as_mut_ptr() as *mut u8, msg.len()) };
        bytes.copy_from_slice(msg);
    }
}

impl fmt::Write for &IOWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_frame(s.as_bytes());
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
