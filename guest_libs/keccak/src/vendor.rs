//! Private types and traits copied from the `tiny-keccak`.

use ceno_rt::syscalls::KECCAK_STATE_WORDS;

pub mod keccak;

#[derive(Default, Clone)]
pub struct Buffer([u64; KECCAK_STATE_WORDS]);

impl Buffer {
    pub fn words(&mut self) -> &mut [u64; KECCAK_STATE_WORDS] {
        &mut self.0
    }

    #[inline]
    pub fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        // # Safety: little-endian target
        let buffer: &mut [u8; KECCAK_STATE_WORDS * 8] =
            unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
    }

    pub fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    pub fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    pub fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

pub trait Permutation {
    fn execute(a: &mut Buffer);
}

#[derive(Clone, Copy)]
pub enum Mode {
    Absorbing,
    Squeezing,
}

pub struct KeccakState<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    mode: Mode,
    permutation: core::marker::PhantomData<P>,
}

impl<P> Clone for KeccakState<P> {
    fn clone(&self) -> Self {
        KeccakState {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            mode: self.mode,
            permutation: core::marker::PhantomData,
        }
    }
}

impl<P: Permutation> KeccakState<P> {
    fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccak(&mut self) {
        P::execute(&mut self.buffer);
    }

    fn update(&mut self, input: &[u8]) {
        if let Mode::Squeezing = self.mode {
            self.mode = Mode::Absorbing;
            self.fill_block();
        }

        // first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccak();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        if let Mode::Absorbing = self.mode {
            self.mode = Mode::Squeezing;
            self.pad();
            self.fill_block();
        }

        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.setout(&mut output[op..], offset, rate);
            self.keccak();
            op += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }

    fn finalize(mut self, output: &mut [u8]) {
        self.squeeze(output);
    }

    fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }
}

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}
