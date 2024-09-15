// Based on: https://github.com/risc0/risc0/blob/aeea62f0c8f4223abfba17d4c78cb7e15c513de2/risc0/circuit/rv32im/src/prove/emu/addr.rs
//
// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{fmt, ops};

pub const WORD_SIZE: usize = 4;
pub const PC_STEP_SIZE: usize = 4;

// Type aliases to clarify the code without wrapper types.
pub type Word = u32;
pub type Addr = u32;
pub type Cycle = u64;
pub type RegIdx = usize;

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ByteAddr(pub u32);

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct WordAddr(u32);

impl From<ByteAddr> for WordAddr {
    fn from(addr: ByteAddr) -> Self {
        addr.waddr()
    }
}

impl From<WordAddr> for ByteAddr {
    fn from(addr: WordAddr) -> Self {
        addr.baddr()
    }
}

impl From<u32> for ByteAddr {
    fn from(addr: u32) -> ByteAddr {
        ByteAddr(addr)
    }
}

impl From<u32> for WordAddr {
    fn from(addr: u32) -> WordAddr {
        ByteAddr(addr).waddr()
    }
}

impl From<ByteAddr> for u32 {
    fn from(addr: ByteAddr) -> Self {
        addr.0
    }
}

impl From<WordAddr> for u32 {
    fn from(addr: WordAddr) -> Self {
        addr.baddr().0
    }
}

impl ByteAddr {
    pub const fn waddr(self) -> WordAddr {
        WordAddr(self.0 / WORD_SIZE as u32)
    }

    pub const fn is_aligned(&self) -> bool {
        self.0 % WORD_SIZE as u32 == 0
    }

    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl WordAddr {
    pub const fn baddr(self) -> ByteAddr {
        ByteAddr(self.0 * WORD_SIZE as u32)
    }
}

impl fmt::Debug for ByteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl fmt::Debug for WordAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.baddr().0)
    }
}

impl ops::Add for WordAddr {
    type Output = WordAddr;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl ops::Add<usize> for WordAddr {
    type Output = WordAddr;

    fn add(self, rhs: usize) -> Self::Output {
        Self(self.0 + rhs as u32)
    }
}

impl ops::Add<u32> for WordAddr {
    type Output = WordAddr;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl ops::AddAssign<usize> for WordAddr {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u32;
    }
}

impl ops::AddAssign<u32> for WordAddr {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

impl ops::Add for ByteAddr {
    type Output = ByteAddr;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl ops::Add<usize> for ByteAddr {
    type Output = ByteAddr;

    fn add(self, rhs: usize) -> Self::Output {
        Self(self.0 + rhs as u32)
    }
}

impl ops::Add<u32> for ByteAddr {
    type Output = ByteAddr;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl ops::AddAssign for ByteAddr {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl ops::AddAssign<usize> for ByteAddr {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u32;
    }
}

impl ops::AddAssign<u32> for ByteAddr {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}
