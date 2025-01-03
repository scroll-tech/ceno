use std::collections::BTreeSet;

use gdbstub::{
    arch::{Arch, BreakpointKind},
    common::Signal,
    target::{
        Target,
        TargetError::NonFatal,
        TargetResult,
        ext::{
            base::{
                BaseOps,
                single_register_access::{SingleRegisterAccess, SingleRegisterAccessOps},
                singlethread::{
                    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps,
                    SingleThreadSingleStep, SingleThreadSingleStepOps,
                },
            },
            breakpoints::{
                Breakpoints, BreakpointsOps, HwBreakpointOps, SwBreakpoint, SwBreakpointOps,
            },
        },
    },
};
use gdbstub_arch::riscv::{Riscv32, reg::id::RiscvRegId};
use itertools::{Itertools, enumerate};

use crate::{ByteAddr, EmuContext, RegIdx, VMState, WordAddr};

// This should probably reference / or be VMState?
pub struct MyTarget {
    state: VMState,
    break_points: BTreeSet<(u32, <Riscv32 as Arch>::BreakpointKind)>,
}

impl Target for MyTarget {
    type Error = anyhow::Error;
    type Arch = gdbstub_arch::riscv::Riscv32;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    // opt-in to support for setting/removing breakpoints
    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }
}

// TODO: add SingleRegisterAccess
impl SingleRegisterAccess<()> for MyTarget {
    fn read_register(
        &mut self,
        _thread_id: (),
        reg_id: <Riscv32 as Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        match reg_id {
            RiscvRegId::Gpr(i) if (0..32).contains(&i) => {
                buf.copy_from_slice(&self.state.peek_register(RegIdx::from(i)).to_le_bytes());
                Ok(4)
            }
            RiscvRegId::Pc => {
                buf.copy_from_slice(&self.state.get_pc().0.to_le_bytes());
                Ok(4)
            }
            // TODO(Matthias): see whether we can make this more specific.
            _ => Err(NonFatal),
        }
    }

    fn write_register(
        &mut self,
        _thread_id: (),
        reg_id: <Riscv32 as Arch>::RegId,
        value: &[u8],
    ) -> TargetResult<(), Self> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(value);
        let buf = u32::from_le_bytes(bytes);
        match reg_id {
            // Note: we refuse to write to register 0.
            RiscvRegId::Gpr(i) if (1..32).contains(&i) => {
                self.state.init_register_unsafe(RegIdx::from(i), buf)
            }
            RiscvRegId::Pc => self.state.set_pc(ByteAddr(buf)),
            // TODO(Matthias): see whether we can make this more specific.
            _ => return Err(NonFatal),
        }
        Ok(())
    }
}

impl SingleThreadBase for MyTarget {
    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }

    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        for (i, reg) in enumerate(&mut regs.x) {
            *reg = self.state.peek_register(i);
        }
        regs.pc = u32::from(self.state.get_pc());
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        for (i, reg) in enumerate(&regs.x) {
            self.state.init_register_unsafe(i, *reg);
        }
        self.state.set_pc(ByteAddr::from(regs.pc));
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<usize, Self> {
        // TODO: deal with misaligned accesses
        if !start_addr.is_multiple_of(4) {
            return Err(NonFatal);
        }
        if !data.len().is_multiple_of(4) {
            return Err(NonFatal);
        }
        let start_addr = WordAddr::from(ByteAddr(start_addr));

        for (i, chunk) in enumerate(data.chunks_exact_mut(4)) {
            let addr = start_addr + i * 4;
            let word = self.state.peek_memory(addr);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(data.len())
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        // TODO: deal with misaligned accesses
        if !start_addr.is_multiple_of(4) {
            return Err(NonFatal);
        }
        if !data.len().is_multiple_of(4) {
            return Err(NonFatal);
        }
        let start_addr = WordAddr::from(ByteAddr(start_addr));
        for (i, chunk) in enumerate(data.chunks_exact(4)) {
            self.state.init_memory(
                start_addr + i * 4,
                u32::from_le_bytes(chunk.try_into().unwrap()),
            );
        }
        Ok(())
    }

    // most targets will want to support at resumption as well...

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

// TODO(Matthias): also support reverse stepping.
impl SingleThreadResume for MyTarget {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        // We need to step until the next breakpoint?
        todo!()
    }

    // ...and if the target supports resumption, it'll likely want to support
    // single-step resume as well

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for MyTarget {
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        // We might want to step with something higher level than rv32im::step, so we can go backwards in time?
        crate::rv32im::step(&mut self.state)?;
        Ok(())
    }
}

// TODO: consider adding WatchKind, and perhaps hardware breakpoints?
impl Breakpoints for MyTarget {
    // there are several kinds of breakpoints - this target uses software breakpoints
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        Some(self)
    }
}

impl SwBreakpoint for MyTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: u32,
        kind: <Riscv32 as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        todo!()
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u32,
        kind: <Riscv32 as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        todo!()
    }
}
