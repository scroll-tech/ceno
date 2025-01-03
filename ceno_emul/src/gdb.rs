use gdbstub::{
    arch::{Arch, BreakpointKind},
    common::Signal,
    target::{
        Target, TargetResult,
        ext::{
            base::{
                BaseOps,
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
use gdbstub_arch::riscv::Riscv32;
use itertools::enumerate;

use crate::{ByteAddr, EmuContext, VMState};

// This should probably reference / or be VMState?
pub struct MyTarget(VMState);

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

impl SingleThreadBase for MyTarget {
    fn read_registers(
        &mut self,
        // regs: &mut gdbstub_arch::arm::reg::ArmCoreRegs,
        regs: &mut gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        for (i, reg) in enumerate(&mut regs.x) {
            *reg = self.0.peek_register(i);
        }
        regs.pc = u32::from(self.0.get_pc());
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        for (i, reg) in enumerate(&regs.x) {
            self.0.init_register_unsafe(i, *reg);
        }
        self.0.set_pc(ByteAddr::from(regs.pc));
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<usize, Self> {
        todo!()
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        todo!()
    }

    // most targets will want to support at resumption as well...

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl SingleThreadResume for MyTarget {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
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
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        todo!()
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
