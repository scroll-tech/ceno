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
            breakpoints::{Breakpoints, BreakpointsOps, SwBreakpoint, SwBreakpointOps},
        },
    },
};
use gdbstub_arch::riscv::Riscv32;

pub struct MyTarget;

impl Target for MyTarget {
    type Error = ();
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
        todo!()
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        todo!()
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
