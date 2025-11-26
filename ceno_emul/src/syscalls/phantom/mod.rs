use crate::{
    Change, EmuContext, Platform, SyscallSpec, VMState, WordAddr, WriteOp,
    syscalls::{SyscallEffects, SyscallWitness},
};
use itertools::Itertools;

pub struct LogPcCycleSpec;
impl SyscallSpec for LogPcCycleSpec {
    const NAME: &'static str = "LOG_PC_CYCLE";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 0;
    const CODE: u32 = ceno_syscall::PHANTOM_LOG_PC_CYCLE;
}

pub fn log_pc_cycle(vm: &VMState) -> SyscallEffects {
    let lable_ptr = vm.peek_register(Platform::reg_arg0());
    let lable_len = vm.peek_register(Platform::reg_arg1());

    // Read the argument `state_ptr`.
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(lable_ptr, lable_ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(lable_len, lable_len),
            0, // Cycle set later in finalize().
        ),
    ];

    let start = lable_ptr;
    let raw_string_u8: Vec<u8> = (start..start + lable_len)
        .map(|addr| {
            let byte_offset = addr % 4;
            let word = vm.peek_memory(WordAddr::from(addr));
            ((word >> (byte_offset * 8)) & 0xFF) as u8
        })
        .collect_vec();
    tracing::debug!(
        "PHANTOM_SYSCALL_LOG_PC_CYCLE: label={},pc={:x},cycle={}",
        String::from_utf8_lossy(&raw_string_u8),
        vm.get_pc().0,
        vm.tracer().cycle()
    );

    SyscallEffects {
        witness: SyscallWitness::new(vec![], reg_ops),
        next_pc: None,
    }
}
