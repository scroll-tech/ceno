use crate::{Change, EmuContext, Platform, Tracer, VMState, WriteOp, utils::MemoryView};

use super::{PubIoCommitSpec, SyscallEffects, SyscallSpec, SyscallWitness};

const PUBIO_COMMIT_WORDS: usize = 8;

/// Trace the PUB_IO_COMMIT syscall by reading 8 digest words from guest memory.
pub fn pubio_commit<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let digest_ptr = vm.peek_register(Platform::reg_arg0());

    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(digest_ptr, digest_ptr),
        0,
    )];

    let digest_view = MemoryView::<_, PUBIO_COMMIT_WORDS>::new(vm, digest_ptr);
    let mem_ops = digest_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), PubIoCommitSpec::MEM_OPS_COUNT);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
