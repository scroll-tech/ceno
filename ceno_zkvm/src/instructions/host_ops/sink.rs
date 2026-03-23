use ceno_emul::WordAddr;
use std::marker::PhantomData;

use crate::{e2e::ShardContext, witness::LkMultiplicity};

use super::{LkOp, SendEvent};

pub trait SideEffectSink {
    fn emit_lk(&mut self, op: LkOp);
    fn emit_send(&mut self, event: SendEvent);
    fn touch_addr(&mut self, addr: WordAddr);
}

pub struct CpuSideEffectSink<'ctx, 'shard, 'lk> {
    shard_ctx: *mut ShardContext<'shard>,
    lk: &'lk mut LkMultiplicity,
    _marker: PhantomData<&'ctx mut ShardContext<'shard>>,
}

impl<'ctx, 'shard, 'lk> CpuSideEffectSink<'ctx, 'shard, 'lk> {
    pub unsafe fn from_raw(
        shard_ctx: *mut ShardContext<'shard>,
        lk: &'lk mut LkMultiplicity,
    ) -> Self {
        Self {
            shard_ctx,
            lk,
            _marker: PhantomData,
        }
    }

    fn shard_ctx(&mut self) -> &mut ShardContext<'shard> {
        // Safety: `from_raw` is only constructed from a live `&mut ShardContext`
        // for the duration of side-effect collection.
        unsafe { &mut *self.shard_ctx }
    }
}

/// Create a `CpuSideEffectSink` and an immutable view of `ShardContext`,
/// then pass both to the closure `f`.
///
/// This encapsulates the raw-pointer trick needed to hold `&mut ShardContext`
/// (inside the sink, for writes) and `&ShardContext` (for reads like
/// `aligned_prev_ts`) simultaneously.
///
/// # Safety
/// Safe to call — the unsafety is internal and bounded by the closure lifetime.
pub fn with_cpu_sink<'a, R>(
    shard_ctx: &'a mut ShardContext<'a>,
    lk: &'a mut LkMultiplicity,
    f: impl FnOnce(&mut CpuSideEffectSink<'a, 'a, 'a>, &ShardContext) -> R,
) -> R {
    let ptr = shard_ctx as *mut ShardContext;
    let view = unsafe { &*ptr };
    let mut sink = unsafe { CpuSideEffectSink::from_raw(ptr, lk) };
    f(&mut sink, view)
}

impl SideEffectSink for CpuSideEffectSink<'_, '_, '_> {
    fn emit_lk(&mut self, op: LkOp) {
        for (table, key) in op.encode_all() {
            self.lk.increment(table, key);
        }
    }

    fn emit_send(&mut self, event: SendEvent) {
        self.shard_ctx().record_send_without_touch(
            event.ram_type,
            event.addr,
            event.id,
            event.cycle,
            event.prev_cycle,
            event.value,
            event.prev_value,
        );
    }

    fn touch_addr(&mut self, addr: WordAddr) {
        self.shard_ctx().push_addr_accessed(addr);
    }
}
