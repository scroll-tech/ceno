use ceno_emul::{Cycle, StepRecord, Word, WriteOp};
use ff_ext::{ExtensionField, FieldInto, SmallField};
use itertools::Itertools;
use p3::field::{Field, FieldAlgebra};

use super::constants::{BIT_WIDTH, PC_STEP_SIZE, UINT_LIMBS, UInt};
use crate::{
    chip_handler::{
        AddressExpr, GlobalStateRegisterMachineChipOperations, MemoryChipOperations, MemoryExpr,
        RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    structs::RAMType,
    uint::Value,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::FullTracer as Tracer;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use std::{iter, marker::PhantomData};

#[derive(Debug)]
pub struct StateInOut<E: ExtensionField> {
    pub pc: WitIn,
    pub next_pc: Option<WitIn>,
    pub ts: WitIn,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> StateInOut<E> {
    /// If circuit is branching, leave witness for next_pc free and return in
    /// configuration so that calling circuit can constrain its value.
    /// Otherwise, internally increment by PC_STEP_SIZE
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        branching: bool,
    ) -> Result<Self, ZKVMError> {
        let pc = circuit_builder.create_witin(|| "pc");
        let (next_pc_opt, next_pc_expr) = if branching {
            let next_pc = circuit_builder.create_witin(|| "next_pc");
            (Some(next_pc), next_pc.expr())
        } else {
            (None, pc.expr() + PC_STEP_SIZE)
        };
        let ts = circuit_builder.create_witin(|| "ts");
        let next_ts = ts.expr() + Tracer::SUBCYCLES_PER_INSN;
        circuit_builder.state_in(pc.expr(), ts.expr())?;
        circuit_builder.state_out(next_pc_expr, next_ts)?;

        Ok(StateInOut {
            pc,
            next_pc: next_pc_opt,
            ts,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &ShardContext,
        // lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();

        set_val!(instance, self.pc, step.pc().before.0 as u64);
        if let Some(n_pc) = self.next_pc {
            set_val!(instance, n_pc, step.pc().after.0 as u64);
        }
        set_val!(instance, self.ts, step.cycle() - current_shard_offset_cycle);

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS1<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLtConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS1<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs1_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs1_id");
        let prev_ts = circuit_builder.create_witin(|| "prev_rs1_ts");
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs1",
            id,
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_RS1,
            rs1_read,
        )?;

        Ok(ReadRS1 {
            id,
            prev_ts,
            lt_cfg,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let op = step.rs1().expect("rs1 op");
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = step.cycle() - current_shard_offset_cycle;
        set_val!(instance, self.id, op.register_index() as u64);
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_RS1,
        )?;
        shard_ctx.send(
            RAMType::Register,
            op.addr,
            op.register_index() as u64,
            step.cycle() + Tracer::SUBCYCLE_RS1,
            op.previous_cycle,
            op.value,
            None,
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS2<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLtConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS2<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs2_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs2_id");
        let prev_ts = circuit_builder.create_witin(|| "prev_rs2_ts");
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs2",
            id,
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_RS2,
            rs2_read,
        )?;

        Ok(ReadRS2 {
            id,
            prev_ts,
            lt_cfg,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let op = step.rs2().expect("rs2 op");
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = step.cycle() - current_shard_offset_cycle;
        set_val!(instance, self.id, op.register_index() as u64);
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_RS2,
        )?;

        shard_ctx.send(
            RAMType::Register,
            op.addr,
            op.register_index() as u64,
            step.cycle() + Tracer::SUBCYCLE_RS2,
            op.previous_cycle,
            op.value,
            None,
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteRD<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub prev_value: UInt<E>,
    pub lt_cfg: AssertLtConfig,
}

impl<E: ExtensionField> WriteRD<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rd_written: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rd_id");
        let prev_ts = circuit_builder.create_witin(|| "prev_rd_ts");
        let prev_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;
        let (_, lt_cfg) = circuit_builder.register_write(
            || "write_rd",
            id,
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_RD,
            prev_value.register_expr(),
            rd_written,
        )?;

        Ok(WriteRD {
            id,
            prev_ts,
            prev_value,
            lt_cfg,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let op = step.rd().expect("rd op");
        self.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), &op)
    }

    pub fn assign_op(
        &self,
        instance: &mut [E::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        cycle: Cycle,
        op: &WriteOp,
    ) -> Result<(), ZKVMError> {
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = cycle - current_shard_offset_cycle;
        set_val!(instance, self.id, op.register_index() as u64);
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        // Register state
        self.prev_value.assign_limbs(
            instance,
            Value::new_unchecked(op.value.before).as_u16_limbs(),
        );

        // Register write
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_RD,
        )?;
        shard_ctx.send(
            RAMType::Register,
            op.addr,
            op.register_index() as u64,
            cycle + Tracer::SUBCYCLE_RD,
            op.previous_cycle,
            op.value.after,
            Some(op.value.before),
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadMEM<E: ExtensionField> {
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLtConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadMEM<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        mem_addr: AddressExpr<E>,
        mem_read: MemoryExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_ts");
        let (_, lt_cfg) = circuit_builder.memory_read(
            || "read_memory",
            &mem_addr,
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_MEM,
            mem_read,
        )?;

        Ok(ReadMEM {
            prev_ts,
            lt_cfg,
            _field_type: PhantomData,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let op = step.memory_op().unwrap();
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = step.cycle() - current_shard_offset_cycle;
        // Memory state
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        // Memory read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_MEM,
        )?;

        shard_ctx.send(
            RAMType::Memory,
            op.addr,
            op.addr.baddr().0 as u64,
            step.cycle() + Tracer::SUBCYCLE_MEM,
            op.previous_cycle,
            op.value.after,
            None,
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteMEM {
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLtConfig,
}

impl WriteMEM {
    pub fn construct_circuit<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        mem_addr: AddressExpr<E>,
        prev_value: MemoryExpr<E>,
        new_value: MemoryExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_ts");

        let (_, lt_cfg) = circuit_builder.memory_write(
            || "write_memory",
            &mem_addr,
            prev_ts.expr(),
            cur_ts.expr() + Tracer::SUBCYCLE_MEM,
            prev_value,
            new_value,
        )?;

        Ok(WriteMEM { prev_ts, lt_cfg })
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let op = step.memory_op().unwrap();
        self.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), &op)
    }

    pub fn assign_op<F: SmallField>(
        &self,
        instance: &mut [F],
        shard_ctx: &mut ShardContext,
        lk_multiplicity: &mut LkMultiplicity,
        cycle: Cycle,
        op: &WriteOp,
    ) -> Result<(), ZKVMError> {
        let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let shard_cycle = cycle - current_shard_offset_cycle;
        set_val!(instance, self.prev_ts, shard_prev_cycle);

        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            shard_prev_cycle,
            shard_cycle + Tracer::SUBCYCLE_MEM,
        )?;

        shard_ctx.send(
            RAMType::Memory,
            op.addr,
            op.addr.baddr().0 as u64,
            cycle + Tracer::SUBCYCLE_MEM,
            op.previous_cycle,
            op.value.after,
            Some(op.value.before),
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct MemAddr<E: ExtensionField> {
    addr: UInt<E>,
    low_bits: Vec<WitIn>,
    max_bits: usize,
}

impl<E: ExtensionField> MemAddr<E> {
    const N_LOW_BITS: usize = 2;

    /// An address which is range-checked, and not aligned. Bits 0 and 1 are variables.
    pub fn construct_unaligned(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        Self::construct(cb, 0)
    }

    /// An address which is range-checked, and aligned to 2 bytes. Bit 0 is constant 0. Bit 1 is variable.
    pub fn construct_align2(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        Self::construct(cb, 1)
    }

    /// An address which is range-checked, and aligned to 4 bytes. Bits 0 and 1 are constant 0.
    pub fn construct_align4(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        Self::construct(cb, 2)
    }

    /// Represent the address as an expression.
    pub fn expr_unaligned(&self) -> AddressExpr<E> {
        self.addr.address_expr()
    }

    pub fn uint_unaligned(&self) -> UInt<E> {
        UInt::from_exprs_unchecked(self.addr.expr())
    }

    pub fn uint_align2(&self) -> UInt<E> {
        UInt::from_exprs_unchecked(vec![
            self.addr.limbs[0].expr() - &self.low_bit_exprs()[0],
            self.addr.limbs[1].expr(),
        ])
    }

    /// Represent the address aligned to 2 bytes.
    pub fn expr_align2(&self) -> AddressExpr<E> {
        self.addr.address_expr() - &self.low_bit_exprs()[0]
    }

    /// Represent the address aligned to 4 bytes.
    pub fn expr_align4(&self) -> AddressExpr<E> {
        let low_bits = self.low_bit_exprs();
        self.addr.address_expr() - &low_bits[1] * 2 - &low_bits[0]
    }

    pub fn uint_align4(&self) -> UInt<E> {
        let low_bits = self.low_bit_exprs();
        UInt::from_exprs_unchecked(vec![
            self.addr.limbs[0].expr() - &low_bits[1] * 2 - &low_bits[0],
            self.addr.limbs[1].expr(),
        ])
    }

    /// Expressions of the low bits of the address, LSB-first: [bit_0, bit_1].
    pub fn low_bit_exprs(&self) -> Vec<Expression<E>> {
        iter::repeat_n(Expression::ZERO, self.n_zeros())
            .chain(self.low_bits.iter().map(ToExpr::expr))
            .collect()
    }

    fn construct(cb: &mut CircuitBuilder<E>, n_zeros: usize) -> Result<Self, ZKVMError> {
        Self::construct_with_max_bits(cb, n_zeros, BIT_WIDTH)
    }

    pub fn construct_with_max_bits(
        cb: &mut CircuitBuilder<E>,
        n_zeros: usize,
        max_bits: usize,
    ) -> Result<Self, ZKVMError> {
        assert!(n_zeros <= Self::N_LOW_BITS);

        // The address as two u16 limbs.
        // Soundness: This does not use the UInt range-check but specialized checks instead.
        let addr = UInt::new_unchecked(|| "memory_addr", cb)?;
        let limbs = addr.expr();

        // Witness and constrain the non-zero low bits.
        let low_bits = (n_zeros..Self::N_LOW_BITS)
            .map(|i| {
                let bit = cb.create_witin(|| format!("addr_bit_{}", i));
                cb.assert_bit(|| format!("addr_bit_{}", i), bit.expr())?;
                Ok(bit)
            })
            .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

        // Express the value of the low bits.
        let low_sum: Expression<E> = (n_zeros..Self::N_LOW_BITS)
            .zip_eq(low_bits.iter())
            .map(|(pos, bit)| bit.expr() << pos)
            .sum();

        // Range check the middle bits, that is the low limb excluding the low bits.
        let shift_right = E::BaseField::from_canonical_u64(1 << Self::N_LOW_BITS)
            .inverse()
            .expr();
        let mid_u14 = (&limbs[0] - low_sum) * shift_right;
        cb.assert_ux::<_, _, 14>(|| "mid_u14", mid_u14)?;

        // Range check the high limb.
        for (i, high_limb) in limbs.iter().enumerate().skip(1) {
            cb.assert_const_range(
                || "high_limb",
                high_limb.clone(),
                (max_bits - i * 16).min(16),
            )?;
        }

        Ok(MemAddr {
            addr,
            low_bits,
            max_bits,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        lkm: &mut LkMultiplicity,
        addr: Word,
    ) -> Result<(), ZKVMError> {
        self.addr.assign_value(instance, Value::new_unchecked(addr));

        // Witness the non-zero low bits.
        for (pos, bit) in (self.n_zeros()..Self::N_LOW_BITS).zip_eq(&self.low_bits) {
            let b = (addr >> pos) & 1;
            set_val!(instance, bit, b as u64);
        }

        // Range check the low limb besides the low bits.
        let mid_u14 = (addr & 0xffff) >> Self::N_LOW_BITS;
        lkm.assert_ux::<14>(mid_u14 as u64);

        // Range check the high limb.
        for i in 1..UINT_LIMBS {
            let high_u16 = (addr >> (i * 16)) & 0xffff;
            lkm.assert_const_range(high_u16 as u64, (self.max_bits - i * 16).min(16));
        }

        Ok(())
    }

    fn n_zeros(&self) -> usize {
        Self::N_LOW_BITS - self.low_bits.len()
    }
}

#[cfg(test)]
mod test {
    use ff_ext::GoldilocksExt2 as E;
    use itertools::Itertools;
    use p3::goldilocks::Goldilocks as F;
    use std::collections::HashSet;
    use witness::{InstancePaddingStrategy, RowMajorMatrix};

    use crate::{
        ROMType,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        error::ZKVMError,
        scheme::mock_prover::MockProver,
        witness::LkMultiplicity,
    };

    use super::MemAddr;

    #[test]
    fn test_mem_addr() -> Result<(), ZKVMError> {
        let aligned_1 = 0xbeadbeef;
        let aligned_2 = 0xbeadbeee;
        let aligned_4 = 0xbeadbeec;

        impl_test_mem_addr(1, aligned_1, true)?;
        impl_test_mem_addr(1, aligned_2, true)?;
        impl_test_mem_addr(1, aligned_4, true)?;

        impl_test_mem_addr(2, aligned_1, false)?;
        impl_test_mem_addr(2, aligned_2, true)?;
        impl_test_mem_addr(2, aligned_4, true)?;

        impl_test_mem_addr(4, aligned_1, false)?;
        impl_test_mem_addr(4, aligned_2, false)?;
        impl_test_mem_addr(4, aligned_4, true)?;
        Ok(())
    }

    fn impl_test_mem_addr(align: u32, addr: u32, is_ok: bool) -> Result<(), ZKVMError> {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let mem_addr = match align {
            1 => MemAddr::construct_unaligned(&mut cb)?,
            2 => MemAddr::construct_align2(&mut cb)?,
            4 => MemAddr::construct_align4(&mut cb)?,
            _ => unreachable!(),
        };

        let mut lkm = LkMultiplicity::default();
        let num_rows = 2;
        let mut raw_witin = RowMajorMatrix::<F>::new(
            num_rows,
            cb.cs.num_witin as usize,
            InstancePaddingStrategy::Default,
        );
        for instance in raw_witin.iter_mut() {
            mem_addr.assign_instance(instance, &mut lkm, addr)?;
        }

        // Check the range lookups.
        let lkm = lkm.into_finalize_result();
        let expected = vec![
            // 14 bits range
            ((1u64 << 14) + (0xbeef >> 2), num_rows),
            // 16 bits range
            ((1 << 16) + 0xbead, num_rows),
        ]
        .into_iter()
        .collect::<HashSet<(u64, usize)>>();

        let result = lkm[ROMType::Dynamic as usize]
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<HashSet<(u64, usize)>>();
        assert_eq!(expected, result);
        assert_eq!(lkm[ROMType::Dynamic as usize].len(), 2);

        if is_ok {
            cb.require_equal(|| "", mem_addr.expr_unaligned(), addr.into())?;
            cb.require_equal(|| "", mem_addr.expr_align2(), (addr & !1).into())?;
            cb.require_equal(|| "", mem_addr.expr_align4(), (addr & !3).into())?;
        }
        MockProver::assert_with_expected_errors(
            &cb,
            &[],
            &raw_witin
                .to_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            &[],
            &[],
            if is_ok { &[] } else { &["mid_u14"] },
            None,
            None,
        );
        Ok(())
    }
}
