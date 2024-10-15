use ceno_emul::{StepRecord, Word};
use ff_ext::ExtensionField;

use super::constants::{PC_STEP_SIZE, UINT_LIMBS, UInt};
use crate::{
    chip_handler::{
        GlobalStateRegisterMachineChipOperations, MemoryChipOperations, MemoryExpr,
        RegisterChipOperations, RegisterExpr,
    },
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::AssertLTConfig,
    set_val,
    uint::Value,
    witness::LkMultiplicity,
};
use ceno_emul::Tracer;
use core::mem::MaybeUninit;
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
        let pc = circuit_builder.create_witin(|| "pc")?;
        let (next_pc_opt, next_pc_expr) = if branching {
            let next_pc = circuit_builder.create_witin(|| "next_pc")?;
            (Some(next_pc), next_pc.expr())
        } else {
            (None, pc.expr() + PC_STEP_SIZE.into())
        };
        let ts = circuit_builder.create_witin(|| "ts")?;
        let next_ts = ts.expr() + (Tracer::SUBCYCLES_PER_INSN as usize).into();
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        // lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.pc, step.pc().before.0 as u64);
        if let Some(n_pc) = self.next_pc {
            set_val!(instance, n_pc, step.pc().after.0 as u64);
        }
        set_val!(instance, self.ts, step.cycle());

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS1<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLTConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS1<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs1_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs1_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs1",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RS1 as usize).into(),
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rs1() as u64);

        // Register state
        set_val!(instance, self.prev_ts, step.rs1().unwrap().previous_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs1().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS1,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadRS2<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLTConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadRS2<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rs2_read: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rs2_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
        let (_, lt_cfg) = circuit_builder.register_read(
            || "read_rs2",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RS2 as usize).into(),
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rs2() as u64);

        // Register state
        set_val!(instance, self.prev_ts, step.rs2().unwrap().previous_cycle);

        // Register read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs2().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS2,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteRD<E: ExtensionField> {
    pub id: WitIn,
    pub prev_ts: WitIn,
    pub prev_value: UInt<E>,
    pub lt_cfg: AssertLTConfig,
}

impl<E: ExtensionField> WriteRD<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        rd_written: RegisterExpr<E>,
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let id = circuit_builder.create_witin(|| "rd_id")?;
        let prev_ts = circuit_builder.create_witin(|| "prev_rd_ts")?;
        let prev_value = UInt::new_unchecked(|| "prev_rd_value", circuit_builder)?;
        let (_, lt_cfg) = circuit_builder.register_write(
            || "write_rd",
            id,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RD as usize).into(),
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, self.id, step.insn().rd() as u64);
        set_val!(instance, self.prev_ts, step.rd().unwrap().previous_cycle);

        // Register state
        self.prev_value.assign_limbs(
            instance,
            Value::new_unchecked(step.rd().unwrap().value.before).as_u16_limbs(),
        );

        // Register write
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rd().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RD,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadMEM<E: ExtensionField> {
    pub prev_ts: WitIn,
    pub lt_cfg: AssertLTConfig,
    _field_type: PhantomData<E>,
}

impl<E: ExtensionField> ReadMEM<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        mem_addr: MemoryExpr<E>,
        mem_read: [Expression<E>; UINT_LIMBS],
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_ts")?;
        let (_, lt_cfg) = circuit_builder.memory_read(
            || "read_memory",
            &mem_addr,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_MEM as usize).into(),
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // Memory state
        set_val!(
            instance,
            self.prev_ts,
            step.memory_op().unwrap().previous_cycle
        );

        // Memory read
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.memory_op().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_MEM,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteMEM<E: ExtensionField> {
    pub prev_ts: WitIn,
    pub prev_value: UInt<E>,
    pub lt_cfg: AssertLTConfig,
}

impl<E: ExtensionField> WriteMEM<E> {
    pub fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        mem_addr: MemoryExpr<E>,
        mem_written: [Expression<E>; UINT_LIMBS],
        cur_ts: WitIn,
    ) -> Result<Self, ZKVMError> {
        let prev_ts = circuit_builder.create_witin(|| "prev_ts")?;
        let prev_value = UInt::new_unchecked(|| "prev_memory_value", circuit_builder)?;

        let (_, lt_cfg) = circuit_builder.memory_write(
            || "write_memory",
            &mem_addr,
            prev_ts.expr(),
            cur_ts.expr() + (Tracer::SUBCYCLE_RD as usize).into(),
            prev_value.memory_expr(),
            mem_written,
        )?;

        Ok(WriteMEM {
            prev_ts,
            prev_value,
            lt_cfg,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(
            instance,
            self.prev_ts,
            step.memory_op().unwrap().previous_cycle
        );

        // Memory State
        self.prev_value.assign_value(
            instance,
            Value::new_unchecked(step.memory_op().unwrap().value.before),
        );

        // Memory Write
        self.lt_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.memory_op().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_MEM,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct MemAddr<E: ExtensionField> {
    addr: UInt<E>,
    low_bits: Vec<WitIn>,
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

    /// A UInt representing the address as u16 limbs.
    pub fn as_uint(&self) -> &UInt<E> {
        &self.addr
    }

    /// Expressions of the low bits of the address, LSB-first: [bit_0, bit_1].
    pub fn low_bit_exprs(&self) -> Vec<Expression<E>> {
        iter::repeat_n(Expression::ZERO, self.n_zeros())
            .chain(self.low_bits.iter().map(|b| b.expr()))
            .collect()
    }

    fn construct(cb: &mut CircuitBuilder<E>, n_zeros: usize) -> Result<Self, ZKVMError> {
        // Soundness: This does not use the UInt range-check but specialized checks instead.
        let addr = UInt::new_unchecked(|| "memory_addr", cb)?;

        assert!(n_zeros <= Self::N_LOW_BITS);
        let low_bits = (n_zeros..Self::N_LOW_BITS)
            .map(|i| cb.create_witin(|| format!("low_bit_{}", i)))
            .collect::<Result<Vec<_>, _>>()?;

        // TODO: range check the high limb.
        // TODO: range check the low limb together with low bits.

        Ok(MemAddr { addr, low_bits })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        addr: Word,
    ) -> Result<(), ZKVMError> {
        self.addr.assign_value(instance, Value::new_unchecked(addr));

        for (i, bit) in self.low_bits.iter().enumerate() {
            let b = ((addr >> self.n_zeros()) >> i) & 1;
            set_val!(instance, bit, b as u64);
        }

        Ok(())
    }

    fn n_zeros(&self) -> usize {
        Self::N_LOW_BITS - self.low_bits.len()
    }
}

#[cfg(test)]
mod test {
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        scheme::mock_prover::MockProver,
        witness::{LkMultiplicity, RowMajorMatrix},
    };

    use super::MemAddr;

    #[test]
    fn test_mem_addr() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let mem_addr = MemAddr::construct_align2(&mut cb).unwrap();

        let mut lkm = LkMultiplicity::default();
        let mut raw_witin = RowMajorMatrix::<F>::new(1, cb.cs.num_witin as usize);
        for instance in raw_witin.iter_mut() {
            mem_addr
                .assign_instance(instance, &mut lkm, 0xbead1010)
                .unwrap();
        }

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }
}
