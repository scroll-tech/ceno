use std::marker::PhantomData;

use ceno_emul::{
    BN254_FP_ADD, BN254_FP_MUL, ByteAddr, Change, InsnKind, Platform, StepRecord, WORD_SIZE,
    WriteOp,
};
use ff_ext::ExtensionField;
use generic_array::typenum::Unsigned;
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator, gkr::GKRCircuit,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, izip};
use multilinear_extensions::{ToExpr, util::max_usable_threads};
use p3::{field::FieldAlgebra, matrix::Matrix};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sp1_curves::{
    params::NumWords,
    utils::biguint_from_le_words,
    weierstrass::{FpOpField, bn254::Bn254BaseField},
};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::FieldOperation,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UInt},
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{FpOpInstance, FpOpLayout, FpOpTrace},
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

pub trait FpAddSpec: FpOpField {
    const SYSCALL_CODE: u32;
}

pub trait FpMulSpec: FpOpField {
    const SYSCALL_CODE: u32;
}

impl FpAddSpec for Bn254BaseField {
    const SYSCALL_CODE: u32 = BN254_FP_ADD;
}

impl FpMulSpec for Bn254BaseField {
    const SYSCALL_CODE: u32 = BN254_FP_MUL;
}

#[derive(Debug)]
pub struct EcallFpOpConfig<E: ExtensionField, P: FpOpField> {
    pub layout: FpOpLayout<E, P>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    value_ptr_0: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    value_ptr_1: (OpFixedRS<E, { Platform::reg_arg1() }, true>, MemAddr<E>),
    mem_rw: Vec<WriteMEM>,
}

pub struct FpAddInstruction<E, P>(PhantomData<(E, P)>);

impl<E: ExtensionField, P: FpOpField + FpAddSpec + NumWords> Instruction<E>
    for FpAddInstruction<E, P>
{
    type InstructionConfig = EcallFpOpConfig<E, P>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "Ecall_FpAdd".to_string()
    }

    fn construct_circuit(
        _circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        unimplemented!()
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        build_fp_op_circuit::<E, P>(cb, P::SYSCALL_CODE, "fp_add")
    }

    fn generate_fixed_traces(
        config: &Self::InstructionConfig,
        num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        let fixed = config.layout.fixed_witness_group();
        assert_eq!(fixed.width(), num_fixed);
        Some(fixed)
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        assign_fp_op_instances::<E, P>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            steps,
            P::SYSCALL_CODE,
            FieldOperation::Add,
        )
    }
}

pub struct FpMulInstruction<E, P>(PhantomData<(E, P)>);

impl<E: ExtensionField, P: FpOpField + FpMulSpec + NumWords> Instruction<E>
    for FpMulInstruction<E, P>
{
    type InstructionConfig = EcallFpOpConfig<E, P>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "Ecall_FpMul".to_string()
    }

    fn construct_circuit(
        _circuit_builder: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        unimplemented!()
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        build_fp_op_circuit::<E, P>(cb, P::SYSCALL_CODE, "fp_mul")
    }

    fn generate_fixed_traces(
        config: &Self::InstructionConfig,
        num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        let fixed = config.layout.fixed_witness_group();
        assert_eq!(fixed.width(), num_fixed);
        Some(fixed)
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        assign_fp_op_instances::<E, P>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            steps,
            P::SYSCALL_CODE,
            FieldOperation::Mul,
        )
    }
}

fn build_fp_op_circuit<E: ExtensionField, P: FpOpField + NumWords>(
    cb: &mut CircuitBuilder<E>,
    syscall_code: u32,
    layer_name: &str,
) -> Result<(EcallFpOpConfig<E, P>, GKRCircuit<E>), ZKVMError> {
    let vm_state = StateInOut::construct_circuit(cb, false)?;

    let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
        cb,
        UInt::from_const_unchecked(vec![
            syscall_code & LIMB_MASK,
            (syscall_code >> LIMB_BITS) & LIMB_MASK,
        ])
        .register_expr(),
        vm_state.ts,
    )?;

    let value_ptr_value_0 = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
    let value_ptr_value_1 = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;

    let value_ptr_0 = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
        cb,
        value_ptr_value_0.uint_unaligned().register_expr(),
        vm_state.ts,
    )?;

    let value_ptr_1 = OpFixedRS::<_, { Platform::reg_arg1() }, true>::construct_circuit(
        cb,
        value_ptr_value_1.uint_unaligned().register_expr(),
        vm_state.ts,
    )?;

    cb.lk_fetch(&InsnRecord::new(
        vm_state.pc.expr(),
        InsnKind::ECALL.into(),
        None,
        0.into(),
        0.into(),
        0.into(),
        #[cfg(feature = "u16limb_circuit")]
        0.into(),
    ))?;

    let layout = <FpOpLayout<E, P> as ProtocolBuilder<E>>::build_layer_logic(cb, ())?;

    let mut mem_rw = izip!(&layout.input32_exprs[0], &layout.output32_exprs)
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                cb,
                value_ptr_0.prev_value.as_ref().unwrap().value()
                    + E::BaseField::from_canonical_u32(ByteAddr::from((i * WORD_SIZE) as u32).0)
                        .expr(),
                val_before.clone(),
                val_after.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    mem_rw.extend(
        layout.input32_exprs[1]
            .iter()
            .enumerate()
            .map(|(i, val_before)| {
                WriteMEM::construct_circuit(
                    cb,
                    value_ptr_1.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_canonical_u32(
                            ByteAddr::from((i * WORD_SIZE) as u32).0,
                        )
                        .expr(),
                    val_before.clone(),
                    val_before.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?,
    );

    let chip = layout.finalize(layer_name.to_string(), cb);

    Ok((
        EcallFpOpConfig {
            layout,
            vm_state,
            ecall_id,
            value_ptr_0: (value_ptr_0, value_ptr_value_0),
            value_ptr_1: (value_ptr_1, value_ptr_value_1),
            mem_rw,
        },
        chip.gkr_circuit(),
    ))
}

fn assign_fp_op_instances<E: ExtensionField, P: FpOpField + NumWords>(
    config: &EcallFpOpConfig<E, P>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    syscall_code: u32,
    op: FieldOperation,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    let mut lk_multiplicity = LkMultiplicity::default();
    if steps.is_empty() {
        return Ok((
            [
                RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
            ],
            lk_multiplicity.into_finalize_result(),
        ));
    }

    let nthreads = max_usable_threads();
    let num_instance_per_batch = steps.len().div_ceil(nthreads).max(1);

    let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
        steps.len(),
        num_witin,
        InstancePaddingStrategy::Default,
    );
    let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
        steps.len(),
        num_structural_witin,
        InstancePaddingStrategy::Default,
    );

    let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
    let shard_ctx_vec = shard_ctx.get_forked();

    raw_witin_iter
        .zip_eq(steps.par_chunks(num_instance_per_batch))
        .zip(shard_ctx_vec)
        .flat_map(|((instances, steps), mut shard_ctx)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin)
                .zip_eq(steps)
                .map(|(instance, step)| {
                    let ops = &step.syscall().expect("syscall step");
                    config
                        .vm_state
                        .assign_instance(instance, &shard_ctx, step)?;
                    config.ecall_id.assign_op(
                        instance,
                        &mut shard_ctx,
                        &mut lk_multiplicity,
                        step.cycle(),
                        &WriteOp::new_register_op(
                            Platform::reg_ecall(),
                            Change::new(syscall_code, syscall_code),
                            step.rs1().unwrap().previous_cycle,
                        ),
                    )?;
                    config.value_ptr_0.1.assign_instance(
                        instance,
                        &mut lk_multiplicity,
                        ops.reg_ops[0].value.after,
                    )?;
                    config.value_ptr_0.0.assign_op(
                        instance,
                        &mut shard_ctx,
                        &mut lk_multiplicity,
                        step.cycle(),
                        &ops.reg_ops[0],
                    )?;
                    config.value_ptr_1.1.assign_instance(
                        instance,
                        &mut lk_multiplicity,
                        ops.reg_ops[1].value.after,
                    )?;
                    config.value_ptr_1.0.assign_op(
                        instance,
                        &mut shard_ctx,
                        &mut lk_multiplicity,
                        step.cycle(),
                        &ops.reg_ops[1],
                    )?;
                    for (writer, op) in config.mem_rw.iter().zip_eq(&ops.mem_ops) {
                        writer.assign_op(
                            instance,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            step.cycle(),
                            op,
                        )?;
                    }
                    lk_multiplicity.fetch(step.pc().before.0);
                    Ok(())
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<(), ZKVMError>>()?;

    let words = <P as NumWords>::WordsFieldElement::USIZE;
    let instances: Vec<FpOpInstance<P>> = steps
        .par_iter()
        .map(|step| {
            let values: Vec<u32> = step
                .syscall()
                .unwrap()
                .mem_ops
                .iter()
                .map(|op| op.value.before)
                .collect();
            let x = biguint_from_le_words(&values[0..words]);
            let y = biguint_from_le_words(&values[words..2 * words]);
            FpOpInstance::new(x, y, op)
        })
        .collect();

    config.layout.phase1_witness_group(
        FpOpTrace { instances },
        [&mut raw_witin, &mut raw_structural_witin],
        &mut lk_multiplicity,
    );

    raw_witin.padding_by_strategy();
    raw_structural_witin.padding_by_strategy();
    Ok((
        [raw_witin, raw_structural_witin],
        lk_multiplicity.into_finalize_result(),
    ))
}
