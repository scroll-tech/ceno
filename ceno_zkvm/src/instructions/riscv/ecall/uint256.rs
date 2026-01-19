use std::marker::PhantomData;

use ceno_emul::{
    ByteAddr, Change, Cycle, InsnKind, Platform, SECP256K1_SCALAR_INVERT, SECP256R1_SCALAR_INVERT,
    StepRecord, UINT256_MUL, WORD_SIZE, WriteOp,
};
use ff_ext::ExtensionField;
use generic_array::typenum::Unsigned;
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    gkr::{GKRCircuit, layer::Layer},
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, chain, izip};
use multilinear_extensions::{ToExpr, util::max_usable_threads};
use num_bigint::BigUint;
use p3::{field::FieldAlgebra, matrix::Matrix};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sp1_curves::{
    params::NumWords,
    uint256::U256Field,
    utils::{biguint_from_be_words, biguint_from_le_words},
    weierstrass::{
        WeierstrassParameters,
        secp256k1::{Secp256k1, Secp256k1BaseField},
        secp256r1::{Secp256r1, Secp256r1BaseField},
    },
};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{LIMB_BITS, LIMB_MASK, MEM_BITS, UInt},
            ecall_base::OpFixedRS,
            insn_base::{MemAddr, StateInOut, WriteMEM},
        },
    },
    precompiles::{
        Uint256InvLayout, Uint256InvSpec, Uint256InvTrace, Uint256MulInstance, Uint256MulLayout,
        Uint256MulTrace,
    },
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallUint256MulConfig<E: ExtensionField> {
    pub layout: Uint256MulLayout<E>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    word_ptr_0: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    word_ptr_1: (OpFixedRS<E, { Platform::reg_arg1() }, true>, MemAddr<E>),
    mem_rw: Vec<WriteMEM>,
}

/// Uint256MulInstruction can handle any instruction and produce its side-effects.
pub struct Uint256MulInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for Uint256MulInstruction<E> {
    type InstructionConfig = EcallUint256MulConfig<E>;

    fn name() -> String {
        "Ecall_Uint256Mul".to_string()
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
        // constrain vmstate
        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let syscall_code = UINT256_MUL;

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                syscall_code & LIMB_MASK,
                (syscall_code >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let word_ptr_value_0 = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let word_ptr_value_1 = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;

        let word_ptr_0 = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            word_ptr_value_0.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        let word_ptr_1 = OpFixedRS::<_, { Platform::reg_arg1() }, true>::construct_circuit(
            cb,
            word_ptr_value_1.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        // fetch
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

        let mut layout =
            <Uint256MulLayout<E> as gkr_iop::ProtocolBuilder<E>>::build_layer_logic(cb, ())?;

        // Write the result to the same address of the first input point.
        let mut mem_rw = izip!(&layout.input32_exprs[0], &layout.output32_exprs)
            .enumerate()
            .map(|(i, (val_before, val_after))| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := word_ptr_0 + i
                    word_ptr_0.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_canonical_u32(
                            ByteAddr::from((i * WORD_SIZE) as u32).0,
                        )
                        .expr(),
                    val_before.clone(),
                    val_after.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?;

        // Keep the second input point unchanged in memory.
        mem_rw.extend(
            chain![
                layout.input32_exprs[1].iter(),
                layout.input32_exprs[2].iter()
            ]
            .enumerate()
            .map(|(i, val_before)| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := word_ptr_1 + i
                    word_ptr_1.prev_value.as_ref().unwrap().value()
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

        let (out_evals, mut chip) = layout.finalize(cb);

        let layer = Layer::from_circuit_builder(
            cb,
            "uint256_mul".to_string(),
            layout.n_challenges,
            out_evals,
        );
        chip.add_layer(layer);

        let circuit = chip.gkr_circuit();

        Ok((
            EcallUint256MulConfig {
                layout,
                vm_state,
                ecall_id,
                word_ptr_0: (word_ptr_0, word_ptr_value_0),
                word_ptr_1: (word_ptr_1, word_ptr_value_1),
                mem_rw,
            },
            circuit,
        ))
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
        steps: Vec<&StepRecord>,
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let syscall_code = UINT256_MUL;

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

        // 1st pass: assign witness outside of gkr-iop scope
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

                        // vm_state
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
                        // assign word_ptr_0
                        config.word_ptr_0.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[0].value.after,
                        )?;
                        config.word_ptr_0.0.assign_op(
                            instance,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &ops.reg_ops[0],
                        )?;
                        // assign word_ptr_1
                        config.word_ptr_1.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[1].value.after,
                        )?;
                        config.word_ptr_1.0.assign_op(
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
                        // fetch
                        lk_multiplicity.fetch(step.pc().before.0);
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        // second pass
        let instances: Vec<Uint256MulInstance> = steps
            .par_iter()
            .map(|step| {
                let (instance, _prev_ts): (Vec<u32>, Vec<Cycle>) = step
                    .syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| (op.value.before, op.previous_cycle))
                    .unzip();

                let x = biguint_from_le_words(
                    &instance[0..<U256Field as NumWords>::WordsFieldElement::USIZE],
                );
                let y = biguint_from_le_words(
                    &instance[<U256Field as NumWords>::WordsFieldElement::USIZE..],
                );
                let modulus = biguint_from_le_words(
                    &instance[2 * <U256Field as NumWords>::WordsFieldElement::USIZE..],
                );
                Uint256MulInstance { x, y, modulus }
            })
            .collect();

        config.layout.phase1_witness_group(
            Uint256MulTrace { instances },
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
}

/// Uint256InvInstruction can handle any instruction and produce its side-effects.
pub struct Uint256InvInstruction<E, P>(PhantomData<(E, P)>);

pub struct Secp256K1EcallSpec;

impl Uint256InvSpec for Secp256K1EcallSpec {
    type P = Secp256k1BaseField;

    fn syscall() -> u32 {
        SECP256K1_SCALAR_INVERT
    }

    fn name() -> String {
        "secp256k1_scalar_invert".to_string()
    }

    fn modulus() -> BigUint {
        Secp256k1::prime_group_order()
    }
}

pub type Secp256k1InvInstruction<E> = Uint256InvInstruction<E, Secp256K1EcallSpec>;

pub struct Secp256R1EcallSpec;

impl Uint256InvSpec for Secp256R1EcallSpec {
    type P = Secp256r1BaseField;

    fn syscall() -> u32 {
        SECP256R1_SCALAR_INVERT
    }

    fn name() -> String {
        "secp256r1_scalar_invert".to_string()
    }

    fn modulus() -> BigUint {
        Secp256r1::prime_group_order()
    }
}

pub type Secp256r1InvInstruction<E> = Uint256InvInstruction<E, Secp256R1EcallSpec>;

#[derive(Debug)]
pub struct EcallUint256InvConfig<E: ExtensionField, Spec: Uint256InvSpec> {
    pub layout: Uint256InvLayout<E, Spec>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    word_ptr_0: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    mem_rw: Vec<WriteMEM>,
}

impl<E: ExtensionField, Spec: Uint256InvSpec> Instruction<E> for Uint256InvInstruction<E, Spec> {
    type InstructionConfig = EcallUint256InvConfig<E, Spec>;

    fn name() -> String {
        Spec::name()
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
        // constrain vmstate
        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let syscall_code = Spec::syscall();

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                syscall_code & LIMB_MASK,
                (syscall_code >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let word_ptr_value_0 = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;

        let word_ptr_0 = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            word_ptr_value_0.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        // fetch
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

        let mut layout =
            <Uint256InvLayout<E, Spec> as ProtocolBuilder<E>>::build_layer_logic(cb, ())?;

        // Write the result to the same address of the first input point.
        let mem_rw = layout
            .input32_exprs
            .iter()
            .zip_eq(&layout.output32_exprs)
            .enumerate()
            .map(|(i, (val_before, val_after))| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := word_ptr_0 + i
                    word_ptr_0.prev_value.as_ref().unwrap().value()
                        + E::BaseField::from_canonical_u32(
                            ByteAddr::from((i * WORD_SIZE) as u32).0,
                        )
                        .expr(),
                    val_before.clone(),
                    val_after.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?;

        let (out_evals, mut chip) = layout.finalize(cb);

        let layer = Layer::from_circuit_builder(cb, Spec::name(), layout.n_challenges, out_evals);
        chip.add_layer(layer);

        let circuit = chip.gkr_circuit();

        Ok((
            EcallUint256InvConfig {
                layout,
                vm_state,
                ecall_id,
                word_ptr_0: (word_ptr_0, word_ptr_value_0),
                mem_rw,
            },
            circuit,
        ))
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
        steps: Vec<&StepRecord>,
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let syscall_code = Spec::syscall();

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

        // 1st pass: assign witness outside of gkr-iop scope
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

                        // vm_state
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
                        // assign word_ptr_0
                        config.word_ptr_0.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[0].value.after,
                        )?;
                        config.word_ptr_0.0.assign_op(
                            instance,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &ops.reg_ops[0],
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
                        // fetch
                        lk_multiplicity.fetch(step.pc().before.0);
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        // second pass
        let instances: Vec<BigUint> = steps
            .par_iter()
            .map(|step| {
                let (instance, _): (Vec<u32>, Vec<Cycle>) = step
                    .syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| (op.value.before, op.previous_cycle))
                    .unzip();
                biguint_from_be_words(&instance)
            })
            .collect();

        config.layout.phase1_witness_group(
            Uint256InvTrace { instances },
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
}
