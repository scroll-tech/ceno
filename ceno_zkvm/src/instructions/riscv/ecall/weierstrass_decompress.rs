use std::marker::PhantomData;

use ceno_emul::{
    Change, Cycle, InsnKind, Platform, SECP256K1_DECOMPRESS, SECP256R1_DECOMPRESS, StepIndex,
    StepRecord, WriteOp,
};
use ff_ext::ExtensionField;
use generic_array::{GenericArray, typenum::Unsigned};
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    gkr::{GKRCircuit, layer::Layer},
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, izip};
use multilinear_extensions::{Expression, ToExpr, util::max_usable_threads};
use num::BigUint;
use p3::matrix::Matrix;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
    },
    slice::ParallelSlice,
};
use sp1_curves::{
    CurveType, EllipticCurve,
    params::{NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
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
        EllipticCurveDecompressInstance, WeierstrassDecompressLayout, WeierstrassDecompressTrace,
    },
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallWeierstrassDecompressConfig<E: ExtensionField, EC: EllipticCurve> {
    pub layout: WeierstrassDecompressLayout<E, EC>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    field_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    sign_bit: OpFixedRS<E, { Platform::reg_arg1() }, true>,
    mem_rw: Vec<WriteMEM>,
}

/// WeierstrassDecompressInstruction can handle any instruction and produce its side-effects.
pub struct WeierstrassDecompressInstruction<E, EC>(PhantomData<(E, EC)>);

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters> Instruction<E>
    for WeierstrassDecompressInstruction<E, EC>
{
    type InstructionConfig = EcallWeierstrassDecompressConfig<E, EC>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "Ecall_WeierstrassDecompress_".to_string() + format!("{:?}", EC::CURVE_TYPE).as_str()
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
        let mut layout =
            <WeierstrassDecompressLayout<E, EC> as gkr_iop::ProtocolBuilder<E>>::build_layer_logic(
                cb,
                (),
            )?;

        let vm_state = StateInOut::construct_circuit(cb, false)?;

        let syscall_code = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => SECP256K1_DECOMPRESS,
            CurveType::Secp256r1 => SECP256R1_DECOMPRESS,
            _ => {
                unreachable!("WeierstrassDecompress is not supported for this curve")
            }
        };

        let ecall_id = OpFixedRS::<_, { Platform::reg_ecall() }, false>::construct_circuit(
            cb,
            UInt::from_const_unchecked(vec![
                syscall_code & LIMB_MASK,
                (syscall_code >> LIMB_BITS) & LIMB_MASK,
            ])
            .register_expr(),
            vm_state.ts,
        )?;

        let field_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;
        let field_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            field_ptr_value.uint_unaligned().register_expr(),
            vm_state.ts,
        )?;

        let sign_bit_value = layout.layer_exprs.wits.sign_bit;
        let sign_bit = OpFixedRS::<_, { Platform::reg_arg1() }, true>::construct_circuit(
            cb,
            [sign_bit_value.expr(), Expression::ZERO],
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

        let num_limbs = <EC::BaseField as NumLimbs>::Limbs::U32;
        assert_eq!(num_limbs, 32);
        let field_ptr_expr = field_ptr.prev_value.as_ref().unwrap().value();
        let mut mem_rw = layout
            .input32_exprs
            .iter()
            .enumerate()
            .map(|(i, val)| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := field_ptr + i * 4
                    field_ptr_expr.expr() + (i as u32) * 4,
                    val.clone(),
                    val.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?;

        mem_rw.extend(
            izip!(
                layout.old_output32_exprs.iter(),
                layout.output32_exprs.iter()
            )
            .enumerate()
            .map(|(i, (val_before, val_after))| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := field_ptr + i * 4 + num_limbs
                    field_ptr_expr.expr() + (i as u32) * 4 + num_limbs,
                    val_before.clone(),
                    val_after.clone(),
                    vm_state.ts,
                )
            })
            .collect::<Result<Vec<WriteMEM>, _>>()?,
        );

        let (out_evals, mut chip) = layout.finalize(cb);

        let layer = Layer::from_circuit_builder(
            cb,
            "weierstrass_decompress".to_string(),
            layout.n_challenges,
            out_evals,
        );
        chip.add_layer(layer);

        let circuit = chip.gkr_circuit();

        Ok((
            EcallWeierstrassDecompressConfig {
                layout,
                vm_state,
                ecall_id,
                field_ptr: (field_ptr, field_ptr_value),
                sign_bit,
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
        steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let syscall_code = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => SECP256K1_DECOMPRESS,
            CurveType::Secp256r1 => SECP256R1_DECOMPRESS,
            _ => {
                unreachable!("WeierstrassDecompress is not supported for this curve")
            }
        };

        let mut lk_multiplicity = LkMultiplicity::default();
        if step_indices.is_empty() {
            return Ok((
                [
                    RowMajorMatrix::new(0, num_witin, InstancePaddingStrategy::Default),
                    RowMajorMatrix::new(0, num_structural_witin, InstancePaddingStrategy::Default),
                ],
                lk_multiplicity.into_finalize_result(),
            ));
        }
        let nthreads = max_usable_threads();
        let num_instance_per_batch = step_indices.len().div_ceil(nthreads).max(1);

        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            step_indices.len(),
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
            step_indices.len(),
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
        let shard_ctx_vec = shard_ctx.get_forked();

        let ec_field_num_words = <EC::BaseField as NumWords>::WordsFieldElement::USIZE;
        // 1st pass: assign witness outside of gkr-iop scope
        let sign_bit_and_y_words = raw_witin_iter
            .zip_eq(step_indices.par_chunks(num_instance_per_batch))
            .zip(shard_ctx_vec)
            .flat_map(|((instances, indices), mut shard_ctx)| {
                let mut lk_multiplicity = lk_multiplicity.clone();

                instances
                    .chunks_mut(num_witin)
                    .zip_eq(indices.iter().copied())
                    .map(|(instance, idx)| {
                        let step = &steps[idx];
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
                        // assign field_ptr
                        config.field_ptr.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[0].value.after,
                        )?;
                        config.field_ptr.0.assign_op(
                            instance,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &ops.reg_ops[0],
                        )?;
                        // register read for sign_bit
                        config.sign_bit.assign_op(
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
                        let old_output32: Vec<_> = ops
                            .mem_ops
                            .iter()
                            .skip(ec_field_num_words)
                            .map(|op| op.value.before)
                            .collect();
                        Ok((
                            ops.reg_ops[1].value.before != 0,
                            old_output32.try_into().unwrap(),
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;

        // second pass
        let instances = step_indices
            .par_iter()
            .zip(sign_bit_and_y_words.into_par_iter())
            .map(|(idx, (sign_bit, old_output32))| {
                let step = &steps[*idx];
                let (instance, _prev_ts): (Vec<u32>, Vec<Cycle>) = step
                    .syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .take(ec_field_num_words)
                    .map(|op| (op.value.before, op.previous_cycle))
                    .unzip();

                let x_words =
                    GenericArray::<_, <EC::BaseField as NumWords>::WordsFieldElement>::try_from(
                        instance[0..<EC::BaseField as NumWords>::WordsFieldElement::USIZE].to_vec(),
                    );

                x_words
                    .map(|x_words: GenericArray<u32, _>| {
                        let x = BigUint::from_bytes_be(
                            &x_words
                                .iter()
                                .flat_map(|n| n.to_le_bytes())
                                .collect::<Vec<_>>(),
                        );
                        EllipticCurveDecompressInstance {
                            x,
                            sign_bit,
                            old_y_words: old_output32,
                        }
                    })
                    .map_err(|_| {
                        ZKVMError::InvalidWitness(
                            "Failed to parse EllipticCurveDecompressInstance".into(),
                        )
                    })
            })
            .collect::<Result<_, _>>()?;

        config.layout.phase1_witness_group(
            WeierstrassDecompressTrace {
                instances,
                _phantom: PhantomData,
            },
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
