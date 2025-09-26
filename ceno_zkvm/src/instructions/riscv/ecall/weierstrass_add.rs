use std::marker::PhantomData;

use ceno_emul::{
    BLS12381_ADD, BN254_ADD, ByteAddr, Change, Cycle, InsnKind, Platform, SECP256K1_ADD,
    SECP256R1_ADD, StepRecord, WORD_SIZE, WriteOp,
};
use ff_ext::ExtensionField;
use generic_array::{GenericArray, typenum::Unsigned};
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    gkr::{GKRCircuit, layer::Layer},
    utils::lk_multiplicity::Multiplicity,
};
use itertools::{Itertools, izip};
use multilinear_extensions::{ToExpr, util::max_usable_threads};
use p3::{field::FieldAlgebra, matrix::Matrix};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sp1_curves::{CurveType, EllipticCurve, params::NumWords};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::general::InstFetch,
    circuit_builder::CircuitBuilder,
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
        EllipticCurveAddInstance, WeierstrassAddAssignLayout, WeierstrassAddAssignTrace,
    },
    structs::ProgramParams,
    tables::{InsnRecord, RMMCollections},
    witness::LkMultiplicity,
};

#[derive(Debug)]
pub struct EcallWeierstrassAddAssignConfig<E: ExtensionField, EC: EllipticCurve> {
    pub layout: WeierstrassAddAssignLayout<E, EC>,
    vm_state: StateInOut<E>,
    ecall_id: OpFixedRS<E, { Platform::reg_ecall() }, false>,
    state_ptr: (OpFixedRS<E, { Platform::reg_arg0() }, true>, MemAddr<E>),
    mem_rw: Vec<WriteMEM>,
}

/// WeierstrassAddAssignInstruction can handle any instruction and produce its side-effects.
pub struct WeierstrassAddAssignInstruction<E, EC>(PhantomData<(E, EC)>);

impl<E: ExtensionField, EC: EllipticCurve> Instruction<E>
    for WeierstrassAddAssignInstruction<E, EC>
{
    type InstructionConfig = EcallWeierstrassAddAssignConfig<E, EC>;

    fn name() -> String {
        "Ecall_WeierstrassAddAssign_".to_string() + format!("{:?}", EC::CURVE_TYPE).as_str()
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

        let syscall_code = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => SECP256K1_ADD,
            CurveType::Secp256r1 => SECP256R1_ADD,
            CurveType::Bn254 => BN254_ADD,
            CurveType::Bls12381 => BLS12381_ADD,
            CurveType::Ed25519 => {
                unreachable!("WeierstrassAddAssign is not supported for Ed25519")
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

        let state_ptr_value = MemAddr::construct_with_max_bits(cb, 2, MEM_BITS)?;

        let state_ptr = OpFixedRS::<_, { Platform::reg_arg0() }, true>::construct_circuit(
            cb,
            state_ptr_value.uint_unaligned().register_expr(),
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
            <WeierstrassAddAssignLayout<E, EC> as gkr_iop::ProtocolBuilder<E>>::build_layer_logic(
                cb,
                (),
            )?;

        // Write the result to the same address of the first input point.
        let mut mem_rw = izip!(&layout.input32_exprs[0], &layout.output32_exprs)
            .enumerate()
            .map(|(i, (val_before, val_after))| {
                WriteMEM::construct_circuit(
                    cb,
                    // mem address := state_ptr_0 + i
                    state_ptr.prev_value.as_ref().unwrap().value()
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

        let n_words = layout.output32_exprs.len();
        // Keep the second input point unchanged in memory.
        mem_rw.extend(
            layout.input32_exprs[1]
                .iter()
                .enumerate()
                .map(|(i, val_before)| {
                    WriteMEM::construct_circuit(
                        cb,
                        // mem address := state_ptr_1 + i
                        state_ptr.prev_value.as_ref().unwrap().value()
                            + E::BaseField::from_canonical_u32(
                                ByteAddr::from(((n_words + i) * WORD_SIZE) as u32).0,
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
            &cb,
            "weierstrass_add".to_string(),
            layout.n_challenges,
            out_evals,
        );
        chip.add_layer(layer);

        let circuit = chip.gkr_circuit();

        Ok((
            EcallWeierstrassAddAssignConfig {
                layout,
                vm_state,
                ecall_id,
                state_ptr: (state_ptr, state_ptr_value),
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
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unreachable!("we override logic in assign_instances")
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        num_structural_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let syscall_code = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => SECP256K1_ADD,
            CurveType::Secp256r1 => SECP256R1_ADD,
            CurveType::Bn254 => BN254_ADD,
            CurveType::Bls12381 => BLS12381_ADD,
            CurveType::Ed25519 => {
                unreachable!("WeierstrassAddAssign is not supported for Ed25519")
            }
        };

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
            config.layout.phase1_witin_rmm_height(steps.len()),
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let mut raw_structural_witin = RowMajorMatrix::<E::BaseField>::new(
            config.layout.phase1_witin_rmm_height(steps.len()),
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);

        // 1st pass: assign witness outside of gkr-iop scope
        raw_witin_iter
            .zip_eq(steps.par_chunks(num_instance_per_batch))
            .flat_map(|(instances, steps)| {
                let mut lk_multiplicity = lk_multiplicity.clone();

                instances
                    .chunks_mut(num_witin)
                    .zip_eq(steps)
                    .map(|(instance, step)| {
                        let ops = &step.syscall().expect("syscall step");

                        // vm_state
                        config.vm_state.assign_instance(instance, step)?;

                        config.ecall_id.assign_op(
                            instance,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &WriteOp::new_register_op(
                                Platform::reg_ecall(),
                                Change::new(syscall_code, syscall_code),
                                step.rs1().unwrap().previous_cycle,
                            ),
                        )?;
                        // assign state_ptr
                        config.state_ptr.1.assign_instance(
                            instance,
                            &mut lk_multiplicity,
                            ops.reg_ops[0].value.after,
                        )?;
                        config.state_ptr.0.assign_op(
                            instance,
                            &mut lk_multiplicity,
                            step.cycle(),
                            &ops.reg_ops[0],
                        )?;
                        for (writer, op) in config.mem_rw.iter().zip_eq(&ops.mem_ops) {
                            writer.assign_op(instance, &mut lk_multiplicity, step.cycle(), op)?;
                        }
                        // fetch
                        lk_multiplicity.fetch(step.pc().before.0);
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        // second pass
        let instances: Vec<EllipticCurveAddInstance<EC::BaseField>> = steps
            .iter()
            .map(|step| {
                let (instance, _prev_ts): (Vec<u32>, Vec<Cycle>) = step
                    .syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| (op.value.before, op.previous_cycle))
                    .unzip();

                println!(
                    "WeierstrassAddAssign input instance: len({:?}) {:?}",
                    instance.len(),
                    instance
                );

                let p = GenericArray::try_from(
                    instance[0..<EC::BaseField as NumWords>::WordsCurvePoint::USIZE].to_vec(),
                );
                let q = GenericArray::try_from(
                    instance[<EC::BaseField as NumWords>::WordsCurvePoint::USIZE..].to_vec(),
                );
                p.and_then(|p| q.map(|q| EllipticCurveAddInstance::<EC::BaseField> { p, q }))
                    .map_err(|_| {
                        ZKVMError::InvalidWitness("Failed to parse EllipticCurveAddInstance".into())
                    })
            })
            .try_collect()?;

        config.layout.phase1_witness_group(
            WeierstrassAddAssignTrace { instances },
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
