use std::{collections::HashMap, iter::repeat_n, marker::PhantomData};

use crate::{
    Value,
    chip_handler::general::PublicIOQuery,
    e2e::RAMRecord,
    error::ZKVMError,
    gadgets::Poseidon2Config,
    instructions::riscv::constants::UINT_LIMBS,
    scheme::septic_curve::{SepticExtension, SepticPoint},
    structs::{ProgramParams, RAMType},
    tables::{RMMCollections, TableCircuit},
    witness::LkMultiplicity,
};
use ceno_emul::WordAddr;
use ff_ext::{ExtensionField, FieldInto, PoseidonField, SmallField};
use gkr_iop::{
    chip::Chip,
    circuit_builder::CircuitBuilder,
    error::CircuitBuilderError,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
};
use itertools::{Itertools, chain};
use multilinear_extensions::{
    Expression, StructuralWitInType::EqualDistanceSequence, ToExpr, WitIn, util::max_usable_threads,
};
use p3::{
    field::{Field, FieldAlgebra},
    matrix::dense::RowMajorMatrix,
    symmetric::Permutation,
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator},
    prelude::ParallelSliceMut,
    slice::ParallelSlice,
};
use std::ops::Deref;
use witness::{InstancePaddingStrategy, next_pow2_instance_padding, set_val};

use crate::{instructions::riscv::constants::UInt, scheme::constants::SEPTIC_EXTENSION_DEGREE};

/// A record for a read/write into the global set
#[derive(Default, Debug, Clone)]
pub struct GlobalRecord {
    pub addr: u32,
    pub ram_type: RAMType,
    pub value: u32,
    pub shard: u64,
    pub local_clk: u64,
    pub global_clk: u64,
    pub is_write: bool,
}

impl From<(&WordAddr, &RAMRecord, bool)> for GlobalRecord {
    fn from((vma, record, is_write): (&WordAddr, &RAMRecord, bool)) -> Self {
        let addr = match record.ram_type {
            RAMType::Register => record.id as u32,
            RAMType::Memory => (*vma).into(),
            _ => unreachable!(),
        };
        let value = record.prev_value.map_or(record.value, |v| v);
        let (shard, local_clk, global_clk) = if is_write {
            (record.shard_id, record.cycle, record.cycle)
        } else {
            (record.shard_id, 0, record.prev_cycle)
        };

        GlobalRecord {
            addr,
            ram_type: record.ram_type,
            value,
            shard: shard as u64,
            local_clk,
            global_clk,
            is_write,
        }
    }
}
/// An EC point corresponding to a global read/write record
/// whose x-coordinate is derived from Poseidon2 hash of the record
#[derive(Clone, Debug)]
pub struct GlobalPoint<E: ExtensionField> {
    pub nonce: u32,
    pub point: SepticPoint<E::BaseField>,
}

impl GlobalRecord {
    pub fn to_ec_point<E: ExtensionField, P: Permutation<Vec<E::BaseField>>>(
        &self,
        hasher: &P,
    ) -> GlobalPoint<E> {
        let mut nonce = 0;
        let mut input = vec![
            E::BaseField::from_canonical_u32(self.addr),
            E::BaseField::from_canonical_u32(self.ram_type as u32),
            E::BaseField::from_canonical_u32(self.value & 0xFFFF), // lower 16 bits
            E::BaseField::from_canonical_u32((self.value >> 16) & 0xFFFF), // higher 16 bits
            E::BaseField::from_canonical_u64(self.shard),
            E::BaseField::from_canonical_u64(self.global_clk),
            E::BaseField::from_canonical_u32(nonce),
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
            E::BaseField::ZERO,
        ];

        let prime = E::BaseField::order().to_u64_digits()[0];
        loop {
            let x: SepticExtension<E::BaseField> =
                hasher.permute(input.clone())[0..SEPTIC_EXTENSION_DEGREE].into();
            if let Some(p) = SepticPoint::from_x(x) {
                let y6 = (p.y.0)[SEPTIC_EXTENSION_DEGREE - 1].to_canonical_u64();
                let is_y_in_2nd_half = y6 >= (prime / 2);

                // we negate y if needed
                // to ensure read => y in [0, p/2) and write => y in [p/2, p)
                let negate = match (self.is_write, is_y_in_2nd_half) {
                    (true, false) => true, // write, y in [0, p/2)
                    (false, true) => true, // read, y in [p/2, p)
                    _ => false,
                };

                let point = if negate { -p } else { p };

                return GlobalPoint { nonce, point };
            } else {
                // try again with different nonce
                nonce += 1;
                input[6] = E::BaseField::from_canonical_u32(nonce);
            }
        }
    }
}
/// opcode circuit + mem init/final table + local finalize circuit + global chip
/// global chip is used to ensure the **local** reads and writes produced by
/// opcode circuits / memory init / memory finalize table / local finalize circuit
/// can balance out.
///
/// 1. For a local memory read record whose previous write is not in the same shard,
///    the global chip will read it from the **global set** and insert a local write record.
/// 2. For a local memory write record which will **not** be read in the future,
///    the local finalize circuit will consume it by inserting a local read record.
/// 3. For a local memory write record which will be read in the future,
///    the global chip will insert a local read record and write it to the **global set**.
pub struct GlobalConfig<E: ExtensionField> {
    addr: WitIn,
    is_ram_register: WitIn,
    value: UInt<E>,
    shard: WitIn,
    global_clk: WitIn,
    local_clk: WitIn,
    nonce: WitIn,
    // if it's a write to global set, then insert a local read record
    // s.t. local offline memory checking can cancel out
    // this serves as propagating local write to global.
    is_global_write: WitIn,
    x: Vec<WitIn>,
    y: Vec<WitIn>,
    slope: Vec<WitIn>,
    perm_config: Poseidon2Config<E, 16, 7, 1, 4, 13>,
}

impl<E: ExtensionField> GlobalConfig<E> {
    // TODO: make `WIDTH`, `HALF_FULL_ROUNDS`, `PARTIAL_ROUNDS` generic parameters
    pub fn configure(cb: &mut CircuitBuilder<E>) -> Result<Self, CircuitBuilderError> {
        let x: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("x{}", i)))
            .collect();
        let y: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("y{}", i)))
            .collect();
        let slope: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("slope{}", i)))
            .collect();
        let addr = cb.create_witin(|| "addr");
        let is_ram_register = cb.create_witin(|| "is_ram_register");
        let value = UInt::new_unchecked(|| "value", cb)?;
        let shard = cb.create_witin(|| "shard");
        let global_clk = cb.create_witin(|| "global_clk");
        let local_clk = cb.create_witin(|| "local_clk");
        let nonce = cb.create_witin(|| "nonce");
        let is_global_write = cb.create_witin(|| "is_global_write");

        let is_ram_reg: Expression<E> = is_ram_register.expr();
        let reg: Expression<E> = RAMType::Register.into();
        let mem: Expression<E> = RAMType::Memory.into();
        let ram_type: Expression<E> = is_ram_reg.clone() * reg + (1 - is_ram_reg) * mem;

        let rc = <E::BaseField as PoseidonField>::get_default_perm_rc().into();
        let perm_config = Poseidon2Config::construct(cb, rc);

        let mut input = vec![];
        input.push(addr.expr());
        input.push(ram_type.clone());
        // memory expr has same number of limbs as register expr
        input.extend(value.memory_expr());
        input.push(shard.expr());
        input.push(global_clk.expr());
        // add nonce to ensure poseidon2(input) always map to a valid ec point
        input.push(nonce.expr());
        input.extend(repeat_n(E::BaseField::ZERO.expr(), 16 - input.len()));

        let mut record = vec![];
        record.push(addr.expr());
        record.push(ram_type.clone());
        record.extend(value.memory_expr());
        record.push(local_clk.expr());

        // if is_global_write = 1, then it means we are propagating a local write to global
        // so we need to insert a local read record to cancel out this local write
        cb.assert_bit(|| "is_global_write must be boolean", is_global_write.expr())?;
        // TODO: for all local reads, enforce they come to global writes
        // TODO: for all local writes, enforce they come from global reads

        // global read => insert a local write with local_clk = 0
        cb.condition_require_zero(
            || "is_global_read => local_clk = 0",
            1 - is_global_write.expr(),
            local_clk.expr(),
        )?;
        // TODO: enforce shard = shard_id in the public values
        cb.read_rlc_record(
            || "r_record",
            ram_type.clone(),
            record.clone(),
            cb.rlc_chip_record(record.clone()),
        )?;
        cb.write_rlc_record(
            || "w_record",
            ram_type,
            record.clone(),
            cb.rlc_chip_record(record),
        )?;

        // enforces final_sum = \sum_i (x_i, y_i) using ecc quark protocol
        let final_sum = cb.query_global_rw_sum()?;
        cb.ec_sum(
            x.iter().map(|xi| xi.expr()).collect::<Vec<_>>(),
            y.iter().map(|yi| yi.expr()).collect::<Vec<_>>(),
            slope.iter().map(|si| si.expr()).collect::<Vec<_>>(),
            final_sum.into_iter().map(|x| x.expr()).collect::<Vec<_>>(),
        );

        // enforces x = poseidon2([addr, ram_type, value[0], value[1], shard, global_clk, nonce, 0, ..., 0])
        for (input_expr, hasher_input) in input.into_iter().zip_eq(perm_config.inputs().into_iter())
        {
            cb.require_equal(|| "poseidon2 input", input_expr, hasher_input)?;
        }
        for (xi, hasher_output) in x.iter().zip(perm_config.output().into_iter()) {
            cb.require_equal(|| "x = poseidon2's output", xi.expr(), hasher_output)?;
        }

        // both (x, y) and (x, -y) are valid ec points
        // if is_global_write = 1, then y should be in [0, p/2)
        // if is_global_write = 0, then y should be in [p/2, p)

        // TODO: enforce 0 <= y < p/2 if is_global_write = 1
        //       enforce p/2 <= y < p if is_global_write = 0

        Ok(GlobalConfig {
            x,
            y,
            slope,
            addr,
            is_ram_register,
            value,
            shard,
            global_clk,
            local_clk,
            nonce,
            is_global_write,
            perm_config,
        })
    }
}

/// This chip is used to manage read/write into a global set
/// shared among multiple shards
#[derive(Default)]
pub struct GlobalChip<E> {
    _marker: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub struct GlobalChipInput<E: ExtensionField> {
    pub record: GlobalRecord,
    pub ec_point: GlobalPoint<E>,
}

impl<E: ExtensionField> GlobalChip<E> {
    fn assign_instance<'a>(
        config: &GlobalConfig<E>,
        instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        input: &GlobalChipInput<E>,
    ) -> Result<(), crate::error::ZKVMError> {
        // assign basic fields
        let record = &input.record;
        let is_ram_register = match record.ram_type {
            RAMType::Register => 1,
            RAMType::Memory => 0,
            _ => unreachable!(),
        };
        set_val!(instance, config.addr, record.addr as u64);
        set_val!(instance, config.is_ram_register, is_ram_register as u64);
        let value = Value::new_unchecked(record.value);
        config.value.assign_limbs(instance, value.as_u16_limbs());
        set_val!(instance, config.shard, record.shard);
        set_val!(instance, config.global_clk, record.global_clk);
        set_val!(instance, config.local_clk, record.local_clk);
        set_val!(instance, config.is_global_write, record.is_write as u64);

        // assign (x, y) and nonce
        let GlobalPoint { nonce, point } = &input.ec_point;
        set_val!(instance, config.nonce, *nonce as u64);
        config
            .x
            .iter()
            .chain(config.y.iter())
            .zip_eq((point.x.deref()).iter().chain((point.y.deref()).iter()))
            .for_each(|(witin, fe)| {
                instance[witin.id as usize] = *fe;
            });

        let ram_type = E::BaseField::from_canonical_u32(record.ram_type as u32);
        let mut input = [E::BaseField::ZERO; 16];

        let k = UINT_LIMBS;
        input[0] = E::BaseField::from_canonical_u32(record.addr);
        input[1] = ram_type;
        input[2..(k + 2)]
            .iter_mut()
            .zip(value.as_u16_limbs().iter())
            .for_each(|(i, v)| *i = E::BaseField::from_canonical_u16(*v));
        input[2 + k] = E::BaseField::from_canonical_u64(record.shard);
        input[2 + k + 1] = E::BaseField::from_canonical_u64(record.global_clk);
        input[2 + k + 2] = E::BaseField::from_canonical_u32(*nonce);

        config
            .perm_config
            // TODO: remove hardcoded constant 28
            .assign_instance(&mut instance[28 + UINT_LIMBS..], input);

        Ok(())
    }
}

impl<E: ExtensionField> TableCircuit<E> for GlobalChip<E> {
    type TableConfig = GlobalConfig<E>;
    type FixedInput = ();
    type WitnessInput = Vec<GlobalChipInput<E>>;

    fn name() -> String {
        "Global".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::TableConfig, crate::error::ZKVMError> {
        let config = GlobalConfig::configure(cb)?;

        Ok(config)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), crate::error::ZKVMError> {
        // create three selectors: selector_r, selector_w, selector_zero
        let selector_r = cb.create_structural_witin(
            || "selector_r",
            // this is just a placeholder, the actural type is SelectorType::Prefix()
            EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );
        let selector_w = cb.create_structural_witin(
            || "selector_w",
            // this is just a placeholder, the actural type is SelectorType::Prefix()
            EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );
        let selector_zero = cb.create_structural_witin(
            || "selector_zero",
            // this is just a placeholder, the actural type is SelectorType::Prefix()
            EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );

        let config = Self::construct_circuit(cb, param)?;

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        let selector_r = SelectorType::Prefix(selector_r.expr());
        // note that the actual offset should be set by prover
        // depending on the number of local read instances
        let selector_w = SelectorType::Prefix(selector_w.expr());
        // TODO: when selector_r = 1 => selector_zero = 1
        //      when selector_w = 1 => selector_zero = 1
        let selector_zero = SelectorType::Prefix(selector_zero.expr());

        cb.cs.r_selector = Some(selector_r);
        cb.cs.w_selector = Some(selector_w);
        cb.cs.zero_selector = Some(selector_zero.clone());
        cb.cs.lk_selector = Some(selector_zero);

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                (0..r_len).collect_vec(),
                // w_record
                (r_len..r_len + w_len).collect_vec(),
                // lk_record
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                // zero_record
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb, 0),
        );

        let layer = Layer::from_circuit_builder(cb, format!("{}_main", Self::name()), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, Some(chip.gkr_circuit())))
    }

    fn generate_fixed_traces(
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _input: &Self::FixedInput,
    ) -> witness::RowMajorMatrix<<E as ExtensionField>::BaseField> {
        unimplemented!()
    }
    fn assign_instances<'a>(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        steps: &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        if steps.is_empty() {
            return Ok([
                witness::RowMajorMatrix::empty(),
                witness::RowMajorMatrix::empty(),
            ]);
        }
        // FIXME selector is the only structural witness
        // this is workaround, as call `construct_circuit` will not initialized selector
        // we can remove this one all opcode unittest migrate to call `build_gkr_iop_circuit`

        assert_eq!(num_structural_witin, 3);
        let selector_r_witin = WitIn { id: 0 };
        let selector_w_witin = WitIn { id: 1 };
        let selector_zero_witin = WitIn { id: 2 };

        let nthreads = max_usable_threads();

        // local read iff it's global write
        let num_local_reads = steps.iter().filter(|s| s.record.is_write).count();
        tracing::debug!(
            "{} local reads / {} local writes in global chip",
            num_local_reads,
            steps.len() - num_local_reads
        );

        let num_instance_per_batch = if steps.len() > 256 {
            steps.len().div_ceil(nthreads)
        } else {
            steps.len()
        }
        .max(1);

        let n = next_pow2_instance_padding(steps.len());
        // compute the input for the binary tree for ec point summation

        let lk_multiplicity = LkMultiplicity::default();
        // *2 because we need to store the internal nodes of binary tree for ec point summation
        let num_rows_padded = 2 * n;

        let mut raw_witin = {
            let matrix_size = num_rows_padded * num_witin;
            let mut value = Vec::with_capacity(matrix_size);
            value.par_extend(
                (0..matrix_size)
                    .into_par_iter()
                    .map(|_| E::BaseField::default()),
            );
            RowMajorMatrix::new(value, num_witin)
        };
        let mut raw_structual_witin = {
            let matrix_size = num_rows_padded * num_structural_witin;
            let mut value = Vec::with_capacity(matrix_size);
            value.par_extend(
                (0..matrix_size)
                    .into_par_iter()
                    .map(|_| E::BaseField::default()),
            );
            RowMajorMatrix::new(value, num_structural_witin)
        };
        let raw_witin_iter = raw_witin.values[0..steps.len() * num_witin]
            .par_chunks_mut(num_instance_per_batch * num_witin);
        let raw_structual_witin_iter = raw_structual_witin.values
            [0..steps.len() * num_structural_witin]
            .par_chunks_mut(num_instance_per_batch * num_structural_witin);

        raw_witin_iter
            .zip_eq(raw_structual_witin_iter)
            .zip_eq(steps.par_chunks(num_instance_per_batch))
            .enumerate()
            .flat_map(|(chunk_idx, ((instances, structural_instance), steps))| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin)
                    .zip_eq(structural_instance.chunks_mut(num_structural_witin))
                    .zip_eq(steps)
                    .enumerate()
                    .map(|(i, ((instance, structural_instance), step))| {
                        let row = chunk_idx * num_instance_per_batch + i;
                        let (sel_r, sel_w) = if row < num_local_reads {
                            (E::BaseField::ONE, E::BaseField::ZERO)
                        } else {
                            (E::BaseField::ZERO, E::BaseField::ONE)
                        };
                        set_val!(structural_instance, selector_r_witin, sel_r);
                        set_val!(structural_instance, selector_w_witin, sel_w);
                        set_val!(structural_instance, selector_zero_witin, E::BaseField::ONE);
                        Self::assign_instance(config, instance, &mut lk_multiplicity, step)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        // assign internal nodes in the binary tree for ec point summation
        let mut cur_layer_points = steps
            .iter()
            .map(|step| step.ec_point.point.clone())
            .enumerate()
            .collect_vec();

        // slope[1,b] = (input[b,0].y - input[b,1].y) / (input[b,0].x - input[b,1].x)
        loop {
            if cur_layer_points.len() <= 1 {
                break;
            }
            // 2b -> b + 2^log_n
            let next_layer_offset = cur_layer_points.first().map(|(i, _)| *i / 2 + n).unwrap();
            cur_layer_points = cur_layer_points
                .par_chunks(2)
                .zip(raw_witin.values[next_layer_offset * num_witin..].par_chunks_mut(num_witin))
                .with_min_len(64)
                .map(|(pair, instance)| {
                    // input[1,b] = affine_add(input[b,0], input[b,1])
                    // the left node is at index 2b, right node is at index 2b+1
                    // the parent node is at index b + 2^n
                    let (o, slope, q) = match pair.len() {
                        2 => {
                            // l = 2b, r = 2b+1
                            let (l, p1) = &pair[0];
                            let (r, p2) = &pair[1];
                            assert_eq!(*r - *l, 1);

                            // parent node idx = b + 2^log2_n
                            let o = n + l / 2;
                            let slope = (&p1.y - &p2.y) * (&p1.x - &p2.x).inverse().unwrap();
                            let q = p1.clone() + p2.clone();

                            (o, slope, q)
                        }
                        1 => {
                            let (l, p) = &pair[0];
                            let o = n + l / 2;
                            (o, SepticExtension::zero(), p.clone())
                        }
                        _ => unreachable!(),
                    };

                    config
                        .x
                        .iter()
                        .chain(config.y.iter())
                        .chain(config.slope.iter())
                        .zip_eq(chain!(
                            q.x.deref().iter(),
                            q.y.deref().iter(),
                            slope.deref().iter(),
                        ))
                        .for_each(|(witin, fe)| {
                            set_val!(instance, *witin, *fe);
                        });

                    (o, q)
                })
                .collect::<Vec<_>>();
        }

        let raw_witin = witness::RowMajorMatrix::new_by_inner_matrix(
            raw_witin,
            InstancePaddingStrategy::Default,
        );
        let raw_structual_witin = witness::RowMajorMatrix::new_by_inner_matrix(
            raw_structual_witin,
            InstancePaddingStrategy::Default,
        );
        Ok([raw_witin, raw_structual_witin])
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ff_ext::{BabyBearExt4, FromUniformBytes, PoseidonField};
    use itertools::Itertools;
    use mpcs::{BasefoldDefault, PolynomialCommitmentScheme, SecurityLevel};
    use p3::babybear::BabyBear;
    use rand::thread_rng;
    use tracing_forest::{ForestLayer, util::LevelFilter};
    use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
    use transcript::BasicTranscript;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::global::{GlobalChip, GlobalChipInput, GlobalRecord},
        scheme::{
            PublicValues, create_backend, create_prover, hal::ProofInput, prover::ZKVMProver,
            septic_curve::SepticPoint, verifier::ZKVMVerifier,
        },
        structs::{ComposedConstrainSystem, PointAndEval, ProgramParams, RAMType, ZKVMProvingKey},
        tables::TableCircuit,
    };
    use multilinear_extensions::mle::IntoMLE;
    use p3::field::PrimeField32;

    type E = BabyBearExt4;
    type F = BabyBear;
    type Perm = <F as PoseidonField>::P;
    type Pcs = BasefoldDefault<E>;

    #[test]
    fn test_global_chip() {
        // default filter
        let default_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::DEBUG.into())
            .from_env_lossy();

        Registry::default()
            .with(ForestLayer::default())
            .with(default_filter)
            .init();

        // init global chip with horizen_rc_consts
        let perm = <F as PoseidonField>::get_default_perm();

        let mut cs = ConstraintSystem::new(|| "global chip test");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (config, gkr_circuit) =
            GlobalChip::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).unwrap();

        // create a bunch of random memory read/write records
        let n_global_reads = 1700;
        let n_global_writes = 1420;
        let global_reads = (0..n_global_reads)
            .map(|i| {
                let addr = i * 8;
                let value = (i + 1) * 8;

                GlobalRecord {
                    addr: addr as u32,
                    ram_type: RAMType::Memory,
                    value: value as u32,
                    shard: 0,
                    local_clk: 0,
                    global_clk: i,
                    is_write: false,
                }
            })
            .collect::<Vec<_>>();

        let global_writes = (0..n_global_writes)
            .map(|i| {
                let addr = i * 8;
                let value = (i + 1) * 8;

                GlobalRecord {
                    addr: addr as u32,
                    ram_type: RAMType::Memory,
                    value: value as u32,
                    shard: 1,
                    local_clk: i,
                    global_clk: i,
                    is_write: true,
                }
            })
            .collect::<Vec<_>>();

        let input = global_writes // local reads
            .into_iter()
            .chain(global_reads) // local writes
            .map(|record| {
                let ec_point = record.to_ec_point::<E, Perm>(&perm);
                GlobalChipInput { record, ec_point }
            })
            .collect::<Vec<_>>();

        let global_ec_sum: SepticPoint<F> = input
            .iter()
            .map(|record| record.ec_point.point.clone())
            .sum();

        let public_value = PublicValues::new(
            0,
            0,
            0,
            0,
            0,
            0,
            vec![0], // dummy
            global_ec_sum
                .x
                .iter()
                .chain(global_ec_sum.y.iter())
                .map(|fe| fe.as_canonical_u32())
                .collect_vec(),
        );

        // assign witness
        let witness = GlobalChip::assign_instances(
            &config,
            cs.num_witin as usize,
            cs.num_structural_witin as usize,
            &[],
            &input,
        )
        .unwrap();

        let composed_cs = ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit,
        };
        let pk = composed_cs.key_gen();

        // create chip proof for global chip
        let pcs_param = Pcs::setup(1 << 20, SecurityLevel::Conjecture100bits).unwrap();
        let (pp, vp) = Pcs::trim(pcs_param, 1 << 20).unwrap();
        let backend = create_backend::<E, Pcs>(20, SecurityLevel::Conjecture100bits);
        let pd = create_prover(backend);

        let zkvm_pk = ZKVMProvingKey::new(pp, vp);
        let zkvm_vk = zkvm_pk.get_vk_slow();
        let zkvm_prover = ZKVMProver::new(zkvm_pk, pd);
        let mut transcript = BasicTranscript::new(b"global chip test");

        let public_input_mles = public_value
            .to_vec::<E>()
            .into_iter()
            .map(|v| Arc::new(v.into_mle()))
            .collect_vec();
        let proof_input = ProofInput {
            witness: witness[0].to_mles().into_iter().map(Arc::new).collect(),
            structural_witness: witness[1].to_mles().into_iter().map(Arc::new).collect(),
            fixed: vec![],
            public_input: public_input_mles.clone(),
            num_instances: vec![n_global_writes as usize, n_global_reads as usize],
            has_ecc_ops: true,
        };
        let mut rng = thread_rng();
        let challenges = [E::random(&mut rng), E::random(&mut rng)];
        let (proof, _, point) = zkvm_prover
            .create_chip_proof(
                "global chip",
                &pk,
                proof_input,
                &mut transcript,
                &challenges,
            )
            .unwrap();

        let mut transcript = BasicTranscript::new(b"global chip test");
        let verifier = ZKVMVerifier::new(zkvm_vk);
        let pi_evals = public_input_mles
            .iter()
            .map(|mle| mle.evaluate(&point[..mle.num_vars()]))
            .collect_vec();
        let vrf_point = verifier
            .verify_opcode_proof(
                "global",
                &pk.vk,
                &proof,
                &pi_evals,
                &mut transcript,
                2,
                &PointAndEval::default(),
                &challenges,
            )
            .expect("verify global chip proof");
        assert_eq!(vrf_point, point);
    }
}
