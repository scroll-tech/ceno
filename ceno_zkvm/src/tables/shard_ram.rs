use std::{iter::repeat_n, marker::PhantomData};

use crate::{
    Value,
    chip_handler::general::PublicValuesQuery,
    e2e::RAMRecord,
    error::ZKVMError,
    gadgets::Poseidon2Config,
    instructions::riscv::constants::UINT_LIMBS,
    scheme::septic_curve::{SepticExtension, SepticPoint},
    structs::{CustomRWTag, ProgramParams, RAMType},
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
use multilinear_extensions::{Expression, ToExpr, WitIn, util::max_usable_threads};
use p3::{
    field::{Field, FieldAlgebra},
    matrix::dense::RowMajorMatrix,
    symmetric::Permutation,
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
    },
    prelude::ParallelSliceMut,
    slice::ParallelSlice,
};
use std::ops::Deref;
use witness::{InstancePaddingStrategy, next_pow2_instance_padding, set_val};

use crate::{instructions::riscv::constants::UInt, scheme::constants::SEPTIC_EXTENSION_DEGREE};

pub(crate) const Y6_LO_TOP_BYTE_LT_BOUND: u64 = 60;

fn shard_ram_ec_point_record<E: ExtensionField>(x: &[WitIn], y: &[WitIn]) -> Vec<Expression<E>> {
    [CustomRWTag::ShardRamEcPoint.expr::<E>()]
        .into_iter()
        .chain(x.iter().map(|w| w.expr()))
        .chain(y.iter().map(|w| w.expr()))
        .collect()
}

/// A record for a read/write into the shard RAM
#[derive(Debug, Clone)]
pub struct ShardRamRecord {
    pub addr: u32,
    pub ram_type: RAMType,
    pub value: u32,
    pub shard: u64,
    pub local_clk: u64,
    pub global_clk: u64,
    pub is_to_write_set: bool,
}

impl From<(&WordAddr, &RAMRecord, bool)> for ShardRamRecord {
    fn from((vma, record, is_to_write_set): (&WordAddr, &RAMRecord, bool)) -> Self {
        let addr = match record.ram_type {
            RAMType::Register => record.reg_id as u32,
            RAMType::Memory => (*vma).into(),
            _ => unreachable!(),
        };
        let (shard, local_clk, global_clk, value) = if is_to_write_set {
            // global write -> local read
            (
                record.shard_id,
                record.shard_cycle,
                record.cycle,
                // local read is for cancel final write value in `Write` set
                record.value,
            )
        } else {
            // global read -> local write
            debug_assert_eq!(record.shard_cycle, 0);
            (
                record.shard_id,
                0,
                record.prev_cycle,
                // local write is for adapting write from previous shard
                record.prev_value.unwrap_or(record.value),
            )
        };

        ShardRamRecord {
            addr,
            ram_type: record.ram_type,
            value,
            shard: shard as u64,
            local_clk,
            global_clk,
            is_to_write_set,
        }
    }
}

/// An EC point corresponding to a cross chunk read/write record
/// whose x-coordinate is derived from Poseidon2 hash of the record
#[derive(Clone, Debug)]
pub struct ECPoint<E: ExtensionField> {
    pub nonce: u32,
    pub point: SepticPoint<E::BaseField>,
}

impl ShardRamRecord {
    pub fn to_ec_point<E: ExtensionField, P: Permutation<Vec<E::BaseField>>>(
        &self,
        hasher: &P,
    ) -> ECPoint<E> {
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
                // Reject cases where y6 = 0 because then the y-sign
                // binding in the circuit cannot distinguish read from write.
                if y6 != 0 {
                    // Strict `>`: `prime / 2 = (p-1)/2` belongs to the lower
                    // half (read region `[1, (p-1)/2]`). Using `>=` would
                    // misclassify it and produce `y6_lo = (p-1)/2` whose top
                    // byte b3 = 60 fails `lookup_ltu_byte(b3, 60, 1)`.
                    let is_y_in_2nd_half = y6 > (prime / 2);

                    // Enforce convention:
                    //   is_to_write_set = 0 (read)  => y6 in [1, (p-1)/2]
                    //   is_to_write_set = 1 (write) => y6 in [(p+1)/2, p-1]
                    let negate = matches!(
                        (self.is_to_write_set, is_y_in_2nd_half),
                        (true, false) | (false, true)
                    );

                    let point = if negate { -p } else { p };

                    return ECPoint { nonce, point };
                }
            }
            // try again with different nonce
            nonce += 1;
            input[6] = E::BaseField::from_canonical_u32(nonce);
        }
    }
}
/// opcode circuit + mem init/final table + local finalize circuit + shard ram circuit
/// shard ram circuit is used to ensure the **local** reads and writes produced by
/// opcode circuits / memory init / memory finalize table / local finalize circuit
/// can balance out.
///
/// 1. For a local memory read record whose previous write is not in the same shard,
///    the shard ram circuit will read it from the **global set** and insert a local write record.
/// 2. For a local memory write record which will **not** be read in the future,
///    the local finalize circuit will consume it by inserting a local read record.
/// 3. For a local memory write record which will be read in the future,
///    the shard ram circuit will insert a local read record and write it to the **global set**.
pub struct ShardRamConfig<E: ExtensionField> {
    pub(crate) addr: WitIn,
    pub(crate) is_ram_register: WitIn,
    pub(crate) value: UInt<E>,
    pub(crate) shard: WitIn,
    pub(crate) global_clk: WitIn,
    pub(crate) local_clk: WitIn,
    pub(crate) nonce: WitIn,
    // if it's write to global set, then insert a local read record
    // s.t. local offline memory checking can cancel out
    // serves as propagating local write to global.
    pub(crate) is_global_write: WitIn,
    pub(crate) x: Vec<WitIn>,
    pub(crate) y: Vec<WitIn>,
    // Byte limbs of `y6_lo`, the helper that binds `y[SEPTIC_EXTENSION_DEGREE - 1]`
    // to `is_global_write` in `configure`.
    pub(crate) y6_lo_bytes: [WitIn; 4],
    pub(crate) perm_config: Poseidon2Config<E, 16, 7, 1, 4, 13>,
}

impl<E: ExtensionField> ShardRamConfig<E> {
    // TODO: make `WIDTH`, `HALF_FULL_ROUNDS`, `PARTIAL_ROUNDS` generic parameters
    pub fn configure(cb: &mut CircuitBuilder<E>) -> Result<Self, CircuitBuilderError> {
        let x: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("x{}", i)))
            .collect();
        let y: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("y{}", i)))
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
        record.push(ram_type.clone());
        record.push(addr.expr());
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
            ram_type.clone(),
            record.clone(),
            cb.rlc_chip_record(record),
        )?;

        let ec_point_record = shard_ram_ec_point_record(&x, &y);
        cb.read_record(
            || "shard_ram_ec_point_in",
            RAMType::Custom,
            ec_point_record.clone(),
        )?;
        cb.write_record(
            || "shard_ram_ec_point_out",
            RAMType::Custom,
            ec_point_record,
        )?;

        // enforces x = poseidon2([addr, ram_type, value[0], value[1], shard, global_clk, nonce, 0, ..., 0])
        for (input_expr, hasher_input) in input.into_iter().zip_eq(perm_config.inputs().into_iter())
        {
            cb.require_equal(|| "poseidon2 input", input_expr, hasher_input)?;
        }
        for (xi, hasher_output) in x.iter().zip(perm_config.output().into_iter()) {
            cb.require_equal(|| "x = poseidon2's output", xi.expr(), hasher_output)?;
        }

        // Bind the sign of y[SEPTIC_EXTENSION_DEGREE - 1] (call it y6) to
        // is_global_write:
        //   is_global_write = 0 (read)  => y6 in [1, (p-1)/2]
        //   is_global_write = 1 (write) => y6 in [(p+1)/2, p-1]
        // y6_lo is witnessed as four byte limbs with the top byte < 60.
        // For BabyBear, (p-1)/2 = 60 * 2^24 exactly, so the byte bound
        // gives y6_lo in [0, (p-1)/2). Branch equality:
        //   read  : y6 = y6_lo + 1
        //   write : y6 + y6_lo + 1 = 0 (mod p)
        // y6 = 0 is the unique fixed point; `to_ec_point` rejects it.
        assert_eq!(
            <E::BaseField as SmallField>::MODULUS_U64,
            0x7800_0001,
            "y6_lo byte bound assumes BabyBear's (p-1)/2 = 60 * 2^24"
        );
        let y6_lo_bytes: [WitIn; 4] =
            std::array::from_fn(|i| cb.create_witin(|| format!("y6_lo_b{i}")));
        for (i, w) in y6_lo_bytes.iter().enumerate().take(3) {
            cb.assert_byte(|| format!("y6_lo_b{i} byte"), w.expr())?;
        }
        // `lookup_ltu_byte(a, b, 1)` asserts `a, b` are bytes and `a < b`.
        cb.lookup_ltu_byte(
            y6_lo_bytes[3].expr(),
            E::BaseField::from_canonical_u64(Y6_LO_TOP_BYTE_LT_BOUND).expr(),
            Expression::ONE,
        )?;
        let y6_lo = y6_lo_bytes[0].expr()
            + y6_lo_bytes[1].expr() * E::BaseField::from_canonical_u64(1 << 8).expr()
            + y6_lo_bytes[2].expr() * E::BaseField::from_canonical_u64(1 << 16).expr()
            + y6_lo_bytes[3].expr() * E::BaseField::from_canonical_u64(1 << 24).expr();
        let y6 = y[SEPTIC_EXTENSION_DEGREE - 1].expr();
        cb.condition_require_equal(
            || "y6 binds to is_global_write",
            is_global_write.expr(),
            y6,
            E::BaseField::from_canonical_u64(<E::BaseField as SmallField>::MODULUS_U64 - 1).expr()
                - y6_lo.clone(),
            y6_lo + Expression::ONE,
        )?;

        Ok(ShardRamConfig {
            x,
            y,
            addr,
            is_ram_register,
            value,
            shard,
            global_clk,
            local_clk,
            nonce,
            is_global_write,
            y6_lo_bytes,
            perm_config,
        })
    }
}

pub struct ShardRamEcTreeConfig<E: ExtensionField> {
    pub(crate) x: Vec<WitIn>,
    pub(crate) y: Vec<WitIn>,
    pub(crate) slope: Vec<WitIn>,
    _marker: PhantomData<E>,
}

impl<E: ExtensionField> ShardRamEcTreeConfig<E> {
    pub fn configure(cb: &mut CircuitBuilder<E>) -> Result<Self, CircuitBuilderError> {
        let x: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("x{i}")))
            .collect();
        let y: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("y{i}")))
            .collect();
        let slope: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("slope{i}")))
            .collect();

        let ec_point_record = shard_ram_ec_point_record(&x, &y);
        cb.read_record(
            || "shard_ram_ec_point_in",
            RAMType::Custom,
            ec_point_record.clone(),
        )?;
        cb.write_record(
            || "shard_ram_ec_point_out",
            RAMType::Custom,
            ec_point_record,
        )?;

        let final_sum = cb.query_global_rw_sum()?;
        cb.ec_sum(
            x.iter().map(|xi| xi.expr()).collect::<Vec<_>>(),
            y.iter().map(|yi| yi.expr()).collect::<Vec<_>>(),
            slope.iter().map(|si| si.expr()).collect::<Vec<_>>(),
            final_sum.into_iter().map(|x| x.expr()).collect::<Vec<_>>(),
        );

        Ok(Self {
            x,
            y,
            slope,
            _marker: PhantomData,
        })
    }
}

/// This chip is used to manage read/write into a global set
/// shared among multiple shards
#[derive(Default)]
pub struct ShardRamCircuit<E> {
    _marker: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub struct ShardRamInput<E: ExtensionField> {
    pub name: &'static str,
    pub record: ShardRamRecord,
    pub ec_point: ECPoint<E>,
}

#[derive(Default)]
pub struct ShardRamEcTreeCircuit<E> {
    _marker: PhantomData<E>,
}

/// Decode `y6_lo` (the byte-decomposed helper bound to `is_global_write` in
/// `ShardRamConfig::configure`) from a witnessed `y6` field element. Mirrors
/// the prover-side derivation done inside the per-row witness assignment;
/// `to_ec_point` guarantees `y6 != 0` and the half-of-field convention, so
/// neither branch underflows.
pub(crate) fn y6_lo_value<E: ExtensionField>(y6: E::BaseField, is_to_write_set: bool) -> u64 {
    let prime = <E::BaseField as SmallField>::MODULUS_U64;
    let y6_u64 = y6.to_canonical_u64();
    if is_to_write_set {
        prime - 1 - y6_u64
    } else {
        y6_u64 - 1
    }
}

impl<E: ExtensionField> ShardRamCircuit<E> {
    fn assign_instance(
        config: &ShardRamConfig<E>,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        input: &ShardRamInput<E>,
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
        set_val!(
            instance,
            config.is_global_write,
            record.is_to_write_set as u64
        );

        // assign (x, y) and nonce
        let ECPoint { nonce, point } = &input.ec_point;
        set_val!(instance, config.nonce, *nonce as u64);
        config
            .x
            .iter()
            .chain(config.y.iter())
            .zip_eq((point.x.deref()).iter().chain((point.y.deref()).iter()))
            .for_each(|(witin, fe)| {
                instance[witin.id as usize] = *fe;
            });

        // y6_lo byte limbs for the y-sign binding constraint in `configure`.
        // `to_ec_point` guarantees y6 != 0 and the half-of-field convention,
        // so the subtraction below never underflows.
        let y6_lo_u64 = y6_lo_value::<E>(
            point.y.0[SEPTIC_EXTENSION_DEGREE - 1],
            record.is_to_write_set,
        );
        for i in 0..4 {
            let b = (y6_lo_u64 >> (8 * i)) & 0xff;
            set_val!(instance, config.y6_lo_bytes[i], b);
        }
        for i in 0..3 {
            let b = (y6_lo_u64 >> (8 * i)) & 0xff;
            lk_multiplicity.assert_const_range(b, 8);
        }
        lk_multiplicity.lookup_ltu_byte((y6_lo_u64 >> 24) & 0xff, Y6_LO_TOP_BYTE_LT_BOUND);

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

        config.perm_config.assign_instance(
            &mut instance[config.perm_config.p3_cols[0].id as usize..],
            input,
        );

        Ok(())
    }

    pub fn extract_ec_sum(
        config: &ShardRamConfig<E>,
        rmm: &witness::RowMajorMatrix<<E as ExtensionField>::BaseField>,
    ) -> SepticPoint<<E as ExtensionField>::BaseField> {
        assert!(rmm.height() >= 2);
        let instance = &rmm[rmm.height() - 2];

        let xy = config
            .x
            .iter()
            .chain(config.y.iter())
            .map(|witin| instance[witin.id as usize])
            .collect_vec();

        let x: SepticExtension<E::BaseField> = xy[0..SEPTIC_EXTENSION_DEGREE].into();
        let y: SepticExtension<E::BaseField> = xy[SEPTIC_EXTENSION_DEGREE..].into();

        SepticPoint::from_affine(x, y)
    }
}

impl<E: ExtensionField> TableCircuit<E> for ShardRamCircuit<E> {
    type TableConfig = ShardRamConfig<E>;
    type FixedInput = ();
    type WitnessInput<'a> = [ShardRamInput<E>];

    fn name() -> String {
        "ShardRamCircuit".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::TableConfig, crate::error::ZKVMError> {
        let config = ShardRamConfig::configure(cb)?;

        Ok(config)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), crate::error::ZKVMError> {
        // create three selectors: selector_r, selector_w, selector_zero
        let selector_r = cb.create_placeholder_structural_witin(|| "selector_r");
        let selector_w = cb.create_placeholder_structural_witin(|| "selector_w");
        let selector_zero = cb.create_placeholder_structural_witin(|| "selector_zero");

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
            Chip::new_from_cb(cb),
        );

        let layer = Layer::from_circuit_builder(cb, format!("{}_main", Self::name()), out_evals);
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

    /// steps format: local reads ++ local writes
    fn assign_instances_with_lk_multiplicities(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        lk_multiplicity: &mut LkMultiplicity,
        steps: &Self::WitnessInput<'_>,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        if steps.is_empty() {
            return Ok([
                witness::RowMajorMatrix::empty(),
                witness::RowMajorMatrix::empty(),
            ]);
        }

        #[cfg(feature = "gpu")]
        if crate::instructions::gpu::config::is_gpu_witgen_enabled() {
            if let Some(result) = Self::try_gpu_assign_instances(
                config,
                num_witin,
                num_structural_witin,
                lk_multiplicity,
                steps,
            )? {
                return Ok(result);
            }
        }
        // FIXME selector is the only structural witness
        // this is workaround, as call `construct_circuit` will not initialized selector
        // we can remove this one all opcode unittest migrate to call `build_gkr_iop_circuit`

        assert_eq!(
            num_structural_witin, 3,
            "ShardRam leaf requires r, w, and zero structural selectors"
        );
        let selector_r_witin = WitIn { id: 0 };
        let selector_w_witin = WitIn { id: 1 };
        let selector_zero_witin = WitIn { id: 2 };

        let nthreads = max_usable_threads();

        // local read iff it's global write
        let num_local_reads = steps
            .iter()
            .take_while(|s| s.record.is_to_write_set)
            .count();
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
        let num_rows_padded = n;

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

impl<E: ExtensionField> ShardRamEcTreeCircuit<E> {
    fn assign_leaf_instance(
        config: &ShardRamEcTreeConfig<E>,
        instance: &mut [E::BaseField],
        input: &ShardRamInput<E>,
    ) {
        config
            .x
            .iter()
            .chain(config.y.iter())
            .zip_eq(
                input
                    .ec_point
                    .point
                    .x
                    .deref()
                    .iter()
                    .chain(input.ec_point.point.y.deref().iter()),
            )
            .for_each(|(witin, fe)| {
                set_val!(instance, *witin, *fe);
            });
    }

    pub fn extract_ec_sum(
        config: &ShardRamEcTreeConfig<E>,
        rmm: &witness::RowMajorMatrix<<E as ExtensionField>::BaseField>,
    ) -> SepticPoint<<E as ExtensionField>::BaseField> {
        assert!(rmm.height() >= 2);
        let instance = &rmm[rmm.height() - 2];

        let xy = config
            .x
            .iter()
            .chain(config.y.iter())
            .map(|witin| instance[witin.id as usize])
            .collect_vec();

        let x: SepticExtension<E::BaseField> = xy[0..SEPTIC_EXTENSION_DEGREE].into();
        let y: SepticExtension<E::BaseField> = xy[SEPTIC_EXTENSION_DEGREE..].into();

        SepticPoint::from_affine(x, y)
    }
}

impl<E: ExtensionField> TableCircuit<E> for ShardRamEcTreeCircuit<E> {
    type TableConfig = ShardRamEcTreeConfig<E>;
    type FixedInput = ();
    type WitnessInput<'a> = [ShardRamInput<E>];

    fn name() -> String {
        "ShardRamEcTreeCircuit".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(ShardRamEcTreeConfig::configure(cb)?)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), ZKVMError> {
        let selector_r = cb.create_placeholder_structural_witin(|| "selector_r");
        let selector_w = cb.create_placeholder_structural_witin(|| "selector_w");
        let selector_ecc_x = cb.create_placeholder_structural_witin(|| "selector_ecc_x");
        let selector_ecc_y = cb.create_placeholder_structural_witin(|| "selector_ecc_y");
        let selector_ecc_s = cb.create_placeholder_structural_witin(|| "selector_ecc_s");
        let selector_ecc_x3 = cb.create_placeholder_structural_witin(|| "selector_ecc_x3");
        let selector_ecc_y3 = cb.create_placeholder_structural_witin(|| "selector_ecc_y3");

        let config = Self::construct_circuit(cb, param)?;

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        cb.cs.r_selector = Some(SelectorType::Prefix(selector_r.expr()));
        cb.cs.w_selector = Some(SelectorType::Prefix(selector_w.expr()));
        cb.cs.ec_bridge_selectors = Some([
            SelectorType::Whole(selector_ecc_x.expr()),
            SelectorType::Whole(selector_ecc_y.expr()),
            SelectorType::Whole(selector_ecc_s.expr()),
            SelectorType::Whole(selector_ecc_x3.expr()),
            SelectorType::Whole(selector_ecc_y3.expr()),
        ]);

        let (out_evals, mut chip) = (
            [
                (0..r_len).collect_vec(),
                (r_len..r_len + w_len).collect_vec(),
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb),
        );

        let layer = Layer::from_circuit_builder(cb, format!("{}_main", Self::name()), out_evals);
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

    fn assign_instances_with_lk_multiplicities(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _lk_multiplicity: &mut LkMultiplicity,
        steps: &Self::WitnessInput<'_>,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        if steps.is_empty() {
            return Ok([
                witness::RowMajorMatrix::empty(),
                witness::RowMajorMatrix::empty(),
            ]);
        }

        assert_eq!(
            num_structural_witin, 7,
            "ShardRam EC tree requires r, w, and 5 EC bridge selectors"
        );
        let selector_r_witin = WitIn { id: 0 };
        let selector_w_witin = WitIn { id: 1 };

        let n = next_pow2_instance_padding(steps.len());
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

        raw_structual_witin
            .values
            .par_chunks_mut(num_structural_witin)
            .for_each(|row| {
                row[2..7].fill(E::BaseField::ONE);
            });

        let num_custom_reads = steps
            .iter()
            .take_while(|step| !step.record.is_to_write_set)
            .count();
        raw_structual_witin.values[0..steps.len() * num_structural_witin]
            .par_chunks_mut(num_structural_witin)
            .enumerate()
            .for_each(|(row_idx, row)| {
                if row_idx < num_custom_reads {
                    set_val!(row, selector_r_witin, E::BaseField::ONE);
                } else {
                    set_val!(row, selector_w_witin, E::BaseField::ONE);
                }
            });

        raw_witin.values[0..steps.len() * num_witin]
            .par_chunks_mut(num_witin)
            .zip_eq(steps.par_iter())
            .for_each(|(instance, step)| Self::assign_leaf_instance(config, instance, step));

        // allocate num_rows_padded size, fill points on first half
        let mut cur_layer_points_buffer: Vec<_> = (0..num_rows_padded)
            .into_par_iter()
            .map(|i| {
                steps
                    .get(i)
                    .map(|step| step.ec_point.point.clone())
                    .unwrap_or_else(SepticPoint::default)
            })
            .collect();
        // raw_witin offset start from n.
        // left node is at b, right node is at b + 1
        // op(left node, right node) = offset + b / 2
        let mut offset = num_rows_padded / 2;
        let mut current_layer_len = cur_layer_points_buffer.len() / 2;

        // slope[1,b] = (input[b,0].y - input[b,1].y) / (input[b,0].x - input[b,1].x)
        loop {
            if current_layer_len <= 1 {
                break;
            }
            let (current_layer, next_layer) =
                cur_layer_points_buffer.split_at_mut(current_layer_len);
            current_layer
                .par_chunks(2)
                .zip_eq(next_layer[..current_layer_len / 2].par_iter_mut())
                .zip(raw_witin.values[offset * num_witin..].par_chunks_mut(num_witin))
                .for_each(|((pair, parent), instance)| {
                    let p1 = &pair[0];
                    let p2 = &pair[1];
                    let (slope, q) = if p2.is_infinity {
                        // input[1,b] = bypass_left(input[b,0], input[b,1])
                        (SepticExtension::zero(), p1.clone())
                    } else {
                        // input[1,b] = affine_add(input[b,0], input[b,1])
                        let slope = (&p1.y - &p2.y) * (&p1.x - &p2.x).inverse().unwrap();
                        let q = p1.clone() + p2.clone();
                        (slope, q)
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
                    *parent = q.clone();
                });
            cur_layer_points_buffer = cur_layer_points_buffer.split_off(current_layer_len);
            current_layer_len /= 2;
            offset += current_layer_len;
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

#[cfg(feature = "gpu")]
impl<E: ExtensionField> ShardRamCircuit<E> {
    fn try_gpu_assign_instances(
        config: &ShardRamConfig<E>,
        num_witin: usize,
        num_structural_witin: usize,
        lk_multiplicity: &mut LkMultiplicity,
        steps: &[ShardRamInput<E>],
    ) -> Result<Option<RMMCollections<E::BaseField>>, ZKVMError> {
        crate::instructions::gpu::chips::shard_ram::try_gpu_assign_shard_ram(
            config,
            num_witin,
            num_structural_witin,
            lk_multiplicity,
            steps,
        )
    }

    #[cfg(feature = "gpu")]
    pub fn try_gpu_assign_instances_from_device(
        config: &ShardRamConfig<E>,
        num_witin: usize,
        num_structural_witin: usize,
        device_records: &ceno_gpu::common::buffer::BufferImpl<'static, u32>,
        num_records: usize,
        num_local_writes: usize,
    ) -> Result<Option<RMMCollections<E::BaseField>>, ZKVMError> {
        crate::instructions::gpu::chips::shard_ram::try_gpu_assign_shard_ram_from_device(
            config,
            num_witin,
            num_structural_witin,
            device_records,
            num_records,
            num_local_writes,
        )
    }
}

#[cfg(test)]
mod tests {
    use either::Either;
    use ff_ext::{BabyBearExt4, FromUniformBytes, PoseidonField};
    use gkr_iop::cpu::{CpuBackend, CpuProver};
    use itertools::Itertools;
    use mpcs::{BasefoldDefault, PolynomialCommitmentScheme, SecurityLevel};
    use p3::{
        babybear::BabyBear,
        field::{FieldAlgebra, PrimeField32},
    };
    use rand::thread_rng;
    use std::sync::Arc;
    use tracing_forest::{ForestLayer, util::LevelFilter};
    use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
    use transcript::BasicTranscript;

    use super::ECPoint;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        scheme::{
            PublicValues,
            constants::SEPTIC_EXTENSION_DEGREE,
            create_backend, create_prover,
            hal::ProofInput,
            mock_prover::MockProver,
            prover::ZKVMProver,
            septic_curve::SepticPoint,
            utils::{WitnessBuildStage, build_main_witness, first_layer_selector_contexts},
        },
        structs::{ComposedConstrainSystem, ProgramParams, RAMType, ZKVMProvingKey},
        tables::{
            RMMCollections, ShardRamCircuit, ShardRamEcTreeCircuit, ShardRamInput, ShardRamRecord,
            TableCircuit,
        },
        witness::LkMultiplicity,
    };
    #[cfg(feature = "gpu")]
    use gkr_iop::gpu::{MultilinearExtensionGpu, get_cuda_hal};

    type E = BabyBearExt4;
    type F = BabyBear;
    type Perm = <F as PoseidonField>::P;
    type Pcs = BasefoldDefault<E>;

    fn shard_ram_test_inputs(read_count: usize, write_count: usize) -> Vec<ShardRamInput<E>> {
        let perm = <F as PoseidonField>::get_default_perm();
        let reads = (0..read_count).map(|i| ShardRamRecord {
            addr: (0x1000 + i * 4) as u32,
            ram_type: RAMType::Memory,
            value: (0x2000 + i) as u32,
            shard: 1,
            local_clk: i as u64 + 1,
            global_clk: i as u64 + 10,
            is_to_write_set: true,
        });
        let writes = (0..write_count).map(|i| ShardRamRecord {
            addr: (0x2000 + i * 4) as u32,
            ram_type: RAMType::Memory,
            value: (0x3000 + i) as u32,
            shard: 2,
            local_clk: 0,
            global_clk: i as u64 + 20,
            is_to_write_set: false,
        });

        reads
            .chain(writes)
            .map(|record| {
                let ec_point = record.to_ec_point::<E, Perm>(&perm);
                ShardRamInput {
                    name: "selector_test",
                    record,
                    ec_point,
                }
            })
            .collect_vec()
    }

    fn assert_selector_column(
        witness: &witness::RowMajorMatrix<F>,
        col: usize,
        ones: std::ops::Range<usize>,
    ) {
        for row in 0..witness.height() {
            let expected = if ones.contains(&row) { F::ONE } else { F::ZERO };
            assert_eq!(witness[row][col], expected, "selector col {col} row {row}");
        }
    }

    fn assert_column_is_binary(witness: &witness::RowMajorMatrix<F>, col: usize) {
        for row in 0..witness.height() {
            let value = witness[row][col];
            assert!(
                value == F::ZERO || value == F::ONE,
                "selector col {col} row {row} is not binary: {value}"
            );
        }
    }

    fn proof_input_for_witness<'a>(
        cs: &ConstraintSystem<E>,
        witness: &'a RMMCollections<F>,
        num_instances: [usize; 2],
        has_ecc_ops: bool,
        public_value: &PublicValues,
    ) -> ProofInput<'a, CpuBackend<E, Pcs>> {
        let witness_mles = witness[0].to_mles().into_iter().map(Arc::new).collect_vec();
        let structural_mles = witness[1].to_mles().into_iter().map(Arc::new).collect_vec();
        let pub_io_evals = cs
            .instance
            .iter()
            .map(|instance| Either::Right(E::from(public_value.query_by_index::<E>(instance.0))))
            .collect_vec();

        ProofInput {
            witness: witness_mles,
            structural_witness: structural_mles,
            fixed: vec![],
            pi: pub_io_evals,
            num_instances,
            has_ecc_ops,
        }
    }

    fn assert_inactive_rows_are_one(
        records: &[Arc<multilinear_extensions::mle::MultilinearExtension<'_, E>>],
        range: std::ops::Range<usize>,
        inactive_rows: impl IntoIterator<Item = usize>,
    ) {
        let inactive_rows = inactive_rows.into_iter().collect_vec();
        for record_idx in range {
            let evals = records[record_idx].get_ext_field_vec();
            for &row in &inactive_rows {
                assert_eq!(evals[row], E::ONE, "record {record_idx} row {row}");
            }
        }
    }

    fn assert_record_rows_match(
        left: &Arc<multilinear_extensions::mle::MultilinearExtension<'_, E>>,
        left_rows: std::ops::Range<usize>,
        right: &Arc<multilinear_extensions::mle::MultilinearExtension<'_, E>>,
        right_rows: std::ops::Range<usize>,
        label: &str,
    ) {
        assert_eq!(left_rows.len(), right_rows.len(), "{label} row count");
        let left_evals = left.get_ext_field_vec();
        let right_evals = right.get_ext_field_vec();
        for (left_row, right_row) in left_rows.zip(right_rows) {
            assert_eq!(
                left_evals[left_row], right_evals[right_row],
                "{label}: left row {left_row}, right row {right_row}"
            );
        }
    }

    #[test]
    fn test_shard_ram_split_selectors_and_tower_padding() {
        let read_count = 2;
        let write_count = 3;
        let input = shard_ram_test_inputs(read_count, write_count);
        let ec_tree_input = input
            .iter()
            .filter(|access| !access.record.is_to_write_set)
            .chain(input.iter().filter(|access| access.record.is_to_write_set))
            .cloned()
            .collect_vec();

        let global_ec_sum: SepticPoint<F> = input
            .iter()
            .map(|record| record.ec_point.point.clone())
            .sum();
        let mut shard_rw_sum = [0u32; SEPTIC_EXTENSION_DEGREE * 2];
        for (i, fe) in global_ec_sum
            .x
            .iter()
            .chain(global_ec_sum.y.iter())
            .enumerate()
        {
            shard_rw_sum[i] = fe.as_canonical_u32();
        }
        let public_value = PublicValues::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [0; 8], shard_rw_sum);

        let mut leaf_cs = ConstraintSystem::new(|| "shard ram selector leaf");
        let mut leaf_cb = CircuitBuilder::new(&mut leaf_cs);
        let (leaf_config, leaf_gkr_circuit) =
            ShardRamCircuit::<E>::build_gkr_iop_circuit(&mut leaf_cb, &ProgramParams::default())
                .unwrap();
        let leaf_witness = ShardRamCircuit::<E>::assign_instances_with_lk_multiplicities(
            &leaf_config,
            leaf_cs.num_witin as usize,
            leaf_cs.num_structural_witin as usize,
            &mut LkMultiplicity::default(),
            &input,
        )
        .unwrap();

        assert_selector_column(&leaf_witness[1], 0, 0..read_count);
        assert_selector_column(&leaf_witness[1], 1, read_count..read_count + write_count);
        assert_selector_column(&leaf_witness[1], 2, 0..read_count + write_count);
        for col in 0..leaf_witness[1].width() {
            assert_column_is_binary(&leaf_witness[1], col);
        }

        let leaf_composed = ComposedConstrainSystem {
            zkvm_v1_css: leaf_cs,
            gkr_circuit: leaf_gkr_circuit,
        };
        let leaf_gkr = leaf_composed.gkr_circuit.as_ref().unwrap();
        let leaf_selector_ctxs =
            first_layer_selector_contexts(&leaf_composed, leaf_gkr, [read_count, write_count], 3);
        assert_eq!(leaf_selector_ctxs[0].offset, 0);
        assert_eq!(leaf_selector_ctxs[0].num_instances, read_count);
        assert_eq!(leaf_selector_ctxs[1].offset, read_count);
        assert_eq!(leaf_selector_ctxs[1].num_instances, write_count);

        let leaf_proof_input = proof_input_for_witness(
            &leaf_composed.zkvm_v1_css,
            &leaf_witness,
            [read_count, write_count],
            false,
            &public_value,
        );
        let leaf_records =
            build_main_witness::<E, Pcs, CpuBackend<E, Pcs>, CpuProver<CpuBackend<E, Pcs>>>(
                &leaf_composed,
                &leaf_proof_input,
                &[E::ONE, E::from_canonical_u32(7)],
                WitnessBuildStage::Tower,
            );
        let leaf_r_len = leaf_composed.zkvm_v1_css.r_expressions.len()
            + leaf_composed.zkvm_v1_css.r_table_expressions.len();
        let leaf_w_len = leaf_composed.zkvm_v1_css.w_expressions.len()
            + leaf_composed.zkvm_v1_css.w_table_expressions.len();
        assert_inactive_rows_are_one(
            &leaf_records,
            0..leaf_r_len,
            read_count..leaf_witness[0].height(),
        );
        assert_inactive_rows_are_one(
            &leaf_records,
            leaf_r_len..leaf_r_len + leaf_w_len,
            (0..read_count).chain(read_count + write_count..leaf_witness[0].height()),
        );

        let mut ec_tree_cs = ConstraintSystem::new(|| "shard ram selector ec tree");
        let mut ec_tree_cb = CircuitBuilder::new(&mut ec_tree_cs);
        let (ec_tree_config, ec_tree_gkr_circuit) =
            ShardRamEcTreeCircuit::<E>::build_gkr_iop_circuit(
                &mut ec_tree_cb,
                &ProgramParams::default(),
            )
            .unwrap();
        let ec_tree_witness = ShardRamEcTreeCircuit::<E>::assign_instances_with_lk_multiplicities(
            &ec_tree_config,
            ec_tree_cs.num_witin as usize,
            ec_tree_cs.num_structural_witin as usize,
            &mut LkMultiplicity::default(),
            &ec_tree_input,
        )
        .unwrap();

        assert_selector_column(&ec_tree_witness[1], 0, 0..write_count);
        assert_selector_column(
            &ec_tree_witness[1],
            1,
            write_count..write_count + read_count,
        );
        for col in 0..ec_tree_witness[1].width() {
            assert_column_is_binary(&ec_tree_witness[1], col);
        }
        for col in 2..ec_tree_witness[1].width() {
            assert_selector_column(&ec_tree_witness[1], col, 0..ec_tree_witness[1].height());
        }

        let ec_tree_composed = ComposedConstrainSystem {
            zkvm_v1_css: ec_tree_cs,
            gkr_circuit: ec_tree_gkr_circuit,
        };
        let ec_tree_gkr = ec_tree_composed.gkr_circuit.as_ref().unwrap();
        let ec_tree_selector_ctxs = first_layer_selector_contexts(
            &ec_tree_composed,
            ec_tree_gkr,
            [write_count, read_count],
            4,
        );
        assert_eq!(ec_tree_selector_ctxs[0].offset, 0);
        assert_eq!(ec_tree_selector_ctxs[0].num_instances, write_count);
        assert_eq!(ec_tree_selector_ctxs[1].offset, write_count);
        assert_eq!(ec_tree_selector_ctxs[1].num_instances, read_count);

        let ec_tree_proof_input = proof_input_for_witness(
            &ec_tree_composed.zkvm_v1_css,
            &ec_tree_witness,
            [write_count, read_count],
            true,
            &public_value,
        );
        let ec_tree_records =
            build_main_witness::<E, Pcs, CpuBackend<E, Pcs>, CpuProver<CpuBackend<E, Pcs>>>(
                &ec_tree_composed,
                &ec_tree_proof_input,
                &[E::ONE, E::from_canonical_u32(7)],
                WitnessBuildStage::Tower,
            );
        let ec_tree_r_len = ec_tree_composed.zkvm_v1_css.r_expressions.len()
            + ec_tree_composed.zkvm_v1_css.r_table_expressions.len();
        let ec_tree_w_len = ec_tree_composed.zkvm_v1_css.w_expressions.len()
            + ec_tree_composed.zkvm_v1_css.w_table_expressions.len();
        assert_inactive_rows_are_one(
            &ec_tree_records,
            0..ec_tree_r_len,
            write_count..ec_tree_witness[0].height(),
        );
        assert_inactive_rows_are_one(
            &ec_tree_records,
            ec_tree_r_len..ec_tree_r_len + ec_tree_w_len,
            (0..write_count).chain(write_count + read_count..ec_tree_witness[0].height()),
        );

        let leaf_custom_read = &leaf_records[leaf_r_len - 1];
        let leaf_custom_write = &leaf_records[leaf_r_len + leaf_w_len - 1];
        let ec_tree_custom_read = &ec_tree_records[ec_tree_r_len - 1];
        let ec_tree_custom_write = &ec_tree_records[ec_tree_r_len + ec_tree_w_len - 1];
        assert_record_rows_match(
            leaf_custom_read,
            0..read_count,
            ec_tree_custom_write,
            write_count..write_count + read_count,
            "leaf read vs ec-tree write",
        );
        assert_record_rows_match(
            leaf_custom_write,
            read_count..read_count + write_count,
            ec_tree_custom_read,
            0..write_count,
            "leaf write vs ec-tree read",
        );
    }

    #[test]
    fn test_shard_ram_circuit() {
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
            ShardRamCircuit::build_gkr_iop_circuit(&mut cb, &ProgramParams::default()).unwrap();

        // create a bunch of random memory read/write records
        let n_global_reads = 170000;
        let n_global_writes = 1420;
        let global_reads = (0..n_global_reads)
            .map(|i| {
                let addr = i * 8;
                let value = (i + 1) * 8;

                ShardRamRecord {
                    addr: addr as u32,
                    ram_type: RAMType::Memory,
                    value: value as u32,
                    shard: 0,
                    local_clk: 0,
                    global_clk: i,
                    is_to_write_set: false,
                }
            })
            .collect::<Vec<_>>();

        let global_writes = (0..n_global_writes)
            .map(|i| {
                let addr = i * 8;
                let value = (i + 1) * 8;

                ShardRamRecord {
                    addr: addr as u32,
                    ram_type: RAMType::Memory,
                    value: value as u32,
                    shard: 1,
                    local_clk: i,
                    global_clk: i,
                    is_to_write_set: true,
                }
            })
            .collect::<Vec<_>>();

        let input = global_writes // local reads
            .into_iter()
            .chain(global_reads) // local writes
            .map(|record| {
                let ec_point = record.to_ec_point::<E, Perm>(&perm);
                ShardRamInput {
                    name: "dummy_test",
                    record,
                    ec_point,
                }
            })
            .collect::<Vec<_>>();

        let global_ec_sum: SepticPoint<F> = input
            .iter()
            .map(|record| record.ec_point.point.clone())
            .sum();

        let mut shard_rw_sum = [0u32; SEPTIC_EXTENSION_DEGREE * 2];
        for (i, fe) in global_ec_sum
            .x
            .iter()
            .chain(global_ec_sum.y.iter())
            .enumerate()
        {
            shard_rw_sum[i] = fe.as_canonical_u32();
        }

        let public_value = PublicValues::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [0; 8], shard_rw_sum);

        // assign witness
        let mut lk_multiplicity = LkMultiplicity::default();
        let witness = ShardRamCircuit::assign_instances_with_lk_multiplicities(
            &config,
            cs.num_witin as usize,
            cs.num_structural_witin as usize,
            &mut lk_multiplicity,
            &input,
        )
        .unwrap();

        let mut ec_tree_cs = ConstraintSystem::new(|| "global ec tree chip test");
        let mut ec_tree_cb = CircuitBuilder::new(&mut ec_tree_cs);
        let (ec_tree_config, _ec_tree_gkr_circuit) = ShardRamEcTreeCircuit::build_gkr_iop_circuit(
            &mut ec_tree_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let ec_tree_input = input
            .iter()
            .filter(|access| !access.record.is_to_write_set)
            .chain(input.iter().filter(|access| access.record.is_to_write_set))
            .cloned()
            .collect_vec();
        let ec_tree_witness = ShardRamEcTreeCircuit::assign_instances_with_lk_multiplicities(
            &ec_tree_config,
            ec_tree_cb.cs.num_witin as usize,
            ec_tree_cb.cs.num_structural_witin as usize,
            &mut LkMultiplicity::default(),
            &ec_tree_input,
        )
        .unwrap();

        // EC accumulation lives in the split EC tree chip.
        assert_eq!(
            global_ec_sum,
            ShardRamEcTreeCircuit::extract_ec_sum(&ec_tree_config, &ec_tree_witness[0])
        );
        MockProver::<E>::assert_satisfied_raw(
            &ec_tree_cb,
            ec_tree_witness.clone(),
            &[],
            Some([E::random(&mut thread_rng()), E::random(&mut thread_rng())]),
            None,
        );

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
        let zkvm_prover = ZKVMProver::new(zkvm_pk.into(), pd);
        let mut transcript = BasicTranscript::new(b"global chip test");

        let pub_io_evals = pk
            .get_cs()
            .zkvm_v1_css
            .instance
            .iter()
            .map(|instance| Either::Right(E::from(public_value.query_by_index::<E>(instance.0))))
            .collect_vec();

        #[cfg(not(feature = "gpu"))]
        let (witness_mles, structural_mles) = {
            (
                witness[0].to_mles().into_iter().map(Arc::new).collect(),
                witness[1].to_mles().into_iter().map(Arc::new).collect(),
            )
        };
        #[cfg(feature = "gpu")]
        let (witness_mles, structural_mles) = {
            let cuda_hal = get_cuda_hal().unwrap();
            let witness_cpu: Vec<_> = witness[0].to_mles();
            let structural_cpu: Vec<_> = witness[1].to_mles();
            (
                witness_cpu
                    .iter()
                    .map(|v| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, v)))
                    .collect_vec(),
                structural_cpu
                    .iter()
                    .map(|v| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, v)))
                    .collect_vec(),
            )
        };

        let proof_input = ProofInput {
            witness: witness_mles,
            structural_witness: structural_mles,
            fixed: vec![],
            pi: pub_io_evals,
            num_instances: [n_global_writes as usize, n_global_reads as usize],
            has_ecc_ops: false,
        };
        let mut rng = thread_rng();
        let challenges = [E::random(&mut rng), E::random(&mut rng)];
        let mut task = crate::scheme::scheduler::ChipTask {
            task_id: 0,
            circuit_name: ShardRamCircuit::<E>::name(),
            circuit_idx: 0,
            pk: &pk,
            input: proof_input,
            estimated_memory_bytes: 0,
            booked_memory_bytes: 0,
            has_witness_or_fixed: true,
            challenges,
            witness_trace_idx: None,
            #[cfg(feature = "gpu")]
            witness_trace_rows: None,
            num_witin: 0,
            structural_rmm: None,
        };
        let (_proof, _main_job) = zkvm_prover
            .create_chip_proof(&mut task, &mut transcript)
            .unwrap();
    }

    /// Drive a single ShardRam row through the full `configure` +
    /// `assign_instances` pipeline and validate with `MockProver`.
    ///
    /// * The honest witness satisfies every assert-zero and lookup
    ///   constraint MockProver checks.
    /// * Negating the EC point but reusing the original record causes
    ///   `assign_instance` to derive `y6_lo` such that the algebraic
    ///   branch equality still holds, but the top byte
    ///   `b3 = (y6_lo >> 24) & 0xff` lands in `[60, 256)`. The query
    ///   `(Ltu, b3, 60, 1)` is missing from the LTU table (which only
    ///   carries `(Ltu, b3, 60, 0)` for `b3 >= 60`), so the
    ///   `lookup_Ltu` constraint rejects the tampered row.
    #[test]
    fn test_shard_ram_y_sign_circuit_rejects_negation() {
        let perm = <F as PoseidonField>::get_default_perm();

        let mut cs = ConstraintSystem::new(|| "y_sign");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let (config, _gkr) =
            ShardRamCircuit::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural = cb.cs.num_structural_witin as usize;
        // Pass a concrete challenge so `assert_with_expected_errors` routes
        // through `run_with_challenge`; the no-challenge `run` path drops
        // `structural_witin` and ShardRam relies on `selector_zero` to gate
        // its lookup queries.
        let mut rng = thread_rng();
        let challenge = [E::random(&mut rng), E::random(&mut rng)];

        for is_to_write_set in [true, false] {
            let record = ShardRamRecord {
                addr: 0x1000,
                ram_type: RAMType::Memory,
                value: 0x1234_5678,
                shard: if is_to_write_set { 1 } else { 2 },
                local_clk: if is_to_write_set { 7 } else { 0 },
                global_clk: 13,
                is_to_write_set,
            };
            let ec = record.to_ec_point::<E, Perm>(&perm);

            // Honest row: every constraint MockProver checks must be
            // satisfied.
            let honest = [ShardRamInput {
                name: "honest",
                record: record.clone(),
                ec_point: ec.clone(),
            }];
            let mut honest_lkm = LkMultiplicity::default();
            let honest_witness = ShardRamCircuit::<E>::assign_instances_with_lk_multiplicities(
                &config,
                num_witin,
                num_structural,
                &mut honest_lkm,
                &honest,
            )
            .unwrap();
            MockProver::<E>::assert_satisfied_raw(&cb, honest_witness, &[], Some(challenge), None);

            // Tampered row: negate the EC point. `assign_instance` re-derives
            // `y6_lo` from the witnessed `y6`, keeping the branch equality
            // intact, so only the `lookup_Ltu` byte bound catches the wrong
            // sign.
            let tampered = [ShardRamInput {
                name: "tampered",
                record,
                ec_point: ECPoint {
                    nonce: ec.nonce,
                    point: -ec.point,
                },
            }];
            let mut tampered_lkm = LkMultiplicity::default();
            let [w, sw] = ShardRamCircuit::<E>::assign_instances_with_lk_multiplicities(
                &config,
                num_witin,
                num_structural,
                &mut tampered_lkm,
                &tampered,
            )
            .unwrap();
            MockProver::<E>::assert_with_expected_errors(
                &cb,
                &[],
                &w.to_mles().into_iter().map(|v| v.into()).collect_vec(),
                &sw.to_mles().into_iter().map(|v| v.into()).collect_vec(),
                &[],
                &["lookup_Ltu"],
                Some(challenge),
                None,
            );
        }
    }
}
