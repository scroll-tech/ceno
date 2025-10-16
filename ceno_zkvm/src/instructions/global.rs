use std::iter::repeat;

use crate::{
    Value,
    chip_handler::general::PublicIOQuery,
    gadgets::{Poseidon2Config, RoundConstants},
    scheme::septic_curve::{SepticExtension, SepticPoint},
    structs::RAMType,
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::{ExtensionField, FieldInto, POSEIDON2_BABYBEAR_WIDTH, SmallField};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::{
    field::{Field, FieldAlgebra},
    symmetric::Permutation,
};
use std::ops::Deref;
use witness::set_val;

use crate::{
    instructions::{Instruction, riscv::constants::UInt},
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
};

// opcode circuit + mem init/final table + global chip:
// have read/write consistency for RAMType::Register and RAMType::Memory
//
// global chip: read from and write into a global set shared
//      among multiple shards
pub struct GlobalConfig<E: ExtensionField, P> {
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
    r_record: WitIn,
    w_record: WitIn,
    x: Vec<WitIn>,
    y: Vec<WitIn>,
    perm_config: Poseidon2Config<E, 16, 7, 1, 4, 13>,
    perm: P,
}

impl<E: ExtensionField, P> GlobalConfig<E, P> {
    // TODO: make `WIDTH`, `HALF_FULL_ROUNDS`, `PARTIAL_ROUNDS` generic parameters
    pub fn configure(
        cb: &mut CircuitBuilder<E>,
        rc: RoundConstants<E::BaseField, 16, 4, 13>,
        perm: P,
    ) -> Result<Self, CircuitBuilderError> {
        let x: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("x{}", i)))
            .collect();
        let y: Vec<WitIn> = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("y{}", i)))
            .collect();
        let addr = cb.create_witin(|| "addr");
        let is_ram_register = cb.create_witin(|| "is_ram_register");
        let value = UInt::new(|| "value", cb)?;
        let shard = cb.create_witin(|| "shard");
        let global_clk = cb.create_witin(|| "global_clk");
        let local_clk = cb.create_witin(|| "local_clk");
        let nonce = cb.create_witin(|| "nonce");
        let is_global_write = cb.create_witin(|| "is_global_write");
        let r_record = cb.create_witin(|| "r_record");
        let w_record = cb.create_witin(|| "w_record");

        let is_ram_reg: Expression<E> = is_ram_register.expr();
        let reg: Expression<E> = RAMType::Register.into();
        let mem: Expression<E> = RAMType::Memory.into();
        let ram_type: Expression<E> = is_ram_reg.clone() * reg + (1 - is_ram_reg) * mem;
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
        input.extend(repeat(E::BaseField::ZERO.expr()).take(16 - input.len()));

        let mut record = vec![];
        record.push(addr.expr());
        record.push(ram_type);
        record.extend(value.memory_expr());
        record.push(shard.expr());
        record.push(local_clk.expr());
        let rlc = cb.rlc_chip_record(record);

        // if is_global_write = 1, then it means we are propagating a local write to global
        // so we need to insert a local read record to cancel out this local write
        // otherwise, we insert a padding value 1 to avoid affecting local memory checking

        cb.assert_bit(|| "is_global_write must be boolean", is_global_write.expr())?;
        // r_record = select(is_global_write, rlc, 1)
        cb.condition_require_equal(
            || "r_record = select(is_global_write, rlc, 1)",
            is_global_write.expr(),
            r_record.expr(),
            rlc.clone(),
            E::BaseField::ONE.expr(),
        )?;

        // if we are reading from global set, then this record should be
        // considered as a initial local write to that address.
        // otherwise, we insert a padding value 1 as if we are not writing anything

        // w_record = select(is_global_write, 1, rlc)
        cb.condition_require_equal(
            || "w_record = select(is_global_write, 1, rlc)",
            is_global_write.expr(),
            w_record.expr(),
            E::BaseField::ONE.expr(),
            rlc,
        )?;

        // local read/write consistency
        cb.condition_require_zero(
            || "is_global_read => local_clk = 0",
            1 - is_global_write.expr(),
            local_clk.expr(),
        )?;
        // TODO: enforce shard = shard_id in the public values

        cb.read_record(
            || "r_record",
            gkr_iop::RAMType::Register, // TODO fixme
            vec![r_record.expr()],
        )?;
        cb.write_record(
            || "w_record",
            gkr_iop::RAMType::Register, // TODO fixme
            vec![w_record.expr()],
        )?;

        // enforces final_sum = \sum_i (x_i, y_i) using ecc quark protocol
        let final_sum = cb.query_global_rw_sum()?;
        cb.ec_sum(
            x.iter().map(|xi| xi.expr()).collect::<Vec<_>>(),
            y.iter().map(|yi| yi.expr()).collect::<Vec<_>>(),
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
            addr,
            is_ram_register,
            value,
            shard,
            global_clk,
            local_clk,
            nonce,
            is_global_write,
            r_record,
            w_record,
            perm_config,
            perm,
        })
    }
}

#[derive(Default)]
pub struct GlobalRecord {
    pub addr: u32,
    pub ram_type: RAMType,
    pub value: u32,
    pub shard: u64,
    pub local_clk: u64,
    pub global_clk: u64,
    pub is_write: bool,
}

impl GlobalRecord {
    pub fn to_ec_point<
        E: ExtensionField,
        P: Permutation<[E::BaseField; POSEIDON2_BABYBEAR_WIDTH]>,
    >(
        &self,
        hasher: &P,
    ) -> (u32, SepticPoint<E::BaseField>) {
        let mut nonce = 0;
        let mut input = [
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
                hasher.permute(input)[0..SEPTIC_EXTENSION_DEGREE].into();
            if let Some(p) = SepticPoint::from_x(x) {
                let y6 = (p.y.0)[SEPTIC_EXTENSION_DEGREE - 1].to_canonical_u64();
                let is_y_in_2nd_half = y6 >= (prime / 2);

                // we negate y if needed
                let negate = match (self.is_write, is_y_in_2nd_half) {
                    (true, false) => true, // write, y in [0, p/2)
                    (false, true) => true, // read, y in [p/2, p)
                    _ => false,
                };

                if negate {
                    return (nonce, -p);
                } else {
                    return (nonce, p);
                }
            } else {
                // try again with different nonce
                nonce += 1;
                input[6] = E::BaseField::from_canonical_u32(nonce);
            }
        }
    }
}

impl From<StepRecord> for GlobalRecord {
    fn from(step: StepRecord) -> Self {
        let mut record = GlobalRecord::default();
        match step.memory_op() {
            None => {
                record.ram_type = RAMType::Register;
            }
            Some(_) => {
                record.ram_type = RAMType::Memory;
            }
        };
        if let Some(op) = step.rs1() {
            // read from previous shard
            record.addr = op.addr.into();
            record.value = op.value;
            record.global_clk = 0; // FIXME
            record.shard = 0; // FIXME
            record.local_clk = 0;
            record.is_write = false;
        } else {
            // propagate local write to global for future shards
            let op = step.rd().unwrap();
            record.addr = op.addr.into();
            record.value = op.value.after;
            record.shard = 0; // FIXME
            record.global_clk = step.cycle();
            record.local_clk = step.cycle();
            record.is_write = true;
        }

        record
    }
}

// This chip is used to manage read/write into a global set
// shared among multiple shards
pub struct GlobalChip<E: ExtensionField, P> {
    rc: RoundConstants<E::BaseField, POSEIDON2_BABYBEAR_WIDTH, 4, 13>,
    perm: P,
}

impl<E: ExtensionField, P: Permutation<[E::BaseField; POSEIDON2_BABYBEAR_WIDTH]> + Send>
    Instruction<E> for GlobalChip<E, P>
{
    type InstructionConfig = GlobalConfig<E, P>;

    fn name() -> String {
        "Global".to_string()
    }

    fn construct_circuit(
        &self,
        cb: &mut CircuitBuilder<E>,
        _param: &crate::structs::ProgramParams,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        let config = GlobalConfig::configure(cb, self.rc.clone(), self.perm.clone())?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        let record: GlobalRecord = _step.clone().into();

        // assign basic fields
        let is_ram_register = match record.ram_type {
            RAMType::Register => 1,
            RAMType::Memory => 0,
            RAMType::GlobalState => unreachable!(),
        };
        set_val!(instance, config.addr, record.addr as u64);
        set_val!(instance, config.is_ram_register, is_ram_register as u64);
        config
            .value
            .assign_limbs(instance, Value::new_unchecked(record.value).as_u16_limbs());
        set_val!(instance, config.shard, record.shard);
        set_val!(instance, config.global_clk, record.global_clk);
        set_val!(instance, config.local_clk, record.local_clk);
        set_val!(instance, config.is_global_write, record.is_write as u64);

        // assign (x, y) and nonce
        let (nonce, point) = record.to_ec_point::<E, P>(&config.perm);
        set_val!(instance, config.nonce, nonce as u64);
        config
            .x
            .iter()
            .chain(config.y.iter())
            .zip_eq((point.x.deref()).iter().chain((point.y.deref()).iter()))
            .for_each(|(witin, fe)| {
                set_val!(instance, *witin, fe.to_canonical_u64());
            });

        // TODO: assign poseidon2 hasher

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff_ext::{BabyBearExt4, PoseidonField};
    use mpcs::{BasefoldDefault, SecurityLevel};
    use p3::babybear::BabyBear;

    use crate::{
        gadgets::horizen_round_consts,
        instructions::global::GlobalChip,
        scheme::{create_backend, create_prover},
    };

    type E = BabyBearExt4;
    type F = BabyBear;
    type PERM = <F as PoseidonField>::P;
    type PCS = BasefoldDefault<E>;

    #[test]
    fn test_global_chip() {
        // init global chip with horizen_rc_consts
        let rc = horizen_round_consts();
        let perm = <F as PoseidonField>::get_default_perm();
        let global_chip = GlobalChip::<E, PERM> { rc, perm };

        // create a bunch of random memory read/write records

        // assign witness

        // create chip proof for global chip
        let backend = create_backend::<E, PCS>(20, SecurityLevel::Conjecture100bits);
        let prover = create_prover(backend);
    }
}
