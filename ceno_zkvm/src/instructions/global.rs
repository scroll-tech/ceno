use std::iter::repeat;

use crate::{
    chip_handler::general::PublicIOQuery,
    gadgets::{Poseidon2Config, RoundConstants},
    structs::RAMType,
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;

use crate::{
    instructions::{Instruction, riscv::constants::UInt},
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
};

// opcode circuit + mem init/final table + global chip:
// have read/write consistency for RAMType::Register and RAMType::Memory
//
// global chip: read from and write into a global set shared
//      among multiple shards
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
    r_record: WitIn,
    w_record: WitIn,
    x: Vec<WitIn>,
    y: Vec<WitIn>,
    poseidon2: Poseidon2Config<E, 16, 7, 1, 4, 13>,
}

impl<E: ExtensionField> GlobalConfig<E> {
    // TODO: make `WIDTH`, `HALF_FULL_ROUNDS`, `PARTIAL_ROUNDS` generic parameters
    pub fn configure(
        cb: &mut CircuitBuilder<E>,
        rc: RoundConstants<E::BaseField, 16, 4, 13>,
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
        let hasher = Poseidon2Config::construct(cb, rc);

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
        for (input_expr, hasher_input) in input.into_iter().zip_eq(hasher.inputs().into_iter()) {
            cb.require_equal(|| "poseidon2 input", input_expr, hasher_input)?;
        }
        for (xi, hasher_output) in x.iter().zip(hasher.output().into_iter()) {
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
            poseidon2: hasher,
        })
    }
}

// This chip is used to manage read/write into a global set
// shared among multiple shards
pub struct GlobalChip<E: ExtensionField> {
    rc: RoundConstants<E::BaseField, 16, 4, 13>,
}

impl<E: ExtensionField> Instruction<E> for GlobalChip<E> {
    type InstructionConfig = GlobalConfig<E>;

    fn name() -> String {
        "Global".to_string()
    }

    fn construct_circuit(
        &self,
        cb: &mut CircuitBuilder<E>,
        _param: &crate::structs::ProgramParams,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        let config = GlobalConfig::configure(cb, self.rc.clone())?;

        Ok(config)
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        // assign (x, y)

        // assign [addr, ram_type, value, shard, clk, is_write]

        // assign poseidon2 hasher

        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_global_chip() {
        // Test the GlobalChip functionality here

        // init global chip with horizen_rc_consts

        // create a bunch of random memory read/write records

        // assign witness

        // create chip proof for global chip
    }
}
