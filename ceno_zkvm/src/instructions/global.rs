use std::iter::repeat;

use crate::{
    chip_handler::general::PublicIOQuery,
    gadgets::{Poseidon2Config, RoundConstants},
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{ToExpr, WitIn};
use p3::field::FieldAlgebra;

use crate::{
    instructions::{Instruction, riscv::constants::UInt},
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
};

// opcode circuit + mem init/final table + global chip:
// have read/write consistency for RAMType::Register
// and RAMType::Memory
//
// global chip: read from and write into a global set shared
//      among multiple shards
pub struct GlobalConfig<E: ExtensionField> {
    addr: WitIn,
    ram_type: WitIn,
    value: UInt<E>,
    shard: WitIn,
    clk: WitIn,
    is_write: WitIn,
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
        let ram_type = cb.create_witin(|| "ram_type");
        let value = UInt::new(|| "value", cb)?;
        let shard = cb.create_witin(|| "shard");
        let clk = cb.create_witin(|| "clk");
        let is_write = cb.create_witin(|| "is_write");

        // TODO: support other field
        let hasher = Poseidon2Config::construct(cb, rc);

        let mut input = vec![];
        input.push(addr.expr());
        input.push(ram_type.expr());
        // memory expr has same number of limbs as register expr
        input.extend(value.memory_expr());
        input.push(shard.expr());
        input.push(clk.expr());
        input.extend(repeat(E::BaseField::ZERO.expr()).take(16 - 6));

        // enforces final_sum = \sum_i (x_i, y_i) using ecc quark protocol
        let final_sum = cb.query_global_rw_sum()?;
        cb.ec_sum(
            x.iter().map(|xi| xi.expr()).collect::<Vec<_>>(),
            y.iter().map(|yi| yi.expr()).collect::<Vec<_>>(),
            final_sum.into_iter().map(|x| x.expr()).collect::<Vec<_>>(),
        );

        // enforces x = poseidon2([addr, ram_type, value[0], value[1], shard, clk, 0])
        for (input_expr, hasher_input) in input.into_iter().zip(hasher.inputs().into_iter()) {
            // TODO: replace with cb.require_equal()
            cb.require_zero(|| "poseidon2 input", input_expr - hasher_input)?;
        }
        for (xi, hasher_output) in x.iter().zip(hasher.output().into_iter()) {
            cb.require_zero(|| "poseidon2 output", xi.expr() - hasher_output)?;
        }

        // TODO: enforce is_write is boolean
        // TODO: enforce y < p/2 if is_write = 1
        //       enforce p/2 <= y < p if is_write = 0

        Ok(GlobalConfig {
            x,
            y,
            addr,
            ram_type,
            value,
            shard,
            clk,
            is_write,
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
