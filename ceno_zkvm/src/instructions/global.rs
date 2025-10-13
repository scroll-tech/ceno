use crate::gadgets::{Poseidon2BabyBearConfig, horizen_round_consts};
use ff_ext::{BabyBearExt4, ExtensionField};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;

use crate::{
    instructions::{Instruction, riscv::constants::UInt},
    scheme::constants::SEPTIC_EXTENSION_DEGREE,
};

// opcode circuit + mem init/final table + mem local chip: consistency RAMType::Register / Memory

// mem local <-> global
// precompile <-> global
pub struct GlobalConfig<E: ExtensionField> {
    addr: WitIn,
    ram_type: WitIn,
    value: UInt<E>,
    shard: WitIn,
    clk: WitIn,
    is_write: WitIn,
    x: Vec<WitIn>,
    y: Vec<WitIn>,
    poseidon2: Poseidon2BabyBearConfig,
}

impl<E: ExtensionField> GlobalConfig<E> {
    pub fn config(cb: &mut CircuitBuilder<E>) -> Result<Self, CircuitBuilderError> {
        let x = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("x{}", i)))
            .collect();
        let y = (0..SEPTIC_EXTENSION_DEGREE)
            .map(|i| cb.create_witin(|| format!("y{}", i)))
            .collect();
        let addr = cb.create_witin(|| "addr");
        let ram_type = cb.create_witin(|| "ram_type");
        let value = UInt::new(|| "value", cb)?;
        let shard = cb.create_witin(|| "shard");
        let clk = cb.create_witin(|| "clk");
        let is_write = cb.create_witin(|| "is_write");

        let rc = horizen_round_consts();
        let cb: &mut CircuitBuilder<'_, BabyBearExt4> = unsafe { std::mem::transmute(cb) };
        let hasher = Poseidon2BabyBearConfig::construct(cb, rc);

        let mut input = vec![];
        input.push(addr.expr());
        input.push(ram_type.expr());
        // memory expr has same number of limbs as register expr
        input.extend(value.memory_expr());
        input.push(shard.expr());
        input.push(clk.expr());

        for (input_expr, hasher_input) in input.into_iter().zip(hasher.inputs().into_iter()) {
            // TODO: replace with cb.require_equal()
            cb.require_zero(|| "poseidon2 input", input_expr - hasher_input);
        }

        // TODO: enforce x = poseidon2([addr, ram_type, value[0], value[1], shard, clk])
        // TODO: enforce \sum_i (xi, yi) = ecc_sum
        // TODO: output ecc_sum as public values

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
pub struct GlobalChip {}

impl<E: ExtensionField> Instruction<E> for GlobalChip {
    type InstructionConfig = GlobalConfig<E>;

    fn name() -> String {
        "Global".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _param: &crate::structs::ProgramParams,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        let config = GlobalConfig::config(cb)?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_global_chip() {
        // Test the GlobalChip functionality here
    }
}
