use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::{Itertools, izip};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::riscv::constants::UINT_LIMBS,
    scheme::constants::MIN_PAR_SIZE,
    set_val,
    structs::RAMType,
    witness::RowMajorMatrix,
};

use super::TableCircuit;

#[derive(Clone, Debug)]
pub struct MemTableConfig {
    addrs: Vec<Fixed>,

    final_v: Vec<WitIn>,
}

impl MemTableConfig {
    const V_LIMBS: usize = UINT_LIMBS + 1; // + 1 for ts

    #[cfg(test)]
    pub const ADDR_RANGE: [usize; 2] = [16, 16];

    #[cfg(not(test))]
    pub const ADDR_RANGE: [usize; 2] = [16, 26];

    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        // a list of fixed address for non-uniform circuit design
        let addrs = (Self::ADDR_RANGE[0]..Self::ADDR_RANGE[1])
            .map(|size| cb.create_fixed(|| format!("addr_{size}",)))
            .collect::<Result<Vec<Fixed>, ZKVMError>>()?;

        let final_v = (0..Self::V_LIMBS)
            .map(|i| cb.create_witin(|| format!("final_v_limb_{i}")))
            .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

        izip!(&addrs, Self::ADDR_RANGE[0]..Self::ADDR_RANGE[1])
            .map(|(addr, size)| {
                let init_table_expr = cb.rlc_chip_record(
                    [
                        vec![(RAMType::Memory as usize).into()],
                        vec![addr.expr()],
                        (0..Self::V_LIMBS)
                            .map(|_| Expression::ZERO)
                            .collect::<Vec<Expression<E>>>(),
                    ]
                    .concat(),
                );
                cb.w_table_record(
                    || format!("init_table_{}", size),
                    1 << size,
                    init_table_expr,
                )?;
                let final_table_expr = cb.rlc_chip_record(
                    [
                        vec![(RAMType::Memory as usize).into()],
                        vec![addr.expr()],
                        final_v.iter().map(|v| v.expr()).collect_vec(),
                    ]
                    .concat(),
                );
                cb.r_table_record(
                    || format!("final_table_{}", size),
                    1 << size,
                    final_table_expr,
                )?;
                Ok(())
            })
            .collect::<Result<(), ZKVMError>>()?;
        Ok(Self { addrs, final_v })
    }

    pub fn gen_init_state(&self, num_fixed: usize) -> Vec<Vec<u32>> {
        assert_eq!(num_fixed, Self::ADDR_RANGE[1] - Self::ADDR_RANGE[0]); // +1 for addr

        let addrs = (Self::ADDR_RANGE[0]..Self::ADDR_RANGE[1])
            .map(|size| (0u32..(1 << size)).map(|i| i << 2).collect_vec())
            .collect_vec(); // riv32

        addrs
    }

    /// TODO consider taking RowMajorMatrix from externally, since both pattern are 1D vector
    /// with that, we can save one allocation cost
    pub fn assign_instances<F: SmallField>(
        &self,
        num_witness: usize,
        final_v: &[u32], // value limb are concated into 1d slice
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        assert_eq!(num_witness, Self::V_LIMBS);
        assert!(final_v.len().is_power_of_two());
        assert_eq!(final_v.len() % Self::V_LIMBS, 0);
        let mut final_table =
            RowMajorMatrix::<F>::new(final_v.len() / Self::V_LIMBS, Self::V_LIMBS);

        final_table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(final_v.into_par_iter().chunks(Self::V_LIMBS))
            .for_each(|(row, v)| {
                self.final_v.iter().zip(v).for_each(|(c, v)| {
                    set_val!(row, c, *v as u64);
                });
            });

        Ok(final_table)
    }
}

pub struct MemCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for MemCircuit<E> {
    type TableConfig = MemTableConfig;
    type FixedInput = ();
    type FixedOutput = Vec<Vec<u32>>;
    type WitnessInput = Vec<u32>;

    fn name() -> String {
        format!("MEM_{:?}", RAMType::Memory)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<MemTableConfig, ZKVMError> {
        cb.namespace(|| Self::name(), |cb| MemTableConfig::construct_circuit(cb))
    }

    // address vector
    fn generate_fixed_traces(
        config: &MemTableConfig,
        num_fixed: usize,
        _input: &Self::FixedInput,
    ) -> Vec<Vec<u32>> {
        config.gen_init_state(num_fixed)
    }

    fn assign_instances(
        config: &MemTableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let mut table = config.assign_instances(num_witin, final_v)?;
        Self::padding_zero(&mut table, num_witin)?;
        Ok(table)
    }
}
