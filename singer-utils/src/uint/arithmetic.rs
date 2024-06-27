use crate::chip_handler::RangeChipOperations;
use crate::error::UtilError;
use crate::uint::uint::UInt;
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{Cell, CellId, CircuitBuilder};

impl<const M: usize, const C: usize> UInt<M, C> {
    /// Little-endian addition.
    /// Assumes users will check the correct range of the result themselves.
    // Addition of A + B with limbs [a, b, c] and [d, e, f] respectively
    //
    // cell_modulo = 2^C
    // addend_0 - a                 b                   c
    // addend_1 - d                 e                   f
    //            --------------------------------------------------
    // result   - (a + d) % 2^C    (b + e) % 2^C       (c + f) % 2^C
    // carry    - (a + d) // 2^C   (b + e) // 2^C      (c + f) % 2^C
    //
    // every limb in addend_0 and addend_1 exists in the range [0, ..., 2^C - 1]
    // after summing two limb values, the result exists in [0, ..., 2^(C+1) - 2]
    // the carry value is either 0 or 1,
    // it cannot be >= 2 as that will require result value >= 2^(C+1)
    //
    // assuming result range check, there is a unique carry vector that makes all
    // constraint pass.
    // if a + b > max_cell_value then carry must be set to 1 (if not range check fails)
    // if a + b <= max_cell_value then carry must be set to 0 (if not range check fails)
    //
    // NOTE: this function doesn't perform the required range check!
    pub fn add_unsafe<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        addend_0: &UInt<M, C>,
        addend_1: &UInt<M, C>,
        carry: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let result: UInt<M, C> = circuit_builder
            .create_cells(Self::N_OPERAND_CELLS)
            .try_into()?;

        for i in 0..Self::N_OPERAND_CELLS {
            let (a, b, result) = (addend_0.values[i], addend_1.values[i], result.values[i]);

            // result = a + b - overflow_carry + last_carry
            circuit_builder.add(result, a, E::BaseField::ONE);
            circuit_builder.add(result, b, E::BaseField::ONE);
            Self::handle_carry(result, circuit_builder, i, carry);
        }

        Ok(result)
    }

    /// Little-endian addition.
    pub fn add<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        addend_0: &UInt<M, C>,
        addend_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let carry = Self::extract_carry_add_sub(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_result = Self::add_unsafe(circuit_builder, addend_0, addend_1, carry)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Add a constant value to a `UInt<M, C>` instance
    /// Assumes users will check the correct range of the result themselves.
    pub fn add_const_unsafe<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        addend_0: &UInt<M, C>,
        constant: E::BaseField,
        carry: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let result: UInt<M, C> = circuit_builder
            .create_cells(Self::N_OPERAND_CELLS)
            .try_into()?;

        // add constant to the first limb
        circuit_builder.add_const(result.values[0], constant);

        // cascade carry
        for i in 0..Self::N_OPERAND_CELLS {
            let (a, result) = (addend_0.values[i], result.values[i]);

            circuit_builder.add(result, a, E::BaseField::ONE);
            Self::handle_carry(result, circuit_builder, i, carry);
        }

        Ok(result)
    }

    /// Add a constant value to a `UInt<M, C>` instance
    pub fn add_const<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        addend_0: &UInt<M, C>,
        constant: E::BaseField,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let carry = Self::extract_carry_add_sub(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_result = Self::add_const_unsafe(circuit_builder, addend_0, constant, carry)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Add a constant value to a `UInt<M, C>` instance
    /// Assumes that addition leads to no overflow.
    pub fn add_const_no_overflow<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        addend_0: &UInt<M, C>,
        constant: E::BaseField,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let carry = Self::extract_carry_no_overflow_add_sub(witness);
        let range_values = Self::extract_range_values_no_overflow(witness);
        let computed_result = Self::add_const_unsafe(circuit_builder, addend_0, constant, carry)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Adds a single cell value to a `UInt<M, C>` instance
    /// Assumes users will check the correct range of the result and
    pub fn add_cell_unsafe<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        addend_0: &UInt<M, C>,
        addend_1: CellId,
        carry: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let result: UInt<M, C> = circuit_builder
            .create_cells(Self::N_OPERAND_CELLS)
            .try_into()?;

        // add small_value to the first limb
        circuit_builder.add(result.values[0], addend_1, E::BaseField::ONE);

        // cascade carry
        for i in 0..Self::N_OPERAND_CELLS {
            let (a, result) = (addend_0.values[i], result.values[i]);

            circuit_builder.add(result, a, E::BaseField::ONE);
            Self::handle_carry(result, circuit_builder, i, carry);
        }

        Ok(result)
    }

    /// Adds a single cell value to a `UInt<M, C>` instance
    pub fn add_cell<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        addend_0: &UInt<M, C>,
        addend_1: CellId,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let carry = Self::extract_carry_add_sub(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_result = Self::add_cell_unsafe(circuit_builder, addend_0, addend_1, carry)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Adds a single cell value to a `UInt<M, C>` instance
    /// Assumes that addition lead to no overflow.
    pub fn add_cell_no_overflow<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        addend_0: &UInt<M, C>,
        addend_1: CellId,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let carry = Self::extract_carry_no_overflow_add_sub(witness);
        let range_values = Self::extract_range_values_no_overflow(witness);
        let computed_result = Self::add_cell_unsafe(circuit_builder, addend_0, addend_1, carry)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Little endian subtraction
    /// Assumes users will check the correct range of the result themselves.
    pub fn sub_unsafe<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        minuend: &UInt<M, C>,
        subtrahend: &UInt<M, C>,
        borrow: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let result: UInt<M, C> = circuit_builder
            .create_cells(Self::N_OPERAND_CELLS)
            .try_into()?;

        for i in 0..Self::N_OPERAND_CELLS {
            let (minuend, subtrahend, result) =
                (minuend.values[i], subtrahend.values[i], result.values[i]);

            circuit_builder.add(result, minuend, E::BaseField::ONE);
            circuit_builder.add(result, subtrahend, -E::BaseField::ONE);

            Self::handle_borrow(result, circuit_builder, i, borrow);
        }

        Ok(result)
    }

    /// Little endian subtraction
    pub fn sub<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        minuend: &UInt<M, C>,
        subtrahend: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<UInt<M, C>, UtilError> {
        let borrow = Self::extract_borrow_add_sub(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_result = Self::sub_unsafe(circuit_builder, minuend, subtrahend, borrow)?;
        range_chip_handler.range_check_uint(circuit_builder, &computed_result, Some(range_values))
    }

    /// Modify addition result based on carry instructions
    fn handle_carry<E: ExtensionField>(
        result_cell_id: CellId,
        circuit_builder: &mut CircuitBuilder<E>,
        limb_index: usize,
        carry: &[CellId],
    ) {
        // overflow carry
        // represents the portion of the result that should move to the next operation
        // inorder to keep the value <= C bits
        // carry[i] = (addend_0[i] + addend_1[i]) % 2^C

        // last carry
        // represents the carry that was passed from the previous operation
        // this carry should be added to the current result
        // carry[i - 1] = (addend_0[i - 1] + addend_1[i - 1]) % 2^C

        if limb_index > carry.len() {
            return;
        }

        // handle overflow carry
        // we need to subtract the carry value from the current result
        if limb_index < carry.len() {
            circuit_builder.add(
                result_cell_id,
                carry[limb_index],
                -E::BaseField::from(1 << C),
            );
        }

        // handle last operation carry
        // we need to add this to the current result
        if limb_index > 0 {
            circuit_builder.add(result_cell_id, carry[limb_index - 1], E::BaseField::ONE);
        }
    }

    /// Modify subtraction result based on borrow instructions
    fn handle_borrow<E: ExtensionField>(
        result_cell_id: CellId,
        circuit_builder: &mut CircuitBuilder<E>,
        limb_index: usize,
        borrow: &[CellId],
    ) {
        // borrow
        // represents the portion of the result that should move from the
        // next operation to the current operation i.e. reduce the result
        // of the operation to come
        // this should be added to the current result
        // = borrow[i]

        // last borrow
        // represents the portion of the current result that was moved during
        // the previous computation
        // this should be removed from the current result

        if limb_index > borrow.len() {
            return;
        }

        // handle borrow
        // we need to add borrow units of C to the result
        if limb_index < borrow.len() {
            circuit_builder.add(
                result_cell_id,
                borrow[limb_index],
                E::BaseField::from(1 << C),
            );
        }

        // handle last borrow
        // we need to remove this from the current result
        if limb_index > 0 {
            circuit_builder.add(result_cell_id, borrow[limb_index - 1], -E::BaseField::ONE);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::uint::constants::AddSubConstants;
    use crate::uint::UInt;
    use gkr::structs::{Circuit, CircuitWitness};
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use simple_frontend::structs::CircuitBuilder;

    #[test]
    fn test_add_unsafe() {
        // UInt<20, 5> (4 limbs)

        // A (big-endian representation)
        // 01001 | 10100 | 11010 | 11110

        // B (big-endian representation)
        // 00101 | 01010 | 10110 | 10000

        // A + B
        // big endian and represented as field elements
        //           9  |  20  |  26  | 30
        //           5  |  10  |  22  | 16
        // result   14  |  31  |  17  | 14
        // carry    0   |  0   |   1  |  1

        // build the circuit
        type UInt20 = UInt<20, 5>;
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();

        // input wires
        // addend_0, addend_1, carry
        let (addend_0_id, addend_0_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        let (addend_1_id, addend_1_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        let (carry_id, carry_cells) =
            circuit_builder.create_witness_in(AddSubConstants::<UInt20>::N_CARRY_CELLS);

        let addend_0 = UInt20::try_from(addend_0_cells).expect("should build uint");
        let addend_1 = UInt20::try_from(addend_1_cells).expect("should build uint");

        // update circuit builder with circuit instructions
        let result =
            UInt20::add_unsafe(&mut circuit_builder, &addend_0, &addend_1, &carry_cells).unwrap();
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // generate witness
        // calling rev() to make things little endian representation
        let addend_0_witness = vec![9, 20, 26, 30]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let addend_1_witness = vec![5, 10, 22, 16]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let carry_witness = vec![0, 0, 1, 1]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();

        let mut wires_in = vec![vec![]; circuit.n_witness_in];
        wires_in[addend_0_id as usize] = addend_0_witness;
        wires_in[addend_1_id as usize] = addend_1_witness;
        wires_in[carry_id as usize] = carry_witness;

        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, wires_in);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        // check the result correctness
        let result_values = circuit_witness.output_layer_witness_ref().instances[0].to_vec();
        assert_eq!(
            result_values,
            [14, 17, 31, 14]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }

    #[test]
    fn test_add_constant_unsafe() {
        // UInt<20, 5> (4 limbs)

        // A + constant
        // A = 14 | 31 | 28 | 14
        // constant = 200
        // big endian and represented as field elements
        //           14 |  31  |  28  | 14
        //              |      |      | 200
        // result    15 |   0  |   2  | 22
        // carry      0 |   1  |   1  |  6

        type UInt20 = UInt<20, 5>;
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();

        // input wires
        // addend_0, carry, constant
        let (addend_0_id, addend_0_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        let (carry_id, carry_cells) =
            circuit_builder.create_witness_in(AddSubConstants::<UInt20>::N_CARRY_CELLS);

        let addend_0 = UInt20::try_from(addend_0_cells).expect("should build uint");

        // update circuit builder
        let result = UInt20::add_const_unsafe(
            &mut circuit_builder,
            &addend_0,
            Goldilocks::from(200),
            &carry_cells,
        )
        .unwrap();
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // generate witness
        // calling rev() to make things little endian representation
        let addend_0_witness = vec![14, 31, 28, 14]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let carry_witness = vec![0, 1, 1, 6]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();

        let mut wires_in = vec![vec![]; circuit.n_witness_in];
        wires_in[addend_0_id as usize] = addend_0_witness;
        wires_in[carry_id as usize] = carry_witness;

        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, wires_in);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        // check the result correctness
        let result_values = circuit_witness.output_layer_witness_ref().instances[0].to_vec();
        assert_eq!(
            result_values,
            [22, 2, 0, 15]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }

    #[test]
    fn test_add_small_unsafe() {
        // UInt<20, 5> (4 limbs)

        // A + constant
        // A = 14 | 31 | 28 | 14
        // small = 200 // TODO: fix this should be < 32
        // big endian and represented as field elements
        //           14 |  31  |  28  | 14
        //              |      |      | 200
        // result    15 |   0  |   2  | 22
        // carry      0 |   1  |   1  |  6

        type UInt20 = UInt<20, 5>;
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();

        // input wires
        // addend_0, carry, constant
        let (addend_0_id, addend_0_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        let (small_value_id, small_value_cell) = circuit_builder.create_witness_in(1);
        let (carry_id, carry_cells) =
            circuit_builder.create_witness_in(AddSubConstants::<UInt20>::N_CARRY_CELLS);

        let addend_0 = UInt20::try_from(addend_0_cells).expect("should build uint");

        // update circuit builder
        let result = UInt20::add_cell_unsafe(
            &mut circuit_builder,
            &addend_0,
            small_value_cell[0],
            &carry_cells,
        )
        .unwrap();
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // generate witness
        // calling rev() to make things little endian representation
        let addend_0_witness = vec![14, 31, 28, 14]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let small_value_witness = vec![200]
            .into_iter()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let carry_witness = vec![0, 1, 1, 6]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();

        let mut wires_in = vec![vec![]; circuit.n_witness_in];
        wires_in[addend_0_id as usize] = addend_0_witness;
        wires_in[small_value_id as usize] = small_value_witness;
        wires_in[carry_id as usize] = carry_witness;

        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, wires_in);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        // check the result correctness
        let result_values = circuit_witness.output_layer_witness_ref().instances[0].to_vec();
        assert_eq!(
            result_values,
            [22, 2, 0, 15]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }

    #[test]
    fn test_sub_unsafe() {
        // A - B
        // big endian and represented as field elements
        //           9  |  20  |  26  | 30
        //           5  |  30  |  28  | 10
        // result    3  |  21  |  30  | 20
        // borrow    0  |   1  |   1  |  0

        // build the circuit
        type UInt20 = UInt<20, 5>;
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();

        // input wires
        // minuend, subtrahend, borrow
        let (minuend_id, minuend_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        let (subtrahend_id, subtrahend_cells) =
            circuit_builder.create_witness_in(UInt20::N_OPERAND_CELLS);
        // |Carry| == |Borrow|
        let (borrow_id, borrow_cells) =
            circuit_builder.create_witness_in(AddSubConstants::<UInt20>::N_CARRY_CELLS);

        let minuend = UInt20::try_from(minuend_cells).expect("should build uint");
        let subtrahend = UInt20::try_from(subtrahend_cells).expect("should build uint");

        // update the circuit builder
        let result =
            UInt20::sub_unsafe(&mut circuit_builder, &minuend, &subtrahend, &borrow_cells).unwrap();
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // generate witness
        // calling rev() to make things little endian representation
        let minuend_witness = vec![9, 20, 26, 30]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();
        let subtrahend_witness = vec![5, 30, 28, 10]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect();
        let borrow_witness = vec![0, 1, 1, 0]
            .into_iter()
            .rev()
            .map(|v| Goldilocks::from(v))
            .collect_vec();

        let mut wires_in = vec![vec![]; circuit.n_witness_in];
        wires_in[minuend_id as usize] = minuend_witness;
        wires_in[subtrahend_id as usize] = subtrahend_witness;
        wires_in[borrow_id as usize] = borrow_witness;

        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, wires_in);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        // check the result correctness
        let result_values = circuit_witness.output_layer_witness_ref().instances[0].to_vec();
        assert_eq!(
            result_values,
            [20, 30, 21, 3]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }
}
