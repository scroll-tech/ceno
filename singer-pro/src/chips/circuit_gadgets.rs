use ff::Field;
use std::sync::Arc;

use gkr::structs::Circuit;
use goldilocks::SmallField;
use simple_frontend::structs::{CircuitBuilder, MixedCell, WireId};

use super::ChipCircuitGadgets;

#[derive(Clone, Debug)]
pub(crate) struct PrefixSelectorCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafFracSumCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_den_id: WireId,
    pub(crate) input_num_id: WireId,
    pub(crate) cond_id: WireId,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafFracSumNoSelectorCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_den_id: WireId,
    pub(crate) input_num_id: WireId,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_id: WireId,
    pub(crate) cond_id: WireId,
}

impl<F: SmallField> ChipCircuitGadgets<F> {
    pub(crate) fn new() -> Self {
        Self {
            inv_sum: Self::construct_inv_sum(),
            frac_sum_inner: Self::construct_frac_sum_inner(),
            frac_sum_leaf: Self::construct_frac_sum_leaf(),
            frac_sum_leaf_no_selector: Self::construct_frac_sum_leaf_no_selector(),
            product_inner: Self::construct_product_inner(),
            product_leaf: Self::construct_product_leaf(),
        }
    }

    /// Construct a selector for n_instances and each instance contains `num`
    /// items. `num` must be a power of 2.
    pub(crate) fn construct_prefix_selector(
        n_instances: usize,
        num: usize,
    ) -> PrefixSelectorCircuit<F> {
        assert_eq!(num, num.next_power_of_two());
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let _ = circuit_builder.create_constant_in(n_instances * num, 1);
        circuit_builder.configure();
        PrefixSelectorCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
        }
    }

    /// Construct a circuit to compute the inverse sum of two extension field
    /// elements.
    /// Wire in 0: 2 extension field elements.
    /// Wire in 1: 2-bit selector.
    /// output layer: the denominator and the numerator.
    pub(crate) fn construct_inv_sum() -> LeafCircuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_id, input) = circuit_builder.create_ext_wire_in(2);
        let (cond_id, cond) = circuit_builder.create_wire_in(2);
        let (_, output) = circuit_builder.create_ext_wire_out(2);
        // selector denominator 1 or input[0] or input[0] * input[1]
        let den_mul = circuit_builder.create_ext_cell();
        circuit_builder.mul2_ext(&den_mul, &input[0], &input[1], F::BaseField::ONE);
        let tmp = circuit_builder.create_ext_cell();
        circuit_builder.sel_mixed_and_ext(
            &tmp,
            &MixedCell::Constant(F::BaseField::ONE),
            &input[0],
            cond[0],
        );
        circuit_builder.sel_ext(&output[0], &tmp, &den_mul, cond[1]);

        // select the numerator 0 or 1 or input[0] + input[1]
        let den_add = circuit_builder.create_ext_cell();
        circuit_builder.add_ext(&den_add, &input[0], F::BaseField::ONE);
        circuit_builder.add_ext(&den_add, &input[0], F::BaseField::ONE);
        circuit_builder.sel_mixed_and_ext(&output[1], &cond[0].into(), &den_add, cond[1]);

        circuit_builder.configure();
        LeafCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            input_id,
            cond_id,
        }
    }

    /// Construct a circuit to compute the sum of two fractions. The
    /// denominators are on the extension field. The numerators are on the base
    /// field.
    /// Wire in 0: denominators, 2 extension field elements.
    /// Wire in 1: numerators, 2 base field elements.
    /// Wire in 2: 2-bit selector.
    /// output layer: the denominator and the numerator.
    pub(crate) fn construct_frac_sum_leaf() -> LeafFracSumCircuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_den_id, input_den) = circuit_builder.create_ext_wire_in(2);
        let (input_num_id, input_num) = circuit_builder.create_wire_in(2);
        let (cond_id, cond) = circuit_builder.create_wire_in(2);
        let (_, output) = circuit_builder.create_ext_wire_out(2);
        // selector denominator, 1 or input_den[0] or input_den[0] * input_den[1]
        let den_mul = circuit_builder.create_ext_cell();
        circuit_builder.mul2_ext(&den_mul, &input_den[0], &input_den[1], F::BaseField::ONE);
        let tmp = circuit_builder.create_ext_cell();
        circuit_builder.sel_mixed_and_ext(
            &tmp,
            &MixedCell::Constant(F::BaseField::ONE),
            &input_den[0],
            cond[0],
        );
        circuit_builder.sel_ext(&output[0], &tmp, &den_mul, cond[1]);

        // select the numerator, 0 or input_num[0] or input_den[0] * input_num[1] + input_num[0] * input_den[1]
        let num = circuit_builder.create_ext_cell();
        circuit_builder.mul_ext_base(&num, &input_den[0], input_num[1], F::BaseField::ONE);
        circuit_builder.mul_ext_base(&num, &input_den[1], input_num[0], F::BaseField::ONE);
        let tmp = circuit_builder.create_cell();
        circuit_builder.sel_mixed(
            tmp,
            MixedCell::Constant(F::BaseField::ZERO),
            input_num[0].into(),
            cond[0],
        );
        circuit_builder.sel_mixed_and_ext(&output[1], &tmp.into(), &num, cond[1]);

        circuit_builder.configure();
        LeafFracSumCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            input_den_id,
            input_num_id,
            cond_id,
        }
    }

    /// Construct a circuit to compute the sum of two fractions. The
    /// denominators are on the extension field. The numerators are on the base
    /// field.
    /// Wire in 0: denominators, 2 extension field elements.
    /// Wire in 1: numerators, 2 base field elements.
    /// output layer: the denominator and the numerator.
    pub(crate) fn construct_frac_sum_leaf_no_selector() -> LeafFracSumNoSelectorCircuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_den_id, input_den) = circuit_builder.create_ext_wire_in(2);
        let (input_num_id, input_num) = circuit_builder.create_wire_in(2);
        let (_, output) = circuit_builder.create_ext_wire_out(2);
        // denominator
        circuit_builder.mul2_ext(
            &output[0], // output_den
            &input_den[0],
            &input_den[1],
            F::BaseField::ONE,
        );

        // numerator
        circuit_builder.mul_ext_base(
            &output[1], // output_num
            &input_den[0],
            input_num[1],
            F::BaseField::ONE,
        );
        circuit_builder.mul_ext_base(
            &output[1], // output_num
            &input_den[1],
            input_num[0],
            F::BaseField::ONE,
        );

        circuit_builder.configure();
        LeafFracSumNoSelectorCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            input_den_id,
            input_num_id,
        }
    }

    /// Construct a circuit to compute the sum of two fractions. The
    /// denominators and numerators are on the extension field
    /// Wire in 0: denominators, 2 extension field elements.
    /// Wire in 1: numerators, 2 extensuin field elements.
    /// Wire out 0: the denominator.
    /// Wire out 1: the numerator.
    pub(crate) fn construct_frac_sum_inner() -> Arc<Circuit<F>> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (_, input) = circuit_builder.create_ext_wire_in(4);
        let (_, output) = circuit_builder.create_ext_wire_out(2);
        // denominator
        circuit_builder.mul2_ext(
            &output[0], // output_den
            &input[0],  // input_den[0]
            &input[2],  // input_den[1]
            F::BaseField::ONE,
        );

        // numerator
        circuit_builder.mul2_ext(
            &output[1], // output_num
            &input[0],  // input_den[0]
            &input[3],  // input_num[1]
            F::BaseField::ONE,
        );
        circuit_builder.mul2_ext(
            &output[1], // output_num
            &input[2],  // input_den[1]
            &input[1],  // input_num[0]
            F::BaseField::ONE,
        );

        circuit_builder.configure();
        Arc::new(Circuit::new(&circuit_builder))
    }

    /// Construct a circuit to compute the product of two extension field elements.
    pub(crate) fn construct_product_leaf() -> LeafCircuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_id, input) = circuit_builder.create_ext_wire_in(2);
        let (cond_id, sel) = circuit_builder.create_wire_in(2);
        let (_, output) = circuit_builder.create_ext_wire_out(1);
        // selector elements, 1 or input[0] or input[0] * input[1]
        let mul = circuit_builder.create_ext_cell();
        circuit_builder.mul2_ext(&mul, &input[0], &input[1], F::BaseField::ONE);
        let tmp = circuit_builder.create_ext_cell();
        circuit_builder.sel_mixed_and_ext(
            &tmp,
            &MixedCell::Constant(F::BaseField::ONE),
            &input[0],
            sel[0],
        );
        circuit_builder.sel_ext(&output[0], &tmp, &mul, sel[1]);

        circuit_builder.configure();
        LeafCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            input_id,
            cond_id,
        }
    }

    /// Construct a circuit to compute the product of two extension field elements.
    pub(crate) fn construct_product_inner() -> Arc<Circuit<F>> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (_, input) = circuit_builder.create_ext_wire_in(2);
        let (_, output) = circuit_builder.create_ext_wire_out(1);
        circuit_builder.mul2_ext(&output[0], &input[0], &input[1], F::BaseField::ONE);

        Arc::new(Circuit::new(&circuit_builder))
    }
}
