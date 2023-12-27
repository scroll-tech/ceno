use std::sync::Arc;

use frontend::structs::ConstantType;
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::{
    structs::{Circuit, CircuitWitness, CircuitWitnessGenerator, LayerWitness, Point},
    utils::ceil_log2,
};

impl<F: SmallField> CircuitWitnessGenerator<F> {
    /// Initialize the structure of the circuit witness.
    pub fn new(circuit: &Circuit<F>, challenges: Vec<F>) -> Self {
        Self {
            layers: vec![vec![]; circuit.layers.len()],
            wires_in: vec![vec![]; circuit.n_wires_in],
            wires_out: vec![vec![]; circuit.output_copy_from.len()],
            other_witnesses: vec![vec![]; circuit.n_other_witnesses],
            challenges: challenges,
            n_instances: 0,
        }
    }

    /// Generate a fresh instance for the circuit, return layer witnesses and
    /// wire out witnesses.
    fn new_instance(
        circuit: &Circuit<F>,
        wires_in: &[&[F]],
        other_witnesses: &[&[F]],
        challenges: &[F],
    ) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
        let n_layers = circuit.layers.len();
        let mut layer_witnesses = vec![vec![]; n_layers];

        // The first layer.
        layer_witnesses[n_layers - 1] = {
            let all_input_witnesses = wires_in.iter().chain(other_witnesses.iter()).collect_vec();
            let mut layer_witness = vec![F::ZERO; circuit.layers[n_layers - 1].size()];
            circuit.layers[n_layers - 1]
                .paste_to
                .iter()
                .for_each(|(id, new_wire_ids)| {
                    new_wire_ids
                        .iter()
                        .enumerate()
                        .for_each(|(i, new_wire_id)| {
                            layer_witness[*new_wire_id] = all_input_witnesses[*id][i];
                        })
                });
            layer_witness
        };

        // The other layers.
        let constant = |c: ConstantType<F>| match c {
            ConstantType::Field(x) => x,
            ConstantType::Challenge(i) => challenges[i],
        };
        for (layer_id, layer) in circuit.layers.iter().enumerate().rev().skip(1) {
            let size = circuit.layers[layer_id].size();
            let mut current_layer_witness = vec![F::ZERO; size];

            layer
                .paste_to
                .iter()
                .for_each(|(old_layer_id, new_wire_ids)| {
                    new_wire_ids
                        .iter()
                        .enumerate()
                        .for_each(|(subset_wire_id, new_wire_id)| {
                            let old_wire_id = circuit.layers[*old_layer_id]
                                .copy_from
                                .get(&layer_id)
                                .unwrap()[subset_wire_id];
                            current_layer_witness[*new_wire_id] =
                                layer_witnesses[*old_layer_id][old_wire_id];
                        });
                });

            let last_layer_witness = &layer_witnesses[layer_id + 1];
            for add_const in layer.add_consts.iter() {
                current_layer_witness[add_const.idx_out] =
                    current_layer_witness[add_const.idx_out] + constant(add_const.constant);
            }

            for add in layer.adds.iter() {
                current_layer_witness[add.idx_out] +=
                    last_layer_witness[add.idx_in] * constant(add.scaler);
            }

            for mul2 in layer.mul2s.iter() {
                current_layer_witness[mul2.idx_out] = current_layer_witness[mul2.idx_out]
                    + last_layer_witness[mul2.idx_in1]
                        * last_layer_witness[mul2.idx_in2]
                        * constant(mul2.scaler);
            }

            for mul3 in layer.mul3s.iter() {
                current_layer_witness[mul3.idx_out] = current_layer_witness[mul3.idx_out]
                    + last_layer_witness[mul3.idx_in1]
                        * last_layer_witness[mul3.idx_in2]
                        * last_layer_witness[mul3.idx_in3]
                        * constant(mul3.scaler);
            }
            for assert_const in layer.assert_consts.iter() {
                assert_eq!(
                    current_layer_witness[assert_const.idx_out],
                    constant(assert_const.constant),
                    "layer: {}, wire_id: {}, assert_const: {:?} != {:?}",
                    layer_id,
                    assert_const.idx_out,
                    current_layer_witness[assert_const.idx_out],
                    constant(assert_const.constant)
                );
            }
            layer_witnesses[layer_id] = current_layer_witness;
        }
        let mut wires_out = vec![vec![]; circuit.output_copy_from.len()];
        circuit.layers[0]
            .copy_from
            .iter()
            .for_each(|(id, old_wire_ids)| {
                wires_out[*id] = old_wire_ids
                    .iter()
                    .map(|old_wire_id| layer_witnesses[0][*old_wire_id])
                    .collect_vec();
            });
        (layer_witnesses, wires_out)
    }

    /// Add another instance for the circuit.
    pub fn add_instance(
        &mut self,
        circuit: &Circuit<F>,
        wires_in: &[&[F]],
        other_witnesses: &[&[F]],
    ) {
        assert!(wires_in.len() == circuit.n_wires_in);
        assert!(other_witnesses.len() == circuit.n_other_witnesses);
        let (new_layer_witnesses, new_wires_out) = CircuitWitnessGenerator::new_instance(
            circuit,
            wires_in,
            other_witnesses,
            &self.challenges,
        );

        // Merge self and circuit_witness.
        for (layer_witness, new_layer_witness) in
            self.layers.iter_mut().zip(new_layer_witnesses.into_iter())
        {
            layer_witness.extend(new_layer_witness);
        }

        for (wire_out, new_wire_out) in self.wires_out.iter_mut().zip(new_wires_out.into_iter()) {
            let new_len = new_wire_out.len().next_power_of_two();
            let old_len = wire_out.len();
            wire_out.extend(new_wire_out);
            wire_out.extend(vec![F::ZERO; new_len - old_len]);
        }

        for (wire_in, new_wire_in) in self.wires_in.iter_mut().zip(wires_in.iter()) {
            let new_len = new_wire_in.len().next_power_of_two();
            wire_in.extend(*new_wire_in);
            wire_in.extend(vec![F::ZERO; new_len - new_wire_in.len()]);
        }

        for (other_witness, new_other_witness) in
            self.other_witnesses.iter_mut().zip(other_witnesses.iter())
        {
            let new_len = new_other_witness.len().next_power_of_two();
            other_witness.extend(*new_other_witness);
            other_witness.extend(vec![F::ZERO; new_len - new_other_witness.len()]);
        }

        self.n_instances += 1;
    }
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn new(gen: CircuitWitnessGenerator<F>) -> Self {
        let n_instances = gen.n_instances;
        let layers = gen.layers.into_iter().map(LayerWitness::new).collect_vec();
        let wires_in = gen
            .wires_in
            .into_iter()
            .map(LayerWitness::new)
            .collect_vec();
        let wires_out = gen
            .wires_out
            .into_iter()
            .map(LayerWitness::new)
            .collect_vec();
        let other_witnesses = gen
            .other_witnesses
            .into_iter()
            .map(LayerWitness::new)
            .collect_vec();
        Self {
            layers,
            wires_in,
            wires_out,
            other_witnesses,
            n_instances,
        }
    }
    pub fn last_layer_witness_ref(&self) -> &LayerWitness<F> {
        self.layers.first().unwrap()
    }

    pub fn n_instances(&self) -> usize {
        self.n_instances
    }

    pub fn wires_in_ref(&self) -> &[LayerWitness<F>] {
        &self.wires_in
    }

    pub fn other_witnesses_ref(&self) -> &[LayerWitness<F>] {
        &self.other_witnesses
    }

    pub fn wires_out_ref(&self) -> &[LayerWitness<F>] {
        &self.wires_out
    }
}

impl<F: SmallField> LayerWitness<F> {
    pub fn new(values: Vec<F>) -> Self {
        let num_vars = ceil_log2(values.len()) as usize;
        // Expand the values to the size of a power of 2
        let values = if values.len() < (1 << num_vars) {
            let mut values = values;
            values.resize(1 << num_vars, F::ZERO);
            values
        } else {
            values
        };
        Self {
            poly: Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars, values,
            )),
        }
    }
    pub fn evaluate(&self, point: &Point<F>) -> F {
        let p = point.iter().map(|x| x.elements[0]).collect_vec();
        self.poly.evaluate(&p)
    }

    /// This function is to compute evaluations of the layer with log_size least significant challenges in the output point.
    pub fn truncate_point_and_evaluate(&self, point: &Point<F>) -> F {
        let p = point.iter().map(|x| x.elements[0]).collect_vec();
        self.poly.evaluate(&p[0..self.poly.num_vars])
    }

    pub fn size(&self) -> usize {
        1 << self.poly.num_vars
    }

    pub fn log_size(&self) -> usize {
        self.poly.num_vars
    }
}
