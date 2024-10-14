use std::{collections::HashMap, sync::Arc};

use crate::circuit::EvaluateConstant;
use ff::Field;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::{
        DenseMultilinearExtension, InstanceIntoIterator, InstanceIntoIteratorMut, IntoInstanceIter,
        IntoInstanceIterMut, IntoMLE, MultilinearExtension,
    },
    virtual_poly_v2::ArcMultilinearExtension,
};
use simple_frontend::structs::{ChallengeConst, LayerId};
use std::fmt::Debug;
use sumcheck::util::ceil_log2;

use crate::{
    structs::{Circuit, CircuitWitness},
    utils::i64_to_field,
};

impl<'a, E: ExtensionField> CircuitWitness<'a, E> {
    /// Initialize the structure of the circuit witness.
    pub fn new(circuit: &Circuit<E>, challenges: Vec<E>) -> Self {
        let create_default = |size| {
            (0..size)
                .map(|_| {
                    let a: ArcMultilinearExtension<E> =
                        Arc::new(DenseMultilinearExtension::default());
                    a
                })
                .collect::<Vec<ArcMultilinearExtension<E>>>()
        };
        Self {
            layers: create_default(circuit.layers.len()),
            witness_in: create_default(circuit.n_witness_in),
            witness_out: create_default(circuit.n_witness_out),
            n_instances: 0,
            challenges: circuit.generate_basefield_challenges(&challenges),
        }
    }

    /// Generate a fresh instance for the circuit, return layer witnesses and
    /// wire out witnesses.
    fn new_instances(
        circuit: &Circuit<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenges: &HashMap<ChallengeConst, Vec<E::BaseField>>,
        n_instances: usize,
    ) -> (
        Vec<DenseMultilinearExtension<E>>,
        Vec<DenseMultilinearExtension<E>>,
    ) {
        let n_layers = circuit.layers.len();
        let mut layer_wits = vec![DenseMultilinearExtension::default(); n_layers];

        // The first layer.
        layer_wits[n_layers - 1] = {
            let mut layer_wit =
                vec![E::BaseField::ZERO; circuit.layers[n_layers - 1].size() * n_instances];
            for (wit_id, (l, r)) in circuit.paste_from_wits_in.iter().enumerate() {
                let layer_wit_iter: InstanceIntoIteratorMut<E::BaseField> =
                    layer_wit.into_instance_iter_mut(n_instances);
                let wit_in = wits_in[wit_id].get_base_field_vec();
                let wit_in_iter: InstanceIntoIterator<E::BaseField> =
                    wit_in.into_instance_iter(n_instances);
                for (layer_wit, wit_in) in layer_wit_iter.zip_eq(wit_in_iter) {
                    for (layer_wit_elem, wit_in_elem) in
                        layer_wit[*l..*r].iter_mut().zip(&wit_in[..*r - *l])
                    {
                        *layer_wit_elem = *wit_in_elem;
                    }
                }
            }
            for (constant, (l, r)) in circuit.paste_from_consts_in.iter() {
                let layer_wit_iter: InstanceIntoIteratorMut<E::BaseField> =
                    layer_wit.into_instance_iter_mut(n_instances);
                for layer_wit in layer_wit_iter {
                    for layer_wit_elem in &mut layer_wit[*l..*r] {
                        *layer_wit_elem = i64_to_field(*constant);
                    }
                }
            }
            for (num_vars, (l, r)) in circuit.paste_from_counter_in.iter() {
                let layer_wit_iter: InstanceIntoIteratorMut<E::BaseField> =
                    layer_wit.into_instance_iter_mut(n_instances);
                for (instance_id, layer_wit) in layer_wit_iter.enumerate() {
                    for (i, layer_wit_elem) in layer_wit[*l..*r].iter_mut().enumerate() {
                        *layer_wit_elem = E::BaseField::from(((instance_id << num_vars) ^ i) as u64)
                    }
                }
            }
            layer_wit.into_mle()
        };

        for (layer_id, layer) in circuit.layers.iter().enumerate().rev().skip(1) {
            let size = circuit.layers[layer_id].size();
            let mut current_layer_wit = vec![E::BaseField::ZERO; size * n_instances];

            let current_layer_wit_instance_iter: InstanceIntoIteratorMut<E::BaseField> =
                current_layer_wit.into_instance_iter_mut(n_instances);
            current_layer_wit_instance_iter.enumerate().for_each(
                |(instance_id, current_layer_wit)| {
                    layer
                        .paste_from
                        .iter()
                        .for_each(|(old_layer_id, new_wire_ids)| {
                            let layer_wits =
                                layer_wits[*old_layer_id as usize].get_base_field_vec();
                            let old_layer_instance_start_index =
                                instance_id * circuit.layers[*old_layer_id as usize].size();

                            new_wire_ids.iter().enumerate().for_each(
                                |(subset_wire_id, new_wire_id)| {
                                    let old_wire_id = circuit.layers[*old_layer_id as usize]
                                        .copy_to
                                        .get(&(layer_id as LayerId))
                                        .unwrap()[subset_wire_id];
                                    current_layer_wit[*new_wire_id] =
                                        layer_wits[old_layer_instance_start_index + old_wire_id];
                                },
                            );
                        });

                    let last_layer_wit = layer_wits[layer_id + 1].get_base_field_vec();
                    let last_layer_instance_start_index =
                        instance_id * circuit.layers[layer_id + 1].size();
                    for add_const in layer.add_consts.iter() {
                        current_layer_wit[add_const.idx_out] += add_const.scalar.eval(challenges);
                    }

                    for add in layer.adds.iter() {
                        current_layer_wit[add.idx_out] += last_layer_wit
                            [last_layer_instance_start_index + add.idx_in[0]]
                            * add.scalar.eval(challenges);
                    }

                    for mul2 in layer.mul2s.iter() {
                        current_layer_wit[mul2.idx_out] += last_layer_wit
                            [last_layer_instance_start_index + mul2.idx_in[0]]
                            * last_layer_wit[last_layer_instance_start_index + mul2.idx_in[1]]
                            * mul2.scalar.eval(challenges);
                    }

                    for mul3 in layer.mul3s.iter() {
                        current_layer_wit[mul3.idx_out] += last_layer_wit
                            [last_layer_instance_start_index + mul3.idx_in[0]]
                            * last_layer_wit[last_layer_instance_start_index + mul3.idx_in[1]]
                            * last_layer_wit[last_layer_instance_start_index + mul3.idx_in[2]]
                            * mul3.scalar.eval(challenges);
                    }
                },
            );

            layer_wits[layer_id] = current_layer_wit.into_mle();
        }
        let mut wits_out = vec![DenseMultilinearExtension::default(); circuit.n_witness_out];
        let output_layer_wit = layer_wits[0].get_base_field_vec();

        circuit
            .copy_to_wits_out
            .iter()
            .enumerate()
            .for_each(|(wit_id, old_wire_ids)| {
                let mut wit_out =
                    vec![E::BaseField::ZERO; old_wire_ids.len().next_power_of_two() * n_instances];
                let wit_out_instance_iter: InstanceIntoIteratorMut<E::BaseField> =
                    wit_out.into_instance_iter_mut(n_instances);
                for (instance_id, wit_out) in wit_out_instance_iter.enumerate() {
                    let output_layer_instance_start_index = instance_id * circuit.layers[0].size();
                    wit_out.iter_mut().zip(old_wire_ids.iter()).for_each(
                        |(wit_out_value, old_wire_id)| {
                            *wit_out_value =
                                output_layer_wit[output_layer_instance_start_index + *old_wire_id]
                        },
                    );
                }
                wits_out[wit_id] = wit_out.into_mle();
            });

        (layer_wits, wits_out)
    }

    pub fn add_instance(
        &mut self,
        circuit: &Circuit<E>,
        wits_in: Vec<DenseMultilinearExtension<E>>,
    ) {
        self.add_instances(circuit, wits_in, 1);
    }

    pub fn set_instances(
        &mut self,
        circuit: &Circuit<E>,
        new_wits_in: Vec<ArcMultilinearExtension<'a, E>>,
        n_instances: usize,
    ) {
        assert_eq!(new_wits_in.len(), circuit.n_witness_in);
        assert!(n_instances.is_power_of_two());
        assert!(
            new_wits_in
                .iter()
                .all(|wit_in| wit_in.evaluations().len() % n_instances == 0)
        );

        let (inferred_layer_wits, inferred_wits_out) =
            CircuitWitness::new_instances(circuit, &new_wits_in, &self.challenges, n_instances);

        assert_eq!(self.layers.len(), inferred_layer_wits.len());
        self.layers = inferred_layer_wits.into_iter().map(|n| n.into()).collect();
        assert_eq!(self.witness_out.len(), inferred_wits_out.len());
        self.witness_out = inferred_wits_out.into_iter().map(|n| n.into()).collect();
        assert_eq!(self.witness_in.len(), new_wits_in.len());
        self.witness_in = new_wits_in;

        self.n_instances = n_instances;

        // check correctness in debug build
        if cfg!(debug_assertions) {
            self.check_correctness(circuit);
        }
    }

    pub fn add_instances(
        &mut self,
        circuit: &Circuit<E>,
        new_wits_in: Vec<DenseMultilinearExtension<E>>,
        n_instances: usize,
    ) {
        assert_eq!(new_wits_in.len(), circuit.n_witness_in);
        assert!(n_instances.is_power_of_two());
        assert!(
            new_wits_in
                .iter()
                .all(|wit_in| wit_in.evaluations().len() % n_instances == 0)
        );

        let (inferred_layer_wits, inferred_wits_out) = CircuitWitness::new_instances(
            circuit,
            &new_wits_in
                .iter()
                .map(|w| {
                    let w: ArcMultilinearExtension<E> = Arc::new(w.get_ranged_mle(1, 0));
                    w
                })
                .collect::<Vec<ArcMultilinearExtension<E>>>(),
            &self.challenges,
            n_instances,
        );

        for (wit_out, inferred_wits_out) in self
            .witness_out
            .iter_mut()
            .zip(inferred_wits_out.into_iter())
        {
            Arc::get_mut(wit_out).unwrap().merge(inferred_wits_out);
        }

        for (wit_in, new_wit_in) in self.witness_in.iter_mut().zip(new_wits_in.into_iter()) {
            Arc::get_mut(wit_in).unwrap().merge(new_wit_in);
        }

        // Merge self and circuit_witness.
        for (layer_wit, inferred_layer_wit) in
            self.layers.iter_mut().zip(inferred_layer_wits.into_iter())
        {
            Arc::get_mut(layer_wit).unwrap().merge(inferred_layer_wit);
        }

        self.n_instances += n_instances;

        // check correctness in debug build
        if cfg!(debug_assertions) {
            self.check_correctness(circuit);
        }
    }

    pub fn instance_num_vars(&self) -> usize {
        ceil_log2(self.n_instances)
    }

    pub fn check_correctness(&self, _circuit: &Circuit<E>) {
        // Check input.

        // let input_layer_wits = self.layers.last().unwrap();
        // let wits_in = self.witness_in_ref();
        // for copy_id in 0..self.n_instances {
        //     for (wit_id, (l, r)) in circuit.paste_from_wits_in.iter().enumerate() {
        //         for (subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
        //             assert_eq!(
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 wits_in[wit_id].instances[copy_id][subset_wire_id],
        //                 "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} !=
        // {:?}",                 circuit.layers.len() - 1,
        //                 copy_id,
        //                 new_wire_id,
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 wits_in[wit_id].instances[copy_id][subset_wire_id]
        //             );
        //         }
        //     }
        //     for (constant, (l, r)) in circuit.paste_from_consts_in.iter() {
        //         for (_subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
        //             assert_eq!(
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 i64_to_field(*constant),
        //                 "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} !=
        // {:?}",                 circuit.layers.len() - 1,
        //                 copy_id,
        //                 new_wire_id,
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 constant
        //             );
        //         }
        //     }
        //     for (num_vars, (l, r)) in circuit.paste_from_counter_in.iter() {
        //         for (subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
        //             assert_eq!(
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 i64_to_field(((copy_id << num_vars) ^ subset_wire_id) as i64),
        //                 "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} !=
        // {:?}",                 circuit.layers.len() - 1,
        //                 copy_id,
        //                 new_wire_id,
        //                 input_layer_wits.instances[copy_id][new_wire_id],
        //                 (copy_id << num_vars) ^ subset_wire_id
        //             );
        //         }
        //     }
        // }

        // for (layer_id, (layer_witnesses, layer)) in self
        //     .layers
        //     .iter()
        //     .zip(circuit.layers.iter())
        //     .enumerate()
        //     .rev()
        //     .skip(1)
        // {
        //     let prev_layer_wits = &self.layers[layer_id + 1];
        //     for (copy_id, (prev, curr)) in prev_layer_wits
        //         .instances
        //         .iter()
        //         .zip(layer_witnesses.instances.iter())
        //         .enumerate()
        //     {
        //         let mut expected = vec![E::ZERO; curr.len()];
        //         for add_const in layer.add_consts.iter() {
        //             expected[add_const.idx_out] += add_const.scalar.eval(&self.challenges);
        //         }
        //         for add in layer.adds.iter() {
        //             expected[add.idx_out] +=
        //                 prev[add.idx_in[0]] * add.scalar.eval(&self.challenges);
        //         }
        //         for mul2 in layer.mul2s.iter() {
        //             expected[mul2.idx_out] += prev[mul2.idx_in[0]]
        //                 * prev[mul2.idx_in[1]]
        //                 * mul2.scalar.eval(&self.challenges);
        //         }
        //         for mul3 in layer.mul3s.iter() {
        //             expected[mul3.idx_out] += prev[mul3.idx_in[0]]
        //                 * prev[mul3.idx_in[1]]
        //                 * prev[mul3.idx_in[2]]
        //                 * mul3.scalar.eval(&self.challenges);
        //         }

        //         let mut expected_max_previous_size = prev.len();
        //         for (old_layer_id, new_wire_ids) in layer.paste_from.iter() {
        //             expected_max_previous_size =
        // expected_max_previous_size.max(new_wire_ids.len());             for
        // (subset_wire_id, new_wire_id) in new_wire_ids.iter().enumerate() {
        // let old_wire_id = circuit.layers[*old_layer_id as usize]
        // .copy_to                     .get(&(layer_id as LayerId))
        //                     .unwrap()[subset_wire_id];
        //                 expected[*new_wire_id] =
        //                     self.layers[*old_layer_id as usize].instances[copy_id][old_wire_id];
        //             }
        //         }
        //         assert_eq!(
        //             ceil_log2(expected_max_previous_size),
        //             layer.max_previous_num_vars,
        //             "layer: {}, expected_max_previous_size: {}, got: {}",
        //             layer_id,
        //             expected_max_previous_size,
        //             layer.max_previous_num_vars
        //         );
        //         for (wire_id, (got, expected)) in curr.iter().zip(expected.iter()).enumerate() {
        //             assert_eq!(
        //                 *got, *expected,
        //                 "layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
        //                 layer_id, copy_id, wire_id, got, expected
        //             );
        //         }

        //         if layer_id != 0 {
        //             for (new_layer_id, old_wire_ids) in layer.copy_to.iter() {
        //                 for (subset_wire_id, old_wire_id) in old_wire_ids.iter().enumerate() {
        //                     let new_wire_id = circuit.layers[*new_layer_id as usize]
        //                         .paste_from
        //                         .get(&(layer_id as LayerId))
        //                         .unwrap()[subset_wire_id];
        //                     assert_eq!(
        //                         curr[*old_wire_id],
        //                         self.layers[*new_layer_id as
        // usize].instances[copy_id][new_wire_id],                         "copy_to check:
        // layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
        // layer_id,                         copy_id,
        //                         old_wire_id,
        //                         curr[*old_wire_id],
        //                         self.layers[*new_layer_id as
        // usize].instances[copy_id][new_wire_id]                     )
        //                 }
        //             }
        //         }
        //     }
        // }

        // let output_layer_witness = &self.layers[0];
        // let wits_out = self.witness_out_ref();
        // for (wit_id, old_wire_ids) in circuit.copy_to_wits_out.iter().enumerate() {
        //     for copy_id in 0..self.n_instances {
        //         for (new_wire_id, old_wire_id) in old_wire_ids.iter().enumerate() {
        //             assert_eq!(
        //                 output_layer_witness.instances[copy_id][*old_wire_id],
        //                 wits_out[wit_id].instances[copy_id][new_wire_id]
        //             );
        //         }
        //     }
        // }
        // for gate in circuit.assert_consts.iter() {
        //     if let ConstantType::Field(constant) = gate.scalar {
        //         for copy_id in 0..self.n_instances {
        //             assert_eq!(
        //                 output_layer_witness.instances[copy_id][gate.idx_out],
        //                 constant
        //             );
        //         }
        //     }
        // }
    }
}

impl<'a, E: ExtensionField> CircuitWitness<'a, E> {
    pub fn output_layer_witness_ref(&self) -> &ArcMultilinearExtension<'a, E> {
        self.layers.first().unwrap()
    }

    pub fn n_instances(&self) -> usize {
        self.n_instances
    }

    pub fn witness_in_ref(&self) -> &[ArcMultilinearExtension<'a, E>] {
        &self.witness_in
    }

    pub fn witness_out_ref(&self) -> &[ArcMultilinearExtension<'a, E>] {
        &self.witness_out
    }

    pub fn challenges(&self) -> &HashMap<ChallengeConst, Vec<E::BaseField>> {
        &self.challenges
    }

    pub fn layers_ref(&self) -> &[ArcMultilinearExtension<'a, E>] {
        &self.layers
    }
}

impl<'a, F: ExtensionField> Debug for CircuitWitness<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CircuitWitness {{")?;
        writeln!(f, "  n_instances: {}", self.n_instances)?;
        writeln!(f, "  layers: ")?;
        for (i, layer) in self.layers.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, layer.evaluations())?;
        }
        writeln!(f, "  wires_in: ")?;
        for (i, wire) in self.witness_in.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, &wire.evaluations())?;
        }
        writeln!(f, "  wires_out: ")?;
        for (i, wire) in self.witness_out.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, &wire.evaluations())?;
        }
        writeln!(f, "  challenges: {:?}", self.challenges)?;
        writeln!(f, "}}")
    }
}

// #[cfg(test)]
// mod test {
//     use std::{collections::HashMap, ops::Neg};

//     use ff::Field;
//     use ff_ext::ExtensionField;
//     use goldilocks::GoldilocksExt2;
//     use itertools::Itertools;
//     use simple_frontend::structs::{ChallengeConst, ChallengeId, CircuitBuilder, ConstantType};

//     use crate::{
//         structs::{Circuit, CircuitWitness, LayerWitness},
//         utils::i64_to_field,
//     };

//     fn copy_and_paste_circuit<Ext: ExtensionField>() -> Circuit<Ext> {
//         let mut circuit_builder = CircuitBuilder::<Ext>::new();
//         // Layer 3
//         let (_, input) = circuit_builder.create_witness_in(4);

//         // Layer 2
//         let mul_01 = circuit_builder.create_cell();
//         circuit_builder.mul2(mul_01, input[0], input[1], Ext::BaseField::ONE);

//         // Layer 1
//         let mul_012 = circuit_builder.create_cell();
//         circuit_builder.mul2(mul_012, mul_01, input[2], Ext::BaseField::ONE);

//         // Layer 0
//         let (_, mul_001123) = circuit_builder.create_witness_out(1);
//         circuit_builder.mul3(
//             mul_001123[0],
//             mul_01,
//             mul_012,
//             input[3],
//             Ext::BaseField::ONE,
//         );

//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);

//         circuit
//     }

//     fn copy_and_paste_witness<Ext: ExtensionField>() -> (
//         Vec<LayerWitness<Ext::BaseField>>,
//         CircuitWitness<Ext::BaseField>,
//     ) {
//         // witness_in, single instance
//         let inputs = vec![vec![
//             i64_to_field(5),
//             i64_to_field(7),
//             i64_to_field(11),
//             i64_to_field(13),
//         ]];
//         let witness_in = vec![LayerWitness { instances: inputs }];

//         let layers = vec![
//             LayerWitness {
//                 instances: vec![vec![i64_to_field(175175)]],
//             },
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(385),
//                     i64_to_field(35),
//                     i64_to_field(13),
//                     i64_to_field(0), // pad
//                 ]],
//             },
//             LayerWitness {
//                 instances: vec![vec![i64_to_field(35), i64_to_field(11)]],
//             },
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(5),
//                     i64_to_field(7),
//                     i64_to_field(11),
//                     i64_to_field(13),
//                 ]],
//             },
//         ];

//         let outputs = vec![vec![i64_to_field(175175)]];
//         let witness_out = vec![LayerWitness { instances: outputs }];

//         (
//             witness_in.clone(),
//             CircuitWitness {
//                 layers,
//                 witness_in,
//                 witness_out,
//                 n_instances: 1,
//                 challenges: HashMap::new(),
//             },
//         )
//     }

//     fn paste_from_wit_in_circuit<Ext: ExtensionField>() -> Circuit<Ext> {
//         let mut circuit_builder = CircuitBuilder::<Ext>::new();

//         // Layer 2
//         let (_leaf_id1, leaves1) = circuit_builder.create_witness_in(3);
//         let (_leaf_id2, leaves2) = circuit_builder.create_witness_in(3);
//         // Unused input elements should also be in the circuit.
//         let (_dummy_id, _) = circuit_builder.create_witness_in(3);
//         let _ = circuit_builder.create_counter_in(1);
//         let _ = circuit_builder.create_constant_in(2, 1);

//         // Layer 1
//         let (_, inners) = circuit_builder.create_witness_out(2);
//         circuit_builder.mul2(inners[0], leaves1[0], leaves1[1], Ext::BaseField::ONE);
//         circuit_builder.mul2(inners[1], leaves1[2], leaves2[0], Ext::BaseField::ONE);

//         // Layer 0
//         let (_, root) = circuit_builder.create_witness_out(1);
//         circuit_builder.mul2(root[0], inners[0], inners[1], Ext::BaseField::ONE);

//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);
//         circuit
//     }

//     fn paste_from_wit_in_witness<Ext: ExtensionField>() -> (
//         Vec<LayerWitness<Ext::BaseField>>,
//         CircuitWitness<Ext::BaseField>,
//     ) {
//         // witness_in, single instance
//         let leaves1 = vec![vec![i64_to_field(5), i64_to_field(7), i64_to_field(11)]];
//         let leaves2 = vec![vec![i64_to_field(13), i64_to_field(17), i64_to_field(19)]];
//         let dummy = vec![vec![i64_to_field(13), i64_to_field(17), i64_to_field(19)]];
//         let witness_in = vec![
//             LayerWitness { instances: leaves1 },
//             LayerWitness { instances: leaves2 },
//             LayerWitness { instances: dummy },
//         ];

//         let layers = vec![
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(5005),
//                     i64_to_field(35),
//                     i64_to_field(143),
//                     i64_to_field(0), // pad
//                 ]],
//             },
//             LayerWitness {
//                 instances: vec![vec![i64_to_field(35), i64_to_field(143)]],
//             },
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(5), // leaves1
//                     i64_to_field(7),
//                     i64_to_field(11),
//                     i64_to_field(13), // leaves2
//                     i64_to_field(17),
//                     i64_to_field(19),
//                     i64_to_field(13), // dummy
//                     i64_to_field(17),
//                     i64_to_field(19),
//                     i64_to_field(0), // counter
//                     i64_to_field(1),
//                     i64_to_field(1), // constant
//                     i64_to_field(1),
//                     i64_to_field(0), // pad
//                     i64_to_field(0),
//                     i64_to_field(0),
//                 ]],
//             },
//         ];

//         let outputs1 = vec![vec![i64_to_field(35), i64_to_field(143)]];
//         let outputs2 = vec![vec![i64_to_field(5005)]];
//         let witness_out = vec![
//             LayerWitness {
//                 instances: outputs1,
//             },
//             LayerWitness {
//                 instances: outputs2,
//             },
//         ];

//         (
//             witness_in.clone(),
//             CircuitWitness {
//                 layers,
//                 witness_in,
//                 witness_out,
//                 n_instances: 1,
//                 challenges: HashMap::new(),
//             },
//         )
//     }

//     fn copy_to_wit_out_circuit<Ext: ExtensionField>() -> Circuit<Ext> {
//         let mut circuit_builder = CircuitBuilder::<Ext>::new();
//         // Layer 2
//         let (_, leaves) = circuit_builder.create_witness_in(4);

//         // Layer 1
//         let (_inner_id, inners) = circuit_builder.create_witness_out(2);
//         circuit_builder.mul2(inners[0], leaves[0], leaves[1], Ext::BaseField::ONE);
//         circuit_builder.mul2(inners[1], leaves[2], leaves[3], Ext::BaseField::ONE);

//         // Layer 0
//         let root = circuit_builder.create_cell();
//         circuit_builder.mul2(root, inners[0], inners[1], Ext::BaseField::ONE);
//         circuit_builder.assert_const(root, 5005);

//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);

//         circuit
//     }

//     fn copy_to_wit_out_witness<Ext: ExtensionField>() -> (
//         Vec<LayerWitness<Ext::BaseField>>,
//         CircuitWitness<Ext::BaseField>,
//     ) {
//         // witness_in, single instance
//         let leaves = vec![vec![
//             i64_to_field(5),
//             i64_to_field(7),
//             i64_to_field(11),
//             i64_to_field(13),
//         ]];
//         let witness_in = vec![LayerWitness { instances: leaves }];

//         let layers = vec![
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(5005),
//                     i64_to_field(35),
//                     i64_to_field(143),
//                     i64_to_field(0), // pad
//                 ]],
//             },
//             LayerWitness {
//                 instances: vec![vec![i64_to_field(35), i64_to_field(143)]],
//             },
//             LayerWitness {
//                 instances: vec![vec![
//                     i64_to_field(5),
//                     i64_to_field(7),
//                     i64_to_field(11),
//                     i64_to_field(13),
//                 ]],
//             },
//         ];

//         let outputs = vec![vec![i64_to_field(35), i64_to_field(143)]];
//         let witness_out = vec![LayerWitness { instances: outputs }];

//         (
//             witness_in.clone(),
//             CircuitWitness {
//                 layers,
//                 witness_in,
//                 witness_out,
//                 n_instances: 1,
//                 challenges: HashMap::new(),
//             },
//         )
//     }

//     fn copy_to_wit_out_witness_2<Ext: ExtensionField>() -> (
//         Vec<LayerWitness<Ext::BaseField>>,
//         CircuitWitness<Ext::BaseField>,
//     ) {
//         // witness_in, 2 instances
//         let leaves = vec![
//             vec![
//                 i64_to_field(5),
//                 i64_to_field(7),
//                 i64_to_field(11),
//                 i64_to_field(13),
//             ],
//             vec![
//                 i64_to_field(5),
//                 i64_to_field(13),
//                 i64_to_field(11),
//                 i64_to_field(7),
//             ],
//         ];
//         let witness_in = vec![LayerWitness { instances: leaves }];

//         let layers = vec![
//             LayerWitness {
//                 instances: vec![
//                     vec![
//                         i64_to_field(5005),
//                         i64_to_field(35),
//                         i64_to_field(143),
//                         i64_to_field(0), // pad
//                     ],
//                     vec![
//                         i64_to_field(5005),
//                         i64_to_field(65),
//                         i64_to_field(77),
//                         i64_to_field(0), // pad
//                     ],
//                 ],
//             },
//             LayerWitness {
//                 instances: vec![
//                     vec![i64_to_field(35), i64_to_field(143)],
//                     vec![i64_to_field(65), i64_to_field(77)],
//                 ],
//             },
//             LayerWitness {
//                 instances: vec![
//                     vec![
//                         i64_to_field(5),
//                         i64_to_field(7),
//                         i64_to_field(11),
//                         i64_to_field(13),
//                     ],
//                     vec![
//                         i64_to_field(5),
//                         i64_to_field(13),
//                         i64_to_field(11),
//                         i64_to_field(7),
//                     ],
//                 ],
//             },
//         ];

//         let outputs = vec![
//             vec![i64_to_field(35), i64_to_field(143)],
//             vec![i64_to_field(65), i64_to_field(77)],
//         ];
//         let witness_out = vec![LayerWitness { instances: outputs }];

//         (
//             witness_in.clone(),
//             CircuitWitness {
//                 layers,
//                 witness_in,
//                 witness_out,
//                 n_instances: 2,
//                 challenges: HashMap::new(),
//             },
//         )
//     }

//     fn rlc_circuit<Ext: ExtensionField>() -> Circuit<Ext> {
//         let mut circuit_builder = CircuitBuilder::<Ext>::new();
//         // Layer 2
//         let (_, leaves) = circuit_builder.create_witness_in(4);

//         // Layer 1
//         let inners = circuit_builder.create_ext_cells(2);
//         circuit_builder.rlc(&inners[0], &[leaves[0], leaves[1]], 0 as ChallengeId);
//         circuit_builder.rlc(&inners[1], &[leaves[2], leaves[3]], 1 as ChallengeId);

//         // Layer 0
//         let (_root_id, roots) = circuit_builder.create_ext_witness_out(1);
//         circuit_builder.mul2_ext(&roots[0], &inners[0], &inners[1], Ext::BaseField::ONE);

//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);

//         circuit
//     }

//     fn rlc_witness_2<Ext>() -> (
//         Vec<LayerWitness<Ext::BaseField>>,
//         CircuitWitness<Ext::BaseField>,
//         Vec<Ext>,
//     )
//     where
//         Ext: ExtensionField<DEGREE = 2>,
//     {
//         let challenges = vec![
//             Ext::from_bases(&[i64_to_field(31), i64_to_field(37)]),
//             Ext::from_bases(&[i64_to_field(97), i64_to_field(23)]),
//         ];
//         let challenge_pows = challenges
//             .iter()
//             .enumerate()
//             .map(|(i, x)| {
//                 (0..3)
//                     .map(|j| {
//                         (
//                             ChallengeConst {
//                                 challenge: i as u8,
//                                 exp: j as u64,
//                             },
//                             x.pow(&[j as u64]),
//                         )
//                     })
//                     .collect_vec()
//             })
//             .collect_vec();

//         // witness_in, double instances
//         let leaves = vec![
//             vec![
//                 i64_to_field(5),
//                 i64_to_field(7),
//                 i64_to_field(11),
//                 i64_to_field(13),
//             ],
//             vec![
//                 i64_to_field(5),
//                 i64_to_field(13),
//                 i64_to_field(11),
//                 i64_to_field(7),
//             ],
//         ];
//         let witness_in = vec![LayerWitness {
//             instances: leaves.clone(),
//         }];

//         let inner00: Ext = challenge_pows[0][0].1 * (&leaves[0][0])
//             + challenge_pows[0][1].1 * (&leaves[0][1])
//             + challenge_pows[0][2].1;
//         let inner01: Ext = challenge_pows[1][0].1 * (&leaves[0][2])
//             + challenge_pows[1][1].1 * (&leaves[0][3])
//             + challenge_pows[1][2].1;
//         let inner10: Ext = challenge_pows[0][0].1 * (&leaves[1][0])
//             + challenge_pows[0][1].1 * (&leaves[1][1])
//             + challenge_pows[0][2].1;
//         let inner11: Ext = challenge_pows[1][0].1 * (&leaves[1][2])
//             + challenge_pows[1][1].1 * (&leaves[1][3])
//             + challenge_pows[1][2].1;

//         let inners = vec![
//             [
//                 inner00.clone().as_bases().to_vec(),
//                 inner01.clone().as_bases().to_vec(),
//             ]
//             .concat(),
//             [
//                 inner10.clone().as_bases().to_vec(),
//                 inner11.clone().as_bases().to_vec(),
//             ]
//             .concat(),
//         ];

//         let root_tmp0 = vec![
//             inners[0][0] * inners[0][2],
//             inners[0][0] * inners[0][3],
//             inners[0][1] * inners[0][2],
//             inners[0][1] * inners[0][3],
//         ];
//         let root_tmp1 = vec![
//             inners[1][0] * inners[1][2],
//             inners[1][0] * inners[1][3],
//             inners[1][1] * inners[1][2],
//             inners[1][1] * inners[1][3],
//         ];
//         let root_tmps = vec![root_tmp0, root_tmp1];

//         let root0 = inner00 * inner01;
//         let root1 = inner10 * inner11;
//         let roots = vec![root0.as_bases().to_vec(), root1.as_bases().to_vec()];

//         let layers = vec![
//             LayerWitness {
//                 instances: roots.clone(),
//             },
//             LayerWitness {
//                 instances: root_tmps,
//             },
//             LayerWitness { instances: inners },
//             LayerWitness { instances: leaves },
//         ];

//         let outputs = roots;
//         let witness_out = vec![LayerWitness { instances: outputs }];

//         (
//             witness_in.clone(),
//             CircuitWitness {
//                 layers,
//                 witness_in,
//                 witness_out,
//                 n_instances: 2,
//                 challenges: challenge_pows
//                     .iter()
//                     .flatten()
//                     .cloned()
//                     .map(|(k, v)| (k, v.as_bases().to_vec()))
//                     .collect::<HashMap<_, _>>(),
//             },
//             challenges,
//         )
//     }

//     #[test]
//     fn test_add_instances() {
//         let circuit = copy_and_paste_circuit::<GoldilocksExt2>();
//         let (wits_in, expect_circuit_wits) = copy_and_paste_witness::<GoldilocksExt2>();

//         let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
//         circuit_wits.add_instances(&circuit, wits_in, 1);

//         assert_eq!(circuit_wits, expect_circuit_wits);

//         let circuit = paste_from_wit_in_circuit::<GoldilocksExt2>();
//         let (wits_in, expect_circuit_wits) = paste_from_wit_in_witness::<GoldilocksExt2>();

//         let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
//         circuit_wits.add_instances(&circuit, wits_in, 1);

//         assert_eq!(circuit_wits, expect_circuit_wits);

//         let circuit = copy_to_wit_out_circuit::<GoldilocksExt2>();
//         let (wits_in, expect_circuit_wits) = copy_to_wit_out_witness::<GoldilocksExt2>();

//         let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
//         circuit_wits.add_instances(&circuit, wits_in, 1);

//         assert_eq!(circuit_wits, expect_circuit_wits);

//         let (wits_in, expect_circuit_wits) = copy_to_wit_out_witness_2::<GoldilocksExt2>();
//         let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
//         circuit_wits.add_instances(&circuit, wits_in, 2);

//         assert_eq!(circuit_wits, expect_circuit_wits);
//     }

//     #[test]
//     fn test_check_correctness() {
//         let circuit = copy_to_wit_out_circuit::<GoldilocksExt2>();
//         let (_wits_in, expect_circuit_wits) = copy_to_wit_out_witness_2::<GoldilocksExt2>();

//         expect_circuit_wits.check_correctness(&circuit);
//     }

//     #[test]
//     fn test_challenges() {
//         let circuit = rlc_circuit::<GoldilocksExt2>();
//         let (wits_in, expect_circuit_wits, challenges) = rlc_witness_2::<GoldilocksExt2>();
//         let mut circuit_wits = CircuitWitness::new(&circuit, challenges);
//         circuit_wits.add_instances(&circuit, wits_in, 2);

//         assert_eq!(circuit_wits, expect_circuit_wits);
//     }

//     #[test]
//     fn test_orphan_const_input() {
//         // create circuit
//         let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();

//         let (_, leaves) = circuit_builder.create_witness_in(3);
//         let mul_0_1_res = circuit_builder.create_cell();

//         // 2 * 3 = 6
//         circuit_builder.mul2(
//             mul_0_1_res,
//             leaves[0],
//             leaves[1],
//             <GoldilocksExt2 as ExtensionField>::BaseField::ONE,
//         );

//         let (_, out) = circuit_builder.create_witness_out(2);
//         // like a bypass gate, passing 6 to output out[0]
//         circuit_builder.add(
//             out[0],
//             mul_0_1_res,
//             <GoldilocksExt2 as ExtensionField>::BaseField::ONE,
//         );

//         // assert const 2
//         circuit_builder.assert_const(leaves[2], 5);

//         // 5 + -5 = 0, put in out[1]
//         circuit_builder.add(
//             out[1],
//             leaves[2],
//             <GoldilocksExt2 as ExtensionField>::BaseField::ONE,
//         );
//         circuit_builder.add_const(
//             out[1],
//             <GoldilocksExt2 as ExtensionField>::BaseField::from(5).neg(), // -5
//         );

//         // assert out[1] == 0
//         circuit_builder.assert_const(out[1], 0);

//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);

//         let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
//         let witness_in = vec![LayerWitness {
//             instances: vec![vec![i64_to_field(2), i64_to_field(3), i64_to_field(5)]],
//         }];
//         circuit_wits.add_instances(&circuit, witness_in, 1);

//         println!("circuit_wits {:?}", circuit_wits);
//         let output_layer_witness = &circuit_wits.layers[0];
//         for gate in circuit.assert_consts.iter() {
//             if let ConstantType::Field(constant) = gate.scalar {
//                 assert_eq!(output_layer_witness.instances[0][gate.idx_out], constant);
//             }
//         }
//     }
// }
