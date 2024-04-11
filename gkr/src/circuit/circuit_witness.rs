use std::{collections::HashMap, fmt::Debug};

use goldilocks::SmallField;
use itertools::{izip, Itertools};
use multilinear_extensions::mle::ArcDenseMultilinearExtension;
use simple_frontend::structs::{ChallengeConst, ConstantType, LayerId};

use crate::{
    structs::{Circuit, CircuitWitness, LayerWitness},
    utils::{ceil_log2, i64_to_field, MultilinearExtensionFromVectors},
};

use super::EvaluateConstant;

impl<F: SmallField> CircuitWitness<F> {
    /// Initialize the structure of the circuit witness.
    pub fn new<E>(circuit: &Circuit<E>, challenges: Vec<E>) -> Self
    where
        E: SmallField<BaseField = F>,
    {
        Self {
            layers: vec![LayerWitness::default(); circuit.layers.len()],
            witness_in: vec![LayerWitness::default(); circuit.n_witness_in],
            witness_out: vec![LayerWitness::default(); circuit.n_witness_out],
            n_instances: 0,
            challenges: circuit.generate_basefield_challenges(&challenges),
        }
    }

    /// Generate a fresh instance for the circuit, return layer witnesses and
    /// wire out witnesses.
    fn new_instances<E>(
        circuit: &Circuit<E>,
        wits_in: &[LayerWitness<F>],
        challenges: &HashMap<ChallengeConst, Vec<F>>,
        n_instances: usize,
    ) -> (Vec<LayerWitness<F>>, Vec<LayerWitness<F>>)
    where
        E: SmallField<BaseField = F>,
    {
        let n_layers = circuit.layers.len();
        let mut layer_wits = vec![
            LayerWitness {
                instances: vec![vec![]; n_instances]
            };
            n_layers
        ];

        // The first layer.
        layer_wits[n_layers - 1] = {
            let mut layer_wit =
                vec![vec![F::ZERO; circuit.layers[n_layers - 1].size()]; n_instances];
            for instance_id in 0..n_instances {
                for (wit_id, (l, r)) in circuit.paste_from_wits_in.iter().enumerate() {
                    for i in *l..*r {
                        layer_wit[instance_id][i] =
                            wits_in[wit_id as usize].instances[instance_id][i - *l];
                    }
                }
                for (constant, (l, r)) in circuit.paste_from_consts_in.iter() {
                    for i in *l..*r {
                        layer_wit[instance_id][i] = i64_to_field(*constant);
                    }
                }
                for (num_vars, (l, r)) in circuit.paste_from_counter_in.iter() {
                    for i in *l..*r {
                        layer_wit[instance_id][i] =
                            F::from(((instance_id << num_vars) ^ (i - *l)) as u64);
                    }
                }
            }
            LayerWitness {
                instances: layer_wit,
            }
        };

        for (layer_id, layer) in circuit.layers.iter().enumerate().rev().skip(1) {
            let size = circuit.layers[layer_id].size();
            let mut current_layer_wits = vec![vec![F::ZERO; size]; n_instances];

            izip!((0..n_instances), current_layer_wits.iter_mut()).for_each(
                |(instance_id, current_layer_wit)| {
                    layer
                        .paste_from
                        .iter()
                        .for_each(|(old_layer_id, new_wire_ids)| {
                            new_wire_ids.iter().enumerate().for_each(
                                |(subset_wire_id, new_wire_id)| {
                                    let old_wire_id = circuit.layers[*old_layer_id as usize]
                                        .copy_to
                                        .get(&(layer_id as LayerId))
                                        .unwrap()[subset_wire_id];
                                    current_layer_wit[*new_wire_id] = layer_wits
                                        [*old_layer_id as usize]
                                        .instances[instance_id][old_wire_id];
                                },
                            );
                        });

                    let last_layer_wit = &layer_wits[layer_id + 1].instances[instance_id];
                    for add_const in layer.add_consts.iter() {
                        current_layer_wit[add_const.idx_out] += add_const.scalar.eval(&challenges);
                    }

                    for add in layer.adds.iter() {
                        current_layer_wit[add.idx_out] +=
                            last_layer_wit[add.idx_in[0]] * add.scalar.eval(&challenges);
                    }

                    for mul2 in layer.mul2s.iter() {
                        current_layer_wit[mul2.idx_out] += last_layer_wit[mul2.idx_in[0]]
                            * last_layer_wit[mul2.idx_in[1]]
                            * mul2.scalar.eval(&challenges);
                    }

                    for mul3 in layer.mul3s.iter() {
                        current_layer_wit[mul3.idx_out] += last_layer_wit[mul3.idx_in[0]]
                            * last_layer_wit[mul3.idx_in[1]]
                            * last_layer_wit[mul3.idx_in[2]]
                            * mul3.scalar.eval(&challenges);
                    }
                },
            );

            layer_wits[layer_id] = LayerWitness {
                instances: current_layer_wits,
            };
        }
        let mut wits_out = vec![
            LayerWitness {
                instances: vec![vec![]; n_instances]
            };
            circuit.n_witness_out
        ];
        for instance_id in 0..n_instances {
            circuit
                .copy_to_wits_out
                .iter()
                .enumerate()
                .for_each(|(wit_id, old_wire_ids)| {
                    let mut wit_out = old_wire_ids
                        .iter()
                        .map(|old_wire_id| layer_wits[0].instances[instance_id][*old_wire_id])
                        .collect_vec();
                    let length = wit_out.len().next_power_of_two();
                    wit_out.resize(length, F::ZERO);
                    wits_out[wit_id].instances[instance_id] = wit_out;
                });
            circuit.assert_consts.iter().for_each(|gate| {
                if let ConstantType::Field(constant) = gate.scalar {
                    assert_eq!(layer_wits[0].instances[instance_id][gate.idx_out], constant);
                }
            });
        }
        (layer_wits, wits_out)
    }

    pub fn add_instance<E>(&mut self, circuit: &Circuit<E>, wits_in: Vec<Vec<F>>)
    where
        E: SmallField<BaseField = F>,
    {
        let wits_in = wits_in
            .into_iter()
            .map(|wit_in| LayerWitness {
                instances: vec![wit_in],
            })
            .collect_vec();
        self.add_instances(circuit, wits_in, 1);
    }

    pub fn add_instances<E>(
        &mut self,
        circuit: &Circuit<E>,
        wits_in: Vec<LayerWitness<F>>,
        n_instances: usize,
    ) where
        E: SmallField<BaseField = F>,
    {
        assert_eq!(wits_in.len(), circuit.n_witness_in);
        assert!(n_instances.is_power_of_two());
        assert!(!wits_in
            .iter()
            .any(|wit_in| wit_in.instances.len() != n_instances));

        let (new_layer_wits, new_wits_out) =
            CircuitWitness::new_instances(circuit, &wits_in, &self.challenges, n_instances);

        // Merge self and circuit_witness.
        for (layer_wit, new_layer_wit) in self.layers.iter_mut().zip(new_layer_wits.into_iter()) {
            layer_wit.instances.extend(new_layer_wit.instances);
        }

        for (wit_out, new_wit_out) in self.witness_out.iter_mut().zip(new_wits_out.into_iter()) {
            wit_out.instances.extend(new_wit_out.instances);
        }

        for (wit_in, new_wit_in) in self.witness_in.iter_mut().zip(wits_in.into_iter()) {
            wit_in.instances.extend(new_wit_in.instances);
        }

        self.n_instances += n_instances;
    }

    pub fn instance_num_vars(&self) -> usize {
        ceil_log2(self.n_instances)
    }

    pub fn check_correctness<Ext>(&self, circuit: &Circuit<Ext>)
    where
        Ext: SmallField<BaseField = F>,
    {
        // Check input.

        let input_layer_wits = self.layers.last().unwrap();
        let wits_in = self.witness_in_ref();
        for copy_id in 0..self.n_instances {
            for (wit_id, (l, r)) in circuit.paste_from_wits_in.iter().enumerate() {
                for (subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
                    assert_eq!(
                        input_layer_wits.instances[copy_id][new_wire_id],
                        wits_in[wit_id].instances[copy_id][subset_wire_id],
                        "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        circuit.layers.len() - 1,
                        copy_id,
                        new_wire_id,
                        input_layer_wits.instances[copy_id][new_wire_id],
                        wits_in[wit_id].instances[copy_id][subset_wire_id]
                    );
                }
            }
            for (constant, (l, r)) in circuit.paste_from_consts_in.iter() {
                for (_subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
                    assert_eq!(
                        input_layer_wits.instances[copy_id][new_wire_id],
                        i64_to_field(*constant),
                        "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        circuit.layers.len() - 1,
                        copy_id,
                        new_wire_id,
                        input_layer_wits.instances[copy_id][new_wire_id],
                        constant
                    );
                }
            }
            for (num_vars, (l, r)) in circuit.paste_from_counter_in.iter() {
                for (subset_wire_id, new_wire_id) in (*l..*r).enumerate() {
                    assert_eq!(
                        input_layer_wits.instances[copy_id][new_wire_id],
                        i64_to_field(((copy_id << num_vars) ^ subset_wire_id) as i64),
                        "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        circuit.layers.len() - 1,
                        copy_id,
                        new_wire_id,
                        input_layer_wits.instances[copy_id][new_wire_id],
                        (copy_id << num_vars) ^ subset_wire_id
                    );
                }
            }
        }

        for (layer_id, (layer_witnesses, layer)) in self
            .layers
            .iter()
            .zip(circuit.layers.iter())
            .enumerate()
            .rev()
            .skip(1)
        {
            let prev_layer_wits = &self.layers[layer_id + 1];
            for (copy_id, (prev, curr)) in prev_layer_wits
                .instances
                .iter()
                .zip(layer_witnesses.instances.iter())
                .enumerate()
            {
                let mut expected = vec![F::ZERO; curr.len()];
                for add_const in layer.add_consts.iter() {
                    expected[add_const.idx_out] += add_const.scalar.eval(&self.challenges);
                }
                for add in layer.adds.iter() {
                    expected[add.idx_out] +=
                        prev[add.idx_in[0]] * add.scalar.eval(&self.challenges);
                }
                for mul2 in layer.mul2s.iter() {
                    expected[mul2.idx_out] += prev[mul2.idx_in[0]]
                        * prev[mul2.idx_in[1]]
                        * mul2.scalar.eval(&self.challenges);
                }
                for mul3 in layer.mul3s.iter() {
                    expected[mul3.idx_out] += prev[mul3.idx_in[0]]
                        * prev[mul3.idx_in[1]]
                        * prev[mul3.idx_in[2]]
                        * mul3.scalar.eval(&self.challenges);
                }

                let mut expected_max_previous_size = prev.len();
                for (old_layer_id, new_wire_ids) in layer.paste_from.iter() {
                    expected_max_previous_size = expected_max_previous_size.max(new_wire_ids.len());
                    for (subset_wire_id, new_wire_id) in new_wire_ids.iter().enumerate() {
                        let old_wire_id = circuit.layers[*old_layer_id as usize]
                            .copy_to
                            .get(&(layer_id as LayerId))
                            .unwrap()[subset_wire_id];
                        expected[*new_wire_id] =
                            self.layers[*old_layer_id as usize].instances[copy_id][old_wire_id];
                    }
                }
                assert_eq!(
                    ceil_log2(expected_max_previous_size),
                    layer.max_previous_num_vars,
                    "layer: {}, expected_max_previous_size: {}, got: {}",
                    layer_id,
                    expected_max_previous_size,
                    layer.max_previous_num_vars
                );
                for (wire_id, (got, expected)) in curr.iter().zip(expected.iter()).enumerate() {
                    assert_eq!(
                        *got, *expected,
                        "layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        layer_id, copy_id, wire_id, got, expected
                    );
                }

                if layer_id != 0 {
                    for (new_layer_id, old_wire_ids) in layer.copy_to.iter() {
                        for (subset_wire_id, old_wire_id) in old_wire_ids.iter().enumerate() {
                            let new_wire_id = circuit.layers[*new_layer_id as usize]
                                .paste_from
                                .get(&(layer_id as LayerId))
                                .unwrap()[subset_wire_id];
                            assert_eq!(
                                curr[*old_wire_id],
                                self.layers[*new_layer_id as usize].instances[copy_id][new_wire_id],
                                "copy_to check: layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                                layer_id,
                                copy_id,
                                old_wire_id,
                                curr[*old_wire_id],
                                self.layers[*new_layer_id as usize].instances[copy_id][new_wire_id]
                            )
                        }
                    }
                }
            }
        }

        let output_layer_witness = &self.layers[0];
        let wits_out = self.witness_out_ref();
        for (wit_id, old_wire_ids) in circuit.copy_to_wits_out.iter().enumerate() {
            for copy_id in 0..self.n_instances {
                for (new_wire_id, old_wire_id) in old_wire_ids.iter().enumerate() {
                    assert_eq!(
                        output_layer_witness.instances[copy_id][*old_wire_id],
                        wits_out[wit_id].instances[copy_id][new_wire_id]
                    );
                }
            }
        }
        for gate in circuit.assert_consts.iter() {
            if let ConstantType::Field(constant) = gate.scalar {
                for copy_id in 0..self.n_instances {
                    assert_eq!(
                        output_layer_witness.instances[copy_id][gate.idx_out],
                        constant
                    );
                }
            }
        }
    }
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn output_layer_witness_ref(&self) -> &LayerWitness<F> {
        self.layers.first().unwrap()
    }

    pub fn n_instances(&self) -> usize {
        self.n_instances
    }

    pub fn witness_in_ref(&self) -> &[LayerWitness<F>] {
        &self.witness_in
    }

    pub fn witness_out_ref(&self) -> &[LayerWitness<F>] {
        &self.witness_out
    }

    pub fn challenges(&self) -> &HashMap<ChallengeConst, Vec<F>> {
        &self.challenges
    }

    pub fn layers_ref(&self) -> &[LayerWitness<F>] {
        &self.layers
    }
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn layer_poly<E>(
        &self,
        layer_id: LayerId,
        single_num_vars: usize,
    ) -> ArcDenseMultilinearExtension<E>
    where
        E: SmallField<BaseField = F>,
    {
        self.layers[layer_id as usize]
            .instances
            .as_slice()
            .mle(single_num_vars, self.instance_num_vars())
    }
}

impl<F: SmallField> Debug for CircuitWitness<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CircuitWitness {{")?;
        writeln!(f, "  n_instances: {}", self.n_instances)?;
        writeln!(f, "  layers: ")?;
        for (i, layer) in self.layers.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, layer)?;
        }
        writeln!(f, "  wires_in: ")?;
        for (i, wire) in self.witness_in.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, wire)?;
        }
        writeln!(f, "  wires_out: ")?;
        for (i, wire) in self.witness_out.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, wire)?;
        }
        writeln!(f, "  challenges: {:?}", self.challenges)?;
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ff::Field;
    use goldilocks::{GoldilocksExt2, SmallField};
    use itertools::Itertools;
    use simple_frontend::structs::{ChallengeConst, ChallengeId, CircuitBuilder};

    use crate::{
        structs::{Circuit, CircuitWitness, LayerWitness},
        utils::i64_to_field,
    };

    fn copy_and_paste_circuit<Ext: SmallField>() -> Circuit<Ext> {
        let mut circuit_builder = CircuitBuilder::<Ext>::new();
        // Layer 3
        let (_, input) = circuit_builder.create_witness_in(4);

        // Layer 2
        let mul_01 = circuit_builder.create_cell();
        circuit_builder.mul2(mul_01, input[0], input[1], Ext::BaseField::ONE);

        // Layer 1
        let mul_012 = circuit_builder.create_cell();
        circuit_builder.mul2(mul_012, mul_01, input[2], Ext::BaseField::ONE);

        // Layer 0
        let (_, mul_001123) = circuit_builder.create_witness_out(1);
        circuit_builder.mul3(
            mul_001123[0],
            mul_01,
            mul_012,
            input[3],
            Ext::BaseField::ONE,
        );

        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        circuit
    }

    fn copy_and_paste_witness<Ext: SmallField>() -> (
        Vec<LayerWitness<Ext::BaseField>>,
        CircuitWitness<Ext::BaseField>,
    ) {
        // witness_in, single instance
        let inputs = vec![vec![
            i64_to_field(5),
            i64_to_field(7),
            i64_to_field(11),
            i64_to_field(13),
        ]];
        let witness_in = vec![LayerWitness { instances: inputs }];

        let layers = vec![
            LayerWitness {
                instances: vec![vec![i64_to_field(175175)]],
            },
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(385),
                    i64_to_field(35),
                    i64_to_field(13),
                    i64_to_field(0), // pad
                ]],
            },
            LayerWitness {
                instances: vec![vec![i64_to_field(35), i64_to_field(11)]],
            },
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(5),
                    i64_to_field(7),
                    i64_to_field(11),
                    i64_to_field(13),
                ]],
            },
        ];

        let outputs = vec![vec![i64_to_field(175175)]];
        let witness_out = vec![LayerWitness { instances: outputs }];

        (
            witness_in.clone(),
            CircuitWitness {
                layers,
                witness_in,
                witness_out,
                n_instances: 1,
                challenges: HashMap::new(),
            },
        )
    }

    fn paste_from_wit_in_circuit<Ext: SmallField>() -> Circuit<Ext> {
        let mut circuit_builder = CircuitBuilder::<Ext>::new();

        // Layer 2
        let (_leaf_id1, leaves1) = circuit_builder.create_witness_in(3);
        let (_leaf_id2, leaves2) = circuit_builder.create_witness_in(3);
        // Unused input elements should also be in the circuit.
        let (_dummy_id, _) = circuit_builder.create_witness_in(3);
        let _ = circuit_builder.create_counter_in(1);
        let _ = circuit_builder.create_constant_in(2, 1);

        // Layer 1
        let (_, inners) = circuit_builder.create_witness_out(2);
        circuit_builder.mul2(inners[0], leaves1[0], leaves1[1], Ext::BaseField::ONE);
        circuit_builder.mul2(inners[1], leaves1[2], leaves2[0], Ext::BaseField::ONE);

        // Layer 0
        let (_, root) = circuit_builder.create_witness_out(1);
        circuit_builder.mul2(root[0], inners[0], inners[1], Ext::BaseField::ONE);

        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);
        circuit
    }

    fn paste_from_wit_in_witness<Ext: SmallField>() -> (
        Vec<LayerWitness<Ext::BaseField>>,
        CircuitWitness<Ext::BaseField>,
    ) {
        // witness_in, single instance
        let leaves1 = vec![vec![i64_to_field(5), i64_to_field(7), i64_to_field(11)]];
        let leaves2 = vec![vec![i64_to_field(13), i64_to_field(17), i64_to_field(19)]];
        let dummy = vec![vec![i64_to_field(13), i64_to_field(17), i64_to_field(19)]];
        let witness_in = vec![
            LayerWitness { instances: leaves1 },
            LayerWitness { instances: leaves2 },
            LayerWitness { instances: dummy },
        ];

        let layers = vec![
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(5005),
                    i64_to_field(35),
                    i64_to_field(143),
                    i64_to_field(0), // pad
                ]],
            },
            LayerWitness {
                instances: vec![vec![i64_to_field(35), i64_to_field(143)]],
            },
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(5), // leaves1
                    i64_to_field(7),
                    i64_to_field(11),
                    i64_to_field(13), // leaves2
                    i64_to_field(17),
                    i64_to_field(19),
                    i64_to_field(13), // dummy
                    i64_to_field(17),
                    i64_to_field(19),
                    i64_to_field(0), // counter
                    i64_to_field(1),
                    i64_to_field(1), // constant
                    i64_to_field(1),
                    i64_to_field(0), // pad
                    i64_to_field(0),
                    i64_to_field(0),
                ]],
            },
        ];

        let outputs1 = vec![vec![i64_to_field(35), i64_to_field(143)]];
        let outputs2 = vec![vec![i64_to_field(5005)]];
        let witness_out = vec![
            LayerWitness {
                instances: outputs1,
            },
            LayerWitness {
                instances: outputs2,
            },
        ];

        (
            witness_in.clone(),
            CircuitWitness {
                layers,
                witness_in,
                witness_out,
                n_instances: 1,
                challenges: HashMap::new(),
            },
        )
    }

    fn copy_to_wit_out_circuit<Ext: SmallField>() -> Circuit<Ext> {
        let mut circuit_builder = CircuitBuilder::<Ext>::new();
        // Layer 2
        let (_, leaves) = circuit_builder.create_witness_in(4);

        // Layer 1
        let (_inner_id, inners) = circuit_builder.create_witness_out(2);
        circuit_builder.mul2(inners[0], leaves[0], leaves[1], Ext::BaseField::ONE);
        circuit_builder.mul2(inners[1], leaves[2], leaves[3], Ext::BaseField::ONE);

        // Layer 0
        let root = circuit_builder.create_cell();
        circuit_builder.mul2(root, inners[0], inners[1], Ext::BaseField::ONE);
        circuit_builder.assert_const(root, 5005);

        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        circuit
    }

    fn copy_to_wit_out_witness<Ext: SmallField>() -> (
        Vec<LayerWitness<Ext::BaseField>>,
        CircuitWitness<Ext::BaseField>,
    ) {
        // witness_in, single instance
        let leaves = vec![vec![
            i64_to_field(5),
            i64_to_field(7),
            i64_to_field(11),
            i64_to_field(13),
        ]];
        let witness_in = vec![LayerWitness { instances: leaves }];

        let layers = vec![
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(5005),
                    i64_to_field(35),
                    i64_to_field(143),
                    i64_to_field(0), // pad
                ]],
            },
            LayerWitness {
                instances: vec![vec![i64_to_field(35), i64_to_field(143)]],
            },
            LayerWitness {
                instances: vec![vec![
                    i64_to_field(5),
                    i64_to_field(7),
                    i64_to_field(11),
                    i64_to_field(13),
                ]],
            },
        ];

        let outputs = vec![vec![i64_to_field(35), i64_to_field(143)]];
        let witness_out = vec![LayerWitness { instances: outputs }];

        (
            witness_in.clone(),
            CircuitWitness {
                layers,
                witness_in,
                witness_out,
                n_instances: 1,
                challenges: HashMap::new(),
            },
        )
    }

    fn copy_to_wit_out_witness_2<Ext: SmallField>() -> (
        Vec<LayerWitness<Ext::BaseField>>,
        CircuitWitness<Ext::BaseField>,
    ) {
        // witness_in, 2 instances
        let leaves = vec![
            vec![
                i64_to_field(5),
                i64_to_field(7),
                i64_to_field(11),
                i64_to_field(13),
            ],
            vec![
                i64_to_field(5),
                i64_to_field(13),
                i64_to_field(11),
                i64_to_field(7),
            ],
        ];
        let witness_in = vec![LayerWitness { instances: leaves }];

        let layers = vec![
            LayerWitness {
                instances: vec![
                    vec![
                        i64_to_field(5005),
                        i64_to_field(35),
                        i64_to_field(143),
                        i64_to_field(0), // pad
                    ],
                    vec![
                        i64_to_field(5005),
                        i64_to_field(65),
                        i64_to_field(77),
                        i64_to_field(0), // pad
                    ],
                ],
            },
            LayerWitness {
                instances: vec![
                    vec![i64_to_field(35), i64_to_field(143)],
                    vec![i64_to_field(65), i64_to_field(77)],
                ],
            },
            LayerWitness {
                instances: vec![
                    vec![
                        i64_to_field(5),
                        i64_to_field(7),
                        i64_to_field(11),
                        i64_to_field(13),
                    ],
                    vec![
                        i64_to_field(5),
                        i64_to_field(13),
                        i64_to_field(11),
                        i64_to_field(7),
                    ],
                ],
            },
        ];

        let outputs = vec![
            vec![i64_to_field(35), i64_to_field(143)],
            vec![i64_to_field(65), i64_to_field(77)],
        ];
        let witness_out = vec![LayerWitness { instances: outputs }];

        (
            witness_in.clone(),
            CircuitWitness {
                layers,
                witness_in,
                witness_out,
                n_instances: 2,
                challenges: HashMap::new(),
            },
        )
    }

    fn rlc_circuit<Ext: SmallField>() -> Circuit<Ext> {
        let mut circuit_builder = CircuitBuilder::<Ext>::new();
        // Layer 2
        let (_, leaves) = circuit_builder.create_witness_in(4);

        // Layer 1
        let inners = circuit_builder.create_ext_cells(2);
        circuit_builder.rlc(&inners[0], &[leaves[0], leaves[1]], 0 as ChallengeId);
        circuit_builder.rlc(&inners[1], &[leaves[2], leaves[3]], 1 as ChallengeId);

        // Layer 0
        let (_root_id, roots) = circuit_builder.create_ext_witness_out(1);
        circuit_builder.mul2_ext(&roots[0], &inners[0], &inners[1], Ext::BaseField::ONE);

        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        circuit
    }

    fn rlc_witness_2<Ext>() -> (
        Vec<LayerWitness<Ext::BaseField>>,
        CircuitWitness<Ext::BaseField>,
        Vec<Ext>,
    )
    where
        Ext: SmallField<DEGREE = 2>,
    {
        let challenges = vec![
            Ext::from_limbs(&[i64_to_field(31), i64_to_field(37)]),
            Ext::from_limbs(&[i64_to_field(97), i64_to_field(23)]),
        ];
        let challenge_pows = challenges
            .iter()
            .enumerate()
            .map(|(i, x)| {
                (0..3)
                    .map(|j| {
                        (
                            ChallengeConst {
                                challenge: i as u8,
                                exp: j as u64,
                            },
                            x.pow(&[j as u64]),
                        )
                    })
                    .collect_vec()
            })
            .collect_vec();

        // witness_in, double instances
        let leaves = vec![
            vec![
                i64_to_field(5),
                i64_to_field(7),
                i64_to_field(11),
                i64_to_field(13),
            ],
            vec![
                i64_to_field(5),
                i64_to_field(13),
                i64_to_field(11),
                i64_to_field(7),
            ],
        ];
        let witness_in = vec![LayerWitness {
            instances: leaves.clone(),
        }];

        let inner00 = challenge_pows[0][0].1.mul_base(&leaves[0][0])
            + challenge_pows[0][1].1.mul_base(&leaves[0][1])
            + challenge_pows[0][2].1;
        let inner01 = challenge_pows[1][0].1.mul_base(&leaves[0][2])
            + challenge_pows[1][1].1.mul_base(&leaves[0][3])
            + challenge_pows[1][2].1;
        let inner10 = challenge_pows[0][0].1.mul_base(&leaves[1][0])
            + challenge_pows[0][1].1.mul_base(&leaves[1][1])
            + challenge_pows[0][2].1;
        let inner11 = challenge_pows[1][0].1.mul_base(&leaves[1][2])
            + challenge_pows[1][1].1.mul_base(&leaves[1][3])
            + challenge_pows[1][2].1;

        let inners = vec![
            [inner00.clone().to_limbs(), inner01.clone().to_limbs()].concat(),
            [inner10.clone().to_limbs(), inner11.clone().to_limbs()].concat(),
        ];

        let root_tmp0 = vec![
            inners[0][0] * inners[0][2],
            inners[0][0] * inners[0][3],
            inners[0][1] * inners[0][2],
            inners[0][1] * inners[0][3],
        ];
        let root_tmp1 = vec![
            inners[1][0] * inners[1][2],
            inners[1][0] * inners[1][3],
            inners[1][1] * inners[1][2],
            inners[1][1] * inners[1][3],
        ];
        let root_tmps = vec![root_tmp0, root_tmp1];

        let root0 = inner00 * inner01;
        let root1 = inner10 * inner11;
        let roots = vec![root0.to_limbs(), root1.to_limbs()];

        let layers = vec![
            LayerWitness {
                instances: roots.clone(),
            },
            LayerWitness {
                instances: root_tmps,
            },
            LayerWitness { instances: inners },
            LayerWitness { instances: leaves },
        ];

        let outputs = roots;
        let witness_out = vec![LayerWitness { instances: outputs }];

        (
            witness_in.clone(),
            CircuitWitness {
                layers,
                witness_in,
                witness_out,
                n_instances: 2,
                challenges: challenge_pows
                    .iter()
                    .flatten()
                    .cloned()
                    .map(|(k, v)| (k, v.to_limbs()))
                    .collect::<HashMap<_, _>>(),
            },
            challenges,
        )
    }

    #[test]
    fn test_add_instances() {
        let circuit = copy_and_paste_circuit::<GoldilocksExt2>();
        let (wits_in, expect_circuit_wits) = copy_and_paste_witness::<GoldilocksExt2>();

        let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
        circuit_wits.add_instances(&circuit, wits_in, 1);

        assert_eq!(circuit_wits, expect_circuit_wits);

        let circuit = paste_from_wit_in_circuit::<GoldilocksExt2>();
        let (wits_in, expect_circuit_wits) = paste_from_wit_in_witness::<GoldilocksExt2>();

        let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
        circuit_wits.add_instances(&circuit, wits_in, 1);

        assert_eq!(circuit_wits, expect_circuit_wits);

        let circuit = copy_to_wit_out_circuit::<GoldilocksExt2>();
        let (wits_in, expect_circuit_wits) = copy_to_wit_out_witness::<GoldilocksExt2>();

        let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
        circuit_wits.add_instances(&circuit, wits_in, 1);

        assert_eq!(circuit_wits, expect_circuit_wits);

        let (wits_in, expect_circuit_wits) = copy_to_wit_out_witness_2::<GoldilocksExt2>();
        let mut circuit_wits = CircuitWitness::new(&circuit, vec![]);
        circuit_wits.add_instances(&circuit, wits_in, 2);

        assert_eq!(circuit_wits, expect_circuit_wits);
    }

    #[test]
    fn test_check_correctness() {
        let circuit = copy_to_wit_out_circuit::<GoldilocksExt2>();
        let (_wits_in, expect_circuit_wits) = copy_to_wit_out_witness_2::<GoldilocksExt2>();

        expect_circuit_wits.check_correctness(&circuit);
    }

    #[test]
    fn test_challenges() {
        let circuit = rlc_circuit::<GoldilocksExt2>();
        let (wits_in, expect_circuit_wits, challenges) = rlc_witness_2::<GoldilocksExt2>();
        let mut circuit_wits = CircuitWitness::new(&circuit, challenges);
        circuit_wits.add_instances(&circuit, wits_in, 2);

        assert_eq!(circuit_wits, expect_circuit_wits);
    }
}
