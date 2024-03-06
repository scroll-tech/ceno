use std::{collections::HashMap, fmt::Debug, sync::Arc};

use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use simple_frontend::structs::{ChallengeConst, ConstantType, InType, LayerId};

use crate::{
    structs::{Circuit, CircuitWitness},
    utils::{ceil_log2, i64_to_field, MultilinearExtensionFromVectors},
};

impl<F: SmallField> CircuitWitness<F> {
    /// Initialize the structure of the circuit witness.
    pub fn new<E>(circuit: &Circuit<E>, challenges: Vec<E>) -> Self
    where
        E: SmallField<BaseField = F>,
    {
        Self {
            layers: vec![vec![]; circuit.layers.len()],
            wires_in: vec![vec![]; circuit.n_wires_in],
            wires_out: vec![vec![]; circuit.copy_to_wires_out.len()],
            n_instances: 0,
            challenges: circuit.generate_basefield_challenges(&challenges),
        }
    }

    /// Generate a fresh instance for the circuit, return layer witnesses and
    /// wire out witnesses.
    fn new_instance<E, T>(
        instance_id: usize,
        circuit: &Circuit<E>,
        wires_in: &[T],
        challenges: &HashMap<ChallengeConst, Vec<F>>,
    ) -> (Vec<Vec<F>>, Vec<Vec<F>>)
    where
        E: SmallField<BaseField = F>,
        T: AsRef<[F]>,
    {
        let n_layers = circuit.layers.len();
        let mut layer_witnesses = vec![vec![]; n_layers];

        // The first layer.
        layer_witnesses[n_layers - 1] = {
            let mut layer_witness = vec![F::ZERO; circuit.layers[n_layers - 1].size()];
            for (ty, l, r) in circuit.paste_from_in.iter() {
                for i in *l..*r {
                    layer_witness[i] = match *ty {
                        InType::Counter(num_vars) => {
                            F::from(((instance_id << num_vars) ^ (i - *l)) as u64)
                        }
                        InType::Constant(c) => i64_to_field(c),
                        InType::Wire(id) => wires_in[id as usize].as_ref()[i - *l],
                    }
                }
            }
            layer_witness
        };

        for (layer_id, layer) in circuit.layers.iter().enumerate().rev().skip(1) {
            let size = circuit.layers[layer_id].size();
            let mut current_layer_witness = vec![F::ZERO; size];

            layer
                .paste_from
                .iter()
                .for_each(|(old_layer_id, new_wire_ids)| {
                    new_wire_ids
                        .iter()
                        .enumerate()
                        .for_each(|(subset_wire_id, new_wire_id)| {
                            let old_wire_id = circuit.layers[*old_layer_id as usize]
                                .copy_to
                                .get(&(layer_id as LayerId))
                                .unwrap()[subset_wire_id];
                            current_layer_witness[*new_wire_id] =
                                layer_witnesses[*old_layer_id as usize][old_wire_id];
                        });
                });

            let constant = |constant: ConstantType<E>| -> F {
                match constant {
                    ConstantType::Challenge(c, j) => challenges[&c][j],
                    ConstantType::ChallengeScaled(c, j, scalar) => challenges[&c][j] * scalar,
                    ConstantType::Field(c) => c,
                }
            };

            let last_layer_witness = &layer_witnesses[layer_id + 1];
            for add_const in layer.add_consts.iter() {
                current_layer_witness[add_const.idx_out] =
                    current_layer_witness[add_const.idx_out] + constant(add_const.scalar);
            }

            for add in layer.adds.iter() {
                current_layer_witness[add.idx_out] +=
                    last_layer_witness[add.idx_in[0]] * constant(add.scalar);
            }

            for mul2 in layer.mul2s.iter() {
                current_layer_witness[mul2.idx_out] = current_layer_witness[mul2.idx_out]
                    + last_layer_witness[mul2.idx_in[0]]
                        * last_layer_witness[mul2.idx_in[1]]
                        * constant(mul2.scalar);
            }

            for mul3 in layer.mul3s.iter() {
                current_layer_witness[mul3.idx_out] = current_layer_witness[mul3.idx_out]
                    + last_layer_witness[mul3.idx_in[0]]
                        * last_layer_witness[mul3.idx_in[1]]
                        * last_layer_witness[mul3.idx_in[2]]
                        * constant(mul3.scalar);
            }
            for assert_const in layer.assert_consts.iter() {
                assert_eq!(
                    current_layer_witness[assert_const.idx_out],
                    constant(assert_const.scalar),
                    "layer: {}, wire_id: {}, assert_const: {:?} != {:?}",
                    layer_id,
                    assert_const.idx_out,
                    current_layer_witness[assert_const.idx_out],
                    assert_const.scalar
                );
            }
            layer_witnesses[layer_id] = current_layer_witness;
        }
        let mut wires_out = vec![vec![]; circuit.copy_to_wires_out.len()];
        circuit
            .copy_to_wires_out
            .iter()
            .enumerate()
            .for_each(|(id, old_wire_ids)| {
                wires_out[id] = old_wire_ids
                    .iter()
                    .map(|old_wire_id| layer_witnesses[0][*old_wire_id])
                    .collect_vec();
            });
        (layer_witnesses, wires_out)
    }

    pub fn constant<E>(&self, constant: ConstantType<E>) -> F
    where
        E: SmallField<BaseField = F>,
    {
        match constant {
            ConstantType::Challenge(c, j) => self.challenges[&c][j],
            ConstantType::ChallengeScaled(c, j, scalar) => self.challenges[&c][j] * scalar,
            ConstantType::Field(c) => c,
        }
    }

    pub fn add_instances<E>(&mut self, circuit: &Circuit<E>, wires_in: &[Vec<Vec<F>>])
    where
        E: SmallField<BaseField = F>,
    {
        (0..wires_in[0].len()).for_each(|i| {
            let instance_wires_in = wires_in.iter().map(|w| &w[i]).collect_vec();
            self.add_instance(circuit, &instance_wires_in);
        });
    }

    /// Add another instance for the circuit.
    pub fn add_instance<E, T>(&mut self, circuit: &Circuit<E>, wires_in: &[T])
    where
        E: SmallField<BaseField = F>,
        T: AsRef<[F]>,
    {
        assert!(wires_in.len() == circuit.n_wires_in);
        let (new_layer_witnesses, new_wires_out) =
            CircuitWitness::new_instance(self.n_instances, circuit, wires_in, &self.challenges);

        // Merge self and circuit_witness.
        for (layer_witness, new_layer_witness) in
            self.layers.iter_mut().zip(new_layer_witnesses.into_iter())
        {
            layer_witness.push(new_layer_witness);
        }

        for (wire_out, new_wire_out) in self.wires_out.iter_mut().zip(new_wires_out.into_iter()) {
            wire_out.push(new_wire_out);
        }

        for (wire_in, new_wire_in) in self.wires_in.iter_mut().zip(wires_in.iter()) {
            wire_in.push(new_wire_in.as_ref().to_vec());
        }

        self.n_instances += 1;
    }

    pub fn instance_num_vars(&self) -> usize {
        ceil_log2(self.n_instances)
    }

    #[cfg(debug_assertions)]
    pub fn check_correctness<E>(&self, circuit: &Circuit<E>)
    where
        E: SmallField<BaseField = F>,
    {
        // Check input.
        let input_layer_witness = self.layers.last().unwrap();
        let input_layer = &circuit.layers.last().unwrap();
        let wires_in = self.wires_in_ref();
        for copy_id in 0..self.n_instances {
            for (id, new_wire_ids) in input_layer.paste_from.iter() {
                for (subset_wire_id, new_wire_id) in new_wire_ids.iter().enumerate() {
                    assert_eq!(
                        input_layer_witness[copy_id][*new_wire_id],
                        wires_in[*id as usize][copy_id][subset_wire_id],
                        "input layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        circuit.layers.len() - 1,
                        copy_id,
                        new_wire_id,
                        input_layer_witness[*new_wire_id],
                        wires_in[*id as usize][subset_wire_id]
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
            let prev_layer_witnesses = &self.layers[layer_id + 1];
            for (copy_id, (prev, curr)) in prev_layer_witnesses
                .iter()
                .zip(layer_witnesses.iter())
                .enumerate()
            {
                let mut expected = vec![F::ZERO; curr.len()];
                for add_const in layer.add_consts.iter() {
                    expected[add_const.idx_out] =
                        expected[add_const.idx_out] + self.constant(add_const.scalar);
                }
                for add in layer.adds.iter() {
                    expected[add.idx_out] += prev[add.idx_in[0]] * self.constant(add.scalar);
                }
                for mul2 in layer.mul2s.iter() {
                    expected[mul2.idx_out] = expected[mul2.idx_out]
                        + prev[mul2.idx_in[0]] * prev[mul2.idx_in[1]] * self.constant(mul2.scalar);
                }
                for mul3 in layer.mul3s.iter() {
                    expected[mul3.idx_out] = expected[mul3.idx_out]
                        + prev[mul3.idx_in[0]]
                            * prev[mul3.idx_in[1]]
                            * prev[mul3.idx_in[2]]
                            * self.constant(mul3.scalar);
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
                            self.layers[*old_layer_id as usize][copy_id][old_wire_id];
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
                for (new_layer_id, old_wire_ids) in layer.copy_to.iter() {
                    for (subset_wire_id, old_wire_id) in old_wire_ids.iter().enumerate() {
                        let new_wire_id = circuit.layers[*new_layer_id as usize]
                            .paste_from
                            .get(&(layer_id as LayerId))
                            .unwrap()[subset_wire_id];
                        assert_eq!(
                            curr[*old_wire_id],
                            self.layers[*new_layer_id as usize][copy_id][new_wire_id],
                            "copy_to check: layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                            layer_id,
                            copy_id,
                            old_wire_id,
                            curr[*old_wire_id],
                            self.layers[*new_layer_id as usize][copy_id][new_wire_id]
                        )
                    }
                }
                for (wire_id, (got, expected)) in curr.iter().zip(expected.iter()).enumerate() {
                    assert_eq!(
                        *got, *expected,
                        "layer: {}, copy_id: {}, wire_id: {}, got != expected: {:?} != {:?}",
                        layer_id, copy_id, wire_id, got, expected
                    );
                }
                for assert_const in layer.assert_consts.iter() {
                    assert_eq!(
                        curr[assert_const.idx_out],
                        self.constant(assert_const.scalar),
                        "layer: {}, wire_id: {}, assert_const: {:?} != {:?}",
                        layer_id,
                        assert_const.idx_out,
                        curr[assert_const.idx_out],
                        self.constant(assert_const.scalar)
                    );
                }
            }
        }
    }
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn last_layer_witness_ref(&self) -> &[Vec<F>] {
        self.layers.first().unwrap()
    }

    pub fn n_instances(&self) -> usize {
        self.n_instances
    }

    pub fn wires_in_ref(&self) -> &[Vec<Vec<F>>] {
        &self.wires_in
    }

    pub fn wires_out_ref(&self) -> &[Vec<Vec<F>>] {
        &self.wires_out
    }

    pub fn challenges(&self) -> &HashMap<ChallengeConst, Vec<F>> {
        &self.challenges
    }

    pub fn layers_ref(&self) -> &[Vec<Vec<F>>] {
        &self.layers
    }
}

impl<F: SmallField> CircuitWitness<F> {
    pub fn layer_poly<E>(
        &self,
        layer_id: LayerId,
        single_num_vars: usize,
    ) -> Arc<DenseMultilinearExtension<E>>
    where
        E: SmallField<BaseField = F>,
    {
        self.layers[layer_id as usize]
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
        for (i, wire) in self.wires_in.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, wire)?;
        }
        writeln!(f, "  wires_out: ")?;
        for (i, wire) in self.wires_out.iter().enumerate() {
            writeln!(f, "    {}: {:?}", i, wire)?;
        }
        writeln!(f, "  challenges: {:?}", self.challenges)?;
        writeln!(f, "}}")
    }
}
