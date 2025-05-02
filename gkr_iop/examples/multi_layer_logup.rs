use std::{marker::PhantomData, mem, sync::Arc};

use ff_ext::ExtensionField;
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    evaluation::{EvalExpression, PointAndEval},
    gkr::{
        GKRCircuitWitness, GKRProverOutput,
        layer::{Layer, LayerType, LayerWitness},
    },
};
use itertools::{Itertools, izip};
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks;
use rand::{Rng, rngs::OsRng};
use subprotocols::expression::{Constant, Expression};
use transcript::{BasicTranscript, Transcript};

#[cfg(debug_assertions)]
use gkr_iop::gkr::mock::MockProver;

#[cfg(debug_assertions)]
use subprotocols::expression::VectorType;

type E = BinomialExtensionField<Goldilocks, 2>;

#[derive(Clone, Debug, Default)]
struct TowerParams {
    height: usize,
}

#[derive(Clone, Debug, Default)]
struct TowerChipLayout<E> {
    params: TowerParams,

    // Committed poly indices.
    committed_table_id: usize,
    committed_count_id: usize,

    lookup_challenge: Constant,

    output_cumulative_sum: [EvalExpression; 2],

    _field: PhantomData<E>,
}

impl<E: ExtensionField> ProtocolBuilder for TowerChipLayout<E> {
    type Params = TowerParams;

    fn init(params: Self::Params) -> Self {
        Self {
            params,
            ..Default::default()
        }
    }

    fn build_commit_phase(&mut self, chip: &mut Chip) {
        [self.committed_table_id, self.committed_count_id] = chip.allocate_committed_base();
        [self.lookup_challenge] = chip.allocate_challenges();
    }

    fn build_gkr_phase(&mut self, chip: &mut Chip) {
        let height = self.params.height;
        let lookup_challenge = Expression::Const(self.lookup_challenge.clone());

        self.output_cumulative_sum = chip.allocate_output_evals::<2>().try_into().unwrap();

        // Tower layers
        let ([updated_table, count], challenges) = (0..height).fold(
            (self.output_cumulative_sum.clone(), vec![]),
            |([den, num], challenges), i| {
                let [den_0, den_1, num_0, num_1] = if i == height - 1 {
                    // Allocate witnesses in the extension field, except numerator inputs in the
                    // base field.
                    let ([num_0, num_1], [den_0, den_1]) = chip.allocate_wits_in_layer();
                    [den_0, den_1, num_0, num_1]
                } else {
                    let ([], [den_0, den_1, num_0, num_1]) = chip.allocate_wits_in_layer();
                    [den_0, den_1, num_0, num_1]
                };

                let [den_expr_0, den_expr_1, num_expr_0, num_expr_1]: [Expression; 4] = [
                    den_0.0.into(),
                    den_1.0.into(),
                    num_0.0.into(),
                    num_1.0.into(),
                ];
                let (in_bases, in_exts) = if i == height - 1 {
                    (vec![num_0.1.clone(), num_1.1.clone()], vec![
                        den_0.1.clone(),
                        den_1.1.clone(),
                    ])
                } else {
                    (vec![], vec![
                        den_0.1.clone(),
                        den_1.1.clone(),
                        num_0.1.clone(),
                        num_1.1.clone(),
                    ])
                };
                chip.add_layer(Layer::new(
                    format!("Tower_layer_{}", i),
                    LayerType::Zerocheck,
                    vec![
                        den_expr_0.clone() * den_expr_1.clone(),
                        den_expr_0 * num_expr_1 + den_expr_1 * num_expr_0,
                    ],
                    challenges,
                    in_bases,
                    in_exts,
                    vec![den, num],
                    vec![],
                ));
                let [challenge] = chip.allocate_challenges();
                (
                    [
                        EvalExpression::Partition(
                            vec![Box::new(den_0.1), Box::new(den_1.1)],
                            vec![(0, challenge.clone())],
                        ),
                        EvalExpression::Partition(
                            vec![Box::new(num_0.1), Box::new(num_1.1)],
                            vec![(0, challenge.clone())],
                        ),
                    ],
                    vec![challenge],
                )
            },
        );

        // Preprocessing layer, compute table + challenge
        let ([table], []) = chip.allocate_wits_in_layer();

        chip.add_layer(Layer::new(
            "Update_table".to_string(),
            LayerType::Linear,
            vec![lookup_challenge + table.0.into()],
            challenges,
            vec![table.1.clone()],
            vec![],
            vec![updated_table],
            vec![],
        ));

        chip.allocate_base_opening(self.committed_table_id, table.1);
        chip.allocate_base_opening(self.committed_count_id, count);
    }
}

pub struct TowerChipTrace {
    pub table: Vec<u64>,
    pub multiplicity: Vec<u64>,
}

impl<E> ProtocolWitnessGenerator<E> for TowerChipLayout<E>
where
    E: ExtensionField,
{
    type Trace = TowerChipTrace;

    fn phase1_witness(&self, phase1: Self::Trace) -> Vec<Vec<E::BaseField>> {
        let mut res = vec![vec![]; 2];
        res[self.committed_table_id] = phase1
            .table
            .into_iter()
            .map(E::BaseField::from_u64)
            .collect();
        res[self.committed_count_id] = phase1
            .multiplicity
            .into_iter()
            .map(E::BaseField::from_u64)
            .collect();
        res
    }

    fn gkr_witness(&self, phase1: &[Vec<E::BaseField>], challenges: &[E]) -> GKRCircuitWitness<E> {
        // Generate witnesses.
        let table = &phase1[self.committed_table_id];
        let count = &phase1[self.committed_count_id];
        let beta = self.lookup_challenge.entry(challenges);

        // Compute table + beta.
        let n_layers = self.params.height + 1;
        let mut layer_wits = Vec::<LayerWitness<E>>::with_capacity(n_layers);
        layer_wits.push(LayerWitness::new(vec![table.clone()], vec![]));

        // Compute den_0, den_1, num_0, num_1 for each layer.
        let updated_table = table.iter().cloned().map(|x| beta + x).collect_vec();

        let (num_0, num_1): (Vec<E::BaseField>, Vec<E::BaseField>) = count.iter().tuples().unzip();
        let (den_0, den_1): (Vec<E>, Vec<E>) = updated_table.into_iter().tuples().unzip();
        let (mut last_den, mut last_num): (Vec<_>, Vec<_>) = izip!(&den_0, &den_1, &num_0, &num_1)
            .map(|(&den_0, &den_1, &num_0, &num_1)| (den_0 * den_1, den_0 * num_1 + den_1 * num_0))
            .unzip();

        layer_wits.push(LayerWitness::new(vec![num_0, num_1], vec![den_0, den_1]));

        layer_wits.extend((1..self.params.height).map(|_i| {
            let (den_0, den_1): (Vec<E>, Vec<E>) =
                mem::take(&mut last_den).into_iter().tuples().unzip();
            let (num_0, num_1): (Vec<E>, Vec<E>) =
                mem::take(&mut last_num).into_iter().tuples().unzip();

            (last_den, last_num) = izip!(&den_0, &den_1, &num_0, &num_1)
                .map(|(&den_0, &den_1, &num_0, &num_1)| {
                    (den_0 * den_1, den_0 * num_1 + den_1 * num_0)
                })
                .unzip();

            LayerWitness::new(vec![], vec![den_0, den_1, num_0, num_1])
        }));
        layer_wits.reverse();

        GKRCircuitWitness { layers: layer_wits }
    }
}

fn main() {
    let log_size = 3;
    let params = TowerParams { height: log_size };
    let (layout, chip) = TowerChipLayout::build(params);
    let gkr_circuit = chip.gkr_circuit();

    let (out_evals, gkr_proof) = {
        let table = (0..1 << log_size)
            .map(|_| OsRng.gen_range(0..1 << log_size as u64))
            .collect_vec();
        let count = (0..1 << log_size)
            .map(|_| OsRng.gen_range(0..1 << log_size as u64))
            .collect_vec();
        let phase1_witness = layout.phase1_witness(TowerChipTrace {
            table,
            multiplicity: count,
        });

        let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

        // Omit the commit phase1 and phase2.

        let challenges = vec![
            prover_transcript
                .sample_and_append_challenge(b"lookup challenge")
                .elements,
        ];
        let gkr_witness = layout.gkr_witness(&phase1_witness, &challenges);

        #[cfg(debug_assertions)]
        {
            let last = gkr_witness.layers[0].exts.clone();
            MockProver::check(
                gkr_circuit.clone(),
                &gkr_witness,
                vec![
                    VectorType::Ext(vec![last[0][0] * last[1][0]]),
                    VectorType::Ext(vec![last[0][0] * last[3][0] + last[1][0] * last[2][0]]),
                ],
                challenges.clone(),
            )
            .expect("Mock prover failed");
        }

        let out_evals = {
            let last = gkr_witness.layers[0].exts.clone();
            let point = Arc::new(vec![]);
            assert_eq!(last[0].len(), 1);
            vec![
                PointAndEval {
                    point: point.clone(),
                    eval: last[0][0] * last[1][0],
                },
                PointAndEval {
                    point,
                    eval: last[0][0] * last[3][0] + last[1][0] * last[2][0],
                },
            ]
        };
        let GKRProverOutput { gkr_proof, .. } = gkr_circuit
            .prove(gkr_witness, &out_evals, &challenges, &mut prover_transcript)
            .expect("Failed to prove phase");

        // Omit the PCS opening phase.

        (out_evals, gkr_proof)
    };

    {
        let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

        // Omit the commit phase1 and phase2.
        let challenges = vec![
            verifier_transcript
                .sample_and_append_challenge(b"lookup challenge")
                .elements,
        ];

        gkr_circuit
            .verify(gkr_proof, &out_evals, &challenges, &mut verifier_transcript)
            .expect("GKR verify failed");

        // Omit the PCS opening phase.
    }
}
