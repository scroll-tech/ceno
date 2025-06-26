// use std::marker::PhantomData;

// use ff_ext::{ExtensionField, GoldilocksExt2};
// use gkr_iop::{
//     ProtocolBuilder, ProtocolWitnessGenerator,
//     chip::Chip,
//     evaluation::EvalExpression,
//     gkr::{
//         GKRProverOutput,
//         layer::{Layer, LayerType},
//     },
// };
// use itertools::Itertools;
// use multilinear_extensions::{Expression, ToExpr, mle::PointAndEval, util::max_usable_threads};
// use p3_field::FieldAlgebra;
// use rand::{Rng, rngs::OsRng};
// use transcript::{BasicTranscript, Transcript};

// #[cfg(debug_assertions)]
// use gkr_iop::gkr::mock::MockProver;

// use witness::RowMajorMatrix;

// type E = GoldilocksExt2;

// #[derive(Clone, Debug, Default)]
// struct TowerParams {
//     height: usize,
// }

// #[derive(Clone, Debug)]
// struct TowerChipLayout<E: ExtensionField> {
//     params: TowerParams,

//     // Committed poly indices.
//     committed_table_id: usize,
//     committed_count_id: usize,

//     output_cumulative_sum: [EvalExpression<E>; 2],

//     _field: PhantomData<E>,
// }

// impl<E: ExtensionField> ProtocolBuilder<E> for TowerChipLayout<E> {
//     type Params = TowerParams;

//     fn init(params: Self::Params) -> Self {
//         Self {
//             params,
//             committed_table_id: 0,
//             committed_count_id: 0,
//             output_cumulative_sum: [EvalExpression::Zero, EvalExpression::Zero],
//             _field: PhantomData,
//         }
//     }

//     fn build_gkr_chip(&mut self, chip: &mut Chip<E>) {
//         let height = self.params.height;
//         self.output_cumulative_sum = chip.allocate_output_evals::<2>().try_into().unwrap();

//         // Tower layers
//         let ([updated_table, count], challenges) = (0..height).fold(
//             (self.output_cumulative_sum.clone(), vec![]),
//             |([den, num], challenges), i| {
//                 let ([den_0, den_1, num_0, num_1], [eq]) = chip.allocate_wits_in_zero_layer();
//                 let [den_expr_0, den_expr_1, num_expr_0, num_expr_1]: [Expression<E>; 4] = [
//                     den_0.0.into(),
//                     den_1.0.into(),
//                     num_0.0.into(),
//                     num_1.0.into(),
//                 ];
//                 let in_evals = vec![
//                     den_0.1.clone(),
//                     den_1.1.clone(),
//                     num_0.1.clone(),
//                     num_1.1.clone(),
//                 ];
//                 chip.add_layer(Layer::new(
//                     format!("Tower_layer_{}", i),
//                     LayerType::Zerocheck,
//                     vec![
//                         den_expr_0.clone() * den_expr_1.clone(),
//                         den_expr_0 * num_expr_1 + den_expr_1 * num_expr_0,
//                     ],
//                     challenges,
//                     in_evals,
//                     vec![(Some(eq.0.expr()), vec![den, num])],
//                     Default::default(),
//                     vec!["denominator".to_string(), "numerator".to_string()],
//                 ));
//                 let [challenge] = chip.allocate_challenges();
//                 (
//                     [
//                         EvalExpression::Partition(
//                             vec![Box::new(den_0.1), Box::new(den_1.1)],
//                             vec![(0, Box::new(challenge.clone()))],
//                         ),
//                         EvalExpression::Partition(
//                             vec![Box::new(num_0.1), Box::new(num_1.1)],
//                             vec![(0, Box::new(challenge.clone()))],
//                         ),
//                     ],
//                     vec![challenge],
//                 )
//             },
//         );

//         // Preprocessing layer, compute table + challenge
//         let [table] = chip.allocate_wits_in_layer();

//         chip.add_layer(Layer::new(
//             "Update_table".to_string(),
//             LayerType::Linear,
//             vec![table.0.into()],
//             challenges,
//             vec![table.1.clone()],
//             vec![(None, vec![updated_table])],
//             Default::default(),
//             vec!["table".to_string()],
//         ));

//         chip.allocate_opening(self.committed_table_id, table.1);
//         chip.allocate_opening(self.committed_count_id, count);
//     }
// }

// pub struct TowerChipTrace {
//     pub table_with_multiplicity: Vec<(u64, u64)>,
// }

// impl<E> ProtocolWitnessGenerator<'_, E> for TowerChipLayout<E>
// where
//     E: ExtensionField,
// {
//     type Trace = TowerChipTrace;

//     fn phase1_witness_group(&self, phase1: Self::Trace) -> RowMajorMatrix<E::BaseField> {
//         let wits = phase1
//             .table_with_multiplicity
//             .iter()
//             .flat_map(|(x, y)| {
//                 vec![
//                     E::BaseField::from_canonical_u64(*x),
//                     E::BaseField::from_canonical_u64(*y),
//                 ]
//             })
//             .collect_vec();
//         RowMajorMatrix::new_by_values(wits, 2, witness::InstancePaddingStrategy::Default)
//     }
// }

// fn main() {
//     let num_threads = max_usable_threads();
//     let num_vars = 3;
//     let params = TowerParams { height: num_vars };
//     let (layout, chip) = TowerChipLayout::build(params);
//     let gkr_circuit = chip.gkr_circuit();

//     let (out_evals, gkr_proof) = {
//         let table_with_multiplicity = (0..1 << num_vars)
//             .map(|_| {
//                 (
//                     OsRng.gen_range(0..1 << num_vars as u64),
//                     OsRng.gen_range(0..1 << num_vars as u64),
//                 )
//             })
//             .collect_vec();
//         let phase1_witness_group = layout.phase1_witness_group(TowerChipTrace {
//             table_with_multiplicity,
//         });

//         let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");

//         // Omit the commit phase1 and phase2.

//         let challenges = vec![
//             prover_transcript
//                 .sample_and_append_challenge(b"lookup challenge")
//                 .elements,
//         ];
//         let (gkr_witness, _) = layout.gkr_witness(&gkr_circuit, &phase1_witness_group, &challenges);

//         #[cfg(debug_assertions)]
//         {
//             use multilinear_extensions::{mle::FieldType, smart_slice::SmartSlice};

//             let last = gkr_witness.layers[0].wits.clone();
//             MockProver::check(
//                 gkr_circuit.clone(),
//                 &gkr_witness,
//                 vec![
//                     FieldType::Ext(SmartSlice::Owned(vec![
//                         last[0].get_ext_field_vec()[0] * last[1].get_ext_field_vec()[0],
//                     ])),
//                     FieldType::Ext(SmartSlice::Owned(vec![
//                         last[0].get_ext_field_vec()[0] * last[3].get_ext_field_vec()[0]
//                             + last[1].get_ext_field_vec()[0] * last[2].get_ext_field_vec()[0],
//                     ])),
//                 ],
//                 challenges.clone(),
//             )
//             .expect("Mock prover failed");
//         }

//         let out_evals = {
//             let last = gkr_witness.layers[0].wits.clone();
//             let point = vec![];
//             assert_eq!(last[0].evaluations().len(), 1);
//             vec![
//                 PointAndEval {
//                     point: point.clone(),
//                     eval: last[0].get_ext_field_vec()[0] * last[1].get_ext_field_vec()[0],
//                 },
//                 PointAndEval {
//                     point,
//                     eval: last[0].get_ext_field_vec()[0] * last[3].get_ext_field_vec()[0]
//                         + last[1].get_ext_field_vec()[0] * last[2].get_ext_field_vec()[0],
//                 },
//             ]
//         };
//         let GKRProverOutput { gkr_proof, .. } = gkr_circuit
//             .prove(
//                 num_threads,
//                 num_vars,
//                 gkr_witness,
//                 &out_evals,
//                 &challenges,
//                 &mut prover_transcript,
//             )
//             .expect("Failed to prove phase");

//         // Omit the PCS opening phase.

//         (out_evals, gkr_proof)
//     };

//     {
//         let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");

//         // Omit the commit phase1 and phase2.
//         let challenges = vec![
//             verifier_transcript
//                 .sample_and_append_challenge(b"lookup challenge")
//                 .elements,
//         ];

//         gkr_circuit
//             .verify(
//                 num_vars,
//                 gkr_proof,
//                 &out_evals,
//                 &challenges,
//                 &mut verifier_transcript,
//             )
//             .expect("GKR verify failed");

//         // Omit the PCS opening phase.
//     }
// }
