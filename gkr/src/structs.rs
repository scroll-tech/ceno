use std::{
    array,
    collections::{BTreeMap, HashMap},
};

use goldilocks::SmallField;
use multilinear_extensions::mle::ArcDenseMultilinearExtension;
use serde::{Deserialize, Serialize, Serializer};
use simple_frontend::structs::{CellId, ChallengeConst, ConstantType, LayerId};

pub(crate) type SumcheckProof<F> = sumcheck::structs::IOPProof<F>;

/// A point is a vector of num_var length
pub type Point<F> = Vec<F>;

/// A point and the evaluation of this point.
#[derive(Clone, Debug, PartialEq)]
pub struct PointAndEval<F> {
    pub point: Point<F>,
    pub eval: F,
}

impl<F: SmallField> Default for PointAndEval<F> {
    fn default() -> Self {
        Self {
            point: vec![],
            eval: F::ZERO,
        }
    }
}

impl<F: Clone> PointAndEval<F> {
    /// Construct a new pair of point and eval.
    /// Caller gives up ownership
    pub fn new(point: Point<F>, eval: F) -> Self {
        Self { point, eval }
    }

    /// Construct a new pair of point and eval.
    /// Performs deep copy.
    pub fn new_from_ref(point: &Point<F>, eval: &F) -> Self {
        Self {
            point: (*point).clone(),
            eval: eval.clone(),
        }
    }
}

/// Represent the prover state for each layer in the IOP protocol. To support
/// gates between non-adjacent layers, we leverage the techniques in
/// [Virgo++](https://eprint.iacr.org/2020/1247).
pub struct IOPProverState<F: SmallField> {
    pub(crate) layer_id: LayerId,
    /// Evaluations to the next phase.
    pub(crate) to_next_phase_point_and_evals: Vec<PointAndEval<F>>,
    /// Evaluations of subsets from layers __closer__ to the output.
    /// __closer__ as in the layer that the subset elements lie in has not been processed.
    ///
    /// LayerId is the layer id of the incoming subset point and evaluation.
    pub(crate) subset_point_and_evals: Vec<Vec<(LayerId, PointAndEval<F>)>>,

    /// The point to the next step.
    pub(crate) to_next_step_point: Point<F>,
    /// layer poly for phase 1 which point to current layer
    pub(crate) phase1_layer_polys: Vec<ArcDenseMultilinearExtension<F>>,
    /// layer poly for phase 2 which point to the next layer
    pub(crate) phase2_next_layer_polys: Vec<ArcDenseMultilinearExtension<F>>,

    // Especially for output phase1.
    pub(crate) assert_point: Point<F>,
    // Especially for phase1.
    pub(crate) g1_values: Vec<F>,
    // Especially for phase2.
    pub(crate) tensor_eq_ty_rtry: Vec<F>,
    pub(crate) tensor_eq_s1x1_rs1rx1: Vec<F>,
    pub(crate) tensor_eq_s2x2_rs2rx2: Vec<F>,
}

/// Represent the verifier state for each layer in the IOP protocol.
pub struct IOPVerifierState<F: SmallField> {
    pub(crate) layer_id: LayerId,
    /// Evaluations from the next layer.
    pub(crate) to_next_phase_point_and_evals: Vec<PointAndEval<F>>,
    /// Evaluations of subsets from layers closer to the output. LayerId is the
    /// layer id of the incoming subset point and evaluation.
    pub(crate) subset_point_and_evals: Vec<Vec<(LayerId, PointAndEval<F>)>>,

    pub(crate) challenges: HashMap<ChallengeConst, Vec<F::BaseField>>,
    pub(crate) instance_num_vars: usize,

    pub(crate) to_next_step_point_and_eval: PointAndEval<F>,

    // Especially for output phase1.
    pub(crate) assert_point: Point<F>,
    // Especially for phase1.
    pub(crate) g1_values: Vec<F>,
    // Especially for phase2.
    pub(crate) out_point: Point<F>,
    pub(crate) eq_y_ry: Vec<F>,
    pub(crate) eq_x1_rx1: Vec<F>,
    pub(crate) eq_x2_rx2: Vec<F>,
}

/// Phase 1 is a sumcheck protocol merging the subset evaluations from the
/// layers closer to the circuit output to an evaluation to the output of the
/// current layer.
/// Phase 2 is several sumcheck protocols (depending on the degree of gates),
/// reducing the correctness of the output of the current layer to the input of
/// the current layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IOPProverStepMessage<F: SmallField> {
    /// Sumcheck proofs for each sumcheck protocol.
    pub sumcheck_proof: SumcheckProof<F>,
    pub sumcheck_eval_values: Vec<F>,
}

pub struct IOPProof<F: SmallField> {
    pub sumcheck_proofs: Vec<IOPProverStepMessage<F>>,
}

/// Represent the point at the final step and the evaluations of the subsets of
/// the input layer.
#[derive(Clone, Debug, PartialEq)]
pub struct GKRInputClaims<F: SmallField> {
    pub point_and_evals: Vec<PointAndEval<F>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(crate) enum SumcheckStepType {
    OutputPhase1Step1,
    OutputPhase1Step2,
    Phase1Step1,
    Phase1Step2,
    Phase2Step1,
    Phase2Step2,
    Phase2Step2NoStep3,
    Phase2Step3,
    LinearPhase2Step1,
    InputPhase2Step1,
}

pub(crate) enum Step {
    Step1 = 0,
    Step2,
    Step3,
}

#[derive(Clone, Serialize)]
pub struct Layer<F: SmallField> {
    pub(crate) layer_id: u32,
    pub(crate) sumcheck_steps: Vec<SumcheckStepType>,
    pub(crate) num_vars: usize,

    // Gates. Should be all None if it's the input layer.
    pub(crate) add_consts: Vec<GateCIn<ConstantType<F>>>,
    pub(crate) adds: Vec<Gate1In<ConstantType<F>>>,
    pub(crate) adds_fanin_mapping: [BTreeMap<CellId, Vec<Gate1In<ConstantType<F>>>>; 1], // grouping for 1 fanins
    pub(crate) mul2s: Vec<Gate2In<ConstantType<F>>>,
    pub(crate) mul2s_fanin_mapping: [BTreeMap<CellId, Vec<Gate2In<ConstantType<F>>>>; 2], // grouping for 2 fanins
    pub(crate) mul3s: Vec<Gate3In<ConstantType<F>>>,
    pub(crate) mul3s_fanin_mapping: [BTreeMap<CellId, Vec<Gate3In<ConstantType<F>>>>; 3], // grouping for 3 fanins

    /// The corresponding wires copied from this layer to later layers. It is
    /// (later layer id -> current wire id to be copied). It stores the non-zero
    /// entry of copy_to[layer_id] for each row.
    pub(crate) copy_to: HashMap<LayerId, Vec<CellId>>,
    /// The corresponding wires from previous layers pasted to this layer. It is
    /// (shallower layer id -> pasted to the current id). It stores the non-zero
    /// entry of paste_from[layer_id] for each column. Undefined for the input.
    pub(crate) paste_from: HashMap<LayerId, Vec<CellId>>,
    /// Maximum size of the subsets pasted from the previous layers, rounded up
    /// to the next power of two. This is the logarithm of the rounded size.
    /// Undefined for the input layer.
    pub(crate) max_previous_num_vars: usize,
}

impl<F: SmallField> Default for Layer<F> {
    fn default() -> Self {
        Layer::<F> {
            layer_id: 0,
            sumcheck_steps: vec![],
            add_consts: vec![],
            adds: vec![],
            adds_fanin_mapping: [BTreeMap::new(); 1],
            mul2s: vec![],
            mul2s_fanin_mapping: array::from_fn(|_| BTreeMap::new()),
            mul3s: vec![],
            mul3s_fanin_mapping: array::from_fn(|_| BTreeMap::new()),
            copy_to: HashMap::new(),
            paste_from: HashMap::new(),
            num_vars: 0,
            max_previous_num_vars: 0,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Circuit<F: SmallField> {
    pub layers: Vec<Layer<F>>,

    pub n_witness_in: usize,
    pub n_witness_out: usize,
    /// The endpoints in the input layer copied from each input witness.
    pub paste_from_wits_in: Vec<(CellId, CellId)>,
    /// The endpoints in the input layer copied from counter.
    pub paste_from_counter_in: Vec<(usize, (CellId, CellId))>,
    /// The endpoints in the output layer copied to each output witness.
    pub paste_from_consts_in: Vec<(i64, (CellId, CellId))>,
    /// The wires copied to the output witness
    pub copy_to_wits_out: Vec<Vec<CellId>>,
    pub assert_consts: Vec<GateCIn<ConstantType<F>>>,
    pub max_wit_in_num_vars: Option<usize>,
}

pub type GateCIn<C> = Gate<C, 0>;
pub type Gate1In<C> = Gate<C, 1>;
pub type Gate2In<C> = Gate<C, 2>;
pub type Gate3In<C> = Gate<C, 3>;

#[derive(Clone, Debug, PartialEq)]
/// Macro struct for Gate
pub struct Gate<C, const FAN_IN: usize> {
    pub(crate) idx_in: [CellId; FAN_IN],
    pub(crate) idx_out: CellId,
    pub(crate) scalar: C,
}

impl<C, const FAN_IN: usize> Serialize for Gate<C, FAN_IN> {
    fn serialize<S>(&self, _: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        // TODO!
        todo!()
    }
}

#[derive(Clone, PartialEq, Serialize)]
pub struct CircuitWitness<F: SmallField> {
    /// Three vectors denote 1. layer_id, 2. instance_id, 3. wire_id.
    pub(crate) layers: Vec<LayerWitness<F>>,
    /// 1. wires_in id, 2. instance_id, 3. wire_id.
    pub(crate) witness_in: Vec<LayerWitness<F>>,
    /// 1. wires_in id, 2. instance_id, 3. wire_id.
    pub(crate) witness_out: Vec<LayerWitness<F>>,
    /// Challenges
    pub(crate) challenges: HashMap<ChallengeConst, Vec<F>>,
    /// The number of instances for the same sub-circuit.
    pub(crate) n_instances: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct LayerWitness<F: SmallField> {
    pub instances: Vec<LayerInstanceWit<F>>,
}

pub type LayerInstanceWit<F> = Vec<F>;
