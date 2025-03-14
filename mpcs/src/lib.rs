#![deny(clippy::cargo)]
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType, MultilinearExtension};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use transcript::{BasicTranscript, Transcript};
use util::hash::Digest;
use p3_field::PrimeCharacteristicRing;

pub mod sum_check;
pub mod util;

pub type Commitment<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::Commitment;
pub type CommitmentChunk<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::CommitmentChunk;
pub type CommitmentWithWitness<E, Pcs> =
    <Pcs as PolynomialCommitmentScheme<E>>::CommitmentWithWitness;

pub type Param<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::Param;
pub type ProverParam<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::ProverParam;
pub type VerifierParam<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::VerifierParam;

pub fn pcs_setup<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    poly_size: usize,
) -> Result<Pcs::Param, Error> {
    Pcs::setup(poly_size)
}

pub fn pcs_trim<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    param: Pcs::Param,
    poly_size: usize,
) -> Result<(Pcs::ProverParam, Pcs::VerifierParam), Error> {
    Pcs::trim(param, poly_size)
}

pub fn pcs_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::commit(pp, poly)
}

pub fn pcs_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::commit_and_write(pp, poly, transcript)
}

pub fn pcs_batch_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit(pp, polys)
}

// Express Value as binary in big-endian
fn compute_binary_with_length(length: usize, mut value: usize) -> Vec<bool> {
    assert!(value < 1 << length);
    let mut bin = Vec::new();
    for _ in 0..length {
        bin.insert(0, value % 2 == 1);
        value <<= 1;
    }
    bin
}

// Pack polynomials of different sizes into the same, returns
// 0: A list of packed polys
// 1: The final packed poly, if of different size
// 2: For each component poly of each packed poly, record its position in tree as binary
// 3: Same as 2 but for the final packed poly only
fn pack_poly_prover<E: ExtensionField>(
    polys: &[DenseMultilinearExtension<E>],
) -> (
    Vec<DenseMultilinearExtension<E>>, 
    Option<DenseMultilinearExtension<E>>,
    Vec<Vec<Vec<bool>>>,
    Option<Vec<Vec<bool>>>,
) {
    // Assert that polys are sorted by size in decreasing order
    assert!(polys.len() > 0);
    for i in 0..polys.len() - 1 {
        assert!(polys[i].num_vars >= polys[i + 1].num_vars);
    }
    // Use depth and index to track the position of the last poly
    let mut depth = 0;
    let mut index = 0;
    // Packed polynomials of various sizes into packed polynomials of the same size
    let max_poly_num_vars = polys[0].num_vars;
    let mut packed_polys = Vec::new();
    let mut packed_comps = Vec::new();
    let mut next_packed_poly = polys[0].clone();
    let mut next_packed_comp = vec![compute_binary_with_length(depth, index)];
    for i in 1..polys.len() {
        let p = &polys[i];
        // Update comp and packed_poly
        if next_packed_poly.num_vars == max_poly_num_vars && next_packed_poly.evaluations.len() == 1 << next_packed_poly.num_vars {
            // If full and reached max poly size, initialize a new packed poly
            packed_comps.push(next_packed_comp);
            depth = 0;
            index = 0;
            next_packed_comp = vec![compute_binary_with_length(depth, index)];
            packed_polys.push(next_packed_poly);
            next_packed_poly = p.clone();
        } else {
            let mut next_packed_poly_num_vars = next_packed_poly.num_vars;
            // Find the next empty slot
            if next_packed_poly.evaluations.len() == 1 << next_packed_poly.num_vars {
                // Conceptually next_packed_poly now has one more variable, but has yet to be reflected in its coefficients
                next_packed_poly_num_vars += 1;
                // If full and not reached max poly size, add a new right subtree
                for c in &mut next_packed_comp {
                    c.insert(0, false);
                }
                depth = 1;
                index = 1;
            } else {
                while index % 2 == 1 {
                    assert!(depth > 1); // If depth == 1 and index == 1, then the tree is full and should be handled in the case above
                    index /= 2;
                    depth -= 1;
                }
                index += 1;
            }
            // If next poly is smaller than the slot, keep branching
            while p.num_vars < next_packed_poly_num_vars - depth {
                depth += 1;
                index *= 2;
            }
            next_packed_comp.push(compute_binary_with_length(depth, index));
            next_packed_poly.merge(p.clone());
        }
    }
    // Pad the evaluations of final poly with 0 until a power of 2
    let pad_num_evals = (1 << next_packed_poly.num_vars) - next_packed_poly.evaluations.len();
    if pad_num_evals > 0 {
        match &mut next_packed_poly.evaluations {
            FieldType::Base(e) => {
                e.extend(vec![E::BaseField::ZERO; pad_num_evals])
            }
            FieldType::Ext(e) => {
                e.extend(vec![E::ZERO; pad_num_evals])
            }
            _ => ()
        }
    }
    // Final packed poly
    if next_packed_poly.num_vars == max_poly_num_vars {
        packed_polys.push(next_packed_poly);
        packed_comps.push(next_packed_comp);
        (packed_polys, None, packed_comps, None)
    } else {
        (packed_polys, Some(next_packed_poly), packed_comps, Some(next_packed_comp))
    }
}

// Given only the number of variables of each polynomial, returns num_vars of the packed poly 
// and deduce the structure of the packed binary tree
fn pack_poly_verifier(
    poly_num_vars: &[usize]
) -> (
    usize,
    Option<usize>,
    Vec<Vec<Vec<bool>>>,
    Option<Vec<Vec<bool>>>,
) {
    // Use depth and index to track the position of the last poly
    let mut depth = 0;
    let mut index = 0;
    // Packed polynomials of various sizes into packed polynomials of the same size
    let max_poly_num_vars = poly_num_vars[0];
    let mut packed_comps = Vec::new();
    let mut next_packed_comp = vec![compute_binary_with_length(depth, index)];
    let mut next_pack_num_vars = poly_num_vars[0];
    let mut next_pack_eval_size = 1 << next_pack_num_vars;
    for i in 1..poly_num_vars.len() {
        let next_num_vars = poly_num_vars[i];
        // Update comp and packed_poly
        if next_pack_num_vars == max_poly_num_vars && next_pack_eval_size == 1 << next_pack_num_vars {
            // If full and reached max poly size, initialize a new packed poly
            packed_comps.push(next_packed_comp);
            depth = 0;
            index = 0;
            next_packed_comp = vec![compute_binary_with_length(depth, index)];
            next_pack_num_vars = next_num_vars;
            next_pack_eval_size = 1 << next_num_vars;
        } else {
            // Find the next empty slot
            if next_pack_eval_size == 1 << next_pack_num_vars {
                // If full and not reached max poly size, add a new right subtree
                next_pack_num_vars += 1;
                for c in &mut next_packed_comp {
                    c.insert(0, false);
                }
                depth = 1;
                index = 1;
            } else {
                while index % 2 == 1 {
                    assert!(depth > 1); // If depth == 1 and index == 1, then the tree is full and should be handled in the case above
                    index /= 2;
                    depth -= 1;
                }
                index += 1;
            }
            // If next poly is smaller than the slot, keep branching
            while next_num_vars < next_pack_num_vars - depth {
                depth += 1;
                index *= 2;
            }
            next_packed_comp.push(compute_binary_with_length(depth, index));
            next_pack_eval_size += 1 << next_num_vars;
        }
    }
    // Final packed poly
    if next_pack_num_vars == max_poly_num_vars {
        packed_comps.push(next_packed_comp);
        (max_poly_num_vars, None, packed_comps, None)
    } else {
        (max_poly_num_vars, Some(next_pack_num_vars), packed_comps, Some(next_packed_comp))
    }
}

// Compute evaluation on packed poly from individual evals and the pack binary tree
fn compute_packed_eval<E: ExtensionField>(
    packed_point: &[E],
    final_point: &[E],
    evals: &[E],
    packed_comps: &[Vec<Vec<bool>>],
    final_comp: &Option<Vec<Vec<bool>>>,
) -> (Vec<E>, Option<E>) {
    // Use comps to compute evals for packed polys from regular evals
    let mut packed_evals = Vec::new();
    let mut next_orig_poly = 0;
    for next_packed_comp in packed_comps {
        let mut packed_eval = E::ZERO;
        for next_index in next_packed_comp {
            let mut next_eval = evals[next_orig_poly];
            for (j, b) in next_index.iter().enumerate() {
                if *b { next_eval *= packed_point[j] }
            }
            packed_eval *= next_eval;
            next_orig_poly += 1;
        }
        packed_evals.push(packed_eval);
    }
    if let Some(final_comp) = final_comp {
        let mut final_eval = E::ZERO;
        for next_index in final_comp {
            let mut next_eval = evals[next_orig_poly];
            for (j, b) in next_index.iter().enumerate() {
                if *b { next_eval *= final_point[j] }
            }
            final_eval *= next_eval;
            next_orig_poly += 1;
        }
        (packed_evals, Some(final_eval))
    } else {
        (packed_evals, None)
    }
}

pub fn pcs_batch_commit_diff_size<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
) -> Result<(Pcs::CommitmentWithWitness, Option<Pcs::CommitmentWithWitness>), Error> {
    let (packed_polys, final_poly, _, _) = pack_poly_prover(polys);
    // Final packed poly
    if let Some(final_poly) = final_poly {
        Ok((Pcs::batch_commit(pp, &packed_polys)?, Some(Pcs::batch_commit(pp, &[final_poly])?)))
    } else {
        Ok((Pcs::batch_commit(pp, &packed_polys)?, None))
    }
} 

pub fn pcs_batch_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit_and_write(pp, polys, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithWitness,
    point: &[E],
    eval: &E,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    comms: &[Pcs::CommitmentWithWitness],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::batch_open(pp, polys, comms, points, evals, transcript)
}

pub fn pcs_batch_open_diff_size<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    packed_comm: &Pcs::CommitmentWithWitness,
    final_comm: &Option<Pcs::CommitmentWithWitness>,
    points: &[Vec<E>],
    evals: &[E],
    transcript: &mut impl Transcript<E>,
) -> Result<(Pcs::Proof, Option<Pcs::Proof>), Error> {
    // TODO: Sort the polys by decreasing size
    // TODO: The prover should be able to avoid packing the polys again
    let (packed_polys, final_poly, packed_comps, final_comp) = pack_poly_prover(polys);
    let packed_polys: Vec<ArcMultilinearExtension<E>> = packed_polys.into_iter().map(|p| ArcMultilinearExtension::from(p)).collect();
    // TODO: Add unifying sumcheck if the points do not match
    // For now, assume that all polys are evaluated on the same points
    let packed_point = points[0].clone();
    let final_point = if let Some(final_poly) = &final_poly { packed_point[packed_point.len() - final_poly.num_vars..packed_point.len()].to_vec() } else { Vec::new() };
    // Use comps to compute evals for packed polys from regular evals
    let (packed_evals, final_eval) = compute_packed_eval(&packed_point, &final_point, evals, &packed_comps, &final_comp);

    let pack_proof = Pcs::simple_batch_open(pp, &packed_polys, packed_comm, &packed_point, &packed_evals, transcript)?;
    let final_proof = match (&final_poly, &final_comm, &final_eval) {
        (Some(final_poly), Some(final_comm), Some(final_eval)) => Some(Pcs::open(pp, final_poly, final_comm, &final_point, final_eval, transcript)?),
        _ => None,
    };
    Ok((pack_proof, final_proof))
}

pub fn pcs_verify<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comm: &Pcs::Commitment,
    point: &[E],
    eval: &E,
    proof: &Pcs::Proof,
    transcript: &mut impl Transcript<E>,
) -> Result<(), Error> {
    Pcs::verify(vp, comm, point, eval, proof, transcript)
}

pub fn pcs_batch_verify<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comms: &[Pcs::Commitment],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    proof: &Pcs::Proof,
    transcript: &mut impl Transcript<E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    Pcs::batch_verify(vp, comms, points, evals, proof, transcript)
}

pub fn pcs_batch_verify_diff_size<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    poly_num_vars: &[usize], // Size of the original polynomials, for reproducing results
    packed_comm: &Pcs::Commitment,
    final_comm: &Option<Pcs::Commitment>,
    points: &[Vec<E>],
    evals: &[E],
    packed_proof: &Pcs::Proof,
    final_proof: &Option<Pcs::Proof>,
    transcript: &mut impl Transcript<E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    // Replicate packing
    let (_, final_poly_num_vars, packed_comps, final_comp) = pack_poly_verifier(poly_num_vars);
    // TODO: Add unifying sumcheck if the points do not match
    // For now, assume that all polys are evaluated on the same points
    let packed_point = points[0].clone();
    let final_point = if let Some(final_poly_num_vars) = &final_poly_num_vars { packed_point[packed_point.len() - final_poly_num_vars..packed_point.len()].to_vec() } else { Vec::new() };
    // Use comps to compute evals for packed polys from regular evals
    let (packed_evals, final_eval) = compute_packed_eval(&packed_point, &final_point, evals, &packed_comps, &final_comp);
    Pcs::simple_batch_verify(vp, packed_comm, &packed_point, &packed_evals, packed_proof, transcript)?;
    match (&final_comm, &final_eval, &final_proof) {
        (Some(final_comm), Some(final_eval), Some(final_proof)) => Pcs::verify(vp, final_comm, &final_point, &final_eval, final_proof, transcript),
        _ => Ok(()),
    }
}


pub trait PolynomialCommitmentScheme<E: ExtensionField>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type CommitmentWithWitness: Clone + Debug;
    type Commitment: Clone + Debug + Default + Serialize + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;
    type Proof: Clone + Debug + Serialize + DeserializeOwned;

    fn setup(poly_size: usize) -> Result<Self::Param, Error>;

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::commit(pp, poly)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment;

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::batch_commit(pp, polys)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithWitness],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;
}

pub trait NoninteractivePCS<E: ExtensionField>:
    PolynomialCommitmentScheme<E, CommitmentChunk = Digest<E::BaseField>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn ni_open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
    ) -> Result<Self::Proof, Error> {
        let mut transcript = BasicTranscript::<E>::new(b"BaseFold");
        Self::open(pp, poly, comm, point, eval, &mut transcript)
    }

    fn ni_batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithWitness],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
    ) -> Result<Self::Proof, Error> {
        let mut transcript = BasicTranscript::new(b"BaseFold");
        Self::batch_open(pp, polys, comms, points, evals, &mut transcript)
    }

    fn ni_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let mut transcript = BasicTranscript::new(b"BaseFold");
        Self::verify(vp, comm, point, eval, proof, &mut transcript)
    }

    fn ni_batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let mut transcript = BasicTranscript::new(b"BaseFold");
        Self::batch_verify(vp, comms, points, evals, proof, &mut transcript)
    }
}

#[derive(Clone, Debug)]
pub struct Evaluation<F> {
    poly: usize,
    point: usize,
    value: F,
}

impl<F> Evaluation<F> {
    pub fn new(poly: usize, point: usize, value: F) -> Self {
        Self { poly, point, value }
    }

    pub fn poly(&self) -> usize {
        self.poly
    }

    pub fn point(&self) -> usize {
        self.point
    }

    pub fn value(&self) -> &F {
        &self.value
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    InvalidSumcheck(String),
    InvalidPcsParam(String),
    InvalidPcsOpen(String),
    InvalidSnark(String),
    Serialization(String),
    Transcript(String),
    ExtensionFieldElementNotFit,
    PolynomialTooLarge(usize),
    PolynomialSizesNotEqual,
    MerkleRootMismatch,
    WhirError(whir::Error),
}

mod basefold;
pub use basefold::{
    Basecode, BasecodeDefaultSpec, Basefold, BasefoldBasecodeParams, BasefoldCommitment,
    BasefoldCommitmentWithWitness, BasefoldDefault, BasefoldParams, BasefoldRSParams, BasefoldSpec,
    EncodingScheme, RSCode, RSCodeDefaultSpec, coset_fft, fft, fft_root_table, one_level_eval_hc,
    one_level_interp_hc,
};
mod whir;
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;
pub use whir::{Whir, WhirDefault, WhirDefaultSpec};

fn validate_input<E: ExtensionField>(
    function: &str,
    param_num_vars: usize,
    polys: &[DenseMultilinearExtension<E>],
    points: &[Vec<E>],
) -> Result<(), Error> {
    let polys = polys.iter().collect_vec();
    let points = points.iter().collect_vec();
    for poly in polys.iter() {
        if param_num_vars < poly.num_vars {
            return Err(err_too_many_variates(
                function,
                param_num_vars,
                poly.num_vars,
            ));
        }
    }
    for point in points.iter() {
        if param_num_vars < point.len() {
            return Err(err_too_many_variates(function, param_num_vars, point.len()));
        }
    }
    Ok(())
}

fn err_too_many_variates(function: &str, upto: usize, got: usize) -> Error {
    Error::InvalidPcsParam(if function == "trim" {
        format!(
            "Too many variates to {function} (param supports variates up to {upto} but got {got})"
        )
    } else {
        format!(
            "Too many variates of poly to {function} (param supports variates up to {upto} but got {got})"
        )
    })
}

// TODO: Need to use some functions here in the integration benchmarks. But
// unfortunately integration benchmarks do not compile the #[cfg(test)]
// code. So remove the gate for the entire module, only gate the test
// functions.
// This is not the best way: the test utility functions should not be
// compiled in the release build. Need a better solution.
#[doc(hidden)]
pub mod test_util {
    #[cfg(test)]
    use crate::Evaluation;
    use crate::PolynomialCommitmentScheme;
    use ff_ext::ExtensionField;
    use itertools::Itertools;
    #[cfg(test)]
    use itertools::chain;
    use multilinear_extensions::mle::DenseMultilinearExtension;
    #[cfg(test)]
    use multilinear_extensions::{
        mle::MultilinearExtension, virtual_poly::ArcMultilinearExtension,
    };
    use rand::rngs::OsRng;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    #[cfg(test)]
    use transcript::BasicTranscript;
    use transcript::Transcript;

    pub fn setup_pcs<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        num_vars: usize,
    ) -> (Pcs::ProverParam, Pcs::VerifierParam) {
        let poly_size = 1 << num_vars;
        let param = Pcs::setup(poly_size).unwrap();
        Pcs::trim(param, poly_size).unwrap()
    }

    pub fn gen_rand_poly_base<E: ExtensionField>(num_vars: usize) -> DenseMultilinearExtension<E> {
        DenseMultilinearExtension::random(num_vars, &mut OsRng)
    }

    pub fn gen_rand_poly_ext<E: ExtensionField>(num_vars: usize) -> DenseMultilinearExtension<E> {
        DenseMultilinearExtension::from_evaluations_ext_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| E::random(&mut OsRng))
                .collect_vec(),
        )
    }

    pub fn gen_rand_polys<E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize + Sync,
        batch_size: usize,
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
    ) -> Vec<DenseMultilinearExtension<E>> {
        (0..batch_size)
            .into_par_iter()
            .map(|i| gen_rand_poly(num_vars(i)))
            .collect::<Vec<_>>()
    }

    pub fn get_point_from_challenge<E: ExtensionField>(
        num_vars: usize,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<E> {
        transcript.sample_and_append_vec(b"Point", num_vars)
    }
    pub fn get_points_from_challenge<E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize,
        num_points: usize,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<Vec<E>> {
        (0..num_points)
            .map(|i| get_point_from_challenge(num_vars(i), transcript))
            .collect()
    }

    pub fn commit_polys_individually<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        pp: &Pcs::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Vec<Pcs::CommitmentWithWitness> {
        polys
            .iter()
            .map(|poly| Pcs::commit_and_write(pp, poly, transcript).unwrap())
            .collect_vec()
    }

    #[cfg(test)]
    pub fn run_commit_open_verify<E: ExtensionField, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Commit and open
            let (comm, eval, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let poly = gen_rand_poly(num_vars);
                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                let eval = poly.evaluate(point.as_slice());
                transcript.append_field_element_ext(&eval);

                (
                    Pcs::get_pure_commitment(&comm),
                    eval,
                    Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap(),
                    transcript.read_challenge(),
                )
            };
            // Verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                transcript.append_field_element_ext(&eval);

                Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);

                println!(
                    "Proof size for single poly: {} bytes",
                    bincode::serialized_size(&proof).unwrap()
                );
            }
        }
    }

    #[cfg(test)]
    pub fn run_batch_commit_open_verify<E, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let batch_size = 2;
            let num_points = batch_size >> 1;
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let (comms, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys = gen_rand_polys(|i| num_vars - (i >> 1), batch_size, gen_rand_poly);

                let comms =
                    commit_polys_individually::<E, Pcs>(&pp, polys.as_slice(), &mut transcript);

                let points =
                    get_points_from_challenge(|i| num_vars - i, num_points, &mut transcript);

                let evals = evals
                    .iter()
                    .copied()
                    .map(|(poly, point)| Evaluation {
                        poly,
                        point,
                        value: polys[poly].evaluate(&points[point]),
                    })
                    .collect_vec();
                let values: Vec<E> = evals
                    .iter()
                    .map(Evaluation::value)
                    .copied()
                    .collect::<Vec<E>>();
                transcript.append_field_element_exts(values.as_slice());

                let proof =
                    Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript).unwrap();
                (comms, evals, proof, transcript.read_challenge())
            };
            // Batch verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let comms = comms
                    .iter()
                    .map(|comm| {
                        let comm = Pcs::get_pure_commitment(comm);
                        Pcs::write_commitment(&comm, &mut transcript).unwrap();
                        comm
                    })
                    .collect_vec();

                let points =
                    get_points_from_challenge(|i| num_vars - i, num_points, &mut transcript);

                let values: Vec<E> = evals
                    .iter()
                    .map(Evaluation::value)
                    .copied()
                    .collect::<Vec<E>>();
                transcript.append_field_element_exts(values.as_slice());

                Pcs::batch_verify(&vp, &comms, &points, &evals, &proof, &mut transcript).unwrap();
                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);

                println!(
                    "Proof size for batch: {} bytes",
                    bincode::serialized_size(&proof).unwrap()
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn run_simple_batch_commit_open_verify<E, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comm, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys = gen_rand_polys(|_| num_vars, batch_size, gen_rand_poly);
                let comm =
                    Pcs::batch_commit_and_write(&pp, polys.as_slice(), &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                let evals = polys.iter().map(|poly| poly.evaluate(&point)).collect_vec();
                transcript.append_field_element_exts(&evals);

                let polys = polys
                    .iter()
                    .map(|poly| ArcMultilinearExtension::from(poly.clone()))
                    .collect_vec();
                let proof =
                    Pcs::simple_batch_open(&pp, &polys, &comm, &point, &evals, &mut transcript)
                        .unwrap();
                (
                    Pcs::get_pure_commitment(&comm),
                    evals,
                    proof,
                    transcript.read_challenge(),
                )
            };
            // Batch verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();

                let point = get_point_from_challenge(num_vars, &mut transcript);
                transcript.append_field_element_exts(&evals);

                Pcs::simple_batch_verify(&vp, &comm, &point, &evals, &proof, &mut transcript)
                    .unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);

                println!(
                    "Proof size for simple batch: {} bytes",
                    bincode::serialized_size(&proof).unwrap()
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn run_diff_size_batch_commit_open_verify<E, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        max_num_vars: usize,
        max_vars_gap: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        use crate::{pcs_batch_commit_diff_size, pcs_batch_open_diff_size, pcs_batch_verify_diff_size};

        for vars_gap in 1..=max_vars_gap {
            assert!(max_num_vars > vars_gap * batch_size);
            let (pp, vp) = setup_pcs::<E, Pcs>(max_num_vars);

            let (poly_num_vars, packed_comm, final_comm, evals, packed_proof, final_proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys: Vec<DenseMultilinearExtension<E>> = (0..batch_size).map(|i| gen_rand_polys(|_| max_num_vars - i * vars_gap, 1, gen_rand_poly)).flatten().collect();
                let (packed_comm, final_comm) = pcs_batch_commit_diff_size::<E, Pcs>(&pp, &polys).unwrap();
                let point = get_point_from_challenge(max_num_vars, &mut transcript);
                let points: Vec<Vec<E>> = polys.iter().map(|p| point[max_num_vars - p.num_vars..].to_vec()).collect();
                let evals = polys.iter().zip(&points).map(|(poly, point)| poly.evaluate(point)).collect_vec();
                transcript.append_field_element_exts(&evals);

                let (packed_proof, final_proof) = pcs_batch_open_diff_size::<E, Pcs>(&pp, &polys, &packed_comm, &final_comm, &points, &evals, &mut transcript).unwrap();
                (
                    polys.iter().map(|p| p.num_vars).collect::<Vec<usize>>(),
                    Pcs::get_pure_commitment(&packed_comm),
                    if let Some(final_comm) = final_comm { Some(Pcs::get_pure_commitment(&final_comm)) } else { None },
                    evals,
                    packed_proof, 
                    final_proof,
                    transcript.read_challenge(),
                )
            };
            // Batch verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                Pcs::write_commitment(&packed_comm, &mut transcript).unwrap();
                if let Some(final_comm) = &final_comm {
                    Pcs::write_commitment(final_comm, &mut transcript).unwrap();
                }

                let point = get_point_from_challenge(max_num_vars, &mut transcript);
                let points: Vec<Vec<E>> = poly_num_vars.iter().map(|n| point[max_num_vars - n..].to_vec()).collect();
                transcript.append_field_element_exts(&evals);

                pcs_batch_verify_diff_size::<E, Pcs>(&vp, &poly_num_vars, &packed_comm, &final_comm, &points, &evals, &packed_proof, &final_proof, &mut transcript).unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);

                println!(
                    "Proof size for simple batch: {} bytes",
                    bincode::serialized_size(&packed_proof).unwrap() + bincode::serialized_size(&final_proof).unwrap()
                );
            }
        }
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_packing() {
        use crate::pack_poly_verifier;

        let poly_num_vars = [27, 26, 25, 24, 23];
        let (pack_size, final_size, pack_comp, final_comp) = pack_poly_verifier(&poly_num_vars);
        println!("PACK_SIZE: {:?}", pack_size);
        println!("FINAL_SIZE: {:?}", final_size);
        println!("PACK_COMP: {:?}", pack_comp);
        println!("FINAL_COMP: {:?}", final_comp);
    }

}
