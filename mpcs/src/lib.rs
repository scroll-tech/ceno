#![deny(clippy::cargo)]
use ff_ext::ExtensionField;
use itertools::{interleave, Either, Itertools};
use multilinear_extensions::{mle::{DenseMultilinearExtension, FieldType, MultilinearExtension}, virtual_poly::{build_eq_x_r, eq_eval, VPAuxInfo}};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use transcript::{BasicTranscript, Transcript};
use util::hash::Digest;
use p3_field::PrimeCharacteristicRing;
use multilinear_extensions::virtual_poly::VirtualPolynomial;
use sumcheck::structs::{IOPProof, IOPProverState, IOPVerifierState};
use witness::RowMajorMatrix;

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
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit(pp, rmm)
}

pub fn pcs_batch_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit_and_write(pp, rmm, transcript)
}

// Express Value as binary in big-endian
fn compute_binary_with_length(length: usize, mut value: usize) -> Vec<bool> {
    assert!(value < (1 << length));
    let mut bin = Vec::new();
    for _ in 0..length {
        bin.insert(0, value % 2 == 1);
        value >>= 1;
    }
    bin
}

/* Old Interleaving Approach for bookkeeping

// Given the sizes of a list of polys sorted in decreasing order,
// Compute which list each entry of their interleaved form belong to
// e.g.: [4, 2, 1, 1] => [0, 1, 0, 2, 0, 1, 0, 3]
// If the sizes do not sum up to a power of 2, use sizes.len() for paddings
// This is performed recursively: at each step, only interleave the polys between head..tail
fn interleave_helper(interleave_size: usize, sizes: &[usize], head: usize, tail: usize) -> Vec<usize> {
    if head == tail {
        // Base case 1: everything is pad
        let pad_index = sizes.len();
        vec![pad_index; interleave_size]
    } else if sizes[head] == interleave_size {
        // Base case 2: everything is of the same poly
        vec![head; interleave_size]
    } else {
        // Mid is the first poly that cannot fit within interleave_size / 2
        let mid_size = interleave_size / 2;
        let mut mid = head;
        let mut sum = 0;
        while mid < tail && sum < mid_size  {
            sum += sizes[mid];
            mid += 1;
        }
        let left = interleave_helper(interleave_size / 2, sizes, head, mid);
        let right = interleave_helper(interleave_size / 2, sizes, mid, tail);
        interleave(left, right).collect()
    }
}
// Denote: N - size of the interleaved poly; M - num of polys; L - size of the smallest poly
// Let f(X) = min(X log X, M * X)
// Naively, interleaving costs O(f(N))
// Instead, we first create a pattern, i.e. the interleave procedure up to the first entry of the last polynomial, which can be computed in O(f(N/L))
// This allows the total interleave to be performe din O(f(N/L) + N) time
fn interleave_pattern(sizes: Vec<usize>) -> Vec<usize> {
    // To compute the pattern, divide every entry by the size of the smallest poly
    let factor = sizes[sizes.len() - 1];
    let sizes: Vec<usize> = sizes.into_iter().map(|s| s / factor).collect();
    let interleave_size = sizes.iter().sum::<usize>().next_power_of_two();
    interleave_helper(interleave_size, &sizes, 0, sizes.len())
}
// Interleave the polys without reason about length
fn interleave_polys<E: ExtensionField>(
    polys: Vec<&DenseMultilinearExtension<E>>
) -> DenseMultilinearExtension<E> {
    assert!(polys.len() > 0);
    let sizes: Vec<usize> = polys.iter().map(|p| p.evaluations.len()).collect();
    let interleaved_size = sizes.iter().sum::<usize>().next_power_of_two();
    let interleaved_num_vars = interleaved_size.ilog2() as usize;
    // First compute the pattern
    let pad_index = sizes.len();
    let pattern = interleave_pattern(sizes);
    // Is there a better way to deal with field types?
    let mut interleaved_evaluations = match polys[0].evaluations {
        FieldType::Base(_) => FieldType::Base(Vec::new()),
        FieldType::Ext(_) => FieldType::Ext(Vec::new()),
        _ => unreachable!()
    };
    // One pointer for each poly. If the pattern includes that poly, push the corresponding entry to the interleaved poly.
    let mut poly_pointer = vec![0; polys.len()];
    let mut pattern_pointer = 0;
    while interleaved_evaluations.len() < interleaved_size {
        let next_poly = pattern[pattern_pointer];
        if next_poly == pad_index {
            // Push a pad entry
            match &mut interleaved_evaluations {
                FieldType::Base(i) => { i.push(E::BaseField::ZERO) }
                FieldType::Ext(i) => { i.push(E::ZERO) }
                _ => unreachable!()
            }
        } else {
            // Push a poly entry
            match (&mut interleaved_evaluations, &polys[next_poly].evaluations) {
                (FieldType::Base(i), FieldType::Base(e)) => {
                    i.push(e[poly_pointer[next_poly]])
                }
                (FieldType::Ext(i), FieldType::Ext(e)) => { 
                    i.push(e[poly_pointer[next_poly]])
                }
                (a, b) => panic!(
                    "do not support merge different field type DME a: {:?} b: {:?}",
                    a, b
                ),
            }
            poly_pointer[next_poly] += 1;
        }
        pattern_pointer = (pattern_pointer + 1) % pattern.len();
    }
    DenseMultilinearExtension { num_vars: interleaved_num_vars, evaluations: interleaved_evaluations }
}
*/

// Interleave the polys give their position on the binary tree
// Assume the polys are sorted by decreasing size
// Denote: N - size of the interleaved poly; M - num of polys
// This function performs interleave in O(M) + O(N) time and is *potentially* parallelizable (maybe? idk)
fn interleave_polys<E: ExtensionField>(
    polys: Vec<&DenseMultilinearExtension<E>>,
    comps: &Vec<Vec<bool>>,
) -> DenseMultilinearExtension<E> {
    assert!(polys.len() > 0);
    let sizes: Vec<usize> = polys.iter().map(|p| p.evaluations.len()).collect();
    let interleaved_size = sizes.iter().sum::<usize>().next_power_of_two();
    let interleaved_num_vars = interleaved_size.ilog2() as usize;
    // Initialize the interleaved poly
    // Is there a better way to deal with field types?
    let mut interleaved_evaluations = match polys[0].evaluations {
        FieldType::Base(_) => FieldType::Base(vec![E::BaseField::ZERO; interleaved_size]),
        FieldType::Ext(_) => FieldType::Ext(vec![E::ZERO; interleaved_size]),
        _ => unreachable!()
    };
    // For every poly, determine its:
    // * Start: where's its first entry in the interleaved poly?
    // * Gap: how many entires are between its consecutive entries in the interleaved poly?
    // Then fill in the corresponding entries in the interleaved poly
    for (poly, comp) in polys.iter().zip(comps) {
        // Start is the decimal representation of the inverse of comp
        let mut start = 0;
        let mut pow_2 = 1;
        for b in comp {
            start += if *b { pow_2 } else { 0 };
            pow_2 *= 2;
        }
        // Gap is 2 ** (interleaved_num_vars - poly_num_vars)
        let gap = 1 << (interleaved_num_vars - poly.num_vars);
        // Fill in the blank
        match (&mut interleaved_evaluations, &poly.evaluations) {
            (FieldType::Base(ie), FieldType::Base(pe)) => {
                for (i, e) in pe.iter().enumerate() {
                    ie[start + gap * i] = *e;
                }
            }
            (FieldType::Ext(ie), FieldType::Ext(pe)) => { 
                for (i, e) in pe.iter().enumerate() {
                    ie[start + gap * i] = *e;
                }
            }
            (a, b) => panic!(
                "do not support merge different field type DME a: {:?} b: {:?}",
                a, b
            ),
        }
    }
    DenseMultilinearExtension { num_vars: interleaved_num_vars, evaluations: interleaved_evaluations }
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
    let mut next_packed_poly = vec![&polys[0]];
    let mut next_packed_comp = vec![compute_binary_with_length(depth, index)];
    let mut next_pack_num_vars = polys[0].num_vars;
    let mut next_pack_eval_size = 1 << next_pack_num_vars;
    for i in 1..polys.len() {
        let p = &polys[i];
        let next_num_vars = p.num_vars;
        // Update comp and packed_poly
        if next_pack_num_vars == max_poly_num_vars && next_pack_eval_size == 1 << next_pack_num_vars {
            // If full and reached max poly size, initialize a new packed poly
            packed_comps.push(next_packed_comp);
            depth = 0;
            index = 0;
            next_packed_comp = vec![compute_binary_with_length(depth, index)];
            packed_polys.push(next_packed_poly);
            next_packed_poly = vec![&p];
            next_pack_num_vars = next_num_vars;
            next_pack_eval_size = 1 << next_num_vars;
        } else {
            // Find the next empty slot
            if next_pack_eval_size == 1 << next_pack_num_vars {
                // Conceptually next_packed_poly now has one more variable, but has yet to be reflected in its coefficients
                next_pack_num_vars += 1;
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
            while p.num_vars < next_pack_num_vars - depth {
                depth += 1;
                index *= 2;
            }
            next_packed_comp.push(compute_binary_with_length(depth, index));
            next_packed_poly.push(&p);
            next_pack_eval_size += 1 << next_num_vars;
        }
    }
    // Interleave every poly
    let mut packed_polys: Vec<_> = packed_polys.into_iter().zip(&packed_comps).map(|(ps, pc)| 
        interleave_polys(ps, pc)
    ).collect();
    let next_packed_poly = interleave_polys(next_packed_poly, &next_packed_comp);
    
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
            // Note: the points are stored in reverse
            for (j, b) in next_index.iter().enumerate() {
                let next_point = packed_point[j];
                if *b { next_eval *= next_point } else { next_eval *= E::ONE - next_point }
            }
            packed_eval += next_eval;
            next_orig_poly += 1;
        }
        packed_evals.push(packed_eval);
    }
    if let Some(final_comp) = final_comp {
        let mut final_eval = E::ZERO;
        for next_index in final_comp {
            let mut next_eval = evals[next_orig_poly];
            // Note: the points are stored in reverse
            for (j, b) in next_index.iter().enumerate() {
                let next_point = final_point[j];
                if *b { next_eval *= next_point } else { next_eval *= E::ONE - next_point }
            }
            final_eval += next_eval;
            next_orig_poly += 1;
        }
        (packed_evals, Some(final_eval))
    } else {
        (packed_evals, None)
    }
}

// Batch the polynomials into pack_poly and final_poly
// Returns the commitment to both (if exist)
pub fn pcs_batch_commit_diff_size<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pack_pp: &Pcs::ProverParam,
    final_pp: &Option<Pcs::ProverParam>,
    polys: &[DenseMultilinearExtension<E>],
) -> Result<(Pcs::CommitmentWithWitness, Option<Pcs::CommitmentWithWitness>), Error> {
    let (packed_polys, final_poly, _, _) = pack_poly_prover(polys);
    // Final packed poly
    match (final_pp, final_poly) {
        (Some(final_pp), Some(final_poly)) => Ok((Pcs::batch_commit_polys(pack_pp, &packed_polys)?, Some(Pcs::commit(final_pp, &final_poly)?))),
        (None, None) => Ok((Pcs::batch_commit_polys(pack_pp, &packed_polys)?, None)),
        _ => unreachable!()
    }
} 

pub fn pcs_batch_commit_diff_size_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    transcript: &mut impl Transcript<E>,
) -> Result<(Pcs::CommitmentWithWitness, Option<Pcs::CommitmentWithWitness>), Error> {
    let (packed_polys, final_poly, _, _) = pack_poly_prover(polys);
    // Final packed poly
    if let Some(final_poly) = final_poly {
        Ok((
            Pcs::batch_commit_and_write_polys(pp, &packed_polys, transcript)?, 
            Some(Pcs::commit_and_write(pp, &final_poly, transcript)?)
        ))
    } else {
        Ok((Pcs::batch_commit_and_write_polys(pp, &packed_polys, transcript)?, None))
    }
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
    _poly_evals: &[E],
    transcript: &mut impl Transcript<E>,
) -> Result<(IOPProof<E>, Vec<E>, Pcs::Proof, Option<Pcs::Proof>), Error> {
    assert_eq!(polys.len(), points.len());
    // Assert that the poly are sorted in decreasing size
    for i in 0..polys.len() - 1 {
        assert!(polys[i].num_vars >= polys[i + 1].num_vars);
    }
    // UNIFY SUMCHECK
    // Sample random coefficients for each poly
    let unify_coeffs = transcript.sample_vec(polys.len());
    // Convert each point into EQ
    let eq_points = points.iter().map(|p| build_eq_x_r(p)).collect::<Vec<_>>();
    // Perform sumcheck
    let arc_polys: Vec<ArcMultilinearExtension<E>> = polys.into_iter().map(|p| ArcMultilinearExtension::from(p.clone())).collect();
    let mut sumcheck_poly = VirtualPolynomial::<E>::new(polys[0].num_vars());
    for ((eq, poly), coeff) in eq_points.into_iter().zip(arc_polys).zip(unify_coeffs) {
        sumcheck_poly.add_mle_list(vec![eq, poly], coeff);
    }
    let (unify_proof, unify_prover_state) = IOPProverState::prove_batch_polys(1, vec![sumcheck_poly], transcript);
    // Obtain new point and evals
    let packed_point = unify_proof.point.clone();
    // sumcheck_poly is consisted of [eq, poly, eq, poly, ...], we only need the evaluations to the `poly`s here
    let sumcheck_evals = unify_prover_state.get_mle_final_evaluations();
    let (_, unify_evals): (Vec<_>, Vec<_>) = sumcheck_evals.into_iter().enumerate().partition_map(|(i, e)| {
        if i % 2 == 0 {
            Either::Left(e)
        } else {
            Either::Right(e)
        }
    });

    // GEN & EVAL PACK POLYS
    // TODO: The prover should be able to avoid packing the polys again
    let (packed_polys, final_poly, packed_comps, final_comp) = pack_poly_prover(polys);
    let packed_polys: Vec<ArcMultilinearExtension<E>> = packed_polys.into_iter().map(|p| ArcMultilinearExtension::from(p)).collect();
    // Note: the points are stored in reverse
    let final_point = if let Some(final_poly) = &final_poly { packed_point[packed_point.len() - final_poly.num_vars..].to_vec() } else { Vec::new() };
    // Use comps to compute evals for packed polys from unify evals
    let (packed_evals, final_eval) = compute_packed_eval(&packed_point, &final_point, &unify_evals, &packed_comps, &final_comp);

    let pack_proof = Pcs::simple_batch_open(pp, &packed_polys, packed_comm, &packed_point, &packed_evals, transcript)?;
    let final_proof = match (&final_poly, &final_comm, &final_eval) {
        (Some(final_poly), Some(final_comm), Some(final_eval)) => {
            Some(Pcs::open(pp, final_poly, final_comm, &final_point, final_eval, transcript)?)
        }
        (None, None, None) => None,
        _ => unreachable!(),
    };
    Ok((unify_proof, unify_evals, pack_proof, final_proof))
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
    poly_evals: &[E], // Evaluation of polys on original points
    unify_proof: &IOPProof<E>,
    unify_evals: &[E], // Evaluation of polys on unified points 
    packed_proof: &Pcs::Proof,
    final_proof: &Option<Pcs::Proof>,
    transcript: &mut impl Transcript<E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    assert_eq!(poly_num_vars.len(), points.len());
    assert_eq!(poly_evals.len(), points.len());
    // Assert that the poly are sorted in decreasing size
    for i in 0..poly_num_vars.len() - 1 {
        assert!(poly_num_vars[i] >= poly_num_vars[i + 1]);
    }
    // UNIFY SUMCHECK
    let max_num_vars = poly_num_vars[0];
    // Sample random coefficients for each poly
    let unify_coeffs = transcript.sample_vec(poly_num_vars.len());
    // Claim is obtained as eval * coeff * (1 << (max_num_vars - num_vars)) due to scaling factor: see prove_round_and_update_state in sumcheck/src/prover.rs
    let claim = poly_evals.iter().zip(&unify_coeffs).zip(poly_num_vars).map(|((e, c), n)| *e * *c * E::from_u64(1 << max_num_vars - n)).sum();
    let sumcheck_subclaim = IOPVerifierState::verify(claim, unify_proof, &VPAuxInfo { max_degree: 2, max_num_variables: max_num_vars, phantom: Default::default() }, transcript);
    // Obtain new point and evals
    let packed_point = sumcheck_subclaim.point.iter().map(|c| c.elements).collect::<Vec<_>>();
    let claimed_eval = sumcheck_subclaim.expected_evaluation;
    // Compute the evaluation of every EQ
    let eq_evals = points.iter().map(|p| eq_eval(p, &packed_point[packed_point.len() - p.len()..]));
    let expected_eval = eq_evals.zip(unify_evals).zip(unify_coeffs).map(|((eq, poly), coeff)| eq * *poly * coeff).sum();
    assert_eq!(claimed_eval, expected_eval);

    // VERIFY PACK POLYS
    // Replicate packing
    let (_, final_poly_num_vars, packed_comps, final_comp) = pack_poly_verifier(poly_num_vars);
    let final_point = if let Some(final_poly_num_vars) = &final_poly_num_vars { packed_point[packed_point.len() - *final_poly_num_vars..].to_vec() } else { Vec::new() };
    // Use comps to compute evals for packed polys from regular evals
    let (packed_evals, final_eval) = compute_packed_eval(&packed_point, &final_point, unify_evals, &packed_comps, &final_comp);

    Pcs::simple_batch_verify(vp, packed_comm, &packed_point, &packed_evals, packed_proof, transcript)?;
    match (&final_comm, &final_eval, &final_proof) {
        (Some(final_comm), Some(final_eval), Some(final_proof)) => {
            Pcs::verify(vp, final_comm, &final_point, &final_eval, final_proof, transcript)
        }
        (None, None, None) => Ok(()),
        _ => unreachable!(),
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
        rmm: witness::RowMajorMatrix<<E as ff_ext::ExtensionField>::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let polys = rmm.to_mles();
        Self::batch_commit_polys(pp, &polys)
    }

    fn batch_commit_polys(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::batch_commit(pp, rmm)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn batch_commit_and_write_polys(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::batch_commit_polys(pp, polys)?;
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
    #[cfg(test)]
    use rand::{distributions::Standard, prelude::Distribution};
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    #[cfg(test)]
    use transcript::BasicTranscript;
    use transcript::Transcript;
    #[cfg(test)]
    use witness::RowMajorMatrix;

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
        _gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
        Standard: Distribution<E::BaseField>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comm, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let rmm =
                    RowMajorMatrix::<E::BaseField>::rand(&mut OsRng, 1 << num_vars, batch_size);
                let polys = rmm.to_mles();
                let comm = Pcs::batch_commit_and_write(&pp, rmm, &mut transcript).unwrap();
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
        use crate::{pcs_batch_commit_diff_size_and_write, pcs_batch_open_diff_size, pcs_batch_verify_diff_size};

        for vars_gap in 0..=max_vars_gap {
            println!("GAP: {vars_gap}");
            assert!(max_num_vars > vars_gap * batch_size);
            let (pp, vp) = setup_pcs::<E, Pcs>(max_num_vars);

            let (poly_num_vars, packed_comm, final_comm, poly_evals, unify_evals, unify_proof, packed_proof, final_proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys: Vec<DenseMultilinearExtension<E>> = (0..batch_size).map(|i| 
                    gen_rand_polys(|_| max_num_vars - i * vars_gap, 1, gen_rand_poly)
                ).flatten().collect();
                let (packed_comm, final_comm) = pcs_batch_commit_diff_size_and_write::<E, Pcs>(&pp, &polys, &mut transcript).unwrap();
                let point = get_point_from_challenge(max_num_vars, &mut transcript);
                let points: Vec<Vec<E>> = polys.iter().map(|p| point[max_num_vars - p.num_vars..].to_vec()).collect();
                let evals = polys.iter().zip(&points).map(|(poly, point)| poly.evaluate(point)).collect_vec();
                transcript.append_field_element_exts(&evals);

                let (unify_proof, unify_evals, packed_proof, final_proof) = pcs_batch_open_diff_size::<E, Pcs>(&pp, &polys, &packed_comm, &final_comm, &points, &evals, &mut transcript).unwrap();
                (
                    polys.iter().map(|p| p.num_vars()).collect::<Vec<_>>(),
                    Pcs::get_pure_commitment(&packed_comm),
                    if let Some(final_comm) = final_comm { Some(Pcs::get_pure_commitment(&final_comm)) } else { None },
                    evals,
                    unify_evals,
                    unify_proof,
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
                let points: Vec<Vec<E>> = poly_num_vars.iter().map(|n| point[max_num_vars - *n..].to_vec()).collect();
                transcript.append_field_element_exts(&poly_evals);

                pcs_batch_verify_diff_size::<E, Pcs>(&vp, &poly_num_vars, &packed_comm, &final_comm, &points, &poly_evals, &unify_proof, &unify_evals,  &packed_proof, &final_proof, &mut transcript).unwrap();

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
    use ark_std::test_rng;
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType, MultilinearExtension};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    // use crate::interleave_pattern;
    type E = GoldilocksExt2;

    // #[test]
    // fn test_interleave() {
    //     let poly_num_vars = [vec![27, 26, 25, 25], vec![4, 4, 4, 4, 4], vec![8], vec![23, 23, 19, 13]];
    //     for num_vars in poly_num_vars {
    //         println!("NUM_VARS: {:?}", num_vars);
    //         let sizes = num_vars.iter().map(|n| 2_i32.pow(*n) as usize).collect();
    //         let interleaved_indices = interleave_pattern(sizes);
    //         println!("INDICES: {:?}", interleaved_indices);
    //     }
    // }

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

    #[test]
    fn test_packing_eval() {
        let mut rng = test_rng();
        let poly0 = DenseMultilinearExtension::<E>::random(4, &mut rng);
        let poly1 = DenseMultilinearExtension::<E>::random(3, &mut rng);
        let poly2 = DenseMultilinearExtension::<E>::random(2, &mut rng);
        let point = [E::from_i32(5), E::from_i32(7), E::from_i32(9), E::from_i32(11), E::from_i32(13)];
        let eval0 = poly0.evaluate(&point[1..]);
        let eval1 = poly1.evaluate(&point[2..]);
        let eval2 = poly2.evaluate(&point[3..]);
        let claim = 
            (E::ONE - point[0]) * eval0 + 
            point[0] * (E::ONE - point[1]) * eval1 + 
            point[0] * point[1] * (E::ONE - point[2]) * eval2;

        let mut poly = poly0.clone();
        poly.merge(poly1.clone());
        poly.merge(poly2.clone());
        match &mut poly.evaluations {
            FieldType::Base(e) => {
                e.extend(vec![Goldilocks::ZERO; 4])
            }
            FieldType::Ext(e) => {
                e.extend(vec![E::ZERO; 4])
            }
            _ => ()
        }
        let eval = poly.evaluate(&point);
        println!("CLAIM: {:?}, EXPECTED: {:?}", claim, eval);
    }
}
