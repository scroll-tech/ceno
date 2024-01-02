use goldilocks::SmallField;
use transcript::{Challenge, Transcript};

use crate::structs::{
    Circuit, CircuitWitness, IOPProof, IOPProverPhase1Message, IOPProverPhase2Message,
    IOPProverPhase3Message, IOPProverState, Point,
};

impl<F: SmallField> IOPProverState<F> {
    pub fn prove(
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
        transcript: &mut Transcript<F>,
    ) -> IOPProof<F> {
        todo!()
    }

    fn prover_init(
        circuit_witness: &CircuitWitness<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
    ) -> Self {
        todo!()
    }

    /// Prove the items in the i-th layer are copied to deeper layers.
    /// sum_j( alpha_j * subset[i][j](rt || rw_j) ) = sum_w( sum_j( (alpha_j copied_to[j](rw_j, w)) * current_out(rt || w) ) )
    fn prove_and_update_state_phase1(
        &mut self,
        deeper_points: &[&Point<F>],
        deeper_evaluations: &[F],
        transcript: &mut Transcript<F>,
    ) -> (IOPProverPhase1Message<F>, Point<F>) {
        todo!()
    }

    /// Prove the computation in the current layer. The number of terms depends on the gate.
    /// Here is an example of degree 3:
    /// current_out(rt || rw) = sum_s1( sum_s2( sum_s3( sum_x( sum_y( sum_z(
    ///     eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * current_in(s1 || x) * current_in(s2 || y) * current_in(s3 || z)
    /// ) ) ) ) ) ) + sum_s1( sum_s2( sum_x( sum_y(
    ///     eq(rt, s1, s2) * mul2(rw, x, y) * current_in(s1 || x) * current_in(s2 || y)
    /// ) ) ) ) + sum_s1( sum_x(
    ///     eq(rt, s1) * add(rw, x) * current_in(s1 || x)
    /// ) )
    ///
    /// It runs 3 sumchecks.
    /// - Sumcheck 1: sigma = sum_(s1 || x) f1(s1 || x) * (g1(s1 || x) + g2(s1 || x) + g3(s1 || x))
    ///     sigma = current_out(rt || rw),
    ///     f1(s1 || x) = current_in(s1 || x)
    ///     g1(s1 || x) = sum_s2( sum_s3( sum_y( sum_z(
    ///         eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * current_in(s2 || y) * current_in(s3 || z)
    ///     ) ) ) )
    ///         g2(s1 || x) = sum_s2( sum_y(
    ///         eq(rt, s1, s2) * mul2(rw, x, y) * current_in(s2 || y)
    ///     ) )
    ///     g3(s1 || x) = eq(rt, s1) * add(rw, x)
    ///
    /// - Sumcheck 2 sigma = sum_(s2 || y) f1'(s2 || y) * (g1'(s2 || y) + g2'(s2 || y))
    ///     sigma = g1(rs1 || rx) + g2(rs1 || rx)
    ///     f1'(s2 || y) = current_in(s2 || y)
    ///     g1'(s2 || y) = sum_s3( sum_z(
    ///         eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * current_in(s3 || z)
    ///     ) )
    ///     g2'(s2 || y) = eq(rt, s1, s2) * mul2(rw, x, y)
    ///
    /// - Sumcheck 3 sigma = sum_(s3 || z) f1''(s3 || z) * g1''(s3 || z)
    ///     sigma = g1'(rs1 || rx)
    ///     f1''(s3 || z) = current_in(s3 || z)
    ///     g1''(s3 || z) = eq(rt, s1, s2, s3) * mul3(rw, x, y, z)
    fn prove_round_and_update_state_phase2(
        &mut self,
        layer_out_point: &Point<F>,
        layer_out_evaluation: F,
        transcript: &mut Transcript<F>,
    ) -> (IOPProverPhase2Message<F>, Vec<Point<F>>) {
        todo!()
    }

    // TODO: Define special protocols of special layers for optimization.

    /// Prove the items of the input of the i-th layer are copied from previous layers.
    ///     gamma_1 current_in(rs1 || rx) + gamma_2 current_in(rs2 || ry) + gamma_2 current_in(rs3 || rz)
    ///         = sum_t( sum_w(
    ///             (gamma_1 eq(rs1 || rx, t || w) + gamma_2 eq(rs2 || ry, t || w) + gamma_3 eq(rs3 || rz, t || w)) * subset[prev_i][i](t || w)
    ///             + sum_j(
    ///                 (gamma_1 eq(rs1 || rx) paste_from(rx, w) + gamma_2 eq(rs2 || ry) paste_from(ry, w) + gamma_3 eq(rs3 || rz) paste_from(rz, w)) * subset[j][i](t || w)
    ///             )
    ///         ) )
    fn prove_round_and_update_state_phase3(
        &mut self,
        layer_in_points: &[&Point<F>],
        layer_in_evaluations: &[F],
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase3Message<F> {
        todo!()
    }
}
