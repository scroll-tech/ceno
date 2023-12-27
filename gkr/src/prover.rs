use goldilocks::SmallField;
use transcript::Transcript;

use crate::structs::{
    Circuit, CircuitWitness, IOPProof, IOPProverPhase1Message, IOPProverPhase2Message,
    IOPProverState, Point,
};

impl<F: SmallField> IOPProverState<F> {
    /// Prove process for data parallel circuits.
    pub fn prove_parallel(
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
        transcript: &mut Transcript<F>,
    ) -> IOPProof<F> {
        todo!()
    }

    /// Initialize proving state for data parallel circuits.
    fn prover_init_parallel(
        circuit_witness: &CircuitWitness<F>,
        output_points: &[&Point<F>],
        output_evaluations: &[F],
    ) -> Self {
        todo!()
    }

    /// Prove the items copied from the current layer to later layers for data parallel circuits.
    /// \sum_j( \alpha_j * subset[i][j](rt || rw_j) ) = \sum_w( \sum_j( (\alpha_j copy_from[j](rw_j, w)) * layers[i](rt || w) ) )
    fn prove_and_update_state_phase1_parallel(
        &mut self,
        deeper_points: &[&Point<F>],
        deeper_evaluations: &[F],
        transcript: &mut Transcript<F>,
    ) -> (IOPProverPhase1Message<F>, Point<F>) {
        todo!()
    }

    /// Prove the computation in the current layer for data parallel circuits.
    /// The number of terms depends on the gate.
    /// Here is an example of degree 3:
    /// layers[i](rt || rw) = \sum_{s1}( \sum_{s2}( \sum_{s3}( \sum_x( \sum_y( \sum_z(
    ///     eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * layers[i + 1](s1 || x) * layers[i + 1](s2 || y) * layers[i + 1](s3 || z)
    /// ) ) ) ) ) ) + sum_s1( sum_s2( sum_x( sum_y(
    ///     eq(rt, s1, s2) * mul2(rw, x, y) * layers[i + 1](s1 || x) * layers[i + 1](s2 || y)
    /// ) ) ) ) + \sum_{s1}( \sum_x(
    ///     eq(rt, s1) * add(rw, x) * layers[i + 1](s1 || x)
    /// ) ) + \sum_{s1}( \sum_x(
    ///      \sum_j eq(rt, s1) paste_to[j](rw, x) * subset[j][i](s1 || x)
    /// ) )
    ///
    /// It runs 3 sumchecks.
    /// - Sumcheck 1: sigma = \sum_{s1 || x} f1(s1 || x) * (g1^{(1)}(s1 || x) + g1^{(2)}(s1 || x) + g1^{(3)}(s1 || x)) + \sum_j f2^{(j)}(s1 || x) * g2^{(j)}(s1 || x)
    ///     sigma = layers[i](rt || rw),
    ///     f1(s1 || x) = layers[i + 1](s1 || x)
    ///     g1^{(1)}(s1 || x) = \sum_{s2}( \sum_{s3}( \sum_y( \sum_z(
    ///         eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * layers[i + 1](s2 || y) * layers[i + 1](s3 || z)
    ///     ) ) ) )
    ///     g1^{(2)}(s1 || x) = \sum_{s2}( \sum_y(
    ///         eq(rt, s1, s2) * mul2(rw, x, y) * layers[i + 1](s2 || y)
    ///     ) )
    ///     g1^{(3)}(s1 || x) = eq(rt, s1) * add(rw, x)
    ///     f2^{(j)}(s1 || x) = eq(rt, s1) paste_to[j](rw, x)
    ///     g2^{(j)}(s1 || x) = subset[j][i](s1 || x)
    ///
    /// - Sumcheck 2 sigma = \sum_{s2 || y} f1'(s2 || y) * (g1'^{(1)}(s2 || y) + g1'^{(2)}(s2 || y))
    ///     sigma = g1^{(1)}(rs1 || rx) + g1^{(2)}(rs1 || rx)
    ///     f1'(s2 || y) = layers[i + 1](s2 || y)
    ///     g1'(s2 || y) = \sum_{s3}( \sum_z(
    ///         eq(rt, s1, s2, s3) * mul3(rw, x, y, z) * layers[i + 1](s3 || z)
    ///     ) )
    ///     g1'^{(2)}(s2 || y) = eq(rt, s1, s2) * mul2(rw, x, y)
    ///
    /// - Sumcheck 3 sigma = \sum_{s3 || z} f1''(s3 || z) * g1''(s3 || z)
    ///     sigma = g1^{(1)}'(rs1 || rx)
    ///     f1''(s3 || z) = layers[i + 1](s3 || z)
    ///     g1''(s3 || z) = eq(rt, s1, s2, s3) * mul3(rw, x, y, z)
    fn prove_round_and_update_state_phase2_parallel(
        &mut self,
        layer_out_point: &Point<F>,
        layer_out_evaluation: F,
        transcript: &mut Transcript<F>,
    ) -> (IOPProverPhase2Message<F>, Vec<Point<F>>) {
        todo!()
    }

    // TODO: Define special protocols of special layers for optimization.
}
