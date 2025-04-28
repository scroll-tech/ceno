use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};
use mpcs::{
    Basefold, BasefoldRSParams, PolynomialCommitmentScheme, Whir, WhirDefaultSpec,
    test_util::{get_point_from_challenge, setup_pcs},
};
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;
use rand::{distributions::Standard, prelude::Distribution, thread_rng};
use transcript::{BasicTranscript, Transcript};
use witness::RowMajorMatrix;

type PcsWhirGoldilocks = Whir<GoldilocksExt2, WhirDefaultSpec>;
type PcsWhirBabyBear = Whir<BabyBearExt4, WhirDefaultSpec>;
type PcsBasefoldGoldilocks = Basefold<GoldilocksExt2, BasefoldRSParams>;
type PcsBasefoldBabyBear = Basefold<BabyBearExt4, BasefoldRSParams>;

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short = 'f', long, default_value = "goldilocks")]
    field: String,
    #[arg(short = 'p', long, default_value = "basefold")]
    pcs: String,
}

fn main() {
    // pass the parameters to determine which field to use, using the clap::Parser
    let args = Args::parse();
    for num_var in 5..=10 {
        let (vp, comm, eval, proof) = match (args.field.as_str(), args.pcs.as_str()) {
            ("goldilocks", "whir") => {
                generate_test_vector::<GoldilocksExt2, PcsWhirGoldilocks>(num_var)
            }
            ("goldilocks", "basefold") => {
                generate_test_vector::<GoldilocksExt2, PcsBasefoldGoldilocks>(num_var)
            }
            ("babybear", "whir") => generate_test_vector::<BabyBearExt4, PcsWhirBabyBear>(num_var),
            ("babybear", "basefold") => {
                generate_test_vector::<BabyBearExt4, PcsBasefoldBabyBear>(num_var)
            }
            _ => panic!("Invalid combination of field and PCS"),
        };
        println!("num_vars: {}", num_var);
        println!("vp: {}", vp);
        println!("comm: {}", comm);
        println!("eval: {}", eval);
        println!("proof: {}", proof);
    }
}

pub fn generate_test_vector<E: ExtensionField, Pcs>(
    num_vars: usize,
) -> (String, String, String, String)
where
    Pcs: PolynomialCommitmentScheme<E>,
    Standard: Distribution<E::BaseField>,
{
    let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);
    let mut test_rng = thread_rng();

    // Commit and open
    let (comm, eval, proof) = {
        let mut transcript = BasicTranscript::new(b"BaseFold");
        let rmm = RowMajorMatrix::<E::BaseField>::rand(&mut test_rng, 1 << num_vars, 1);
        let poly: ArcMultilinearExtension<E> = rmm.to_mles().remove(0).into();
        let comm = Pcs::commit_and_write(&pp, rmm, &mut transcript).unwrap();

        let point = get_point_from_challenge(num_vars, &mut transcript);
        let eval = poly.evaluate(point.as_slice());
        transcript.append_field_element_ext(&eval);

        (
            Pcs::get_pure_commitment(&comm),
            eval,
            Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap(),
        )
    };
    // Serialize vp, comm, eval, proof using bincode
    let vp_bin = bincode::serialize(&vp).unwrap();
    let comm_bin = bincode::serialize(&comm).unwrap();
    let eval_bin = bincode::serialize(&eval).unwrap();
    let proof_bin = bincode::serialize(&proof).unwrap();

    // Encode them as hex strings
    let vp_hex = hex::encode(vp_bin);
    let comm_hex = hex::encode(comm_bin);
    let eval_hex = hex::encode(eval_bin);
    let proof_hex = hex::encode(proof_bin);

    (vp_hex, comm_hex, eval_hex, proof_hex)
}
