use gkr::structs::GKRInputClaims;
use goldilocks::SmallField;
use transcript::Challenge;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpcodeType {
    Push1 = 0x60,
    Pop = 0x50,
    Dup2 = 0x8d,
    Swap2 = 0x91,
    Swap4 = 0x93,
    Add = 0x01,
    Gt = 0x0a,
    Jumpi = 0x57,
    Jump = 0x56,
    Mstore = 0x52,
    Jumpdest = 0x5b,
    Return = 0xf3,
}

// TODO: to be changed to a real PCS scheme.
type BatchedPCSProof<F> = Vec<Vec<F>>;
type Commitment<F> = Vec<F>;

pub struct CommitPhaseProof<F: SmallField> {
    commitments: Vec<Commitment<F>>,
}

pub struct GKRPhaseProverState<F: SmallField> {
    proved_input_claims: Vec<GKRInputClaims<F>>,
}

pub struct GKRPhaseVerifierState<F: SmallField> {
    proved_input_claims: Vec<GKRInputClaims<F>>,
}

pub type GKRProof<F> = gkr::structs::IOPProof<F>;

pub struct GKRPhaseProof<F: SmallField> {
    gkr_proofs: Vec<GKRProof<F>>,
}

pub struct OpenPhaseProof<F: SmallField> {
    pcs_proof: BatchedPCSProof<F>,
}

pub struct ZKVMProof<F: SmallField> {
    commitment_phase_proof: CommitPhaseProof<F>,
    gkr_phase_proof: GKRPhaseProof<F>,
    open_phase_proof: OpenPhaseProof<F>,
}

pub enum VMError {
    VerifyError,
}
