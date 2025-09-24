extern crate ceno_rt;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChunkWitness {
    pub test: Vec<u32>,
}


fn main() {
    let witness_bytes = ceno_rt::read_slice();
    let config = bincode::config::standard();
    let _: Result<(ChunkWitness, _), _> = bincode::serde::decode_from_slice(witness_bytes, config); // ignore error
}
