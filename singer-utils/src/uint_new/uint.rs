use simple_frontend::structs::CellId;

pub struct UInt<const M: usize, const C: usize> {
    // TODO: handle access control
    pub values: Vec<CellId>,
}

impl<const M: usize, const C: usize> UInt<M, C> {
    pub fn bye() {
        dbg!("bye");
        dbg!(Self::HMM);
    }
}
