use ff::Field;
use itertools::Itertools;
use std::marker::PhantomData;

use goldilocks::SmallField;

use crate::structs::{
    CellId, CellType, ChallengeConst, ChallengeId, CircuitBuilder, ConstantType, InType, MixedCell,
    OutType, WireId,
};

/// An ExtCell consists DEGREE number of cells.
pub struct ExtCell<Ext: SmallField> {
    cells: Vec<CellId>,
    phantom: PhantomData<Ext>,
}

impl<Ext: SmallField> From<Vec<CellId>> for ExtCell<Ext> {
    /// converting a vector of CellIds into an ext cell
    fn from(cells: Vec<CellId>) -> Self {
        Self {
            cells,
            phantom: PhantomData::default(),
        }
    }
}

impl<Ext: SmallField> Into<Vec<CellId>> for ExtCell<Ext> {
    /// converting an ext cell into a vector of CellIds
    fn into(self) -> Vec<CellId> {
        self.cells
    }
}

impl<Ext: SmallField> AsRef<[CellId]> for ExtCell<Ext> {
    fn as_ref(&self) -> &[CellId] {
        &self.cells
    }
}

impl<Ext: SmallField> ExtCell<Ext> {
    /// converting a vector of ext cells into a vector of CellIds
    pub fn exts_to_cells(exts: &[Self]) -> Vec<CellId> {
        exts.iter().flat_map(|ext| ext.cells.clone()).collect()
    }

    /// degree of the ext cell
    pub fn degree(&self) -> usize {
        self.cells.len()
    }
}

macro_rules! rlc_const_term {
    ($builder:ident, $n_ext:expr, $out:expr; $c:expr) => {
        for j in 0..$n_ext {
            $builder.add_const_internal($out[j], ConstantType::Challenge($c, j));
        }
    };
    ($builder:ident, $n_ext:expr, $out:expr; $c:expr, $scalar:expr) => {
        for j in 0..$n_ext {
            $builder.add_const_internal($out[j], ConstantType::ChallengeScaled($c, j, $scalar));
        }
    };
}

macro_rules! rlc_base_term {
    ($builder:ident, $n_ext:expr, $out:expr, $in_0:expr; $c:expr) => {
        for j in 0..$n_ext {
            $builder.add_internal($out[j], $in_0, ConstantType::Challenge($c, j));
        }
    };
    ($builder:ident, $n_ext:expr, $out:expr, $in_0:expr; $c:expr, $scalar:expr) => {
        for j in 0..$n_ext {
            $builder.add_internal(
                $out[j],
                $in_0,
                ConstantType::ChallengeScaled($c, j, $scalar),
            );
        }
    };
}

// Public APIs
impl<F: SmallField> CircuitBuilder<F> {
    pub fn create_ext(&mut self) -> Vec<CellId> {
        self.create_cells(F::DEGREE)
    }

    /// Create an ExtCell for an extension field element.
    /// Note: an extension cell already consists of multiple cells.
    pub fn create_ext_cell(&mut self) -> ExtCell<F> {
        self.create_cells(F::DEGREE).into()
    }

    pub fn create_exts(&mut self, num: usize) -> Vec<Vec<CellId>> {
        let cells = self.create_cells(num * F::DEGREE);
        cells
            .chunks_exact(F::DEGREE)
            .map(|x| x.try_into().unwrap())
            .collect()
    }

    /// Create a vector of ExtCells for a vector of extension field elements.
    /// Note: an extension cell already consists of multiple cells.
    pub fn create_ext_cells(&mut self, num: usize) -> Vec<ExtCell<F>> {
        let cells = self.create_cells(num * F::DEGREE);
        cells
            .chunks_exact(F::DEGREE)
            .map(|x| x.to_vec().into())
            .collect()
    }

    pub fn create_ext_wire_in(&mut self, num: usize) -> (WireId, Vec<ExtCell<F>>) {
        let cells = self.create_cells(num * F::DEGREE);
        self.mark_cells(
            CellType::In(InType::Wire(self.n_wires_in as WireId)),
            &cells,
        );
        self.n_wires_in += 1;
        (
            (self.n_wires_in - 1) as WireId,
            cells
                .chunks_exact(F::DEGREE)
                .map(|x| x.to_vec().into())
                .collect(),
        )
    }

    /// Create input cells and assign it to be constant.
    pub fn create_ext_constant_in(&mut self, num: usize, constant: i64) -> Vec<ExtCell<F>> {
        let cells = self.create_ext_cells(num);
        cells.iter().for_each(|ext_cell| {
            ext_cell.cells.iter().for_each(|&cell| {
                self.mark_cells(CellType::In(InType::Constant(constant)), &[cell])
            })
        });
        cells
    }

    pub fn create_ext_wire_out(&mut self, num: usize) -> (WireId, Vec<ExtCell<F>>) {
        let cells = self.create_cells(num * F::DEGREE);
        self.mark_cells(
            CellType::Out(OutType::Wire(self.n_wires_out as WireId)),
            &cells,
        );
        self.n_wires_out += 1;
        (
            (self.n_wires_out - 1) as WireId,
            cells
                .chunks_exact(F::DEGREE)
                .map(|x| x.to_vec().into())
                .collect(),
        )
    }

    pub fn create_wire_out_from_exts<T>(&mut self, exts: &[ExtCell<F>]) -> WireId {
        for ext in exts {
            self.mark_cells(
                CellType::Out(OutType::Wire(self.n_wires_out as WireId)),
                ext.as_ref(),
            );
        }
        self.n_wires_out += 1;
        (self.n_wires_out - 1) as WireId
    }

    // Q: this seems to be a base operation
    /// Compute the random linear combination of `in_array` by challenge.
    /// out = \sum_{i = 0}^{in_array.len()} challenge^i * in_array[i] + challenge^{in_array.len()}.
    pub fn rlc(&mut self, out: &[CellId], in_array: &[CellId], challenge: ChallengeId) {
        assert_eq!(out.len(), F::DEGREE);
        for (i, item) in in_array.iter().enumerate() {
            let c = ChallengeConst {
                challenge,
                exp: i as u64,
            };
            rlc_base_term!(self, F::DEGREE, out, *item; c);
        }
        let c = ChallengeConst {
            challenge,
            exp: in_array.len() as u64,
        };
        rlc_const_term!(self, F::DEGREE, out; c);
    }

    /// Compute the random linear combination of `in_array` with mixed types by challenge.
    /// out = \sum_{i = 0}^{in_array.len()} challenge^i * (\sum_j in_array[i][j]) + challenge^{in_array.len()}.
    pub fn rlc_mixed(&mut self, out: &[CellId], in_array: &[MixedCell<F>], challenge: ChallengeId) {
        assert_eq!(out.len(), F::DEGREE);
        for (i, item) in in_array.iter().enumerate() {
            let c: ChallengeConst = ChallengeConst {
                challenge,
                exp: i as u64,
            };
            match item {
                MixedCell::Constant(constant) => {
                    rlc_const_term!(self, F::DEGREE, out; c, *constant)
                }
                MixedCell::Cell(cell_id) => {
                    rlc_base_term!(self, F::DEGREE, out, *cell_id; c)
                }
                MixedCell::CellExpr(cell_id, a, b) => {
                    rlc_base_term!(self, F::DEGREE, out, *cell_id; c, *a);
                    rlc_const_term!(self, F::DEGREE, out; c, *b);
                }
            }
        }
        let c: ChallengeConst = ChallengeConst {
            challenge,
            exp: in_array.len() as u64,
        };
        rlc_const_term!(self, F::DEGREE, out; c);
    }

    /// Base on the selection, select
    /// - either extension cell in_0,
    /// - or build a new extension cell from [in_1, 0, 0, 0 ...]
    pub fn sel_ext_and_mixed(
        &mut self,
        out: &ExtCell<F>,
        in_0: &ExtCell<F>,
        in_1: &MixedCell<F>,
        cond: CellId,
    ) {
        assert_eq!(out.degree(), F::DEGREE);
        assert_eq!(in_0.degree(), F::DEGREE);

        out.cells
            .iter()
            .zip_eq(in_0.cells.iter().zip_eq([*in_1].iter().chain(
                std::iter::repeat(&MixedCell::Constant(F::BaseField::ZERO)).take(F::DEGREE - 1),
            )))
            .for_each(|(&out, (&in0, &in1))| self.sel_mixed(out, in0.into(), in1, cond));
    }

    pub fn sel_mixed_and_ext(
        &mut self,
        out: &ExtCell<F>,
        in_0: &MixedCell<F>,
        in_1: &ExtCell<F>,
        cond: CellId,
    ) {
        self.sel_ext_and_mixed(out, in_1, in_0, cond)
    }

    pub fn sel_ext(
        &mut self,
        out: &ExtCell<F>,
        in_0: &ExtCell<F>,
        in_1: &ExtCell<F>,
        cond: CellId,
    ) {
        // we only need to check one degree since the rest are
        // enforced by zip_eq
        assert_eq!(out.degree(), F::DEGREE);

        out.cells
            .iter()
            .zip_eq(in_0.cells.iter().zip_eq(in_1.cells.iter()))
            .for_each(|(&out, (&in0, &in1))| self.select(out, in0, in1, cond));
    }

    pub fn add_ext(&mut self, out: &ExtCell<F>, in_0: &ExtCell<F>, scalar: F::BaseField) {
        // we only need to check one degree since the rest are
        // enforced by zip_eq
        assert_eq!(out.degree(), F::DEGREE);
        out.cells
            .iter()
            .zip_eq(in_0.cells.iter())
            .for_each(|(&o, &i)| self.add(o, i, scalar));
    }

    pub fn mul_ext_base(
        &mut self,
        out: &ExtCell<F>,
        in_0: &ExtCell<F>,
        in_1: CellId,
        scalar: F::BaseField,
    ) {
        assert_eq!(out.degree(), F::DEGREE);
        out.cells
            .iter()
            .zip_eq(in_0.cells.iter())
            .for_each(|(&o, &i)| self.mul2(o, i, in_1, scalar));
    }

    pub fn mul2_ext(
        &mut self,
        out: &ExtCell<F>,
        in_0: &ExtCell<F>,
        in_1: &ExtCell<F>,
        scalar: F::BaseField,
    ) {
        assert_eq!(out.degree(), F::DEGREE);
        match F::DEGREE {
            2 => self.mul2_degree_2_ext_internal(&out.cells, &in_0.cells, &in_1.cells, scalar),
            3 => self.mul2_degree_3_ext_internal(&out.cells, &in_0.cells, &in_1.cells, scalar),
            // we do not support extension field beyond 3 at the moment
            _ => unimplemented!(),
        }
    }

    pub fn add_ext_mul_challenge(&mut self, out: &[CellId], in_0: &[CellId], c: ChallengeConst) {
        assert_eq!(out.len(), F::DEGREE);
        assert_eq!(in_0.len(), F::DEGREE);
        match F::DEGREE {
            2 => self.add_ext_mul_challenge_2(out, in_0, c),
            3 => self.add_ext_mul_challenge_3(out, in_0, c),
            _ => unimplemented!(),
        }
    }

    pub fn add_product_of_ext_and_challenge(
        &mut self,
        out: &ExtCell<F>,
        in_0: &ExtCell<F>,
        c: ChallengeConst,
    ) {
        assert_eq!(out.degree(), F::DEGREE);
        assert_eq!(in_0.degree(), F::DEGREE);
        match F::DEGREE {
            2 => self.add_ext_mul_challenge_2(&out.cells, &in_0.cells, c),
            3 => self.add_ext_mul_challenge_3(&out.cells, &in_0.cells, c),
            _ => unimplemented!(),
        }
    }

    pub fn rlc_ext(&mut self, out: &ExtCell<F>, in_array: &[ExtCell<F>], challenge: ChallengeId) {
        assert_eq!(out.degree(), F::DEGREE);
        match F::DEGREE {
            2 => self.rlc_ext_2(out, in_array, challenge),
            3 => self.rlc_ext_3(out, in_array, challenge),
            _ => unimplemented!(),
        }
    }
}

// Internal APIs
impl<F: SmallField> CircuitBuilder<F> {
    /// let a1b1 = a.0[0] * b.0[0];
    /// let a1b2 = a.0[0] * b.0[1];
    /// let a2b1 = a.0[1] * b.0[0];
    /// let a2b2 = a.0[1] * b.0[1];
    /// let c1 = a1b1 + Goldilocks(7) * a2b2;
    /// let c2 = a2b1 + a1b2;
    fn mul2_degree_2_ext_internal(
        &mut self,
        out: &[CellId],
        in_0: &[CellId],
        in_1: &[CellId],
        scalar: F::BaseField,
    ) {
        let a0b0 = self.create_cell();
        self.mul2(a0b0, in_0[0], in_1[0], F::BaseField::ONE);
        let a0b1 = self.create_cell();
        self.mul2(a0b1, in_0[0], in_1[1], F::BaseField::ONE);
        let a1b0 = self.create_cell();
        self.mul2(a1b0, in_0[1], in_1[0], F::BaseField::ONE);
        let a1b1 = self.create_cell();
        self.mul2(a1b1, in_0[1], in_1[1], F::BaseField::ONE);
        self.add(out[0], a0b0, scalar);
        self.add(out[0], a1b1, F::BaseField::from(7) * scalar);
        self.add(out[1], a1b0, scalar);
        self.add(out[1], a0b1, scalar);
    }

    fn add_ext_mul_challenge_2(&mut self, out: &[CellId], in_0: &[CellId], c: ChallengeConst) {
        let a0b0 = self.create_cell();
        let in_1 = [ConstantType::Challenge(c, 0), ConstantType::Challenge(c, 1)];
        self.add_internal(a0b0, in_0[0], in_1[0]);
        let a0b1 = self.create_cell();
        self.add_internal(a0b1, in_0[0], in_1[1]);
        let a1b0 = self.create_cell();
        self.add_internal(a1b0, in_0[1], in_1[0]);
        let a1b1 = self.create_cell();
        self.add_internal(a1b1, in_0[1], in_1[1]);
        self.add(out[0], a0b0, F::BaseField::ONE);
        self.add(out[0], a1b1, F::BaseField::from(7));
        self.add(out[1], a1b0, F::BaseField::ONE);
        self.add(out[1], a0b1, F::BaseField::ONE);
    }

    /// Random linear combinations for extension cells with degree = 2
    fn rlc_ext_2(&mut self, out: &ExtCell<F>, in_array: &[ExtCell<F>], challenge: ChallengeId) {
        assert_eq!(out.degree(), F::DEGREE);
        for (i, item) in in_array.iter().enumerate() {
            let c = ChallengeConst {
                challenge,
                exp: i as u64,
            };
            self.add_ext_mul_challenge_2(&out.cells, &item.cells, c);
        }
        let c = ChallengeConst {
            challenge,
            exp: in_array.len() as u64,
        };
        rlc_const_term!(self, F::DEGREE, out.cells; c);
    }

    /// Random linear combinations for extension cells with degree = 3
    fn rlc_ext_3(&mut self, out: &ExtCell<F>, in_array: &[ExtCell<F>], challenge: ChallengeId) {
        assert_eq!(out.degree(), 3);
        for (i, item) in in_array.iter().enumerate() {
            let c = ChallengeConst {
                challenge,
                exp: i as u64,
            };
            self.add_ext_mul_challenge_3(&out.cells, &item.cells, c);
        }
        let c = ChallengeConst {
            challenge,
            exp: in_array.len() as u64,
        };
        rlc_const_term!(self, 3, out.cells; c);
    }

    /// let a1b1 = a.0[0] * b.0[0];
    /// let a1b2 = a.0[0] * b.0[1];
    /// let a1b3 = a.0[0] * b.0[2];
    /// let a2b1 = a.0[1] * b.0[0];
    /// let a2b2 = a.0[1] * b.0[1];
    /// let a2b3 = a.0[1] * b.0[2];
    /// let a3b1 = a.0[2] * b.0[0];
    /// let a3b2 = a.0[2] * b.0[1];
    /// let a3b3 = a.0[2] * b.0[2];
    /// let c1 = a1b1 + a3b2 + a2b3;
    /// let c2 = a2b1 + a1b2 + a2b3 + a3b2 + a3b3;
    /// let c3 = a3b1 + a2b2 + a1b3 + a3b3;
    /// GoldilocksExt3([c1, c2, c3])
    fn mul2_degree_3_ext_internal(
        &mut self,
        out: &[CellId],
        in_0: &[CellId],
        in_1: &[CellId],
        scalar: F::BaseField,
    ) {
        let a0b0 = self.create_cell();
        self.mul2(a0b0, in_0[0], in_1[0], F::BaseField::ONE);
        let a0b1 = self.create_cell();
        self.mul2(a0b1, in_0[0], in_1[1], F::BaseField::ONE);
        let a0b2 = self.create_cell();
        self.mul2(a0b2, in_0[0], in_1[2], F::BaseField::ONE);
        let a1b0 = self.create_cell();
        self.mul2(a1b0, in_0[1], in_1[0], F::BaseField::ONE);
        let a1b1 = self.create_cell();
        self.mul2(a1b1, in_0[1], in_1[1], F::BaseField::ONE);
        let a1b2 = self.create_cell();
        self.mul2(a1b2, in_0[1], in_1[2], F::BaseField::ONE);
        let a2b0 = self.create_cell();
        self.mul2(a2b0, in_0[2], in_1[0], F::BaseField::ONE);
        let a2b1 = self.create_cell();
        self.mul2(a2b1, in_0[2], in_1[1], F::BaseField::ONE);
        let a2b2 = self.create_cell();
        self.mul2(a2b2, in_0[2], in_1[2], F::BaseField::ONE);
        self.add(out[0], a0b0, scalar);
        self.add(out[0], a2b1, scalar);
        self.add(out[0], a1b2, scalar);
        self.add(out[1], a1b0, scalar);
        self.add(out[1], a0b1, scalar);
        self.add(out[1], a2b1, scalar);
        self.add(out[1], a1b2, scalar);
        self.add(out[1], a2b2, scalar);
        self.add(out[2], a2b0, scalar);
        self.add(out[2], a1b1, scalar);
        self.add(out[2], a0b2, scalar);
        self.add(out[2], a2b2, scalar);
    }

    fn add_ext_mul_challenge_3(&mut self, out: &[CellId], in_0: &[CellId], c: ChallengeConst) {
        let in_1 = [
            ConstantType::Challenge(c, 0),
            ConstantType::Challenge(c, 1),
            ConstantType::Challenge(c, 2),
        ];
        let a0b0 = self.create_cell();
        self.add_internal(a0b0, in_0[0], in_1[0]);
        let a0b1 = self.create_cell();
        self.add_internal(a0b1, in_0[0], in_1[1]);
        let a0b2 = self.create_cell();
        self.add_internal(a0b2, in_0[0], in_1[2]);
        let a1b0 = self.create_cell();
        self.add_internal(a1b0, in_0[1], in_1[0]);
        let a1b1 = self.create_cell();
        self.add_internal(a1b1, in_0[1], in_1[1]);
        let a1b2 = self.create_cell();
        self.add_internal(a1b2, in_0[1], in_1[2]);
        let a2b0 = self.create_cell();
        self.add_internal(a2b0, in_0[2], in_1[0]);
        let a2b1 = self.create_cell();
        self.add_internal(a2b1, in_0[2], in_1[1]);
        let a2b2 = self.create_cell();
        self.add_internal(a2b2, in_0[2], in_1[2]);
        self.add(out[0], a0b0, F::BaseField::ONE);
        self.add(out[0], a2b1, F::BaseField::ONE);
        self.add(out[0], a1b2, F::BaseField::ONE);
        self.add(out[1], a1b0, F::BaseField::ONE);
        self.add(out[1], a0b1, F::BaseField::ONE);
        self.add(out[1], a2b1, F::BaseField::ONE);
        self.add(out[1], a1b2, F::BaseField::ONE);
        self.add(out[1], a2b2, F::BaseField::ONE);
        self.add(out[2], a2b0, F::BaseField::ONE);
        self.add(out[2], a1b1, F::BaseField::ONE);
        self.add(out[2], a0b2, F::BaseField::ONE);
        self.add(out[2], a2b2, F::BaseField::ONE);
    }
}
