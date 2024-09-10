use ff_ext::ExtensionField;

use ff::Field;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    structs::ROMType,
};

impl<'a, E: ExtensionField> CircuitBuilder<'a, E> {
    pub fn new(cs: &'a mut ConstraintSystem<E>) -> Self {
        Self { cs }
    }

    pub fn create_witin<NR, N>(&mut self, name_fn: N) -> Result<WitIn, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_witin(name_fn)
    }

    pub fn create_fixed<NR, N>(&mut self, name_fn: N) -> Result<Fixed, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_fixed(name_fn)
    }

    pub fn lk_record<NR, N>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.lk_record(name_fn, rlc_record)
    }

    pub fn lk_table_record<NR, N>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
        multiplicity: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.lk_table_record(name_fn, rlc_record, multiplicity)
    }

    pub fn read_record<NR, N>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.read_record(name_fn, rlc_record)
    }

    pub fn write_record<NR, N>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.write_record(name_fn, rlc_record)
    }

    pub fn rlc_chip_record(&self, records: Vec<Expression<E>>) -> Expression<E> {
        assert!(!records.is_empty());
        let beta_pows = {
            let mut beta_pows = Vec::with_capacity(records.len());
            beta_pows.push(Expression::Constant(E::BaseField::ONE));
            (0..records.len() - 1).for_each(|_| {
                beta_pows.push(self.cs.chip_record_beta.clone() * beta_pows.last().unwrap().clone())
            });
            beta_pows
        };

        let item_rlc = beta_pows
            .into_iter()
            .zip(records.iter())
            .map(|(beta, record)| beta * record.clone())
            .reduce(|a, b| a + b)
            .expect("reduce error");

        item_rlc + self.cs.chip_record_alpha.clone()
    }

    pub fn require_zero<NR, N>(
        &mut self,
        name_fn: N,
        assert_zero_expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "require_zero",
            |cb| cb.cs.require_zero(name_fn, assert_zero_expr),
        )
    }

    pub fn require_equal<NR, N>(
        &mut self,
        name_fn: N,
        target: Expression<E>,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "require_equal",
            |cb| cb.cs.require_zero(name_fn, target - rlc_record),
        )
    }

    pub fn require_one<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "require_one",
            |cb| cb.cs.require_zero(name_fn, Expression::from(1) - expr),
        )
    }

    pub(crate) fn assert_ux<NR, N, const C: usize>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        match C {
            16 => self.assert_u16(name_fn, expr),
            8 => self.assert_byte(name_fn, expr),
            5 => self.assert_u5(name_fn, expr),
            _ => panic!("Unsupported bit range"),
        }
    }

    fn assert_u5<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "assert_u5",
            |cb| {
                let items: Vec<Expression<E>> = vec![
                    Expression::Constant(E::BaseField::from(ROMType::U5 as u64)),
                    expr,
                ];
                let rlc_record = cb.rlc_chip_record(items);
                cb.cs.lk_record(name_fn, rlc_record)
            },
        )
    }

    fn assert_u16<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(ROMType::U16 as u64)),
            expr,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.lk_record(name_fn, rlc_record)?;
        Ok(())
    }

    /// create namespace to prefix all constraints define under the scope
    pub fn namespace<NR: Into<String>, N: FnOnce() -> NR, T>(
        &mut self,
        name_fn: N,
        cb: impl FnOnce(&mut CircuitBuilder<E>) -> Result<T, ZKVMError>,
    ) -> Result<T, ZKVMError> {
        self.cs.namespace(name_fn, |cs| {
            let mut inner_circuit_builder = CircuitBuilder::new(cs);
            cb(&mut inner_circuit_builder)
        })
    }

    pub(crate) fn assert_byte<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.assert_u16(name_fn, expr * Expression::from(1 << 8))
    }

    pub(crate) fn assert_bit<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.assert_u16(name_fn, expr * Expression::from(1 << 15))
    }

    /// lookup a ^ b = res
    /// a and b are bytes
    pub(crate) fn lookup_and_byte(
        &mut self,
        res: Expression<E>,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<(), ZKVMError> {
        let key = a * 256.into() + b;
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(ROMType::And as u64)),
            key,
            res,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.lk_record(|| "and lookup record", rlc_record)?;
        Ok(())
    }

    /// lookup a < b as unsigned byte
    pub(crate) fn lookup_ltu_limb8(
        &mut self,
        res: Expression<E>,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<(), ZKVMError> {
        let key = a * 256.into() + b;
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(ROMType::Ltu as u64)),
            key,
            res,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.lk_record(|| "ltu lookup record", rlc_record)?;
        Ok(())
    }

    pub(crate) fn is_equal(
        &mut self,
        lhs: Expression<E>,
        rhs: Expression<E>,
    ) -> Result<(WitIn, WitIn), ZKVMError> {
        let is_eq = self.create_witin(|| "is_eq")?;
        let diff_inverse = self.create_witin(|| "diff_inverse")?;

        self.require_zero(
            || "is equal",
            is_eq.expr().clone() * lhs.clone() - is_eq.expr() * rhs.clone(),
        )?;
        self.require_zero(
            || "is equal",
            Expression::from(1) - is_eq.expr().clone() - diff_inverse.expr() * lhs
                + diff_inverse.expr() * rhs,
        )?;

        Ok((is_eq, diff_inverse))
    }
}
