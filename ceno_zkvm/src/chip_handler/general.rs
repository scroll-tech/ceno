use ff_ext::ExtensionField;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    expression::{Expression, Fixed, Instance, ToExpr, WitIn},
    instructions::riscv::constants::EXIT_CODE_IDX,
    structs::ROMType,
    tables::InsnRecord,
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

    pub fn query_exit_code(&mut self) -> Result<[Instance; 2], ZKVMError> {
        Ok([
            self.cs.query_instance(|| "exit_code_low", EXIT_CODE_IDX)?,
            self.cs
                .query_instance(|| "exit_code_high", EXIT_CODE_IDX + 1)?,
        ])
    }

    pub fn lk_record<NR, N>(
        &mut self,
        name_fn: N,
        items: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.lk_record(name_fn, items)
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

    /// Fetch an instruction at a given PC from the Program table.
    pub fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), ZKVMError> {
        let mut fields = vec![E::BaseField::from(ROMType::Instruction as u64).expr()];
        fields.extend_from_slice(record.as_slice());

        self.lk_record(|| "fetch", fields)
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

    pub fn rlc_chip_record(&self, records: &[Expression<E>]) -> Expression<E> {
        self.cs.rlc_chip_record(records)
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

    pub fn condition_require_equal<NR, N>(
        &mut self,
        name_fn: N,
        cond: Expression<E>,
        target: Expression<E>,
        true_expr: Expression<E>,
        false_expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // cond * (true_expr) + (1 - cond) * false_expr
        // => false_expr + cond * true_expr - cond * false_expr
        self.namespace(
            || "cond_require_equal",
            |cb| {
                let cond_target = false_expr.clone() + cond.clone() * true_expr - cond * false_expr;
                cb.cs.require_zero(name_fn, target - cond_target)
            },
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
            c => panic!("Unsupported bit range {c}"),
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
                cb.lk_record(
                    name_fn,
                    vec![
                        Expression::Constant(E::BaseField::from(ROMType::U5 as u64)),
                        expr,
                    ],
                )
            },
        )
    }

    fn assert_u16<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(
            name_fn,
            vec![
                Expression::Constant(E::BaseField::from(ROMType::U16 as u64)),
                expr,
            ],
        )?;
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
        self.lk_record(name_fn, vec![(ROMType::U8 as usize).into(), expr])?;
        Ok(())
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
        self.namespace(
            || "assert_bit",
            |cb| {
                cb.cs
                    .require_zero(name_fn, expr.clone() * (Expression::ONE - expr))
            },
        )
    }

    /// Assert `rom_type(a, b) = c` and that `a, b, c` are all bytes.
    pub fn logic_u8(
        &mut self,
        rom_type: ROMType,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.lk_record(
            || format!("lookup_{:?}", rom_type),
            vec![(rom_type as usize).into(), a, b, c],
        )
    }

    /// Assert `a & b = c` and that `a, b, c` are all bytes.
    pub fn lookup_and_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.logic_u8(ROMType::And, a, b, c)
    }

    /// Assert `a | b = c` and that `a, b, c` are all bytes.
    pub fn lookup_or_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.logic_u8(ROMType::Or, a, b, c)
    }

    /// Assert `a ^ b = c` and that `a, b, c` are all bytes.
    pub fn lookup_xor_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.logic_u8(ROMType::Xor, a, b, c)
    }

    /// Assert that `(a < b) == c as bool`, that `a, b` are unsigned bytes, and that `c` is 0 or 1.
    pub fn lookup_ltu_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.logic_u8(ROMType::Ltu, a, b, c)
    }

    // Assert that `2^b = c` and that `b` is a 5-bit unsigned integer.
    pub fn lookup_pow2(&mut self, b: Expression<E>, c: Expression<E>) -> Result<(), ZKVMError> {
        self.logic_u8(ROMType::Pow, 2.into(), b, c)
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
