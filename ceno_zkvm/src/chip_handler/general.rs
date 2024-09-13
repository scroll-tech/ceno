use std::fmt::Display;

use ff_ext::ExtensionField;
use itertools::Itertools;

use crate::{
    chip_handler::utils::pows_expr,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    instructions::riscv::config::ExprLtConfig,
    structs::ROMType,
    tables::InsnRecord,
};

use super::utils::rlc_chip_record;

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

    /// Fetch an instruction at a given PC from the Program table.
    pub fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), ZKVMError> {
        let rlc_record = {
            let mut fields = vec![E::BaseField::from(ROMType::Instruction as u64).expr()];
            fields.extend_from_slice(record.as_slice());
            self.rlc_chip_record(fields)
        };

        self.cs.lk_record(|| "fetch", rlc_record)
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
        rlc_chip_record(
            records,
            self.cs.chip_record_alpha.clone(),
            self.cs.chip_record_beta.clone(),
        )
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

    /// less_than
    pub(crate) fn less_than<N, NR>(
        &mut self,
        name_fn: N,
        lhs: Expression<E>,
        rhs: Expression<E>,
        assert_less_than: Option<bool>,
    ) -> Result<ExprLtConfig, ZKVMError>
    where
        NR: Into<String> + Display + Clone,
        N: FnOnce() -> NR,
    {
        #[cfg(feature = "riv64")]
        panic!("less_than is not supported for riv64 yet");

        #[cfg(feature = "riv32")]
        self.namespace(
            || "less_than",
            |cb| {
                let name = name_fn();
                let (is_lt, is_lt_expr) = if let Some(lt) = assert_less_than {
                    (
                        None,
                        if lt {
                            Expression::ONE
                        } else {
                            Expression::ZERO
                        },
                    )
                } else {
                    let is_lt = cb.create_witin(|| format!("{name} is_lt witin"))?;
                    (Some(is_lt), is_lt.expr())
                };

                let mut witin_u16 = |var_name: String| -> Result<WitIn, ZKVMError> {
                    cb.namespace(
                        || format!("var {var_name}"),
                        |cb| {
                            let witin = cb.create_witin(|| var_name.to_string())?;
                            cb.assert_ux::<_, _, 16>(|| name.clone(), witin.expr())?;
                            Ok(witin)
                        },
                    )
                };

                let diff = (0..2)
                    .map(|i| witin_u16(format!("diff_{i}")))
                    .collect::<Result<Vec<WitIn>, _>>()?;

                let pows = pows_expr((1 << u16::BITS).into(), diff.len());

                let diff_expr = diff
                    .iter()
                    .zip_eq(pows)
                    .map(|(record, beta)| beta * record.expr())
                    .reduce(|a, b| a + b)
                    .expect("reduce error");

                let range = (1 << u32::BITS).into();

                cb.require_equal(|| name.clone(), lhs - rhs, diff_expr - is_lt_expr * range)?;

                Ok(ExprLtConfig { is_lt, diff })
            },
        )
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
