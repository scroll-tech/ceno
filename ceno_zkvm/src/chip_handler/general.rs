use ff_ext::ExtensionField;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    expression::{Expression, Fixed, Instance, ToExpr, WitIn},
    instructions::riscv::constants::{
        END_CYCLE_IDX, END_PC_IDX, EXIT_CODE_IDX, INIT_CYCLE_IDX, INIT_PC_IDX,
    },
    structs::ROMType,
    tables::InsnRecord,
};

impl<'a, E: ExtensionField> CircuitBuilder<'a, E> {
    pub fn new(cs: &'a mut ConstraintSystem<E>) -> Self {
        Self { cs }
    }

    pub fn create_witin<Name>(&mut self, name: Name) -> Result<WitIn, ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.create_witin(name)
    }

    pub fn create_fixed<Name>(&mut self, name: Name) -> Result<Fixed, ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.create_fixed(name)
    }

    pub fn query_exit_code(&mut self) -> Result<[Instance; 2], ZKVMError> {
        Ok([
            self.cs.query_instance("exit_code_low", EXIT_CODE_IDX)?,
            self.cs
                .query_instance("exit_code_high", EXIT_CODE_IDX + 1)?,
        ])
    }

    pub fn query_init_pc(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance("init_pc", INIT_PC_IDX)
    }

    pub fn query_init_cycle(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance("init_cycle", INIT_CYCLE_IDX)
    }

    pub fn query_end_pc(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance("end_pc", END_PC_IDX)
    }

    pub fn query_end_cycle(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance("end_cycle", END_CYCLE_IDX)
    }

    pub fn lk_record<Name>(
        &mut self,
        name: Name,
        rom_type: ROMType,
        items: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.lk_record(name, rom_type, items)
    }

    pub fn lk_table_record<Name>(
        &mut self,
        name: Name,
        table_len: usize,
        rlc_record: Expression<E>,
        multiplicity: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs
            .lk_table_record(name, table_len, rlc_record, multiplicity)
    }

    pub fn r_table_record<Name>(
        &mut self,
        name: Name,
        table_len: usize,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.r_table_record(name, table_len, rlc_record)
    }

    pub fn w_table_record<Name>(
        &mut self,
        name: Name,
        table_len: usize,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.w_table_record(name, table_len, rlc_record)
    }

    /// Fetch an instruction at a given PC from the Program table.
    pub fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), ZKVMError> {
        self.lk_record("fetch", ROMType::Instruction, record.as_slice().to_vec())
    }

    pub fn read_record<Name>(
        &mut self,
        name: Name,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.read_record(name, rlc_record)
    }

    pub fn write_record<Name>(
        &mut self,
        name: Name,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.cs.write_record(name, rlc_record)
    }

    pub fn rlc_chip_record(&self, records: Vec<Expression<E>>) -> Expression<E> {
        self.cs.rlc_chip_record(records)
    }

    pub fn require_zero<Name>(
        &mut self,
        name: Name,
        assert_zero_expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.namespace("require_zero", |cb| {
            cb.cs.require_zero(name, assert_zero_expr)
        })
    }

    pub fn require_equal<Name>(
        &mut self,
        name: Name,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.namespace("require_equal", |cb| {
            cb.cs
                .require_zero(name, a.to_monomial_form() - b.to_monomial_form())
        })
    }

    pub fn require_one<Name>(&mut self, name: Name, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.namespace("require_one", |cb| {
            cb.cs.require_zero(name, Expression::from(1) - expr)
        })
    }

    pub fn condition_require_equal<Name>(
        &mut self,
        name: Name,
        cond: Expression<E>,
        target: Expression<E>,
        true_expr: Expression<E>,
        false_expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        // cond * (true_expr) + (1 - cond) * false_expr
        // => false_expr + cond * true_expr - cond * false_expr
        self.namespace("cond_require_equal", |cb| {
            let cond_target = false_expr.clone() + cond.clone() * true_expr - cond * false_expr;
            cb.cs.require_zero(name, target - cond_target)
        })
    }

    pub fn select(
        &mut self,
        cond: &Expression<E>,
        when_true: &Expression<E>,
        when_false: &Expression<E>,
    ) -> Expression<E> {
        cond.clone() * when_true.clone() + (1 - cond.clone()) * when_false.clone()
    }

    pub(crate) fn assert_ux<Name, const C: usize>(
        &mut self,
        name: Name,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        match C {
            16 => self.assert_u16(name, expr),
            14 => self.assert_u14(name, expr),
            8 => self.assert_byte(name, expr),
            5 => self.assert_u5(name, expr),
            c => panic!("Unsupported bit range {c}"),
        }
    }

    fn assert_u5<Name>(&mut self, name: Name, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.namespace("assert_u5", |cb| {
            cb.lk_record(name, ROMType::U5, vec![expr])
        })
    }

    fn assert_u14<Name>(&mut self, name: Name, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.lk_record(name, ROMType::U14, vec![expr])?;
        Ok(())
    }

    fn assert_u16<Name>(&mut self, name: Name, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.lk_record(name, ROMType::U16, vec![expr])?;
        Ok(())
    }

    /// create namespace to prefix all constraints define under the scope
    pub fn namespace<Name: Into<String>, T>(
        &mut self,
        name: Name,
        cb: impl FnOnce(&mut CircuitBuilder<E>) -> Result<T, ZKVMError>,
    ) -> Result<T, ZKVMError> {
        self.cs.namespace(name, |cs| {
            let mut inner_circuit_builder = CircuitBuilder::new(cs);
            cb(&mut inner_circuit_builder)
        })
    }

    pub(crate) fn assert_byte<Name>(
        &mut self,
        name: Name,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.lk_record(name, ROMType::U8, vec![expr])?;
        Ok(())
    }

    pub(crate) fn assert_bit<Name>(
        &mut self,
        name: Name,
        expr: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        Name: Into<String>,
    {
        self.namespace("assert_bit", |cb| {
            cb.cs
                .require_zero(name, expr.clone() * (Expression::ONE - expr))
        })
    }

    /// Assert `rom_type(a, b) = c` and that `a, b, c` are all bytes.
    pub fn logic_u8(
        &mut self,
        rom_type: ROMType,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.lk_record(format!("lookup_{:?}", rom_type), rom_type, vec![a, b, c])
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
        let is_eq = self.create_witin("is_eq")?;
        let diff_inverse = self.create_witin("diff_inverse")?;

        self.require_zero(
            "is equal",
            is_eq.expr().clone() * lhs.clone() - is_eq.expr() * rhs.clone(),
        )?;
        self.require_zero(
            "is equal",
            Expression::from(1) - is_eq.expr().clone() - diff_inverse.expr() * lhs
                + diff_inverse.expr() * rhs,
        )?;

        Ok((is_eq, diff_inverse))
    }
}
