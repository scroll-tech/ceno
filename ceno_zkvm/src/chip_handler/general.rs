use ff_ext::ExtensionField;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem, SetTableSpec},
    error::ZKVMError,
    expression::{Expression, Fixed, Instance, StructuralWitIn, ToExpr, WitIn},
    instructions::riscv::constants::{
        END_CYCLE_IDX, END_PC_IDX, EXIT_CODE_IDX, INIT_CYCLE_IDX, INIT_PC_IDX, PUBLIC_IO_IDX,
        UINT_LIMBS,
    },
    structs::{ProgramParams, RAMType, ROMType},
    tables::InsnRecord,
};

impl<'a, E: ExtensionField> CircuitBuilder<'a, E> {
    pub fn new(cs: &'a mut ConstraintSystem<E>) -> Self {
        Self::new_with_params(cs, ProgramParams::default())
    }
    pub fn new_with_params(cs: &'a mut ConstraintSystem<E>, params: ProgramParams) -> Self {
        Self { cs, params }
    }

    pub fn create_witin<NR, N>(&mut self, name_fn: N) -> WitIn
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_witin(name_fn)
    }

    pub fn create_structural_witin<NR, N>(
        &mut self,
        name_fn: N,
        max_len: usize,
        offset: u32,
        multi_factor: usize,
    ) -> StructuralWitIn
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .create_structural_witin(name_fn, max_len, offset, multi_factor)
    }

    pub fn create_fixed<NR, N>(&mut self, name_fn: N) -> Result<Fixed, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_fixed(name_fn)
    }

    pub fn query_exit_code(&mut self) -> Result<[Instance; UINT_LIMBS], ZKVMError> {
        Ok([
            self.cs.query_instance(|| "exit_code_low", EXIT_CODE_IDX)?,
            self.cs
                .query_instance(|| "exit_code_high", EXIT_CODE_IDX + 1)?,
        ])
    }

    pub fn query_init_pc(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance(|| "init_pc", INIT_PC_IDX)
    }

    pub fn query_init_cycle(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance(|| "init_cycle", INIT_CYCLE_IDX)
    }

    pub fn query_end_pc(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance(|| "end_pc", END_PC_IDX)
    }

    pub fn query_end_cycle(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance(|| "end_cycle", END_CYCLE_IDX)
    }

    pub fn query_public_io(&mut self) -> Result<Instance, ZKVMError> {
        self.cs.query_instance(|| "public_io", PUBLIC_IO_IDX)
    }

    pub fn lk_record<NR, N>(
        &mut self,
        name_fn: N,
        rom_type: ROMType,
        items: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.lk_record(name_fn, rom_type, items)
    }

    pub fn lk_table_record<NR, N>(
        &mut self,
        name_fn: N,
        table_spec: SetTableSpec,
        rom_type: ROMType,
        record: Vec<Expression<E>>,
        multiplicity: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .lk_table_record(name_fn, table_spec, rom_type, record, multiplicity)
    }

    pub fn r_table_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        table_spec: SetTableSpec,
        record: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .r_table_record(name_fn, ram_type, table_spec, record)
    }

    pub fn w_table_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        table_spec: SetTableSpec,
        record: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .w_table_record(name_fn, ram_type, table_spec, record)
    }

    /// Fetch an instruction at a given PC from the Program table.
    pub fn lk_fetch(&mut self, record: &InsnRecord<Expression<E>>) -> Result<(), ZKVMError> {
        self.lk_record(|| "fetch", ROMType::Instruction, record.as_slice().to_vec())
    }

    pub fn read_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.read_record(name_fn, ram_type, record)
    }

    pub fn write_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.write_record(name_fn, ram_type, record)
    }

    pub fn rlc_chip_record(&self, records: Vec<Expression<E>>) -> Expression<E> {
        self.cs.rlc_chip_record(records)
    }

    pub fn create_u8<NR, N>(&mut self, name_fn: N) -> Result<WitIn, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR + Clone,
    {
        let byte = self.cs.create_witin(name_fn.clone());
        self.assert_ux::<_, _, 8>(name_fn, byte.expr())?;

        Ok(byte)
    }

    pub fn create_u16<NR, N>(&mut self, name_fn: N) -> Result<WitIn, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR + Clone,
    {
        let limb = self.cs.create_witin(name_fn.clone());
        self.assert_ux::<_, _, 16>(name_fn, limb.expr())?;

        Ok(limb)
    }

    /// Create a new WitIn constrained to be equal to input expression.
    pub fn flatten_expr<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<WitIn, ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR + Clone,
    {
        let wit = self.cs.create_witin(name_fn.clone());
        self.require_equal(name_fn, wit.expr(), expr)?;

        Ok(wit)
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
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "require_equal",
            |cb| {
                cb.cs
                    .require_zero(name_fn, a.to_monomial_form() - b.to_monomial_form())
            },
        )
    }

    pub fn require_one<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(|| "require_one", |cb| cb.cs.require_zero(name_fn, 1 - expr))
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

    pub fn select(
        &mut self,
        cond: &Expression<E>,
        when_true: &Expression<E>,
        when_false: &Expression<E>,
    ) -> Expression<E> {
        cond * when_true + (1 - cond) * when_false
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
            14 => self.assert_u14(name_fn, expr),
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
            |cb| cb.lk_record(name_fn, ROMType::U5, vec![expr]),
        )
    }

    fn assert_u14<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(name_fn, ROMType::U14, vec![expr])?;
        Ok(())
    }

    fn assert_u16<NR, N>(&mut self, name_fn: N, expr: Expression<E>) -> Result<(), ZKVMError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(name_fn, ROMType::U16, vec![expr])?;
        Ok(())
    }

    /// create namespace to prefix all constraints define under the scope
    pub fn namespace<NR: Into<String>, N: FnOnce() -> NR, T>(
        &mut self,
        name_fn: N,
        cb: impl FnOnce(&mut CircuitBuilder<E>) -> Result<T, ZKVMError>,
    ) -> Result<T, ZKVMError> {
        self.cs.namespace(name_fn, |cs| {
            let mut inner_circuit_builder =
                CircuitBuilder::new_with_params(cs, self.params.clone());
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
        self.lk_record(name_fn, ROMType::U8, vec![expr])?;
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
            |cb| cb.cs.require_zero(name_fn, &expr * (1 - &expr)),
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
        self.lk_record(|| format!("lookup_{:?}", rom_type), rom_type, vec![a, b, c])
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
        let is_eq = self.create_witin(|| "is_eq");
        let diff_inverse = self.create_witin(|| "diff_inverse");

        self.require_zero(|| "is equal", is_eq.expr() * &lhs - is_eq.expr() * &rhs)?;
        self.require_zero(
            || "is equal",
            1 - is_eq.expr() - diff_inverse.expr() * lhs + diff_inverse.expr() * rhs,
        )?;

        Ok((is_eq, diff_inverse))
    }
}
