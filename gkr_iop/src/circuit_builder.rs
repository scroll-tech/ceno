use itertools::{Itertools, chain};
use multilinear_extensions::{
    Expression, Fixed, Instance, StructuralWitIn, StructuralWitInType, ToExpr, WitIn, WitnessId,
    rlc_chip_record,
};
use serde::de::DeserializeOwned;
use std::{collections::HashMap, iter::once, marker::PhantomData};

use ff_ext::ExtensionField;

use crate::{
    RAMType, error::CircuitBuilderError, gkr::layer::ROTATION_OPENING_COUNT,
    selector::SelectorType, tables::LookupTable,
};
use p3::field::FieldAlgebra;

pub mod ram;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct RotationParams<E: ExtensionField> {
    pub rotation_eqs: Option<[Expression<E>; ROTATION_OPENING_COUNT]>,
    pub rotation_cyclic_group_log2: usize,
    pub rotation_cyclic_subgroup_size: usize,
}

/// namespace used for annotation, preserve meta info during circuit construction
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct NameSpace {
    namespace: Vec<String>,
}

impl NameSpace {
    pub fn new<NR: Into<String>, N: FnOnce() -> NR>(name_fn: N) -> Self {
        NameSpace {
            namespace: vec![name_fn().into()],
        }
    }
    pub fn namespace<NR: Into<String>, N: FnOnce() -> NR>(&self, name_fn: N) -> Self {
        let mut new = self.clone();
        new.push_namespace(name_fn().into());
        new
    }

    pub(crate) fn push_namespace(&mut self, namespace: String) {
        self.namespace.push(namespace)
    }

    pub(crate) fn pop_namespace(&mut self) {
        let _ = self.namespace.pop();
    }

    pub(crate) fn compute_path(&self, this: String) -> String {
        if this.chars().contains(&'/') {
            panic!("'/' is not allowed in names");
        }
        chain!(self.get_namespaces(), once(&this)).join("/")
    }

    pub fn get_namespaces(&self) -> &[String] {
        &self.namespace
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct LogupTableExpression<E: ExtensionField> {
    pub multiplicity: Expression<E>,
    pub values: Expression<E>,
    pub table_spec: SetTableSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SetTableSpec {
    pub len: Option<usize>,
    pub structural_witins: Vec<StructuralWitIn>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct SetTableExpression<E: ExtensionField> {
    /// table expression
    pub expr: Expression<E>,

    // TODO make decision to have enum/struct
    // for which option is more friendly to be processed by ConstrainSystem + recursive verifier
    pub table_spec: SetTableSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct ConstraintSystem<E: ExtensionField> {
    pub ns: NameSpace,

    pub num_witin: WitnessId,
    pub witin_namespace_map: Vec<String>,

    pub num_structural_witin: WitnessId,
    pub structural_witin_namespace_map: Vec<String>,

    pub num_fixed: usize,
    pub fixed_namespace_map: Vec<String>,

    pub instance_name_map: HashMap<Instance, String>,

    pub ec_point_exprs: Vec<Expression<E>>,
    pub ec_slope_exprs: Vec<Expression<E>>,
    pub ec_final_sum: Vec<Expression<E>>,

    pub r_selector: Option<SelectorType<E>>,
    pub r_expressions: Vec<Expression<E>>,
    pub r_expressions_namespace_map: Vec<String>,
    // for each read expression we store its ram type and original value before doing RLC
    // the original value will be used for debugging
    pub r_ram_types: Vec<(RAMType, Vec<Expression<E>>)>,

    pub w_selector: Option<SelectorType<E>>,
    pub w_expressions: Vec<Expression<E>>,
    pub w_expressions_namespace_map: Vec<String>,
    // for each write expression we store its ram type and original value before doing RLC
    // the original value will be used for debugging
    pub w_ram_types: Vec<(RAMType, Vec<Expression<E>>)>,

    /// init/final ram expression
    pub r_table_expressions: Vec<SetTableExpression<E>>,
    pub r_table_expressions_namespace_map: Vec<String>,
    pub w_table_expressions: Vec<SetTableExpression<E>>,
    pub w_table_expressions_namespace_map: Vec<String>,

    pub lk_selector: Option<SelectorType<E>>,
    /// lookup expression
    pub lk_expressions: Vec<Expression<E>>,
    pub lk_table_expressions: Vec<LogupTableExpression<E>>,
    pub lk_expressions_namespace_map: Vec<String>,
    pub lk_expressions_items_map: Vec<(LookupTable, Vec<Expression<E>>)>,

    pub zero_selector: Option<SelectorType<E>>,
    /// main constraints zero expression
    pub assert_zero_expressions: Vec<Expression<E>>,
    pub assert_zero_expressions_namespace_map: Vec<String>,

    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<Expression<E>>,
    pub assert_zero_sumcheck_expressions_namespace_map: Vec<String>,

    /// max zero sumcheck degree
    pub max_non_lc_degree: usize,

    /// rotation argumment
    pub rotations: Vec<(Expression<E>, Expression<E>)>,
    pub rotation_params: Option<RotationParams<E>>,

    // alpha, beta challenge for chip record
    pub chip_record_alpha: Expression<E>,
    pub chip_record_beta: Expression<E>,

    pub debug_map: HashMap<usize, Vec<Expression<E>>>,

    pub(crate) phantom: PhantomData<E>,
}

impl<E: ExtensionField> ConstraintSystem<E> {
    pub fn new<NR: Into<String>, N: FnOnce() -> NR>(root_name_fn: N) -> Self {
        Self {
            num_witin: 0,
            // platform,
            witin_namespace_map: vec![],
            num_structural_witin: 0,
            structural_witin_namespace_map: vec![],
            num_fixed: 0,
            fixed_namespace_map: vec![],
            ns: NameSpace::new(root_name_fn),
            instance_name_map: HashMap::new(),
            ec_final_sum: vec![],
            ec_slope_exprs: vec![],
            ec_point_exprs: vec![],
            r_selector: None,
            r_expressions: vec![],
            r_expressions_namespace_map: vec![],
            r_ram_types: vec![],
            w_selector: None,
            w_expressions: vec![],
            w_expressions_namespace_map: vec![],
            w_ram_types: vec![],
            r_table_expressions: vec![],
            r_table_expressions_namespace_map: vec![],
            w_table_expressions: vec![],
            w_table_expressions_namespace_map: vec![],
            lk_selector: None,
            lk_expressions: vec![],
            lk_table_expressions: vec![],
            lk_expressions_namespace_map: vec![],
            lk_expressions_items_map: vec![],
            zero_selector: None,
            assert_zero_expressions: vec![],
            assert_zero_expressions_namespace_map: vec![],
            assert_zero_sumcheck_expressions: vec![],
            assert_zero_sumcheck_expressions_namespace_map: vec![],
            max_non_lc_degree: 0,
            rotations: vec![],
            rotation_params: None,
            chip_record_alpha: Expression::Challenge(0, 1, E::ONE, E::ZERO),
            chip_record_beta: Expression::Challenge(1, 1, E::ONE, E::ZERO),

            debug_map: HashMap::new(),

            phantom: std::marker::PhantomData,
        }
    }

    pub fn create_witin<NR: Into<String>, N: FnOnce() -> NR>(&mut self, n: N) -> WitIn {
        let wit_in = WitIn { id: self.num_witin };
        self.num_witin = self.num_witin.strict_add(1);

        let path = self.ns.compute_path(n().into());
        self.witin_namespace_map.push(path);

        wit_in
    }

    pub fn create_structural_witin<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        n: N,
        witin_type: StructuralWitInType,
    ) -> StructuralWitIn {
        let wit_in = StructuralWitIn {
            id: self.num_structural_witin,
            witin_type,
        };
        self.num_structural_witin = self.num_structural_witin.strict_add(1);

        let path = self.ns.compute_path(n().into());
        self.structural_witin_namespace_map.push(path);

        wit_in
    }

    pub fn create_fixed<NR: Into<String>, N: FnOnce() -> NR>(&mut self, n: N) -> Fixed {
        let f = Fixed(self.num_fixed);
        self.num_fixed += 1;

        let path = self.ns.compute_path(n().into());
        self.fixed_namespace_map.push(path);

        f
    }

    pub fn query_instance<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        n: N,
        idx: usize,
    ) -> Result<Instance, CircuitBuilderError> {
        let i = Instance(idx);

        let name = n().into();
        self.instance_name_map.insert(i, name);

        Ok(i)
    }

    pub fn rlc_chip_record(&self, items: Vec<Expression<E>>) -> Expression<E> {
        rlc_chip_record(
            items,
            self.chip_record_alpha.clone(),
            self.chip_record_beta.clone(),
        )
    }

    pub fn lk_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        rom_type: LookupTable,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError> {
        let rlc_record = self.rlc_chip_record(
            std::iter::once(E::BaseField::from_canonical_u64(rom_type as u64).expr())
                .chain(record.clone())
                .collect(),
        );
        self.lk_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.lk_expressions_namespace_map.push(path);
        // Since lk_expression is RLC(record) and when we're debugging
        // it's helpful to recover the value of record itself.
        self.lk_expressions_items_map.push((rom_type, record));
        Ok(())
    }

    pub fn lk_table_record<NR, N>(
        &mut self,
        name_fn: N,
        table_spec: SetTableSpec,
        rom_type: LookupTable,
        record: Vec<Expression<E>>,
        multiplicity: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let rlc_record = self.rlc_chip_record(
            vec![(rom_type as usize).into()]
                .into_iter()
                .chain(record.clone())
                .collect_vec(),
        );
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc lk_table_record degree ({})",
            name_fn().into()
        );
        self.lk_table_expressions.push(LogupTableExpression {
            values: rlc_record,
            multiplicity,
            table_spec,
        });
        let path = self.ns.compute_path(name_fn().into());
        self.lk_expressions_namespace_map.push(path);
        // Since lk_expression is RLC(record) and when we're debugging
        // it's helpful to recover the value of record itself.
        self.lk_expressions_items_map.push((rom_type, record));

        Ok(())
    }

    pub fn r_table_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        table_spec: SetTableSpec,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let rlc_record = self.rlc_chip_record(record.clone());
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.r_table_expressions.push(SetTableExpression {
            expr: rlc_record,
            table_spec,
        });
        let path = self.ns.compute_path(name_fn().into());
        self.r_table_expressions_namespace_map.push(path);
        self.r_ram_types.push((ram_type, record));

        Ok(())
    }

    pub fn w_table_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        table_spec: SetTableSpec,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let rlc_record = self.rlc_chip_record(record.clone());
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.w_table_expressions.push(SetTableExpression {
            expr: rlc_record,
            table_spec,
        });
        let path = self.ns.compute_path(name_fn().into());
        self.w_table_expressions_namespace_map.push(path);
        self.w_ram_types.push((ram_type, record));

        Ok(())
    }

    pub fn read_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError> {
        let rlc_record = self.rlc_chip_record(record.clone());
        self.r_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.r_expressions_namespace_map.push(path);
        // Since r_expression is RLC(record) and when we're debugging
        // it's helpful to recover the value of record itself.
        self.r_ram_types.push((ram_type, record));
        Ok(())
    }

    pub fn write_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError> {
        let rlc_record = self.rlc_chip_record(record.clone());
        self.w_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.w_expressions_namespace_map.push(path);
        self.w_ram_types.push((ram_type, record));
        Ok(())
    }

    pub fn ec_sum(
        &mut self,
        xs: Vec<Expression<E>>,
        ys: Vec<Expression<E>>,
        slopes: Vec<Expression<E>>,
        final_sum: Vec<Expression<E>>,
    ) {
        assert_eq!(xs.len(), 7);
        assert_eq!(ys.len(), 7);
        assert_eq!(slopes.len(), 7);
        assert_eq!(final_sum.len(), 7 * 2);

        assert_eq!(self.ec_point_exprs.len(), 0);
        self.ec_point_exprs.extend(xs);
        self.ec_point_exprs.extend(ys);

        self.ec_slope_exprs = slopes;
        self.ec_final_sum = final_sum;
    }

    pub fn require_zero<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        assert_zero_expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        assert!(
            assert_zero_expr.degree() > 0,
            "constant expression assert to zero ?"
        );
        if assert_zero_expr.degree() == 1 {
            self.assert_zero_expressions.push(assert_zero_expr);
            let path = self.ns.compute_path(name_fn().into());
            self.assert_zero_expressions_namespace_map.push(path);
        } else {
            let assert_zero_expr = if assert_zero_expr.is_monomial_form() {
                assert_zero_expr
            } else {
                let e = assert_zero_expr.get_monomial_form();
                assert!(e.is_monomial_form(), "failed to put into monomial form");
                e
            };
            self.max_non_lc_degree = self.max_non_lc_degree.max(assert_zero_expr.degree());
            self.assert_zero_sumcheck_expressions.push(assert_zero_expr);
            let path = self.ns.compute_path(name_fn().into());
            self.assert_zero_sumcheck_expressions_namespace_map
                .push(path);
        }
        Ok(())
    }

    pub fn namespace<NR: Into<String>, N: FnOnce() -> NR, T>(
        &mut self,
        name_fn: N,
        cb: impl FnOnce(&mut ConstraintSystem<E>) -> T,
    ) -> T {
        self.ns.push_namespace(name_fn().into());
        let t = cb(self);
        self.ns.pop_namespace();
        t
    }
}

impl<E: ExtensionField> ConstraintSystem<E> {
    pub fn register_debug_expr<T: Into<usize>>(&mut self, debug_index: T, expr: Expression<E>) {
        let key = debug_index.into();
        self.debug_map.entry(key).or_default().push(expr);
    }

    pub fn get_debug_expr<T: Into<usize>>(&mut self, debug_index: T) -> &[Expression<E>] {
        let key = debug_index.into();
        match self.debug_map.get(&key) {
            Some(v) => v,
            _ => panic!("non-existent entry {}", key),
        }
    }
}

#[derive(Debug)]
pub struct CircuitBuilder<'a, E: ExtensionField> {
    pub cs: &'a mut ConstraintSystem<E>,
}

impl<'a, E: ExtensionField> CircuitBuilder<'a, E> {
    pub fn new(cs: &'a mut ConstraintSystem<E>) -> Self {
        Self { cs }
    }

    pub fn create_witin<NR, N>(&mut self, name_fn: N) -> WitIn
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_witin(name_fn)
    }

    /// create namespace to prefix all constraints define under the scope
    pub fn namespace<NR: Into<String>, N: FnOnce() -> NR, T>(
        &mut self,
        name_fn: N,
        cb: impl for<'b> FnOnce(&mut CircuitBuilder<'b, E>) -> Result<T, CircuitBuilderError>,
    ) -> Result<T, CircuitBuilderError> {
        self.cs.namespace(name_fn, |cs| {
            let mut inner_circuit_builder = CircuitBuilder::<'_, E>::new(cs);
            cb(&mut inner_circuit_builder)
        })
    }

    pub fn create_witin_from_exprs<NR, N>(
        &mut self,
        name_fn: N,
        input: Expression<E>,
        debug: bool,
    ) -> Result<WitIn, CircuitBuilderError>
    where
        NR: Into<String> + Clone,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "witin_from_expr",
            |cb| {
                let name = name_fn().into();
                let wit = cb.create_witin(|| name.clone());
                if !debug {
                    cb.require_zero(|| name.clone(), wit.expr() - input)?;
                }
                Ok(wit)
            },
        )
    }

    pub fn create_structural_witin<NR, N>(
        &mut self,
        name_fn: N,
        witin_type: StructuralWitInType,
    ) -> StructuralWitIn
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_structural_witin(name_fn, witin_type)
    }

    pub fn create_fixed<NR, N>(&mut self, name_fn: N) -> Fixed
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.create_fixed(name_fn)
    }

    pub fn lk_record<NR, N>(
        &mut self,
        name_fn: N,
        rom_type: LookupTable,
        items: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError>
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
        rom_type: LookupTable,
        record: Vec<Expression<E>>,
        multiplicity: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .w_table_record(name_fn, ram_type, table_spec, record)
    }

    pub fn read_record<NR, N>(
        &mut self,
        name_fn: N,
        ram_type: RAMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs.write_record(name_fn, ram_type, record)
    }

    pub fn rlc_chip_record(&self, records: Vec<Expression<E>>) -> Expression<E> {
        self.cs.rlc_chip_record(records)
    }

    pub fn ec_sum(
        &mut self,
        xs: Vec<Expression<E>>,
        ys: Vec<Expression<E>>,
        slope: Vec<Expression<E>>,
        final_sum: Vec<Expression<E>>,
    ) {
        self.cs.ec_sum(xs, ys, slope, final_sum);
    }

    pub fn create_bit<NR, N>(&mut self, name_fn: N) -> Result<WitIn, CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR + Clone,
    {
        let bit = self.cs.create_witin(name_fn.clone());
        self.assert_bit(name_fn, bit.expr())?;

        Ok(bit)
    }

    pub fn create_u8<NR, N>(&mut self, name_fn: N) -> Result<WitIn, CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR + Clone,
    {
        let byte = self.cs.create_witin(name_fn.clone());
        self.assert_ux::<_, _, 8>(name_fn, byte.expr())?;

        Ok(byte)
    }

    pub fn create_u16<NR, N>(&mut self, name_fn: N) -> Result<WitIn, CircuitBuilderError>
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
    ) -> Result<WitIn, CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "require_equal",
            |cb| {
                cb.cs
                    .require_zero(name_fn, a.get_monomial_form() - b.get_monomial_form())
            },
        )
    }

    pub fn require_one<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
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
    ) -> Result<(), CircuitBuilderError>
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

    pub fn condition_require_zero<NR, N>(
        &mut self,
        name_fn: N,
        cond: Expression<E>,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // cond * expr
        self.namespace(
            || "cond_require_zero",
            |cb| cb.cs.require_zero(name_fn, cond * expr.expr()),
        )
    }

    pub fn condition_require_one<NR, N>(
        &mut self,
        name_fn: N,
        cond: Expression<E>,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // cond * expr
        self.namespace(
            || "cond_require_one",
            |cb| cb.cs.require_zero(name_fn, cond * (expr.expr() - 1)),
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

    pub fn assert_ux<NR, N, const C: usize>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.assert_const_range(name_fn, expr, C)
    }

    pub fn assert_dynamic_range<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
        bits: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(name_fn, LookupTable::Dynamic, vec![expr, bits])?;
        Ok(())
    }

    pub fn assert_const_range<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
        max_bits: usize,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        if max_bits == 1 {
            self.assert_bit(name_fn, expr)
        } else {
            self.namespace(
                || "assert_const_range",
                |cb| {
                    cb.lk_record(
                        name_fn,
                        LookupTable::Dynamic,
                        vec![expr, E::BaseField::from_canonical_usize(max_bits).expr()],
                    )
                },
            )
        }
    }

    pub fn assert_byte<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "assert_byte",
            |cb| {
                cb.lk_record(
                    name_fn,
                    LookupTable::Dynamic,
                    vec![expr, E::BaseField::from_canonical_usize(8).expr()],
                )
            },
        )
    }

    pub fn assert_double_u8<NR, N>(
        &mut self,
        name_fn: N,
        a_expr: Expression<E>,
        b_expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "assert_double_u8",
            |cb| cb.lk_record(name_fn, LookupTable::DoubleU8, vec![a_expr, b_expr]),
        )
    }

    pub fn assert_bytes<NR, N>(
        &mut self,
        name_fn: N,
        exprs: &[impl ToExpr<E, Output = Expression<E>> + Clone],
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name = name_fn().into();
        for (i, pair) in exprs.chunks(2).enumerate() {
            match pair {
                [a, b] => {
                    self.assert_double_u8(|| format!("{}_{i:?}", name), a.expr(), b.expr())?
                }
                [a] => {
                    self.assert_double_u8(|| format!("{}_{i:?}", name), a.expr(), Expression::ZERO)?
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn assert_bit<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
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
        rom_type: LookupTable,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.lk_record(|| format!("lookup_{:?}", rom_type), rom_type, vec![a, b, c])
    }

    /// Assert `a & b = c` and that `a, b, c` are all bytes.
    pub fn lookup_and_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.logic_u8(LookupTable::And, a, b, c)
    }

    /// Assert `a | b = c` and that `a, b, c` are all bytes.
    pub fn lookup_or_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.logic_u8(LookupTable::Or, a, b, c)
    }

    /// Assert `a ^ b = c` and that `a, b, c` are all bytes.
    pub fn lookup_xor_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.logic_u8(LookupTable::Xor, a, b, c)
    }

    /// Assert that `(a < b) == c as bool`, that `a, b` are unsigned bytes, and that `c` is 0 or 1.
    pub fn lookup_ltu_byte(
        &mut self,
        a: Expression<E>,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.logic_u8(LookupTable::Ltu, a, b, c)
    }

    // Assert that `2^b = c` and that `b` is a 5-bit unsigned integer.
    pub fn lookup_pow2(
        &mut self,
        b: Expression<E>,
        c: Expression<E>,
    ) -> Result<(), CircuitBuilderError> {
        self.logic_u8(LookupTable::Pow, 2.into(), b, c)
    }

    pub fn is_equal(
        &mut self,
        lhs: Expression<E>,
        rhs: Expression<E>,
    ) -> Result<(WitIn, WitIn), CircuitBuilderError> {
        let is_eq = self.create_witin(|| "is_eq");
        let diff_inverse = self.create_witin(|| "diff_inverse");

        self.require_zero(|| "is equal", is_eq.expr() * &lhs - is_eq.expr() * &rhs)?;
        self.require_zero(
            || "is equal",
            1 - is_eq.expr() - diff_inverse.expr() * lhs + diff_inverse.expr() * rhs,
        )?;

        Ok((is_eq, diff_inverse))
    }

    // Constrains that lhs and rhs encode the same value of SIZE bits
    // WARNING: Assumes that forall i, (lhs[i].1 < (2 ^ lhs[i].0))
    // This needs to be constrained separately
    fn require_reps_equal<const SIZE: usize, NR, N>(
        &mut self,
        name_fn: N,
        lhs: &[(usize, Expression<E>)],
        rhs: &[(usize, Expression<E>)],
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.require_zero(
            name_fn,
            expansion_expr::<E, SIZE>(lhs) - expansion_expr::<E, SIZE>(rhs),
        )
    }

    /// Checks that `rot8` is equal to `input8` left-rotated by `delta`.
    /// `rot8` and `input8` each consist of 8 chunks of 8-bits.
    ///
    /// `split_rep` is a chunk representation of the input which
    /// allows to reduce the required rotation to an array rotation. It may use
    /// non-uniform chunks.
    ///
    /// For example, when `delta = 2`, the 64 bits are split into chunks of
    /// sizes `[16a, 14b, 2c, 16d, 14e, 2f]` (here the first chunks contains the
    /// least significant bits so a left rotation will become a right rotation
    /// of the array). To perform the required rotation, we can
    /// simply rotate the array: [2f, 16a, 14b, 2c, 16d, 14e].
    ///
    /// In the first step, we check that `rot8` and `split_rep` represent the
    /// same 64 bits. In the second step we check that `rot8` and the appropiate
    /// array rotation of `split_rep` represent the same 64 bits.
    ///
    /// This type of representation-equality check is done by packing chunks
    /// into sizes of exactly 32 (so for `delta = 2` we compare [16a, 14b,
    /// 2c] to the first 4 elements of `rot8`). In addition, we do range
    /// checks on `split_rep` which check that the felts meet the required
    /// sizes.
    ///
    /// This algorithm imposes the following general requirements for
    /// `split_rep`:
    /// - There exists a suffix of `split_rep` which sums to exactly `delta`.
    ///   This suffix can contain several elements.
    /// - Chunk sizes are at most 16 (so they can be range-checked) or they are
    ///   exactly equal to 32.
    /// - There exists a prefix of chunks which sums exactly to 32. This must
    ///   hold for the rotated array as well.
    /// - The number of chunks should be as small as possible.
    ///
    /// Consult the method `rotation_split` to see how splits are computed for a
    /// given `delta
    ///
    /// Note that the function imposes range checks on chunk values, but it
    /// makes two exceptions:
    ///     1. It doesn't check the 8-bit reps (input and output). This is
    ///        because all 8-bit reps in the global circuit are implicitly
    ///        range-checked because they are lookup arguments.
    ///     2. It doesn't range-check 32-bit chunks. This is because a 32-bit
    ///        chunk value is checked to be equal to the composition of 4 8-bit
    ///        chunks. As mentioned in 1., these can be trusted to be range
    ///        checked, so the resulting 32-bit is correct by construction as
    ///        well.
    pub fn require_left_rotation64<NR, N>(
        &mut self,
        name: N,
        input8: &[Expression<E>],
        split_rep: &[(usize, Expression<E>)],
        rot8: &[Expression<E>],
        delta: usize,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: Fn() -> NR,
    {
        assert_eq!(input8.len(), 8);
        assert_eq!(rot8.len(), 8);

        // Assert that the given split witnesses are correct for this delta
        let (sizes, chunks_rotation) = rotation_split(delta);
        assert_eq!(sizes, split_rep.iter().map(|e| e.0).collect_vec());

        // Lookup ranges
        for (i, (size, elem)) in split_rep.iter().enumerate() {
            self.assert_const_range(|| format!("{}_{}", name().into(), i), elem.clone(), *size)?;
        }

        // constrain the fact that rep8 and repX.rotate_left(chunks_rotation) are
        // the same 64 bitstring
        let mut helper = |rep8: &[Expression<E>],
                          rep_x: &[(usize, Expression<E>)],
                          chunks_rotation: usize|
         -> Result<(), CircuitBuilderError> {
            // Do the same thing for the two 32-bit halves
            let mut rep_x = rep_x.to_owned();
            rep_x.rotate_right(chunks_rotation);

            // 64 bits represent in 4 limb, each with 16 bits
            let num_limbs = 4;
            let mut rep_x_iter = rep_x.iter().cloned();
            for limb_i in 0..num_limbs {
                let lhs = rep8[2 * limb_i..2 * (limb_i + 1)]
                    .iter()
                    .map(|wit| (8, wit.expr()))
                    .collect_vec();
                let rhs_limbs = take_til_threshold(&mut rep_x_iter, 16, &|limb| limb.0).unwrap();

                assert_eq!(rhs_limbs.iter().map(|e| e.0).sum::<usize>(), 16);

                self.require_reps_equal::<16, _, _>(
                    ||format!(
                        "rotation internal {}, round {limb_i}, rot: {chunks_rotation}, delta: {delta}, {:?}",
                        name().into(),
                        sizes
                    ),
                    &lhs,
                    &rhs_limbs,
                )?;
            }
            Ok(())
        };

        helper(input8, split_rep, 0)?;
        helper(rot8, split_rep, chunks_rotation)?;

        Ok(())
    }

    pub fn set_rotation_params(&mut self, params: RotationParams<E>) {
        assert!(self.cs.rotation_params.is_none());
        self.cs.rotation_params = Some(params);
    }

    pub fn rotate_and_assert_eq(&mut self, a: Expression<E>, b: Expression<E>) {
        self.cs.rotations.push((a, b));
    }
}

/// take items from an iterator until the accumulated "weight" (measured by `f`)
/// reaches exactly `threshold`.
///
/// - `iter`: a mutable iterator to consume items from
/// - `threshold`: the sum of weights at which to stop and return the group
/// - `f`: closure that extracts the "weight" (e.g., bit length) from each item
///
/// returns:
/// - `Some(Vec<T>)` containing the next group of items whose weights sum to `threshold`
/// - `None` if the iterator is exhausted and no items remain
///
/// panics if the sum of weights ever exceeds `threshold`.
pub fn take_til_threshold<I, T, F>(iter: &mut I, threshold: usize, f: &F) -> Option<Vec<T>>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> usize,
{
    let mut group = Vec::new();
    let mut sum = 0;

    for x in iter.by_ref() {
        sum += f(&x);
        group.push(x);

        if sum == threshold {
            return Some(group);
        } else if sum > threshold {
            panic!("sum exceeded threshold!");
        }
    }

    if group.is_empty() {
        None
    } else {
        Some(group) // leftover if input not perfectly divisible
    }
}

/// Compute an adequate split of 64-bits into chunks for performing a rotation
/// by `delta`. The first element of the return value is the vec of chunk sizes.
/// The second one is the length of its suffix that needs to be rotated
pub fn rotation_split(delta: usize) -> (Vec<usize>, usize) {
    if delta == 0 {
        return (vec![16, 16, 16, 16], 0);
    }

    let remainder = delta % 16;
    let split16 = std::iter::repeat_with(|| [16 - remainder, remainder])
        .flatten()
        .scan(0, |sum, x| {
            if *sum >= 64 {
                None
            } else {
                *sum += x;
                Some(x)
            }
        })
        .filter(|v| *v > 0)
        .collect_vec();

    let mut sum = 0;
    for (i, size) in split16.iter().rev().enumerate() {
        sum += size;
        if sum == delta {
            return (split16, i + 1);
        }
    }

    panic!("delta {:?} split16 {:?}", remainder, split16);
}

pub fn expansion_expr<E: ExtensionField, const SIZE: usize>(
    expansion: &[(usize, Expression<E>)],
) -> Expression<E> {
    let (total, ret) =
        expansion
            .iter()
            .rev()
            .fold((0, E::BaseField::ZERO.expr()), |acc, (sz, felt)| {
                (
                    acc.0 + sz,
                    acc.1 * E::BaseField::from_canonical_u64(1 << sz).expr() + felt.expr(),
                )
            });

    assert_eq!(total, SIZE);
    ret
}

pub enum DebugIndex {
    RdWrite = 0,
    MemWrite = 1,
}

impl<E: ExtensionField> CircuitBuilder<'_, E> {
    pub fn register_debug_expr<T: Into<usize>>(&mut self, debug_index: T, expr: Expression<E>) {
        self.cs.register_debug_expr(debug_index, expr)
    }

    pub fn get_debug_expr<T: Into<usize>>(&mut self, debug_index: T) -> &[Expression<E>] {
        self.cs.get_debug_expr(debug_index)
    }
}
