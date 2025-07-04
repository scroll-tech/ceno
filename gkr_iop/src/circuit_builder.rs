use itertools::{Itertools, chain};
use multilinear_extensions::{
    Expression, Fixed, Instance, StructuralWitIn, ToExpr, WitIn, WitnessId, rlc_chip_record,
};
use serde::de::DeserializeOwned;
use std::{collections::HashMap, iter::once, marker::PhantomData};

use ff_ext::ExtensionField;

use crate::{RAMType, error::CircuitBuilderError, tables::LookupTable};
use multilinear_extensions::monomial::Term;
use p3::field::FieldAlgebra;
pub mod ram;

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

    pub r_expressions: Vec<Expression<E>>,
    pub r_expressions_namespace_map: Vec<String>,
    // for each read expression we store its ram type and original value before doing RLC
    // the original value will be used for debugging
    pub r_ram_types: Vec<(RAMType, Vec<Expression<E>>)>,

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

    /// lookup expression
    pub lk_expressions: Vec<Expression<E>>,
    pub lk_table_expressions: Vec<LogupTableExpression<E>>,
    pub lk_expressions_namespace_map: Vec<String>,
    pub lk_expressions_items_map: Vec<(LookupTable, Vec<Expression<E>>)>,

    /// main constraints zero expression
    pub assert_zero_expressions: Vec<Expression<E>>,
    pub assert_zero_expressions_namespace_map: Vec<String>,

    /// main constraints zero expression for expression degree > 1, which require sumcheck to prove
    pub assert_zero_sumcheck_expressions: Vec<Expression<E>>,
    pub assert_zero_sumcheck_expressions_namespace_map: Vec<String>,

    /// max zero sumcheck degree
    pub max_non_lc_degree: usize,

    // alpha, beta challenge for chip record
    pub chip_record_alpha: Expression<E>,
    pub chip_record_beta: Expression<E>,

    pub debug_map: HashMap<usize, Vec<Expression<E>>>,

    // this main expr will be finalized when constrian system finish
    pub backend_expr_monomial_form: Vec<Term<Expression<E>, Expression<E>>>,
    // this will be finalized when constriansystem finish
    // represent all the alloc of witin: fixed, witin, structural_wit, ...
    pub num_backend_witin: u16,
    pub num_layer_challenges: u16,

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
            r_expressions: vec![],
            r_expressions_namespace_map: vec![],
            r_ram_types: vec![],
            w_expressions: vec![],
            w_expressions_namespace_map: vec![],
            w_ram_types: vec![],
            r_table_expressions: vec![],
            r_table_expressions_namespace_map: vec![],
            w_table_expressions: vec![],
            w_table_expressions_namespace_map: vec![],
            lk_expressions: vec![],
            lk_table_expressions: vec![],
            lk_expressions_namespace_map: vec![],
            lk_expressions_items_map: vec![],
            assert_zero_expressions: vec![],
            assert_zero_expressions_namespace_map: vec![],
            assert_zero_sumcheck_expressions: vec![],
            assert_zero_sumcheck_expressions_namespace_map: vec![],
            max_non_lc_degree: 0,
            chip_record_alpha: Expression::Challenge(0, 1, E::ONE, E::ZERO),
            chip_record_beta: Expression::Challenge(1, 1, E::ONE, E::ZERO),

            backend_expr_monomial_form: vec![],
            num_backend_witin: 0,
            num_layer_challenges: 0,

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
        max_len: usize,
        offset: u32,
        multi_factor: usize,
        descending: bool,
    ) -> StructuralWitIn {
        let wit_in = StructuralWitIn {
            id: self.num_structural_witin,
            max_len,
            offset,
            multi_factor,
            descending,
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
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc lk_record degree ({})",
            name_fn().into()
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
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc read_record degree ({})",
            name_fn().into()
        );
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
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc write_record degree ({})",
            name_fn().into()
        );
        self.w_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.w_expressions_namespace_map.push(path);
        self.w_ram_types.push((ram_type, record));
        Ok(())
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

    pub fn finalize_backend_monomial_expression(&mut self) {
        let exprs =
            self.r_table_expressions
                .iter()
                .map(|r| r.expr.clone())
                .chain(
                    // padding with 1
                    self.r_expressions
                        .iter()
                        .map(|expr| expr - E::BaseField::ONE.expr()),
                )
                .chain(self.w_table_expressions.iter().map(|w| &w.expr).cloned())
                .chain(
                    // padding with 1
                    self.w_expressions
                        .iter()
                        .map(|expr| expr - E::BaseField::ONE.expr()),
                )
                .chain(
                    self.lk_table_expressions
                        .iter()
                        .map(|lk| &lk.multiplicity)
                        .cloned(),
                )
                .chain(
                    self.lk_table_expressions
                        .iter()
                        .map(|lk| &lk.values)
                        .cloned(),
                )
                .chain(
                    // padding with alpha
                    self.lk_expressions
                        .iter()
                        .map(|expr| expr.clone() - Expression::Challenge(0, 1, E::ONE, E::ZERO)),
                )
                .chain(self.assert_zero_sumcheck_expressions.clone())
                .chain(self.assert_zero_expressions.clone())
                .zip(
                    (2u16..) // challenge id start from 2 because 0, 1 is alpha, beta respectively
                        .map(|challenge_id| {
                            Expression::Challenge(challenge_id, 1, E::ONE, E::ZERO)
                        }),
                )
                .map(|(expr, r)| expr * r)
                .collect_vec();

        let num_layer_challenges = exprs.len() as u16;
        let main_sumcheck_expr = exprs.into_iter().sum::<Expression<E>>();

        let witid_offset = 0 as WitnessId;
        let structural_witin_offset = witid_offset + self.num_witin;
        let fixed_offset = structural_witin_offset + self.num_structural_witin;

        let monomial_terms_expr = main_sumcheck_expr.get_monomial_terms();
        self.backend_expr_monomial_form = monomial_terms_expr
            .into_iter()
            .map(
                |Term {
                     scalar,
                     mut product,
                 }| {
                    product.iter_mut().for_each(|t| match t {
                        Expression::WitIn(_) => (),
                        Expression::StructuralWitIn(structural_wit_id, _, _, _) => {
                            *t = Expression::WitIn(structural_witin_offset + *structural_wit_id);
                        }
                        Expression::Fixed(Fixed(fixed_id)) => {
                            *t = Expression::WitIn(fixed_offset + (*fixed_id as u16));
                        }
                        e => panic!("unknown monimial terms {:?}", e),
                    });
                    Term { scalar, product }
                },
            )
            .collect_vec();
        self.num_backend_witin = fixed_offset;
        self.num_layer_challenges = num_layer_challenges;
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
        max_len: usize,
        offset: u32,
        multi_factor: usize,
        descending: bool,
    ) -> StructuralWitIn
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.cs
            .create_structural_witin(name_fn, max_len, offset, multi_factor, descending)
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
        match C {
            16 => self.assert_u16(name_fn, expr),
            14 => self.assert_u14(name_fn, expr),
            8 => self.assert_byte(name_fn, expr),
            5 => self.assert_u5(name_fn, expr),
            c => panic!("Unsupported bit range {c}"),
        }
    }

    fn assert_u5<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace(
            || "assert_u5",
            |cb| cb.lk_record(name_fn, LookupTable::U5, vec![expr]),
        )
    }

    fn assert_u14<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(name_fn, LookupTable::U14, vec![expr])?;
        Ok(())
    }

    fn assert_u16<NR, N>(
        &mut self,
        name_fn: N,
        expr: Expression<E>,
    ) -> Result<(), CircuitBuilderError>
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.lk_record(name_fn, LookupTable::U16, vec![expr])?;
        Ok(())
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
        self.lk_record(name_fn, LookupTable::U8, vec![expr])?;
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

    pub fn finalize(&mut self) {
        self.cs.finalize_backend_monomial_expression();
    }
}

pub enum DebugIndex {
    RdWrite = 0,
}

impl<E: ExtensionField> CircuitBuilder<'_, E> {
    pub fn register_debug_expr<T: Into<usize>>(&mut self, debug_index: T, expr: Expression<E>) {
        self.cs.register_debug_expr(debug_index, expr)
    }

    pub fn get_debug_expr<T: Into<usize>>(&mut self, debug_index: T) -> &[Expression<E>] {
        self.cs.get_debug_expr(debug_index)
    }
}
