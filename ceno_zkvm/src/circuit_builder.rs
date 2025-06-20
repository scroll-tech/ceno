use itertools::{Itertools, chain};
use multilinear_extensions::{
    Expression, Fixed, Instance, StructuralWitIn, ToExpr, WitIn, WitnessId,
};
use serde::de::DeserializeOwned;
use std::{collections::HashMap, iter::once, marker::PhantomData};

use ff_ext::ExtensionField;

use crate::{
    ROMType,
    chip_handler::utils::rlc_chip_record,
    error::ZKVMError,
    structs::{ProgramParams, ProvingKey, RAMType, VerifyingKey},
};
use multilinear_extensions::monomial::Term;
use p3::field::FieldAlgebra;

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
    pub(crate) ns: NameSpace,

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
    pub lk_expressions_items_map: Vec<(ROMType, Vec<Expression<E>>)>,

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

    pub fn key_gen(self) -> ProvingKey<E> {
        ProvingKey {
            vk: VerifyingKey { cs: self },
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

    pub fn create_fixed<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        n: N,
    ) -> Result<Fixed, ZKVMError> {
        let f = Fixed(self.num_fixed);
        self.num_fixed += 1;

        let path = self.ns.compute_path(n().into());
        self.fixed_namespace_map.push(path);

        Ok(f)
    }

    pub fn query_instance<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        n: N,
        idx: usize,
    ) -> Result<Instance, ZKVMError> {
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
        rom_type: ROMType,
        record: Vec<Expression<E>>,
    ) -> Result<(), ZKVMError> {
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
        rom_type: ROMType,
        record: Vec<Expression<E>>,
        multiplicity: Expression<E>,
    ) -> Result<(), ZKVMError>
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
    ) -> Result<(), ZKVMError>
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
    ) -> Result<(), ZKVMError>
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
    ) -> Result<(), ZKVMError> {
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
    ) -> Result<(), ZKVMError> {
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
    ) -> Result<(), ZKVMError> {
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

#[cfg(test)]
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
    pub(crate) cs: &'a mut ConstraintSystem<E>,
    pub params: ProgramParams,
}
