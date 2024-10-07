use itertools::Itertools;
use std::{collections::HashMap, marker::PhantomData};

use ff_ext::ExtensionField;
use mpcs::PolynomialCommitmentScheme;

use crate::{
    error::ZKVMError,
    expression::{Expression, Fixed, Instance, WitIn},
    structs::{ProvingKey, VerifyingKey, WitnessId},
    witness::RowMajorMatrix,
};

/// namespace used for annotation, preserve meta info during circuit construction
#[derive(Clone, Debug)]
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
        let ns = self.get_namespaces();
        if this.chars().any(|a| a == '/') {
            panic!("'/' is not allowed in names");
        }

        let mut name = String::new();

        let mut needs_separation = false;
        for ns in ns.iter().chain(Some(&this).into_iter()) {
            if needs_separation {
                name += "/";
            }

            name += ns;
            needs_separation = true;
        }

        name
    }

    pub fn get_namespaces(&self) -> &[String] {
        &self.namespace
    }
}

#[derive(Clone, Debug)]
pub struct LogupTableExpression<E: ExtensionField> {
    pub multiplicity: Expression<E>,
    pub values: Expression<E>,
}

#[derive(Clone, Debug)]
pub struct ConstraintSystem<E: ExtensionField> {
    pub(crate) ns: NameSpace,

    pub num_witin: WitnessId,
    pub witin_namespace_map: Vec<String>,

    pub num_fixed: usize,
    pub fixed_namespace_map: Vec<String>,

    pub instance_name_map: HashMap<Instance, String>,

    pub r_expressions: Vec<Expression<E>>,
    pub r_expressions_namespace_map: Vec<String>,

    pub w_expressions: Vec<Expression<E>>,
    pub w_expressions_namespace_map: Vec<String>,

    /// lookup expression
    pub lk_expressions: Vec<Expression<E>>,
    pub lk_expressions_namespace_map: Vec<String>,
    pub lk_table_expressions: Vec<LogupTableExpression<E>>,
    pub lk_table_expressions_namespace_map: Vec<String>,

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

    pub(crate) phantom: PhantomData<E>,
}

impl<E: ExtensionField> ConstraintSystem<E> {
    pub fn new<NR: Into<String>, N: FnOnce() -> NR>(root_name_fn: N) -> Self {
        Self {
            num_witin: 0,
            witin_namespace_map: vec![],
            num_fixed: 0,
            fixed_namespace_map: vec![],
            ns: NameSpace::new(root_name_fn),
            instance_name_map: HashMap::new(),
            r_expressions: vec![],
            r_expressions_namespace_map: vec![],
            w_expressions: vec![],
            w_expressions_namespace_map: vec![],
            lk_expressions: vec![],
            lk_expressions_namespace_map: vec![],
            lk_table_expressions: vec![],
            lk_table_expressions_namespace_map: vec![],
            assert_zero_expressions: vec![],
            assert_zero_expressions_namespace_map: vec![],
            assert_zero_sumcheck_expressions: vec![],
            assert_zero_sumcheck_expressions_namespace_map: vec![],
            max_non_lc_degree: 0,
            chip_record_alpha: Expression::Challenge(0, 1, E::ONE, E::ZERO),
            chip_record_beta: Expression::Challenge(1, 1, E::ONE, E::ZERO),

            phantom: std::marker::PhantomData,
        }
    }

    pub fn key_gen<PCS: PolynomialCommitmentScheme<E>>(
        self,
        pp: &PCS::ProverParam,
        fixed_traces: Option<RowMajorMatrix<E::BaseField>>,
    ) -> ProvingKey<E, PCS> {
        // transpose from row-major to column-major
        let fixed_traces = fixed_traces.map(|t| t.into_mles().into_iter().collect_vec());

        let fixed_commit_wd = fixed_traces
            .as_ref()
            .map(|traces| PCS::batch_commit(pp, traces).unwrap());
        let fixed_commit = fixed_commit_wd
            .as_ref()
            .map(|commit_wd| PCS::get_pure_commitment(commit_wd));

        ProvingKey {
            fixed_traces,
            fixed_commit_wd,
            vk: VerifyingKey {
                cs: self,
                fixed_commit,
            },
        }
    }

    pub fn create_witin<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        n: N,
    ) -> Result<WitIn, ZKVMError> {
        let wit_in = WitIn {
            id: {
                let id = self.num_witin;
                self.num_witin += 1;
                id
            },
        };

        let path = self.ns.compute_path(n().into());
        self.witin_namespace_map.push(path);

        Ok(wit_in)
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

    pub fn lk_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc lk_record degree ({})",
            name_fn().into()
        );
        self.lk_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.lk_expressions_namespace_map.push(path);
        Ok(())
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
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc lk_table_record degree ({})",
            name_fn().into()
        );
        self.lk_table_expressions.push(LogupTableExpression {
            values: rlc_record,
            multiplicity,
        });
        let path = self.ns.compute_path(name_fn().into());
        self.lk_table_expressions_namespace_map.push(path);

        Ok(())
    }

    pub fn read_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc read_record degree ({})",
            name_fn().into()
        );
        self.r_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.r_expressions_namespace_map.push(path);
        Ok(())
    }

    pub fn write_record<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc write_record degree ({})",
            name_fn().into()
        );
        self.w_expressions.push(rlc_record);
        let path = self.ns.compute_path(name_fn().into());
        self.w_expressions_namespace_map.push(path);
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
                let e = assert_zero_expr.to_monomial_form();
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
        cb: impl FnOnce(&mut ConstraintSystem<E>) -> Result<T, ZKVMError>,
    ) -> Result<T, ZKVMError> {
        self.ns.push_namespace(name_fn().into());
        let t = cb(self);
        self.ns.pop_namespace();
        t
    }
}

#[derive(Debug)]
pub struct CircuitBuilder<'a, E: ExtensionField> {
    pub(crate) cs: &'a mut ConstraintSystem<E>,
}
