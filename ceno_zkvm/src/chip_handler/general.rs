use ff_ext::ExtensionField;

use ff::Field;

use crate::{
    circuit_builder::{Circuit, CircuitBuilder},
    error::ZKVMError,
    expression::{Expression, WitIn},
    structs::ROMType,
};

impl<E: ExtensionField> Default for CircuitBuilder<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ExtensionField> CircuitBuilder<E> {
    pub fn new() -> Self {
        Self {
            num_witin: 0,
            r_expressions: vec![],
            w_expressions: vec![],
            lk_expressions: vec![],
            assert_zero_expressions: vec![],
            assert_zero_sumcheck_expressions: vec![],
            max_non_lc_degree: 0,
            chip_record_alpha: Expression::Challenge(0, 1, E::ONE, E::ZERO),
            chip_record_beta: Expression::Challenge(1, 1, E::ONE, E::ZERO),
            phantom: std::marker::PhantomData,
        }
    }

    pub fn create_witin(&mut self) -> WitIn {
        WitIn {
            id: {
                let id = self.num_witin;
                self.num_witin += 1;
                id
            },
        }
    }

    pub fn lk_record(&mut self, rlc_record: Expression<E>) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.lk_expressions.push(rlc_record);
        Ok(())
    }

    pub fn read_record(&mut self, rlc_record: Expression<E>) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.r_expressions.push(rlc_record);
        Ok(())
    }

    pub fn write_record(&mut self, rlc_record: Expression<E>) -> Result<(), ZKVMError> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.w_expressions.push(rlc_record);
        Ok(())
    }

    pub fn rlc_chip_record(&self, records: Vec<Expression<E>>) -> Expression<E> {
        assert!(!records.is_empty());
        let beta_pows = {
            let mut beta_pows = Vec::with_capacity(records.len());
            beta_pows.push(Expression::Constant(E::BaseField::ONE));
            (0..records.len() - 1).for_each(|_| {
                beta_pows.push(self.chip_record_beta.clone() * beta_pows.last().unwrap().clone())
            });
            beta_pows
        };

        let item_rlc = beta_pows
            .into_iter()
            .zip(records.iter())
            .map(|(beta, record)| beta * record.clone())
            .reduce(|a, b| a + b)
            .expect("reduce error");

        item_rlc + self.chip_record_alpha.clone()
    }

    pub fn require_zero(&mut self, assert_zero_expr: Expression<E>) -> Result<(), ZKVMError> {
        assert!(
            assert_zero_expr.degree() > 0,
            "constant expression assert to zero ?"
        );
        if assert_zero_expr.degree() == 1 {
            self.assert_zero_expressions.push(assert_zero_expr);
        } else {
            assert!(
                assert_zero_expr.is_monomial_form(),
                "only support sumcheck in monomial form"
            );
            self.max_non_lc_degree = self.max_non_lc_degree.max(assert_zero_expr.degree());
            self.assert_zero_sumcheck_expressions.push(assert_zero_expr);
        }
        Ok(())
    }

    pub fn require_equal(
        &mut self,
        target: Expression<E>,
        rlc_record: Expression<E>,
    ) -> Result<(), ZKVMError> {
        self.require_zero(target - rlc_record)
    }

    pub fn require_one(&mut self, expr: Expression<E>) -> Result<(), ZKVMError> {
        self.require_zero(Expression::from(1) - expr)
    }

    pub(crate) fn assert_u5(&mut self, expr: Expression<E>) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(ROMType::U5 as u64)),
            expr,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.lk_record(rlc_record)?;
        Ok(())
    }

    pub fn finalize_circuit(&self) -> Circuit<E> {
        Circuit {
            num_witin: self.num_witin,
            r_expressions: self.r_expressions.clone(),
            w_expressions: self.w_expressions.clone(),
            lk_expressions: self.lk_expressions.clone(),
            assert_zero_expressions: self.assert_zero_expressions.clone(),
            assert_zero_sumcheck_expressions: self.assert_zero_sumcheck_expressions.clone(),
            max_non_lc_degree: self.max_non_lc_degree,
        }
    }
}
