use ff_ext::ExtensionField;

use crate::{
    structs_v2::CircuitBuilderV2,
    util_v2::{ExpressionV2, WitIn, ZKVMV2Error},
};
use ff::Field;

impl<E: ExtensionField> CircuitBuilderV2<E> {
    pub fn new() -> Self {
        Self {
            num_witin: 0,
            r_expressions: vec![],
            w_expressions: vec![],
            lk_expressions: vec![],
            assert_zero_expressions: vec![],
            assert_zero_sumcheck_expressions: vec![],
            chip_record_alpha: ExpressionV2::Challenge(0),
            chip_record_beta: ExpressionV2::Challenge(1),
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
    pub fn read_record(&mut self, rlc_record: ExpressionV2<E>) -> Result<(), ZKVMV2Error> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.r_expressions.push(rlc_record);
        Ok(())
    }

    pub fn write_record(&mut self, rlc_record: ExpressionV2<E>) -> Result<(), ZKVMV2Error> {
        assert_eq!(
            rlc_record.degree(),
            1,
            "rlc record degree {} != 1",
            rlc_record.degree()
        );
        self.w_expressions.push(rlc_record);
        Ok(())
    }

    pub fn rlc_chip_record(&self, records: Vec<ExpressionV2<E>>) -> ExpressionV2<E> {
        assert!(!records.is_empty());
        let beta_pows = {
            let mut beta_pows = Vec::with_capacity(records.len());
            beta_pows.push(ExpressionV2::Constant(E::BaseField::ONE));
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

    pub fn require_zero(&mut self, assert_zero_expr: ExpressionV2<E>) -> Result<(), ZKVMV2Error> {
        assert!(
            assert_zero_expr.degree() > 0,
            "constant expression assert to zero ?"
        );
        if assert_zero_expr.degree() == 1 {
            self.assert_zero_expressions.push(assert_zero_expr);
        } else {
            // TODO check expression must be in multivariate monomial form
            self.assert_zero_sumcheck_expressions.push(assert_zero_expr);
        }
        Ok(())
    }

    pub fn require_equal(
        &mut self,
        target: ExpressionV2<E>,
        rlc_record: ExpressionV2<E>,
    ) -> Result<(), ZKVMV2Error> {
        self.require_zero(target - rlc_record)
    }

    pub fn require_one(&mut self, expr: ExpressionV2<E>) -> Result<(), ZKVMV2Error> {
        self.require_zero(ExpressionV2::from(1) - expr)
    }
}
