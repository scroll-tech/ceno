use ff_ext::ExtensionField;

use crate::util_v2::{CircuitBuilderV2, ExpressionV2, ZKVMV2Error};
use ff::Field;

impl<E: ExtensionField> CircuitBuilderV2<E> {
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
}
