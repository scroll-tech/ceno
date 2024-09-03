use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    structs::{ROMType, WitnessId},
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use std::{collections::BTreeMap, marker::PhantomData};

#[derive(Clone, Debug)]
pub struct RangeTableConfig<E> {
    u16_tbl: Fixed,
    u16_mlt: WitIn,
    _marker: PhantomData<E>,
}

#[derive(Default)]
pub struct RangeTableTrace<E: ExtensionField> {
    pub fixed: BTreeMap<Fixed, DenseMultilinearExtension<E>>,
    pub wits: BTreeMap<WitnessId, DenseMultilinearExtension<E>>,
}

impl<E: ExtensionField> RangeTableConfig<E> {
    #[allow(unused)]
    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<RangeTableConfig<E>, ZKVMError> {
        let u16_tbl = cb.create_fixed(|| "u16_tbl")?;
        let u16_mlt = cb.create_witin(|| "u16_mlt")?;

        let u16_table_values = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U16 as u64)),
            Expression::Fixed(u16_tbl.clone()),
        ]);

        cb.lk_table_record(|| "u16 table", u16_table_values, u16_mlt.expr())?;

        Ok(RangeTableConfig {
            u16_tbl,
            u16_mlt,
            _marker: Default::default(),
        })
    }

    #[allow(unused)]
    fn generate_traces(self, inputs: &[u16]) -> RangeTableTrace<E> {
        let mut u16_mlt = vec![0; 1 << 16];
        for limb in inputs {
            u16_mlt[*limb as usize] += 1;
        }

        let u16_tbl = DenseMultilinearExtension::from_evaluations_vec(
            16,
            (0..(1 << 16)).map(E::BaseField::from).collect_vec(),
        );
        let u16_mlt = DenseMultilinearExtension::from_evaluations_vec(
            16,
            u16_mlt.into_iter().map(E::BaseField::from).collect_vec(),
        );

        let config = self.clone();
        let mut traces = RangeTableTrace::default();
        traces.fixed.insert(config.u16_tbl, u16_tbl);
        traces.wits.insert(config.u16_mlt.id, u16_mlt);

        traces
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        scheme::{constants::NUM_FANIN_LOGUP, prover::ZKVMProver, verifier::ZKVMVerifier},
        structs::PointAndEval,
        tables::range::RangeTableConfig,
    };
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use transcript::Transcript;

    #[test]
    fn test_range_circuit() {
        let mut cs = ConstraintSystem::new(|| "riscv");
        let config = cs
            .namespace(
                || "range",
                |cs| {
                    let mut cb = CircuitBuilder::<GoldilocksExt2>::new(cs);
                    RangeTableConfig::construct_circuit(&mut cb)
                },
            )
            .expect("construct range table circuit");

        let traces = config.generate_traces((0..1 << 8).collect_vec().as_slice());

        let pk = cs.key_gen(Some(traces.fixed.clone().into_values().collect_vec()));
        let vk = pk.vk.clone();
        let prover = ZKVMProver::new(pk);

        let mut transcript = Transcript::new(b"range");
        let challenges = [1.into(), 2.into()];

        let proof = prover
            .create_table_proof(
                traces
                    .wits
                    .into_values()
                    .map(|mle| mle.into())
                    .collect_vec(),
                // TODO: fix the verification error for num_instances is not power-of-two case
                1 << 16,
                1,
                &mut transcript,
                &challenges,
            )
            .expect("create proof");

        let mut transcript = Transcript::new(b"range");
        let verifier = ZKVMVerifier::new(vk);
        verifier
            .verify_table_proof(
                &proof,
                &mut transcript,
                NUM_FANIN_LOGUP,
                &PointAndEval::default(),
                &challenges,
            )
            .expect("verify proof failed");
    }
}
