use ceno_emul::InsnKind;

#[cfg(not(feature = "u16limb_circuit"))]
mod div_circuit;
#[cfg(feature = "u16limb_circuit")]
mod div_circuit_v2;

use super::RIVInstruction;

#[derive(Default)]
pub struct DivuOp;

impl RIVInstruction for DivuOp {
    const INST_KIND: InsnKind = InsnKind::DIVU;
}
#[cfg(feature = "u16limb_circuit")]
pub type DivuInstruction<E> = div_circuit_v2::ArithInstruction<E, DivuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivuInstruction<E> = div_circuit::ArithInstruction<E, DivuOp>;

#[derive(Default)]
pub struct RemuOp;

impl RIVInstruction for RemuOp {
    const INST_KIND: InsnKind = InsnKind::REMU;
}
#[cfg(feature = "u16limb_circuit")]
pub type RemuInstruction<E> = div_circuit_v2::ArithInstruction<E, RemuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type RemuInstruction<E> = div_circuit::ArithInstruction<E, RemuOp>;

#[derive(Default)]
pub struct RemOp;

impl RIVInstruction for RemOp {
    const INST_KIND: InsnKind = InsnKind::REM;
}
#[cfg(feature = "u16limb_circuit")]
pub type RemInstruction<E> = div_circuit_v2::ArithInstruction<E, RemOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type RemInstruction<E> = div_circuit::ArithInstruction<E, RemOp>;

#[derive(Default)]
pub struct DivOp;

impl RIVInstruction for DivOp {
    const INST_KIND: InsnKind = InsnKind::DIV;
}
#[cfg(feature = "u16limb_circuit")]
pub type DivInstruction<E> = div_circuit_v2::ArithInstruction<E, DivOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivInstruction<E> = div_circuit::ArithInstruction<E, DivOp>;

#[cfg(test)]
mod test {

    #[cfg(not(feature = "u16limb_circuit"))]
    use super::div_circuit::DivRemConfig;
    #[cfg(feature = "u16limb_circuit")]
    use super::div_circuit_v2::DivRemConfig;
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{
            Instruction,
            riscv::{
                constants::UInt,
                div::{DivInstruction, DivuInstruction, RemInstruction, RemuInstruction},
            },
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };
    use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
    #[cfg(feature = "u16limb_circuit")]
    use ff_ext::BabyBearExt4 as BE;
    use ff_ext::{ExtensionField, GoldilocksExt2 as GE};
    use itertools::Itertools;
    use rand::RngCore;

    // unifies DIV/REM/DIVU/REMU interface for testing purposes
    trait TestInstance<E: ExtensionField>
    where
        Self: Instruction<E>,
    {
        // type the instruction works with (i32 or u32)
        type NumType: Copy;
        // conv to register necessary due to lack of native "as" trait
        fn as_u32(val: Self::NumType) -> u32;
        // designates output value of the circuit that is under scrutiny
        fn output(config: Self::InstructionConfig) -> UInt<E>;
        // the correct/expected value for given parameters
        fn correct(dividend: Self::NumType, divisor: Self::NumType) -> Self::NumType;
        const INSN_KIND: InsnKind;
    }

    impl<E: ExtensionField> TestInstance<E> for DivInstruction<E> {
        type NumType = i32;
        fn as_u32(val: Self::NumType) -> u32 {
            val as u32
        }
        fn output(config: DivRemConfig<E>) -> UInt<E> {
            config.quotient
        }
        fn correct(dividend: i32, divisor: i32) -> i32 {
            if divisor == 0 {
                -1i32
            } else {
                dividend.wrapping_div(divisor)
            }
        }
        const INSN_KIND: InsnKind = InsnKind::DIV;
    }

    impl<E: ExtensionField> TestInstance<E> for RemInstruction<E> {
        type NumType = i32;
        fn as_u32(val: Self::NumType) -> u32 {
            val as u32
        }
        fn output(config: DivRemConfig<E>) -> UInt<E> {
            config.remainder
        }
        fn correct(dividend: i32, divisor: i32) -> i32 {
            if divisor == 0 {
                dividend
            } else {
                dividend.wrapping_rem(divisor)
            }
        }
        const INSN_KIND: InsnKind = InsnKind::REM;
    }

    impl<E: ExtensionField> TestInstance<E> for DivuInstruction<E> {
        type NumType = u32;
        fn as_u32(val: Self::NumType) -> u32 {
            val
        }
        fn output(config: DivRemConfig<E>) -> UInt<E> {
            config.quotient
        }
        fn correct(dividend: u32, divisor: u32) -> u32 {
            if divisor == 0 {
                u32::MAX
            } else {
                dividend / divisor
            }
        }
        const INSN_KIND: InsnKind = InsnKind::DIVU;
    }

    impl<E: ExtensionField> TestInstance<E> for RemuInstruction<E> {
        type NumType = u32;
        fn as_u32(val: Self::NumType) -> u32 {
            val
        }
        fn output(config: DivRemConfig<E>) -> UInt<E> {
            config.remainder
        }
        fn correct(dividend: u32, divisor: u32) -> u32 {
            if divisor == 0 {
                dividend
            } else {
                dividend % divisor
            }
        }
        const INSN_KIND: InsnKind = InsnKind::REMU;
    }

    fn verify<
        E: ExtensionField,
        Insn: Instruction<E, Record = StepRecord> + TestInstance<E> + Default,
    >(
        name: &str,
        dividend: <Insn as TestInstance<E>>::NumType,
        divisor: <Insn as TestInstance<E>>::NumType,
        exp_outcome: <Insn as TestInstance<E>>::NumType,
        is_ok: bool,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let inst = Insn::default();
        let config = cb
            .namespace(
                || format!("{}_({})", Insn::name(), name),
                |cb| Ok(inst.construct_circuit(cb, &ProgramParams::default())),
            )
            .unwrap()
            .unwrap();
        let outcome = Insn::correct(dividend, divisor);
        let insn_code = encode_rv32(Insn::INSN_KIND, 2, 3, 4, 0);
        // values assignment
        let ([raw_witin, _], lkm) = Insn::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                Insn::as_u32(dividend),
                Insn::as_u32(divisor),
                Change::new(0, Insn::as_u32(outcome)),
                0,
            )],
        )
        .unwrap();
        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked(Insn::as_u32(exp_outcome))
                .as_u16_limbs()
                .to_vec(),
        );

        Insn::output(config)
            .require_equal(|| "assert_outcome", &mut cb, &expected_rd_written)
            .unwrap();

        let expected_errors: &[_] = if is_ok { &[] } else { &[name] };
        MockProver::assert_with_expected_errors(
            &cb,
            &[],
            &raw_witin
                .to_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            &[],
            &[insn_code],
            expected_errors,
            None,
            Some(lkm),
        );
    }

    // shortcut to verify given pair produces correct output
    fn verify_positive<
        E: ExtensionField,
        Insn: Instruction<E, Record = StepRecord> + TestInstance<E> + Default,
    >(
        name: &str,
        dividend: <Insn as TestInstance<E>>::NumType,
        divisor: <Insn as TestInstance<E>>::NumType,
    ) {
        verify::<E, Insn>(
            name,
            dividend,
            divisor,
            Insn::correct(dividend, divisor),
            true,
        );
    }

    // Test unsigned opcodes
    type DivuG = DivuInstruction<GE>;
    type RemuG = RemuInstruction<GE>;
    #[cfg(feature = "u16limb_circuit")]
    type DivuB = DivuInstruction<BE>;
    #[cfg(feature = "u16limb_circuit")]
    type RemuB = RemuInstruction<BE>;

    #[test]
    fn test_divrem_unsigned_handmade() {
        let test_cases = [
            ("10 / 2", 10, 2),
            ("10 / 11", 10, 11),
            ("11 / 2", 11, 2),
            ("large values 1", 1234 * 5678 * 100, 1234),
            ("large values 2", 1202729773, 171818539),
        ];

        for (name, dividend, divisor) in test_cases.into_iter() {
            verify_positive::<GE, DivuG>(name, dividend, divisor);
            verify_positive::<GE, RemuG>(name, dividend, divisor);
            #[cfg(feature = "u16limb_circuit")]
            {
                verify_positive::<BE, DivuB>(name, dividend, divisor);
                verify_positive::<BE, RemuB>(name, dividend, divisor);
            }
        }
    }

    #[test]
    fn test_divrem_unsigned_edges() {
        let interesting_values = [u32::MAX, u32::MAX - 1, 0, 1, 2];

        for dividend in interesting_values {
            for divisor in interesting_values {
                let name = format!("dividend = {}, divisor = {}", dividend, divisor);
                verify_positive::<GE, DivuG>(&name, dividend, divisor);
                verify_positive::<GE, RemuG>(&name, dividend, divisor);
                #[cfg(feature = "u16limb_circuit")]
                {
                    verify_positive::<BE, DivuB>(&name, dividend, divisor);
                    verify_positive::<BE, RemuB>(&name, dividend, divisor);
                }
            }
        }
    }

    #[test]
    fn test_divrem_unsigned_unsatisfied() {
        verify::<GE, DivuG>("assert_outcome", 10, 2, 3, false);
    }

    #[test]
    fn test_divrem_unsigned_random() {
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let dividend: u32 = rng.next_u32();
            let divisor: u32 = rng.next_u32();
            let name = format!("random: dividend = {}, divisor = {}", dividend, divisor);
            verify_positive::<GE, DivuG>(&name, dividend, divisor);
            verify_positive::<GE, RemuG>(&name, dividend, divisor);
            #[cfg(feature = "u16limb_circuit")]
            {
                verify_positive::<BE, DivuB>(&name, dividend, divisor);
                verify_positive::<BE, RemuB>(&name, dividend, divisor);
            }
        }
    }

    // Test signed opcodes
    type DivG = DivInstruction<GE>;
    type RemG = RemInstruction<GE>;
    #[cfg(feature = "u16limb_circuit")]
    type DivB = DivInstruction<BE>;
    #[cfg(feature = "u16limb_circuit")]
    type RemB = RemInstruction<BE>;

    #[test]
    fn test_divrem_signed_handmade() {
        let test_cases = [
            ("10 / 2", 10, 2),
            ("10 / 11", 10, 11),
            ("11 / 2", 11, 2),
            ("-10 / 3", -10, 3),
            ("-10 / -3", -10, -3),
            ("large values 1", -1234 * 5678 * 100, 5678),
            ("large values 2", 1234 * 5678 * 100, 1234),
            ("large values 3", 1202729773, 171818539),
        ];

        for (name, dividend, divisor) in test_cases.into_iter() {
            verify_positive::<GE, DivG>(name, dividend, divisor);
            verify_positive::<GE, RemG>(name, dividend, divisor);
            #[cfg(feature = "u16limb_circuit")]
            {
                verify_positive::<BE, DivB>(name, dividend, divisor);
                verify_positive::<BE, RemB>(name, dividend, divisor);
            }
        }
    }

    #[test]
    fn test_divrem_signed_edges() {
        let interesting_values = [i32::MIN, i32::MAX, i32::MIN + 1, i32::MAX - 1, 0, -1, 1, 2];

        for dividend in interesting_values {
            for divisor in interesting_values {
                let name = format!("dividend = {}, divisor = {}", dividend, divisor);
                verify_positive::<GE, DivG>(&name, dividend, divisor);
                verify_positive::<GE, RemG>(&name, dividend, divisor);
                #[cfg(feature = "u16limb_circuit")]
                {
                    verify_positive::<BE, DivB>(&name, dividend, divisor);
                    verify_positive::<BE, RemB>(&name, dividend, divisor);
                }
            }
        }
    }

    #[test]
    fn test_divrem_signed_random() {
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let dividend: i32 = rng.next_u32() as i32;
            let divisor: i32 = rng.next_u32() as i32;
            let name = format!("random: dividend = {}, divisor = {}", dividend, divisor);
            verify_positive::<GE, DivG>(&name, dividend, divisor);
            verify_positive::<GE, RemG>(&name, dividend, divisor);
            #[cfg(feature = "u16limb_circuit")]
            {
                verify_positive::<BE, DivB>(&name, dividend, divisor);
                verify_positive::<BE, RemB>(&name, dividend, divisor);
            }
        }
    }
}
