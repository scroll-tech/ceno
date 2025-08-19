use ceno_emul::InsnKind;

mod div_circuit;
mod div_circuit_v2;

use super::RIVInstruction;

pub struct DivuOp;
impl RIVInstruction for DivuOp {
    const INST_KIND: InsnKind = InsnKind::DIVU;
}
#[cfg(feature = "u16limb_circuit")]
pub type DivuInstruction<E> = div_circuit_v2::ArithInstruction<E, DivuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivuInstruction<E> = div_circuit::ArithInstruction<E, DivuOp>;

pub struct RemuOp;
impl RIVInstruction for RemuOp {
    const INST_KIND: InsnKind = InsnKind::REMU;
}
#[cfg(feature = "u16limb_circuit")]
pub type RemuInstruction<E> = div_circuit_v2::ArithInstruction<E, RemuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivuInstruction<E> = div_circuit::ArithInstruction<E, RemuOp>;

pub struct RemOp;
impl RIVInstruction for RemOp {
    const INST_KIND: InsnKind = InsnKind::REM;
}
#[cfg(feature = "u16limb_circuit")]
pub type RemInstruction<E> = div_circuit_v2::ArithInstruction<E, RemOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivuInstruction<E> = div_circuit::ArithInstruction<E, RemOp>;

pub struct DivOp;
impl RIVInstruction for DivOp {
    const INST_KIND: InsnKind = InsnKind::DIV;
}
#[cfg(feature = "u16limb_circuit")]
pub type DivInstruction<E> = div_circuit_v2::ArithInstruction<E, DivOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type DivuInstruction<E> = div_circuit::ArithInstruction<E, DivOp>;

#[cfg(test)]
mod test {

    #[cfg(not(feature = "u16limb_circuit"))]
    use super::div_circuit::DivRemConfig;
    #[cfg(feature = "u16limb_circuit")]
    use super::div_circuit_v2::DivRemConfig;
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
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

    fn verify<Insn: Instruction<GE> + TestInstance<GE>>(
        name: &str,
        dividend: <Insn as TestInstance<GE>>::NumType,
        divisor: <Insn as TestInstance<GE>>::NumType,
        exp_outcome: <Insn as TestInstance<GE>>::NumType,
        is_ok: bool,
    ) {
        let mut cs = ConstraintSystem::<GE>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{}_({})", Insn::name(), name),
                |cb| Ok(Insn::construct_circuit(cb, &ProgramParams::default())),
            )
            .unwrap()
            .unwrap();
        let outcome = Insn::correct(dividend, divisor);
        let insn_code = encode_rv32(Insn::INSN_KIND, 2, 3, 4, 0);
        // values assignment
        let ([raw_witin, _], lkm) = Insn::assign_instances(
            &config,
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
    fn verify_positive<Insn: Instruction<GE> + TestInstance<GE>>(
        name: &str,
        dividend: <Insn as TestInstance<GE>>::NumType,
        divisor: <Insn as TestInstance<GE>>::NumType,
    ) {
        verify::<Insn>(
            name,
            dividend,
            divisor,
            Insn::correct(dividend, divisor),
            true,
        );
    }

    // Test unsigned opcodes
    type Divu = DivuInstruction<GE>;
    type Remu = RemuInstruction<GE>;

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
            verify_positive::<Divu>(name, dividend, divisor);
            verify_positive::<Remu>(name, dividend, divisor);
        }
    }

    #[test]
    fn test_divrem_unsigned_edges() {
        let interesting_values = [u32::MAX, u32::MAX - 1, 0, 1, 2];

        for dividend in interesting_values {
            for divisor in interesting_values {
                let name = format!("dividend = {}, divisor = {}", dividend, divisor);
                verify_positive::<Divu>(&name, dividend, divisor);
                verify_positive::<Remu>(&name, dividend, divisor);
            }
        }
    }

    #[test]
    fn test_divrem_unsigned_unsatisfied() {
        verify::<Divu>("assert_outcome", 10, 2, 3, false);
    }

    #[test]
    fn test_divrem_unsigned_random() {
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let dividend: u32 = rng.next_u32();
            let divisor: u32 = rng.next_u32();
            let name = format!("random: dividend = {}, divisor = {}", dividend, divisor);
            verify_positive::<Divu>(&name, dividend, divisor);
            verify_positive::<Remu>(&name, dividend, divisor);
        }
    }

    // Test signed opcodes
    type Div = DivInstruction<GE>;
    type Rem = RemInstruction<GE>;

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
            verify_positive::<Div>(name, dividend, divisor);
            verify_positive::<Rem>(name, dividend, divisor);
        }
    }

    #[test]
    fn test_divrem_signed_edges() {
        let interesting_values = [i32::MIN, i32::MAX, i32::MIN + 1, i32::MAX - 1, 0, -1, 1, 2];

        for dividend in interesting_values {
            for divisor in interesting_values {
                let name = format!("dividend = {}, divisor = {}", dividend, divisor);
                verify_positive::<Div>(&name, dividend, divisor);
                verify_positive::<Rem>(&name, dividend, divisor);
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
            verify_positive::<Div>(&name, dividend, divisor);
            verify_positive::<Rem>(&name, dividend, divisor);
        }
    }
}
