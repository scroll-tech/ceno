#[cfg(test)]
mod tests {
    use crate::arithmetics::{challenger_multi_observe, exts_to_felts};
    use crate::zkvm_verifier::binding::F;
    use openvm_circuit::arch::SystemConfig;
    use openvm_circuit::arch::VmExecutor;
    use openvm_native_circuit::Native;
    use openvm_native_circuit::NativeConfig;
    use openvm_native_compiler::conversion::convert_program;
    use openvm_native_compiler::prelude::*;
    use openvm_native_compiler::{asm::AsmBuilder, conversion::CompilerOptions};
    use openvm_native_recursion::challenger::CanSampleVariable;
    use openvm_native_recursion::challenger::{
        duplex::DuplexChallengerVariable, CanObserveVariable,
    };
    use openvm_stark_backend::config::StarkGenericConfig;
    use openvm_stark_backend::p3_field::{Field, FieldAlgebra};
    use openvm_stark_sdk::{
        config::baby_bear_poseidon2::BabyBearPoseidon2Config, p3_baby_bear::BabyBear,
    };

    type SC = BabyBearPoseidon2Config;
    type EF = <SC as StarkGenericConfig>::Challenge;

    #[test]
    pub fn test_native_multi_observe() {
        // OpenVM DSL
        let mut builder = AsmBuilder::<F, EF>::default();

        vm_program(&mut builder);

        builder.halt();

        // Pass in witness stream
        let witness_stream: Vec<
            Vec<p3_monty_31::MontyField31<openvm_stark_sdk::p3_baby_bear::BabyBearParameters>>,
        > = Vec::new();

        // Compile program
        let options = CompilerOptions::default().with_cycle_tracker();
        let mut compiler = AsmCompiler::new(options.word_size);
        compiler.build(builder.operations);
        let asm_code = compiler.code();
        let program = convert_program(asm_code, options);

        let mut system_config = SystemConfig::default()
            .with_public_values(4)
            .with_max_segment_len((1 << 25) - 100);
        system_config.profiling = true;
        let config = NativeConfig::new(system_config, Native);

        let executor = VmExecutor::<BabyBear, NativeConfig>::new(config);

        // Alternative execution
        // executor.execute(program, witness_stream).unwrap();

        let res = executor
            .execute_and_then(program, witness_stream, |_, seg| Ok(seg), |err| err)
            .unwrap();

        for (i, seg) in res.iter().enumerate() {
            println!("=> segment {:?} metrics: {:?}", i, seg.metrics);
        }
    }

    fn vm_program<C: Config>(builder: &mut Builder<C>) {
        let e1: Ext<C::F, C::EF> = builder.constant(C::EF::GENERATOR.exp_power_of_2(16));
        let e2: Ext<C::F, C::EF> = builder.constant(C::EF::GENERATOR.exp_power_of_2(32));
        let e3: Ext<C::F, C::EF> = builder.constant(C::EF::GENERATOR.exp_power_of_2(64));
        let e4: Ext<C::F, C::EF> = builder.constant(C::EF::GENERATOR.exp_power_of_2(128));
        let e5: Ext<C::F, C::EF> = builder.constant(C::EF::GENERATOR.exp_power_of_2(256));
        let len: usize = 5;

        let e_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(len);
        builder.set(&e_arr, 0, e1);
        builder.set(&e_arr, 1, e2);
        builder.set(&e_arr, 2, e3);
        builder.set(&e_arr, 3, e4);
        builder.set(&e_arr, 4, e5);

        unsafe {
            let mut c1 = DuplexChallengerVariable::new(builder);
            let mut c2 = DuplexChallengerVariable::new(builder);

            let f_arr1 = exts_to_felts(builder, &e_arr);
            let f_arr2 = f_arr1.clone();

            challenger_multi_observe(builder, &mut c1, &f_arr1);
            let test_e1 = c1.sample(builder);

            c2.observe_slice(builder, f_arr2);
            let test_e2 = c2.sample(builder);

            builder.assert_felt_eq(test_e1, test_e2);
        }
    }
}
