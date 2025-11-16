const TWO_ADICITY: usize = 32;
const TWO_ADIC_GENERATORS: [usize; 33] = [
    0x0000000000000001,
    0xffffffff00000000,
    0x0001000000000000,
    0xfffffffeff000001,
    0xefffffff00000001,
    0x00003fffffffc000,
    0x0000008000000000,
    0xf80007ff08000001,
    0xbf79143ce60ca966,
    0x1905d02a5c411f4e,
    0x9d8f2ad78bfed972,
    0x0653b4801da1c8cf,
    0xf2c35199959dfcb6,
    0x1544ef2335d17997,
    0xe0ee099310bba1e2,
    0xf6b2cffe2306baac,
    0x54df9630bf79450e,
    0xabd0a6e8aa3d8a0e,
    0x81281a7b05f9beac,
    0xfbd41c6b8caa3302,
    0x30ba2ecd5e93e76d,
    0xf502aef532322654,
    0x4b2a18ade67246b5,
    0xea9d5a1336fbc98b,
    0x86cdcc31c307e171,
    0x4bbaf5976ecfefd8,
    0xed41d05b78d6e286,
    0x10d78dd8915a171d,
    0x59049500004a4485,
    0xdfa8c93ba46d2666,
    0x7e9bd009b86a0845,
    0x400a7f755588e659,
    0x185629dcda58878c,
];

use openvm_native_compiler::prelude::*;
use p3_field::FieldAlgebra;

fn two_adic_generator<C: Config>(
    builder: &mut Builder<C>,
    bits: Var<C::N>,
) -> Var<C::F> {
    let bits_limit = builder.eval(Usize::from(TWO_ADICITY) + Usize::from(1));
    builder.assert_less_than_slow_small_rhs(bits, bits_limit);

    let two_adic_generator: Array<C, Var<<C as Config>::F>> = builder.dyn_array(TWO_ADICITY + 1);
    builder.range(0, TWO_ADICITY + 1).for_each(|i_vec, builder| {
        let i = i_vec[0];
        builder.set_value(&two_adic_generator, i, C::F::from_canonical_usize(TWO_ADIC_GENERATORS[i.value()]));
    });
    builder.get(&two_adic_generator, bits)
}