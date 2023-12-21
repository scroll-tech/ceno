//! This is an example for computing Fibonacci numbers using zkVM.
//! It refers to the code in https://medium.com/coinmonks/develop-evm-assembly-opcode-logic-for-fibonacci-107f92dbc9d1.

// The Solidity code of Finbonacci computation is:
// ```solidity
// contract Fibonacci {
//     fallback() payable external returns (bytes memory k) {
//         initialize j = 0
//         initialize k = 1
//         for {i = 2, i <= n, i++}:
//             m = k + j
//             j = k
//             k = m
//         return k
//     }
// }
// ```
// Bytecode is `600035600160009160025b818111601c576001019180930191600a565b505060005260206000f3`
// The opcode sequences:
//     PUSH1 0x00
//     CALLDATALOAD
//     PUSH1 0x01
//     PUSH1 0x00
//     SWAP2
//     PUSH1 0x02
//     JUMPDEST
//     DUP2
//     DUP2
//     GT
//     PUSH1 0x1c
//     JUMPI
//     PUSH1 0x01
//     ADD
//     SWAP2
//     DUP1
//     SWAP4
//     ADD
//     SWAP2
//     PUSH1 0x0a
//     JUMP
//     JUMPDEST
//     POP
//     POP
//     PUSH1 0x00
//     MSTORE
//     PUSH1 0x20
//     PUSH1 0x00
//     RETURN

use goldilocks::{Goldilocks, SmallField};
use transcript::Transcript;
use zkvm::zkvm_basic::{
    self,
    structs::{VMBasic, VMBasicBuilder, VMBasicInterpreter, VMBasicWitness},
};

fn construct_circuit<F: SmallField>(bytecode: &[u8]) -> VMBasic<F> {
    let mut vm_builder = VMBasicBuilder::<F>::new();
    vm_builder.build(bytecode);
    VMBasic::new(vm_builder)
}

fn main() {
    let bytecode = vec![
        0x60, 0x00, 0x35, 0x60, 0x01, 0x60, 0x00, 0x91, 0x60, 0x02, 0x5b, 0x81, 0x81, 0x11, 0x60,
        0x1c, 0x57, 0x60, 0x01, 0x01, 0x91, 0x80, 0x93, 0x01, 0x91, 0x60, 0x0a, 0x56, 0x5b, 0x50,
        0x50, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ];
    let vm = construct_circuit::<Goldilocks>(&bytecode);

    let public_input = vec![16];
    let mut interpreter = VMBasicInterpreter::<Goldilocks>::new();
    interpreter.run(&bytecode, &public_input);
    let vm_basic_witness = VMBasicWitness::new(&vm, &interpreter);

    let public_input = public_input
        .iter()
        .map(|x| Goldilocks::from(*x as u64))
        .collect::<Vec<_>>();
    let proof = {
        let mut transcript = Transcript::<Goldilocks>::new(b"fibonacci");
        zkvm_basic::prover::prove(&vm, &vm_basic_witness, &public_input, &mut transcript)
    };

    let verify = {
        let mut transcript = Transcript::<Goldilocks>::new(b"fibonacci");
        zkvm_basic::verifier::verify(&vm, &proof, &public_input, &mut transcript)
    };
    assert!(verify.is_ok());
}
