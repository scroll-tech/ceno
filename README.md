# MVP
step 1
- non-uniform prover end to end
  - no recursion
  - no PCS
  - with IOP
  - with lookup
  - with Frontend + VM

step 2
- introduce PCS

step 3
- recursion and achieve uniformality

# Building blocks
- hash function
<!---  - [ ] merkle tree hash: 2-1 or 3-1 with padding
  - [ ] transcript: 3-1
  - [ ] (optional) breakdown: 16-1
  - [ ] plonky2 12-4 --->
  - [ ] decision: start with 8-4 first

- IOP
  - lookup
    - [ ] logup: spec @wenqing
    - [ ] implement as an IOP module along with high degree gate
  - high degree gates
    - [ ] paper/spec @tianyi
    - one on one tianyi/zhenfei

- PCS

- gates/subcircuits
  - spec
  - example by tianyi


option 1
- repeat sumcheck twice/three times
option 2
- use F_q^2/3 extension field, do not repeat
- rule of thumb: n rounds, soundness ~ (64-n) bits




 
