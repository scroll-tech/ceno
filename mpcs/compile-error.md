    Checking mpcs v0.1.0 (/Users/zhangyuncong/Documents/GitHub/working-projects/ceno/mpcs)
error: associated type in `impl` without body
  --> mpcs/src/whir/fp.rs:85:5
   |
85 |     type FrobCoeff;
   |     ^^^^^^^^^^^^^^-
   |                   |
   |                   help: provide a definition for the type: `= <type>;`

error: associated constant in `impl` without body
  --> mpcs/src/whir/fp.rs:87:5
   |
87 |     const DEGREE_OVER_BASE_PRIME_FIELD: usize;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^-
   |                                              |
   |                                              help: provide a definition for the constant: `= <expr>;`

error: associated constant in `impl` without body
  --> mpcs/src/whir/fp.rs:89:5
   |
89 |     const NONRESIDUE: Self::BaseField;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^-
   |                                      |
   |                                      help: provide a definition for the constant: `= <expr>;`

error: associated constant in `impl` without body
  --> mpcs/src/whir/fp.rs:91:5
   |
91 |     const FROBENIUS_COEFF_C1: &'static [Self::FrobCoeff];
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^-
   |                                                         |
   |                                                         help: provide a definition for the constant: `= <expr>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:14:5
   |
14 |     type Param;
   |     ^^^^^^^^^^-
   |               |
   |               help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:15:5
   |
15 |     type ProverParam;
   |     ^^^^^^^^^^^^^^^^-
   |                     |
   |                     help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:16:5
   |
16 |     type VerifierParam;
   |     ^^^^^^^^^^^^^^^^^^-
   |                       |
   |                       help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:17:5
   |
17 |     type CommitmentWithData;
   |     ^^^^^^^^^^^^^^^^^^^^^^^-
   |                            |
   |                            help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:18:5
   |
18 |     type Commitment;
   |     ^^^^^^^^^^^^^^^-
   |                    |
   |                    help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:19:5
   |
19 |     type CommitmentChunk;
   |     ^^^^^^^^^^^^^^^^^^^^-
   |                         |
   |                         help: provide a definition for the type: `= <type>;`

error: associated type in `impl` without body
  --> mpcs/src/whir.rs:20:5
   |
20 |     type Proof;
   |     ^^^^^^^^^^-
   |               |
   |               help: provide a definition for the type: `= <type>;`

error[E0407]: method `serialize_uncompressed_with_flags` is not a member of trait `CanonicalSerializeWithFlags`
   --> mpcs/src/whir/ff.rs:121:5
    |
121 | /     fn serialize_uncompressed_with_flags<W: std::io::Write, F: ark_serialize::Flags>(
122 | |         &self,
123 | |         writer: W,
124 | |         flags: F,
125 | |     ) -> Result<(), ark_serialize::SerializationError> {
126 | |         self.0.serialize_uncompressed_with_flags(writer, flags)
127 | |     }
    | |_____^ not a member of trait `CanonicalSerializeWithFlags`

error[E0407]: method `uncompressed_size_with_flags` is not a member of trait `CanonicalSerializeWithFlags`
   --> mpcs/src/whir/ff.rs:129:5
    |
129 | /     fn uncompressed_size_with_flags<F: ark_serialize::Flags>(&self) -> usize {
130 | |         self.0.uncompressed_size_with_flags::<F>()
131 | |     }
    | |_____^ not a member of trait `CanonicalSerializeWithFlags`

error[E0407]: method `deserialize_uncompressed_with_flags` is not a member of trait `CanonicalDeserializeWithFlags`
   --> mpcs/src/whir/ff.rs:141:5
    |
141 | /     fn deserialize_uncompressed_with_flags<R: std::io::Read, F: ark_serialize::Flags>(
142 | |         reader: R,
143 | |     ) -> Result<(Self, F), ark_serialize::SerializationError> {
144 | |         E::deserialize_uncompressed_with_flags(reader).map(|(e, f)| (Self(e), f))
145 | |     }
    | |_____^ not a member of trait `CanonicalDeserializeWithFlags`

error[E0407]: method `zero` is not a member of trait `Field`
   --> mpcs/src/whir/ff.rs:277:5
    |
277 | /     fn zero() -> Self {
278 | |         Self(E::zero())
279 | |     }
    | |_____^ not a member of trait `Field`

error[E0407]: method `is_zero` is not a member of trait `Field`
   --> mpcs/src/whir/ff.rs:281:5
    |
281 | /     fn is_zero(&self) -> bool {
282 | |         self.0.is_zero()
283 | |     }
    | |_____^ not a member of trait `Field`

error[E0201]: duplicate definitions with name `from_random_bytes_with_flags`:
   --> mpcs/src/whir/ff.rs:293:5
    |
240 | /     fn from_random_bytes_with_flags<F: ark_serialize::Flags>(bytes: &[u8]) -> Option<(Self, F)> {
241 | |         E::from_random_bytes(bytes).map(|x| (Self(x), F::default()))
242 | |     }
    | |_____- previous definition here
...
293 | /     fn from_random_bytes_with_flags(bytes: &[u8]) -> Option<(Self, EmptyFlags)> {
294 | |         E::from_random_bytes(bytes).map(|x| (Self(x), EmptyFlags))
295 | |     }
    | |_____^ duplicate definition
    |
   ::: /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:253:5
    |
253 |       fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)>;
    |       ----------------------------------------------------------------------------- item in trait

error[E0407]: method `double` is not a member of trait `Field`
   --> mpcs/src/whir/ff.rs:297:5
    |
297 | /     fn double(&self) -> Self {
298 | |         Self(self.0.double())
299 | |     }
    | |_____^ not a member of trait `Field`

error[E0407]: method `double_in_place` is not a member of trait `Field`
   --> mpcs/src/whir/ff.rs:301:5
    |
301 |       fn double_in_place(&mut self) -> &mut Self {
    |       ^  --------------- help: there is an associated function with a similar name: `square_in_place`
    |  _____|
    | |
302 | |         self.0.double_in_place();
303 | |         self
304 | |     }
    | |_____^ not a member of trait `Field`

error[E0407]: method `neg_in_place` is not a member of trait `Field`
   --> mpcs/src/whir/ff.rs:306:5
    |
306 |       fn neg_in_place(&mut self) -> &mut Self {
    |       ^  ------------ help: there is an associated function with a similar name: `sqrt_in_place`
    |  _____|
    | |
307 | |         self.0.neg_in_place();
308 | |         self
309 | |     }
    | |_____^ not a member of trait `Field`

warning: unused imports: `FftField`, `Field`, and `PrimeField`
 --> mpcs/src/whir.rs:2:14
  |
2 | use ark_ff::{FftField, Field, PrimeField};
  |              ^^^^^^^^  ^^^^^  ^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: unused import: `whir::whir::pcs::Whir as WhirInner`
 --> mpcs/src/whir.rs:5:5
  |
5 | use whir::whir::pcs::Whir as WhirInner;
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `Compress`, `Flags`, `SerializationError`, and `Validate`
 --> mpcs/src/whir/ff.rs:4:34
  |
4 |     CanonicalSerializeWithFlags, Compress, EmptyFlags, Flags, SerializationError, Validate,
  |                                  ^^^^^^^^              ^^^^^  ^^^^^^^^^^^^^^^^^^  ^^^^^^^^

warning: unused import: `Neg`
 --> mpcs/src/whir/ff.rs:6:65
  |
6 | use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
  |                                                                 ^^^

warning: unused imports: `Read` and `Write`
 --> mpcs/src/whir/ff.rs:8:15
  |
8 | use std::io::{Read, Write};
  |               ^^^^  ^^^^^

warning: unused import: `Fp2Config`
 --> mpcs/src/whir/fp.rs:3:22
  |
3 | use ark_ff::{BigInt, Fp2Config, FpConfig, QuadExtConfig};
  |                      ^^^^^^^^^

warning: unused import: `Field`
 --> mpcs/src/whir/fp.rs:4:10
  |
4 | use ff::{Field, PrimeField};
  |          ^^^^^

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Valid` is not satisfied
   --> mpcs/src/whir/ff.rs:98:50
    |
98  | impl<E: ExtensionField> CanonicalDeserialize for ExtensionFieldWrapper<E> {
    |                                                  ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Valid` is not implemented for `ExtensionFieldWrapper<E>`
    |
    = help: the following other types implement trait `Valid`:
              ()
              (A, B)
              (A, B, C)
              (A, B, C, D)
              (A, B, C, D, E)
              (A,)
              Arc<T>
              BTreeMap<K, V>
            and 58 others
note: required by a bound in `CanonicalDeserialize`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-serialize-0.5.0/src/lib.rs:148:33
    |
148 | pub trait CanonicalDeserialize: Valid {
    |                                 ^^^^^ required by this bound in `CanonicalDeserialize`

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=&'a ExtensionFieldWrapper<E>>`
    |
    = help: the trait `for<'a> Sum<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:83:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
83  |     + for<'a> ark_std::iter::Sum<&'a Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=ExtensionFieldWrapper<E>>`
    |
    = help: the trait `Sum` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:82:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
82  |     + ark_std::iter::Sum<Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `for<'a> ExtensionFieldWrapper<E>: MulAssign<&'a mut <ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar>`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:81:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
81  |     + for<'a> MulAssign<&'a mut <Self as AdditiveGroup>::Scalar>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot subtract-assign `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:80:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
80  |     + for<'a> SubAssign<&'a mut Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot add-assign `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:79:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
79  |     + for<'a> AddAssign<&'a mut Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `for<'a> ExtensionFieldWrapper<E>: Mul<&'a mut <ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar>`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:78:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
78  |     + for<'a> Mul<&'a mut <Self as AdditiveGroup>::Scalar, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot subtract `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:77:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
77  |     + for<'a> Sub<&'a mut Self, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot add `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:76:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
76  |     + for<'a> Add<&'a mut Self, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `for<'a> ExtensionFieldWrapper<E>: MulAssign<&'a <ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar>`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:75:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
75  |     + for<'a> MulAssign<&'a <Self as AdditiveGroup>::Scalar>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot subtract-assign `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:74:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
74  |     + for<'a> SubAssign<&'a Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot add-assign `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:73:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
73  |     + for<'a> AddAssign<&'a Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `for<'a> ExtensionFieldWrapper<E>: Mul<&'a <ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar>`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:72:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
72  |     + for<'a> Mul<&'a <Self as AdditiveGroup>::Scalar, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot subtract `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:71:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
71  |     + for<'a> Sub<&'a Self, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: cannot add `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:70:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
70  |     + for<'a> Add<&'a Self, Output = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Neg` is not satisfied
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Neg` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:63:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
63  |     + Neg<Output = Self>
    |       ^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: ark_std::Zero` is not satisfied
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `ark_std::Zero` is not implemented for `ExtensionFieldWrapper<E>`
    |
    = help: the following other types implement trait `ark_std::Zero`:
              BigUint
              CubicExtField<P>
              QuadExtField<P>
              Wrapping<T>
              ark_ec::models::short_weierstrass::group::Projective<P>
              ark_ec::models::twisted_edwards::group::Projective<P>
              ark_ec::pairing::PairingOutput<P>
              ark_ff::Fp<P, N>
            and 22 others
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:62:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
62  |     + Zero
    |       ^^^^ required by this bound in `AdditiveGroup`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `std::fmt::Display`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted with the default formatter
    |
    = help: the trait `std::fmt::Display` is not implemented for `ExtensionFieldWrapper<E>`
    = note: in format strings you may be able to use `{:?}` (or {:#?} for pretty-print) instead
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:59:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
59  |     + Display
    |       ^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `Debug`
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted using `{:?}`
    |
    = help: the trait `Debug` is not implemented for `ExtensionFieldWrapper<E>`
    = note: add `#[derive(Debug)]` to `ExtensionFieldWrapper<E>` or manually `impl Debug for ExtensionFieldWrapper<E>`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:58:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
58  |     + Debug
    |       ^^^^^ required by this bound in `AdditiveGroup`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Debug)]`
    |
12  + #[derive(Debug)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Hash` is not satisfied
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Hash` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:57:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
57  |     + Hash
    |       ^^^^ required by this bound in `AdditiveGroup`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Hash)]`
    |
12  + #[derive(Hash)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Valid` is not satisfied
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Valid` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: CanonicalDeserialize`
    |
    = help: the following other types implement trait `Valid`:
              ()
              (A, B)
              (A, B, C)
              (A, B, C, D)
              (A, B, C, D, E)
              (A,)
              Arc<T>
              BTreeMap<K, V>
            and 58 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `CanonicalDeserialize`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:51:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
51  |     + CanonicalDeserialize
    |       ^^^^^^^^^^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0277]: the trait bound `Standard: Distribution<ExtensionFieldWrapper<E>>` is not satisfied
   --> mpcs/src/whir/ff.rs:194:43
    |
194 | impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    |                                           ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Distribution<ExtensionFieldWrapper<E>>` is not implemented for `Standard`, which is required by `ExtensionFieldWrapper<E>: ark_ff::UniformRand`
    |
    = help: the following other types implement trait `Distribution<T>`:
              `Standard` implements `Distribution<()>`
              `Standard` implements `Distribution<(A, B)>`
              `Standard` implements `Distribution<(A, B, C)>`
              `Standard` implements `Distribution<(A, B, C, D)>`
              `Standard` implements `Distribution<(A, B, C, D, E)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G, H)>`
            and 72 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::UniformRand`
note: required by a bound in `AdditiveGroup`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:60:7
    |
46  | pub trait AdditiveGroup:
    |           ------------- required by a bound in this trait
...
60  |     + UniformRand
    |       ^^^^^^^^^^^ required by this bound in `AdditiveGroup`

error[E0220]: associated type `BasePrimeField` not found for `E`
   --> mpcs/src/whir/ff.rs:214:8
    |
214 |     E::BasePrimeField: Clone + 'static,
    |        ^^^^^^^^^^^^^^ associated type `BasePrimeField` not found

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=&'a ExtensionFieldWrapper<E>>`
    |
    = help: the trait `for<'a> Sum<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=ExtensionFieldWrapper<E>>`
    |
    = help: the trait `Sum` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot subtract-assign `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot add-assign `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot subtract `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot add `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot subtract-assign `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot add-assign `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot subtract `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: cannot add `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `AdditiveGroup`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Valid` is not satisfied
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ the trait `Valid` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    |
    = help: the following other types implement trait `Valid`:
              ()
              (A, B)
              (A, B, C)
              (A, B, C, D)
              (A, B, C, D, E)
              (A,)
              Arc<T>
              BTreeMap<K, V>
            and 58 others
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `CanonicalDeserialize`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Hash` is not satisfied
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ the trait `Hash` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    |
    = help: the following other types implement trait `ark_ff::Field`:
              CubicExtField<P>
              ExtensionFieldWrapper<E>
              QuadExtField<P>
              ark_ff::Fp<P, N>
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Hash)]`
    |
12  + #[derive(Hash)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Neg` is not satisfied
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ the trait `Neg` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    |
    = help: the following other types implement trait `ark_ff::Field`:
              CubicExtField<P>
              ExtensionFieldWrapper<E>
              QuadExtField<P>
              ark_ff::Fp<P, N>
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: ark_std::Zero` is not satisfied
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ the trait `ark_std::Zero` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    |
    = help: the following other types implement trait `ark_std::Zero`:
              BigUint
              CubicExtField<P>
              QuadExtField<P>
              Wrapping<T>
              ark_ec::models::short_weierstrass::group::Projective<P>
              ark_ec::models::twisted_edwards::group::Projective<P>
              ark_ec::pairing::PairingOutput<P>
              ark_ff::Fp<P, N>
            and 22 others
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `std::fmt::Display`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ `ExtensionFieldWrapper<E>` cannot be formatted with the default formatter
    |
    = help: the trait `std::fmt::Display` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = note: in format strings you may be able to use `{:?}` (or {:#?} for pretty-print) instead
    = help: the following other types implement trait `ark_ff::Field`:
              CubicExtField<P>
              ExtensionFieldWrapper<E>
              QuadExtField<P>
              ark_ff::Fp<P, N>
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `Debug`
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ `ExtensionFieldWrapper<E>` cannot be formatted using `{:?}`
    |
    = help: the trait `Debug` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    = note: add `#[derive(Debug)]` to `ExtensionFieldWrapper<E>` or manually `impl Debug for ExtensionFieldWrapper<E>`
    = help: the following other types implement trait `ark_ff::Field`:
              CubicExtField<P>
              ExtensionFieldWrapper<E>
              QuadExtField<P>
              ark_ff::Fp<P, N>
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Debug)]`
    |
12  + #[derive(Debug)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `Standard: Distribution<ExtensionFieldWrapper<E>>` is not satisfied
   --> mpcs/src/whir/ff.rs:195:19
    |
195 |     type Scalar = Self;
    |                   ^^^^ the trait `Distribution<ExtensionFieldWrapper<E>>` is not implemented for `Standard`, which is required by `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar: ark_ff::Field`
    |
    = help: the following other types implement trait `Distribution<T>`:
              `Standard` implements `Distribution<()>`
              `Standard` implements `Distribution<(A, B)>`
              `Standard` implements `Distribution<(A, B, C)>`
              `Standard` implements `Distribution<(A, B, C, D)>`
              `Standard` implements `Distribution<(A, B, C, D, E)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G, H)>`
            and 72 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::UniformRand`
    = note: required for `<ExtensionFieldWrapper<E> as AdditiveGroup>::Scalar` to implement `ark_ff::Field`
note: required by a bound in `ark_ff::AdditiveGroup::Scalar`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:85:18
    |
85  |     type Scalar: Field;
    |                  ^^^^^ required by this bound in `AdditiveGroup::Scalar`

error[E0220]: associated type `BasePrimeField` not found for `E`
   --> mpcs/src/whir/ff.rs:217:30
    |
217 |     type BasePrimeField = E::BasePrimeField;
    |                              ^^^^^^^^^^^^^^ associated type `BasePrimeField` not found

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=&'a ExtensionFieldWrapper<E>>`
    |
    = help: the trait `for<'a> Sum<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=ExtensionFieldWrapper<E>>`
    |
    = help: the trait `Sum` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot subtract-assign `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot add-assign `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot subtract `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot add `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot subtract-assign `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot add-assign `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot subtract `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: cannot add `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: AdditiveGroup`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:181:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
181 |     + AdditiveGroup<Scalar = Self>
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Valid` is not satisfied
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Valid` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: CanonicalDeserialize`
    |
    = help: the following other types implement trait `Valid`:
              ()
              (A, B)
              (A, B, C)
              (A, B, C, D)
              (A, B, C, D, E)
              (A,)
              Arc<T>
              BTreeMap<K, V>
            and 58 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `CanonicalDeserialize`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:179:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
179 |     + CanonicalDeserialize
    |       ^^^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Hash` is not satisfied
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Hash` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:176:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
176 |     + Hash
    |       ^^^^ required by this bound in `Field`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Hash)]`
    |
12  + #[derive(Hash)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Neg` is not satisfied
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Neg` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:172:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
172 |     + Neg<Output = Self>
    |       ^^^^^^^^^^^^^^^^^^ required by this bound in `Field`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: ark_std::Zero` is not satisfied
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `ark_std::Zero` is not implemented for `ExtensionFieldWrapper<E>`
    |
    = help: the following other types implement trait `ark_std::Zero`:
              BigUint
              CubicExtField<P>
              QuadExtField<P>
              Wrapping<T>
              ark_ec::models::short_weierstrass::group::Projective<P>
              ark_ec::models::twisted_edwards::group::Projective<P>
              ark_ec::pairing::PairingOutput<P>
              ark_ff::Fp<P, N>
            and 22 others
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:169:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
169 |     + Zero
    |       ^^^^ required by this bound in `Field`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `std::fmt::Display`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted with the default formatter
    |
    = help: the trait `std::fmt::Display` is not implemented for `ExtensionFieldWrapper<E>`
    = note: in format strings you may be able to use `{:?}` (or {:#?} for pretty-print) instead
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:164:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
164 |     + Display
    |       ^^^^^^^ required by this bound in `Field`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `Debug`
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted using `{:?}`
    |
    = help: the trait `Debug` is not implemented for `ExtensionFieldWrapper<E>`
    = note: add `#[derive(Debug)]` to `ExtensionFieldWrapper<E>` or manually `impl Debug for ExtensionFieldWrapper<E>`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:163:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
163 |     + Debug
    |       ^^^^^ required by this bound in `Field`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Debug)]`
    |
12  + #[derive(Debug)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `Standard: Distribution<ExtensionFieldWrapper<E>>` is not satisfied
   --> mpcs/src/whir/ff.rs:212:35
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |                                   ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Distribution<ExtensionFieldWrapper<E>>` is not implemented for `Standard`, which is required by `ExtensionFieldWrapper<E>: ark_ff::UniformRand`
    |
    = help: the following other types implement trait `Distribution<T>`:
              `Standard` implements `Distribution<()>`
              `Standard` implements `Distribution<(A, B)>`
              `Standard` implements `Distribution<(A, B, C)>`
              `Standard` implements `Distribution<(A, B, C, D)>`
              `Standard` implements `Distribution<(A, B, C, D, E)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G, H)>`
            and 72 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::UniformRand`
note: required by a bound in `ark_ff::Field`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:173:7
    |
159 | pub trait Field:
    |           ----- required by a bound in this trait
...
173 |     + UniformRand
    |       ^^^^^^^^^^^ required by this bound in `Field`

error[E0053]: method `characteristic` has an incompatible type for trait
   --> mpcs/src/whir/ff.rs:285:28
    |
285 |     fn characteristic() -> Vec<u64> {
    |                            ^^^^^^^^ expected `&'static [u64]`, found `Vec<u64>`
    |
    = note: expected signature `fn() -> &'static [u64]`
               found signature `fn() -> Vec<u64>`
help: change the output type to match the trait
    |
285 |     fn characteristic() -> &'static [u64] {
    |                            ~~~~~~~~~~~~~~

error[E0599]: no method named `to_base_prime_field_elements` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:227:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `to_base_prime_field_elements` not found for this type parameter
...
227 |         self.0.to_base_prime_field_elements()
    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `to_base_prime_field_elements`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=&'a ExtensionFieldWrapper<E>>`
    |
    = help: the trait `for<'a> Sum<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: a value of type `ExtensionFieldWrapper<E>` cannot be made by summing an iterator over elements of type `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ value of type `ExtensionFieldWrapper<E>` cannot be made by summing a `std::iter::Iterator<Item=ExtensionFieldWrapper<E>>`
    |
    = help: the trait `Sum` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the following other types implement trait `Sum<A>`:
              `BigUint` implements `Sum<T>`
              `BitMask<R>` implements `Sum<BitSel<R>>`
              `CubicExtField<P>` implements `Sum<&'a CubicExtField<P>>`
              `CubicExtField<P>` implements `Sum`
              `Duration` implements `Sum<&'a Duration>`
              `Duration` implements `Sum`
              `Expression<F>` implements `Sum<&'a Expression<F>>`
              `Expression<F>` implements `Sum`
            and 125 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot subtract-assign `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot add-assign `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a mut ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot subtract `&'a mut ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot add `&'a mut ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a mut ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a mut ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a mut ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot multiply-assign `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> *= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> MulAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `MulAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot subtract-assign `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> -= &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> SubAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `SubAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot add-assign `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> += &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> AddAssign<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `AddAssign` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot multiply `ExtensionFieldWrapper<E>` by `&'a ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> * &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Mul<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Mul` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot subtract `&'a ExtensionFieldWrapper<E>` from `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> - &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Sub<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Sub` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: cannot add `&'a ExtensionFieldWrapper<E>` to `ExtensionFieldWrapper<E>`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ no implementation for `ExtensionFieldWrapper<E> + &'a ExtensionFieldWrapper<E>`
    |
    = help: the trait `for<'a> Add<&'a ExtensionFieldWrapper<E>>` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = help: the trait `Add` is implemented for `ExtensionFieldWrapper<E>`
    = help: for that trait implementation, expected `ExtensionFieldWrapper<E>`, found `&'a ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `AdditiveGroup`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Valid` is not satisfied
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Valid` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    |
    = help: the following other types implement trait `Valid`:
              ()
              (A, B)
              (A, B, C)
              (A, B, C, D)
              (A, B, C, D, E)
              (A,)
              Arc<T>
              BTreeMap<K, V>
            and 58 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `CanonicalDeserialize`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Hash` is not satisfied
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Hash` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    |
    = help: the trait `ark_ff::Field` is implemented for `ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Hash)]`
    |
12  + #[derive(Hash)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Neg` is not satisfied
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Neg` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    |
    = help: the trait `ark_ff::Field` is implemented for `ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: ark_std::Zero` is not satisfied
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `ark_std::Zero` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    |
    = help: the following other types implement trait `ark_std::Zero`:
              BigUint
              CubicExtField<P>
              QuadExtField<P>
              Wrapping<T>
              ark_ec::models::short_weierstrass::group::Projective<P>
              ark_ec::models::twisted_edwards::group::Projective<P>
              ark_ec::pairing::PairingOutput<P>
              ark_ff::Fp<P, N>
            and 22 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `std::fmt::Display`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted with the default formatter
    |
    = help: the trait `std::fmt::Display` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = note: in format strings you may be able to use `{:?}` (or {:#?} for pretty-print) instead
    = help: the trait `ark_ff::Field` is implemented for `ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `Debug`
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted using `{:?}`
    |
    = help: the trait `Debug` is not implemented for `ExtensionFieldWrapper<E>`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    = note: add `#[derive(Debug)]` to `ExtensionFieldWrapper<E>` or manually `impl Debug for ExtensionFieldWrapper<E>`
    = help: the trait `ark_ff::Field` is implemented for `ExtensionFieldWrapper<E>`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Debug)]`
    |
12  + #[derive(Debug)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `Standard: Distribution<ExtensionFieldWrapper<E>>` is not satisfied
   --> mpcs/src/whir/ff.rs:318:38
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Distribution<ExtensionFieldWrapper<E>>` is not implemented for `Standard`, which is required by `ExtensionFieldWrapper<E>: ark_ff::Field`
    |
    = help: the following other types implement trait `Distribution<T>`:
              `Standard` implements `Distribution<()>`
              `Standard` implements `Distribution<(A, B)>`
              `Standard` implements `Distribution<(A, B, C)>`
              `Standard` implements `Distribution<(A, B, C, D)>`
              `Standard` implements `Distribution<(A, B, C, D, E)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G, H)>`
            and 72 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::UniformRand`
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::Field`
note: required by a bound in `FftField`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/fft_friendly.rs:2:21
    |
2   | pub trait FftField: crate::Field {
    |                     ^^^^^^^^^^^^ required by this bound in `FftField`

error[E0308]: mismatched types
  --> mpcs/src/whir/ff.rs:16:9
   |
14 | impl<'a, E: ExtensionField> std::iter::Product for ExtensionFieldWrapper<E> {
   |          - found this type parameter
15 |     fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
   |                                                      ---- expected `ExtensionFieldWrapper<E>` because of return type
16 |         E::product(iter.map(|x| x.0))
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `ExtensionFieldWrapper<E>`, found type parameter `E`
   |
   = note:      expected struct `ExtensionFieldWrapper<E>`
           found type parameter `E`
help: try wrapping the expression in `whir::ff::ExtensionFieldWrapper`
   |
16 |         whir::ff::ExtensionFieldWrapper(E::product(iter.map(|x| x.0)))
   |         ++++++++++++++++++++++++++++++++                             +

error[E0308]: mismatched types
  --> mpcs/src/whir/ff.rs:22:9
   |
20 | impl<'a, E: ExtensionField> std::iter::Product<&'a Self> for ExtensionFieldWrapper<E> {
   |          - found this type parameter
21 |     fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
   |                                                          ---- expected `ExtensionFieldWrapper<E>` because of return type
22 |         E::product(iter.map(|x| x.0))
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `ExtensionFieldWrapper<E>`, found type parameter `E`
   |
   = note:      expected struct `ExtensionFieldWrapper<E>`
           found type parameter `E`
help: try wrapping the expression in `whir::ff::ExtensionFieldWrapper`
   |
22 |         whir::ff::ExtensionFieldWrapper(E::product(iter.map(|x| x.0)))
   |         ++++++++++++++++++++++++++++++++                             +

error[E0369]: cannot divide `E` by `E`
  --> mpcs/src/whir/ff.rs:40:21
   |
40 |         Self(self.0 / other.0)
   |              ------ ^ ------- E
   |              |
   |              E
   |
help: consider further restricting this bound
   |
36 | impl<E: ExtensionField + std::ops::Div<Output = E>> Div for ExtensionFieldWrapper<E> {
   |                        +++++++++++++++++++++++++++

error[E0369]: cannot divide `E` by `E`
  --> mpcs/src/whir/ff.rs:48:21
   |
48 |         Self(self.0 / other.0)
   |              ------ ^ ------- E
   |              |
   |              E
   |
help: consider further restricting this bound
   |
44 | impl<'a, E: ExtensionField + std::ops::Div<Output = E>> Div<&'a Self> for ExtensionFieldWrapper<E> {
   |                            +++++++++++++++++++++++++++

error[E0368]: binary assignment operation `/=` cannot be applied to type `E`
  --> mpcs/src/whir/ff.rs:54:9
   |
54 |         self.0 /= other.0;
   |         ------^^^^^^^^^^^
   |         |
   |         cannot use `/=` on type `E`
   |
help: consider further restricting this bound
   |
52 | impl<'a, E: ExtensionField + std::ops::DivAssign> DivAssign<&'a Self> for ExtensionFieldWrapper<E> {
   |                            +++++++++++++++++++++

error[E0369]: cannot divide `E` by `E`
  --> mpcs/src/whir/ff.rs:62:21
   |
62 |         Self(self.0 / other.0)
   |              ------ ^ ------- E
   |              |
   |              E
   |
help: consider further restricting this bound
   |
58 | impl<'a, E: ExtensionField + std::ops::Div<Output = E>> Div<&'a mut Self> for ExtensionFieldWrapper<E> {
   |                            +++++++++++++++++++++++++++

error[E0368]: binary assignment operation `/=` cannot be applied to type `E`
  --> mpcs/src/whir/ff.rs:68:9
   |
68 |         self.0 /= other.0;
   |         ------^^^^^^^^^^^
   |         |
   |         cannot use `/=` on type `E`
   |
help: consider further restricting this bound
   |
66 | impl<'a, E: ExtensionField + std::ops::DivAssign> DivAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
   |                            +++++++++++++++++++++

error[E0368]: binary assignment operation `/=` cannot be applied to type `E`
  --> mpcs/src/whir/ff.rs:74:9
   |
74 |         self.0 /= other.0;
   |         ------^^^^^^^^^^^
   |         |
   |         cannot use `/=` on type `E`
   |
help: consider further restricting this bound
   |
72 | impl<'a, E: ExtensionField + std::ops::DivAssign> DivAssign<Self> for ExtensionFieldWrapper<E> {
   |                            +++++++++++++++++++++

error[E0599]: no method named `zeroize` found for type parameter `E` in the current scope
  --> mpcs/src/whir/ff.rs:80:16
   |
78 | impl<E: ExtensionField> Zeroize for ExtensionFieldWrapper<E> {
   |      - method `zeroize` not found for this type parameter
79 |     fn zeroize(&mut self) {
80 |         self.0.zeroize();
   |                ^^^^^^^ method cannot be called on `E` due to unsatisfied trait bounds
   |
   = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `zeroize`, perhaps you need to restrict type parameter `E` with it:
   |
78 | impl<E: ExtensionField + Zeroize> Zeroize for ExtensionFieldWrapper<E> {
   |                        +++++++++

error[E0599]: no method named `serialize_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:114:16
    |
108 | impl<E: ExtensionField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |      - method `serialize_with_flags` not found for this type parameter
...
114 |         self.0.serialize_with_flags(writer, flags)
    |                ^^^^^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `serialize_with_flags`, perhaps you need to restrict type parameter `E` with it:
    |
108 | impl<E: ExtensionField + CanonicalSerializeWithFlags> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |                        +++++++++++++++++++++++++++++

error[E0599]: no method named `serialized_size_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:118:16
    |
108 | impl<E: ExtensionField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |      - method `serialized_size_with_flags` not found for this type parameter
...
118 |         self.0.serialized_size_with_flags::<F>()
    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `serialized_size_with_flags`, perhaps you need to restrict type parameter `E` with it:
    |
108 | impl<E: ExtensionField + CanonicalSerializeWithFlags> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |                        +++++++++++++++++++++++++++++

error[E0599]: no method named `serialize_uncompressed_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:126:16
    |
108 | impl<E: ExtensionField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |      - method `serialize_uncompressed_with_flags` not found for this type parameter
...
126 |         self.0.serialize_uncompressed_with_flags(writer, flags)
    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`

error[E0599]: no method named `uncompressed_size_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:130:16
    |
108 | impl<E: ExtensionField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    |      - method `uncompressed_size_with_flags` not found for this type parameter
...
130 |         self.0.uncompressed_size_with_flags::<F>()
    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`

error[E0599]: no function or associated item named `deserialize_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:138:12
    |
134 | impl<E: ExtensionField> CanonicalDeserializeWithFlags for ExtensionFieldWrapper<E> {
    |      - function or associated item `deserialize_with_flags` not found for this type parameter
...
138 |         E::deserialize_with_flags(reader).map(|(e, f)| (Self(e), f))
    |            ^^^^^^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `deserialize_with_flags`, perhaps you need to restrict type parameter `E` with it:
    |
134 | impl<E: ExtensionField + CanonicalDeserializeWithFlags> CanonicalDeserializeWithFlags for ExtensionFieldWrapper<E> {
    |                        +++++++++++++++++++++++++++++++

error[E0599]: no function or associated item named `deserialize_uncompressed_with_flags` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:144:12
    |
134 | impl<E: ExtensionField> CanonicalDeserializeWithFlags for ExtensionFieldWrapper<E> {
    |      - function or associated item `deserialize_uncompressed_with_flags` not found for this type parameter
...
144 |         E::deserialize_uncompressed_with_flags(reader).map(|(e, f)| (Self(e), f))
    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ function or associated item not found in `E`

error[E0599]: no function or associated item named `one` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:150:17
    |
148 | impl<E: ExtensionField> One for ExtensionFieldWrapper<E> {
    |      - function or associated item `one` not found for this type parameter
149 |     fn one() -> Self {
150 |         Self(E::one())
    |                 ^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: there is a method `ne` with a similar name, but with different arguments
   --> /Users/zhangyuncong/.rustup/toolchains/nightly-2024-10-03-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/cmp.rs:261:5
    |
261 |     fn ne(&self, other: &Rhs) -> bool {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: the following trait defines an item `one`, perhaps you need to restrict type parameter `E` with it:
    |
148 | impl<E: ExtensionField + One> One for ExtensionFieldWrapper<E> {
    |                        +++++

error[E0277]: the trait bound `E: From<u8>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<u8>` is not implemented for `E`
...
200 | impl_from_for_extension_field_wrapper!(u8);
    | ------------------------------------------ in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<u8> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 ++++++++++++++++++++++

error[E0277]: the trait bound `E: From<u16>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<u16>` is not implemented for `E`
...
201 | impl_from_for_extension_field_wrapper!(u16);
    | ------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<u16> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 +++++++++++++++++++++++

error[E0277]: the trait bound `E: From<u32>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<u32>` is not implemented for `E`
...
202 | impl_from_for_extension_field_wrapper!(u32);
    | ------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<u32> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 +++++++++++++++++++++++

error[E0277]: the trait bound `E: From<u128>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<u128>` is not implemented for `E`
...
204 | impl_from_for_extension_field_wrapper!(u128);
    | -------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<u128> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 ++++++++++++++++++++++++

error[E0277]: the trait bound `E: From<i8>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<i8>` is not implemented for `E`
...
205 | impl_from_for_extension_field_wrapper!(i8);
    | ------------------------------------------ in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<i8> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 ++++++++++++++++++++++

error[E0277]: the trait bound `E: From<i16>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<i16>` is not implemented for `E`
...
206 | impl_from_for_extension_field_wrapper!(i16);
    | ------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<i16> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 +++++++++++++++++++++++

error[E0277]: the trait bound `E: From<i32>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<i32>` is not implemented for `E`
...
207 | impl_from_for_extension_field_wrapper!(i32);
    | ------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<i32> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 +++++++++++++++++++++++

error[E0277]: the trait bound `E: From<i64>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<i64>` is not implemented for `E`
...
208 | impl_from_for_extension_field_wrapper!(i64);
    | ------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<i64> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 +++++++++++++++++++++++

error[E0277]: the trait bound `E: From<i128>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<i128>` is not implemented for `E`
...
209 | impl_from_for_extension_field_wrapper!(i128);
    | -------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<i128> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 ++++++++++++++++++++++++

error[E0277]: the trait bound `E: From<bool>` is not satisfied
   --> mpcs/src/whir/ff.rs:30:22
    |
30  |                 Self(E::from(b))
    |                      ^ the trait `From<bool>` is not implemented for `E`
...
210 | impl_from_for_extension_field_wrapper!(bool);
    | -------------------------------------------- in this macro invocation
    |
    = note: this error originates in the macro `impl_from_for_extension_field_wrapper` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider restricting type parameter `E`
    |
28  |         impl<E: std::convert::From<bool> ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
    |                 ++++++++++++++++++++++++

error[E0599]: no function or associated item named `one` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:220:31
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `one` not found for this type parameter
...
220 |     const ONE: Self = Self(E::one());
    |                               ^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: there is a method `ne` with a similar name, but with different arguments
   --> /Users/zhangyuncong/.rustup/toolchains/nightly-2024-10-03-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/cmp.rs:261:5
    |
261 |     fn ne(&self, other: &Rhs) -> bool {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: the following trait defines an item `one`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + One> Field for ExtensionFieldWrapper<E>
    |                        +++++

error[E0599]: no function or associated item named `extension_degree` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:223:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `extension_degree` not found for this type parameter
...
223 |         E::extension_degree()
    |            ^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `extension_degree`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no function or associated item named `from_base_prime_field_elems` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:233:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `from_base_prime_field_elems` not found for this type parameter
...
233 |         E::from_base_prime_field_elems(elems).map(Self)
    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `from_base_prime_field_elems`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no function or associated item named `from_base_prime_field` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:237:17
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `from_base_prime_field` not found for this type parameter
...
237 |         Self(E::from_base_prime_field(elem))
    |                 ^^^^^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `from_base_prime_field`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no function or associated item named `from_random_bytes` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:241:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `from_random_bytes` not found for this type parameter
...
241 |         E::from_random_bytes(bytes).map(|x| (Self(x), F::default()))
    |            ^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `from_random_bytes`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + ark_ec::AffineRepr> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
help: there is an associated function `from_uniform_bytes` with a similar name
    |
241 |         E::from_uniform_bytes(bytes).map(|x| (Self(x), F::default()))
    |            ~~~~~~~~~~~~~~~~~~

error[E0599]: no method named `legendre` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:245:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `legendre` not found for this type parameter
...
245 |         self.0.legendre()
    |                ^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `legendre`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no method named `square_in_place` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:253:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `square_in_place` not found for this type parameter
...
253 |         self.0.square_in_place();
    |                ^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `square_in_place`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + FpConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++
212 | impl<E: ExtensionField + MontConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no method named `inverse` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:258:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `inverse` not found for this type parameter
...
258 |         self.0.inverse().map(Self)
    |                ^^^^^^^
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `inverse`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + FpConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++
212 | impl<E: ExtensionField + MontConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
212 | impl<E: ExtensionField + plonky2::plonky2_field::types::Field> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++++++++++++++++++++
help: there is a method `invert` with a similar name
    |
258 |         self.0.invert().map(Self)
    |                ~~~~~~

error[E0599]: no method named `inverse_in_place` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:262:33
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `inverse_in_place` not found for this type parameter
...
262 |         if let Some(_) = self.0.inverse_in_place() {
    |                                 ^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `inverse_in_place`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no method named `frobenius_map_in_place` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:270:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `frobenius_map_in_place` not found for this type parameter
...
270 |         self.0.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `frobenius_map_in_place`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no method named `mul_by_base_prime_field` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:274:21
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `mul_by_base_prime_field` not found for this type parameter
...
274 |         Self(self.0.mul_by_base_prime_field(elem))
    |                     ^^^^^^^^^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following trait defines an item `mul_by_base_prime_field`, perhaps you need to restrict type parameter `E` with it:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++

error[E0599]: no function or associated item named `zero` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:278:17
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `zero` not found for this type parameter
...
278 |         Self(E::zero())
    |                 ^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `zero`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + ark_ec::AffineRepr> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++
212 | impl<E: ExtensionField + ark_std::Zero> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
212 | impl<E: ExtensionField + zerocopy::FromZeroes> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++++
help: there is a method `is_zero` with a similar name
    |
278 |         Self(E::is_zero())
    |                 ~~~~~~~

error[E0308]: mismatched types
   --> mpcs/src/whir/ff.rs:282:9
    |
281 |     fn is_zero(&self) -> bool {
    |                          ---- expected `bool` because of return type
282 |         self.0.is_zero()
    |         ^^^^^^^^^^^^^^^^ expected `bool`, found `Choice`
    |
help: call `Into::into` on this expression to convert `subtle::Choice` into `bool`
    |
282 |         self.0.is_zero().into()
    |                         +++++++

error[E0599]: no function or associated item named `characteristic` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:286:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `characteristic` not found for this type parameter
...
286 |         E::characteristic()
    |            ^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `characteristic`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
212 | impl<E: ExtensionField + plonky2::plonky2_field::types::Field> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++++++++++++++++++++

error[E0599]: no function or associated item named `from_random_bytes` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:290:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `from_random_bytes` not found for this type parameter
...
290 |         E::from_random_bytes(bytes).map(Self)
    |            ^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `from_random_bytes`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + ark_ec::AffineRepr> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
help: there is an associated function `from_uniform_bytes` with a similar name
    |
290 |         E::from_uniform_bytes(bytes).map(Self)
    |            ~~~~~~~~~~~~~~~~~~

error[E0599]: no function or associated item named `from_random_bytes` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:294:12
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - function or associated item `from_random_bytes` not found for this type parameter
...
294 |         E::from_random_bytes(bytes).map(|x| (Self(x), EmptyFlags))
    |            ^^^^^^^^^^^^^^^^^ function or associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `from_random_bytes`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + ark_ec::AffineRepr> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++++++++++
212 | impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
help: there is an associated function `from_uniform_bytes` with a similar name
    |
294 |         E::from_uniform_bytes(bytes).map(|x| (Self(x), EmptyFlags))
    |            ~~~~~~~~~~~~~~~~~~

error[E0599]: no method named `double_in_place` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:302:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `double_in_place` not found for this type parameter
...
302 |         self.0.double_in_place();
    |                ^^^^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `double_in_place`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + AdditiveGroup> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
212 | impl<E: ExtensionField + FpConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++
212 | impl<E: ExtensionField + MontConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++

error[E0599]: no method named `neg_in_place` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:307:16
    |
212 | impl<E: ExtensionField> Field for ExtensionFieldWrapper<E>
    |      - method `neg_in_place` not found for this type parameter
...
307 |         self.0.neg_in_place();
    |                ^^^^^^^^^^^^ method not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `neg_in_place`, perhaps you need to restrict type parameter `E` with one of them:
    |
212 | impl<E: ExtensionField + AdditiveGroup> Field for ExtensionFieldWrapper<E>
    |                        +++++++++++++++
212 | impl<E: ExtensionField + FpConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++
212 | impl<E: ExtensionField + MontConfig> Field for ExtensionFieldWrapper<E>
    |                        ++++++++++++

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `Debug`
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted using `{:?}`
    |
    = help: the trait `Debug` is not implemented for `ExtensionFieldWrapper<E>`
    = note: add `#[derive(Debug)]` to `ExtensionFieldWrapper<E>` or manually `impl Debug for ExtensionFieldWrapper<E>`
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:163:7
    |
163 |     + Debug
    |       ^^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Debug)]`
    |
12  + #[derive(Debug)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: `ExtensionFieldWrapper<E>` doesn't implement `std::fmt::Display`
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ `ExtensionFieldWrapper<E>` cannot be formatted with the default formatter
    |
    = help: the trait `std::fmt::Display` is not implemented for `ExtensionFieldWrapper<E>`
    = note: in format strings you may be able to use `{:?}` (or {:#?} for pretty-print) instead
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:164:7
    |
164 |     + Display
    |       ^^^^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: ark_std::Zero` is not satisfied
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ the trait `ark_std::Zero` is not implemented for `ExtensionFieldWrapper<E>`
    |
    = help: the following other types implement trait `ark_std::Zero`:
              BigUint
              CubicExtField<P>
              QuadExtField<P>
              Wrapping<T>
              ark_ec::models::short_weierstrass::group::Projective<P>
              ark_ec::models::twisted_edwards::group::Projective<P>
              ark_ec::pairing::PairingOutput<P>
              ark_ff::Fp<P, N>
            and 22 others
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:169:7
    |
169 |     + Zero
    |       ^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Neg` is not satisfied
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ the trait `Neg` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:172:7
    |
172 |     + Neg<Output = Self>
    |       ^^^^^^^^^^^^^^^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function

error[E0277]: the trait bound `ExtensionFieldWrapper<E>: Hash` is not satisfied
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ the trait `Hash` is not implemented for `ExtensionFieldWrapper<E>`
    |
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:176:7
    |
176 |     + Hash
    |       ^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function
help: consider annotating `ExtensionFieldWrapper<E>` with `#[derive(Hash)]`
    |
12  + #[derive(Hash)]
13  | pub struct ExtensionFieldWrapper<E: ExtensionField>(E);
    |

error[E0277]: the trait bound `Standard: Distribution<ExtensionFieldWrapper<E>>` is not satisfied
   --> mpcs/src/whir/ff.rs:313:16
    |
313 |         result.frobenius_map_in_place(power);
    |                ^^^^^^^^^^^^^^^^^^^^^^ the trait `Distribution<ExtensionFieldWrapper<E>>` is not implemented for `Standard`, which is required by `ExtensionFieldWrapper<E>: ark_ff::UniformRand`
    |
    = help: the following other types implement trait `Distribution<T>`:
              `Standard` implements `Distribution<()>`
              `Standard` implements `Distribution<(A, B)>`
              `Standard` implements `Distribution<(A, B, C)>`
              `Standard` implements `Distribution<(A, B, C, D)>`
              `Standard` implements `Distribution<(A, B, C, D, E)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G)>`
              `Standard` implements `Distribution<(A, B, C, D, E, F, G, H)>`
            and 72 others
    = note: required for `ExtensionFieldWrapper<E>` to implement `ark_ff::UniformRand`
note: required by a bound in `frobenius_map_in_place`
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/fields/mod.rs:173:7
    |
173 |     + UniformRand
    |       ^^^^^^^^^^^ required by this bound in `Field::frobenius_map_in_place`
...
305 |     fn frobenius_map_in_place(&mut self, power: usize);
    |        ---------------------- required by a bound in this associated function

error[E0599]: no associated item named `GENERATOR` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:319:37
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |      - associated item `GENERATOR` not found for this type parameter
319 |     const GENERATOR: Self = Self(E::GENERATOR);
    |                                     ^^^^^^^^^ associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `GENERATOR`, perhaps you need to restrict type parameter `E` with one of them:
    |
318 | impl<E: ExtensionField + FftField> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + FpConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + MontConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++++
318 | impl<E: ExtensionField + ark_ec::models::short_weierstrass::SWCurveConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++++++++++++++++++++++++++++++++++++++++++
      and 1 other candidate

error[E0599]: no associated item named `TWO_ADICITY` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:321:33
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |      - associated item `TWO_ADICITY` not found for this type parameter
...
321 |     const TWO_ADICITY: u32 = E::TWO_ADICITY;
    |                                 ^^^^^^^^^^^ associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `TWO_ADICITY`, perhaps you need to restrict type parameter `E` with one of them:
    |
318 | impl<E: ExtensionField + FftField> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + Fp3Config> FftField for ExtensionFieldWrapper<E> {
    |                        +++++++++++
318 | impl<E: ExtensionField + FpConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + plonky2::plonky2_field::types::Field> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++++++++++++++++++++++++++++++

error[E0599]: no associated item named `TWO_ADIC_ROOT_OF_UNITY` found for type parameter `E` in the current scope
   --> mpcs/src/whir/ff.rs:323:50
    |
318 | impl<E: ExtensionField> FftField for ExtensionFieldWrapper<E> {
    |      - associated item `TWO_ADIC_ROOT_OF_UNITY` not found for this type parameter
...
323 |     const TWO_ADIC_ROOT_OF_UNITY: Self = Self(E::TWO_ADIC_ROOT_OF_UNITY);
    |                                                  ^^^^^^^^^^^^^^^^^^^^^^ associated item not found in `E`
    |
    = help: items from traits can only be used if the type parameter is bounded by the trait
help: the following traits define an item `TWO_ADIC_ROOT_OF_UNITY`, perhaps you need to restrict type parameter `E` with one of them:
    |
318 | impl<E: ExtensionField + FftField> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + FpConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++
318 | impl<E: ExtensionField + MontConfig> FftField for ExtensionFieldWrapper<E> {
    |                        ++++++++++++
help: there is an associated constant `ROOT_OF_UNITY` with a similar name
    |
323 |     const TWO_ADIC_ROOT_OF_UNITY: Self = Self(E::ROOT_OF_UNITY);
    |                                                  ~~~~~~~~~~~~~

error[E0308]: mismatched types
  --> mpcs/src/whir/fp.rs:18:27
   |
18 |         BigInt::<1>::new([<E::BaseField as PrimeField>::MULTIPLICATIVE_GENERATOR]),
   |                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `u64`, found associated type
   |
   = note:         expected type `u64`
           found associated type `<E as ff_ext::ExtensionField>::BaseField`
help: consider constraining the associated type `<E as ff_ext::ExtensionField>::BaseField` to `u64`
   |
14 | impl<E: ExtensionField<BaseField = u64>> FpConfig<1> for FpConfigBaseFieldOf<E> {
   |                       +++++++++++++++++

error[E0308]: mismatched types
   --> mpcs/src/whir/fp.rs:29:26
    |
29  |         BigInt::<1>::new(<E::BaseField as PrimeField>::ROOT_OF_UNITY),
    |         ---------------- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `[u64; 1]`, found associated type
    |         |
    |         arguments to this function are incorrect
    |
    = note:        expected array `[u64; 1]`
            found associated type `<E as ff_ext::ExtensionField>::BaseField`
note: associated function defined here
   --> /Users/zhangyuncong/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ark-ff-0.5.0/src/biginteger/mod.rs:129:18
    |
129 |     pub const fn new(value: [u64; N]) -> Self {
    |                  ^^^
help: consider constraining the associated type `<E as ff_ext::ExtensionField>::BaseField` to `[u64; 1]`
    |
14  | impl<E: ExtensionField<BaseField = [u64; 1]>> FpConfig<1> for FpConfigBaseFieldOf<E> {
    |                       ++++++++++++++++++++++

warning: unused variable: `compress`
  --> mpcs/src/whir/ff.rs:93:31
   |
93 |     fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
   |                               ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_compress`
   |
   = note: `#[warn(unused_variables)]` on by default

warning: unused variable: `compress`
   --> mpcs/src/whir/ff.rs:101:9
    |
101 |         compress: ark_serialize::Compress,
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_compress`

warning: unused variable: `validate`
   --> mpcs/src/whir/ff.rs:102:9
    |
102 |         validate: ark_serialize::Validate,
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_validate`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:36:19
   |
36 |     fn add_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                   ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `b`
  --> mpcs/src/whir/fp.rs:36:48
   |
36 |     fn add_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                                                ^ help: if this is intentional, prefix it with an underscore: `_b`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:40:19
   |
40 |     fn sub_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                   ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `b`
  --> mpcs/src/whir/fp.rs:40:48
   |
40 |     fn sub_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                                                ^ help: if this is intentional, prefix it with an underscore: `_b`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:44:24
   |
44 |     fn double_in_place(a: &mut ark_ff::Fp<Self, 1>) {
   |                        ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:48:21
   |
48 |     fn neg_in_place(a: &mut ark_ff::Fp<Self, 1>) {
   |                     ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:52:19
   |
52 |     fn mul_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                   ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `b`
  --> mpcs/src/whir/fp.rs:52:48
   |
52 |     fn mul_assign(a: &mut ark_ff::Fp<Self, 1>, b: &ark_ff::Fp<Self, 1>) {
   |                                                ^ help: if this is intentional, prefix it with an underscore: `_b`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:57:9
   |
57 |         a: &[ark_ff::Fp<Self, 1>; T],
   |         ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `b`
  --> mpcs/src/whir/fp.rs:58:9
   |
58 |         b: &[ark_ff::Fp<Self, 1>; T],
   |         ^ help: if this is intentional, prefix it with an underscore: `_b`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:63:24
   |
63 |     fn square_in_place(a: &mut ark_ff::Fp<Self, 1>) {
   |                        ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `a`
  --> mpcs/src/whir/fp.rs:67:16
   |
67 |     fn inverse(a: &ark_ff::Fp<Self, 1>) -> Option<ark_ff::Fp<Self, 1>> {
   |                ^ help: if this is intentional, prefix it with an underscore: `_a`

warning: unused variable: `other`
  --> mpcs/src/whir/fp.rs:71:20
   |
71 |     fn from_bigint(other: ark_ff::BigInt<1>) -> Option<ark_ff::Fp<Self, 1>> {
   |                    ^^^^^ help: if this is intentional, prefix it with an underscore: `_other`

warning: unused variable: `other`
  --> mpcs/src/whir/fp.rs:75:20
   |
75 |     fn into_bigint(other: ark_ff::Fp<Self, 1>) -> ark_ff::BigInt<1> {
   |                    ^^^^^ help: if this is intentional, prefix it with an underscore: `_other`

warning: unused variable: `fe`
  --> mpcs/src/whir/fp.rs:93:37
   |
93 |     fn mul_base_field_by_frob_coeff(fe: &mut Self::BaseField, power: usize) {
   |                                     ^^ help: if this is intentional, prefix it with an underscore: `_fe`

warning: unused variable: `power`
  --> mpcs/src/whir/fp.rs:93:63
   |
93 |     fn mul_base_field_by_frob_coeff(fe: &mut Self::BaseField, power: usize) {
   |                                                               ^^^^^ help: if this is intentional, prefix it with an underscore: `_power`

Some errors have detailed explanations: E0053, E0201, E0220, E0277, E0308, E0368, E0369, E0407, E0599.
For more information about an error, try `rustc --explain E0053`.
warning: `mpcs` (lib) generated 26 warnings
error: could not compile `mpcs` (lib) due to 164 previous errors; 26 warnings emitted
