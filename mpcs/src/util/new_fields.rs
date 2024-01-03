use std::time::Instant;
use core::fmt;
use halo2_curves::ff::{PrimeField};
use serde::{Serialize, Deserialize};
use ff::{PrimeFieldBits,BatchInvert};
use std::ops::{Shr, BitAnd};
use rand::RngCore;
use std::fmt::{Display,Formatter,Debug};
use core::{iter::{Product,Sum}, ops::{Add,Mul,AddAssign, Sub, SubAssign, Neg, Div, DivAssign, MulAssign}};
use subtle::{ConstantTimeEq,Choice,ConditionallySelectable,CtOption};
use rand::SeedableRng;
use crate::util::{BigUint, {arithmetic::{modulus,Field}}};
#[derive(PrimeField,Serialize,Deserialize,Hash)]
#[PrimeFieldModulus = "170141183460469231731687303715884105727"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Mersenne127([u64;2]);




#[derive(Eq,Copy,Clone,Default, fmt::Debug, Serialize, Deserialize,Hash)]
pub struct Mersenne61{
    value: u64
}
impl From<u64> for Mersenne61{

    fn from(val:u64) -> Self{
	Self{value: val}
    }

}
impl PrimeField for Mersenne61{
    type Repr = [u8;8];
    const MODULUS: &'static str = "1FFFFFFFFFFFFFFF";
    const NUM_BITS:u32 = 64;
    const CAPACITY: u32 = 61;
    const TWO_INV: Self = Self::ZERO; //todo;
    const MULTIPLICATIVE_GENERATOR:Self = Self{ value: 7 }; //todo

    const S: u32 = 3;

    const ROOT_OF_UNITY: Self = Self::ONE; //todo

    const ROOT_OF_UNITY_INV: Self = Self::ONE; //todo

    const DELTA:Self = Self::ONE; //todo
    fn from_repr(repr: Self::Repr) -> CtOption<Self>{
	CtOption::new(Self{ value: u64::from_le_bytes(repr) }, Choice::from(1u8))
    }

    fn to_repr(&self) -> Self::Repr{
	self.value.to_le_bytes()
    }


    fn is_odd(&self) -> Choice{
	if(self.value %2 == 0){
	    return Choice::from(0u8);
	}
	else{
	    return Choice::from(1u8);
	}
    }    

}
impl Mersenne61 {
    const ORDER: u64 = (1 << 61) - 1;
    const TWO:Self = Self{ value: 2 };
    const NEG_ONE:Self = Self{ value: Self::ORDER - 1};
    fn new(value: u64) -> Self {
	if value == Self::ORDER{
	    return Self::ZERO;
	}
        let hi = (value >> 61);
	if(hi == 0){
	    return Self{ value };
	}

        let lo = value & Self::ORDER;
	let res = unsafe { lo.unchecked_add(hi) };
        Self{ value: res }
    }
}

#[test]

fn bench_new(){
    type F = Mersenne61;

    let now = Instant::now();
    let el = Mersenne61::new(4345233423);
    println!("now elapsed {:?}", now.elapsed());

}
impl PartialEq for Mersenne61 {
    fn eq(&self, other: &Self) -> bool {
	let mut val1 = self.value;
	let mut val2 = other.value;
        if self.value == Self::ORDER{
	    val1 = 0;
	}
	if other.value == Self::ORDER{
	    val2 = 0;
	}

	val1 == val2
    }
}
impl ConstantTimeEq for Mersenne61{
    fn ct_eq(&self, other:&Self) -> Choice{
	if self == other{
	    return Choice::from(1u8);
	}
	else{
	    return Choice::from(0u8);
	}
    }

}


impl ConditionallySelectable for Mersenne61{
    fn conditional_select(a:&Self, b: &Self, choice:Choice) -> Self{
	let mut res = Self::ZERO;
	if choice.unwrap_u8() == 0{
	    res = *a;
	}
	else {
	    res = *b;
	}
	res
    }

}

#[test]
fn test_conditional_select(){
    type F = Mersenne61;
    assert_eq!(F::conditional_select(&F::ZERO,&F::ONE,Choice::from(0)), F::ZERO);
    assert_eq!(F::conditional_select(&F::ZERO,&F::ONE,Choice::from(1)), F::ONE);    
}

impl Ord for Mersenne61 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for Mersenne61 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Mersenne61 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.value, f)
    }
}

impl Add for Mersenne61 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
	let res = unsafe{ self.value.unchecked_add(rhs.value) };
	Self::new(res)	

    }
}


impl<'r> Add<&'r Mersenne61> for Mersenne61 {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self {
	self + *rhs
    }
}

impl AddAssign for Mersenne61 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'r> AddAssign<&'r Mersenne61> for Mersenne61 {
    fn add_assign(&mut self, rhs: &'r Self) {
        *self = *self + *rhs;
    }
}

impl<'r> Product<&'r Mersenne61> for Mersenne61 {
    fn product<I: Iterator<Item = &'r Self>>(iter: I) -> Self {
	assert!(1==0,"do not use this function");
	Self::ZERO
    }
}


impl Product for Mersenne61 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::ONE)
    }
}


impl<'r> Sum<&'r Mersenne61> for Mersenne61 {
    fn sum<I: Iterator<Item = &'r Self>>(iter: I) -> Self {
	assert!(1==0,"do not use this function");
	Self::ZERO
//        *iter.reduce(|x, y| &(*x + *y)).unwrap_or(&Self::ZERO)
    }
}


impl Sum for Mersenne61 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}


impl Sub for Mersenne61 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        // TODO: Very naive for now.
        self + (-rhs)
    }
}

impl<'r> Sub<&'r Mersenne61> for Mersenne61 {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self {
        // TODO: Very naive for now.
        self + (-*rhs)
    }
}

impl SubAssign for Mersenne61 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}


impl<'r> SubAssign<&'r Mersenne61> for Mersenne61 {
    fn sub_assign(&mut self, rhs: &'r Self) {
        *self = *self - *rhs;
    }
}

impl Neg for Mersenne61 {
    type Output = Self;

    fn neg(self) -> Self::Output {
	let hi = self.value >> 61;
	if(hi == 0){
	    let res = unsafe { Self::ORDER.unchecked_sub(self.value) };
	    return Self{ value: res };
	}
        let lo = (self.value) & ((1 << 61) - 1);
	let sum = unsafe { lo.unchecked_add(hi) };
	let res = unsafe { Self::ORDER.unchecked_sub(sum) };
        Self { value: res }
    }
}

impl Mul for Mersenne61 {
    type Output = Self;

    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: Self) -> Self {
        let prod:u128 = unsafe { u128::from(self.value).unchecked_mul(u128::from(rhs.value)) };
	let prod_lo:u64 = (prod as u64) & Self::ORDER;
        let prod_hi:u64 = (prod >> 61) as u64;

	let red = unsafe { prod_lo.unchecked_add(prod_hi) };

	Self::new(red)

    }
}


impl<'r> Mul<&'r Mersenne61> for Mersenne61 {
    type Output = Self;

    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: &Self) -> Self {
        let prod:u128 = unsafe { u128::from(self.value).unchecked_mul(u128::from(rhs.value)) };
	let prod_lo:u64 = (prod as u64) & Self::ORDER;
        let prod_hi:u64 = (prod >> 61) as u64;

	let red = unsafe { prod_lo.unchecked_add(prod_hi) };

	Self::new(red)

    }
}


impl<'r> MulAssign<&'r Mersenne61> for Mersenne61{
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * *rhs;
    }

}

impl MulAssign for Mersenne61 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}


  

impl Div for Mersenne61 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.invert().unwrap()
    }
}

impl DivAssign for Mersenne61 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self * rhs.invert().unwrap();
    }
}

impl<'r> DivAssign<&'r Mersenne61> for Mersenne61 {
    fn div_assign(&mut self, rhs: &Self) {
        *self = *self * rhs.invert().unwrap();
    }
}





impl Field for Mersenne61 {
    const ZERO: Self = Self { value: 0 };
    const ONE: Self = Self { value: 1 };    

   fn random(mut rng: impl RngCore) -> Self {
      loop {
	  let next_u61 = rng.next_u64() >> 4;
	  let is_canonical = next_u61 != Mersenne61::ORDER;
	  if is_canonical {
           return Mersenne61::new(next_u61);
	  }
      }
   }



    fn double(&self) -> Self{
	*self + *self
    }

    fn square(&self) -> Self{
	*self * *self

    }
    fn invert(&self) -> CtOption<Self> {
	let res = extended_euclidean_algorithm(self.value as i64, Self::ORDER as i64);


	if(res.1 < 0){
	    return CtOption::new(-Self{value:res.1.abs() as u64},Choice::from(1u8))
	}
	else{
	    return CtOption::new(Self{value:res.1 as u64},Choice::from(1u8))
	}
    }

    fn sqrt(&self) -> CtOption<Self> {
	assert!(1 == 0, "do not use this function");
       /// `(t - 1) // 2` where t * 2^s + 1 = p with t odd.
	CtOption::new(Self::ZERO,Choice::from(0u8))
    }

    fn sqrt_ratio(num:&Self,div:&Self) -> (Choice,Self){
	assert!(1 == 0, "do not use this function");
       /// `(t - 1) // 2` where t * 2^s + 1 = p with t odd.
       (Choice::from(0u8),Self::ZERO)
    }    

}

fn update_step(a: &mut i64, old_a: &mut i64, quotient: i64) {
    let temp = *a;
    *a = *old_a - quotient * temp;
    *old_a = temp;
}

pub fn extended_euclidean_algorithm(a: i64, b: i64) -> (i64, i64, i64) {
    let (mut old_r, mut rem) = (a, b);
    let (mut old_s, mut coeff_s) = (1, 0);
    let (mut old_t, mut coeff_t) = (0, 1);

    while rem != 0 {
        let quotient = old_r / rem;

        update_step(&mut rem, &mut old_r, quotient);
        update_step(&mut coeff_s, &mut old_s, quotient);
        update_step(&mut coeff_t, &mut old_t, quotient);
    }

    (old_r, old_s, old_t)
}

use rand_chacha::ChaCha12Rng;

    #[test]
fn add() {
    type F = Mersenne61;
    assert_eq!(F::ONE + F::ONE, F::TWO);
    assert_eq!(F::NEG_ONE + F::ONE, F::ZERO);
    assert_eq!(F::NEG_ONE + F::TWO, F::ONE);
    assert_eq!(F::NEG_ONE + F::NEG_ONE, F::new(F::ORDER - 2));
    }

    #[test]
fn sub() {
        type F = Mersenne61;
        assert_eq!(F::ONE - F::ONE, F::ZERO);
        assert_eq!(F::TWO - F::TWO, F::ZERO);
        assert_eq!(F::NEG_ONE - F::NEG_ONE, F::ZERO);
        assert_eq!(F::TWO - F::ONE, F::ONE);
        assert_eq!(F::NEG_ONE - F::ZERO, F::NEG_ONE);
    }

    #[test]
fn mul(){
    let mut rng = ChaCha12Rng::from_entropy();    
    type F = Mersenne61;

    assert_eq!(F::ONE * F::new((1 as u64) << 61), F::new((1 as u64) << 61));
    let el1 = F::random(&mut rng);
    let el2 = F::random(&mut rng);
    let s = F::random(&mut rng);
    assert_eq!(s*(el1 - el2), s*el1 - s*el2);
}


#[test]
fn inverse() {
    type F = Mersenne61;
    let mut rng = ChaCha12Rng::from_entropy();
    for i in 0..1000{
	let el = F::random(&mut rng);
	let inverse = el.invert().unwrap();
	assert_eq!(el * inverse, F::ONE);
    }
}

#[test]
fn is_zero(){
    type F= Mersenne61;
    let zero = F::ZERO;
    assert_eq!(zero.is_zero().unwrap_u8(),Choice::from(1u8).unwrap_u8());    

    let el = F{value:F::ORDER };
    let prod = el*F::ONE;
    assert_eq!(prod.is_zero().unwrap_u8(),Choice::from(1u8).unwrap_u8());    
    
}
    
    #[test]
fn test_batch_inverse(){
    type F = Mersenne61;
    let mut rng = ChaCha12Rng::from_entropy();
    let els:Vec<F> = (0..1000).map(|_| F::random(&mut rng)).collect();

    let mut inverses = els.clone();
    assert_eq!(inverses,els);
    inverses.iter_mut().batch_invert();
    for i in 0..els.len(){
	assert_eq!(els[i]*inverses[i],F::ONE);
	assert_eq!(els[i].invert().unwrap(), inverses[i]);
	assert_eq!(els[i].invert().unwrap(), F::ONE/els[i]);
	assert_eq!(els[i] * inverses[i], F::ONE);
	}
    }

#[test]
fn batch_inversion() {
    use ff::{BatchInverter, Field};
    let mut rng = ChaCha12Rng::from_entropy();
    let one = Mersenne61::ONE;
    type F = Mersenne61;


    let els:Vec<F> = (0..1000).map(|_| F::random(&mut rng)).collect();    
    let values: Vec<_> = els.iter()
        .scan(one, |acc, _| {
            let ret = *acc;
            *acc += &one;
            Some(ret)
        })
        .collect();

    // Test BatchInverter::invert_with_external_scratch
    {
        let mut elements = values.clone();
        let mut scratch_space = vec![Mersenne61::ZERO; elements.len()];
        BatchInverter::invert_with_external_scratch(&mut elements, &mut scratch_space);
        for (a, a_inv) in values.iter().zip(elements.into_iter()) {
            assert_eq!(*a * a_inv, one);
        }
    }

    // Test BatchInverter::invert_with_internal_scratch
    {
        let mut items: Vec<_> = values.iter().cloned().map(|p| (p, one)).collect();
        BatchInverter::invert_with_internal_scratch(
            &mut items,
            |item| &mut item.0,
            |item| &mut item.1,
        );
        for (a, (a_inv, _)) in values.iter().zip(items.into_iter()) {
            assert_eq!(*a * a_inv, one);
        }
    }
}



    #[test]
    fn test_basic_arith(){
	use rand::{rngs::OsRng, Rng};
	use ff::Field;
	
	let mut rng = OsRng; 
	type F = Mersenne61;
	let a = F::random(&mut rng);
	let b = F::random(&mut rng);
	let sum = a + b;
	let c = F::random(&mut rng);
	let prod = sum*c;
	assert_eq!(a*c + b*c, prod);
    }

#[test]
fn compare_mult(){
    let mut rng = ChaCha12Rng::from_entropy();
    type F1 = Mersenne127;
    type F2 = Mersenne61;
    let m127 = Instant::now();
    F1::random(&mut rng) * F1::random(&mut rng);
    println!("m127 time {:?}", m127.elapsed());

    let m61 = Instant::now();
    F2::random(&mut rng) * F2::random(&mut rng);
    println!("m61 time {:?}", m61.elapsed());

    
}
