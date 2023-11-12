//! This module defines our customized field trait.

use ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::Goldilocks;

pub trait SmallField: PrimeField + Serialize {}

impl SmallField for Goldilocks {}
