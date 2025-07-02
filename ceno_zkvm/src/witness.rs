#[macro_export]
macro_rules! set_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.id as usize] = $val.into_f();
    };
}

#[macro_export]
macro_rules! set_fixed_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.0] = $val;
    };
}

pub type MultiplicityRaw<K> = gkr_iop::utils::lk_multiplicity::MultiplicityRaw<K>;
pub type Multiplicity<K> = gkr_iop::utils::lk_multiplicity::Multiplicity<K>;
pub type LkMultiplicity = gkr_iop::utils::lk_multiplicity::LkMultiplicity;
