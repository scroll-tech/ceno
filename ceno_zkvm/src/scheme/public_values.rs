use goldilocks::SmallField;
use paste::paste;
use serde::{Deserialize, Serialize};

macro_rules! define_public_values {
    ($struct_name:ident, { $($field_name:ident: [$field_type:ty; $size:expr]),* }) => {
        #[derive(Default, Serialize, Deserialize)]
        pub struct $struct_name<T: Clone + Into<u64>> {
            $(
                pub $field_name: [T; $size],
            )*
        }

            // implement methods for the public value
            impl<T: Clone + Into<u64>> $struct_name<T> {
                // define field index as constant
                define_public_values!(@internal 0usize, $($field_name => $size),*);

                paste! {
                    // getter
                    $(
                    pub fn $field_name(&self) -> &[T] {
                        &self.$field_name
                    }

                    // setter
                    pub fn [<set _ $field_name>](&mut self, value: [T; $size]) {
                        self.$field_name = value;
                    }
                    )*
                }

                /// to_vec
                pub fn to_vec<F: SmallField>(&self) -> Vec<F> {
                    let mut result = Vec::new();
                    $(
                        result.extend(self.$field_name.iter().cloned().map(|v| F::from(v.into())).collect::<Vec<_>>());
                    )*
                    result
                }
        }
    };

    // generate field index as constant
    (@internal $offset:expr, $field_name:ident => $size:expr $(, $rest:ident => $rest_size:expr)*) => {
        paste! {
            pub const [<$field_name:upper _ IDX>]: usize = $offset;
        }
        define_public_values!(@internal $offset + $size, $($rest => $rest_size),*);
    };


    (@internal $offset:expr,) => {};
}

define_public_values!(InnerPublicValues, {
    exit_code: [T; 2],
    end_pc: [T; 1]
});

#[cfg(feature = "riv32")]
pub type PublicValues = InnerPublicValues<u32>;
#[cfg(feature = "riv64")]
pub type PublicValues = InnerPublicValues<u64>;

#[cfg(test)]
mod tests {
    use super::InnerPublicValues;

    #[test]
    fn test_public_values() {
        type F = goldilocks::Goldilocks;
        let mut pi = InnerPublicValues::default();

        // setter
        pi.set_exit_code([1u32, 2]);
        pi.set_end_pc([3]);

        // test getter
        assert!(pi.exit_code()[0] == 1);
        assert!(pi.exit_code()[1] == 2);
        assert!(pi.end_pc()[0] == 3);

        // test to_vec
        let pi_vec = pi.to_vec::<F>();
        assert!(pi_vec[InnerPublicValues::<u32>::EXIT_CODE_IDX] == F::from(1));
        assert!(pi_vec[InnerPublicValues::<u32>::EXIT_CODE_IDX + 1] == F::from(2));
        assert!(pi_vec[InnerPublicValues::<u32>::END_PC_IDX] == F::from(3));
    }
}
