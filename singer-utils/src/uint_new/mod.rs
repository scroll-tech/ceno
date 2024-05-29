mod constants;
mod uint;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uint_new::uint::UInt;

    #[test]
    fn hello_bye() {
        UInt::<5, 6>::hello();
        UInt::<5, 6>::bye();
    }
}
