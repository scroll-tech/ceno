use std::array;

use ceno_rt::syscalls::{
    syscall_keccak_permute, syscall_secp256k1_add, syscall_secp256k1_decompress,
    syscall_secp256k1_double, syscall_sha256_extend,
};

/// One unit test for each implemented syscall
/// Meant to be used identically in a sp1 guest to confirm compatibility
pub fn test_syscalls() {
    /// `bytes` is expected to contain the uncompressed representation of
    /// a curve point, as described in https://docs.rs/secp/latest/secp/struct.Point.html
    ///
    /// The return value is an array of words compatible with the sp1 syscall for `add` and `double`
    /// Notably, these words should encode the X and Y coordinates of the point
    /// in "little endian" and not "big endian" as is the case of secp
    fn bytes_to_words(bytes: [u8; 65]) -> [u32; 16] {
        // ignore the tag byte (specific to the secp repr.)
        let mut bytes: [u8; 64] = bytes[1..].try_into().unwrap();

        // Reverse the order of bytes for each coordinate
        bytes[0..32].reverse();
        bytes[32..].reverse();
        std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
    }
    {
        const P: [u8; 65] = [
            4, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10,
            64, 50, 63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166,
            242, 145, 107, 249, 24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67,
            37, 222, 234, 108, 57, 84, 148,
        ];
        const Q: [u8; 65] = [
            4, 117, 102, 61, 142, 169, 5, 99, 112, 146, 4, 241, 177, 255, 72, 34, 34, 12, 251, 37,
            126, 213, 96, 38, 9, 40, 35, 20, 186, 78, 125, 73, 44, 215, 29, 243, 127, 197, 147,
            216, 206, 110, 116, 63, 96, 72, 143, 182, 205, 11, 234, 96, 127, 206, 19, 1, 103, 103,
            219, 255, 25, 229, 210, 4, 141,
        ];
        const P_PLUS_Q: [u8; 65] = [
            4, 188, 11, 115, 232, 35, 63, 79, 186, 163, 11, 207, 165, 64, 247, 109, 81, 125, 56,
            83, 131, 221, 140, 154, 19, 186, 109, 173, 9, 127, 142, 169, 219, 108, 17, 216, 218,
            125, 37, 30, 87, 86, 194, 151, 20, 122, 64, 118, 123, 210, 29, 60, 209, 138, 131, 11,
            247, 157, 212, 209, 123, 162, 111, 197, 70,
        ];

        const DOUBLE_P: [u8; 65] = [
            4, 111, 137, 182, 244, 228, 50, 13, 91, 93, 34, 231, 93, 191, 248, 105, 28, 226, 251,
            23, 66, 192, 188, 66, 140, 44, 218, 130, 239, 101, 255, 164, 76, 202, 170, 134, 48,
            127, 46, 14, 9, 192, 64, 102, 67, 163, 33, 48, 157, 140, 217, 10, 97, 231, 183, 28,
            129, 177, 185, 253, 179, 135, 182, 253, 203,
        ];
        {
            let mut p = bytes_to_words(P);
            let mut q = bytes_to_words(Q);
            let p_plus_q = bytes_to_words(P_PLUS_Q);
            syscall_secp256k1_add(&mut p, &mut q);

            assert!(p == p_plus_q);
        }

        {
            let mut p = bytes_to_words(P);
            let double_p = bytes_to_words(DOUBLE_P);

            syscall_secp256k1_double(&mut p);
            assert!(p == double_p);
        }
    }

    {
        const COMPRESSED: [u8; 33] = [
            2, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10,
            64, 50, 63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133,
        ];
        const DECOMPRESSED: [u8; 64] = [
            180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64,
            50, 63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166, 242,
            145, 107, 249, 24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67, 37,
            222, 234, 108, 57, 84, 148,
        ];

        let is_odd = match COMPRESSED[0] {
            2 => false,
            3 => true,
            _ => panic!("parity byte should be 2 or 3"),
        };

        // ignore parity byte, append 32 zero bytes for writing Y
        let mut compressed_with_space: [u8; 64] = [COMPRESSED[1..].to_vec(), vec![0; 32]]
            .concat()
            .try_into()
            .unwrap();

        // Note that in the case of the `decompress` syscall the X-coordinate which is part of
        // the compressed representation has type [u8; 64] and expects the bytes
        // to be "big-endian".
        //
        // Contrast with the format used for `add` and `double`, where arrays of words are used
        // and "little-endian" ordering is expected.
        syscall_secp256k1_decompress(&mut compressed_with_space, is_odd);
        assert!(compressed_with_space == DECOMPRESSED);
    }

    {
        let mut state = [0u64; 25];
        syscall_keccak_permute(&mut state);

        const KECCAK_ON_ZEROS: [u64; 25] = [
            17376452488221285863,
            9571781953733019530,
            15391093639620504046,
            13624874521033984333,
            10027350355371872343,
            18417369716475457492,
            10448040663659726788,
            10113917136857017974,
            12479658147685402012,
            3500241080921619556,
            16959053435453822517,
            12224711289652453635,
            9342009439668884831,
            4879704952849025062,
            140226327413610143,
            424854978622500449,
            7259519967065370866,
            7004910057750291985,
            13293599522548616907,
            10105770293752443592,
            10668034807192757780,
            1747952066141424100,
            1654286879329379778,
            8500057116360352059,
            16929593379567477321,
        ];

        assert!(state == KECCAK_ON_ZEROS);
    }

    {
        let mut words: [u32; 64] = array::from_fn(|i| i as u32);

        let expected = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 34013193, 67559435, 1711661200,
            3020350282, 1447362251, 3118632270, 4004188394, 690615167, 6070360, 1105370215,
            2385558114, 2348232513, 507799627, 2098764358, 5845374, 823657968, 2969863067,
            3903496557, 4274682881, 2059629362, 1849247231, 2656047431, 835162919, 2096647516,
            2259195856, 1779072524, 3152121987, 4210324067, 1557957044, 376930560, 982142628,
            3926566666, 4164334963, 789545383, 1028256580, 2867933222, 3843938318, 1135234440,
            390334875, 2025924737, 3318322046, 3436065867, 652746999, 4261492214, 2543173532,
            3334668051, 3166416553, 634956631,
        ];

        syscall_sha256_extend(&mut words);
        assert_eq!(words, expected);
    }
}

fn main() {
    test_syscalls();
}
