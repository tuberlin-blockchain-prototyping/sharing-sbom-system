//! Shared Merkle tree utilities for both host and guest code
//!
//! These functions are used in both the host (proving-service) and guest (zkVM)
//! contexts to ensure consistent behavior across the system.

#![cfg_attr(not(feature = "std"), no_std)]

use sha2::{Digest, Sha256};

/// Hash a value (as a decimal string) to create a leaf hash.
/// The value is converted to a 32-byte big-endian representation, then hashed.
pub fn hash_value(value: &str) -> [u8; 32] {
    let mut padded_bytes = [0u8; 32];

    // Parse the value string as a decimal number (should be "0" for non-membership)
    if let Ok(val) = parse_u64(value) {
        // Convert to big-endian bytes (right-aligned in the 32-byte array)
        let val_bytes = val.to_be_bytes();
        padded_bytes[32 - val_bytes.len()..].copy_from_slice(&val_bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(&padded_bytes);
    hasher.finalize().into()
}

/// Hash two 32-byte values together
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the 32-byte hash of a purl (used as the path in the SMT)
pub fn compute_purl_hash(purl: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(purl.as_bytes());
    hasher.finalize().into()
}

/// Convert hex string to 32-byte array.
/// Uses manual parsing to avoid external dependencies.
pub fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32], HexError> {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        if i * 2 + 2 > hex_clean.len() {
            return Err(HexError::TooShort);
        }
        let byte_str = &hex_clean[i*2..i*2+2];
        bytes[i] = parse_hex_byte(byte_str)?;
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    TooShort,
    InvalidCharacter,
}

fn parse_hex_byte(s: &str) -> Result<u8, HexError> {
    let bytes = s.as_bytes();
    if bytes.len() != 2 {
        return Err(HexError::TooShort);
    }

    let high = hex_char_to_nibble(bytes[0])?;
    let low = hex_char_to_nibble(bytes[1])?;

    Ok((high << 4) | low)
}

fn hex_char_to_nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::InvalidCharacter),
    }
}

fn parse_u64(s: &str) -> Result<u64, ()> {
    let mut result: u64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(());
        }
        let digit = (b - b'0') as u64;
        result = result.checked_mul(10).ok_or(())?;
        result = result.checked_add(digit).ok_or(())?;
    }
    Ok(result)
}

// ============================================================================
// Compact Merkle Proof Utilities
// ============================================================================

/// Helper macro to convert hex string literal to [u8; 32] at compile time
/// Usage: hex_to_array!("46b93ff02a8a7bad4172d16bcd9173011bf1c8c66e55f02cb975ba3f9a209147")
macro_rules! hex_to_array {
    ($hex:expr) => {{
        const fn hex_char_value(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("Invalid hex character"),
            }
        }

        const fn parse_hex(s: &str) -> [u8; 32] {
            let bytes = s.as_bytes();
            let mut result = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                result[i] = (hex_char_value(bytes[i * 2]) << 4) | hex_char_value(bytes[i * 2 + 1]);
                i += 1;
            }
            result
        }

        parse_hex($hex)
    }};
}

/// Default hash values for each depth level in a 256-depth sparse Merkle tree.
/// Index semantics:
///   - DEFAULTS[0] = default hash at depth 0 (leaf level, H(0))
///   - DEFAULTS[i] = default hash at depth i (i steps up from leaf)
///   - DEFAULTS[256] = default hash at root level
///
/// Note: For a tree with depth=256, we need 257 entries (indices 0..256)
/// because DEFAULTS[0] is the leaf level and DEFAULTS[256] is the root.
pub const DEFAULTS: [[u8; 32]; 257] = [
    hex_to_array!("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"),
    hex_to_array!("2eeb74a6177f588d80c0c752b99556902ddf9682d0b906f5aa2adbaf8466a4e9"),
    hex_to_array!("1223349a40d2ee10bd1bebb5889ef8018c8bc13359ed94b387810af96c6e4268"),
    hex_to_array!("5b82b695a7ac2668e188b75f7d4fa79faa504117d1fdfcbe8a46915c1a8a5191"),
    hex_to_array!("0c211f9b5384c68848a209ac1f93905330128cb710ae583779c07127ef88ff5c"),
    hex_to_array!("56460a80e1171e24ac1dcdc0d3f10a4f33bf31766260ab0ade1c7eb0dcbc5d70"),
    hex_to_array!("2dea2fc40d00e5b0af8bec53643e2bb68614f530bd0c6b927d3e5ed97173417b"),
    hex_to_array!("ee935dcf025e3016579ec39fcfdea5688ab4ca5f3b54726ac395771a658d2ea1"),
    hex_to_array!("10a411babd72a3bf9c9f82793e7371f78539c1b80a2bc13791bdc8d8b85e3793"),
    hex_to_array!("a15c4a922d99997278612794a7c740469f7b45def6bef262e2eec2703d1872e7"),
    hex_to_array!("86e76e201c2ead88b8bded0b23912e431a1babc89ef151e505438622350bd991"),
    hex_to_array!("c7fe09c567bf12d179ffcf8653a64e1d0dcf11938fd444399fd54620a2edf7f9"),
    hex_to_array!("07ef7659ff16d14b61578319e7d9405ec9cbc5c470d987cfb426eed515a5fa50"),
    hex_to_array!("b7c2fa725e389b5179a99bc659c561b4c7881cca943d449122cdb56217385b0d"),
    hex_to_array!("d536d02ae6a0a727a6e907b2fafc71577544d256e4db5f2f22d5bedf73c0cd7c"),
    hex_to_array!("aa4c42f09ecb58a7667e1a27b644b2d4bc9fb4213cf83cce6e59350bbe477b9d"),
    hex_to_array!("2ed4373149a1dd68868e1d77da082a79caad470b6cb80f99f4a97730c327ad6f"),
    hex_to_array!("ae733b66f70e8a852ed75b8d137ffdc011b233278b2f372679c25b5382b477f5"),
    hex_to_array!("f2fc7517a99d580bc0a970ebf98969b533d4d5929c10e0db91d7ef5aa724de0b"),
    hex_to_array!("4847eb8f74aa407babb518db4a37cef8363dfd1e1679d72893b74af39738e0ab"),
    hex_to_array!("799881750019ca39515941a00231729514ca4029498a0c675e9d66a0f4340103"),
    hex_to_array!("1e7cd67e461f80acdbb4c29dcde443da56589ecb9cda7c7778e583e650844934"),
    hex_to_array!("4117e2bdaed06121e41606d616b3af858f956f2195c708f0e474126e711b17c9"),
    hex_to_array!("315b864fb86944b75d50bc285e3d79b3f73e4af04a844cd0ee83305f8e825b4c"),
    hex_to_array!("9dc86dcb8145c82b1f0da6d0c8d3f27da5827353ca6db7abf9cbf51d3fb0db88"),
    hex_to_array!("457a83ac04e794bcba13ff78602187e3234116047f7bd3942219e11ddfe9c4cd"),
    hex_to_array!("43a94d25454ef5945cfca9c22a3f4c93a3765434c6cf991c71fa29aac0d6699e"),
    hex_to_array!("f6bbde71701f5d6acd3b85c8fc9832571613aba26f24423711ffef85ee2771f3"),
    hex_to_array!("e1471f760dc880914e511d5d0805ae2a293eeb17fca447071ba1e2694cc45732"),
    hex_to_array!("6d01e6658b94b2cc18605e86761e9916449ffab8230308d4a3cd9df091e90166"),
    hex_to_array!("cfe6d20d059469c2da7648d3ae5a1458fd91a2ee88095efdce675d694c809f6e"),
    hex_to_array!("45af778c61c6fad87f52c823fac66e08e4c92e42f926e5f8eacb7e0f349bd051"),
    hex_to_array!("b39f2380bce216f431684ea51c999b6fb8cbe91b0c61ce3914b605cce8ee88fa"),
    hex_to_array!("1ebb2384076e0b7fba67e389ffa67caae56c2aeb21d448a6db4d5489bce291e7"),
    hex_to_array!("b3926916304778aa861422ef7fde55f0ec1889142ca6815c2ef35b26384fd39b"),
    hex_to_array!("90b9f1812f381113ecd88faa4a03befa2db7675816fa4cc84c3b4b5815c7d03c"),
    hex_to_array!("acf7f0353c7c6621811e10cbcc03e10086b0973e039ff8319264b4bdd2cef4e6"),
    hex_to_array!("5d87fd89f3acfc6fb7f5ac9b9336d2a7df8f928c3f06ee9885fefdf2bd555d30"),
    hex_to_array!("b0f55ab6f3662be95bbb5b4403f5a30dde2f3399b693670c1fdfc75609edf071"),
    hex_to_array!("d20a33b0ae244e9985b86d780e330e4ef4ae606f99ab6a45dea24a6fefd261e1"),
    hex_to_array!("9163413d3e7d60214d1ede833375a441be086769b018ddc0702fb772f2ee6800"),
    hex_to_array!("b992e077a917cf0e30cc442234b6a527c57727da93fdd6678d1065f18df3307e"),
    hex_to_array!("a2b3014a67cb06f2813e90fb939a44977e22dcb5ad9cf29711fa370c07dc130f"),
    hex_to_array!("192b5772c1cf2b75c1666f6f20112d001d25db90764309ec0b65653d978a8fd8"),
    hex_to_array!("6d3dd3417c6501b0dfcbc3adf3d6c8a72c2b3872cf204fb2fdd00840078ce889"),
    hex_to_array!("728b3fdf682e270217b1d17447005810368376ea00f9465d3648f7a09290f7f0"),
    hex_to_array!("caf66f4e9938af1b454a7640842658d14bc867e17d02ac1ca8aa5f558c89d142"),
    hex_to_array!("bc76279ef59bbaf99bbcacf6bdb35e19db1d5310d30f5629481199f868995b1a"),
    hex_to_array!("6f553ae4f9c60c9a32fd5b2b75d2faee30a1cb93ca7b7f267c63fa09097d91e8"),
    hex_to_array!("ef437795e7b4b63c35f8412dd268671519e7784cbacbc8a99f2b20125c449981"),
    hex_to_array!("0d7a308f1476963e2ec383e326708a7be8c6b767075433278ff71ef9e52182f6"),
    hex_to_array!("812dc49fc31cff1f8f5b6e110d1fb0ed98b3a8307fd67b042f88154e4343e37f"),
    hex_to_array!("479b5ea57bfca9faa67f8a62ba7e7e89c522de7b15b8189de989feb886b2ff96"),
    hex_to_array!("910a7574543598fee242786ff4dcfd2760c288c6beb8f5ac93185d3f53110fe5"),
    hex_to_array!("0e2989423da846fd01448979ecac32a1a72bf36a54da5f614f906e003dc4c577"),
    hex_to_array!("1f0e8efc9da5ea45436ba55f679238f8acc56706b0e8825e812f9085850219eb"),
    hex_to_array!("78292981e8f192d96a401e48028b2f60a23a8c2748ec58654c672901ded3527f"),
    hex_to_array!("bcf404c9de4dbcf09deb57cb1c096d9bd4eab213176960615c18f600208d81d7"),
    hex_to_array!("c638bd27b69408e8d9e847069bc4f3dbda79890dfe770d8cb25962c01473e579"),
    hex_to_array!("bed1b146ec5badae93712902c914eebf0ec9ef6378eaf31cdc9804d046e4e8dd"),
    hex_to_array!("04ed8c4cfb9236ff1c50115f2948a0037731e8d8f429a91523841f146550d9b2"),
    hex_to_array!("5a65f9d1faf29ebf0f0375eebad437dc17226d0a4ff6411410b1af8adc2c6cc0"),
    hex_to_array!("f644b8dae7ebd13eda5f8d785ae11efac7876d816e080f0d30969cfd797eeac8"),
    hex_to_array!("1f851668e3979442bf9b549becb2b4a5cfaf465455f013f22ba532d4ba2c4943"),
    hex_to_array!("25441aeb06532079d31e076f0210a8f2d14175fff809058f10f8e40e3bcea40d"),
    hex_to_array!("d9bf15e0aaf982630cf78232756d282e0d4aa425d6bd1a78f7347ff8338fdac7"),
    hex_to_array!("fc0fb568beb93b366064b854749e62679f55c90ed8d1b10b3d116842b09299c3"),
    hex_to_array!("77f0f501b11d54061246e0851db7f1688e06f794cd89c360b51054e6cad82cd2"),
    hex_to_array!("bf08e6cfd35bd64996dfec1d82e960694c908d015ff149dab2c6592dacfe019c"),
    hex_to_array!("c19ca418545e099044c9eafc6021a4e7e2f4f8baa5f2a96a82d9d93574e1bfaa"),
    hex_to_array!("b9b999722be59e111fe3b0005152da1552983aef87f4d26ef2ab111a050ad6f4"),
    hex_to_array!("d9a9fa31de4f186d581bad541264fa05a740192a8f0d06eec503f4e6156bf8cd"),
    hex_to_array!("42ce48bde1a9aa6436cb450795313d6db87702395882113962e4162c2916e2f4"),
    hex_to_array!("1c0a203718ba9471717a76a5cf39a40c6ee5a6b9eb139d30f1191b28833f545a"),
    hex_to_array!("fecc1ceb8b13e091a2125a0f2188086d827aff4565a323759113be83b1141309"),
    hex_to_array!("1df4ed83a66e6668e6c8967abca1e1000ba392aa0d8dbba2dee490e612c71cd1"),
    hex_to_array!("511771cde2a1be2e30e7888b1aed61333653316d36de5880b44dae96e3328d28"),
    hex_to_array!("4b73e6426068eef6d3d2c04672933dc4390b6b0e63a6112621ff49b34625d3e2"),
    hex_to_array!("41ec75e570f03e57b3d9a5b81465556cf53fb8fad74e9847023ff3db201dc359"),
    hex_to_array!("456070bbc1b60d404c513174f28afe0772b9c8f2158997562cf24a3779f15cbc"),
    hex_to_array!("1b8d7ab455ddddf3dc43efec979c64ee4becf5c41fb7694d11a0b5e9991fcb70"),
    hex_to_array!("8f93745313e52e52f3ad84fcd1abe6181524f8dbf6b4d6f68538db7c2dcffdb7"),
    hex_to_array!("7af9bde034d72d7d8d7b99927545d73561beff42ad77badec0a4ad776d7f1fca"),
    hex_to_array!("689ec4935a31fa762c72b4ec0139dd527b7d3f36283d38474a14540f7e8804d1"),
    hex_to_array!("0d7a0604091c9e323456b391bb66d16654bfefc6cba5755cc91854604fb904aa"),
    hex_to_array!("93a1448c5c8ddfd8657db577c158791ae49ac7a7aa15adbe4498fdd3ac218d16"),
    hex_to_array!("e74cee3b510a433bd3c49df7179358f1d255019284b9e5ea89100d0adaf5a5a1"),
    hex_to_array!("90da8d64a800a947db39ff680a1db2b1e56c8c6955fcd6fd66ad4532e3f98fc9"),
    hex_to_array!("8cd37f78e656b4d8291505ca4a09966867f6ff3dbc3cce2e2e446165465a6e82"),
    hex_to_array!("df2d34af3ab889ca3503ee6b4b02931b1774ce0d316807342e44ac4dacc125d4"),
    hex_to_array!("f82bbb774097b62a74314cca75f90d06c16082b1f0014042f081655b313487e0"),
    hex_to_array!("a257d9539cbf8bbcb711cad7f562210fee333440273bbd0847a47c271d47240e"),
    hex_to_array!("27aec85ece7c1ee2a406703fbc7e97d7f9f2227386d4813e584b1248d1f808d4"),
    hex_to_array!("0583106912c607986fbda28e046aad9a689a508349c2ad8ae5bffa6b4a58c9b9"),
    hex_to_array!("9cca4686c8e729214219e215313eb06ea207bb0e10b3719246f322b0097073bc"),
    hex_to_array!("c374ede0b87e8c739b3ae39a1b394e7a17b0f46b25c1ce28f07ec489b015dcf6"),
    hex_to_array!("0227ac900f358c2706758e9680a773587986f2c9288c0590d4ce214fea2ff1af"),
    hex_to_array!("5709fabc0e021c07c96b5ddf6f01fb7e8ae7419861530bbdfa10a1177fe2dbfb"),
    hex_to_array!("6ab40b1cf47e3f55f95472e0b6885ae9b5797f8087018d9c7c831d376c4a6e54"),
    hex_to_array!("877ea0b0bd18bcf2c6258ec3275f93af25add12778769633e580073bdbb6af40"),
    hex_to_array!("94efd0dfdbd7f2ba6abc524dcdb1a6d21f80bb4816a758f325688b4c9483d319"),
    hex_to_array!("c84e5e3189f908fb198bc704763a712348deec4dae6b5fe99c31c74dfc50c892"),
    hex_to_array!("7ba6619deea73a1678070a418e091737c1cda3736effb51e0babd5017d11b9dd"),
    hex_to_array!("ff52068a885ecac6015bfd82c8839b15c918cfaf1d909fa0de45594233d8fd37"),
    hex_to_array!("fbe09d57ff4963ebb933f59d40797f361ab5a7938295b9b87c30298260314e13"),
    hex_to_array!("f1762a87a8de2b1a0e71f0e475f6871a283aeeec9e49cd81c199cffb89bce79c"),
    hex_to_array!("739b3057a8b4db1e2851792e12ed9e0552520fb3ed3e3dd3ca686e547c62df59"),
    hex_to_array!("d58c64dbe87a9f4aa35c15803837c89fc171129cef73b99bde42945ae39762dc"),
    hex_to_array!("1826b9b655d08066b6a5927d9dafe834d4b5e92578dc68975b7f7efc73e839a1"),
    hex_to_array!("9d65ac662aa298c34b70476e28b4ae090140bfec6097b3ae0fa50ecaef892ce0"),
    hex_to_array!("0b7aae4e4575bcb11425396006d8c18e86090106df955433c1746b97520cab6d"),
    hex_to_array!("27fc2ea81f0adc5a5836481bfa2c250f1c5acb8ed2241cdb6a3a879165ca6416"),
    hex_to_array!("66e197307b12284563b6db3fda292571c7a279f6700b1973107639140caf4f01"),
    hex_to_array!("e517bda23565aa1a4463892a9db916d8eb225ae45936ddc6495e6cb9f33a3941"),
    hex_to_array!("a109d1f5a1d25e275e1dfd85b55a71dda92867d484bd9aaef905072775e0c8cd"),
    hex_to_array!("83a7fb7528fa7786c50da44c1f5923b973c585299cdccd72e1682eb560d3b095"),
    hex_to_array!("900c5003e719155d44357c2328f306530cd00e051afd22bbdc055c4ff8663b00"),
    hex_to_array!("d173fd6240e89f1b76cfe3d5d7c8962ddcaf6abf65914fdadc1454b5c19e5a04"),
    hex_to_array!("45d2c48e0021289598981f11b34f72f6865b156eb14fdf8d8ff21e2c9a7caf30"),
    hex_to_array!("0ca4b02df29a6e0de12315ec7a46a2d76e20415363203b3193eebe06318d5480"),
    hex_to_array!("078e7f1d8ba6c19625ced293230d1e2eee91f506671238a1217b2562524af9b0"),
    hex_to_array!("1c26ecaf0226348c074afe8aaedd2a5ca9f28300ef84f7f44e3dafcba06eee31"),
    hex_to_array!("a328afb4a949f4d451ea9587fa174ce0d4da88f380e60178989f41c9f2ded3ae"),
    hex_to_array!("401f73fdf05890d265fdf6fd5d79f4e6a344a24ca20a5498a5794aa9303afcde"),
    hex_to_array!("d39b2555c3239f3ebb8e81fa60959959d91e6f3fbf0700cc07263edef057b933"),
    hex_to_array!("39db070cc3783fbc27649d6deaf8202eee3b0a22d2fb75a8ef2bbbbb77545cc6"),
    hex_to_array!("fe7b35cf3c2393dd06a259c2c6b086cd3222b1898f8b4ec3ab33e80da32c5484"),
    hex_to_array!("50962ce1ab3a9747216c85646f8906db6e71b58e6cfed6c81768e4510c6bc91f"),
    hex_to_array!("ee744204d628eb2b51f1f96f57572968cc68328c14c48c8e038d32e14b9df1d6"),
    hex_to_array!("e05318ebec1214c3670c3ebc1281eeb656929ba94693b8dc83579bf28f3b6cf2"),
    hex_to_array!("8c91b458e0706c01c9f6c8955047ca67c1e136c09455bf302f39dd005702be69"),
    hex_to_array!("7008f04f60628395ed8f1ef4edd5abd8d77ee6cc827869e97bd6c5c0bd8cd45e"),
    hex_to_array!("991f1d96537b9a2c625a9f696458ce2e9c481c9d933c225a49a183f1777e5330"),
    hex_to_array!("f0bd5a55d0c6e505f1d61f21965034f9b03b96c18066cce4e58232277dffee3a"),
    hex_to_array!("9bd2d173a48673f0f135bf44e5b240a60e146ec2ccf9ed0a8a97cc2975c1871f"),
    hex_to_array!("08f41f263bbc53eaad023d18faf7d041241ebfd69430fa3407e5e8fe566c0231"),
    hex_to_array!("d29129213ee39d2c1a71e257ff0372ab30c858bfea70d2ad6e2581c584edfb50"),
    hex_to_array!("3d09992f0a4418e58c8360434c267a99726ac0efccf80080bb2df34bdbb66c35"),
    hex_to_array!("5a3a535e43aaeda8c8f7c33d4ec13e60a80ce47ac1235b62b41dced3b462219a"),
    hex_to_array!("1ef7aaf2cf8377c663c9cc2613aced6f16151f2791306ac1b6b8d4e969229a1d"),
    hex_to_array!("7689614d4176dc9407deae6bb61085953255e06e1a61167607a2a9618a84b003"),
    hex_to_array!("2931f0b86ed16dc9bed11eeabcbfd02c57c2e406c32064cec699dc15630c2ed1"),
    hex_to_array!("7fc97bbf9fb5688d57fb371068d6edea0311199ef2aac2d39951a191a77476ca"),
    hex_to_array!("19ba5332e681937757ef9c19826394083e587cc84333a86e1287215d4f4e419f"),
    hex_to_array!("bbc6feb078f0cf7ec67197c818310625f3e1132dbc356c76644c7a33cd9547da"),
    hex_to_array!("84aed7347317b444aba02c08098c2884b4b69200343d7c7218e64001f08aa1c1"),
    hex_to_array!("c44734db0a647b8d421600de2eee49f5f9495ee2efdbdfaf2ee2a095ef8f20bf"),
    hex_to_array!("15061b86939c2b298df8e7b0858e0379c1fd994a90e0887a09e59cd23cb240f7"),
    hex_to_array!("10e7e166baf8e554d0c38edbaa3625d3047b4158e22eed3cd234cc20417998ec"),
    hex_to_array!("e8bcdd35d4dd57174e99d671ef34c866cb84e4b49f6b6327811621d6ac52cfd5"),
    hex_to_array!("62b51475b83dff59cdf34b5bedb622861e97e3ee8866ba2a2acd0027789fb84a"),
    hex_to_array!("1b075692fc7e118e7d9d24336a0ff3aad1e1d1a9ab263e5660ecc6c58c4ba4b2"),
    hex_to_array!("6f7cc29e85efe400924d5b231f117b4321f2f5322227c07b9158badea88741d3"),
    hex_to_array!("4c65b99965f41bb63c2016c022d41b2ee9044563b6d5b0316f41d5b1aba15e36"),
    hex_to_array!("8a4334c3aaaf306424edf27fc37dabc24113e62fab71e8e22b37334fc46b282e"),
    hex_to_array!("0e1f8ebf88a1d6e03c069aa45bdad0aa2fedde5465e84efbd4712ab7445366d2"),
    hex_to_array!("abe495060080b155355bd87ff1b520c3082762bfb7f185d5a72564fd395ac5ac"),
    hex_to_array!("d8ba8bb7d8672728db2f7080dec17f67b52b4085142f9c6ddca38b561899aa7c"),
    hex_to_array!("7b8af327a698f306415f57e6ba2ece956641025ef4e55aa8cdca1720e0cea1ab"),
    hex_to_array!("e6c23d63cb6e883472be402997dfadf47736ab420b501cd1517a9dd031ecb0e7"),
    hex_to_array!("a752cfe628303a941e9f546760a8aff81b1806b462b045d54cd16bc385c32b37"),
    hex_to_array!("02fcb96c9d7dc1391b67da786b50073df480ca00c14fb7751999212cd801aadb"),
    hex_to_array!("e10858445f7177267d53c13fa453042e9d7bf00f1a55a93888a4eaa7f4d0a52f"),
    hex_to_array!("4e61c62da4a0a48da28a2fdd125b99a18961be4c07062d069b0d386f9529f13d"),
    hex_to_array!("acc6ac8fa3c6eb26235c7f3864529a033f1098acabb137c45839820f230f259f"),
    hex_to_array!("2b2f7cab059eebd8ec4d54a15467c0b1cb45dec7ade335ddc6a44eddf123457a"),
    hex_to_array!("6b84b69864ddc9295cadb3b2240eafc9148af780a2ebb7a47d97c59af0ea441d"),
    hex_to_array!("56cef977a6f31e4f455c33b2db010b592f95aaf6b1cdac5e9f375eda623ee5a2"),
    hex_to_array!("a0367c41d4259df9e879c0b7084fb4738317b0ec412cb7c53c060381af1054ad"),
    hex_to_array!("be4f27a03ce4624b3884e1ee51e8fa61173dd1634ab25f82ea5508b26a7b898c"),
    hex_to_array!("b0c7e02567d52829442b375984ac414c477aee7c8f89abbf2165dd8384514190"),
    hex_to_array!("953547fec2fad7833aa622b09cff38a2df006a7b78ba556690cd1a7073b49c96"),
    hex_to_array!("1316c44e8e1638b37556233094046eefa76b08aa519c5a031cf7fe215fbc0549"),
    hex_to_array!("87f7f2280f78dde072154e000d1359dcf0a9903867c35f3308365d541cdc1ac2"),
    hex_to_array!("4bd4dcfcd4bad217c349d8aae4e8b9801b42e96d5a8704cca1f138a4cca69b00"),
    hex_to_array!("5dfdfc18f94b469389c2502e41d4503be05e01515f340273fc9c14582611b5e5"),
    hex_to_array!("de0483233989c9e685b92b4b76b9203496dd835c5004081f830c9b4983461f46"),
    hex_to_array!("083ffb5393589dc8345e5613a20dd03e8ae34016bee5ff7a4d8e2155c94c02bb"),
    hex_to_array!("11ed894f853cc4487a328611b52d0423ecf2d7ad4f522eaa1890661666ecd0af"),
    hex_to_array!("5475269d14777d2ea0c7b67980110d9d8e7d561080e71af492f2bc2e24725ec9"),
    hex_to_array!("7976453abdd930834df3fc70ee3cf851aed953ff5304775950387ba0ed2fa59a"),
    hex_to_array!("59fc2eda7427c4f3a4d22dd01efa4d2fe70c1ef42a75e3012566f70efc672c8e"),
    hex_to_array!("a86ddfaf43dd8f9cd454f6d59b586f611c071a8c4678cfa5da6abcacee75c0fa"),
    hex_to_array!("98dedd94c6ad8c87fb99d136eaae627b141a1aba43ee25667bf17600d7e27fbb"),
    hex_to_array!("d19a0ac1f44d4783a9cd83c7d73ba8bd5f1bfbd9a98eb4575168be083625496d"),
    hex_to_array!("3e1057275964a43781e6ed81330cfe4cd475c783f9e5a4d66e8396b31e6b0267"),
    hex_to_array!("347edbbd9f5a43b9ce6b8771082e410d22f240ee1138da701d701e806f469044"),
    hex_to_array!("cc89d767ddced651f987cdcfa2c65c7850689dbac6d991cd40cfabe58973634a"),
    hex_to_array!("1970f9e47ce8c0b54119da9b76a8bf37792f87f258de983bfb2c262aaa0b0c18"),
    hex_to_array!("834a930e43033ee821fee39f783480561be2d3d77a5e5ff37115bd42658f2a65"),
    hex_to_array!("627230c96d68b6a73781db81c116cac74d08b98d47233951153a36000e4aaeec"),
    hex_to_array!("6285520ad00152289921a3ddb1774f17a5573725c9e52c4b14886d2a3cef837c"),
    hex_to_array!("0366d02aee5825fb0bd98eb54d13ca60286823bd8531889bdff3e139b946b357"),
    hex_to_array!("70807a13e2a177e212b7a539a0f8d19e7becc56ae3afd01b65ce347da82ed88f"),
    hex_to_array!("7eda5a6012924f61834a32ab6c95d4559eb2c76fb2d3bfcaecfbc934a9fd0888"),
    hex_to_array!("a00f191a49c4820496c060359cfe0ccb38a6d116ff664c382da526bf54b0fae6"),
    hex_to_array!("6964cbbe5041af38084e4205ec3f9c69907188c5a797d00a8e0b713d115f679b"),
    hex_to_array!("f1f711c1463f3c9fbebdba8d5c410d0a0401fe48d76a7897bca87a17c8e7cd2e"),
    hex_to_array!("3870a82aea6101cbe32334bfe17b45502b0c4a1482c0376ea3675fc83cb25a44"),
    hex_to_array!("a29890c025bf2306474feb883066b280c751ac1c8b1dbe2827130f6ceaf73670"),
    hex_to_array!("19cb56610f93e9b1b6fd6894471cf514f7dbb74903652bb4c4a216def9cfae45"),
    hex_to_array!("907058efd37eaec39c241b97e3a3e7b101e5f03c378192a215de188898ecfe13"),
    hex_to_array!("f9dc2bda08f50092869db2b7031bf884cb00839933df63c83ba61ffccecbd728"),
    hex_to_array!("7e4a9a53252d939bcb8319776c0e9b5b9f0b45b19f2a1de7eeefc22d19a140b3"),
    hex_to_array!("b1cf9fe189098e94168b007e49f062fc9c87645d45c9371003accf44ae29cb72"),
    hex_to_array!("d0c8093199da39e0e9af6a5020acff24a1d16ab67a0b2130006a688a295c2c20"),
    hex_to_array!("dee9f62931e9256251fe4588fa8a8b8298630e72341ebaee6fe7129b23512143"),
    hex_to_array!("30e81be17f36779315b09c9883662610ea50f801a2d9cb53c89a69e0eaaa0b2f"),
    hex_to_array!("47c0a8da1f8545564b5ceb6af2906984c65c5df7546b515a68f899a617e6d00a"),
    hex_to_array!("f39cb90605259c64554f3c8d6808f46a5e1989d947a38d0b94ec565fdd34b0f6"),
    hex_to_array!("1e197ba36d3eab99617bc65927740c28c1fd48b8b3dc93083adf063edbd596e3"),
    hex_to_array!("bfa5c775df0ed39834c4928cb169862c9c215986a1bc56bab7ada3119b7604aa"),
    hex_to_array!("37c661184b43cfa485e78f8fa76a50b0007b854a83385175f37b22a9b8aa1cba"),
    hex_to_array!("79617f1f0ef36975876e6354e4a9ca50acd2dc8e01f02732106891a0bda91ede"),
    hex_to_array!("40f2fe7c3575f8ec3dfc7c2895fb25c61657cd73b2692fd2961cd7df77ebac05"),
    hex_to_array!("a442ccd88a5f4d115cb6134ba4cce4d628f3b98d1bf1ef08d61b88b7aa92f6ad"),
    hex_to_array!("ad0515f324f01daa86ea5b702af53fa4ee2e38e3acb155faef75c2667c6c110c"),
    hex_to_array!("b9cd66c61deefd8d2b4db61d83cf07c3a849f042f3e1a1517f20f2b75d5443f1"),
    hex_to_array!("6c3efb720d07f3547209f62ef2b56bfca63b66e5531cf611f43ed6efd71170b0"),
    hex_to_array!("6eb69db847df007ba252c903eace8a8ba35267d3d5eac8c4e7239af472af1246"),
    hex_to_array!("ec7c652805db38eae0f37f6f0a13b245b4f2021b7171f2081f5a4087297f1d4f"),
    hex_to_array!("dabdd2c4a417372426cf7bb2ef5dc2e78c762fca114067dfdc40bae9aab66dbc"),
    hex_to_array!("86cb0c29250b9099d19369493a6a7152aebd617d6fc7cc47ef58f9060bdb6ebd"),
    hex_to_array!("4aeac97ef43d110f735d0e7e03c869cb7d5c8de7913706f10fe5b3f6238f5ae0"),
    hex_to_array!("ef85f612f00e65d19a0b9889777062eb78e531616d5d476758f377db4d5dff4e"),
    hex_to_array!("42332dbb26180fc6a2f47ff405209795d9e2e51a594d6597f5a9874af9f3ba20"),
    hex_to_array!("f4ad3e38e37d1d2bac3a4d62126bbb4073da7e2c899cbad04de4cde9cf865ab1"),
    hex_to_array!("c82160d3c0999959507bc3d47d29ca005a79d4dbaabdabc25b99583293c28460"),
    hex_to_array!("476de94084799fae38bb824953120d7ab6593c656be9340c54ad01ab8c0d647b"),
    hex_to_array!("0bdcec9da257bee74d568b85d072951b9e01c1bcab5022de5512be1f70bccd04"),
    hex_to_array!("7960ff8df2eb9ef3f24c758fd1d5e5a9beef1105e4bc783c5966ce693f25cf75"),
    hex_to_array!("c2ff8cd1d2b60ff5b969b0bce7e853169e19253b09480de62beb89fe74498015"),
    hex_to_array!("89071ca766ab1660389b3ccbb3d5256cf6013276682739c7bb1d85df770fbf3b"),
    hex_to_array!("7abd39ce30e3a32c6c1f3d11ff9993043169e237b2e0916de376bf4daf932322"),
    hex_to_array!("39f283a034351ef3d908408530552815b8a884697bb8441b32c4f884adb55d08"),
    hex_to_array!("74a11cec30ef63f7a24cdae660b8c825ff8b2e6ad2b49b606c855f1799275ba3"),
    hex_to_array!("c27436a8726b16d460b7099dccd7410231935f421243590cb8c2db1c533a185f"),
    hex_to_array!("b36c3f94f87ed0ef67aa3a4d6d1045bc0850121d8f46a27ef4858d3aec15c28d"),
    hex_to_array!("2aaa72991e0d56b377e6c3babb85eed9aa6d89ce8aa455be172b4dcd7e2842fc"),
    hex_to_array!("a47504ecc2d04d4da286a815bb4fb5155a2a964a994c5d2820af35d948a7d353"),
    hex_to_array!("2fea330e4760a941a1f11d05e4377bfb37dc9a25348eff072360421a69007ded"),
    hex_to_array!("0654b75413934300fb954445b92fa9f6a9f112c78ebce9549da6d76883cd3bea"),
    hex_to_array!("e35ea68d665f9f26e7e9a7683f807576c70cc37a0c1735a573858751b7d859ee"),
    hex_to_array!("ecbb458b3abca6201210375751fffd17a9ac9fcea2118f12ba57be115be69924"),
    hex_to_array!("d7b50201bd201a0d5a1561c6d6ab3ca46bb68a98b898bb5694cc3296864144a7"),
    hex_to_array!("957b8cd6ef358e846165fffabecfd8219837ff41f42c684e9966dee056f411c3"),
    hex_to_array!("1fcee71a2d3c690b23d5dedc52deeb7446e690f50f636cc1932afd582314508b"),
    hex_to_array!("32f68b78c32c5a95f8726eac40afc8c026e201600f773cde436ec593e8bb4c57"),
    hex_to_array!("81ef7302e434a52a2f91f10c5e322716bcf1eaf419ff34a4f59ac7d5d3900874"),
    hex_to_array!("af4d07e651cf5dc10078d517100c0a75a9441de84f3256300acc55eb8a7bf767"),
    hex_to_array!("3063a80e48ec3d5ac2d86520cbc5b4c5a24a73dfc6b93aeaf174dc5c1afa898f"),
    hex_to_array!("71d8684647301ac31969d559ae3e8e6c5b36af7c9e969c3d78469f5c8dd92f47"),
    hex_to_array!("0db79e51fd89d6e954a31b826840879b84471267380fee8a2752c31f27f9f52b"),
    hex_to_array!("e3546ea4d3ab28783468d35ebbcbe6f5c5bfbe1fa220fba4afe2a2436724c571"),
    hex_to_array!("aaa637f79b5628047db352d5f03534d5046d747f3004e4235ae5f84598e1d75a"),
    hex_to_array!("46b93ff02a8a7bad4172d16bcd9173011bf1c8c66e55f02cb975ba3f9a209147"),
    hex_to_array!("876422b7697ae7c337e2ee7727feb3db474adf7be1cf04b6b5857d82d610e88a"),
];

/// Extract bit at depth `d` from a 32-byte bitmap (bit-packed, 256 bits total).
/// Formula: (bitmap[d / 8] >> (d % 8)) & 1
/// Returns 1 if sibling at depth d should be taken from provided siblings, 0 to use DEFAULTS[d].
pub fn bitmap_bit(bitmap: &[u8; 32], d: usize) -> u8 {
    let byte_index = d / 8;
    let bit_index = d % 8;
    (bitmap[byte_index] >> bit_index) & 1
}

/// Extract path direction bit at depth `d` from leaf_index (32-byte SHA-256 hash).
/// Interprets leaf_index as big-endian integer (matching Go's big.Int.Bit(d) where Bit(0) is LSB).
/// Formula: (leaf_index[31 - (d / 8)] >> (d % 8)) & 1
/// Returns 0 for left child, 1 for right child at depth d.
pub fn path_bit(leaf_index: &[u8; 32], d: usize) -> u8 {
    let byte_index = 31 - (d / 8);
    let bit_index = d % 8;
    (leaf_index[byte_index] >> bit_index) & 1
}

/// Count the number of 1-bits in a 32-byte bitmap.
/// Used to validate that the number of provided siblings matches the bitmap.
pub fn count_bitmap_ones(bitmap: &[u8; 32]) -> usize {
    bitmap.iter().map(|&byte| byte.count_ones() as usize).sum()
}
