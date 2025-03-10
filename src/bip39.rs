use crate::Language;
use bitcoin::{
    bip32::Xpriv,
    hashes::{sha256, Hash},
};
use nbits::BitConjoin;

/// BIP39 Derivation for Xpriv
///
/// Create bip32 master key from mnemonic words list.
///
/// see: [BIP39 spec](https://bips.dev/39/)
///
/// # Examples
/// ```
/// use artimonist::{BIP39, Xpriv};
///
/// let xprv = Xpriv::from_mnemonic("lake album jump occur hedgehog fantasy drama sauce oyster velvet gadget control behave hamster begin", "🌱")?;
/// # #[cfg(not(feature = "testnet"))]  
/// assert_eq!(xprv.to_string(), "xprv9s21ZrQH143K36NWXJp6dEYdnu27DM1GdQB7jxTtmXZDk4Bs65ZuHTV92tN5Dp42VPEnkAMknGM2FbStkEFUmH8g7AbPVi7jZNQgKMrAZYJ");
///
/// # Ok::<(), artimonist::Error>(())
/// ```
// # Reference
// [1] - [BIP39 spec](https://bips.dev/39/)
// [2] - [Ref website](https://iancoleman.io/bip39/)
//
pub trait Derivation {
    /// # Parameters
    ///   mnemonic: mnemonic words joined by ascii space.
    fn from_mnemonic(mnemonic: &str, salt: &str) -> Bip39Result<Xpriv>;
}

impl Derivation for Xpriv {
    fn from_mnemonic(mnemonic: &str, salt: &str) -> Bip39Result<Xpriv> {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(Bip39Error::InvalidParameter("words: 12, 15, 18, 21, 24"));
        }
        #[cfg(not(feature = "multilingual"))]
        if words.iter().any(|w| !w.is_ascii()) {
            return Err(Bip39Error::InvalidParameter("Unsupported language"));
        }
        if !words_validate(&words) {
            return Err(Bip39Error::InvalidParameter("invalid checksum"));
        }
        let seed = {
            use pbkdf2::pbkdf2_hmac;
            let salt = format!("mnemonic{salt}").into_bytes();
            let mut output: [u8; 64] = [0; 64];
            pbkdf2_hmac::<sha2::Sha512>(
                words.join(" ").as_bytes(),
                &salt,
                u32::pow(2, 11),
                &mut output,
            );
            output
        };
        let xpriv = Xpriv::new_master(crate::NETWORK, &seed)?;
        Ok(xpriv)
    }
}

fn words_validate(words: &Vec<&str>) -> bool {
    assert!(matches!(words.len(), 12 | 15 | 18 | 21 | 24));

    for indices in words_indices(words) {
        if indices.len() != words.len() {
            continue;
        }
        let mut entropy = indices.iter().map(|&v| v as u16).bit_conjoin(11);

        // verify entropy checksum
        let tail = entropy.pop().unwrap();
        let checksum = sha256::Hash::hash(&entropy).as_byte_array()[0];
        let valid = match words.len() {
            12 => (checksum & 0b1111_0000) ^ (tail & 0b1111_0000) == 0,
            15 => (checksum & 0b1111_1000) ^ (tail & 0b1111_1000) == 0,
            18 => (checksum & 0b1111_1100) ^ (tail & 0b1111_1100) == 0,
            21 => (checksum & 0b1111_1110) ^ (tail & 0b1111_1110) == 0,
            24 => checksum ^ tail == 0,
            _ => false,
        };
        if valid {
            return true;
        }
    }
    false
}

fn words_indices(words: &Vec<&str>) -> Vec<Vec<usize>> {
    let do_search = |lang: Language| {
        let indices: Vec<_> = words.iter().map_while(|&w| lang.index_of(w)).collect();
        match indices.len() == words.len() {
            true => Some(indices),
            false => None,
        }
    };

    #[cfg(not(feature = "multilingual"))]
    {
        use crate::Language::English;
        match words.iter().all(|&w| w.is_ascii()) {
            true => [English].into_iter().filter_map(do_search).collect(),
            false => vec![],
        }
    }
    #[cfg(feature = "multilingual")]
    {
        use crate::Language::*;
        const EN_LANGS: [Language; 6] = [English, Italian, Czech, Portuguese, Spanish, French];
        const TONE_LANGS: [Language; 2] = [Spanish, French];
        const CN_LANGS: [Language; 2] = [TraditionalChinese, SimplifiedChinese];

        match words[0].chars().next().unwrap() as u32 {
            0x1100..0x11ff => [Korean].into_iter().filter_map(do_search).collect(),
            0x3040..0x309f => [Japanese].into_iter().filter_map(do_search).collect(),
            0x4e00..0x9f9f => CN_LANGS.into_iter().filter_map(do_search).collect(),
            _ => match words.iter().all(|&w| w.is_ascii()) {
                true => EN_LANGS.into_iter().filter_map(do_search).collect(),
                false => TONE_LANGS.into_iter().filter_map(do_search).collect(),
            },
        }
    }
}

type Bip39Error = crate::Error;
type Bip39Result<T = ()> = Result<T, crate::Error>;

#[cfg(not(feature = "multilingual"))]
#[cfg(test)]
mod bip39_test {
    use super::*;
    #[test]
    fn test_bip39() -> Bip39Result {
        #[cfg(not(feature = "testnet"))]
        const TEST_DATA: &[[&str; 3]] = &[
          ["theme rain hollow final expire proud detect wife hotel taxi witness strategy park head forest", "🍔🍟🌭🍕",
          "xprv9s21ZrQH143K2k5PPw697AeKWWdeQueM2JCKu8bsmF7M7dDmPGHecHJJNGeujWTJ97Fy9PfobsgZfxhcpWaYyAauFMxcy4fo3x7JNnbYQyD"],
        ];
        #[cfg(feature = "testnet")]
        const TEST_DATA: &[[&str; 3]] = &[
          ["theme rain hollow final expire proud detect wife hotel taxi witness strategy park head forest", "🍔🍟🌭🍕",
          "tprv8ZgxMBicQKsPdZJv4VweGpGJpe3reRgMMr7SmZ2LFDbpuDxrNddQ82fkHSpZjsqcWYnk9VHZmEGN8pFMwivVnDrVn1AvdRPqy3ripW55kfq"]
        ];
        for x in TEST_DATA {
            let xpriv = Xpriv::from_mnemonic(x[0], x[1])?;
            assert_eq!(xpriv.to_string(), x[2]);
        }
        Ok(())
    }
}

#[cfg(not(feature = "testnet"))]
#[cfg(feature = "multilingual")]
#[cfg(test)]
mod bip39_test {
    use super::*;

    /// # Reference
    ///     <https://iancoleman.io/bip39>
    #[test]
    fn test_bip39() -> Bip39Result {
        const TEST_DATA: &[[&str; 3]] = &[
          ["solda osso frasco encontro donzela oficina colono vidraria fruteira sinal visto sacola mirtilo flamingo ereto", "",
            "xprv9s21ZrQH143K2KFS6iHoFXZC9Y5AWVKwxZis4GMRkQeaTFHiNRTkrjCsnBZ46s7VNihoMapH64FE93ZbzZ28Ld2oiHh6FYQx4eA8jEisYsc"],
          ["岗 跨 困 倒 考 邦 调 晒 慢 孟 畅 埋 黎 句 皮", "黎句皮",
            "xprv9s21ZrQH143K2SwhdXXWCKa3Sj3mw6123eUe4osWEbHavCv7FDqgFChzfedPDmgnHm9qnQrdveb8sVrywNxxBYCXTdaeNyxRRmhF4q33ovb"],
          ["클럽 작가 소설 부족 별도 일정 모금 확장 소형 콤플렉스 회복 촛불 위성 성별 비바람", "😎",
            "xprv9s21ZrQH143K43d7XRnapkCsoE2bLUJfA57hYseNpDaJxf5rpuhHgHjSXNMGMpaGYNNZfxxBzv1e2kW5CSy7p1rddfWYXtvYhgC6MPfHd9Z"],
          ["theme rain hollow final expire proud detect wife hotel taxi witness strategy park head forest", "🍔🍟🌭🍕",
            "xprv9s21ZrQH143K2k5PPw697AeKWWdeQueM2JCKu8bsmF7M7dDmPGHecHJJNGeujWTJ97Fy9PfobsgZfxhcpWaYyAauFMxcy4fo3x7JNnbYQyD"],
        ];
        for x in TEST_DATA {
            let xpriv = Xpriv::from_mnemonic(x[0], x[1])?;
            assert_eq!(xpriv.to_string(), x[2]);
        }

        const INVALID_CHECKSUM: &[&str] = &[
          "solda osso frasco encontro donzela oficina colono vidraria fruteira sinal visto sacola mirtilo flamingo final",
          "theme rain hollow sinal expire proud detect wife hotel taxi witness strategy park head forest",
          "岗 跨 困 倒 考 邦 调 晒 慢 孟 畅 句 埋 黎 皮"
        ];
        for x in INVALID_CHECKSUM {
            let r = Xpriv::from_mnemonic(*x, Default::default());
            assert!(matches!(r, Err(Bip39Error::InvalidParameter(_))));
        }

        const INVALID_LENGTH: &[&str] = &[
            " 跨 困 倒 考 邦 调 晒 慢 孟 畅 句 埋 黎 皮",
            "theme rain hollow sinal expire proud detect wife hotel taxi witness",
        ];
        for x in INVALID_LENGTH {
            let r = Xpriv::from_mnemonic(*x, Default::default());
            assert!(matches!(r, Err(Bip39Error::InvalidParameter(_))));
        }
        Ok(())
    }
}
