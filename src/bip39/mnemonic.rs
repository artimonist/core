use super::Language;
use sha2::{Digest, Sha256};
use xbits::{FromBits, XBits};

/// A BIP39 mnemonic phrase, which is a sequence of words
/// used to represent a seed for cryptographic purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mnemonic {
    words: Vec<String>,
    language: Language,
}

type MnemonicError = super::Bip39Error;

#[allow(unused)]
impl Mnemonic {
    const fn check_mask(len: usize) -> u8 {
        match len {
            12 => 0b1111_0000,
            15 => 0b1111_1000,
            18 => 0b1111_1100,
            21 => 0b1111_1110,
            24 => 0b1111_1111,
            _ => unreachable!(),
        }
    }

    /// Create a new mnemonic from raw entropy and language.
    /// # Arguments
    /// * `entropy` - A byte slice representing the entropy.  
    ///   The entropy length must be one of: 16, 20, 24, 28, or 32 bytes.
    ///   Mnemonic lengths will be 12, 15, 18, 21, or 24 words respectively.
    /// * `language` - The language of the mnemonic.
    /// # Returns
    /// * `Ok(Mnemonic)` - If the mnemonic is successfully created.
    pub fn new(entropy: &[u8], language: Language) -> Result<Self, MnemonicError> {
        // verify length
        let length = match entropy.len() {
            16 => 12,
            20 => 15,
            24 => 18,
            28 => 21,
            32 => 24,
            _ => return Err(MnemonicError::InvalidLength),
        };

        // calculate checksum
        let checksum = Sha256::digest(entropy)[0] & Mnemonic::check_mask(length);

        // convert entropy to indices
        let indices: Vec<usize> = [entropy.to_vec(), vec![checksum]]
            .concat()
            .bits()
            .chunks(11)
            .take(length)
            .collect();

        // convert indices to words
        let words = indices
            .iter()
            .map(|&i| language.word_at(i).unwrap_or_default().to_string())
            .collect();

        Ok(Mnemonic { words, language })
    }

    /// Mnemonic words count.
    #[inline]
    pub fn count(&self) -> usize {
        self.words.len()
    }

    /// Mnemonic words indices.
    #[inline]
    pub fn indices(&self) -> Vec<usize> {
        self.language.indices(self.words.iter()).unwrap()[..self.words.len()].to_vec()
    }

    /// Detect the language of a mnemonic phrase based on its words.
    pub fn detect_language<T>(words: impl Iterator<Item = T>) -> Vec<Language>
    where
        T: AsRef<str>,
    {
        // words common languages
        words
            .map(|w| Language::detect(w.as_ref()))
            .reduce(|mut acc, v| {
                acc.retain(|x| v.contains(x));
                acc
            })
            .unwrap_or_default()
    }

    /// Verify the checksum of a mnemonic phrase based on its indices.
    pub fn verify_checksum(indices: &[usize]) -> Result<(), MnemonicError> {
        // verify length
        if !matches!(indices.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(MnemonicError::InvalidLength);
        }

        let mut entropy = Vec::from_bits_chunk(indices.iter().copied(), 11);
        let tail = entropy.pop().unwrap();
        let checksum = Sha256::digest(&entropy)[0] & Mnemonic::check_mask(indices.len());

        // verify checksum
        if checksum != tail {
            return Err(MnemonicError::InvalidChecksum);
        }
        Ok(())
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // verify length
        let words: Vec<&str> = s.split_whitespace().collect();
        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(MnemonicError::InvalidLength);
        }

        // detect languages
        let mut languages = Mnemonic::detect_language(words.iter());

        // verify checksum
        languages.retain(|&language| {
            if let Ok(indices) = language.indices(words.iter()) {
                Mnemonic::verify_checksum(&indices).is_ok()
            } else {
                false
            }
        });

        // return mnemonic
        match languages.len() {
            0 => Err(MnemonicError::InvalidChecksum),
            1 => Ok(Mnemonic {
                words: words.into_iter().map(String::from).collect(),
                language: languages.pop().unwrap(),
            }),
            2.. => Err(MnemonicError::InconclusiveLanguage(languages)),
        }
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.words.join(" "))
    }
}

trait Indices {
    fn indices<T>(&self, words: impl Iterator<Item = T>) -> Result<Vec<usize>, MnemonicError>
    where
        T: AsRef<str>;
}
impl Indices for Language {
    fn indices<T>(&self, words: impl Iterator<Item = T>) -> Result<Vec<usize>, MnemonicError>
    where
        T: AsRef<str>,
    {
        words
            .map(|w| self.index_of(w.as_ref()))
            .collect::<Option<Vec<_>>>()
            .ok_or(MnemonicError::InvalidLanguage)
    }
}
