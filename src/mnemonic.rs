//! Recovery keys as 24 BIP-39 words: 256 bits of entropy plus an 8-bit SHA-256 checksum,
//! 11 bits per word. The English list is embedded (`mnemonic/english.txt`, the list of the
//! BIP-39 repository) rather than pulled in with a crate.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::schema::Secret;

pub const WORD_COUNT: usize = 24;
pub type Entropy = Zeroizing<[u8; 32]>;

const LIST: &str = include_str!("mnemonic/english.txt");

fn words() -> Vec<&'static str> {
    // `lines` also drops a `\r`, in case Git checked the list out with Windows line endings.
    LIST.lines().collect()
}

fn checksum(entropy: &[u8; 32]) -> u8 {
    Sha256::digest(entropy)[0]
}

/// The 24 words of `entropy`, separated by single spaces.
pub fn encode(entropy: &[u8; 32]) -> Secret {
    let list = words();
    let mut bits = Zeroizing::new(Vec::with_capacity(33));
    bits.extend_from_slice(entropy);
    bits.push(checksum(entropy));

    let index = |word: usize| -> usize {
        (0..11).fold(0usize, |acc, offset| {
            let bit = word * 11 + offset;
            let set = bits[bit / 8] >> (7 - bit % 8) & 1;
            acc << 1 | usize::from(set)
        })
    };
    let mut phrase = String::with_capacity(WORD_COUNT * 9);
    for word in 0..WORD_COUNT {
        if word > 0 {
            phrase.push(' ');
        }
        phrase.push_str(list[index(word)]);
    }
    Secret::new(phrase)
}

/// The entropy of 24 words separated by whitespace (case is ignored).
pub fn decode(phrase: &str) -> Result<Entropy> {
    let list = words();
    let given: Vec<String> = phrase.split_whitespace().map(str::to_lowercase).collect();
    if given.len() != WORD_COUNT {
        bail!(
            "A recovery key has {WORD_COUNT} words, {} were given.",
            given.len()
        );
    }

    let mut bits = Zeroizing::new([0u8; 33]);
    for (position, word) in given.iter().enumerate() {
        let Ok(index) = list.binary_search(&word.as_str()) else {
            bail!("Word #{} is not a recovery key word.", position + 1);
        };
        for offset in 0..11 {
            if index >> (10 - offset) & 1 == 1 {
                let bit = position * 11 + offset;
                bits[bit / 8] |= 1 << (7 - bit % 8);
            }
        }
    }

    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bits[..32]);
    if checksum(&entropy) != bits[32] {
        bail!("The recovery key is not valid: a word is wrong or out of order.");
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// The 256-bit vectors of the BIP-39 reference implementation.
    const VECTORS: [(&str, &str); 5] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
    ];

    #[test]
    fn the_embedded_list_is_the_bip39_english_list() {
        let list = words();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]), "sorted");
        let normalized = format!("{}\n", list.join("\n"));
        let digest: String = Sha256::digest(normalized.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn encoding_matches_the_reference_vectors() {
        for (entropy, phrase) in VECTORS {
            assert_eq!(encode(&hex(entropy)).expose_secret(), phrase);
            assert_eq!(*decode(phrase).unwrap(), hex(entropy));
        }
    }

    #[test]
    fn decoding_tolerates_case_and_spacing() {
        let (entropy, phrase) = VECTORS[4];
        let messy = format!("  {}\n", phrase.to_uppercase().replace(' ', "   "));
        assert_eq!(*decode(&messy).unwrap(), hex(entropy));
    }

    #[test]
    fn wrong_phrases_are_rejected() {
        let (_, phrase) = VECTORS[4];
        let err = decode("abandon abandon").unwrap_err().to_string();
        assert!(err.contains("24 words, 2 were given"), "{err}");

        let unknown = phrase.replacen("hamster", "hamburger", 1);
        let err = decode(&unknown).unwrap_err().to_string();
        assert!(err.contains("Word #1 is not"), "{err}");

        let swapped = phrase.replacen("hamster diagram", "diagram hamster", 1);
        let err = decode(&swapped).unwrap_err().to_string();
        assert!(err.contains("not valid"), "{err}");
    }
}
