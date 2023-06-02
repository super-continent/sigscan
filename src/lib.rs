use std::{
    collections::HashMap,
    ops::{Index, Range, RangeFrom, RangeFull, RangeTo},
};

#[derive(Debug, Clone)]
pub struct SigScan(Vec<ScannerByte>);

impl SigScan {
    /// Create a new SigScan directly.
    /// You most likely do not want to call this and instead should use
    /// [`sigscan`] or [`new_yara`](SigScan::new_yara) to create this type more easily.
    pub fn new(pattern: Vec<ScannerByte>) -> Self {
        Self(pattern)
    }

    /// Create a new `SigScan` using a Yara-style pattern string.
    /// 
    /// # Panics
    /// This function will panic if the string:
    /// - Is empty
    /// - Contains characters other than hex digits, `?`, or whitespace
    /// - contains an odd number of (non-whitespace) characters
    pub fn new_yara_style(pattern: &str) -> Self {
        yara_style(pattern)
    }

    pub fn scan(&self, haystack: impl AsRef<[u8]>) -> Option<usize> {
        scan_aob(haystack.as_ref(), self)
    }

    fn contains_masked_character(&self) -> bool {
        self.0.iter().any(|x| {
            if let ScannerByte::MaskedByte { .. } = x {
                true
            } else {
                false
            }
        })
    }
}

/// A single byte to match in a pattern.
/// You probably don't want to directly interface with this type.
/// Use [`sigscan`] to construct a pattern
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ScannerByte {
    Byte(u8),
    MaskedByte { byte: u8, mask: u8 },
    Unknown,
}

impl ScannerByte {
    #[inline]
    pub fn matches(self, rhs: u8) -> bool {
        match self {
            ScannerByte::Byte(byte) => byte == rhs,
            ScannerByte::MaskedByte { byte, mask } => ((byte ^ rhs) & mask) == 0,
            ScannerByte::Unknown => true,
        }
    }
}

macro_rules! impl_indexing {
    ($index_type:ty, $output:ty) => {
        impl Index<$index_type> for SigScan {
            type Output = $output;

            fn index(&self, index: $index_type) -> &Self::Output {
                &self.0[index]
            }
        }
    };
}

impl_indexing!(usize, ScannerByte);
impl_indexing!(Range<usize>, [ScannerByte]);
impl_indexing!(RangeTo<usize>, [ScannerByte]);
impl_indexing!(RangeFrom<usize>, [ScannerByte]);
impl_indexing!(RangeFull, [ScannerByte]);

/// Directly create an AOB signature scanner.
/// This macro allows finer control over byte masks than the yara-style string syntax.
///
/// # Syntax
/// ```
/// use sigscan::sigscan;
/// 
/// let pattern = sigscan!(0x20, _, (0x50 mask 0xF0));
/// ```
/// This pattern will match the pattern `0x20` (a literal) followed by any byte (_ is a wildcard),
/// followed by a byte that is the same as the high nibble of `0x50`, as
/// `(0x50 mask 0xF0)` translates to `((0x50 ^ byte) & 0xF0) == 0`
///
/// # Notes
/// Constructing a [`SigScan`] with no masked bytes should perform significantly better than with masked bytes.
/// This is because internally scanning uses boyer-moore-horspool substring search,
/// which cant have a skip table containing masked characters.
/// For patterns where masked bytes are present, a simple brute-force substring search will be used.
#[macro_export]
macro_rules! sigscan {
    ( $( $x:tt ),* ) => {
        $crate::SigScan::new(
            vec![ $( sigscan!(@BYTE $x), )* ]
        )
    };
    (@BYTE $x:literal) => { $crate::ScannerByte::Byte($x) };
    (@BYTE ($num:literal mask $mask:literal)) => { $crate::ScannerByte::MaskedByte {
        byte: $num,
        mask: $mask,
    } };
    (@BYTE _) => { $crate::ScannerByte::Unknown };
}

fn yara_style(pattern: &str) -> SigScan {
    let pattern = pattern
        .chars()
        .filter(|x| !x.is_whitespace())
        .collect::<Vec<char>>();
    assert!(
        !pattern.is_empty(),
        "byte pattern must not be an empty string"
    );
    assert!(
        pattern.len() % 2 == 0,
        "byte pattern did not contain an even number of characters"
    );
    assert!(
        pattern.iter().all(|x| *x == '?' || x.is_ascii_hexdigit()),
        "byte pattern must only contain hex digits and `?` characters"
    );

    let mut scanner: Vec<ScannerByte> = vec![];

    let mut chunks = pattern.chunks(2);

    while let Some([hi, lo]) = chunks.next() {
        match (*hi, *lo) {
            ('?', '?') => scanner.push(ScannerByte::Unknown),
            (hi, '?') => {
                let value = u8::from_str_radix(&hi.to_string(), 16).unwrap();
                scanner.push(ScannerByte::MaskedByte {
                    byte: value << 4,
                    mask: 0xF0,
                });
            }
            ('?', lo) => {
                let value = u8::from_str_radix(&lo.to_string(), 16).unwrap();
                scanner.push(ScannerByte::MaskedByte {
                    byte: value,
                    mask: 0x0F,
                });
            }
            (hi, lo) => {
                let value = u8::from_str_radix(&String::from_iter([hi, lo]), 16).unwrap();
                scanner.push(ScannerByte::Byte(value));
            }
        }
    }

    SigScan(scanner)
}

fn scan_aob(haystack: &[u8], needle: &SigScan) -> Option<usize> {
    let (pattern_len, haystack_len) = (needle.0.len(), haystack.len());

    if pattern_len > haystack_len {
        panic!("pattern length must be less than haystack length")
    }

    let mut skips: HashMap<u8, usize> = HashMap::new();

    if !needle.contains_masked_character() {
        // BMH preprocessing only occurs when there arent any masked bytes
        // because masked bytes make constructing the skip table impossible
        needle[..pattern_len - 1]
            .iter()
            .enumerate()
            .for_each(|(idx, byte)| {
                if let ScannerByte::Byte(b) = *byte {
                    skips.insert(b, pattern_len - 1 - idx);
                };
            });
    }

    let mut haystack_idx = pattern_len - 1;
    while haystack_idx < haystack_len {
        let mut amount_to_skip_by = 1;

        let mut hay_idx = haystack_idx;
        for pat_idx in (0..pattern_len).rev() {
            let character = needle[pat_idx];

            if !character.matches(haystack[hay_idx]) {
                // only use skips >1 if there are no masked characters
                if !skips.is_empty() {
                    if let ScannerByte::Byte(b) = character {
                        amount_to_skip_by = skips.get(&b).map(|x| *x).unwrap_or(pattern_len)
                    }
                }

                break;
            }

            if pat_idx == 0 {
                return Some(hay_idx);
            }

            hay_idx -= 1;
        }

        haystack_idx += amount_to_skip_by;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let pattern_macro: SigScan = sigscan!(b'a', _, (0x50 mask 0xF0));
        let pattern_yara = SigScan::new_yara_style("61 ?? 5?");

        assert!(pattern_macro.0 == pattern_yara.0);

        let haystack = b"ab\x5F";

        let result = pattern_macro.scan(haystack);
        assert!(Some(0) == result);

        let haystack = b"ad\x60";

        let result = pattern_macro.scan(haystack);

        assert!(None == result);
    }
}
