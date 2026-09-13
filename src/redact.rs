use std::collections::BTreeMap;
use std::fmt;

use crate::harden::ResolvedSecret;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use zeroize::Zeroizing;

use crate::harden::SecretBuf;

const REDACTED: &str = "[REDACTED]";
const MIN_LENGTH: usize = 8;
const PERCENT_URL: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub struct Redactor {
    patterns: Vec<SecretBuf>,
}

impl Redactor {
    pub fn from_values(values: &BTreeMap<String, ResolvedSecret>) -> Self {
        let mut patterns: Vec<SecretBuf> = Vec::new();
        for value in values.values() {
            let secret = value.expose_secret();
            if secret.len() < MIN_LENGTH {
                continue;
            }
            let strict = Zeroizing::new(utf8_percent_encode(secret, NON_ALPHANUMERIC).to_string());
            let url = Zeroizing::new(utf8_percent_encode(secret, &PERCENT_URL).to_string());
            let strict_lower = Zeroizing::new(lowercase_percent_hex(&strict));
            let url_lower = Zeroizing::new(lowercase_percent_hex(&url));
            for pattern in [
                Zeroizing::new(secret.to_string()),
                Zeroizing::new(STANDARD.encode(secret)),
                strict,
                url,
                strict_lower,
                url_lower,
            ] {
                if !patterns
                    .iter()
                    .any(|seen| seen.as_str() == pattern.as_str())
                {
                    patterns.push(SecretBuf::new(pattern.as_str()));
                }
            }
        }
        patterns.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        Redactor { patterns }
    }

    pub fn apply(&self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for (start, _) in bytes.iter().enumerate() {
            let mut best = 0;
            for pattern in &self.patterns {
                let candidate = pattern.as_bytes();
                if candidate.len() > best && bytes[start..].starts_with(candidate) {
                    best = candidate.len();
                }
            }
            if best > 0 {
                spans.push((start, start + best));
            }
        }

        let mut out = String::with_capacity(line.len());
        let mut cursor = 0;
        let mut index = 0;
        while index < spans.len() {
            let start = spans[index].0;
            let mut end = spans[index].1;
            while index + 1 < spans.len() && spans[index + 1].0 < end {
                index += 1;
                if spans[index].1 > end {
                    end = spans[index].1;
                }
            }
            out.push_str(&line[cursor..start]);
            out.push_str(REDACTED);
            cursor = end;
            index += 1;
        }
        out.push_str(&line[cursor..]);
        out
    }
}

fn lowercase_percent_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '%' {
            for _ in 0..2 {
                if let Some(h) = chars.next() {
                    out.push(h.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redactor {{ patterns: {} }}", self.patterns.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(values: &[&str]) -> Redactor {
        let map: BTreeMap<String, ResolvedSecret> = values
            .iter()
            .enumerate()
            .map(|(i, value)| (format!("V{i}"), ResolvedSecret::new((*value).to_string())))
            .collect();
        Redactor::from_values(&map)
    }

    #[test]
    fn literal_is_redacted_in_the_middle_and_at_both_edges() {
        let r = redactor(&["supersecretvalue"]);
        assert_eq!(r.apply("token=supersecretvalue;"), "token=[REDACTED];");
        assert_eq!(r.apply("supersecretvalue tail"), "[REDACTED] tail");
        assert_eq!(r.apply("head supersecretvalue"), "head [REDACTED]");
        assert_eq!(r.apply("supersecretvalue"), "[REDACTED]");
    }

    #[test]
    fn standard_base64_is_redacted() {
        let r = redactor(&["hunter2hunter2"]);
        let encoded = "aHVudGVyMmh1bnRlcjI=";
        assert!(!"hunter2hunter2".contains(encoded));

        let line = format!("Authorization: Basic {encoded}");
        let safe = r.apply(&line);

        assert_eq!(safe, "Authorization: Basic [REDACTED]");
        assert!(!safe.contains(encoded), "{safe}");
    }

    #[test]
    fn percent_encoding_is_redacted() {
        let r = redactor(&["p@ss:w/rd!"]);
        let encoded = "p%40ss%3Aw%2Frd%21";

        let line = format!("https://example.com/?key={encoded}");
        let safe = r.apply(&line);

        assert_eq!(safe, "https://example.com/?key=[REDACTED]");
        assert!(!safe.contains(encoded), "{safe}");
    }

    #[test]
    fn seven_bytes_is_skipped_and_eight_bytes_is_redacted() {
        let seven = redactor(&["1234567"]);
        assert_eq!(seven.apply("x1234567y"), "x1234567y");

        let eight = redactor(&["12345678"]);
        assert_eq!(eight.apply("x12345678y"), "x[REDACTED]y");
    }

    #[test]
    fn a_unicode_value_is_redacted_in_all_three_forms() {
        let value = "pässwörd";
        assert_eq!(value.len(), 10);
        let r = redactor(&[value]);

        assert_eq!(r.apply("id=pässwörd"), "id=[REDACTED]");
        assert_eq!(r.apply("id=cMOkc3N3w7ZyZA=="), "id=[REDACTED]");
        assert_eq!(r.apply("id=p%C3%A4ssw%C3%B6rd"), "id=[REDACTED]");
    }

    #[test]
    fn a_substring_value_leaves_no_fragment() {
        let r = redactor(&["longsecretvalue", "secretvalue"]);

        let safe = r.apply("pre longsecretvalue mid secretvalue post");

        assert_eq!(safe, "pre [REDACTED] mid [REDACTED] post");
        assert!(!safe.contains("secretvalue"), "{safe}");
    }

    #[test]
    fn two_secrets_on_one_line_keep_their_surroundings() {
        let r = redactor(&["firstsecret99", "secondsecret88"]);

        let safe = r.apply("a=firstsecret99 b=secondsecret88 c");

        assert_eq!(safe, "a=[REDACTED] b=[REDACTED] c");
    }

    #[test]
    fn coincident_encodings_dedup_to_one_redaction() {
        let r = redactor(&["Abcdefgh123"]);

        assert_eq!(format!("{r:?}"), "Redactor { patterns: 2 }");
        assert_eq!(r.apply("Abcdefgh123"), "[REDACTED]");
        assert_eq!(r.apply("x Abcdefgh123 y"), "x [REDACTED] y");
    }

    #[test]
    fn conventional_url_encoding_is_redacted() {
        let r = redactor(&["abcd-efg/h"]);
        assert_eq!(r.apply("key=abcd-efg%2Fh"), "key=[REDACTED]");
        assert_eq!(r.apply("key=abcd%2Defg%2Fh"), "key=[REDACTED]");
        assert_eq!(r.apply("key=abcd-efg%2fh"), "key=[REDACTED]");
        assert_eq!(r.apply("key=abcd%2defg%2fh"), "key=[REDACTED]");
    }

    #[test]
    fn multibyte_values_gate_on_bytes_not_characters() {
        let four_chars = redactor(&["äöüü"]);
        assert_eq!(four_chars.apply("xäöüüy"), "x[REDACTED]y");

        let three_chars = redactor(&["äöü"]);
        assert_eq!(three_chars.apply("xäöüy"), "xäöüy");
    }

    #[test]
    fn a_clean_line_is_unchanged() {
        let r = redactor(&["supersecretvalue"]);
        let line = "nothing to see here";
        assert_eq!(r.apply(line), line);
    }

    #[test]
    fn an_empty_line_is_unchanged() {
        let r = redactor(&["supersecretvalue"]);
        assert_eq!(r.apply(""), "");
    }

    #[test]
    fn debug_never_prints_a_value_or_a_pattern() {
        let r = redactor(&["supersecretvalue"]);
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("supersecretvalue"), "{rendered}");
        assert!(rendered.contains("patterns"), "{rendered}");
    }
}
