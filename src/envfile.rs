use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum EnvFileError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("line {line}: expected KEY=VALUE")]
    MissingEquals { line: usize },
    #[error("line {line}: invalid key `{key}`")]
    InvalidKey { line: usize, key: String },
    #[error("line {line}: duplicate key `{key}`")]
    DuplicateKey { line: usize, key: String },
}

#[derive(Debug, Default)]
pub struct EnvFile {
    entries: Vec<(String, String)>,
}

impl EnvFile {
    pub fn parse(text: &str) -> Result<Self, EnvFileError> {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);

            let (name, value) = body
                .split_once('=')
                .ok_or(EnvFileError::MissingEquals { line })?;
            let key = name.trim();
            if !is_valid_key(key) {
                return Err(EnvFileError::InvalidKey {
                    line,
                    key: key.to_string(),
                });
            }
            if !seen.insert(key.to_string()) {
                return Err(EnvFileError::DuplicateKey {
                    line,
                    key: key.to_string(),
                });
            }

            entries.push((key.to_string(), value.trim_start().to_string()));
        }

        Ok(EnvFile { entries })
    }

    pub fn load(path: &Path) -> Result<Self, EnvFileError> {
        let text = std::fs::read_to_string(path).map_err(|source| EnvFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(String, String)> {
        EnvFile::parse(text)
            .unwrap_or_else(|e| panic!("{text:?}: {e}"))
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const OK: &[(&str, &[(&str, &str)])] = &[
        ("A=1\nB=2\n", &[("A", "1"), ("B", "2")]),
        ("\n  \nA=1\n\t\n", &[("A", "1")]),
        ("# comment\n  # indented\nA=1\n", &[("A", "1")]),
        ("export A=1\n", &[("A", "1")]),
        ("  export A=1\n", &[("A", "1")]),
        ("export  A=1\n", &[("A", "1")]),
        ("A = 1\n", &[("A", "1")]),
        ("A=   1\n", &[("A", "1")]),
        ("A=1   \n", &[("A", "1   ")]),
        ("A=\n", &[("A", "")]),
        ("A=   \n", &[("A", "")]),
        ("A=foo#bar\n", &[("A", "foo#bar")]),
        ("A=1 # not a comment\n", &[("A", "1 # not a comment")]),
        ("A=\"quoted\"\n", &[("A", "\"quoted\"")]),
        ("A='quoted'\n", &[("A", "'quoted'")]),
        ("_A1=ok\n", &[("_A1", "ok")]),
        ("A=b=c\n", &[("A", "b=c")]),
        ("exportA=1\n", &[("exportA", "1")]),
        ("  A=1\n", &[("A", "1")]),
        (
            "A=ref+sops://x.enc.yaml#/y\n",
            &[("A", "ref+sops://x.enc.yaml#/y")],
        ),
        ("A=1\r\nB=2\r\n", &[("A", "1"), ("B", "2")]),
        ("\tA\t=\tvalue\t\n", &[("A", "value\t")]),
        (
            "A=1\nB=2\n\nA_B=3\n",
            &[("A", "1"), ("B", "2"), ("A_B", "3")],
        ),
    ];

    #[test]
    fn parses_the_subset() {
        for (input, want) in OK {
            let got = pairs(input);
            let want: Vec<(String, String)> = want
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            assert_eq!(got, want, "{input:?}");
        }
    }

    #[test]
    fn strips_a_carriage_return() {
        let got = pairs("A=1\r\nB=2\r\n");
        assert_eq!(got[0].1, "1");
        assert_eq!(got[1].1, "2");
    }

    fn kind(e: &EnvFileError) -> u8 {
        match e {
            EnvFileError::Read { .. } => 0,
            EnvFileError::MissingEquals { .. } => 1,
            EnvFileError::InvalidKey { .. } => 2,
            EnvFileError::DuplicateKey { .. } => 3,
        }
    }

    const ERR: &[(&str, u8, usize)] = &[
        ("A\n", 1, 1),
        ("A=1\nB\n", 1, 2),
        ("# c\nA=1\nB\n", 1, 3),
        ("export\n", 1, 1),
        ("=1\n", 2, 1),
        ("export =1\n", 2, 1),
        ("1A=1\n", 2, 1),
        ("A B=1\n", 2, 1),
        ("A-B=1\n", 2, 1),
        ("A=1\nA=2\n", 3, 2),
        ("A=1\nB=2\nA=3\n", 3, 3),
    ];

    #[test]
    fn rejects_bad_lines_with_their_line_number() {
        for (input, want_kind, want_line) in ERR {
            let err = EnvFile::parse(input).expect_err(input);
            assert_eq!(kind(&err), *want_kind, "{input:?}: {err:?}");
            let text = err.to_string();
            assert!(
                text.contains(&format!("line {want_line}")),
                "{input:?}: {text:?}"
            );
        }
    }

    #[test]
    fn distinct_case_is_not_a_duplicate() {
        let got = pairs("A=1\na=2\n");
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn invalid_key_error_names_the_key() {
        let err = EnvFile::parse("bad key=1\n").expect_err("bad key");
        assert_eq!(err.to_string(), "line 1: invalid key `bad key`");
    }

    #[test]
    fn a_missing_file_is_a_read_error() {
        let err =
            EnvFile::load(Path::new("/nonexistent/yett/.env.refs")).expect_err("missing file");
        assert!(matches!(err, EnvFileError::Read { .. }), "{err:?}");
        assert!(err.to_string().contains("cannot read"), "{err}");
    }
}
