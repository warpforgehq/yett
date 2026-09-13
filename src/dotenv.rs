use std::path::{Path, PathBuf};

use crate::envfile::is_valid_key;

#[derive(Debug, thiserror::Error)]
pub enum DotenvError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("line {line}: expected KEY=VALUE")]
    MissingEquals { line: usize },
    #[error("line {line}: invalid key `{key}`")]
    InvalidKey { line: usize, key: String },
    #[error("line {line}: multiline values are not supported")]
    Multiline { line: usize },
    #[error("line {line}: unsupported escape `\\{escape}` in double-quoted value")]
    Escape { line: usize, escape: char },
}

#[derive(Debug, Default)]
pub struct Dotenv {
    entries: Vec<(String, String)>,
}

impl Dotenv {
    pub fn load(path: &Path) -> Result<Self, DotenvError> {
        let text = std::fs::read_to_string(path).map_err(|source| DotenvError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, DotenvError> {
        let mut entries = Vec::new();
        for (index, raw) in text.split('\n').enumerate() {
            let line = index + 1;
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = raw.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            let (key, raw_value) = body
                .split_once('=')
                .ok_or(DotenvError::MissingEquals { line })?;
            if !is_valid_key(key) {
                return Err(DotenvError::InvalidKey {
                    line,
                    key: key.to_string(),
                });
            }
            let value = parse_value(raw_value, line)?;
            match entries.iter().position(|(name, _)| name == key) {
                Some(position) => entries[position].1 = value,
                None => entries.push((key.to_string(), value)),
            }
        }
        Ok(Self { entries })
    }

    pub fn into_entries(self) -> Vec<(String, String)> {
        self.entries
    }
}

fn parse_value(raw: &str, line: usize) -> Result<String, DotenvError> {
    if raw.ends_with('\\') {
        return Err(DotenvError::Multiline { line });
    }
    let Some(quote) = raw.chars().next().filter(|c| *c == '\'' || *c == '"') else {
        return Ok(raw.to_string());
    };
    if raw.len() < 2 || !raw.ends_with(quote) {
        return Err(DotenvError::Multiline { line });
    }
    let inner = &raw[quote.len_utf8()..raw.len() - quote.len_utf8()];
    if quote == '\'' {
        return Ok(inner.to_string());
    }
    decode_double(inner, line)
}

fn decode_double(inner: &str, line: usize) -> Result<String, DotenvError> {
    let mut value = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('t') => value.push('\t'),
            Some('\\') => value.push('\\'),
            Some('"') => value.push('"'),
            Some(escape) => return Err(DotenvError::Escape { line, escape }),
            None => return Err(DotenvError::Multiline { line }),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_exports_and_last_duplicate() {
        let parsed = Dotenv::parse(
            "# comment\nexport A='one'\nB= verbatim \nC=\"line\\nnext\\t\\\\\\\"\"\nA=last\r\n",
        )
        .unwrap();
        assert_eq!(
            parsed.into_entries(),
            vec![
                ("A".into(), "last".into()),
                ("B".into(), " verbatim ".into()),
                ("C".into(), "line\nnext\t\\\"".into())
            ]
        );
    }

    #[test]
    fn rejects_invalid_and_multiline_values_with_line_numbers() {
        let invalid = Dotenv::parse("OK=1\nbad-key=2\n").unwrap_err();
        assert_eq!(invalid.to_string(), "line 2: invalid key `bad-key`");
        let multiline = Dotenv::parse("A=\"open\nB=next\n").unwrap_err();
        assert_eq!(
            multiline.to_string(),
            "line 1: multiline values are not supported"
        );
    }
}
