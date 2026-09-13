#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sops,
    Vault,
    Op,
    AwsSecrets,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    #[error("not a reference: value does not start with `ref+`")]
    NotARef,
    #[error("missing `://` after backend")]
    MissingSeparator,
    #[error("empty backend")]
    EmptyBackend,
    #[error("unknown backend `{0}`")]
    UnknownBackend(String),
    #[error("empty path")]
    EmptyPath,
    #[error("invalid fragment: {0}")]
    InvalidFragment(&'static str),
    #[error("backend not implemented")]
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    backend: Backend,
    path: String,
    params: Option<String>,
    fragment: Option<String>,
}

impl std::fmt::Display for Ref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backend = match self.backend {
            Backend::Sops => "sops",
            Backend::Vault => "vault",
            Backend::Op => "op",
            Backend::AwsSecrets => "awssecrets",
        };
        write!(f, "ref+{backend}://{}", self.path)
            .and_then(|()| self.params.as_ref().map_or(Ok(()), |p| write!(f, "?{p}")))
            .and_then(|()| {
                self.fragment
                    .as_ref()
                    .map_or(Ok(()), |fragment| write!(f, "#{fragment}"))
            })
    }
}
impl Backend {
    fn from_token(token: &str) -> Result<Backend, RefError> {
        match token {
            "" => Err(RefError::EmptyBackend),
            "sops" => Ok(Backend::Sops),
            "vault" => Ok(Backend::Vault),
            "op" => Ok(Backend::Op),
            "awssecrets" => Ok(Backend::AwsSecrets),
            other => Err(RefError::UnknownBackend(other.to_string())),
        }
    }
}

impl Ref {
    pub fn parse(s: &str) -> Result<Ref, RefError> {
        let rest = s.strip_prefix("ref+").ok_or(RefError::NotARef)?;
        let (token, rest) = rest.split_once("://").ok_or(RefError::MissingSeparator)?;
        let backend = Backend::from_token(token)?;

        let (path, tail) = match rest.find(['?', '#']) {
            Some(i) => (&rest[..i], Some(&rest[i..])),
            None => (rest, None),
        };
        if path.is_empty() {
            return Err(RefError::EmptyPath);
        }

        let (params, fragment) = match tail {
            None => (None, None),
            Some(tail) => match tail.strip_prefix('?') {
                Some(query) => match query.split_once('#') {
                    Some((params, fragment)) => {
                        (Some(params.to_string()), Some(fragment.to_string()))
                    }
                    None => (Some(query.to_string()), None),
                },
                None => (None, Some(tail[1..].to_string())),
            },
        };

        if let Some(f) = &fragment {
            if !f.is_empty() && !f.starts_with('/') {
                return Err(RefError::InvalidFragment("must start with `/`"));
            }
        }

        Ok(Ref {
            backend,
            path: path.to_string(),
            params,
            fragment,
        })
    }

    pub fn is_ref(s: &str) -> bool {
        s.starts_with("ref+")
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn params(&self) -> Option<&str> {
        self.params.as_deref()
    }

    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    pub fn pointer(&self) -> Result<Vec<String>, RefError> {
        match self.fragment.as_deref() {
            None => Ok(Vec::new()),
            Some(fragment) => decode_pointer(fragment),
        }
    }

    pub fn ensure_supported(&self) -> Result<(), RefError> {
        match self.backend {
            Backend::Sops => Ok(()),
            Backend::Vault | Backend::Op | Backend::AwsSecrets => Err(RefError::NotImplemented),
        }
    }
}

pub fn decode_pointer(fragment: &str) -> Result<Vec<String>, RefError> {
    match fragment.strip_prefix('/') {
        Some(body) => body.split('/').map(unescape_token).collect(),
        None if fragment.is_empty() => Ok(Vec::new()),
        None => Err(RefError::InvalidFragment("must start with `/`")),
    }
}

fn unescape_token(token: &str) -> Result<String, RefError> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return Err(RefError::InvalidFragment("invalid `~` escape")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Backend, Ref, RefError};

    struct ParseOk {
        input: &'static str,
        backend: Backend,
        path: &'static str,
        params: Option<&'static str>,
        fragment: Option<&'static str>,
    }

    const PARSE_OK: &[ParseOk] = &[
        ParseOk {
            input: "ref+sops://path#/a",
            backend: Backend::Sops,
            path: "path",
            params: None,
            fragment: Some("/a"),
        },
        ParseOk {
            input: "ref+sops://.yett/secrets.dev.enc.yaml#/db/password",
            backend: Backend::Sops,
            path: ".yett/secrets.dev.enc.yaml",
            params: None,
            fragment: Some("/db/password"),
        },
        ParseOk {
            input: "ref+sops://p?a=1&b=2#/x",
            backend: Backend::Sops,
            path: "p",
            params: Some("a=1&b=2"),
            fragment: Some("/x"),
        },
        ParseOk {
            input: "ref+sops://p?a=1",
            backend: Backend::Sops,
            path: "p",
            params: Some("a=1"),
            fragment: None,
        },
        ParseOk {
            input: "ref+sops://p?",
            backend: Backend::Sops,
            path: "p",
            params: Some(""),
            fragment: None,
        },
        ParseOk {
            input: "ref+sops://p?#/x",
            backend: Backend::Sops,
            path: "p",
            params: Some(""),
            fragment: Some("/x"),
        },
        ParseOk {
            input: "ref+sops://p",
            backend: Backend::Sops,
            path: "p",
            params: None,
            fragment: None,
        },
        ParseOk {
            input: "ref+sops://p#",
            backend: Backend::Sops,
            path: "p",
            params: None,
            fragment: Some(""),
        },
        ParseOk {
            input: "ref+sops://a%20b#/x",
            backend: Backend::Sops,
            path: "a%20b",
            params: None,
            fragment: Some("/x"),
        },
        ParseOk {
            input: "ref+sops://p#/a?b",
            backend: Backend::Sops,
            path: "p",
            params: None,
            fragment: Some("/a?b"),
        },
        ParseOk {
            input: "ref+vault://secret/data/app#/key",
            backend: Backend::Vault,
            path: "secret/data/app",
            params: None,
            fragment: Some("/key"),
        },
        ParseOk {
            input: "ref+op://vault/item#/field",
            backend: Backend::Op,
            path: "vault/item",
            params: None,
            fragment: Some("/field"),
        },
        ParseOk {
            input: "ref+awssecrets://prod/db#/password",
            backend: Backend::AwsSecrets,
            path: "prod/db",
            params: None,
            fragment: Some("/password"),
        },
    ];
    #[test]
    fn parses_valid_references() {
        for case in PARSE_OK {
            let r = Ref::parse(case.input).unwrap_or_else(|e| panic!("{}: {e}", case.input));
            assert_eq!(r.backend(), case.backend, "{}", case.input);
            assert_eq!(r.path(), case.path, "{}", case.input);
            assert_eq!(r.params(), case.params, "{}", case.input);
            assert_eq!(r.fragment(), case.fragment, "{}", case.input);
        }
    }
    const PARSE_ERR: &[(&str, RefError)] = &[
        ("plain-string", RefError::NotARef),
        ("", RefError::NotARef),
        ("REF+sops://p#/a", RefError::NotARef),
        ("ref:sops://p", RefError::NotARef),
        ("ref+doppler://x", RefError::UnknownBackend(String::new())),
        ("ref+SOPS://p#/a", RefError::UnknownBackend(String::new())),
        ("ref+sops:/p", RefError::MissingSeparator),
        ("ref+sops", RefError::MissingSeparator),
        ("ref+://x", RefError::EmptyBackend),
        ("ref+sops://", RefError::EmptyPath),
        ("ref+sops://#/a", RefError::EmptyPath),
        ("ref+sops://?a=1", RefError::EmptyPath),
        ("ref+sops://x#a/b", RefError::InvalidFragment("")),
        ("ref+sops://x#a", RefError::InvalidFragment("")),
    ];

    fn same_variant(a: &RefError, b: &RefError) -> bool {
        std::mem::discriminant(a) == std::mem::discriminant(b)
    }

    #[test]
    fn rejects_invalid_references() {
        for (input, want) in PARSE_ERR {
            let got = Ref::parse(input).expect_err(input);
            assert!(
                same_variant(&got, want),
                "{input}: got {got:?}, want {want:?}"
            );
        }
    }

    #[test]
    fn unknown_backend_carries_the_name() {
        let err = Ref::parse("ref+doppler://x").unwrap_err();
        assert_eq!(err, RefError::UnknownBackend("doppler".to_string()));
    }

    const POINTER_OK: &[(&str, &[&str])] = &[
        ("ref+sops://p", &[]),
        ("ref+sops://p#", &[]),
        ("ref+sops://p#/a", &["a"]),
        ("ref+sops://p#/db/password", &["db", "password"]),
        ("ref+sops://p#/", &[""]),
        ("ref+sops://p#/a~0b", &["a~b"]),
        ("ref+sops://p#/a~1b", &["a/b"]),
        ("ref+sops://p#/~01", &["~1"]),
        ("ref+sops://p#/~10", &["/0"]),
        ("ref+sops://p#/a~0~1b", &["a~/b"]),
        ("ref+sops://p?x=1#/a/b", &["a", "b"]),
    ];

    #[test]
    fn decodes_pointers() {
        for (input, want) in POINTER_OK {
            let r = Ref::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            let got = r.pointer().unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got, *want, "{input}");
        }
    }

    const POINTER_ERR: &[&str] = &[
        "ref+sops://p#/a~2b",
        "ref+sops://p#/a~",
        "ref+sops://p#/~",
        "ref+sops://p#/a~b/c",
    ];

    #[test]
    fn rejects_bad_pointer_escapes() {
        for input in POINTER_ERR {
            let r = Ref::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            let err = r.pointer().expect_err(input);
            assert!(
                same_variant(&err, &RefError::InvalidFragment("")),
                "{input}: got {err:?}"
            );
        }
    }

    const SUPPORTED: &[(&str, bool)] = &[
        ("ref+sops://p#/a", true),
        ("ref+vault://p#/a", false),
        ("ref+op://p#/a", false),
        ("ref+awssecrets://p#/a", false),
    ];

    #[test]
    fn reserved_backends_parse_but_are_not_supported() {
        for (input, ok) in SUPPORTED {
            let r = Ref::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            match r.ensure_supported() {
                Ok(()) => assert!(ok, "{input}: expected NotImplemented"),
                Err(e) => {
                    assert!(!ok, "{input}: expected Ok");
                    assert_eq!(e, RefError::NotImplemented, "{input}");
                    assert_eq!(e.to_string(), "backend not implemented", "{input}");
                }
            }
        }
    }

    const IS_REF: &[(&str, bool)] = &[
        ("ref+sops://p#/a", true),
        ("ref+", true),
        ("ref+nonsense", true),
        ("REF+sops://p#/a", false),
        ("plain", false),
        ("", false),
        (" ref+sops://p", false),
    ];

    #[test]
    fn is_ref_matches_the_prefix() {
        for (input, want) in IS_REF {
            assert_eq!(Ref::is_ref(input), *want, "{input}");
        }
    }
}
