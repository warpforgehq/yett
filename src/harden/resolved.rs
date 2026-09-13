use secrecy::{ExposeSecret, SecretString};

use super::PageLocks;

pub struct ResolvedSecret {
    inner: SecretString,
    locks: PageLocks,
}

impl ResolvedSecret {
    pub fn new(value: String) -> Self {
        let inner = SecretString::from(value);
        let locks = PageLocks::for_bytes(inner.expose_secret());
        ResolvedSecret { inner, locks }
    }

    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

impl Drop for ResolvedSecret {
    fn drop(&mut self) {
        use secrecy::ExposeSecretMut;
        use zeroize::Zeroize;

        self.inner.expose_secret_mut().zeroize();
        self.locks.release();
    }
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResolvedSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn keeps_the_value_readable_and_redacted() {
        let secret = ResolvedSecret::new("hunter2".to_string());

        assert_eq!(secret.expose_secret(), "hunter2");
        assert_eq!(secret.len(), 7);
        assert!(!secret.is_empty());
        assert_eq!(format!("{secret:?}"), "ResolvedSecret(<redacted>)");
    }

    #[test]
    fn an_empty_value_stays_empty() {
        let secret = ResolvedSecret::new(String::new());

        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn the_inner_buffer_is_wiped() {
        let mut secret = ResolvedSecret::new("wipe-me-please".to_string());
        let ptr = secret.inner.expose_secret().as_ptr();
        let len = secret.inner.expose_secret().len();

        secret.wipe_in_place();

        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "the buffer must be wiped"
        );
    }

    impl ResolvedSecret {
        fn wipe_in_place(&mut self) {
            use secrecy::ExposeSecretMut;
            let bytes = unsafe { self.inner.expose_secret_mut().as_bytes_mut() };
            bytes.zeroize();
        }
    }
}
