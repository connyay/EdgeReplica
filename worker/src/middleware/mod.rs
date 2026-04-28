pub mod request_id;
pub mod session_auth;

pub use request_id::{HEADER_NAME, RequestId, RequestIdLayer};
pub use session_auth::{SessionAuthLayer, require_session};

pub(crate) fn extract_bearer(s: &str) -> Option<&str> {
    let s = s.trim();
    let prefix = "Bearer ";
    if s.len() > prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(s[prefix.len()..].trim())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_case_insensitively() {
        assert_eq!(extract_bearer("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("BEARER  abc "), Some("abc"));
        assert!(extract_bearer("Basic abc").is_none());
        assert!(extract_bearer("").is_none());
    }
}
