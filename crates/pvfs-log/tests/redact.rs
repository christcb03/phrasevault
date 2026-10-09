//! PVOS D230 — a URL in a diagnostics bundle keeps no user, password or query.

use pvfs_log::redact_urls;

#[test]
fn urls_lose_their_user_password_and_query() {
    let t = "POST https://user:s3cret@splunk.example:8088/services/collector?token=abc123 failed; see http://10.0.0.5:3100/loki/api/v1/push and x";
    let r = redact_urls(t);
    assert!(!r.contains("s3cret") && !r.contains("abc123") && !r.contains("user:"), "{r}");
    assert!(r.contains("https://‹user›@splunk.example:8088/services/collector?‹…› failed"), "{r}");
    assert!(r.contains("http://10.0.0.5:3100/loki/api/v1/push and x"), "{r}");
    assert_eq!(redact_urls("no urls here"), "no urls here");
    assert_eq!(redact_urls("\"https://h/p?k=v\""), "\"https://h/p?‹…›\"");
}
