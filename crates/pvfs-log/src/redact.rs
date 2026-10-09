//! PVOS D230 — text that leaves the box in a diagnostics bundle.

/// Every `scheme://user:pass@host/path?query#frag` cut to
/// `scheme://host/path`: a URL's user, password, query or fragment can hold
/// a token (Splunk's, a webhook's).
pub fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail.find(|c: char| c.is_whitespace() || "\"'<>)]},".contains(c)).unwrap_or(tail.len());
        let url = &tail[..end];
        let url = url.split(['?', '#']).next().unwrap_or("");
        let (authority, path) = match url.find('/') {
            Some(j) => (&url[..j], &url[j..]),
            None => (url, ""),
        };
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if host.len() != authority.len() {
            out.push_str("‹user›@");
        }
        out.push_str(host);
        out.push_str(path);
        if end > url.len() && tail[url.len()..end].starts_with(['?', '#']) {
            out.push_str("?‹…›");
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

