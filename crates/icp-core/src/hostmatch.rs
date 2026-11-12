//! Matching a page's host against what is stored.
//!
//! The rules are conservative: a match needs a dotted boundary, so
//! `notexample.com` never matches `example.com`, and a stored host of `com`
//! would otherwise match every `.com` page.

/// Does the page's domain match the stored one?
///
/// Matches the exact host, and either being a sub-domain of the other (so
/// `example.com` fills on `login.example.com` and vice-versa).
pub fn domains_match(page: &str, stored: &str) -> bool {
    let p = normalise(page);
    let s = normalise(stored);
    if p.is_empty() || s.is_empty() {
        return false;
    }
    if p == s {
        return true;
    }
    if !p.contains('.') || !s.contains('.') {
        return false;
    }
    p.ends_with(&format!(".{s}")) || s.ends_with(&format!(".{p}"))
}

/// A host, in the form the matching uses: lower-case, without the scheme, the
/// port, the path or a leading `www.`.
pub fn normalise(value: &str) -> String {
    let mut v = value.trim().to_lowercase();
    if let Some((_, rest)) = v.split_once("://") {
        v = rest.to_string();
    }
    v = v.split('/').next().unwrap_or("").to_string();
    v = v.split('?').next().unwrap_or("").to_string();
    v = v.rsplit('@').next().unwrap_or("").to_string();
    v = v.split(':').next().unwrap_or("").to_string();
    if let Some(rest) = v.strip_prefix("www.") {
        v = rest.to_string();
    }
    v
}

/// A stored login with no host of its own can still match, by its title - but
/// only on the label left of the top-level domain, so a site like
/// `cloudflare.attacker.net` cannot claim a "Cloudflare" entry.
///
/// This is the fallback for the *dotless* entries only: a login stored against
/// `example.com` never matches `login.example.com` by its name.
pub fn title_matches(page: &str, title: &str) -> bool {
    if normalise(title).contains('.') {
        return false;
    }
    let host = normalise(page);
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return false;
    }
    let candidate = labels[labels.len() - 2];
    normalise(title) == candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_match_needs_a_dotted_boundary() {
        assert!(domains_match("example.com", "example.com"));
        assert!(domains_match("login.example.com", "example.com"));
        assert!(domains_match("example.com", "login.example.com"));
        assert!(!domains_match("notexample.com", "example.com"));
        assert!(!domains_match("example.com", "com"));
        assert!(!domains_match("", "example.com"));
    }

    #[test]
    fn the_host_is_normalised() {
        assert_eq!(normalise("  HTTPS://WWW.Example.com/ "), "example.com");
        assert_eq!(normalise("example.com:8080"), "example.com");
        assert_eq!(normalise("user@example.com"), "example.com");
    }

    #[test]
    fn a_dotless_title_matches_the_label_below_the_domain() {
        assert!(title_matches("login.example.com", "Example"));
        assert!(!title_matches("cloudflare.attacker.net", "Cloudflare"));
        assert!(!title_matches("login.example.com", "example.com"));
    }
}
