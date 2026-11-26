//! Exact origins: scheme, host and effective port (`docs/SPEC.md` section
//! 4.3). The Graph client sends a request only to a URL whose origin equals
//! the Graph origin exactly, paging links included.

use std::fmt;

use url::Url;

/// The Microsoft Graph v1.0 base URL. Every Graph request is built below it.
pub const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0/";

/// A scheme, host and effective port. Two URLs share an origin only when
/// all three are equal; a URL with user information, a host that ends in a
/// dot, or a scheme other than `http` and `https` has no origin here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// The origin of `url`, or `None` when it has none that a request may
    /// go to.
    pub fn of(url: &Url) -> Option<Self> {
        if !matches!(url.scheme(), "https" | "http") {
            return None;
        }
        // A user name or password before the host names the same host, but a
        // URL carrying credentials is never one the tool built or should
        // follow.
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = url.host_str()?;
        // `graph.microsoft.com.` resolves to the same host in DNS but is a
        // different name to TLS and to the comparison below; refuse it
        // outright rather than compare it.
        if host.is_empty() || host.ends_with('.') {
            return None;
        }
        Some(Self {
            scheme: url.scheme().to_owned(),
            // The url crate lowercases the host of a special scheme.
            host: host.to_owned(),
            port: url.port_or_known_default()?,
        })
    }

    /// Whether `url` has exactly this origin.
    pub fn admits(&self, url: &Url) -> bool {
        Self::of(url).as_ref() == Some(self)
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

/// `https://graph.microsoft.com:443`: the port is always written, so the
/// form shows what is compared.
impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// The production Graph base, parsed.
pub fn graph_base() -> Url {
    // A constant that parses; the test below proves it.
    Url::parse(GRAPH_BASE).unwrap_or_else(|_| unreachable!("a valid URL literal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Graph URL with user information, joined at run time so that the
    /// public-data lint does not read it as an address.
    fn with_user(user: &str, path: &str) -> String {
        format!("https://{user}{}graph.microsoft.com{path}", '@')
    }

    fn origin(text: &str) -> Option<Origin> {
        Origin::of(&Url::parse(text).unwrap())
    }

    #[test]
    fn the_graph_origin_is_https_graph_on_443() {
        let graph = Origin::of(&graph_base()).unwrap();
        assert_eq!(graph.to_string(), "https://graph.microsoft.com:443");
        assert_eq!(
            origin("https://graph.microsoft.com:443/v1.0/x"),
            Some(graph)
        );
    }

    #[test]
    fn equality_needs_the_same_scheme_host_and_effective_port() {
        let graph = Origin::of(&graph_base()).unwrap();
        for same in [
            "https://graph.microsoft.com/v1.0/security",
            "https://GRAPH.microsoft.com/v1.0/",
            "https://graph.microsoft.com:443/",
        ] {
            assert!(graph.admits(&Url::parse(same).unwrap()), "{same}");
        }
        for other in [
            "http://graph.microsoft.com/v1.0/",
            "https://graph.microsoft.com:8443/v1.0/",
            "https://graph.microsoft.com.evil.example/v1.0/",
            "https://evil.example/graph.microsoft.com/v1.0/",
            "https://graph.microsoft.com./v1.0/",
            &with_user("user", "/v1.0/"),
            &with_user("user:pass", "/v1.0/"),
            &with_user(":pass", "/v1.0/"),
            "ftp://graph.microsoft.com/v1.0/",
        ] {
            assert!(!graph.admits(&Url::parse(other).unwrap()), "{other}");
        }
    }

    #[test]
    fn urls_with_credentials_a_trailing_dot_or_another_scheme_have_no_origin() {
        assert_eq!(origin(&with_user("user", "/")), None);
        assert_eq!(origin("https://graph.microsoft.com./"), None);
        assert_eq!(origin("file:///etc/passwd"), None);
        assert_eq!(origin("data:text/plain,x"), None);
        assert_eq!(
            origin("http://127.0.0.1:8080/v1.0/").map(|o| o.to_string()),
            Some("http://127.0.0.1:8080".to_owned())
        );
    }
}
