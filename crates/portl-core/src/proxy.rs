//! Outbound HTTP proxy selection shared by every portl network path.
//!
//! One [`ProxyConfig`] per process decides how portl reaches relays,
//! pkarr publishers/resolvers, iroh's net-report probes, the short-code
//! mailbox, and release downloads. Sources, highest precedence first:
//!
//! 1. `--proxy <URL>` / `--no-proxy`
//! 2. `PORTL_PROXY` (a URL, or `direct` / `none`)
//! 3. `portl.toml` `[network] proxy`
//! 4. `HTTPS_PROXY` / `ALL_PROXY` / `HTTP_PROXY` (and lowercase), with `NO_PROXY`
//! 5. direct
//!
//! iroh only tunnels its relay connection when the endpoint builder is
//! given an explicit proxy URL ([`configure_endpoint`]), while iroh's
//! internal reqwest clients (pkarr, net-report) only read the standard
//! proxy env vars. For an explicit choice (1–3), [`init_process`] rewrites
//! those env vars to match it, so no client in the process can disagree.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::str::FromStr;
use std::sync::{OnceLock, RwLock};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use iroh_base::RelayUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::{Host, Url};

use crate::diagnostics::redact_url_userinfo;

/// Appended to every tracing filter: iroh-relay logs the proxy URL and the
/// `Proxy-Authorization` header at debug level when dialing via a proxy.
pub const CREDENTIAL_SAFE_LOG_DIRECTIVE: &str = "iroh_relay::client::tls=info";

/// Portl-specific proxy override; wins over `portl.toml` and the standard vars.
pub const PORTL_PROXY_ENV: &str = "PORTL_PROXY";

const HTTPS_VARS: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];
const HTTP_VARS: [&str; 4] = ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
/// Every variable [`init_process`] may rewrite.
const MANAGED_VARS: [&str; 9] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    PORTL_PROXY_ENV,
];

/// A validated `http://` proxy URL. `Display` and `Debug` hide credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl(Url);

impl ProxyUrl {
    /// Parse a proxy URL. A bare `host:port` means `http://host:port`.
    ///
    /// Only `http://` proxies are accepted: iroh's relay client speaks HTTP
    /// CONNECT only (no SOCKS), and portl's own CONNECT tunnel does not
    /// wrap the proxy hop in TLS.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let with_scheme = if value.contains("://") {
            value.to_owned()
        } else {
            format!("http://{value}")
        };
        let url = Url::parse(&with_scheme).map_err(|err| anyhow!("invalid proxy URL: {err}"))?;
        match url.scheme() {
            "http" => {}
            "https" => bail!(
                "https:// proxies are not supported; use an http:// proxy URL (traffic inside the CONNECT tunnel stays TLS-encrypted)"
            ),
            "socks4" | "socks4a" | "socks5" | "socks5h" => bail!(
                "SOCKS proxies are not supported (iroh's relay client only speaks HTTP CONNECT); use an http:// proxy URL"
            ),
            other => bail!("unsupported proxy scheme `{other}://`; use an http:// proxy URL"),
        }
        if url.host_str().is_none_or(str::is_empty) {
            bail!("proxy URL has no host");
        }
        Ok(Self(url))
    }

    /// The full URL, including credentials. Never log this; use `Display`.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.0
    }

    /// Percent-decoded `user:password` from the URL, if any.
    #[must_use]
    pub fn credentials(&self) -> Option<(String, String)> {
        if self.0.username().is_empty() && self.0.password().is_none() {
            return None;
        }
        let decode = |s: &str| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned()
        };
        Some((
            decode(self.0.username()),
            decode(self.0.password().unwrap_or_default()),
        ))
    }

    /// iroh 1.3's relay client sends the userinfo still percent-encoded and
    /// base64url-encodes it, so some credentials reach the proxy mangled.
    fn relay_auth_caveat(&self) -> Option<String> {
        let raw = format!(
            "{}:{}",
            self.0.username(),
            self.0.password().unwrap_or_default()
        );
        let mangled = raw.contains('%')
            || base64::engine::general_purpose::STANDARD.encode(&raw)
                != base64::engine::general_purpose::URL_SAFE.encode(&raw);
        (self.credentials().is_some() && mangled).then(|| {
            format!(
                "proxy {self}: credentials contain characters that iroh's relay client encodes incorrectly; the proxy may reject relay connections (407). Prefer credentials made of letters and digits"
            )
        })
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_url_userinfo(self.0.as_str()))
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyUrl({self})")
    }
}

/// An explicit choice from `--proxy`/`--no-proxy`, `PORTL_PROXY`, or `portl.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySetting {
    Direct,
    Proxy(ProxyUrl),
}

impl FromStr for ProxySetting {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => bail!("proxy setting is empty; use an http:// URL, `direct`, or `none`"),
            "direct" | "none" => Ok(Self::Direct),
            _ => ProxyUrl::parse(value).map(Self::Proxy),
        }
    }
}

/// Where the effective proxy decision came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxySource {
    Flag,
    PortlProxyEnv,
    ConfigFile,
    /// A standard variable such as `HTTPS_PROXY`.
    Env(&'static str),
    Default,
}

impl ProxySource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::PortlProxyEnv => PORTL_PROXY_ENV,
            Self::ConfigFile => "portl.toml",
            Self::Env(name) => name,
            Self::Default => "default",
        }
    }

    fn is_explicit(self) -> bool {
        matches!(self, Self::Flag | Self::PortlProxyEnv | Self::ConfigFile)
    }
}

#[derive(Clone, Debug)]
enum Route {
    Direct,
    /// Explicit proxy for every destination; `NO_PROXY` does not apply.
    All(ProxyUrl),
    /// Standard env vars, matched per destination scheme and `NO_PROXY`.
    Env {
        https: Option<ProxyUrl>,
        http: Option<ProxyUrl>,
        no_proxy: Option<String>,
    },
}

/// The resolved proxy decision for this process.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    source: ProxySource,
    route: Route,
    warnings: Vec<String>,
}

impl ProxyConfig {
    #[must_use]
    pub fn direct() -> Self {
        Self {
            source: ProxySource::Default,
            route: Route::Direct,
            warnings: Vec::new(),
        }
    }

    /// Apply the precedence rules. `file` is `portl.toml`'s `[network] proxy`;
    /// `env` looks up environment variables (injectable for tests).
    pub fn resolve(
        flag: Option<ProxySetting>,
        file: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let explicit = if let Some(setting) = flag {
            Some((setting, ProxySource::Flag))
        } else if let Some(value) = env(PORTL_PROXY_ENV).filter(|v| !v.trim().is_empty()) {
            Some((
                value.parse().context("invalid PORTL_PROXY")?,
                ProxySource::PortlProxyEnv,
            ))
        } else if let Some(value) = file {
            Some((
                value
                    .parse()
                    .context("invalid portl.toml [network] proxy")?,
                ProxySource::ConfigFile,
            ))
        } else {
            None
        };
        let mut warnings = Vec::new();
        let (source, route) = match explicit {
            Some((ProxySetting::Direct, source)) => (source, Route::Direct),
            Some((ProxySetting::Proxy(url), source)) => (source, Route::All(url)),
            None => {
                let https = first_valid_env(&env, &HTTPS_VARS, &mut warnings);
                let http = first_valid_env(&env, &HTTP_VARS, &mut warnings);
                match https.as_ref().or(http.as_ref()) {
                    None => (ProxySource::Default, Route::Direct),
                    Some((name, _)) => (
                        ProxySource::Env(name),
                        Route::Env {
                            https: https.map(|(_, url)| url),
                            http: http.map(|(_, url)| url),
                            no_proxy: NO_PROXY_VARS
                                .iter()
                                .find_map(|name| env(name))
                                .filter(|v| !v.trim().is_empty()),
                        },
                    ),
                }
            }
        };
        let mut cfg = Self {
            source,
            route,
            warnings,
        };
        let caveats = cfg
            .proxies()
            .filter_map(ProxyUrl::relay_auth_caveat)
            .collect::<Vec<_>>();
        for caveat in caveats {
            if !cfg.warnings.contains(&caveat) {
                cfg.warnings.push(caveat);
            }
        }
        Ok(cfg)
    }

    #[must_use]
    pub fn source(&self) -> ProxySource {
        self.source
    }

    /// Ignored env values and credential caveats, for logging and doctor.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether any proxy is configured (for any destination).
    #[must_use]
    pub fn has_proxy(&self) -> bool {
        self.proxies().next().is_some()
    }

    fn proxies(&self) -> impl Iterator<Item = &ProxyUrl> {
        let (a, b) = match &self.route {
            Route::Direct => (None, None),
            Route::All(url) => (Some(url), None),
            Route::Env { https, http, .. } => (https.as_ref(), http.as_ref()),
        };
        a.into_iter().chain(b)
    }

    /// The proxy for a request to `target`; `None` means connect directly.
    /// `ws`/`wss` targets follow the `http`/`https` rules.
    #[must_use]
    pub fn proxy_for(&self, target: &Url) -> Option<&ProxyUrl> {
        match &self.route {
            Route::Direct => None,
            Route::All(url) => Some(url),
            Route::Env {
                https,
                http,
                no_proxy,
            } => {
                if no_proxy
                    .as_deref()
                    .is_some_and(|list| no_proxy_matches(list, target))
                {
                    return None;
                }
                match target.scheme() {
                    "https" | "wss" => https.as_ref(),
                    "http" | "ws" => http.as_ref(),
                    _ => None,
                }
            }
        }
    }

    /// The proxy for relay connections. iroh takes one proxy for all relays,
    /// so the first (preferred) relay decides.
    #[must_use]
    pub fn relay_proxy(&self, relays: &[RelayUrl]) -> Option<&ProxyUrl> {
        relays.first().and_then(|relay| self.proxy_for(relay))
    }

    /// One-line human summary with credentials redacted.
    #[must_use]
    pub fn describe(&self) -> String {
        let source = self.source.as_str();
        match &self.route {
            Route::Direct if self.source == ProxySource::Default => {
                "direct (no proxy configured)".to_owned()
            }
            Route::Direct => format!("direct (forced by {source})"),
            Route::All(url) => format!("{url} (from {source})"),
            Route::Env {
                https,
                http,
                no_proxy,
            } => {
                let url = https.as_ref().or(http.as_ref()).map(ToString::to_string);
                let no_proxy = if no_proxy.is_some() {
                    ", NO_PROXY applies"
                } else {
                    ""
                };
                format!(
                    "{} (from {source}{no_proxy})",
                    url.unwrap_or_else(|| "direct".to_owned())
                )
            }
        }
    }
}

fn first_valid_env(
    env: &impl Fn(&str) -> Option<String>,
    names: &[&'static str],
    warnings: &mut Vec<String>,
) -> Option<(&'static str, ProxyUrl)> {
    for name in names {
        let Some(value) = env(name).filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        match ProxyUrl::parse(&value) {
            Ok(url) => return Some((name, url)),
            Err(err) => {
                let warning = format!("ignoring {name}: {err}");
                if !warnings.contains(&warning) {
                    warnings.push(warning);
                }
            }
        }
    }
    None
}

/// `NO_PROXY` semantics (`*`, hostnames, domain suffixes, IPs, CIDRs).
///
/// Delegates to hyper-util's matcher, the one reqwest uses for iroh's pkarr
/// and net-report clients, so the relay path and those clients agree.
fn no_proxy_matches(list: &str, target: &Url) -> bool {
    let Some(host) = target.host_str() else {
        return false;
    };
    let Ok(uri) = format!("http://{host}/").parse::<http::Uri>() else {
        return false;
    };
    hyper_util::client::proxy::matcher::Matcher::builder()
        .all("http://proxy.invalid")
        .no(list)
        .build()
        .intercept(&uri)
        .is_none()
}

static PROCESS: RwLock<Option<ProxyConfig>> = RwLock::new(None);
static ORIGINAL_ENV: OnceLock<Vec<(&'static str, Option<OsString>)>> = OnceLock::new();

/// The process-wide decision set by [`init_process`]. Library callers that
/// never initialized (FFI, tests) get one resolved from the environment.
#[must_use]
pub fn current() -> ProxyConfig {
    if let Some(cfg) = PROCESS.read().ok().and_then(|guard| guard.clone()) {
        return cfg;
    }
    let cfg = ProxyConfig::resolve(None, None, env_var).unwrap_or_else(|err| {
        tracing::warn!(error = %redact_url_userinfo(&format!("{err:#}")), "invalid proxy configuration; connecting directly");
        ProxyConfig::direct()
    });
    if let Ok(mut guard) = PROCESS.write() {
        guard.get_or_insert(cfg).clone()
    } else {
        cfg
    }
}

/// Resolve the process-wide proxy decision and, for an explicit setting,
/// rewrite the standard proxy env vars (and `PORTL_PROXY`) to match it so
/// iroh's internal HTTP clients and child portl processes follow it.
///
/// Call from `main` before any thread is spawned: it mutates the process
/// environment.
pub fn init_process(flag: Option<ProxySetting>, file: Option<&str>) -> Result<ProxyConfig> {
    let cfg = ProxyConfig::resolve(flag, file, env_var)?;
    if cfg.source.is_explicit() {
        rewrite_env(&cfg.route);
    }
    if let Ok(mut guard) = PROCESS.write() {
        *guard = Some(cfg.clone());
    }
    Ok(cfg)
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[allow(unsafe_code)]
fn rewrite_env(route: &Route) {
    ORIGINAL_ENV.get_or_init(|| {
        MANAGED_VARS
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect()
    });
    let proxy = match route {
        Route::All(url) => Some(url.url().as_str()),
        Route::Direct | Route::Env { .. } => None,
    };
    for name in HTTPS_VARS.iter().chain(&HTTP_VARS).chain(&NO_PROXY_VARS) {
        // SAFETY: `init_process` is documented to run before any other
        // thread exists, so nothing can read the environment concurrently.
        unsafe {
            match proxy {
                Some(value) if !NO_PROXY_VARS.contains(name) => std::env::set_var(name, value),
                _ => std::env::remove_var(name),
            }
        }
    }
    // SAFETY: as above.
    unsafe { std::env::set_var(PORTL_PROXY_ENV, proxy.unwrap_or("direct")) };
}

/// [`std::env::vars`] as the process saw it before [`init_process`], for
/// children that run user workloads: portl's own proxy choice must not
/// leak into user shells.
#[must_use]
pub fn child_env_vars() -> Vec<(String, String)> {
    let Some(original) = ORIGINAL_ENV.get() else {
        return std::env::vars().collect();
    };
    let managed: HashSet<&str> = MANAGED_VARS.into_iter().collect();
    std::env::vars()
        .filter(|(name, _)| !managed.contains(name.as_str()))
        .chain(original.iter().filter_map(|(name, value)| {
            Some(((*name).to_owned(), value.as_ref()?.to_str()?.to_owned()))
        }))
        .collect()
}

/// Route an iroh endpoint's relay connections (and with them iroh's
/// HTTPS net-report probes) through the process proxy, if one applies.
#[must_use]
pub fn configure_endpoint(
    builder: iroh::endpoint::Builder,
    relays: &[RelayUrl],
) -> iroh::endpoint::Builder {
    match current().relay_proxy(relays) {
        Some(proxy) => builder.proxy_url(proxy.url().clone()),
        None => builder,
    }
}

/// Open a TCP stream to `host:port` through `proxy` with HTTP CONNECT.
/// `host` is as in a URL (IPv6 in brackets).
pub async fn connect_tunnel(proxy: &ProxyUrl, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let proxy_host = match proxy.url().host() {
        Some(Host::Ipv6(addr)) => addr.to_string(),
        Some(host) => host.to_string(),
        None => return Err(std::io::Error::other("proxy URL has no host")),
    };
    let proxy_port = proxy.url().port_or_known_default().unwrap_or(80);
    let mut stream = TcpStream::connect((proxy_host.as_str(), proxy_port)).await?;
    let authority = format!("{host}:{port}");
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, password)) = proxy.credentials() {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        request = format!("{request}Proxy-Authorization: Basic {token}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read the response head byte by byte so no tunnelled bytes are consumed.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 8192 {
            return Err(std::io::Error::other(
                "proxy CONNECT response header too large",
            ));
        }
        let mut byte = [0_u8];
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("proxy {proxy} closed the connection during CONNECT"),
            ));
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let status_line = head.lines().next().unwrap_or_default();
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2'));
    if !ok {
        return Err(std::io::Error::other(format!(
            "proxy {proxy} refused CONNECT {authority}: {status_line}"
        )));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn proxy_host(cfg: &ProxyConfig, target: &str) -> Option<String> {
        cfg.proxy_for(&url(target))
            .map(|p| p.url().host_str().unwrap().to_owned())
    }

    const RELAY: &str = "https://relay.example.com/";

    #[test]
    fn precedence_flag_then_portl_proxy_then_file_then_env() {
        let all = env(&[
            ("PORTL_PROXY", "http://portl-env:1"),
            ("HTTPS_PROXY", "http://std-env:2"),
        ]);
        let flag = Some("http://flag:3".parse().unwrap());
        let cfg = ProxyConfig::resolve(flag, Some("http://file:4"), &all).unwrap();
        assert_eq!(cfg.source(), ProxySource::Flag);
        assert_eq!(proxy_host(&cfg, RELAY).as_deref(), Some("flag"));

        let cfg = ProxyConfig::resolve(None, Some("http://file:4"), &all).unwrap();
        assert_eq!(cfg.source(), ProxySource::PortlProxyEnv);
        assert_eq!(proxy_host(&cfg, RELAY).as_deref(), Some("portl-env"));

        let std_only = env(&[("HTTPS_PROXY", "http://std-env:2")]);
        let cfg = ProxyConfig::resolve(None, Some("http://file:4"), &std_only).unwrap();
        assert_eq!(cfg.source(), ProxySource::ConfigFile);
        assert_eq!(proxy_host(&cfg, RELAY).as_deref(), Some("file"));

        let cfg = ProxyConfig::resolve(None, None, &std_only).unwrap();
        assert_eq!(cfg.source(), ProxySource::Env("HTTPS_PROXY"));
        assert_eq!(proxy_host(&cfg, RELAY).as_deref(), Some("std-env"));

        let cfg = ProxyConfig::resolve(None, None, env(&[])).unwrap();
        assert_eq!(cfg.source(), ProxySource::Default);
        assert_eq!(proxy_host(&cfg, RELAY), None);
    }

    #[test]
    fn explicit_direct_beats_standard_env_at_every_level() {
        let std_env = env(&[
            ("HTTPS_PROXY", "http://std:1"),
            ("ALL_PROXY", "http://std:1"),
            ("HTTP_PROXY", "http://std:1"),
        ]);
        let cfg = ProxyConfig::resolve(Some(ProxySetting::Direct), None, &std_env).unwrap();
        assert_eq!(proxy_host(&cfg, RELAY), None);
        assert_eq!(cfg.describe(), "direct (forced by flag)");

        let with_portl = env(&[("PORTL_PROXY", "none"), ("HTTPS_PROXY", "http://std:1")]);
        let cfg = ProxyConfig::resolve(None, Some("http://file:4"), &with_portl).unwrap();
        assert_eq!(proxy_host(&cfg, RELAY), None);
        assert_eq!(cfg.source(), ProxySource::PortlProxyEnv);

        let cfg = ProxyConfig::resolve(None, Some("Direct"), &std_env).unwrap();
        assert_eq!(proxy_host(&cfg, RELAY), None);
        assert_eq!(cfg.source(), ProxySource::ConfigFile);
    }

    #[test]
    fn standard_env_picks_proxy_by_destination_scheme() {
        let cfg = ProxyConfig::resolve(
            None,
            None,
            env(&[
                ("https_proxy", "http://secure:1"),
                ("HTTP_PROXY", "http://plain:2"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.source(), ProxySource::Env("https_proxy"));
        assert_eq!(proxy_host(&cfg, "https://a/").as_deref(), Some("secure"));
        assert_eq!(proxy_host(&cfg, "wss://a/").as_deref(), Some("secure"));
        assert_eq!(proxy_host(&cfg, "http://a/").as_deref(), Some("plain"));

        // ALL_PROXY backs up whichever scheme has no specific variable.
        let cfg = ProxyConfig::resolve(
            None,
            None,
            env(&[
                ("ALL_PROXY", "http://all:1"),
                ("HTTP_PROXY", "http://plain:2"),
            ]),
        )
        .unwrap();
        assert_eq!(proxy_host(&cfg, "https://a/").as_deref(), Some("all"));
        assert_eq!(proxy_host(&cfg, "http://a/").as_deref(), Some("plain"));

        // An explicit proxy applies to every scheme.
        let cfg =
            ProxyConfig::resolve(Some("fixed:3128".parse().unwrap()), None, env(&[])).unwrap();
        assert_eq!(proxy_host(&cfg, "http://a/").as_deref(), Some("fixed"));
        assert_eq!(
            cfg.proxy_for(&url("http://a/")).unwrap().url().port(),
            Some(3128)
        );
    }

    #[test]
    fn no_proxy_matches_hosts_suffixes_ips_cidrs_and_wildcard() {
        let resolve = |no_proxy: &str| {
            ProxyConfig::resolve(
                None,
                None,
                env(&[("HTTPS_PROXY", "http://p:1"), ("NO_PROXY", no_proxy)]),
            )
            .unwrap()
        };
        let cfg = resolve("internal.corp, .example.org,10.0.0.0/8,192.168.1.7");
        for bypassed in [
            "https://internal.corp/",
            "https://relay.internal.corp/",
            "https://example.org/",
            "https://a.example.org/",
            "https://10.20.30.40/",
            "https://192.168.1.7:8443/",
        ] {
            assert_eq!(proxy_host(&cfg, bypassed), None, "{bypassed} should bypass");
        }
        for proxied in [
            "https://notinternal.corp/",
            "https://example.com/",
            "https://11.0.0.1/",
            "https://192.168.1.8/",
        ] {
            assert!(
                proxy_host(&cfg, proxied).is_some(),
                "{proxied} should be proxied"
            );
        }
        assert_eq!(proxy_host(&resolve("*"), "https://anything/"), None);

        // NO_PROXY is part of the standard-env tier only.
        let explicit = ProxyConfig::resolve(
            None,
            None,
            env(&[("PORTL_PROXY", "http://p:1"), ("NO_PROXY", "*")]),
        )
        .unwrap();
        assert!(proxy_host(&explicit, "https://anything/").is_some());
    }

    #[test]
    fn relay_proxy_follows_first_relay() {
        let cfg = ProxyConfig::resolve(
            None,
            None,
            env(&[("HTTPS_PROXY", "http://p:1"), ("no_proxy", "near.example")]),
        )
        .unwrap();
        let near: RelayUrl = "https://near.example/".parse().unwrap();
        let far: RelayUrl = "https://far.example/".parse().unwrap();
        assert!(cfg.relay_proxy(&[near.clone(), far.clone()]).is_none());
        assert!(cfg.relay_proxy(&[far, near]).is_some());
        assert!(cfg.relay_proxy(&[]).is_none());
    }

    #[test]
    fn rejects_unsupported_schemes_and_garbage_with_clear_errors() {
        for (value, needle) in [
            ("socks5://p:1080", "SOCKS proxies are not supported"),
            ("socks5h://p:1080", "SOCKS proxies are not supported"),
            ("https://p:443", "https:// proxies are not supported"),
            ("ftp://p:21", "unsupported proxy scheme"),
            ("http://", "invalid proxy URL"),
            ("   ", "empty"),
        ] {
            let err = value.parse::<ProxySetting>().unwrap_err();
            assert!(format!("{err:#}").contains(needle), "{value}: {err:#}");
        }
        let err = ProxyConfig::resolve(
            None,
            None,
            env(&[("PORTL_PROXY", "socks5://u:hunter2@p:1")]),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid PORTL_PROXY") && !msg.contains("hunter2"),
            "{msg}"
        );
        let err = ProxyConfig::resolve(None, Some("socks5://p:1"), env(&[])).unwrap_err();
        assert!(format!("{err:#}").contains("portl.toml [network] proxy"));
    }

    #[test]
    fn invalid_standard_env_values_are_skipped_with_a_warning() {
        let cfg = ProxyConfig::resolve(
            None,
            None,
            env(&[
                ("HTTPS_PROXY", "socks5://p:1"),
                ("ALL_PROXY", "http://fallback:2"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.source(), ProxySource::Env("ALL_PROXY"));
        assert_eq!(proxy_host(&cfg, RELAY).as_deref(), Some("fallback"));
        assert!(cfg.warnings()[0].starts_with("ignoring HTTPS_PROXY: SOCKS"));
    }

    #[test]
    fn credentials_are_decoded_for_use_and_redacted_for_display() {
        let proxy = ProxyUrl::parse("http://us%40er:p%3Ass@proxy:3128").unwrap();
        assert_eq!(
            proxy.credentials(),
            Some(("us@er".to_owned(), "p:ss".to_owned()))
        );
        assert_eq!(proxy.to_string(), "http://***@proxy:3128/");
        assert_eq!(format!("{proxy:?}"), "ProxyUrl(http://***@proxy:3128/)");

        let cfg = ProxyConfig::resolve(
            None,
            None,
            env(&[("PORTL_PROXY", "http://user:hunter2@proxy:3128")]),
        )
        .unwrap();
        let shown = format!("{} {cfg:?}", cfg.describe());
        assert!(
            !shown.contains("hunter2") && !shown.contains("user"),
            "{shown}"
        );
        assert_eq!(cfg.describe(), "http://***@proxy:3128/ (from PORTL_PROXY)");
        assert!(
            cfg.warnings().is_empty(),
            "plain credentials need no caveat"
        );
        // The real URL still carries credentials for the proxy handshake.
        assert_eq!(
            cfg.proxy_for(&url(RELAY)).unwrap().url().password(),
            Some("hunter2")
        );

        let mangled = ProxyConfig::resolve(
            Some("http://u:p%40ss@proxy:1".parse().unwrap()),
            None,
            env(&[]),
        )
        .unwrap();
        assert!(mangled.warnings()[0].contains("encodes incorrectly"));
    }

    async fn fake_proxy(reply: &'static str) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0_u8];
            while !head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            socket.write_all(reply.as_bytes()).await.unwrap();
            // Tunnelled bytes follow; echo one line back.
            let mut buf = [0_u8; 5];
            if socket.read_exact(&mut buf).await.is_ok() {
                socket.write_all(&buf).await.unwrap();
            }
            String::from_utf8(head).unwrap()
        });
        (port, task)
    }

    #[tokio::test]
    async fn connect_tunnel_sends_connect_with_basic_auth_and_passes_bytes_through() {
        let (port, proxy_task) =
            fake_proxy("HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n").await;
        let proxy = ProxyUrl::parse(&format!("http://alice:s3cr%3Ft@127.0.0.1:{port}")).unwrap();

        let mut stream = connect_tunnel(&proxy, "mailbox.example", 4000)
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        let head = proxy_task.await.unwrap();
        assert!(
            head.starts_with("CONNECT mailbox.example:4000 HTTP/1.1\r\n"),
            "{head}"
        );
        // base64("alice:s3cr?t"), standard alphabet.
        assert!(
            head.contains("Proxy-Authorization: Basic YWxpY2U6czNjcj90\r\n"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn connect_tunnel_reports_refusal_without_credentials() {
        let (port, _task) = fake_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let proxy = ProxyUrl::parse(&format!("http://alice:hunter2@127.0.0.1:{port}")).unwrap();
        let err = connect_tunnel(&proxy, "mailbox.example", 443)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("407") && !msg.contains("hunter2"), "{msg}");
    }
}
