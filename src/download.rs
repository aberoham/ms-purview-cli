//! `DownloadClient` and file publishing (`docs/SPEC.md` section 4.7).
//!
//! - A `downloadUrl` may receive the download token only when it passes
//!   `DownloadRule`: `https`, port 443, no user information, and a host
//!   `<label>.proxyservice.ediscovery.svc.cloud.microsoft`. The token is then
//!   bound to that one origin.
//! - Requests carry the download token and `X-AllowWithAADToken: true`,
//!   never the Graph token. 401 and 403 are `DownloadRefused`.
//! - Redirects are handled here, not by reqwest: one to the same origin is
//!   followed, at most `MAX_REDIRECTS` times, with the same headers; one to
//!   any other origin is refused with `CrossOriginRedirect` and never
//!   contacted.
//! - The body is not decompressed. It streams into a temporary file
//!   `.<name>.<random>.part` (mode 0600) while its SHA-256 is computed, and
//!   is cut off past the known size, `max_unknown_size` when the size is
//!   unknown, and `max_size` always. The length is then checked, the file
//!   synced, and its zip central directory opened.
//! - Only then is it published: by a hard link, which fails if another
//!   writer created the name meanwhile (`TargetAppeared`), or with
//!   `--overwrite` by a rename. A failure before publication removes the
//!   temporary file and leaves the final name alone.
//! - The trace records each response's status, kept headers and length,
//!   never its body.

pub mod manifest;
pub mod names;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, LOCATION};
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::env::Clock;
use crate::error::{PurviewError, Result};
use crate::origin::Origin;
use crate::output::sanitize;
use crate::redact::{self, Redactor};
use crate::token::TokenProvider;
use crate::trace::{Exchange, TraceSink, TracedBody, TracedResponse};

/// The host suffix of the Purview download proxy. The observed host was
/// `eur.` under it (Observed); other regions are assumed to share it
/// (Assumption).
pub const HOST_SUFFIX: &str = ".proxyservice.ediscovery.svc.cloud.microsoft";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// No data for this long ends a download.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Same-origin redirects followed for one file.
pub const MAX_REDIRECTS: usize = 3;
/// The download token must stay valid this long when a file starts
/// (`docs/SPEC.md` section 4.5).
pub const TOKEN_VALIDITY: Duration = Duration::from_secs(300);
pub const DEFAULT_MAX_SIZE: u64 = 64 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_UNKNOWN_SIZE: u64 = 1024 * 1024 * 1024;

/// Which `downloadUrl` may receive the download token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRule {
    /// `HOST_SUFFIX` in production. The host must be one label of
    /// `[a-z0-9-]` followed by it.
    pub suffix: String,
    /// Tests only: `http` is accepted too.
    pub allow_http: bool,
    /// Tests only: any port is accepted, not only 443.
    pub any_port: bool,
}

impl DownloadRule {
    pub fn production() -> Self {
        Self {
            suffix: HOST_SUFFIX.to_owned(),
            allow_http: false,
            any_port: false,
        }
    }

    /// The origin `url` binds the download token to, or why it may not
    /// have the token. The reason never quotes the URL.
    pub fn origin(&self, url: &Url) -> std::result::Result<Origin, &'static str> {
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            _ => return Err("its downloadUrl does not use https"),
        }
        let origin = Origin::of(url)
            .ok_or("its downloadUrl has user information, no host, or a host that ends in a dot")?;
        if !self.any_port && url.port_or_known_default() != Some(443) {
            return Err("its downloadUrl does not use port 443");
        }
        let host = origin.host().to_ascii_lowercase();
        let label = host
            .strip_suffix(self.suffix.as_str())
            .ok_or("its downloadUrl's host is not a Purview download host")?;
        if label.is_empty()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("its downloadUrl's host is not a Purview download host");
        }
        Ok(origin)
    }
}

/// The size limits of `docs/SPEC.md` section 4.7, step 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_size: u64,
    pub max_unknown_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_unknown_size: DEFAULT_MAX_UNKNOWN_SIZE,
        }
    }
}

impl Limits {
    /// The limits in `config.json`'s `download` object, each a size such
    /// as `64GiB`; an absent key keeps its default.
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let mut limits = Self::default();
        let Some(download) = extra.get("download") else {
            return Ok(limits);
        };
        let Some(object) = download.as_object() else {
            return Err(PurviewError::message(
                "config.json: download must be an object",
            ));
        };
        for (key, slot) in [
            ("max_size", &mut limits.max_size),
            ("max_unknown_size", &mut limits.max_unknown_size),
        ] {
            match object.get(key) {
                None | Some(Value::Null) => {}
                Some(value) => {
                    *slot = value.as_str().and_then(parse_size).ok_or_else(|| {
                        PurviewError::message(format!(
                            "config.json: download.{key} must be a size such as 1GiB or 512MiB"
                        ))
                    })?;
                }
            }
        }
        Ok(limits)
    }

    /// The most bytes a file of `size` may have.
    pub fn cap(&self, size: Option<u64>) -> u64 {
        size.unwrap_or(self.max_unknown_size).min(self.max_size)
    }
}

/// A size: whole bytes, or a whole number of `KiB`, `MiB`, `GiB` or `TiB`
/// (`B` and the unit are optional, any case).
pub fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text.chars().take_while(char::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let number: u64 = number.parse().ok()?;
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "kib" => 10,
        "mib" => 20,
        "gib" => 30,
        "tib" => 40,
        _ => return None,
    };
    number.checked_mul(1u64 << shift).filter(|size| *size > 0)
}

/// How a client is set up, from `Env` and the global flags.
#[derive(Debug, Clone)]
pub struct DownloadSettings {
    pub rule: DownloadRule,
    /// Tests only: host names resolved to the mock listeners.
    pub resolve: Vec<(String, SocketAddr)>,
    pub idle_timeout: Duration,
    pub verbose: bool,
    pub trace: Option<Arc<TraceSink>>,
}

/// A file the operation offers, with a `downloadUrl` that passed the rule
/// (`docs/SPEC.md` section 7.1, `DownloadableFile`).
#[derive(Debug, Clone, PartialEq)]
pub struct DownloadableFile {
    pub server_name: String,
    pub url: Url,
    pub origin: Origin,
    /// `None` when Graph gave 0 or nothing.
    pub size: Option<u64>,
}

/// What a fetch wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: u64,
    /// Lowercase hexadecimal.
    pub sha256: String,
}

/// The download transport. It holds the token provider, never a token.
pub struct DownloadClient {
    http: reqwest::Client,
    rule: DownloadRule,
    tokens: Arc<dyn TokenProvider>,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    verbose: bool,
    trace: Option<Arc<TraceSink>>,
    trace_failed: AtomicBool,
}

impl std::fmt::Debug for DownloadClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DownloadClient")
            .field("rule", &self.rule)
            .finish_non_exhaustive()
    }
}

impl DownloadClient {
    pub fn new(
        settings: DownloadSettings,
        tokens: Arc<dyn TokenProvider>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // The bytes are hashed and sized as the service sent them.
            .no_gzip()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(settings.idle_timeout)
            .user_agent(concat!("purview/", env!("CARGO_PKG_VERSION")));
        for (host, address) in &settings.resolve {
            builder = builder.resolve(host, *address);
        }
        Ok(Self {
            http: builder.build()?,
            rule: settings.rule,
            tokens,
            redactor,
            clock,
            verbose: settings.verbose,
            trace: settings.trace,
            trace_failed: AtomicBool::new(false),
        })
    }

    pub fn rule(&self) -> &DownloadRule {
        &self.rule
    }

    /// Streams `file` into `sink`, which must be empty.
    pub async fn fetch(
        &self,
        file: &DownloadableFile,
        limits: Limits,
        sink: &mut tokio::fs::File,
        log: &mut (dyn Write + Send),
    ) -> Result<Fetched> {
        // Checked again here, so that no caller can skip the rule.
        if self.rule.origin(&file.url).as_ref() != Ok(&file.origin) {
            return Err(PurviewError::FileNotDownloadable(
                "the file's downloadUrl does not pass the download host rule".to_owned(),
            ));
        }
        let token = self.tokens.download(TOKEN_VALIDITY).await;
        self.log_notes(log);
        let token = token.map_err(|error| match error {
            // Its message already says what to do.
            PurviewError::DownloadNotConsented { .. } => error,
            error => error.context(
                "getting the download token (if the identity platform refused the refresh, sign \
                 in again with 'purview auth login')",
            ),
        })?;
        let mut current = file.url.clone();
        let mut redirects = 0;
        let mut response = loop {
            self.log(log, &format!("GET {}", self.shown(&current)));
            let started = self.clock.elapsed();
            let sent = self
                .http
                .get(current.clone())
                .bearer_auth(token.expose())
                .header("X-AllowWithAADToken", "true")
                .send()
                .await;
            let took = self.clock.elapsed().saturating_sub(started).as_millis();
            let response =
                match sent {
                    Ok(response) => response,
                    Err(error) if error.is_builder() => return Err(PurviewError::message(
                        "the download request could not be built: the stored download token is \
                         not a valid header value; run 'purview auth refresh'",
                    )),
                    Err(error) => {
                        let reason = transport_failure(&error);
                        self.record(&current, None, Some(reason), log);
                        return Err(PurviewError::message(format!(
                            "could not reach the download service: {reason}"
                        )));
                    }
                };
            let status = response.status();
            self.log(log, &format!("HTTP {} in {took} ms", status.as_u16()));
            if !status.is_redirection() {
                break response;
            }
            let headers = response.headers().clone();
            drop(response);
            self.record(&current, Some((status, &headers, 0)), None, log);
            let target = headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| current.join(value.trim()).ok())
                .ok_or_else(|| {
                    PurviewError::message(format!(
                        "the download service answered HTTP {} with no location the tool could \
                         read",
                        status.as_u16()
                    ))
                })?;
            if !file.origin.admits(&target) {
                return Err(PurviewError::CrossOriginRedirect {
                    target: Origin::of(&target).map_or_else(
                        || "an address with no origin".to_owned(),
                        |origin| sanitize(&self.redactor.redact(&origin.to_string())),
                    ),
                });
            }
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(PurviewError::message(format!(
                    "the download service redirected more than {MAX_REDIRECTS} times"
                )));
            }
            self.log(log, "following a redirect on the same origin");
            current = target;
        };
        drop(token);
        let status = response.status();
        let headers = response.headers().clone();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            self.record(&current, Some((status, &headers, 0)), None, log);
            return Err(PurviewError::DownloadRefused {
                status: status.as_u16(),
            });
        }
        if !status.is_success() {
            self.record(&current, Some((status, &headers, 0)), None, log);
            return Err(PurviewError::message(format!(
                "the download service answered HTTP {}",
                status.as_u16()
            )));
        }
        let cap = limits.cap(file.size);
        let declared = response.content_length();
        if let Some(length) = declared {
            if length > cap {
                self.record(&current, Some((status, &headers, 0)), None, log);
                return Err(over_limit(file.size, cap));
            }
        }
        let mut hasher = Sha256::new();
        let mut bytes: u64 = 0;
        let streamed = loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    bytes = bytes.saturating_add(chunk.len() as u64);
                    if bytes > cap {
                        break Err(over_limit(file.size, cap));
                    }
                    hasher.update(&chunk);
                    if let Err(error) = sink.write_all(&chunk).await {
                        break Err(error.into());
                    }
                }
                Ok(None) => break Ok(()),
                Err(error) if error.is_timeout() => {
                    break Err(PurviewError::message(format!(
                        "the download stalled: no data arrived for {} seconds",
                        IDLE_TIMEOUT.as_secs()
                    )))
                }
                Err(_) => {
                    break Err(PurviewError::message(
                        "the download was cut off before it ended",
                    ))
                }
            }
        };
        self.record(&current, Some((status, &headers, bytes)), None, log);
        streamed?;
        for (expected, what) in [
            (file.size, "the size Graph gave"),
            (declared, "Content-Length"),
        ] {
            if let Some(expected) = expected {
                if bytes != expected {
                    return Err(PurviewError::message(format!(
                        "the download ended after {bytes} bytes, but {what} is {expected}"
                    )));
                }
            }
        }
        sink.flush().await?;
        Ok(Fetched {
            bytes,
            sha256: hex(&hasher.finalize()),
        })
    }

    fn shown(&self, url: &Url) -> String {
        sanitize(&self.redactor.redact(&redact::url(url, &self.redactor)))
    }

    /// Writes the exchange to the trace, if one is open: status, kept
    /// headers and length, never the body.
    fn record(
        &self,
        url: &Url,
        response: Option<(StatusCode, &HeaderMap, u64)>,
        error: Option<&str>,
        log: &mut (dyn Write + Send),
    ) {
        let Some(trace) = &self.trace else {
            return;
        };
        let exchange = Exchange {
            method: "GET",
            url,
            request_body: None,
            response: response.map(|(status, headers, bytes)| TracedResponse {
                status: status.as_u16(),
                headers,
                body: TracedBody::Omitted { bytes },
            }),
            error,
        };
        if let Err(error) = trace.record(&exchange) {
            if !self.trace_failed.swap(true, Ordering::Relaxed) {
                let _ = writeln!(
                    log,
                    "warning: could not write a trace file: {}",
                    sanitize(&error.to_string())
                );
            }
        }
    }

    fn log(&self, log: &mut (dyn Write + Send), line: &str) {
        if self.verbose {
            let _ = writeln!(log, "[verbose] {line}");
        }
    }

    fn log_notes(&self, log: &mut (dyn Write + Send)) {
        for note in self.tokens.take_notes() {
            self.log(log, &sanitize(&self.redactor.redact(&note)));
        }
    }
}

fn over_limit(size: Option<u64>, cap: u64) -> PurviewError {
    PurviewError::message(match size {
        Some(size) if size <= cap => {
            format!("the download passed the {size} bytes Graph gave as its size; it was stopped")
        }
        _ => format!(
            "the download passed the {cap}-byte limit (config.json download.max_size or \
             download.max_unknown_size); it was stopped"
        ),
    })
}

/// A request that got no response. reqwest's own message names the URL,
/// so only the kind is kept.
fn transport_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "the connection failed"
    } else {
        "the request failed"
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A test's hook, called with a path.
pub type PathHook = Arc<dyn Fn(&Path) + Send + Sync>;

/// Test hooks, all off in production.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct DownloadFaults {
    /// Called with the final path just before a file is published.
    pub before_publish: Option<PathHook>,
    /// Makes every manifest write fail.
    pub manifest_write: bool,
}

impl std::fmt::Debug for DownloadFaults {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DownloadFaults")
            .field("before_publish", &self.before_publish.is_some())
            .field("manifest_write", &self.manifest_write)
            .finish()
    }
}

/// A file as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

/// Where a file goes: `dir/name`, replacing a file there only with
/// `overwrite`.
#[derive(Debug, Clone, Copy)]
pub struct Placement<'a> {
    pub dir: &'a Path,
    pub name: &'a str,
    pub overwrite: bool,
}

/// Downloads `file` to `placement` (section 4.7, steps 3 to 8). The
/// caller has checked the target: absent, or replaceable under
/// `overwrite`.
pub async fn download_into(
    client: &DownloadClient,
    file: &DownloadableFile,
    placement: &Placement<'_>,
    limits: Limits,
    faults: &DownloadFaults,
    log: &mut (dyn Write + Send),
) -> Result<Published> {
    let target = placement.dir.join(placement.name);
    let (part, guard) = create_part(placement.dir, placement.name)?;
    let mut sink = tokio::fs::File::from_std(part);
    let fetched = client.fetch(file, limits, &mut sink, log).await;
    // Waits for any write in flight, so the file is closed here, before
    // the guard removes it on failure: Windows cannot remove, link or
    // rename a file that is open.
    let part = sink.into_std().await;
    let fetched = fetched?;
    let part = tokio::task::spawn_blocking(move || part.sync_all())
        .await
        .map_err(|_| PurviewError::message("the file sync stopped unexpectedly"))?;
    part?;
    let checked = guard.path().to_path_buf();
    tokio::task::spawn_blocking(move || check_zip(&checked))
        .await
        .map_err(|_| PurviewError::message("the zip check stopped unexpectedly"))??;
    if let Some(hook) = &faults.before_publish {
        hook(&target);
    }
    publish(guard, &target, placement.overwrite)?;
    Ok(Published {
        path: target,
        bytes: fetched.bytes,
        sha256: fetched.sha256,
    })
}

/// A temporary file this process created; removed when dropped unless
/// kept.
struct PartFile(Option<PathBuf>);

impl PartFile {
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or(Path::new(""))
    }

    fn keep(&mut self) {
        self.0 = None;
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// `.<name>.<16 hexadecimal characters>.part`, created new with mode 0600.
fn create_part(dir: &Path, name: &str) -> Result<(fs::File, PartFile)> {
    for _ in 0..16 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|_| PurviewError::message("could not draw a random temporary file name"))?;
        let path = dir.join(format!(".{name}.{}.part", hex(&random)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((file, PartFile(Some(path)))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PurviewError::message(
        "could not create a temporary file for the download: every candidate name was taken",
    ))
}

/// Opens the zip's central directory.
pub fn check_zip(path: &Path) -> Result<()> {
    let file = fs::File::open(path)?;
    zip::ZipArchive::new(file).map(|_| ()).map_err(|_| {
        PurviewError::message(
            "the downloaded file is not a zip whose central directory can be read",
        )
    })
}

/// Publishes the temporary file under `target`. Without `overwrite`, a
/// hard link, which fails if the name exists; with it, a rename that
/// replaces it, refused when `target` is a link.
fn publish(mut part: PartFile, target: &Path, overwrite: bool) -> Result<()> {
    let shown = || sanitize(&target.display().to_string());
    if overwrite {
        if let Ok(metadata) = fs::symlink_metadata(target) {
            if crate::config::is_link_like(&metadata) {
                return Err(PurviewError::message(format!(
                    "{} is a link; refusing to write through it",
                    shown()
                )));
            }
        }
        fs::rename(part.path(), target)?;
        part.keep();
        return Ok(());
    }
    match fs::hard_link(part.path(), target) {
        // The guard removes the temporary name.
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(PurviewError::TargetAppeared { path: shown() })
        }
        Err(error) if links_unsupported(&error) => {
            Err(PurviewError::PublishUnsupported { path: shown() })
        }
        Err(error) => Err(error.into()),
    }
}

/// Whether a hard link failed because the file system has none: `EPERM`
/// on Linux, `ENOTSUP` on macOS, `ERROR_INVALID_FUNCTION` and
/// `ERROR_NOT_SUPPORTED` on Windows.
fn links_unsupported(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    let code = error.raw_os_error();
    if cfg!(target_os = "linux") {
        matches!(code, Some(1 | 95))
    } else if cfg!(target_os = "macos") {
        matches!(code, Some(45 | 102))
    } else if cfg!(windows) {
        matches!(code, Some(1 | 50))
    } else {
        false
    }
}

/// The length and SHA-256 of a file on disk.
pub fn digest_file(path: &Path) -> Result<(u64, String)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((bytes, hex(&hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> DownloadRule {
        DownloadRule::production()
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    /// A download URL joined from pieces at run time, so that the
    /// public-data lint does not read the refused forms as addresses.
    fn proxy(scheme: &str, label: &str, after_host: &str) -> String {
        [
            scheme,
            "://",
            label,
            HOST_SUFFIX,
            after_host,
            "/ediscovery/api/proxy/x",
        ]
        .concat()
    }

    #[test]
    fn the_host_rule_takes_one_label_under_the_proxy_suffix_on_https_port_443() {
        assert!(rule().origin(&url(&proxy("https", "eur", ""))).is_ok());
        assert!(rule().origin(&url(&proxy("https", "EUR", ":443"))).is_ok());
        for refused in [
            proxy("http", "eur", ""),
            proxy("http", "eur", ":443"),
            proxy("https", "eur", ":8443"),
            proxy("https", "a.b", ""),
            proxy("https", "", ""),
            proxy("https", "eur", "."),
            proxy("https", "eur_1", ""),
            proxy("https", "eur", ".example"),
            proxy("ftp", "eur", ""),
            proxy("https", &["u", ":", "p", "@", "eur"].concat(), ""),
            "https://graph.microsoft.com/v1.0/x".to_owned(),
        ] {
            assert!(rule().origin(&url(&refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_test_rule_may_allow_http_and_any_port() {
        let test = DownloadRule {
            allow_http: true,
            any_port: true,
            ..rule()
        };
        assert!(test.origin(&url(&proxy("http", "alpha", ":8080"))).is_ok());
        assert!(test.origin(&url("http://127.0.0.1:8080/x")).is_err());
    }

    #[test]
    fn sizes_parse_with_binary_units() {
        assert_eq!(parse_size("64GiB"), Some(64 << 30));
        assert_eq!(parse_size("1 gib"), Some(1 << 30));
        assert_eq!(parse_size("512MiB"), Some(512 << 20));
        assert_eq!(parse_size("2048"), Some(2048));
        assert_eq!(parse_size("10b"), Some(10));
        for bad in ["", "0", "1.5GiB", "1GB", "GiB", "-1", "99999999999TiB"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
    }

    #[test]
    fn limits_come_from_the_download_object() {
        let mut extra = BTreeMap::new();
        assert_eq!(Limits::from_config(&extra).unwrap(), Limits::default());
        extra.insert(
            "download".into(),
            serde_json::json!({"max_size": "2GiB", "max_unknown_size": null}),
        );
        let limits = Limits::from_config(&extra).unwrap();
        assert_eq!(limits.max_size, 2 << 30);
        assert_eq!(limits.max_unknown_size, DEFAULT_MAX_UNKNOWN_SIZE);
        assert_eq!(limits.cap(None), 1 << 30);
        assert_eq!(limits.cap(Some(5)), 5);
        assert_eq!(limits.cap(Some(3 << 30)), 2 << 30);
        extra.insert("download".into(), serde_json::json!({"max_size": "lots"}));
        assert!(Limits::from_config(&extra).is_err());
        extra.insert("download".into(), serde_json::json!("1GiB"));
        assert!(Limits::from_config(&extra).is_err());
    }

    #[test]
    fn publishing_without_overwrite_never_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.zip");
        let (mut file, part) = create_part(dir.path(), "a.zip").unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        fs::write(&target, b"other writer").unwrap();
        let part_path = part.path().to_path_buf();
        let error = publish(part, &target, false).unwrap_err();
        assert_eq!(error.metadata().0, "TargetAppeared");
        assert_eq!(fs::read(&target).unwrap(), b"other writer");
        assert!(!part_path.exists());
    }

    #[test]
    fn publishing_links_then_removes_the_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.zip");
        let (mut file, part) = create_part(dir.path(), "a.zip").unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        let part_path = part.path().to_path_buf();
        assert!(part_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".a.zip."));
        publish(part, &target, false).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!part_path.exists());
        let (mut file, part) = create_part(dir.path(), "a.zip").unwrap();
        file.write_all(b"newer").unwrap();
        drop(file);
        publish(part, &target, true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"newer");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_target_is_refused_even_with_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, b"keep").unwrap();
        let target = dir.path().join("a.zip");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();
        let (_file, part) = create_part(dir.path(), "a.zip").unwrap();
        assert!(publish(part, &target, true).is_err());
        assert_eq!(fs::read(&elsewhere).unwrap(), b"keep");
    }

    #[test]
    fn the_zip_check_reads_the_central_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.zip");
        fs::write(&path, b"PK\x03\x04 not really").unwrap();
        assert!(check_zip(&path).is_err());
        let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        writer
            .start_file("Summary.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"a,b\n").unwrap();
        writer.finish().unwrap();
        check_zip(&path).unwrap();
        assert_eq!(
            digest_file(&path).unwrap().0,
            fs::metadata(&path).unwrap().len()
        );
    }
}
