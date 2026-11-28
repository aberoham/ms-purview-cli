//! `purview download <case> <op>` (`docs/SPEC.md` sections 3.5 and 4.7).
//!
//! The operation is read again for current `downloadUrl` values. Every
//! file is then planned before any download request: its local name, and
//! whether its target is absent, already a verified download, a file with
//! no manifest entry that verifies (recorded as recovered), or a file that
//! needs `--overwrite`. A refusal stops the command before any request.
//! The files are then fetched one at a time, each recorded in
//! `manifest.json` as soon as it is published.
//!
//! A file with no name, no `downloadUrl` or one the host rule refuses is
//! left out with a `FileNotDownloadable` reason, and the others are still
//! downloaded; such a reason, or an operation that finished without
//! succeeding, makes the command exit 4 with every path it wrote.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use url::Url;

use super::{case_id, shown, Produced, Session};
use crate::download::manifest::{Entry, Manifest};
use crate::download::{
    self, check_zip, digest_file, names, DirLock, DownloadClient, DownloadFaults, DownloadableFile,
    Limits,
};
use crate::error::{PurviewError, Result};
use crate::model::valid::CaseKey;
use crate::model::wire::{FileRecord, Source};
use crate::output::{sanitize, write_rows, OutputFormat};
use crate::routes::{CaseId, OperationId, Query, ReadRoute};

/// The table `download` prints.
pub const COLUMNS: &[&str] = &["STATUS", "SIZE", "PATH"];

/// The checked arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub case: CaseKey,
    pub operation: OperationId,
    pub out: Option<PathBuf>,
    /// A server file name, matched exactly.
    pub file: Option<String>,
    pub overwrite: bool,
    /// Which named files may be fetched at all.
    pub keep: Keep,
}

/// Which of an operation's named files a fetch may download. A file with
/// no name is reported as not downloadable whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// Every file: `download`, and `export create`, whose parts are what
    /// it collects.
    Every,
    /// Every file but an export's items parts (`Items.….zip`): an
    /// estimate's or item report's evidence.
    NoItems,
    /// Only the `Reports-…` files: an export's evidence.
    Reports,
}

impl Keep {
    /// Whether a file named `name` may be fetched.
    pub fn allows(self, name: &str) -> bool {
        match self {
            Self::Every => true,
            Self::NoItems => !super::action::is_items_part(name),
            Self::Reports => !super::action::is_items_part(name) && name.starts_with("Reports-"),
        }
    }
}

/// What the command downloads with, beyond the session.
pub struct Context {
    pub client: DownloadClient,
    pub limits: Limits,
    /// The root below which `cases/<case>/<op>/` is made when `--out` is
    /// not given; `None` for the platform's local data directory, which is
    /// looked up only then.
    pub data_root: Option<PathBuf>,
    pub faults: DownloadFaults,
}

/// What happened to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Downloaded,
    AlreadyDownloaded,
    Recovered,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Downloaded => "downloaded",
            Self::AlreadyDownloaded => "alreadyDownloaded",
            Self::Recovered => "recovered",
        }
    }
}

/// One file written or found already downloaded.
pub struct Done {
    pub server_name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    status: Status,
}

impl Done {
    /// `downloaded`, `alreadyDownloaded` or `recovered`.
    pub fn status(&self) -> &'static str {
        self.status.as_str()
    }
}

/// One file's plan.
enum Plan {
    Fetch {
        file: DownloadableFile,
        name: String,
        replace: bool,
    },
    Done(Done),
}

pub async fn run(
    session: &mut Session<'_>,
    request: &Request,
    context: &Context,
) -> Result<Produced> {
    let case = case_id(&session.graph, &request.case, &mut session.env.stderr).await?;
    let route = ReadRoute::Operation(case, request.operation.clone());
    let body = session
        .graph
        .get(&route, &Query::new(), &mut session.env.stderr)
        .await?;
    let record = crate::poll::checked(body, &route)?;
    if !record.status.is_terminal() {
        return Err(PurviewError::message(format!(
            "operation {} is {}, so its files are not ready; wait for it with 'purview operation \
             get {case} {} --wait'",
            request.operation,
            sanitize(&shown(session, record.status.as_str())),
            request.operation
        )));
    }
    super::operation::warn_invalid_counts(
        &session.env.redactor.clone(),
        &mut session.env.stderr,
        std::iter::once(&record),
    );
    let fetched = fetch(session, case, &record, request, context).await?;
    finish(session, fetched.done, fetched.reasons, fetched.interrupted)
}

/// What `fetch` wrote, and why the download is incomplete, if it is.
pub struct Fetched {
    pub done: Vec<Done>,
    /// Exit-4 reasons: the operation did not succeed, or a file cannot be
    /// downloaded.
    pub reasons: Vec<Value>,
    /// Ctrl-C stopped it; the files already published are kept.
    pub interrupted: bool,
}

/// Downloads the files of `record`, a finished operation of `case` read
/// just before, as `request` asks, printing nothing but notices.
pub async fn fetch(
    session: &mut Session<'_>,
    case: CaseId,
    record: &crate::model::wire::OperationRecord,
    request: &Request,
    context: &Context,
) -> Result<Fetched> {
    let files: Vec<FileRecord> = record
        .detail()
        .map(|detail| detail.files().to_vec())
        .unwrap_or_default();
    if let Some(wanted) = &request.file {
        if !files
            .iter()
            .any(|file| file.file_name.as_deref() == Some(wanted.as_str()))
        {
            // The name is not repeated: it is tenant text.
            return Err(PurviewError::message(
                "the operation has no file with the name given to --file; 'purview operation \
                 get' lists its files",
            ));
        }
    }
    let mut reasons: Vec<Value> = Vec::new();
    if let Some(reason) = super::operation::incomplete_reason(record) {
        let message = shown(session, reason["message"].as_str().unwrap_or_default());
        reasons.push(json!({"code": reason["code"], "message": message}));
    }
    let candidates = downloadable(
        context.client.rule(),
        &session.env.redactor,
        &files,
        request.file.as_deref(),
        request.keep,
        &mut reasons,
    );
    if candidates.is_empty() {
        if files.is_empty() {
            let _ = writeln!(
                session.env.stderr,
                "notice: operation {} lists no files",
                request.operation
            );
        }
        return Ok(Fetched {
            done: Vec::new(),
            reasons,
            interrupted: false,
        });
    }
    // A known size over the limit is refused before anything is written.
    for (index, (file, _)) in candidates.iter().enumerate() {
        if let Some(size) = file.size.filter(|size| *size > context.limits.max_size) {
            return Err(PurviewError::message(format!(
                "a file of the operation is {size} bytes, over the {}-byte limit \
                 (config.json download.max_size); nothing was downloaded (file {} of those \
                 to download)",
                context.limits.max_size,
                index + 1
            )));
        }
    }
    // Every path the command prints is a full one (`docs/SPEC.md` section
    // 5.4), whatever --out or defaults.data_dir gave.
    let dir = match &request.out {
        Some(out) => {
            let dir = std::path::absolute(crate::config::normalise(out))?;
            prepare_dir(&dir)?;
            dir
        }
        None => {
            let root = match &context.data_root {
                Some(root) => root.clone(),
                None => crate::config::data_dir()?,
            };
            // Normalised first, as --out is, so a trailing separator
            // cannot make the link check follow a linked root.
            let root = std::path::absolute(crate::config::normalise(&root))?;
            prepare_dir(&root)?;
            let mut dir = root;
            for part in [
                "cases".to_owned(),
                case.to_string(),
                request.operation.to_string(),
            ] {
                dir.push(part);
                prepare_dir(&dir)?;
            }
            dir
        }
    };
    let _lock = DirLock::acquire(&dir, session.env.clock.as_ref()).await?;
    let mut manifest = Manifest::load(&dir)?;
    let action = record.action(Source::Single).label().to_owned();
    let ids = Ids {
        case,
        operation: request.operation.clone(),
        action,
    };
    let now = session.env.clock.now();
    let mut plans = Vec::new();
    let mut recovered = false;
    for (file, name) in candidates {
        let plan = plan(&dir, &manifest, &ids, file, name, request.overwrite)?;
        if let Plan::Done(done) = &plan {
            if done.status == Status::Recovered {
                manifest.record(entry(&ids, done, &now, true));
                recovered = true;
            }
        }
        plans.push(plan);
    }
    if recovered {
        save_manifest(&manifest, &dir, session, context, Saving::Recovered)?;
    }
    // One listener for the whole run; Ctrl-C abandons the file in flight,
    // whose temporary file is removed, and keeps the files already
    // published.
    let interrupt = session.env.interrupt.clone();
    let mut interrupted: download::Interrupted<'_> = interrupt.wait();
    let mut done = Vec::new();
    let fetches = plans
        .iter()
        .filter(|plan| matches!(plan, Plan::Fetch { .. }))
        .count();
    let mut fetch = 0;
    for plan in plans {
        let (file, name, replace) = match plan {
            Plan::Done(finished) => {
                done.push(finished);
                continue;
            }
            Plan::Fetch {
                file,
                name,
                replace,
            } => (file, name, replace),
        };
        let placement = download::Placement {
            dir: &dir,
            name: &name,
            overwrite: replace,
        };
        fetch += 1;
        // Files are named by position: a server name is tenant text.
        let what = format!("downloading file {fetch} of {fetches}");
        let context_for = |error: PurviewError| error.context(what.clone());
        let staged = download::stage(
            &context.client,
            &file,
            &placement,
            context.limits,
            &mut interrupted,
            &context.faults,
            &mut session.env.stderr,
        )
        .await
        .map_err(context_for)?;
        let Some(staged) = staged else {
            return Ok(Fetched {
                done,
                reasons,
                interrupted: true,
            });
        };
        let finished = Done {
            server_name: file.server_name.clone(),
            path: staged.target().to_path_buf(),
            bytes: staged.bytes,
            sha256: staged.sha256.clone(),
            status: Status::Downloaded,
        };
        let recorded = entry(&ids, &finished, &session.env.clock.now(), false);
        if replace {
            // Written ahead: the manifest names the replacement, and no
            // longer the file it replaces (under this name or another for
            // the same file), before the rename. If the manifest cannot be
            // written, nothing is replaced; if the rename fails, the entry's
            // hash does not match the old file, so no later run takes it
            // for this one.
            let replaced = owners(&dir, &manifest, &name);
            manifest
                .files
                .retain(|entry| !replaced.contains(&entry.file_name));
            manifest.record(recorded);
            save_manifest(&manifest, &dir, session, context, Saving::BeforeReplacing)?;
            staged
                .publish(true, &context.faults, &mut session.env.stderr)
                .map_err(context_for)?;
        } else {
            staged
                .publish(false, &context.faults, &mut session.env.stderr)
                .map_err(context_for)?;
            // A stale entry under another name for the same file, such as
            // one whose file was deleted by hand, goes too: at most one
            // entry reaches a file.
            let stale = owners(&dir, &manifest, &name);
            manifest
                .files
                .retain(|entry| !stale.contains(&entry.file_name));
            manifest.record(recorded);
            save_manifest(
                &manifest,
                &dir,
                session,
                context,
                Saving::AfterPublishing(&finished.path),
            )?;
        }
        done.push(finished);
    }
    Ok(Fetched {
        done,
        reasons,
        interrupted: false,
    })
}

struct Ids {
    case: CaseId,
    operation: OperationId,
    action: String,
}

/// The files that can be downloaded, with their local names; a reason for
/// each that cannot. Names are made across every file of the operation,
/// so `--file` gives a file the same local name a full download does.
fn downloadable(
    rule: &download::DownloadRule,
    redactor: &crate::redact::Redactor,
    files: &[FileRecord],
    wanted: Option<&str>,
    keep: Keep,
    reasons: &mut Vec<Value>,
) -> Vec<(DownloadableFile, String)> {
    let named: Vec<&str> = files
        .iter()
        .filter_map(|file| file.file_name.as_deref())
        .filter(|name| !name.is_empty())
        .collect();
    let local = names::local_names(&named);
    let mut local = named.iter().zip(local);
    let mut kept = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let server_name = file.file_name.as_deref().filter(|name| !name.is_empty());
        let name = server_name.and_then(|_| local.next().and_then(|(_, name)| name));
        if wanted.is_some() && server_name != wanted {
            continue;
        }
        if server_name.is_some_and(|name| !keep.allows(name)) {
            continue;
        }
        let refuse = |reasons: &mut Vec<Value>, why: &str| {
            reasons.push(json!({
                "code": "FileNotDownloadable",
                "message": format!(
                    "file {} of the operation cannot be downloaded: {why}",
                    index + 1
                ),
            }));
        };
        let Some(server_name) = server_name else {
            refuse(reasons, "it has no fileName");
            continue;
        };
        // A name that holds a web address or a secret would carry it into
        // the local path and the manifest.
        if server_name.contains("://")
            || crate::redact::urls_in_text(server_name, redactor) != server_name
            || redactor.redact(server_name) != server_name
        {
            refuse(reasons, "its fileName holds a web address or a secret");
            continue;
        }
        let Some(name) = name else {
            refuse(
                reasons,
                "its fileName gives the same local name as another file's",
            );
            continue;
        };
        let Some(text) = file.download_url.as_deref() else {
            refuse(reasons, "it has no downloadUrl");
            continue;
        };
        let Ok(url) = Url::parse(text.trim()) else {
            refuse(reasons, "its downloadUrl is not a URL");
            continue;
        };
        match rule.origin(&url) {
            Ok(origin) => kept.push((
                DownloadableFile {
                    server_name: server_name.to_owned(),
                    url,
                    origin,
                    size: file.size,
                },
                name,
            )),
            // The rule's reason names the check, never the URL.
            Err(why) => refuse(reasons, why),
        }
    }
    kept
}

/// Creates the directory privately when it is missing; an existing one
/// keeps its mode but must not be a link.
fn prepare_dir(dir: &Path) -> Result<()> {
    if crate::config::check_dir_kind(dir)?.is_none() {
        crate::config::ensure_private_dir(dir)?;
    }
    Ok(())
}

/// The manifest entry for the file at `dir/name`: one recorded under that
/// name, or under another name that reaches the same file, as `Report.zip`
/// and `report.zip` do on a case-insensitive file system.
fn entry_for<'m>(
    dir: &Path,
    manifest: &'m Manifest,
    name: &str,
    metadata: &fs::Metadata,
) -> Option<&'m Entry> {
    let path = dir.join(name);
    manifest.entry(name).or_else(|| {
        manifest
            .files
            .iter()
            .find(|entry| same_file(&path, metadata, &dir.join(&entry.file_name)))
    })
}

/// The local names of every manifest entry that reaches the file at
/// `dir/name`: the entry under that name, and any under another name for
/// the same file.
fn owners(dir: &Path, manifest: &Manifest, name: &str) -> Vec<String> {
    let path = dir.join(name);
    let target = fs::symlink_metadata(&path).ok();
    manifest
        .files
        .iter()
        .filter(|entry| {
            entry.file_name == name
                || target
                    .as_ref()
                    .is_some_and(|target| same_file(&path, target, &dir.join(&entry.file_name)))
        })
        .map(|entry| entry.file_name.clone())
        .collect()
}

/// Whether `other` is the same regular file as `path` (whose metadata,
/// read without following links, is `metadata`): the same device and
/// inode on Unix. Elsewhere, where the standard library gives no file
/// identity, the same canonical path, which Windows gives with the name's
/// stored case, so `Report.zip` and `report.zip` agree. A link is never the
/// same file.
fn same_file(path: &Path, metadata: &fs::Metadata, other: &Path) -> bool {
    let Ok(other_metadata) = fs::symlink_metadata(other) else {
        return false;
    };
    if !metadata.is_file()
        || !other_metadata.is_file()
        || crate::config::is_link_like(metadata)
        || crate::config::is_link_like(&other_metadata)
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = (path, other);
        metadata.dev() == other_metadata.dev() && metadata.ino() == other_metadata.ino()
    }
    #[cfg(not(unix))]
    {
        match (fs::canonicalize(path), fs::canonicalize(other)) {
            (Ok(first), Ok(second)) => first == second,
            _ => false,
        }
    }
}

/// The plan for one file whose target is `dir/name`.
fn plan(
    dir: &Path,
    manifest: &Manifest,
    ids: &Ids,
    file: DownloadableFile,
    name: String,
    overwrite: bool,
) -> Result<Plan> {
    let path = dir.join(&name);
    let shown_path = || sanitize(&path.display().to_string());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Plan::Fetch {
                file,
                name,
                replace: overwrite,
            })
        }
        Err(error) => return Err(error.into()),
    };
    if crate::config::is_link_like(&metadata) {
        return Err(PurviewError::message(format!(
            "{} is a link; refusing to write through it",
            shown_path()
        )));
    }
    if !metadata.is_file() {
        return Err(PurviewError::message(format!(
            "{} exists and is not a regular file",
            shown_path()
        )));
    }
    if overwrite {
        return Ok(Plan::Fetch {
            file,
            name,
            replace: true,
        });
    }
    let entry = entry_for(dir, manifest, &name, &metadata);
    let ours = entry.is_some_and(|entry| {
        entry.file_name == name
            && entry.case_id == ids.case.to_string()
            && entry.operation_id == ids.operation.to_string()
            && entry.server_file_name == file.server_name
    });
    match (entry, ours) {
        (Some(entry), true) => {
            let (bytes, sha256) = digest_file(&path)?;
            if bytes == entry.size && sha256 == entry.sha256 {
                return Ok(Plan::Done(Done {
                    server_name: file.server_name,
                    path,
                    bytes,
                    sha256,
                    status: Status::AlreadyDownloaded,
                }));
            }
        }
        (None, _) => {
            // A file no entry reaches: verified and recorded, as after a
            // manifest write that failed.
            let size_ok = file.size.is_none_or(|size| size == metadata.len());
            if size_ok && check_zip(&path).is_ok() {
                let (bytes, sha256) = digest_file(&path)?;
                if file.size.is_none_or(|size| size == bytes) {
                    return Ok(Plan::Done(Done {
                        server_name: file.server_name,
                        path,
                        bytes,
                        sha256,
                        status: Status::Recovered,
                    }));
                }
            }
        }
        (Some(_), false) => {}
    }
    Err(PurviewError::TargetExists { path: shown_path() })
}

fn entry(ids: &Ids, done: &Done, now: &chrono::DateTime<chrono::Utc>, recovered: bool) -> Entry {
    Entry {
        case_id: ids.case.to_string(),
        operation_id: ids.operation.to_string(),
        action: ids.action.clone(),
        server_file_name: done.server_name.clone(),
        file_name: done
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        size: done.bytes,
        sha256: done.sha256.clone(),
        downloaded_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        recovered,
        extra: Default::default(),
    }
}

/// Why the manifest is being saved, for the error if it cannot be.
#[derive(Debug, Clone, Copy)]
enum Saving<'a> {
    Recovered,
    BeforeReplacing,
    AfterPublishing(&'a Path),
}

/// Saves the manifest. After a publication, a failure is
/// `ManifestWriteFailed`, naming the file that stays.
fn save_manifest(
    manifest: &Manifest,
    dir: &Path,
    session: &Session<'_>,
    context: &Context,
    saving: Saving<'_>,
) -> Result<()> {
    let saved = if context.faults.manifest_write {
        Err(PurviewError::message("the manifest write was made to fail"))
    } else {
        manifest.save(dir, &session.env.redactor)
    };
    let Err(error) = saved else {
        return Ok(());
    };
    Err(match saving {
        Saving::AfterPublishing(path) => PurviewError::ManifestWriteFailed {
            path: sanitize(&path.display().to_string()),
            reason: sanitize(&error.to_string()),
        },
        Saving::Recovered => error.context("recording recovered files in manifest.json"),
        Saving::BeforeReplacing => error
            .context("updating manifest.json before replacing the file, so nothing was replaced"),
    })
}

/// What an interrupted run says. The temporary file of the file in flight
/// is removed; the files already published stay recorded.
const INTERRUPTED: &str = "interrupted; the files listed were written and recorded, and running \
                           the same command again downloads the rest";

/// Prints what was done: every path, and the reasons for exit 4, or exit
/// 130 when Ctrl-C ended the run.
fn finish(
    session: &mut Session<'_>,
    done: Vec<Done>,
    reasons: Vec<Value>,
    interrupted: bool,
) -> Result<Produced> {
    let exit_code = if interrupted {
        130
    } else if reasons.is_empty() {
        0
    } else {
        4
    };
    if session.output.format == OutputFormat::Json {
        let count = done.len();
        let results: Vec<Value> = done
            .iter()
            .map(|done| {
                json!({
                    "fileName": done.server_name,
                    "path": done.path.to_string_lossy(),
                    "size": done.bytes,
                    "sha256": done.sha256,
                    "status": done.status.as_str(),
                })
            })
            .collect();
        let mut output = session.output.clone();
        if exit_code != 0 {
            // Exit 4 prints the whole envelope, so that the outcome has
            // somewhere to go.
            output.results_only = false;
        }
        let mut document =
            output.untrusted_json_value(Value::Array(results), count, &session.env.redactor)?;
        if let Value::Object(object) = &mut document {
            if !reasons.is_empty() {
                object.insert(
                    "outcome".into(),
                    json!({"code": "Incomplete", "reasons": reasons}),
                );
            }
            if interrupted {
                object.insert(
                    "error".into(),
                    json!({"code": "Interrupted", "status": 0, "message": INTERRUPTED}),
                );
            }
        }
        return Ok(Produced {
            exit_code,
            document: Some(document),
        });
    }
    let rows: Vec<Vec<String>> = done
        .iter()
        .map(|done| {
            vec![
                done.status.as_str().to_owned(),
                done.bytes.to_string(),
                done.path.display().to_string(),
            ]
        })
        .collect();
    write_rows(&mut session.env.stdout, session.output, COLUMNS, &rows)?;
    for reason in &reasons {
        let _ = writeln!(
            session.env.stderr,
            "incomplete: {}",
            sanitize(reason["message"].as_str().unwrap_or_default())
        );
    }
    if interrupted {
        let _ = writeln!(session.env.stderr, "{INTERRUPTED}");
    }
    Ok(Produced {
        exit_code,
        document: None,
    })
}
