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
    self, check_zip, digest_file, names, DownloadClient, DownloadFaults, DownloadableFile, Limits,
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
}

/// What the command downloads with, beyond the session.
pub struct Context {
    pub client: DownloadClient,
    pub limits: Limits,
    /// The root below which `cases/<case>/<op>/` is made when `--out` is
    /// not given.
    pub data_root: PathBuf,
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

struct Done {
    server_name: String,
    path: PathBuf,
    bytes: u64,
    sha256: String,
    status: Status,
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
    let files: Vec<FileRecord> = record
        .detail()
        .map(|detail| detail.files().to_vec())
        .unwrap_or_default();
    let files = match &request.file {
        None => files,
        Some(wanted) => {
            let kept: Vec<FileRecord> = files
                .into_iter()
                .filter(|file| file.file_name.as_deref() == Some(wanted.as_str()))
                .collect();
            if kept.is_empty() {
                // The name is not repeated: it is tenant text.
                return Err(PurviewError::message(
                    "the operation has no file with the name given to --file; 'purview \
                     operation get' lists its files",
                ));
            }
            kept
        }
    };
    let mut reasons: Vec<Value> = Vec::new();
    if let Some(reason) = super::operation::incomplete_reason(&record) {
        let message = shown(session, reason["message"].as_str().unwrap_or_default());
        reasons.push(json!({"code": reason["code"], "message": message}));
    }
    let candidates = downloadable(context.client.rule(), &files, &mut reasons);
    let dir = match &request.out {
        Some(out) => crate::config::normalise(out),
        None => context
            .data_root
            .join("cases")
            .join(case.to_string())
            .join(request.operation.to_string()),
    };
    // Every path the command prints is a full one (`docs/SPEC.md` section
    // 5.4), whatever --out or defaults.data_dir gave.
    let dir = std::path::absolute(&dir)?;
    if candidates.is_empty() {
        if files.is_empty() {
            let _ = writeln!(
                session.env.stderr,
                "notice: operation {} lists no files",
                request.operation
            );
        }
        return finish(session, Vec::new(), reasons);
    }
    prepare_dir(&dir)?;
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
        save_manifest(&manifest, &dir, session, context, None)?;
    }
    let mut done = Vec::new();
    for plan in plans {
        match plan {
            Plan::Done(finished) => done.push(finished),
            Plan::Fetch {
                file,
                name,
                replace,
            } => {
                let published = download::download_into(
                    &context.client,
                    &file,
                    &download::Placement {
                        dir: &dir,
                        name: &name,
                        overwrite: replace,
                    },
                    context.limits,
                    &context.faults,
                    &mut session.env.stderr,
                )
                .await
                .map_err(|error| {
                    error.context(format!(
                        "downloading {}",
                        sanitize(&shown(session, &file.server_name))
                    ))
                })?;
                let finished = Done {
                    server_name: file.server_name,
                    path: published.path,
                    bytes: published.bytes,
                    sha256: published.sha256,
                    status: Status::Downloaded,
                };
                manifest.record(entry(&ids, &finished, &session.env.clock.now(), false));
                save_manifest(&manifest, &dir, session, context, Some(&finished.path))?;
                done.push(finished);
            }
        }
    }
    finish(session, done, reasons)
}

struct Ids {
    case: CaseId,
    operation: OperationId,
    action: String,
}

/// The files that can be downloaded, with their local names; a reason for
/// each that cannot.
fn downloadable(
    rule: &download::DownloadRule,
    files: &[FileRecord],
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
        let refuse = |reasons: &mut Vec<Value>, why: &str| {
            reasons.push(json!({
                "code": "FileNotDownloadable",
                "message": format!(
                    "file {} of the operation cannot be downloaded: {why}",
                    index + 1
                ),
            }));
        };
        let Some(server_name) = file.file_name.as_deref().filter(|name| !name.is_empty()) else {
            refuse(reasons, "it has no fileName");
            continue;
        };
        let name = local.next().and_then(|(_, name)| name);
        let Some(name) = name else {
            refuse(reasons, "it has the same fileName as another file");
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
                replace: false,
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
    let entry = manifest.entry(&name);
    let ours = entry.is_some_and(|entry| {
        entry.case_id == ids.case.to_string()
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
            // A file with no entry: verified and recorded, as after a
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

/// Saves the manifest. After a publication, a failure is
/// `ManifestWriteFailed`, naming the file that stays.
fn save_manifest(
    manifest: &Manifest,
    dir: &Path,
    session: &Session<'_>,
    context: &Context,
    published: Option<&Path>,
) -> Result<()> {
    let saved = if context.faults.manifest_write {
        Err(PurviewError::message("the manifest write was made to fail"))
    } else {
        manifest.save(dir, &session.env.redactor)
    };
    match (saved, published) {
        (Ok(()), _) => Ok(()),
        (Err(error), Some(path)) => Err(PurviewError::ManifestWriteFailed {
            path: sanitize(&path.display().to_string()),
            reason: sanitize(&error.to_string()),
        }),
        (Err(error), None) => Err(error.context("recording recovered files in manifest.json")),
    }
}

/// Prints what was done: every path, and the reasons for exit 4.
fn finish(session: &mut Session<'_>, done: Vec<Done>, reasons: Vec<Value>) -> Result<Produced> {
    let exit_code = if reasons.is_empty() { 0 } else { 4 };
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
        if exit_code != 0 {
            if let Value::Object(object) = &mut document {
                object.insert(
                    "outcome".into(),
                    json!({"code": "Incomplete", "reasons": reasons}),
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
    Ok(Produced {
        exit_code,
        document: None,
    })
}
