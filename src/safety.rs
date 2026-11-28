//! Plan, approve, send (`docs/SPEC.md` section 6.2).
//!
//! A write command runs its read-only preflight and builds a `WritePlan`:
//! the account and tenant, the `WriteRoute`, the body serialised once to
//! bytes, a SHA-256 digest of method, path and body, the effects as plain
//! sentences, warnings and the preflight results. `decide` turns the plan
//! into a `Decision` from `--dry-run`, `--yes`, `--no-input` and, at a
//! terminal, the person's answer. Only `approve` builds an `ApprovedWrite`,
//! and only this module can make the `Approval` it needs, so the one
//! request method that sends a POST, `GraphClient::send_write`, can only
//! send a plan that was approved, exactly as it was shown.

use std::io::Write;

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::AccountRecord;
use crate::env::Input;
use crate::error::{PurviewError, Result};
use crate::graph::{GraphClient, WriteResponse};
use crate::kql::GuardConfig;
use crate::naming::Naming;
use crate::output::{sanitize, sanitize_multiline};
use crate::redact::Redactor;
use crate::routes::WriteRoute;

/// One write, as preflight planned it.
#[derive(Debug, Clone, PartialEq)]
pub struct WritePlan {
    command: &'static str,
    account: String,
    tenant: String,
    route: WriteRoute,
    path: String,
    body: Vec<u8>,
    digest: String,
    effects: Vec<String>,
    warnings: Vec<String>,
    preflight: Vec<Value>,
    blocked: Option<Blocked>,
    /// Text the person must type at the terminal to approve, instead of
    /// `y`: the case name for `case close`.
    typed: Option<String>,
}

/// Why a plan may be shown but not sent. A dry run prints the plan; any
/// other run fails with the reason's own error before anyone is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// An operation that may be a duplicate, without `--allow-concurrent`
    /// (`ConcurrentOperation`).
    Concurrent(String),
    /// The search's latest estimate passes `volume.max_export_size`,
    /// without `--allow-large` (`TooLarge`).
    TooLarge(String),
    /// The search has no estimate whose size can be compared with
    /// `volume.max_export_size`, without `--allow-large`
    /// (`VolumeUnchecked`).
    VolumeUnchecked(String),
}

impl Blocked {
    pub fn error(&self) -> PurviewError {
        match self {
            Self::Concurrent(message) => PurviewError::ConcurrentOperation(message.clone()),
            Self::TooLarge(message) => PurviewError::TooLarge(message.clone()),
            Self::VolumeUnchecked(message) => PurviewError::VolumeUnchecked(message.clone()),
        }
    }
}

/// What a command gives to build its plan.
#[derive(Debug, Clone)]
pub struct PlanInput {
    /// The command as typed, such as `case create`.
    pub command: &'static str,
    pub account: String,
    pub tenant: String,
    pub route: WriteRoute,
    pub body: Value,
    /// What the write changes, as plain sentences.
    pub effects: Vec<String>,
    pub warnings: Vec<String>,
    /// What each preflight read found.
    pub preflight: Vec<Value>,
    /// Why the plan may be shown but not sent, such as an operation that
    /// may be a duplicate without `--allow-concurrent`.
    pub blocked: Option<Blocked>,
}

impl WritePlan {
    /// The plan, with the body serialised once: these bytes are the ones
    /// shown, digested and sent. A route that takes no body
    /// (`WriteRoute::takes_body`) is given `null` and sends no bytes.
    pub fn new(input: PlanInput) -> Result<Self> {
        let body = if input.route.takes_body() {
            if !input.body.is_object() {
                return Err(PurviewError::message("a write body must be a JSON object"));
            }
            serde_json::to_vec(&input.body)?
        } else {
            if !input.body.is_null() {
                return Err(PurviewError::message("this write takes no body"));
            }
            Vec::new()
        };
        let path = format!("/{}", input.route.segments().join("/"));
        let digest = digest(input.route.method(), &path, &body);
        Ok(Self {
            command: input.command,
            account: input.account,
            tenant: input.tenant,
            route: input.route,
            path,
            body,
            digest,
            effects: input.effects,
            warnings: input.warnings,
            preflight: input.preflight,
            blocked: input.blocked,
            typed: None,
        })
    }

    /// The plan, approved at a terminal only when the person types `text`
    /// exactly (ignoring surrounding spaces), rather than `y`. `--yes`
    /// still approves it.
    pub fn with_typed_confirmation(mut self, text: String) -> Self {
        self.typed = Some(text);
        self
    }

    pub fn command(&self) -> &'static str {
        self.command
    }

    pub fn route(&self) -> WriteRoute {
        self.route
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn method(&self) -> &'static str {
        self.route.method()
    }

    /// The path below the Graph base, such as
    /// `/security/cases/ediscoveryCases`.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Lowercase hexadecimal SHA-256 of method, path and body.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Why the plan may not be sent, when it may not.
    pub fn blocked(&self) -> Option<&Blocked> {
        self.blocked.as_ref()
    }

    /// The plan as JSON: `{"command", "account", "tenant", "method",
    /// "path", "body", "digest", "effects", "warnings", "preflight"}`. The
    /// body is read back from the bytes that will be sent.
    pub fn to_value(&self) -> Value {
        json!({
            "command": self.command,
            "account": self.account,
            "tenant": self.tenant,
            "method": self.method(),
            "path": self.path,
            "body": serde_json::from_slice::<Value>(&self.body).unwrap_or(Value::Null),
            "digest": self.digest,
            "effects": self.effects,
            "warnings": self.warnings,
            "preflight": self.preflight,
        })
    }

    /// The plan for a person. It is built from the JSON form after the
    /// redaction every printed document gets (URLs as in the trace, then
    /// the secrets the tool holds, as values, before anything is escaped),
    /// and every value is then sanitised.
    pub fn write_text(&self, out: &mut dyn Write, redactor: &Redactor) -> Result<()> {
        let shown = redactor.redact_value(&crate::trace::redact_urls(&self.to_value(), redactor));
        let text = |key: &str| sanitize(shown[key].as_str().unwrap_or_default());
        let list = |key: &str| -> Vec<Value> { shown[key].as_array().cloned().unwrap_or_default() };
        writeln!(out, "Plan: purview {}", text("command"))?;
        writeln!(out, "  account: {}", text("account"))?;
        writeln!(out, "  tenant:  {}", text("tenant"))?;
        writeln!(out, "  request: {} {}", text("method"), text("path"))?;
        let body = serde_json::to_string_pretty(&shown["body"]).unwrap_or_default();
        writeln!(out, "  body:")?;
        for line in sanitize_multiline(&body).lines() {
            writeln!(out, "    {line}")?;
        }
        writeln!(out, "  digest:  sha256:{}", text("digest"))?;
        writeln!(out, "  effects:")?;
        for effect in list("effects") {
            writeln!(
                out,
                "    - {}",
                sanitize(effect.as_str().unwrap_or_default())
            )?;
        }
        let preflight = list("preflight");
        if !preflight.is_empty() {
            writeln!(out, "  preflight:")?;
            for result in preflight {
                let line = match &result {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                writeln!(out, "    - {}", sanitize(&line))?;
            }
        }
        for warning in list("warnings") {
            writeln!(
                out,
                "  warning: {}",
                sanitize(warning.as_str().unwrap_or_default())
            )?;
        }
        Ok(())
    }
}

/// SHA-256 of `method`, a line feed, `path`, a line feed and `body`, as
/// lowercase hexadecimal.
pub fn digest(method: &str, path: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Proof that a plan was approved: by `--yes`, or by the person at the
/// terminal. Only this module can make one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval(Approver);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approver {
    YesFlag,
    Prompt,
}

/// A plan that may be sent, once. `GraphClient::send_write` takes it by
/// value and sends its method, path and bytes as they are. It is not
/// `Clone`, so one approval cannot be sent twice.
#[derive(Debug, PartialEq)]
pub struct ApprovedWrite {
    plan: WritePlan,
    approval: Approval,
}

impl ApprovedWrite {
    pub fn plan(&self) -> &WritePlan {
        &self.plan
    }

    pub fn route(&self) -> WriteRoute {
        self.plan.route
    }

    pub fn method(&self) -> &'static str {
        self.plan.method()
    }

    pub fn body(&self) -> &[u8] {
        &self.plan.body
    }

    /// Whether `--yes` approved it, rather than an answer at the terminal.
    pub fn by_flag(&self) -> bool {
        self.approval.0 == Approver::YesFlag
    }

    pub fn into_plan(self) -> WritePlan {
        self.plan
    }
}

/// The only way to an `ApprovedWrite`, and only `decide` holds an
/// `Approval` to give it.
fn approve(plan: WritePlan, approval: Approval) -> ApprovedWrite {
    ApprovedWrite { plan, approval }
}

/// The flags and terminal state approval depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApprovalSettings {
    pub dry_run: bool,
    pub yes: bool,
    pub no_input: bool,
    /// Standard input and standard error are both terminals.
    pub interactive: bool,
}

/// Why a write was not sent, for exit 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplied {
    /// No `--yes`, and no one to ask: not a terminal, or `--no-input`.
    ConfirmationRequired,
    /// The person at the terminal did not answer yes.
    Declined,
}

impl NotApplied {
    pub fn code(self) -> &'static str {
        match self {
            Self::ConfirmationRequired => "ConfirmationRequired",
            Self::Declined => "Declined",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::ConfirmationRequired => {
                "the write was not sent: pass --yes to approve it, or run the command at a \
                 terminal without --no-input to be asked"
            }
            Self::Declined => "the write was not sent: it was declined",
        }
    }
}

/// What happens to a plan.
#[derive(Debug, PartialEq)]
pub enum Decision {
    /// `--dry-run`: printed, not sent. It wins over `--yes`.
    DryRun(WritePlan),
    Approved(ApprovedWrite),
    NotApplied(WritePlan, NotApplied),
}

/// Decides what to do with `plan`. `--dry-run` wins over `--yes`; `--yes`
/// approves; without either, the person is asked only when both standard
/// input and standard error are terminals and `--no-input` is not given.
/// The prompt is `Apply? [y/N]` on `prompt`, after the plan; `y` or `yes`,
/// in any case, approves, and anything else, end of input included,
/// declines. A plan with a typed confirmation asks for that text instead,
/// and only that text approves. Only `cli`'s write runner calls it, with the parsed flags;
/// `tests/write_allow_list.rs` checks that.
pub(crate) async fn decide(
    plan: WritePlan,
    settings: ApprovalSettings,
    input: &dyn Input,
    prompt: &mut dyn Write,
    redactor: &Redactor,
) -> Result<Decision> {
    if settings.dry_run {
        return Ok(Decision::DryRun(plan));
    }
    if settings.yes {
        return Ok(Decision::Approved(approve(
            plan,
            Approval(Approver::YesFlag),
        )));
    }
    if settings.no_input || !settings.interactive {
        return Ok(Decision::NotApplied(plan, NotApplied::ConfirmationRequired));
    }
    plan.write_text(prompt, redactor)?;
    match &plan.typed {
        // The text is tenant text: shown as every printed value is.
        Some(text) => write!(
            prompt,
            "Type the case name to apply ({}): ",
            sanitize(&crate::redact::shown(text, redactor))
        )?,
        None => write!(prompt, "Apply? [y/N] ")?,
    }
    prompt.flush()?;
    let answer = input.read_line().await?;
    let yes = answer
        .as_deref()
        .map(str::trim)
        .is_some_and(|answer| match &plan.typed {
            Some(text) => !answer.is_empty() && answer == text.trim(),
            None => answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"),
        });
    Ok(if yes {
        Decision::Approved(approve(plan, Approval(Approver::Prompt)))
    } else {
        Decision::NotApplied(plan, NotApplied::Declined)
    })
}

/// The settings from `config.json` that a write reads before sign-in:
/// the naming templates and the guard's term lists, each checked.
#[derive(Debug, Clone)]
pub struct WriteSettings {
    pub naming: Naming,
    pub guard: GuardConfig,
    /// The limits for reading report zips (`limits` in `config.json`).
    pub report: crate::report::ReportLimits,
    /// The volume warning's limits (`volume` in `config.json`).
    pub volume: crate::report::volume::VolumeLimits,
    /// `defaults.teams_context`, `true` unless set to `false`.
    pub teams_context: bool,
}

/// What preflight decided.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // One per command run; never stored.
pub enum Planned {
    /// A write to decide on.
    Write(WritePlan),
    /// Nothing to send, because what the command would create exists
    /// already and may be used (`case create --reuse-existing`). `result`
    /// is shown as the command's result, after `notice`.
    Existing { result: Value, notice: String },
}

/// What reconciliation found: candidates the write may have created, each
/// named by id, and notes on how far the check got.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub candidates: Vec<String>,
    pub notes: Vec<String>,
}

/// What a write command gets while it plans, reconciles or reads its
/// result: the Graph client, the signed-in account and a log for notices.
/// Not `Env`: the terminal, the approval input and the prompt belong to the
/// runner, so a command cannot take part in its own approval. The account
/// is shared, so the command cannot change whom the plan is checked
/// against.
pub struct Preflight<'a> {
    pub graph: &'a GraphClient,
    pub account: &'a AccountRecord,
    pub log: &'a mut (dyn Write + Send),
    pub verbose: bool,
    pub clock: &'a dyn crate::env::Clock,
}

/// What a write command gets after Graph accepted the write, to read and
/// show its result: the session (streams, output settings, Graph client,
/// account) and, for a command that asked for it, the download client.
/// The approval has been used by then, and the runner sends nothing more.
pub struct After<'a> {
    pub session: crate::commands::Session<'a>,
    pub download: Option<&'a crate::commands::download::Context>,
}

/// What the result of a write is.
#[derive(Debug)]
pub enum Applied {
    /// The result, printed in the write envelope. A reason, such as an
    /// operation that did not succeed, makes the exit 4, with the reasons
    /// as the envelope's `outcome`.
    Result { result: Value, reasons: Vec<Value> },
    /// A document the command printed in its own shape, such as the wait
    /// deadline's exit 5 (`docs/SPEC.md` section 3.3).
    Produced(crate::commands::Produced),
}

impl Applied {
    /// A result with no reasons.
    pub fn result(result: Value) -> Self {
        Self::Result {
            result,
            reasons: Vec::new(),
        }
    }
}

/// The body of one write command, run by `cli`'s write runner, which
/// checks `--no-write` and the read-only session, signs in, decides on the
/// plan, sends it and prints the outcome.
#[async_trait]
pub trait WriteCommand: Send {
    /// Checks that need no sign-in, such as the KQL guard on a query given
    /// on the command line, with the settings from `config.json`. Runs
    /// before sign-in; a command keeps what it needs from `settings`.
    fn check(&mut self, _settings: &WriteSettings) -> Result<()> {
        Ok(())
    }

    /// The read-only preflight, then the plan, or what already exists when
    /// nothing needs to be sent. Only Graph GETs and token refreshes may be
    /// sent here.
    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned>;

    /// Runs after approval and before the send: a command whose plan
    /// rests on state another person can change (an action's search)
    /// reads it again and refuses when it differs from what the plan
    /// showed. Reads only. A change after this read is still possible.
    async fn recheck(&mut self, _preflight: &mut Preflight<'_>) -> Result<()> {
        Ok(())
    }

    /// Whether the command downloads files after its write, so that the
    /// runner sets up the download client.
    fn downloads(&self) -> bool {
        false
    }

    /// Which keys of `volume` in `config.json` the command reads, so that a
    /// bad setting there stops only the commands that use it.
    fn volume_use(&self) -> crate::report::volume::VolumeUse {
        crate::report::volume::VolumeUse::None
    }

    /// Whether the command reads `defaults.teams_context`, so that a bad
    /// setting there stops only the commands that use it.
    fn reads_teams_context(&self) -> bool {
        false
    }

    /// The result shown after Graph accepted the write.
    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied>;

    /// After an unclear outcome: what the write may have created, for the
    /// person to check. Reads only.
    async fn reconcile(&mut self, _preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        Ok(Reconciled::default())
    }
}

/// The JSON document of a write that was not sent (exit 3).
pub fn not_applied_value(plan: &WritePlan, reason: NotApplied) -> Value {
    json!({
        "plan": plan.to_value(),
        "applied": false,
        "error": {
            "code": reason.code(),
            "status": 0,
            "message": reason.message(),
        }
    })
}

/// The `results` of a write that was not needed (exit 0): `{"applied":
/// false, "plan": null, "result", "reused": true}`.
pub fn existing_value(result: Value) -> Value {
    json!({
        "applied": false,
        "plan": Value::Null,
        "result": result,
        "reused": true,
    })
}

/// The `results` of a write that ran (exit 0): `{"applied", "plan",
/// "result"}`, with `result` null after a dry run.
pub fn results_value(plan: &WritePlan, applied: bool, result: Option<Value>) -> Value {
    json!({
        "applied": applied,
        "plan": plan.to_value(),
        "result": result.unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::ScriptedInput;
    use crate::routes::CaseId;

    fn plan() -> WritePlan {
        WritePlan::new(PlanInput {
            command: "search create",
            account: "alex@contoso.example".into(),
            tenant: "00000000-0000-4000-8000-000000000002".into(),
            route: WriteRoute::CreateSearch(
                CaseId::parse("00000000-0000-4000-8000-000000000011").unwrap(),
            ),
            body: json!({"displayName": "s", "contentQuery": "\"orders-api\""}),
            effects: vec!["Creates a search over all tenant mailboxes. Places no hold.".into()],
            warnings: vec!["w".into()],
            preflight: vec![json!({"read": "case", "status": "active"})],
            blocked: None,
        })
        .unwrap()
    }

    #[test]
    fn the_plan_holds_what_will_be_sent() {
        let plan = plan();
        let value = plan.to_value();
        assert_eq!(value["command"], "search create");
        assert_eq!(value["account"], "alex@contoso.example");
        assert_eq!(value["method"], "POST");
        assert_eq!(
            value["path"],
            "/security/cases/ediscoveryCases/00000000-0000-4000-8000-000000000011/searches"
        );
        assert_eq!(value["body"]["contentQuery"], "\"orders-api\"");
        assert_eq!(value["effects"][0], plan.effects[0]);
        assert_eq!(value["warnings"], json!(["w"]));
        assert_eq!(value["preflight"][0]["read"], "case");
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "account",
                "body",
                "command",
                "digest",
                "effects",
                "method",
                "path",
                "preflight",
                "tenant",
                "warnings"
            ]
        );
    }

    #[test]
    fn the_digest_covers_method_path_and_the_bytes() {
        let plan = plan();
        assert_eq!(plan.digest(), digest("POST", plan.path(), plan.body()));
        assert_eq!(plan.to_value()["digest"], plan.digest());
        assert_eq!(plan.digest().len(), 64);
        let mut changed = plan.body().to_vec();
        changed.push(b' ');
        assert_ne!(plan.digest(), digest("POST", plan.path(), &changed));
        assert_ne!(plan.digest(), digest("POST", "/other", plan.body()));
        // Known value, from `printf 'POST\n/p\n{}' | shasum -a 256`.
        assert_eq!(
            digest("POST", "/p", b"{}"),
            "70afba2bdaa6e008e2c7c76079284057d04446716920855bb1c95f65a9b7fece"
        );
    }

    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        let mut input = PlanInput {
            command: "case create",
            account: String::new(),
            tenant: String::new(),
            route: WriteRoute::CreateCase,
            body: json!([]),
            effects: Vec::new(),
            warnings: Vec::new(),
            preflight: Vec::new(),
            blocked: None,
        };
        assert!(WritePlan::new(input.clone()).is_err());
        input.body = json!({});
        assert!(WritePlan::new(input).is_ok());
    }

    async fn decision(settings: ApprovalSettings, answers: &[&str]) -> (Decision, String) {
        let input = ScriptedInput::new(answers);
        let mut prompt = Vec::new();
        let decision = decide(plan(), settings, &input, &mut prompt, &Redactor::new())
            .await
            .unwrap();
        (decision, String::from_utf8(prompt).unwrap())
    }

    #[tokio::test]
    async fn dry_run_wins_over_yes() {
        let settings = ApprovalSettings {
            dry_run: true,
            yes: true,
            interactive: true,
            ..Default::default()
        };
        let (decision, prompt) = decision(settings, &["y"]).await;
        assert!(matches!(decision, Decision::DryRun(_)));
        assert!(prompt.is_empty());
    }

    #[tokio::test]
    async fn yes_approves_without_asking() {
        let settings = ApprovalSettings {
            yes: true,
            interactive: true,
            ..Default::default()
        };
        let (decision, prompt) = decision(settings, &[]).await;
        let Decision::Approved(write) = decision else {
            panic!("{decision:?}")
        };
        assert!(write.by_flag());
        assert_eq!(write.body(), plan().body());
        assert!(prompt.is_empty());
    }

    #[tokio::test]
    async fn without_yes_no_one_to_ask_means_confirmation_required() {
        for settings in [
            ApprovalSettings::default(),
            ApprovalSettings {
                no_input: true,
                interactive: true,
                ..Default::default()
            },
        ] {
            let (decision, prompt) = decision(settings, &["y"]).await;
            assert!(
                matches!(
                    decision,
                    Decision::NotApplied(_, NotApplied::ConfirmationRequired)
                ),
                "{settings:?}"
            );
            assert!(prompt.is_empty());
        }
    }

    #[tokio::test]
    async fn at_a_terminal_only_yes_approves() {
        let settings = ApprovalSettings {
            interactive: true,
            ..Default::default()
        };
        for answer in ["y", "Y", "yes", " YES\n"] {
            let (decision, prompt) = decision(settings, &[answer]).await;
            let Decision::Approved(write) = decision else {
                panic!("{answer:?}: {decision:?}")
            };
            assert!(!write.by_flag());
            assert!(
                prompt.starts_with("Plan: purview search create\n"),
                "{prompt}"
            );
            assert!(prompt.ends_with("Apply? [y/N] "), "{prompt}");
        }
        for answers in [&["n"][..], &[""], &["no"], &["yess"], &[]] {
            let (decision, _) = decision(settings, answers).await;
            assert!(
                matches!(decision, Decision::NotApplied(_, NotApplied::Declined)),
                "{answers:?}"
            );
        }
    }

    /// Compiles only while `ApprovedWrite` is not `Clone`: with a `Clone`
    /// impl, the call below would be ambiguous.
    #[test]
    fn an_approved_write_cannot_be_copied() {
        trait AmbiguousIfClone<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}
        <ApprovedWrite as AmbiguousIfClone<_>>::check();
    }

    #[test]
    fn the_exit_3_document_has_the_plan_and_the_reason() {
        let value = not_applied_value(&plan(), NotApplied::ConfirmationRequired);
        assert_eq!(value["applied"], false);
        assert_eq!(value["error"]["code"], "ConfirmationRequired");
        assert_eq!(value["error"]["status"], 0);
        assert_eq!(value["plan"], plan().to_value());
        assert_eq!(
            not_applied_value(&plan(), NotApplied::Declined)["error"]["code"],
            "Declined"
        );
    }

    #[test]
    fn the_plan_text_is_sanitised() {
        let mut input = PlanInput {
            command: "case create",
            account: "alex@contoso.example".into(),
            tenant: "t".into(),
            route: WriteRoute::CreateCase,
            body: json!({"displayName": "a\u{1b}[31mb"}),
            effects: vec!["e\u{7}".into()],
            warnings: vec!["w\u{1b}".into()],
            preflight: Vec::new(),
            blocked: None,
        };
        input.account.push('\u{1b}');
        let mut out = Vec::new();
        WritePlan::new(input)
            .unwrap()
            .write_text(&mut out, &Redactor::new())
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains('\u{7}'), "{text:?}");
    }

    #[test]
    fn the_plan_text_is_redacted_and_shows_the_preflight() {
        let secret = ["canary", "\"quoted\\secret-0042"].concat();
        let redactor = Redactor::new();
        redactor.register(&secret);
        let signed = ["https://", "files.contoso.example/a?sig=canary-sig-0043"].concat();
        let input = PlanInput {
            command: "case create",
            account: "alex@contoso.example".into(),
            tenant: "t".into(),
            route: WriteRoute::CreateCase,
            body: json!({"description": format!("see {signed} and {secret}")}),
            effects: vec![format!("e {secret}")],
            warnings: vec![format!("w {signed}")],
            preflight: vec![
                json!({"case": "none with that name"}),
                json!("holds: none"),
                json!({ signed.clone(): "a signed link used as a key" }),
            ],
            blocked: None,
        };
        let mut out = Vec::new();
        WritePlan::new(input)
            .unwrap()
            .write_text(&mut out, &redactor)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("canary-sig-0043"), "{text}");
        assert!(!text.contains("secret-0042"), "{text}");
        assert!(text.contains("  preflight:\n"), "{text}");
        assert!(text.contains("none with that name"), "{text}");
        assert!(text.contains("    - holds: none\n"), "{text}");
    }
}
