# `ms-purview-cli` (`purview`): specification and implementation plan

Status: v3, 2026-11-26, for maintainer review. Revised after two review rounds. The review
history (reviews, dispositions and the frozen v1) is private working material. It lives
outside the published tree and must not ship in the public repository; the public-data lint
fails if a `docs/reviews/` directory is present (section 8.1).

Target repository: `github.com/aberoham/ms-purview-cli`, MIT licence. Binary: `purview`.
Sibling of `aberoham/ms-entra-cli` (`entra`).

**Evidence labels.** Every claim about the service carries one of these:

| Label | Meaning |
|---|---|
| **Observed** | Recorded in the maintainer's private API notes of 2026-11-25, from live calls against one tenant |
| **Observed (trace)** | Seen in the raw request and response recordings of the same day, not written into the notes. No design decision rests on one of these without an observation gate (section 12.1) |
| **Prototype** | What the maintainer's private Python prototype does in its source code; evidence of what was requested, not of what the service guarantees |
| **Docs** | Microsoft Learn only |
| **Derived** | Inferred from observations |
| **Assumption** | Not checked against the service |

Measurements come from one observed tenant. The spec gives ratios, timings and orders of
magnitude, not that tenant's counts. `docs/api-notes.md` (section 9) is the public version of
the notes and follows the same rule.

---

## 1. Purpose, non-goals, audience

### Purpose

`purview` drives Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0
(`/security/cases/ediscoveryCases`) from a terminal. It:

- lists, inspects, creates and closes cases;
- creates searches over every mailbox in the tenant, which covers mail and Teams chat and
  channel messages;
- runs estimates, item reports (`exportReport`) and item exports (`exportResult`), polls the
  resulting operations and downloads their files;
- turns report zips into summaries: hit counts per location, failed locations, and a profile
  of the unique items;
- joins an item export to its report and reads message headers and body text, streamed from
  the zip, so a records question can be answered from the terminal;
- later, lists old cases with their hold policies and ages, read-only, so a clean-up can be
  planned.

The tool never places a hold.

### Non-goals

- **Placing or releasing holds.** There is no command that adds custodians, non-custodial
  data sources or legal holds. `case close` reads holds, read-only, from phase 2; the
  inventory commands arrive in phase 6. Releasing holds is out of scope.
- **Deleting cases.** Graph v1.0 documents no case delete. Delete cases in the portal.
- **Reopening cases.** `reopen` exists in the Graph documentation (Docs). The tool does not
  call it; reopening is a manual change made in the portal.
- **Review sets, tags, analytics, and SharePoint or OneDrive scopes** (`allTenantSites`).
- **National clouds** (US Government Community Cloud High, Department of Defense, China).
- **Rendering attachments or extracting them to disk.** `export read` reports attachment
  names and sizes, not their content.
- **Anything specific to one organisation.** No tenant id, client id, organisation name,
  domain, naming policy or policy text appears in code, docs, tests or fixtures. All of these
  come from config or flags.

### Audience

- Security, compliance and records staff who hold the Purview eDiscovery Manager or
  eDiscovery Administrator role.
- AI coding agents that run the tool under a `SKILL.md`. The tool enforces in code the rules
  a skill would otherwise state in prose.
- Rust engineers who implement it from this document.

---

## 2. Prior art and why not existing tools

- **Purview portal.** It does everything, but only by hand. Per-location hit counts and
  failure details are inside zips that the portal hands back one at a time.
- **Security & Compliance PowerShell** (`New-ComplianceSearch`, `New-ComplianceSearchAction
  -Export`). It creates and runs searches but cannot download exports; downloads need the
  portal's export tooling (Docs).
- **Azure command-line interface (CLI)** (client `04b07795-…`). A token for the Purview
  eDiscovery app (`b26e684c-5068-4120-a679-64a5d2c909d9`) fails with `AADSTS65002`: first-party
  apps need pre-authorisation by the API owner, which consent cannot provide (Observed).
- **Microsoft Graph Command Line Tools** (client `14d82eec-…`, used by Graph PowerShell and
  the Graph CLI). It obtains a Graph token with `eDiscovery.ReadWrite.All` after per-user
  consent, but gets `AADSTS65001` for the eDiscovery app (Observed). It can search but cannot
  download.
- **An app registration of one's own** (public client, no secret). One refresh token yields
  both the Graph token and the download token (Observed). `purview` is built on this.
- **The maintainer's Python prototype.** It proved the flow, including trace recording.
  `purview` replaces it with signed binaries, keychain storage, safety checks in code and
  report parsing.

---

## 3. Command reference

### 3.1 Global flags

| Flag | Env | Meaning |
|---|---|---|
| `--json` | `PURVIEW_JSON` | JSON output; shapes per exit code in section 3.3 |
| `--results-only` | `PURVIEW_RESULTS_ONLY` | With `--json` and exit 0, print `results` without the envelope |
| `--plain` | `PURVIEW_PLAIN` | Tab-separated values (TSV), no header |
| `--select COLS` | `PURVIEW_SELECT` | Table or `--plain` columns by header name. An unknown name is an error, raised before sign-in in every output format; the error does not repeat the name. Every table's columns are listed in `docs/command-reference.md` |
| `--account EMAIL` | `PURVIEW_ACCOUNT` | Stored identity to use. Matches the stored account key, or the `upn` claim recorded at sign-in, case-insensitively. No alias resolution (there is no `/me` read) and no fallback to another account |
| `-v, --verbose` | `PURVIEW_VERBOSE` | Requests and sign-in steps on stderr, through the redactor (section 6.8) |
| `--timeout SECS` | `PURVIEW_TIMEOUT` | Per-request Graph timeout. `0` means 60; at most 600. Downloads use their own timeouts (section 4.7) |
| `--no-input` | `PURVIEW_NO_INPUT` | Never prompt. A write without `--yes` stops with exit 3 |
| `--no-write` | `PURVIEW_NO_WRITE` | Refuse every write command before sign-in, with error code `WriteRefused` |
| `--yes` | `PURVIEW_YES` | Approve a write without the interactive prompt |
| `--dry-run` | none | Run the read-only preflight, print the plan, send no write, exit 0. Wins over `--yes` |
| `--trace DIR` | `PURVIEW_TRACE_DIR` | Record Graph and download exchanges as JSON (section 4.9) |
| `--wrap-untrusted` | `PURVIEW_WRAP_UNTRUSTED` | In JSON, wrap free text that tenant users or outside senders control as `[UNTRUSTED:<id>]…[/UNTRUSTED:<id>]`, with one random id per document and an `untrustedNotice` in the envelope. From v0.1 it covers every string under `displayName`, `description`, `externalId`, `contentQuery` and `fileName`, at any depth (`output::UNTRUSTED_KEYS`) |

`PURVIEW_CONFIG_DIR` is an environment variable only; there is no flag. `--color` is not
offered: `entra` keeps it only for compatibility, and `purview` has none to keep.

### 3.2 Command classes

| Class | Network | Changes |
|---|---|---|
| **local** | none, no sign-in | nothing outside the local filesystem |
| **auth** | the Microsoft identity platform only: the device-code, authorization (browser, through the system browser and a loopback listener) and token endpoints | local credentials and account metadata |
| **read** | Graph `GET`, download `GET`, and token-endpoint refreshes | nothing in the tenant; downloads write local files |
| **write** | Graph `GET` for preflight, token-endpoint refreshes, then exactly one Graph `POST` after approval | Purview state: see section 6.1 |

`--no-write` blocks the write class. It does not block auth commands, which change only
local state, as in `entra`.

### 3.3 Exit codes and JSON outcomes

`cli::execute_with` returns `Outcome { exit_code, stdout_value }`. A fatal error is an
`Err(PurviewError)`, and the top-level printer turns it into exit 1. Exit codes 3, 4 and 5
are not errors at that level, so nothing is appended to output already written.

Document-producing commands write one JSON document on stdout under `--json`. JSON Lines
(JSONL) commands (`parse items`, `export index`, `export read`) write one record per line and
nothing else on stdout, whatever the exit code; their summary and any reasons go to stderr.

| Code | Meaning | `--json` stdout for document-producing commands |
|---|---|---|
| 0 | Success, including a write applied or a `--dry-run` | `{"results": …, "count": …}`. For a write, `results` is `{"applied": true|false, "plan": {…}, "result": {…}|null}` and `count` is 1. `--results-only` prints that inner object |
| 1 | Failure, including argument errors, guard refusals and `WriteRefused` | `{"error": {"code", "status", "message"}}` |
| 3 | Write not applied: no `--yes` in a non-interactive run, or the user declined | `{"plan": {…}, "applied": false, "error": {"code": "ConfirmationRequired" or "Declined", "status": 0, "message"}}` |
| 4 | Finished but incomplete: operation `partiallySucceeded`, `failed` or `submissionFailed`, an unknown terminal status, `--strict` with failed locations or missing evidence, or items that failed to parse or join | The command's normal envelope, plus `"outcome": {"code": "Incomplete", "reasons": [ … ]}`. Each reason is `{"code", "message"}`; an operation gives `OperationPartiallySucceeded`, `OperationFailed`, `OperationSubmissionFailed` or `UnknownStatus`, with `resultInfo` in the message. The envelope is printed whole even under `--results-only` |
| 5 | Wait deadline reached | Operation waits: `{"caseId", "operationId", "status", "elapsedSeconds", "resume": [ … ], "error": {"code": "WaitTimeout", …}}`. Case-close waits: `{"caseId", "caseStatus", "elapsedSeconds", "resume": ["purview case get <case>"], "error": {"code": "WaitTimeout", …}}` |
| 130 | Interrupted (Ctrl-C) while waiting | As exit 5, with code `Interrupted` |

`resume` names the account the command ran as (`purview --account=<email> …`, attached so that a name beginning with `-` stays a value), so that it
resumes as the same identity whatever the default is then. It lists only commands that exist
in the running release: `purview operation get <case>
<op> --wait` from v0.1; `--check` added from v0.2; then `purview download <case> <op>`, which
skips files already downloaded and verified (section 4.7).

Human output for 3, 4, 5 and 130 goes to stderr, apart from tables already written to stdout.

### 3.4 Keys

- `<case>`: a case id (globally unique identifier, GUID) or an exact `displayName`. Names are
  not unique (Observed). Name matching covers every status, compares the whole name with
  case, and needs the case list to reach its last page. Several matches fail with
  `AmbiguousCase`, listing id, status and creation date but not the name; none fails with
  `CaseNotFound`. A name match prints `notice:` on stderr with the id it matched. An id is
  used as given, with no read of the case: a command that reads below the case gets Graph's
  answer to that read. `case get` reads a matched case again by its id, so a name and an id
  give the same record. Diagnostics never repeat the argument, a name or other tenant text.
- `<search>`: a search id or an exact display name within the case, with the same ambiguity
  rule (`AmbiguousSearch`, or `SearchNotFound`).
- `<op>`: an operation id, 32 hexadecimal characters with no hyphens (Observed).

### 3.5 Commands

#### `purview version` (local)

Prints `purview <version> <commit> <target>`.

#### `purview auth login` (auth)

Flags: `--client-id`, `--tenant-id` (env `PURVIEW_CLIENT_ID`, `PURVIEW_TENANT_ID`),
`--browser`, `--read-only`.

1. Sign in for Graph with the scopes in section 5.1. The default flow is device code;
   `--browser` uses the authorization code flow with Proof Key for Code Exchange (PKCE) on a
   loopback address.
2. Redeem the refresh token for the download token, to prove download consent.
3. Store both tokens in the operating-system credential store.

If step 2 fails with `AADSTS65001`, login still succeeds, with a warning naming the missing
grant. Download commands then fail with `DownloadNotConsented` until `auth refresh` succeeds.
`--no-input` refuses login before any network call.

JSON: `{"account", "upn", "tenantId", "clientId", "graphScope", "downloadReady"}`.

#### `purview auth refresh` (auth)

Redeems the stored refresh token for both resources, with the scopes already stored. It
never narrows or widens scopes; sign in again with `auth login` (with or without
`--read-only`) to change them, as `entra` requires for narrowing. A Graph response whose
permissions differ from the stored set is refused and nothing is stored (section 4.5); the
error names neither set. It
succeeds only if both redemptions and every credential-store write succeed. Each result is
stored before the next step: if the download redemption fails with `AADSTS65001`, the Graph
rotation stays stored, the refused download entry is removed from the store, and the
command exits 1 with `DownloadNotConsented`. Only `auth login` treats that refusal as a
warning.

JSON: `{"account", "graphExpiresAt", "downloadExpiresAt", "graphScope"}`.

#### `purview auth status` (read)

Calls `GET /security/cases/ediscoveryCases?$top=1` to prove the Graph token and the Purview
role. It reads the download token's expiry from local metadata and never sends that token.

Output: account, tenant, scopes, both expiries, `purviewRole: ok | denied | unknown`. A 403
means `denied`; any other failure of the read means `unknown`; each exits 0. A Graph token
that cannot be had (the identity platform refuses the refresh, or the refreshed credential
cannot be stored) is an error, exit 1, so that a check of the exit code alone sees a broken
sign-in. That a missing role gives 403 is an Assumption, checked in PR 1.4.

#### `purview auth list`, `purview auth logout [--account]` (local)

As in `entra`.

#### `purview kql [query flags]` (local)

Builds the Keyword Query Language (KQL) string, parses it with the guard's parser (section
6.3), and prints the string, the per-leaf classification and the verdict. Exit 0 if the
query is narrowed, exit 1 with `GenericQuery` or `KqlNotUnderstood` otherwise. `kql` takes no
override flag: it reports what the guard would decide.

Output (settled in PR 1.6). The table has the columns `COLUMN`, `FIELD`, `VALUE`, `NEGATED`,
`CLASS` and `RULE`, between a `kql:` line and a `verdict:` line; `--plain` prints the rows
only. JSON `results` is `{"kql", "narrowed", "unnarrowedAt"?, "leaves": [{"column", "field",
"value", "quoted", "negated", "class", "rule", "reason", "tokens"?}]}`. A query that is not
narrowed prints the same report, then fails: in a table the report is on stdout and
`Error: …` on stderr; under `--json` one document holds `{"analysis": …, "error": …}`,
whatever `--results-only` says, as exit 3 does for a plan. The error names the column of a
branch that is not narrowed. `KqlNotUnderstood` has no report. `kql` reads `config.json`
for `guard` only after the query flags are checked, and never signs in.

Query flags (shared with `search create`):

| Flag | KQL |
|---|---|
| `--term T` (repeatable) | each quoted, all ORed. A `"`, a `*`, a web address (`http://` or `https://`), or a control or invisible character inside a term is refused |
| `--participant ADDR` (repeatable) | `participants:ADDR`, all ORed. Each must be a full address (section 6.3) |
| `--since YYYY-MM-DD` | `sent>=YYYY-MM-DD` |
| `--until YYYY-MM-DD` | `sent<=YYYY-MM-DD` |
| `--kind email\|teams` | `kind:email` or `kind:microsoftteams` |
| `--exclude-from ADDR` (repeatable) | `NOT from:ADDR`, each ANDed |
| `--kql RAW` | raw query; conflicts with every flag above |

The builder's local verdict runs before sign-in. A query that arrives from the service (an
existing search) can only be checked after it is fetched (section 6.4).

The groups are ANDed, in the order of the table:

```text
("orders-api" OR "orders_export_bucket") AND (participants:alex@contoso.example OR participants:sam@contoso.example) AND sent>=2025-01-01 AND NOT from:noreply@notify.example
```

The forms `participants:`, `from:`, `NOT from:`, `sent>=`, `sent<=`, `kind:email`,
`kind:microsoftteams`, quoted phrases and nested parentheses were accepted at search creation
(Observed). The other forms in the grammar of section 6.3 (`to:`, `cc:`, `bcc:`, `subject:`)
are standard KQL (Docs) and have not been observed.

#### `purview case list` (read)

Flags: `--status active|closing|closed|all` (default `all`), `--name SUBSTR`,
`--created-before DATE`, `--created-after DATE`, `--mine`.

- `--name` is a case-insensitive substring match, applied on the client.
- `--created-before` and `--created-after` are inclusive and compare UTC dates.
- `--mine` keeps cases whose `createdBy.user.id` equals the stored `oid`, or, when the id is
  absent, whose `createdBy.user.userPrincipalName` equals the stored `upn`,
  case-insensitively.

- A case without `createdDateTime` is left out when either date flag is given.
- When the sign-in recorded no `upn` (the observed id token had none), `--mine` compares
  `createdBy.user.userPrincipalName` with the account key.
- The observed tenant's case records carried no `createdBy` at all, in the list or a single
  `GET` (Observed, PR 1.4), so `--mine` matched nothing there; when no case read has
  `createdBy`, the command says so on stderr. Section 3.5's `case close` check on
  `createdBy` meets the same gap, and PR 2.6 has to settle it.

Columns: `ID`, `NAME`, `STATUS`, `CREATED`, `AGE (DAYS)`, `CREATED BY`. Rows with a missing
id or name are shown with `?` and counted in a stderr warning; they are not dropped. `AGE
(DAYS)` is whole days since `createdDateTime`; `CREATED BY` is the creator's user principal
name, else their display name. JSON `results` is the list of Graph's records as they came.
A list that stops before its last page (a repeated paging link, or 200 pages) is shown with
a warning.

#### `purview case get <case>` (read)

The full case, with the original JSON preserved in `--json`.

#### `purview case create --topic TEXT` (write: create)

Flags: `--name OVERRIDE`, `--requester TEXT`, `--description OVERRIDE`, `--reuse-existing`.

Preflight (read):
1. Render `naming.case_name` and `naming.case_description` (section 5.5).
2. List all cases and find exact `displayName` matches in any status.

Then:
- **No match:** plan, approval, `POST /security/cases/ediscoveryCases`. Expect 201 and
  `status: active` (Observed).
- **One active match and `--reuse-existing`:** print it, exit 0, no write.
- **Any other match:** refuse with `CaseNameInUse`, listing id and status of each match. Two
  cases with one name, even if one is closed, would make every later name lookup ambiguous.

Settled in PR 2.2:
- The flags are trimmed; blank text, or a control or invisible character anywhere in the
  value as given, is an argument error. `naming.marker` must not be blank. The templates are rendered before the first request, so a template that uses a
  variable with no value (`{query_summary}` in `case_name`) fails before any request.
- `naming.marker` is added to the description, `--description` included, when it does not
  hold it already, so that `case close` can rely on it (section 3.5, `case close`, step 2).
- The `CaseNameInUse` message lists id, status and creation date, never the name. With one
  active match and no `--reuse-existing`, it names that flag. An entry whose name cannot be
  read (not an object, or a `displayName` that is missing or not a string) refuses the
  check, because it cannot be shown that the name is free; a `displayName` of `null` is no
  name.
- `--reuse-existing` with its one active match prints `{"applied": false, "plan": null,
  "result": <the case as Graph listed it>, "reused": true}` in the exit-0 envelope, or a
  `Reused: case <id> …` line and the record as indented JSON (as an applied write prints its
  result), and sends nothing, `--dry-run` included.
- After the 201, a status other than 201, a case status other than `active`, or a missing
  case id is a warning on stderr. `result` is Graph's record as it came.

#### `purview case close <case>` (write: state)

Flags: `--any-case`, `--wait`, `--wait-timeout DUR` (default 15 minutes), `--poll-interval
DUR`. This command ships only after PR 2.6's observation (section 11).

Preflight (read). Every step must succeed; a denied, malformed, unreadable or partly paged
response refuses with `ClosePrecheckFailed`:
1. The case is `active`.
2. Unless `--any-case`, the description carries `naming.marker`, or `createdBy` is the
   signed-in account.
3. `GET …/custodians`, `GET …/noncustodialDataSources` and `GET …/legalHolds` (Docs) each
   return an empty `value` with no `@odata.nextLink`. Any entry refuses with `CaseHasHolds`,
   listing the counts. The check depends only on whether `value` is empty, not on the shape
   of an entry.

Approval needs the case display name typed in an interactive terminal, or `--yes`. Then
`POST …/{caseId}/close`. `--wait` polls `GET` on the case until `closed`. At the deadline, or
on Ctrl-C, the command returns the case-close shape in section 3.3, with the last case status
read. If the POST outcome is unclear, the same `GET` on the case is the reconciliation: the
command reports the status it finds and exits 1 with `WriteOutcomeUnknown`. In the observed tenant some cases were in `closing` status at the time of the
snapshot (Observed); whether they were stuck there is not known.

#### `purview search list <case>`, `purview search get <case> <search>` (read)

Columns: `ID`, `NAME`, `SCOPE`, `CREATED`, `QUERY` (cut to 80 characters in the table; full
in JSON).

`search get` also reads the search's `custodianSources`, `noncustodialSources` and
`additionalSources`, at once, because an action on the search would also collect from them
(section 6.4). JSON puts each list read in full on Graph's record under that name, replacing
any list Graph sent inline (it sends `additionalSources` inline, Observed). A source list
that cannot be read, or that stops before its last page, is a warning, shown as `unknown`
or "N or more", and is removed from the JSON, inline value included; a token
that cannot be had fails the command before any warning. `search get <case> <name>` reads
the matched search again by its id.

In tables and record views, tenant text has registered secrets removed and URLs redacted as
in free text before it is sanitised or cut. In JSON, a string that is one URL (a
`downloadUrl`) keeps only its OData options, and a URL in other text keeps only scheme, host
and path, as in the trace (section 4.9). `--select` is checked against a list command's
columns before sign-in.

#### `purview search create <case> --name NAME [query flags]` (write: create)

Further flags: `--description TEXT`, `--allow-generic --reason TEXT`.

1. Build the KQL and run the guard (section 6.3).
2. Preflight: list the case's searches and refuse `SearchNameInUse` on an exact name match.
3. Render `naming.search_description`. With an override, it records the reason.
4. Plan, approval, `POST …/searches` with `dataSourceScopes: "allTenantMailboxes"`, which
   the type system enforces (section 7.5).
5. Compare the echoed `contentQuery` with what was sent. It was echoed unchanged (Observed);
   a difference is a warning.

Settled in PR 2.2:
- The KQL is built, and its arguments checked, before `--no-write`; the guard runs after
  `--no-write` and before sign-in, with `guard` from `config.json`.
- Preflight reads the case (`GET` on it, after the name match for a `<case>` name), refuses
  an answer whose id is not the case read, and refuses a case that is not `active` with
  `CaseNotActive`, then lists its searches. `SearchNameInUse` lists ids and creation dates,
  never the name; an entry whose name cannot be read refuses as for `case create`.
- `{query_summary}` turns a line break or tab between the query's tokens into a space; the
  query sent is the one the guard checked, unchanged.
- The description is `--description`, or `naming.search_description`; with
  `--allow-generic`, `Guard overridden with --allow-generic: <reason>` follows it; then
  `naming.marker` is added when it is not there already. The plan carries a warning for an
  override.
- A difference in the echoed `contentQuery` or `dataSourceScopes`, a status other than 201,
  or a missing search id is a warning on stderr; it never repeats the query.
  `result` is Graph's record as it came.

#### Actions on a search

`estimate`, `report` and `export create` take `<case> <search>`. Before planning, each runs
the action preflight in section 6.4. That preflight fetches the search, checks its scope and
sources, and puts its current KQL through the guard, with the same `--allow-generic --reason`
override as `search create`. A search the tool did not create gets exactly the same checks.

Wait flags. One Clap `TimingArgs` struct holds `--wait-timeout DUR` and `--poll-interval DUR`
(fixed interval, at least 5 s; the default is the schedule in section 4.6). Commands combine
it with one of two switches:
- actions wait by default and take `--no-wait`; their default deadline is `2h`;
- `operation get` and `case close` do not wait by default and take `--wait`; their default
  deadlines are `2h` and 15 minutes.

Also on every action: `--allow-concurrent` (section 6.7) and `--out DIR`.

**Collection check.** Each action has one check of whether every location was searched:

| Action | Evidence | Source |
|---|---|---|
| `estimate` | `Locations-*.csv` rows with `Status=Failed`, plus `Statistics-*.csv` rows with `StatType=Error` | the estimate's report zip |
| `report` | `Locations-*.csv` rows with `Status=Failed` (an item report has no `Statistics-*.csv`, Observed) | the report zip |
| `export create` | the same, from the `Reports-…zip` part of the package | the report part |

`collection` is `complete`, `incomplete` (at least one failure) or `unchecked` (evidence not
read, or the expected CSV missing from the zip). `--strict` conflicts in Clap with
`--no-download` and `--no-wait`. Under `--strict`, `incomplete` and `unchecked` both give
exit 4, with reason `FailedLocations` or `EvidenceMissing`.

#### `purview estimate <case> <search>` (write: action)

Further flags: `--no-download`, `--strict`.

1. `POST …/searches/{id}/estimateStatistics` with `{"statisticsOptions":"includeQueryStats"}`.
   Returns 202 and a `Location` header (Observed).
2. Poll (section 4.6). The last poll is a single GET of the operation, which carries the
   typed object with counts and files (Observed); there is no extra GET.
3. Unless `--no-download`, download the report zip and parse `Locations-*.csv` and
   `Statistics-*.csv` (section 4.8).

Output:
- `operationStatus`;
- `collection: complete | incomplete | unchecked`. `incomplete` means at least one location
  failed. `unchecked` means the zip was not read (`--no-download`);
- `indexedItemCount`, `indexedItemsSize`, `unindexedItemCount`;
- `mailboxCount`, labelled "locations with hits" (Observed meaning);
- `locationsSearched`, from `LocationCount` in `Summary-*.csv`;
- the 10 locations with most hits, and `failedLocations`;
- the path of every file written.

An operation can report `succeeded` while some locations failed (Observed). The command
warns about this on stderr, and `--strict` turns it into exit 4 (see the collection check
above).

Settled in PR 2.3:
- Further flags: `--allow-generic --reason`, `--allow-concurrent`, `--no-wait`,
  `--wait-timeout`, `--poll-interval` and `--out`. `--strict` and `--out` conflict with
  `--no-download` and `--no-wait`; the timing flags conflict with `--no-wait`.
- A plan whose concurrency check (section 6.7) found an estimate not yet finished is
  `blocked`: a dry run prints it with a warning per operation, and any other run fails with
  `ConcurrentOperation` before anyone is asked, unless `--allow-concurrent` is given.
- `result` is `{"operationId", "operationStatus", "collection", "indexedItemCount",
  "indexedItemsSize", "unindexedItemCount", "mailboxCount", "locationsSearched",
  "topLocations", "failedLocations", "files"}`: the 10 locations with most hits (at least
  one), each failed location with `sources` (`locations`, `statistics` or both), and each
  file with its path, size, SHA-256 and download status. `--no-wait` gives `operationId`,
  `collection: unchecked` and `resume`, the commands that carry on.
- A finished estimate that did not succeed, a file that cannot be downloaded, or `--strict`
  with `FailedLocations` or `EvidenceMissing`, exits 4 with the write envelope and an
  `outcome`, whole even under `--results-only`. The wait deadline and Ctrl-C, during the
  wait or the download, give the operation-wait shapes of section 3.3.
- The reason of `--allow-generic` is in the plan's warnings only; the download manifest
  does not record it yet.
- After approval and before the send, `WriteCommand::recheck` reads the search again
  through the same checks. A scope, sources or query that no longer pass refuse with the
  check's own code; a query or verdict that pass but differ from the plan refuse with
  `SearchChanged`. A change after that read is not caught: Graph offers no conditional
  action (Assumption).
- The answer must be 202, and the operation the `Location` header names must be an
  `estimateStatistics` operation with estimate detail before any file is fetched; anything
  else is `UnexpectedLocation`.
- The concurrency check and the source lists use `GraphClient::list_bound`, which refuses a
  paging link to another path. An operation entry whose action or status cannot be read
  counts as a possible duplicate.
- `--wait-timeout` covers the wait. The download has its own timeouts (section 4.7); Ctrl-C
  during it gives exit 130 with the time since the POST, as `operation get --check` does.
- Exit-4 reasons are redacted as the rest of the document, after they are added.
- Without `--allow-concurrent`, the recheck also lists the case's operations again. An
  error in the recheck keeps its own code, with context saying nothing was sent.
- `operation get --check` stopped by Ctrl-C resumes with `operation get <case> <op>
  --check` alone, never with `download`, which would fetch an export's item content.
- A downloaded zip's declared entry count is checked against 1,000,000 (the export cap)
  before the zip crate indexes it; a report is held to `limits.report_zip_entries` when it
  is read.

#### `purview report <case> <search>` (write: action)

Further flags: `--name NAME`, `--no-teams-context`, `--no-download`, `--strict`, `--profile`.

Posts `exportReport` with `exportCriteria: searchHits`, `exportLocation: responsiveLocations`,
`additionalOptions: teamsAndYammerConversations` and `displayName` from `naming.export_name`
(the body used in the observed runs; Observed). With `--no-teams-context`, or
`defaults.teams_context: false`, `additionalOptions` is left out. That body has not been
observed: the flag is marked experimental in help until PR 2.5 observes it.

After polling, it downloads the zip (whose `size` is real; Observed) and reports
`collection` by the report check above. With `--profile` it runs `parse profile` on the zip.
The plan carries the row-count warning in section 6.6.

#### `purview export create <case> <search>` (write: action; phase 4)

Further flags: `--name`, `--no-teams-context`, `--no-download`, `--strict`.

Body: `exportCriteria: searchHits`, `exportLocation: responsiveLocations`,
`exportFormat: msg`, `additionalOptions: teamsAndYammerConversations,includeReport`
(Observed). `--no-teams-context` sends `additionalOptions: includeReport`, which has not been
observed; PR 4.1 observes it before the flag leaves experimental status. Only `msg` is
offered. There is no `--no-report`: the report part of the package carries the metadata that
`export index` and `export read` join on.

`exportFileMetadata` lists two files (Observed):
1. `Reports-<case>-<search>-StartDirectExport-<export name>-<timestamp>.zip`: the item
   report layout (`Items_0_*.csv`, `Locations`, `Settings`, `Summary`), on the order of a
   megabyte.
2. `Items.1.001.<export name>.zip`: the items, on the order of gigabytes for a few thousand
   items. The `1.001` suggests numbered parts for larger exports (Derived). The tool
   downloads every `Items.*.zip` listed.

`collection` comes from the report part, by the export check above.

In the observed run, posting the export and downloading both files took about ten minutes
(Observed). The plan warns about two things. The estimate undercounts: with Teams context on,
the export held roughly four times the estimated count (Observed, one run). And the download
is large: on the order of a few hundred kilobytes per item (Derived from one run).

#### `purview operation list <case>` (read)

Flags: `--action estimate|report|export|any`, `--status S`, `--resolve`.

The list response has base fields only, and it shows an `exportReport` operation with
`action: exportResult` (Observed). So without `--resolve`:
- the `ACTION` column shows `exportResult?` for any entry whose action reads `exportResult`,
  with a footer explaining why;
- `--action report` and `--action export` are refused with `ResolveRequired`, because the
  list cannot tell them apart.

`--resolve` fetches each operation individually, at most 4 at a time, and reports the true
action, the counts and the files. Only entries that could pass `--action` and `--status` on
their list record are fetched, and both filters apply again to the fetched record. JSON
marks `actionSource: "list" | "get"` on each record. Any failed fetch fails the command.

`--status` takes `notStarted`, `running`, `succeeded`, `partiallySucceeded`, `failed` or
`submissionFailed`, ignoring case. Columns: `ID`, `ACTION`, `STATUS`, `CREATED`, `COMPLETED`,
`CREATED BY`, `ITEMS` (an estimate's `indexedItemCount`) and `FILES`; the last two are filled
only for fetched records. The `exportResult?` footer goes to stderr, so `--plain` output
stays rows only.

#### `purview operation get <case> <op>` (read)

Flags: `--wait`, timing flags, `--check` (from v0.2).

Shows the full typed operation: file names, sizes (an estimate's `size: 0` is shown as
"unknown", Observed), `resultInfo` where present (Docs; the prototype read it), and
`downloadUrl` in JSON only. Output includes `collection: unchecked` unless `--check` is
given. `--check` downloads the evidence file into the data directory and applies the
collection check for the operation's action, taken from the single GET: the estimate's
report zip, the report zip, or the report part of an export. A later `download` reuses that
verified file instead of fetching it again. The 30-second not-found grace in section 4.6 does
not apply here: a wrong id fails at once.

`collection` is added for an estimate, item report or export only. A finished operation whose
status is not `succeeded` exits 4, with or without `--wait`. `--wait-timeout` takes whole
seconds or a duration such as `90s`, `15m`, `2h` or `1h30m`, from 1 second to 24 hours;
`--wait-timeout` and `--poll-interval` need `--wait`.

Settled in PR 2.3: `--check` downloads every file of an estimate or item report through the
same code as `download`, into the data directory, and reads the first that is a report zip;
for an export it downloads only the file whose name starts with `Reports-` (Assumption).
An operation that is not finished is `unchecked`, with a notice. `--check` changes no exit
code by itself.

#### `purview download <case> <op>` (read)

Flags: `--out DIR`, `--file NAME`, `--overwrite`.

Fetches the operation again for current `downloadUrl` values, then downloads each file
(section 4.7) and prints every path written. A file already in the manifest, present, and
matching its recorded size and SHA-256 is reported as already downloaded and not fetched
again, unless `--overwrite` is given. A URL cannot be passed on the command line.

- An operation that has not finished (`notStarted`, `running`) is refused, naming
  `operation get --wait`; nothing is downloaded.
- `--out DIR` is the directory the files go to, as given. Without it they go to
  `cases/<case-id>/<operation-id>/` below the data root (section 5.4). `--file NAME` keeps
  the one file whose server `fileName` is exactly `NAME`; no match is an error that does not
  repeat the name.
- Every file is planned before any download request: its local name (section 4.7.1, made
  across all the operation's files, so `--file` gives the same name a full download does),
  and whether its target is absent, a verified download (skipped), a file that no manifest
  entry reaches and that verifies (recorded as `recovered`), or anything else
  (`TargetExists` without `--overwrite`). An entry reaches a file under its own name or
  under another name for the same file (`Report.zip` and `report.zip` on a case-insensitive
  file system), so another operation's file is never recovered as this one's. A link at a
  target, and a link at any directory of the managed path below the data root, is refused
  even with `--overwrite`. A known size over `download.max_size` is refused too. Any refusal
  ends the command before a download request or a download-token refresh.
- A command holds an exclusive lock on the directory (`.purview-download.lock`) from
  reading the manifest to its last write, so two commands writing into one directory never
  lose each other's entries. A command waits up to 30 seconds for the lock, then fails.
- A file with no `fileName`, a `fileName` that holds a web address or a secret the
  Redactor knows, no `downloadUrl`, one that does not parse, one the host rule refuses, or a
  `fileName` whose local name cannot be made unique, is left out with
  a `FileNotDownloadable` reason, and the other files are still downloaded. Such a reason,
  or an operation that finished without succeeding (its exit-4 reason as in `operation
  get`), makes the command exit 4 after the other files are written; the envelope is
  printed whole even under `--results-only`.
- Files are fetched one at a time. A failure while fetching ends the command with exit 1;
  files already published stay recorded, and the next run skips them. A download is not
  retried automatically.
- Under `--overwrite`, the replacement is fetched and checked first. The manifest is then
  written ahead of the rename: it names the replacement, with its size and SHA-256, and
  drops every entry that reaches the target (under its name or another for the same file).
  If that write fails, nothing is replaced. If the rename fails after it, the entry's hash
  does not match the file left in place, so no later run takes that file for this
  operation's. Without `--overwrite`, the file is published first and recorded after.
- Ctrl-C ends the run with exit 130: the file in flight is abandoned and its temporary
  file removed, and the files already published are printed, with `"error": {"code":
  "Interrupted", …}` beside `results` under `--json`.
- JSON `results` has one object per file: `fileName` (the server name), `path`, `size`,
  `sha256` and `status` (`downloaded`, `alreadyDownloaded` or `recovered`). The table has
  `STATUS`, `SIZE` and `PATH`.

#### `purview parse <subcommand> <zip>` (local)

No sign-in. The kind of zip is detected from its entry names: `Statistics-*.csv` means an
estimate, `Items_N_*.csv` without an `Items.*.zip` sibling means an item report.

- `parse locations <zip> [--top N] [--with-hits] [--subtype primary|archive|system]`: sorted
  by `Count` descending, ties broken by `Location` ascending, then `LocationSubType`.
- `parse failures <zip>`
- `parse summary <zip>`
- `parse items <zip> [filters] [--jsonl | --json [--force-buffer]] [--all-rows]
  [--max-unique N]`. The default is `--jsonl`: one line per unique item, written after the
  pass. `--all-rows` streams one line per row instead. `--json` buffers one document and is
  refused above 10,000 records unless `--force-buffer` is given. Each unique-item record has
  `key`, `keyKind`, `class`, `date`, `sender`, `senderDomain`, `recipientCount`, `title`,
  `conversationType`, `workload`, `copies`, `locations`, `hasAttachment`, `immutableId` and
  `internetMessageId`.
- `parse profile <zip> [filters] [--top N] [--bucket day|week|month] [--merge-local-part]`

Filters: `--since`, `--until` (on `Date`, both inclusive, UTC), `--subject-regex RE` (on
`Subject/Title` or `Conversation name`), `--class PREFIX`, `--sender ADDR`,
`--exclude-sender ADDR`, `--workload W`.

#### `purview export index <items.zip>... [--report <Reports-…zip | Items_0_*.csv>]` (local; phase 4)

Joins items zips to the report CSV through `Target path` (section 4.8), without parsing any
message. One JSONL record per entry: entry name, part, compressed and uncompressed size,
`joined`, and the CSV fields of section 7.6.
- Without `--report` it lists entries only. Records carry `joined: null`, and the command
  exits 0 when every entry was listed.
- With `--report`, it exits 4 if any entry or row stays unjoined, or a part is missing.

Output is JSONL by default; `--json [--force-buffer]` as for `parse items`.

#### `purview export read <items.zip>... --report <…>` (local; phase 5)

Reads headers and body text from each `.msg` and writes one JSONL record per item to stdout
(section 4.11). Flags:

| Flag | Meaning |
|---|---|
| `--body text\|html\|none` | default `text` |
| `--max-body-chars N` | default 200,000; longer bodies are cut and `bodyTruncated` set |
| `--cut-quoted` | cut at the first quoted-reply marker |
| `--thread-dedup` | drop repeats of (conversation, date, sender), applied after reordering |
| `--headers` | include transport headers when present |
| `--max-entry-bytes N` | default 64 MiB per `.msg` |
| `--jobs N` | parse threads, default 4 |
| `--verbose-fields` | keep `.msg` values that differ from the CSV, under `msg.*` |
| `--entry NAME`, `--immutable-id ID` (repeatable) | read only these items |
| `--jsonl` (default), `--json [--force-buffer]` | as for `parse items`: `--json` is refused above 10,000 items unless `--force-buffer` |
| filters | as for `parse items` |

At the end it writes a summary to stderr: items read, joined, unjoined and failed, each
broken down by item class. Exit 4 if any item failed to parse or join; those items still get
a record with `error` set.
The command refuses to run when stdout is a terminal, unless `--to-terminal` is given:
bodies are colleagues' and outsiders' mail. Section 9 explains where the output should go.

#### `purview inventory cases` (read; phase 6)

Flags: `--older-than DUR`, `--status S`, `--holds-only`, `--concurrency N` (default 4,
maximum 8), `--csv FILE`.

For each case: age, status, counts of custodians, non-custodial sources and legal holds, how
many holds are enabled, and the date of the last operation. Cases are not closed, and
nothing is recommended. A case whose reads fail is listed with its error, and the run exits
with 4.

#### `purview inventory holds <case>` (read; phase 6)

Each hold policy: status, whether it is enabled, created date, `contentQuery`, and counts of
user and site sources (Docs).

---

## 4. Architecture

### 4.1 Crate layout

```text
src/
  main.rs        tokio entry; calls cli::execute
  lib.rs
  cli.rs         Clap tree; execute() and #[doc(hidden)] execute_with(Env) -> Outcome
  env.rs         Env: endpoints, credential store, clock, stdin/stdout/stderr, terminal detection
  auth.rs        device code and PKCE login, refresh, id-token account claims
  token.rs       TokenProvider: lazy refresh for both resources, SecretString newtypes
  secrets.rs     CredentialStore trait and KeyringStore (from entra: Windows chunking and lock, macOS label)
  config.rs      config.json, data directory, atomic writes, 0600 and 0700 modes
  error.rs       PurviewError, typed predicates, metadata() for JSON codes
  origin.rs      Origin type, exact-origin checks, URL redaction for output
  graph.rs       GraphClient: the only Graph transport; GET, paging, send_write(ApprovedWrite)
  routes.rs      ReadRoute and WriteRoute enums: every method and path the tool may use
  poll.rs        operation polling state machine with a deadline
  commands/      bodies of the read commands (case.rs, search.rs, operation.rs) and key
                 resolution (mod.rs); cli.rs checks arguments, signs in and dispatches
  download.rs    DownloadClient: origin binding, streaming, temporary files, publishing, manifest
  trace.rs       TraceSink: redacted JSON exchange recording
  redact.rs      Redactor applied to every output sink
  model/
    wire.rs      tolerant records as Graph sends them, with the raw JSON kept
    valid.rs     validated inputs for commands (CaseRef, SearchForAction, DownloadableFile)
    requests.rs  request bodies
  kql/
    lexer.rs     tokens
    parser.rs    recursive-descent parser to a syntax tree (abstract syntax tree, AST)
    classify.rs  term and address classification
    guard.rs     narrowing verdict
    build.rs     builder used by the query flags
  naming.rs      template rendering
  safety.rs      WritePlan, approval, ApprovedWrite
  zipread.rs     zip opening, entry discovery, counting readers, limits
  report/
    csvread.rs   byte-order-mark handling, per-record byte budget, header index
    estimate.rs  Locations, Statistics
    summary.rs   header-less Summary and Settings parser
    items.rs     streaming Items_N reader, dedup aggregation, filters, JSONL
    profile.rs   counts, top-N lists, histograms, sender normalisation
  export/
    join.rs      Target path normalisation and join (phase 4)
    index.rs     export index (phase 4)
    read.rs      export read: parse pool, reorder buffer, records (phase 5)
  msg/           phase 5
    cfbread.rs   compound file container access through the cfb crate
    props.rs     MAPI property streams and the fixed-size property table
    body.rs      HTML and text body selection, cleaning, quote cutting
  output.rs      table, plain, JSON envelope, sanitise, wrap-untrusted (from entra)
contrib/
  create-purview-app.sh   app registration; dry run by default, --apply to change (section 5.2)
  install.sh, resign.sh   from entra, identifier com.aberoham.purview
  msg-bodies.py           phase 5 fallback reader, uv script with extract-msg pinned
tests/
  cli.rs         assert_cmd: offline process contracts only
  flows.rs       in-process flows through cli::execute_with against wiremock origins
  support/       origins, replay loader, zip and .msg generators, canary scanner
  fixtures/      section 8.3
```

### 4.2 Differences from `entra`

| Area | `entra` | `purview` |
|---|---|---|
| Write path | none; `--no-write` is nominal | six Purview writes, each through a plan and approval checked at the transport (section 6.2) |
| Resources | Graph | Graph plus the Purview eDiscovery app, from one refresh token |
| Token use | the client holds an access token string | `TokenProvider`, refreshed lazily during long waits (section 4.5) |
| Account identity | `/me` (`User.Read`) | id-token claims; no `User.Read` grant, which the observed consent did not include |
| Account selection | `--account` is strict; some commands with an *implicit* account fall back to other stored accounts after a typed refusal | always one identity, explicit or default, with no fallback, because case visibility and the audit trail depend on it. `--account` matches the stored key or `upn`, without alias resolution |
| Redirects | disabled | disabled for Graph; only same-origin redirects on download (section 4.7) |
| Response bound | 8 MiB | 8 MiB for Graph JSON; downloads streamed under their own limits |
| POST retry | not applicable | never automatic (section 4.3) |
| Exit codes | 0, 1 | 0, 1, 3, 4, 5, 130 with per-code JSON shapes |
| Test harness | `with_base_url` on the client | `Env` injected into `execute_with`, for in-process flows |
| tokio features | `full` | `rt-multi-thread, macros, time, net, io-util, fs, signal, sync` |

### 4.3 Graph transport (`graph.rs`, `routes.rs`, `origin.rs`)

**Origins.** `Origin` is scheme, host and effective port. The Graph origin is
`https://graph.microsoft.com:443`, set in `Env`. `GraphClient` sends a request only when the
URL's origin equals the Graph origin exactly and its path lies below the base path `/v1.0/`.
That covers paging links and polling URLs as well as constructed routes. Redirects are disabled. User-controlled path segments are encoded
one at a time through `url::Url`.

**Routes.** Requests come only from `ReadRoute` and `WriteRoute`.

`WriteRoute`, with every POST the tool can send:

| Variant | Method and path |
|---|---|
| `CreateCase` | `POST /security/cases/ediscoveryCases` |
| `CloseCase(case)` | `POST /security/cases/ediscoveryCases/{case}/close` |
| `CreateSearch(case)` | `POST …/{case}/searches` |
| `EstimateStatistics(case, search)` | `POST …/{case}/searches/{search}/estimateStatistics` |
| `ExportReport(case, search)` | `POST …/{case}/searches/{search}/exportReport` |
| `ExportResult(case, search)` | `POST …/{case}/searches/{search}/exportResult` |

`ReadRoute`: list and get cases, searches and operations; the search's `custodianSources`,
`noncustodialSources` and `additionalSources` (Docs, section 6.4); and the case's
`custodians`, `noncustodialDataSources`, `legalHolds`, `legalHolds/{id}/userSources` and
`legalHolds/{id}/siteSources` (Docs). Every read route is `GET`.

`GraphClient` has two request methods: `get(ReadRoute)` (from PR 1.3) and
`send_write(ApprovedWrite)` (from PR 2.1, together with its argument type). A unit test
asserts that `WriteRoute::ALL` equals the table above. No `PATCH`, `PUT` or
`DELETE` exists anywhere in the crate; a test scans the source tree for those method names.
Adding a write needs a reviewed design, a change to that test and an update to
`docs/safety.md`.

**Retries.**

- **GET:** at most 3 attempts. Retries happen on connection errors, timeouts, a truncated
  body, 429, 500, 502, 503 and 504. `Retry-After` is honoured in seconds or HTTP-date form,
  up to 60 s; a longer one ends the GET with Graph's error rather than wait. Otherwise the wait is 250 ms × 2^(attempt−1), capped at 30 s. A 401 makes the token
  provider refresh once, then the GET is retried once, within the same three attempts.
- **POST: never retried automatically**, whatever the status or error. Only a 4xx other than
  408 and 429 is a clean refusal. A connection that could not be opened sent nothing and is
  `GraphUnreachable`. Every other answer is `WriteOutcomeUnknown`: none, a timeout, 408, 429,
  a 5xx, a redirect (never followed), and a 2xx whose body cannot be read, is not a JSON
  object, or is empty for a create, which Graph answers with the created object (Docs). A `Retry-After` header
  says when to try again; it does not prove the first request had no effect. If the outcome
  is unclear (timeout, reset, 5xx, 429), the command runs the reconciliation in section 6.7
  and exits 1 with `WriteOutcomeUnknown`. A 401 on a POST is reported and not retried. Before
  a POST, the provider refreshes the Graph token if fewer than 5 minutes remain, so a 401
  should not happen.
- No 429 has been observed (Observed). The retry path is tested with mocks only.

**Paging.** The tool follows `@odata.nextLink` only on the Graph origin. It stops on a
repeated link and after 200 pages. Paging has not been observed on cases or operations; it
is handled anyway. A list read by `case close` preflight or `inventory` must reach its final
page, or the command fails.

**Envelope.** `Page { value: Vec<serde_json::Value>, next_link: Option<String> }`. Each
element is parsed into a wire record separately, so one bad element cannot fail the list
(section 7.1).

### 4.4 Identifiers and the `Location` header

- `CaseId(Uuid)`, `SearchId(Uuid)`, `OperationId(String)` (validated as 32 hexadecimal
  characters).
- Every action returns 202 with a `Location` header naming the operation (Observed). Its
  form in the trace was
  `https://graph.microsoft.com/v1.0/security/cases/ediscoverycases('<case>')/operations('<op>')`
  (Observed (trace)). The parser accepts both that key form and the path form
  `…/ediscoveryCases/<case>/operations/<op>`, case-insensitively. It requires the Graph
  origin, the case id the tool posted to, and a valid operation id. Polling then uses the
  canonical route built from those ids. Anything else is `UnexpectedLocation` and stops the
  command. In that case the operation may still be running, so the error message shows the
  reconciliation command. There is no fallback to the raw URL. The header exists only on the
  original 202 response, so PR 2.3, the first PR that posts an action, checks the form live.

### 4.5 Tokens at runtime (`token.rs`)

```rust
pub struct SecretString(Box<str>); // Debug prints "[redacted]"; no Display; no Serialize except into the credential store

pub struct GraphToken(SecretString);
pub struct DownloadToken(SecretString);

#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn graph(&self, min_validity: Duration) -> Result<GraphToken>;
    async fn download(&self, min_validity: Duration) -> Result<DownloadToken>;
    async fn invalidate_graph(&self);
}
```

- `GraphClient` and `DownloadClient` hold an `Arc<dyn TokenProvider>`, never a token string.
- Before each request, `graph` refreshes when fewer than 60 s remain; before a POST, when
  fewer than 5 minutes remain. Refresh rotates the refresh token and stores the newest one.
  A refresh is written to the credential store before its tokens are used. If the store
  refuses the write, the refresh is that command's error, and the rotated refresh token is
  never used; the provider keeps the credential the store still holds.
- The Graph refresh request is built from the stored scope list: short Graph permission
  names get the `https://graph.microsoft.com/` prefix, repeats are dropped and
  `offline_access` is added when missing. A response whose Graph permission set (ignoring
  case, the resource prefix and the OpenID Connect entries) differs from the stored one is
  refused, and nothing is stored: the stored scope must describe the token in use, and a
  refresh must neither widen nor narrow a session. A response without a `scope` keeps the
  stored list.
- `download` runs only when a download starts, after polling ends, never at command start.
  It refreshes when fewer than 5 minutes remain, before each file. The server is assumed to
  check the token when a request starts, not during the transfer (Assumption; PR 4.1 checks
  this with a download that outlasts the token).
- A missing `download` entry in the stored credential triggers one silent refresh attempt.
  If the identity platform refuses it for want of consent (error code `65001`, matched as a
  complete code), the error is `DownloadNotConsented` with its remedy. Any other failure,
  such as a network error or an expired session, keeps its own error and remedy, and a
  later call may try again.
- A consent refusal, whether for a missing entry or while renewing an expired one, stops
  further download attempts in the process: the entry is cleared and the credential stored
  without it, so a later call finds no expired entry to renew and fails at once with
  `DownloadNotConsented`.
- Concurrent refreshes in one process share one refresh request, guarded by a
  `tokio::sync::Mutex` (tokio feature `sync`). Writes from several processes to the store
  follow `entra`'s locking.
- Every secret value the provider has held during the command, including superseded access
  tokens and refresh tokens after rotation, stays registered with the Redactor until the
  process exits (section 6.8).
- `TokenResponse` and `DeviceCodeResponse` hold their secret fields as `SecretString`, so a
  derived `Debug` cannot print them.

### 4.6 Polling (`poll.rs`)

States, from the Graph documentation for `caseOperationStatus`:

| Status | Meaning here | Evidence |
|---|---|---|
| `notStarted` | continue | Observed |
| `running` | continue | Observed |
| `succeeded` | stop, success | Observed |
| `partiallySucceeded`, `failed`, `submissionFailed` | stop, exit 4, show `resultInfo` | Docs |
| `unknownFutureValue` or any other string | stop, exit 4, show the raw value | Docs or Assumption |

- **Deadline.** `--wait-timeout` is a single deadline. It covers sleeps, `Retry-After` waits
  and requests in flight: each read runs under `tokio::time::timeout` for the time left, and
  each sleep is cut to the time left. When it passes, the command exits 5 without a further
  read.
- **Each read** is checked: a record without a valid id or status, or for another
  operation, ends the command. A read that ends after the deadline does not count, even if it
  shows the operation finished; the command exits 5 with that status.
- **Failed reads.** A read that gets no response, or 429 or any 5xx after `GraphClient`'s own
  three attempts, does not end the wait; a warning goes to stderr. That includes a
  `Retry-After` longer than the 60 seconds `GraphClient` waits for (section 4.3): the poll
  waits the interval or the `Retry-After`, whichever is longer, cut to the deadline. Any
  other failure, including a token that cannot be had, ends the command.
- **Interval schedule:** 10 s for the first 2 minutes, then 30 s up to 10 minutes, then
  60 s. `--poll-interval` overrides it.
- **Observed timings,** from the queries sampled in one tenant:
  - estimates took about 5 minutes, for queries of one to ten terms;
  - small item reports took 2 to 4 minutes, and one took 18;
  - one large item report took about 50 minutes;
  - one export with its downloads took about 10 minutes.

  That most of the large report's time was spent queued is Derived from its zip entry times.
  Other queries and tenants may differ. The default deadline of 2 hours leaves room above
  these.
- `percentProgress` is displayed but treated as a hint only. The trace showed only 0 and 100
  (Observed (trace)).
- `completedDateTime` of `0001-01-01T00:00:00Z` on a running operation reads as `None`
  (Observed).
- **Not-found grace.** Only for an operation the same command has just submitted: a 404 in
  the first 30 s is retried (Assumption: possible delay before the operation is visible).
  `operation get --wait` fails on a 404 at once.
- **Progress** goes to stderr when stderr is a terminal and `--verbose` is off:
  `estimate 3f2a…: running · 4m10s`.
- **Ctrl-C** (tokio `signal`, injected through `Env` as `Interrupt`) ends the wait, prints the
  resume commands available in the running release (section 3.3) and exits 130. One listener
  covers the whole wait, and a read in flight is abandoned. The service carries on running the
  operation. A case-close wait prints `purview case get <case>` instead.

### 4.7 Download (`download.rs`)

**Which URL may receive the token.** The `downloadUrl` from operation metadata must:
- use `https`, have no user information, and use port 443 (explicit or implied);
- have a host matching `^[a-z0-9-]+\.proxyservice\.ediscovery\.svc\.cloud\.microsoft$`
  (case-insensitive, no trailing dot).

The observed host was `eur.proxyservice.ediscovery.svc.cloud.microsoft` (Observed); `eur` is
read as the tenant's region (Derived). Other regions are assumed to share the suffix
(Assumption).

The `DownloadToken` is bound to that one origin. It is sent only to a request whose origin
is identical, never to another host under the same suffix. Tests override the pattern only
through `Env`.

**Headers.** `Authorization: Bearer <download token>` and `X-AllowWithAADToken: true`
(Observed: 200). A Graph token gets 401 (Observed). The two token types are distinct, so a
Graph token cannot be given to the download client by mistake. A 401 or 403 is
`DownloadRefused`, and its remedy names `eDiscovery.Download.Read` and `auth refresh`.

**Redirects.** These are handled by the tool, not by `reqwest`:
- A redirect to the same origin is followed, at most 3 times, with the same headers.
- A redirect to any other origin is refused with `CrossOriginRedirect`. It is not followed
  with or without credentials, so no plaintext, private-address or storage-signature target
  is ever contacted.
- The notes say the prototype followed redirects without inspecting them, so whether any
  occur is unknown (Observed: "redirects followed; none observed needed checking"). PR 1.5
  makes a live download with redirects disabled and records the result. If the proxy turns
  out to redirect to a storage host, a separate design is needed: credentials stripped, the
  signature query never logged.

**Timeouts.** The download `reqwest::Client` has no total `.timeout()`. It has
`.connect_timeout(30 s)` and `.read_timeout(120 s)`, which reqwest resets after each read, as
the idle timeout. It does not decompress (`no_gzip`), so the size and SHA-256 are those of
the bytes the service sent.

**Writing a file.**
1. Sanitise the server file name (section 4.7.1) and check for collisions within the
   operation.
2. If the target exists and the manifest shows it verified (same size and SHA-256), report
   it as already downloaded and stop for this file. If it exists otherwise and `--overwrite`
   is not given, refuse before making any request. A target that is a symlink is refused in
   every case.
3. Create a temporary file `.<name>.<random>.part` in the target directory with
   `create_new`, mode 0600. Write to it with `tokio::fs`.
4. Stream into it, computing SHA-256. Abort when the byte count passes the known `size`, or,
   when `size` is unknown, passes `download.max_unknown_size` (default 1 GiB; estimate report
   files had `size: 0`, Observed, and were well under a megabyte). Every download also obeys
   `download.max_size` (default 64 GiB).
5. Check the length against `size` when known, or against `Content-Length` when present.
6. Run `sync_all` (on a blocking thread).
7. Open the zip's central directory from the temporary file. Every file the service offers
   is a zip (Observed), so a file that is not one is refused.
8. Only after steps 4 to 7 pass, publish it under the final name.
   - **Default, no replace:** `std::fs::hard_link(temp, final)`, which fails atomically with
     `AlreadyExists` if another process created the name in the meantime. Then the temporary
     file is removed. On `AlreadyExists` the command refuses with `TargetAppeared` and keeps
     the other process's file. A filesystem without hard links gives `PublishUnsupported`,
     naming `--overwrite` as the alternative.
   - **With `--overwrite`:** `std::fs::rename`, which replaces the old file on every
     platform. The manifest is written first (step 9 before step 8): its entry names the
     replacement, and every entry that reaches the target is dropped (section 3.5).
9. Update `manifest.json` atomically (temporary file and rename): after publication by
   default, before it with `--overwrite`. Each entry records:
   - case id, operation id and action;
   - server file name and local file name;
   - size and SHA-256;
   - `downloadedAt`;
   - for estimates, the guard verdict and any `--allow-generic` reason (section 6.4).

**Failures.**
- Before publication, the temporary file is removed and the final name is left untouched.
- By default, if publication succeeded but the manifest update failed, the verified file
  stays. The command exits 1 with `ManifestWriteFailed`, naming the file.
- With `--overwrite`, a manifest update that fails replaces nothing. A rename that fails
  after it leaves the old file under an entry whose SHA-256 does not match it, so the next
  run refuses it with `TargetExists` rather than recording it.
- **Recovery:** the next `download` or `--check` in that directory finds, under the local
  names of the operation's files, files that have no manifest entry. It verifies each one (size when known, central directory, SHA-256) and adds
  an entry marked `recovered: true`. A file that fails verification is left in place and
  reported, and is never overwritten without `--overwrite`.

#### 4.7.1 File names

Server file names embed the case, search and export names (Observed), so they can be long
and contain any character. The tool:

- splits the name into stem and extension (`.zip` is kept);
- replaces `/ \ < > : " | ? *`, control characters and leading or trailing dots and spaces
  with `_`;
- prefixes `_` to Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`);
- cuts the stem, on a character boundary, so the whole name fits 200 bytes, and adds `~` plus
  8 hexadecimal characters of the SHA-256 of the original name when it cuts;
- checks that the result is a single normal path component;
- when two files of one operation map to the same name, without regard to case, adds the
  hash suffix to both, and does the same for `manifest.json`; a name that is still not
  unique leaves that file out (`FileNotDownloadable`). Names that differ only in Unicode
  normalisation are not detected; on a file system that treats them as one, the second
  publication fails with `TargetAppeared` and nothing is replaced.

The manifest keeps the original server name, because `export index` matches item zips by
that name.

### 4.8 Zip and comma-separated values (CSV) parsing (`zipread.rs`, `report/`, `export/join.rs`)

**Zip limits.** These are enforced on bytes actually read, through counting `Read` adapters,
not on header fields:

| Limit | Report and estimate zips | Export items zips |
|---|---|---|
| Entries | 1,000 | 1,000,000 |
| Decompressed bytes per entry | 4 GiB | `--max-entry-bytes`, default 64 MiB |
| Decompressed bytes, total | 64 GiB | unbounded; each entry is read and dropped |
| Compression ratio per entry, checked during reading | 1,000 | 1,000 |

All limits can be changed in config. In the observed tenant, a large item report was tens
of megabytes compressed and about eleven times larger uncompressed (Observed). An item
export with several thousand items stayed far below the export entry limit (Observed).

Entry names must pass `zip`'s `enclosed_name()`. A name that fails is `HostileZip`. Entries
are never extracted to disk. Report zips are recognised by `Locations-*.csv`,
`Statistics-*.csv`, `Summary-*.csv`, `Settings-*.csv` and `Items_(\d+)_.*\.csv`. Items files
are read in numeric order of N. A large report was split into several items files of about
200 MB each (Observed). Zip64 and the compression methods used by real exports are recorded
in PR 4.1; the `zip` crate's `deflate` feature is enabled from PR 1.5, and `deflate64` only
if PR 4.1 finds it.

**CSV.** The tool uses `csv` with `flexible(true)` and reads `ByteRecord`s as a stream.

- Files are UTF-8 with a byte-order mark (BOM) (Observed). A leading U+FEFF is removed from
  the first field of the first record explicitly.
- `RecordBudgetReader` wraps the input and fails with `RecordTooLarge` when more than
  `limits.csv_max_record_bytes` (default 64 MiB) is read between two record boundaries. The parser
  resets it after each record. Rust's `csv` has no field size limit of its own; the
  prototype's Python reader needed one raised.
- Headers are indexed by name. A missing column is a named warning, not a failure.

Settled in PR 2.3: the ratio is checked once an entry has given 1 MiB, so that a small,
very repetitive file is not refused; the entry cap is `limits.report_zip_entries`; a zip
that is not a zip, has too many entries or a name that leaves its folder, or passes a
limit, is `HostileZip`, whose message never names an entry. The column names, read by
name, are those of the notes: `Locations-*.csv` `DataSourceName`, `DataSourceType`,
`Location`, `LocationId`, `LocationType`, `LocationSubType`, `Count`, `Size`, `Status`,
`ErrorWarning`, `Query`; `Statistics-*.csv` `DataSourceName`, `DataSourceType`, `Location`,
`LocationType`, `LocationSubType`, `StatType`, `StatName`, `OriginalStatName`, `Value`
(Observed). The collection check is `unchecked` when the file it reads, or its `Location`,
`Status` or `StatType` column, is missing, when a row lacks the location, status or
`StatType` it needs, or when the zip holds more than one Locations or Statistics file. The
entry count declared by the end of central directory record (or its ZIP64 form) is read
before the zip is indexed, and an index with fewer entries than declared (a name listed
twice) is `HostileZip`. The ratio's compressed size is at most the file's size. The record
budget is checked on each record's own bytes; the reader below allows two 64 KiB buffers
more as a backstop.

**Summary and Settings.** These are parsed as before:

- `Summary-*.csv` has no header. It is key, value, description rows, with blank lines
  between groups (Observed). It is read whole, up to `limits.csv_max_record_bytes`, and
  split at blank lines outside quoted fields (settled in PR 2.3: the `csv` crate skips blank
  lines and its line numbers do not show them). Item-report summaries add a help link, `Export Name`, an item
  count table, an "Informational" table and a "Consumption summary" (Observed). The parser
  returns groups and a map of known keys.
- `StartTime (UTC)` uses the format `03/14/2026 9:07:41 AM` (an invented example; format Observed). It is parsed with
  `%m/%d/%Y %-I:%M:%S %p`; if parsing fails, the raw string is kept.
- `Settings-*.csv` has the header `"Setting Name","Value","Description"`, and some rows have
  two fields (Observed).

**Locations and Statistics.** Columns and meanings as in the notes (Observed):

- `Locations-*.csv` has one row per location searched. `LocationSubType` is one of
  `PrimaryMailBox`, `ArchiveMailBox`, `SystemMailbox`. `Status` is `Succeeded` or `Failed`.
  `Query` repeats the KQL on every row.
- In `Statistics-*.csv`, a row with `StatType: Error` names a failed location, with the
  message in `StatName`.
- Failed locations are the union of the two, keyed by `Location` and `LocationSubType`. A
  tenant-wide estimate in the observed tenant covered on the order of ten thousand locations,
  and a handful failed with a transient cancellation error (Observed).

**Items and deduplication.** An item report has one row per copy of an item in each mailbox;
it has 162 columns and no body text (Observed). In the observed tenant, a large report held
about 37 rows per estimated item, and about 12.6 rows per unique item (Observed, one
report).

- **Key:** `Internet message ID` if it is not empty, else `Immutable ID`, else a SHA-256 of
  `Item class|Date|Sender|Subject/Title|Conversation name`. Hash keys are counted and
  reported.
- **Aggregation:** `HashMap<Box<str>, UniqueAgg>`. Each `UniqueAgg` holds the slim fields of
  the first row, a copy count, and a sorted `Vec<u32>` of interned `Location ID` indexes,
  deduplicated at the end. `parse items` writes its JSONL after the pass. Memory grows with
  the number of unique items, roughly 1 KB each (Assumption). `--max-unique` (default
  2,000,000) fails with `TooManyUnique` instead of exhausting memory. `--all-rows` keeps no
  map and streams.
- `Subject/Title` is empty for Teams messages; `Conversation name` labels them (Observed).
  `Date` uses the format `2024-06-03 08:15:00Z` (an invented example; format Observed).

**Profile:**
- unique items by `Item class`;
- top senders, after normalisation;
- top Teams conversation names;
- a histogram by day, week or month in UTC;
- counts by `Workload`;
- copies per item, mean and maximum.

Senders are lowercased. The forms `addr` and `Name <addr>` are accepted. A Teams thread id
(`19:…@thread.v2`) counts as "Teams thread" and never as a person (Observed: `Sender` is
sometimes a thread id). Domains are mapped through `identity.domain_aliases`.
`--merge-local-part` merges local parts only within `identity.internal_domains`. The same
person was seen under an old and a new domain (Observed); merging across outside domains
would join unrelated people.

**Export join (phase 4).** The export's report CSV has one row per exported file, with no
copy per mailbox, and every row had `Status: Successful` in the observed run (Observed).

1. `Target path` has the form `Items.1.001.<export name>.zip\Exchange\Items\<id>.msg`
   (Observed). `normalise_target_path` splits off the first component (the part name, matched
   against the original server names of the given items zips) and turns `\` into `/`.
2. Items zips hold one flat folder, `Exchange/Items/<32 hex>.msg`, plus two directory entries
   (Observed). Entry names that do not match `^Exchange/Items/[0-9a-fA-F]{32}\.msg$` are
   counted and skipped.
3. Every row matched exactly one file in the observed run (Observed).

The join is a `HashMap` from (part, entry) to the row. A repeated `Target path` keeps the
first row and is counted. A row for a part that was not supplied counts as `partMissing`.
An entry with no row has `joined: false`.

### 4.9 Trace (`trace.rs`)

`--trace DIR` writes one file per exchange:
`<unix-nanos>-<METHOD>-<last path segment, 40 chars>.json`, sanitised to `[A-Za-z0-9._-]`.
The format is the prototype's:

```json
{"time": "...", "request": {"method": "POST", "url": "...", "body": {...}},
 "response": {"status": 202, "headers": {...}, "body": {...}}}
```

- Request headers are never written.
- Of response headers, only these are kept: `content-type`, `content-length`, `location`,
  `retry-after`, `request-id`, `client-request-id`, `date`, `x-ms-ags-diagnostic`.
- Every URL, including `location` values and `downloadUrl` fields inside bodies, passes
  through `redact::url`. That function keeps only these query keys: `$top`, `$select`,
  `$filter`, `$expand`, `$skiptoken`, `downloadType`. Every other value becomes `REDACTED`,
  which covers storage signatures (`sig`, `se`, `sp`, `sv`) and any `code` or `token`.
- Token endpoint exchanges are never traced.
- Download responses record status, the kept headers and the byte count, never the body.
- Directories are created 0700 and files 0600.
- At start the tool warns: `warning: trace files hold tenant data (names, addresses,
  queries, case names); keep DIR out of version control`. If `DIR` is inside a git work tree,
  it warns again.

Traces exist to learn response shapes. They never become fixtures (section 8.1).

### 4.10 Output (`output.rs`)

Copied from `entra`:
- the table, `--plain` and JSON envelope;
- `sanitize` and `sanitize_multiline` on every string sent to a terminal;
- `--wrap-untrusted`, which covers case and search names and descriptions, subjects,
  conversation names, sender names, attachment names and bodies.

Every sink (stdout, stderr, trace, manifest) writes through the `Redactor` (section 6.8).

### 4.11 Reading exported items (phase 5: `export/read.rs`, `msg/`)

**Pipeline.**
1. One reader thread walks the items zip in central-directory order.
2. It reads each `.msg` entry into a `Vec<u8>`, up to `--max-entry-bytes`. `cfb` needs
   `Seek`, and zip entries do not provide it.
3. **The window.** Before reading an entry, the reader takes one permit from a counting
   semaphore of `W = 2 × jobs` permits. The output thread returns the permit only when it
   has written that item in order. At most `W` items are therefore anywhere between
   admission and output: raw bytes, being parsed, or waiting in the reorder buffer. One slow
   item early in the zip stops admission rather than letting later results pile up.
4. It sends `(index, bytes)` into a `crossbeam` channel; the permits bound it.
5. `--jobs` worker threads, run under `std::thread::scope` and not on tokio, parse each item.
6. Results go to an output thread with a reorder buffer, which writes in zip order. The
   buffer holds at most `W` entries.
7. `--thread-dedup` runs on the output thread after reordering, so output is the same for
   every `--jobs` value.

**Peak memory** is about `W × (max-entry-bytes + parsed item)` for the window, plus the CSV
join map. The join map is roughly 1 KB per report row (Assumption), held for the whole run.
An entry over the cap gets
`error: "entryTooLarge"` without parsing.

**Record:**

```json
{"entry":"Exchange/Items/0123456789abcdef0123456789abcdef.msg","part":"Items.1.001.export_2026_03_14_0930Z.zip",
 "joined":true,"class":"IPM.Note","date":"2025-03-02T09:14:00Z","workload":"Exchange",
 "conversationName":null,"immutableId":"…","internetMessageId":"<…@contoso.example>",
 "subject":"Orders API cut-over",
 "from":{"name":"Alex Example","address":"alex@contoso.example"},
 "to":[{"name":"Sam Example","address":"sam@contoso.example"}],"cc":[],
 "sent":"2025-03-02T09:13:58Z","received":"2025-03-02T09:14:00Z",
 "attachments":[{"name":"plan.xlsx","size":48211}],
 "headers":null,"body":"…","bodySource":"html","bodyTruncated":false,"quotedCut":true,
 "error":null}
```

`class`, `date`, `workload` and `conversationName` come from the CSV; the other fields come
from the `.msg`. `error` is one of `cfbInvalid`, `noBody`, `bodyDecode`, `entryTooLarge`,
`unsupportedClass`, with `errorDetail` explaining.

**Parser choice.**

1. **Chosen: the `cfb` crate plus a reader of our own for the MAPI (Messaging Application
   Programming Interface) properties we need.** `cfb` reads the Compound File Binary
   container that `.msg` uses and is widely depended on. The engineer records the pinned
   version and its last release date in PR 5.1. The `.msg` property layout (MS-OXMSG) is
   published, so a small reader can be tested property by property:
   - Variable-length properties live in streams named `__substg1.0_<PPPP><TTTT>`. `PPPP` is
     the property id. `TTTT` is the type: `001F` is a UTF-16LE string, `001E` an 8-bit
     string, `0102` binary.
   - Fixed-size properties live in `__properties_version1.0`. Its header is 32 bytes for the
     top-level message, 24 for an embedded message or attachment and 8 for a recipient. Each
     entry is 16 bytes, and type `0040` is a FILETIME.
   - Recipients and attachments are the storages `__recip_version1.0_#XXXXXXXX` and
     `__attach_version1.0_#XXXXXXXX`.

   Properties read:
   - **Message:** `PidTagMessageClass` 0x001A, `PidTagSubject` 0x0037,
     `PidTagConversationTopic` 0x0070, `PidTagInternetMessageId` 0x1035,
     `PidTagTransportMessageHeaders` 0x007D, `PidTagClientSubmitTime` 0x0039,
     `PidTagMessageDeliveryTime` 0x0E06, `PidTagInternetCodepage` 0x3FDE.
   - **Sender:** `PidTagSenderName` 0x0C1A, then `PidTagSenderSmtpAddress` 0x5D01,
     `PidTagSenderEmailAddress` 0x0C1F, `PidTagSentRepresentingSmtpAddress` 0x5D02, in that
     order of preference.
   - **Body:** `PidTagBody` 0x1000, `PidTagHtml` 0x1013, `PidTagRtfCompressed` 0x1009.
   - **Recipients:** `PidTagRecipientType` 0x0C15, `PidTagDisplayName` 0x3001,
     `PidTagSmtpAddress` 0x39FE, then `PidTagEmailAddress` 0x3003.
   - **Attachments:** `PidTagAttachLongFilename` 0x3707, then `PidTagAttachFilename` 0x3704,
     and `PidTagAttachSize` 0x0E20, for names and sizes only.

   Unknown properties are ignored.
2. **Not used: `msg_parser`.** We need to read `PidTagHtml` as binary with its code page,
   because mail bodies are often only HTML (Observed). We have not confirmed that
   `msg_parser` exposes this. A wrapper we cannot extend would lose most mail text. It is
   also not added as a dev-dependency; the cross-check is against the Python fallback.
3. **Fallback: `contrib/msg-bodies.py`.** It is a `uv` script with `extract-msg` pinned, and
   it writes the same JSONL schema from the same inputs. In the observed run, `extract-msg`
   read every item except the Teams system messages, all from the zip in memory (Observed).
   Users run it when the Rust reader's failure count is too high for their data. CI compares
   the two readers on synthetic fixtures.

**Body selection.**
1. `PidTagHtml`: a binary value is decoded with `PidTagInternetCodepage` through
   `encoding_rs` (default UTF-8); a string value is UTF-16LE. The text is then cleaned:
   - remove `<head>`, `<style>`, `<script>` and Office conditional comments
     (`<!--[if …]>…<![endif]-->`);
   - remove leftover style text matching `v\:* {behavior:…}`, as the VML (Vector Markup
     Language) text naive tag-stripping leaves behind (Observed). The similar `o\:*`,
     `w\:*` and `.shape` rules are removed too (Assumption: same origin);
   - convert with `html2text` at a fixed very large width, so nothing wraps. The width is
     chosen in PR 5.2 after checking how the pinned version treats width;
   - set `bodySource: "html"`.
2. Else `PidTagBody`, with `bodySource: "text"`.
3. Else `PidTagRtfCompressed` only: `error: "noBody"`, `errorDetail: "compressed RTF only"`.
   Decompressing it (MS-OXRTFCP and MS-OXRTFEX) waits until such an item turns up in real
   data.
4. Else `error: "noBody"`.

`IPM.SkypeTeams.SystemMessage` items failed in `extract-msg` (Observed). Here they produce
whatever properties can be read, with `error: "unsupportedClass"` when they have no body.

**Reading threads.** Quoted reply history repeats in every message of a thread (Observed).
- `--cut-quoted` cuts at the first line matching `^From: .+`,
  `^-----\s*Original Message\s*-----`, `^On .+ wrote:$` or `^_{32}$`.
- `--thread-dedup` keys on (`conversationName`, or the normalised subject; date; sender), as
  the notes suggest.

---

## 5. Authentication and configuration

### 5.1 Tokens

- One public-client app registration in the user's tenant, with no secret.
- **Graph sign-in scopes:** `https://graph.microsoft.com/eDiscovery.ReadWrite.All
  offline_access openid profile`. With `--read-only`, `eDiscovery.Read.All` replaces the
  first. The observed consent used the read-write set (Observed). PR 1.4 checks live that a
  read-only session can list and get; it does not establish whether actions work under it.
- **Download token:** a refresh-token grant for
  `b26e684c-5068-4120-a679-64a5d2c909d9/.default`. The prototype requested `.default`
  (Prototype), and a download with the resulting token succeeded (Observed).
- **Account:** from the id token, `preferred_username`, else `upn`, else `email`, lowercased
  as the account key. `tid`, `oid` and `name` (as `display_name`, when present) are
  recorded. With none of the three claims, the error
  is `NoAccountClaim`. The id token comes straight from the token endpoint over TLS
  (Transport Layer Security) and is used only to label the account, so its signature is not
  verified.

**Stored credential.** One credential-store item per account, holding JSON:

```json
{"version":1,"email":"alex@contoso.example","tid":"<tenant-id>","oid":"<object-id>",
 "client_id":"<application-client-id>","tenant_id":"<tenant-id>","refresh_token":"…",
 "graph":{"access_token":"…","expires_at":"…","scope":"…"},
 "download":{"access_token":"…","expires_at":"…","scope":"…"},
 "access":"read-write","sign_in":"<random id>"}
```

`download` may be absent. `tid` and `oid` are the id token's claims for the identity the
tokens belong to: they bind the account key to one principal. `client_id` and `tenant_id`
name the app registration and tenant that issued the tokens. Every refresh and redemption uses the registration recorded here,
never one from `config.json` or the account file, so tokens and registration cannot come
apart. A stored credential without any of these four, or with a registration that is not GUIDs,
is treated as needing sign-in (`auth login` again), not as matching. A sign-in whose id
token lacks `tid` or `oid` stores nothing. `auth refresh` also refuses, before any
request, when the credential's `tid` and `oid` differ from the selected account file's. If the account file or `config.json`
names a different registration, a sign-in stopped part way: `auth refresh` refuses with a
"sign in again" error and sends nothing. The service name is `purview`, the key `purview:token:<email>`,
the macOS label `purview — <email>`, and the description `Microsoft Purview eDiscovery
token`. Windows chunking and Linux keyutils behave as in `entra`. The credential store is the
only place a token is ever persisted.

`access` records how the account signed in: `read-write`, or `read-only` after `auth login
--read-only` (from PR 2.1). `sign_in` is a random id made at each sign-in, which refreshes
keep. A refresh stores its tokens only over a credential of the same principal and
registration from the same sign-in, so a session that another `auth login` replaced while it
ran (with another access, scope or registration) cannot write its older credential back; it
stops and asks for the command to be run again. Two commands of one sign-in still refresh
side by side. A
refreshed token that does not last as long as the request needs (five minutes before a POST)
is stored but not used. A credential without it, as v0.1 stored, or
with any other value, is read and refreshed as before but counts as neither.

**Read-only sessions.** The stored scope cannot tell: a `--read-only` sign-in was granted
`eDiscovery.ReadWrite.All` too, because the identity platform grants every consented
permission (Observed, PR 1.4). So a write needs `access` to be `read-write`, and the stored
Graph scope to hold `eDiscovery.ReadWrite.All`; otherwise it
fails before any network call with `ReadOnlySession`, whose message says whether the
sign-in was read-only or predates the record. Signing in again records it. Whether the service would
accept actions under `eDiscovery.Read.All` is unknown and is not tested: the tool refuses
them anyway. Read-only sessions are documented as able to read and download only (download
itself is checked in PR 1.5).

### 5.2 App registration (`docs/auth.md`)

Each item below carries its own label. The notes record steps 1 to 4 as carried out once by
hand in the observed tenant. They do not record a Purview role assignment step, or the
OpenID Connect scopes as separate entries in `requiredResourceAccess`.

1. **Purview eDiscovery service principal.** The tenant may not have one; the observed
   tenant did not. `az ad sp create --id b26e684c-5068-4120-a679-64a5d2c909d9` creates it as
   `MicrosoftPurviewEDiscovery`. It exposes the delegated scope `eDiscovery.Download.Read`
   (`c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2`, admin type) and an application role of the same
   name, which `purview` does not use (Observed).
2. **Application.**
   - `signInAudience: AzureADMyOrg`, `isFallbackPublicClient: true` (Observed).
   - Public-client redirect `http://localhost/callback` (Observed). `--browser` works with
     `http://localhost:<port>/callback` on this registration (Observed in the PR 1.2 live
     check).
   - No credentials (Observed).
   - `requiredResourceAccess`:
     - Graph `eDiscovery.ReadWrite.All` (`acb8f680-0834-4146-b69e-4ab1b39745ad`) (Observed).
     - Or Graph `eDiscovery.Read.All` (`99201db3-7652-4d5a-809a-bdb94f85fe3c`). Its id is
       from the notes; its use here is an Assumption.
     - `offline_access`, `openid` and `profile`: listing them here is an Assumption. The
       notes record them only on the consent grant (step 4).
     - The eDiscovery scope from step 1 (Observed).
   - A Graph `POST /applications` does not add the caller as owner (Observed); add owners
     explicitly.
3. **Service principal for the app,** with `appRoleAssignmentRequired: true`. Assign users
   with the default role `00000000-0000-0000-0000-000000000000` (Observed).
4. **Consent.**
   - *Per user (Observed):* one `oauth2PermissionGrant` per resource with
     `consentType: Principal`: Graph with `eDiscovery.ReadWrite.All offline_access openid
     profile`, the eDiscovery service principal with `eDiscovery.Download.Read`. A per-user
     grant takes a user, not a group (Docs).
   - *Tenant-wide (Docs, not observed):* `AllPrincipals`, with assignment deciding who may
     sign in.
5. **Purview role:** membership of the eDiscovery Manager or eDiscovery Administrator role
   group, assigned in the Purview portal (Docs). The notes record only that the observed
   account was an eDiscovery Administrator (Observed).
6. **Sign in:** `purview auth login --client-id <application-client-id> --tenant-id
   <tenant-id>`.

**`contrib/create-purview-app.sh`.** It automates steps 1 to 4 under its own safety
contract.

- **Dry run by default.** Without `--apply`, it runs only read-only `az` calls and prints a
  plan:
  - the target tenant (from `az account show`, which must equal `TENANT_ID`);
  - whether it will create an app or update `CLIENT_ID`;
  - the service principals it will create;
  - the full `requiredResourceAccess`;
  - each assignee, resolved to object id and user principal name (UPN);
  - **effective assignment state:** `appRoleAssignmentRequired` and who may sign in;
  - **consent,** shown separately: type and scopes per resource.

  It then exits 0. The script never prompts, so it can run in sessions without a terminal.
- **`--apply`** carries out the plan in order:
  - **Each mutation is sent once.** Nothing is retried automatically.
  - **Readiness is polled with reads.** After creating a service principal, the script
    polls `az ad sp show` (a read) every 5 s for up to 60 s until the object is visible.
    Only then does it send the next mutation.
  - **Unclear outcomes are read back.** If a mutation's outcome is unclear (timeout,
    throttling, a 5xx, or a non-zero exit without a definite error), the script reads back
    the intended object or grant. It reports whether that object exists, then stops with a
    non-zero exit and names the step. Running it again is then safe, because each step first
    reads the current state and skips what already matches.
- **Two assignment branches,** chosen explicitly:
  - **Restricted (default).** `ASSIGN_USERS` (users) or `GROUP_OBJECT_ID` must be set, and
    `appRoleAssignmentRequired` is `true`. `CONSENT=principal` (the default) accepts only
    `ASSIGN_USERS`. With `GROUP_OBJECT_ID` it refuses and names `CONSENT=tenant` or
    `ASSIGN_USERS`.
  - **All users.** `ALLOW_ALL_TENANT_USERS=1` sets `appRoleAssignmentRequired: false`. It
    requires `CONSENT=tenant` and no assignment variables. The plan states that every user in
    the tenant can sign in through the app. This is the exception that `entra`'s setup
    script also makes.
- **Variables:** `TENANT_ID`, `CLIENT_ID`, `APP_NAME` (default `Purview CLI (eDiscovery)`),
  `ASSIGN_USERS`, `GROUP_OBJECT_ID`, `READ_ONLY=1`, `CONSENT=principal|tenant`,
  `ALLOW_ALL_TENANT_USERS`.
- **Testing:** CI runs the script with a fake `az` on `PATH` that records its arguments and
  can be scripted to time out or throttle. Assertions:
  - a dry run issues no `create`, `update`, `delete`, `add` or `grant` subcommand;
  - a timeout or throttle on a mutation produces exactly one call of that mutation, followed
    by a read-back;
  - `GROUP_OBJECT_ID` with principal consent is refused;
  - both branches, restricted and all users, produce the expected plans and calls.

### 5.3 Config location

`config.json` lives under `dirs::config_dir()/purview/`, overridable with
`PURVIEW_CONFIG_DIR`. Account files are `accounts/<email>.json`, holding
`{email, upn, oid, display_name, tenant_id, client_id, login_time}`. The account file is for
display and account selection (`tenant_id` is the id token's `tid`, and `oid` binds
`--account` at sign-in); `config.json` `clients` only says which registration to offer at
the next sign-in. Neither chooses the registration a refresh uses (section 5.1).

After the ownership check below, `auth login` stores a sign-in in this order: the
credential, replaced in place under its
key (the old item is not deleted first, so a macOS keychain item keeps its access list);
then the account file; then `config.json`. If the store refuses the first write
outright, the earlier sign-in is left as it was. A failure the store reports after the write
took effect (a macOS label failure, a Windows clean-up failure) can leave the new credential
in place: on a first sign-in it is swept (below); on a later sign-in the account file still
names the earlier sign-in, and `auth refresh` refuses the mismatch. A failure at the account file on a first sign-in removes the new
credential again; on a later sign-in it leaves an account file that may name the old
registration, which `auth refresh` detects. A failure at `config.json` leaves a working
account whose stale registration, if it differs, `auth refresh` also detects.

**An account key belongs to one principal.** Before any write, `auth login` refuses when
the destination key already has an account file, or a credential, that records a different
`tid` or `oid` from the sign-in's. This covers an address reassigned to another person and a
rename onto a key another stored account holds; both accounts' files and credentials stay
as they were. `auth logout --account <key>` frees the key, after which the new identity can
sign in under it. A rename onto a free key is stored under the new key; the old key's
entries stay until they are logged out.

If a first sign-in fails at the credential or the account file, `auth login` sweeps the key:
the primary entry and, in the Windows chunked layout, every chunk in both slots, whether or not
a header was written. If that sweep fails, the error names `auth logout --account <key>`.
`auth logout --account <key>` acts on that exact key when an account file or any store entry
exists under it, before any `upn` matching, and removes the entry without parsing it, so a
damaged credential or headerless chunks can always be removed.

An unreadable, damaged or partly recorded destination counts as owned: an account file that
cannot be read or lacks `tid` or `oid`, or a credential that cannot be read or records only one
of them. `auth login` then refuses and names `auth logout --account <key>`. The exception is a
damaged or partly recorded credential under a key whose account file is readable and records
the sign-in's own `tid` and `oid`: the sign-in replaces (repairs) it. Each id is compared on
its own.

`auth login` (from the ownership check to its last write or rollback), `auth logout` and each
refresh commit hold a per-account lock file under the local data directory, taken with the
same file lock the credential store uses on Windows, so two processes cannot interleave on one
key. Before committing a rotation, a refresh checks under that lock that the key still holds a
credential of the same principal and registration.

When `--account` (or `PURVIEW_ACCOUNT`) names a stored account, the sign-in must return
that account's recorded `tid` and `oid`; otherwise the returned account key or `upn` must
equal the name given, ignoring case. On a mismatch nothing is written. Symlinks are refused, modes are 0600
and 0700, and writes are atomic, as in `entra`.

- On Windows there are no modes. The configuration lives under the user's profile and relies on
  that directory's default access control list (ACL); the tool sets no ACL of its own. Any
  reparse point (a symlink or a junction) is refused as the configuration directory, the
  accounts directory or `config.json`.
- Keys the running release does not read are kept when the file is saved.
- `config.json` never holds a secret. Saving refuses any value the Redactor recognises
  (section 6.8).

### 5.4 Data directory

Downloads go to `dirs::data_local_dir()/purview/cases/<case-id>/<operation-id>/` (mode 0700),
unless `--out` or `defaults.data_dir` says otherwise. `defaults.data_dir` replaces the root
(`<data_dir>/cases/<case-id>/<operation-id>/`); `--out` is the directory itself. A missing
directory is created with mode 0700; an existing one keeps its mode, and a link is refused. That directory is outside any
repository on purpose. Every command that writes a file prints its full path.

### 5.5 Settings

```json
{
  "default_account": "alex@contoso.example",
  "clients": { "alex@contoso.example": { "client_id": "<application-client-id>", "tenant_id": "<tenant-id>" } },
  "defaults": { "teams_context": true, "data_dir": null, "wait_timeout": "2h", "top": 20 },
  "naming": {
    "case_name": "Records research - {topic} {yyyy_mm}",
    "case_description": "Requested by {requester}. Tenant-wide mailbox search with no custodians or holds. {marker}",
    "search_description": "{query_summary} {marker}",
    "export_name": "{action} {utc_date} {utc_hhmm}Z",
    "marker": "[created-by:purview-cli]"
  },
  "guard": { "specific_terms": [], "generic_terms": [] },
  "identity": { "internal_domains": [], "domain_aliases": {} },
  "download": { "max_size": "64GiB", "max_unknown_size": "1GiB" },
  "limits": { "report_zip_entries": 1000, "export_zip_entries": 1000000, "csv_max_record_bytes": "64MiB" }
}
```

An object or value given as `null` means unset, as if it were missing; any other value of
the wrong type is an error. `guard.specific_terms` and `guard.generic_terms` are lists of
non-blank strings.

Template variables:

| Variable | Value |
|---|---|
| `{topic}` | `--topic` |
| `{requester}` | `--requester`, or `{user}` when absent |
| `{user}` | the signed-in account |
| `{query_summary}` | the first 200 characters of the KQL, cut on a character boundary |
| `{yyyy_mm}` | e.g. `2026-11` |
| `{utc_date}`, `{utc_hhmm}` | e.g. `2026-03-14`, `0930` |
| `{action}` | `estimate`, `report` or `export` |
| `{marker}` | `naming.marker` |

An unknown variable, or a `{` or `}` outside one, is an error when a write command reads
the configuration, before sign-in. A template that uses a variable with no value for that
name (`{topic}` in `export_name`, say) is an error when it is rendered. Where an empty value
leaves a space on both sides, one is dropped; other spaces are kept.

`export_name` uses UTC because the service builds the zip file name from the display name.
In the prototype the caller's local time ended up in that file name (Observed).

---

## 6. Safety design

### 6.1 What changes what

| Command | Kind | What it changes |
|---|---|---|
| `case create` | create | A new case, visible to eDiscovery administrators |
| `search create` | create | A search in the case. Nothing runs until an action is posted (Observed) |
| `estimate` | action | Runs the search over every mailbox; adds an operation and a report file to the case |
| `report` | action | As above, and collects item metadata into a report |
| `export create` | action | As above, and collects item **content** into packages |
| `case close` | state | Moves the case to `closing`, then `closed` |
| `contrib/create-purview-app.sh --apply` | tenant directory | Creates or updates directory objects, assignments and consent grants (section 5.2) |

Every Purview change is assumed to appear in the tenant's audit log under the signed-in
account (Docs).

### 6.2 Plan, approve, send

- **Preflight.** Each write runs a fixed list of read-only preflight requests, named per
  command in section 3.5. These resolve names, check for duplicates, fetch the search, check
  holds and list active operations. `--dry-run` runs them too, so the plan predicts what
  `--yes` would do.
- **What may be sent before approval.**
  - To the Purview Graph origin: only these `GET`s, and no other method.
  - To the identity provider: token exchanges are allowed (a refresh of an expired token is
    a `POST` to the token endpoint). They change no tenant state.
  - Nothing else.
- **What runs offline, before sign-in,** in this order (settled in PR 2.2): argument
  validation, including building the KQL from the query flags; `--no-write`; `--select`
  validation (a write has no columns, so any `--select` is refused); `config.json`'s
  `naming` templates and `guard` lists, which `WriteCommand::check` receives as
  `WriteSettings`; then `check`, which runs the KQL guard for a query supplied on the command
  line. Then the read-only check (section 5.1), still before any network call. The KQL of an
  existing search can only be checked after the preflight `GET` that fetches it.
- **`WritePlan`** holds:
  - the account and tenant;
  - the `WriteRoute`;
  - the body, serialised once to bytes;
  - a SHA-256 digest of method, path and body;
  - effects as plain sentences ("Creates a search over all tenant mailboxes. Places no
    hold.");
  - warnings and the preflight results.
- **Approval:**
  - `--dry-run`: print, exit 0.
  - Interactive (stdin and stderr are terminals), no `--yes` and no `--no-input`: print the
    plan on stderr, then `Apply? [y/N]`; only `y` or `yes`, in any case, approves, and
    anything else, end of input included, is `Declined` (exit 3). This holds under `--json`
    too: the prompt is on stderr and the document on stdout. For `case close`, the prompt
    asks for the case name instead (PR 2.7).
  - `--yes`: approve.
  - Non-interactive or `--no-input` without `--yes`: exit 3.
- **`ApprovedWrite`** can only be built by `safety::approve(plan, Approval)`, which only
  `safety::decide` calls, and only the write runner in `cli` calls `decide` and
  `GraphClient::send_write` (a source scan checks both). `send_write` takes it by value, so
  one approval sends once, and sends exactly the stored method, path and bytes. No other
  code path can send a non-`GET` request. A command's preflight, reconciliation and result
  reading get the Graph client, the signed-in account and a log, never the terminal state,
  the approval input or the prompt. The runner also refuses a plan that names another
  account or tenant than the signed-in one. The human plan shows the preflight results, and
  goes through the same URL and secret redaction as JSON.
- **Testing.** Each wiremock origin records every request. For each write, tests assert:
  - no non-`GET` request reaches the Graph origin before approval, and exactly one after it;
  - a dry run that starts with an expired token makes one token-endpoint refresh and still
    sends no Graph write;
  - a saved search with a generic query is refused only after its preflight `GET`, with no
    write.

JSON for a write follows section 3.3. `plan` is `{"command", "account", "tenant", "method",
"path", "body", "digest", "effects", "warnings", "preflight"}`. Exit 0 wraps
`{"applied", "plan", "result"}` in the `results` envelope; exit 3 uses the unwrapped error
shape.

### 6.3 Guard against generic tenant-wide searches

A tenant-wide search on a common word reads a large amount of unrelated mail and chat. The
rule:

> Every branch of the query that can match a message must be narrowed. A branch is narrowed
> by a positive specific term, or by a positive `participants:` restriction on a full
> address.

`--allow-generic --reason TEXT` overrides a "not narrowed" verdict, and the reason must not
be blank. It never overrides a parse error. The guard catches mistakes. It is not a security
control: anyone with the Purview role can use the portal.

**Supported subset.** The lexer and a recursive-descent parser accept exactly this grammar
(EBNF, Extended Backus–Naur Form). Everything else is `KqlNotUnderstood`, with the position
and the token:

```text
query      = or_expr EOF
or_expr    = and_expr { "OR" and_expr }
and_expr   = unary { "AND" unary }
unary      = "NOT" unary | primary
primary    = "(" or_expr ")" | restriction | phrase | word
restriction= addr_prop ":" address
           | "subject" ":" ( phrase | word )
           | "kind" ":" ( "email" | "microsoftteams" )
           | "sent" ( ">=" | "<=" ) date
addr_prop  = "participants" | "from" | "to" | "cc" | "bcc"
phrase     = '"' { any char except '"' } '"'      (non-empty, no wildcard)
word       = letter-or-digit start, then letters, digits, - _ . / @ ; optional single trailing *
date       = YYYY-MM-DD
```

- `AND`, `OR` and `NOT` must be upper case.
- The unquoted words `and`, `or`, `not` and `near`, in any case, are refused, because KQL
  might read them as operators.
- Juxtaposition (two operands with no operator between them) is refused, because KQL's
  implicit operator is easy to misread.
- Refused outright: prefix `+` or `-`, `NEAR`, `ONEAR`, `property:(…)`, ranges `..`,
  properties not listed above, `=`, `<`, `>`, wildcards inside a word, and `*` in an address.
- Property names are case-insensitive. Values keep their case. `kind:` values are compared
  ignoring case.
- An address that fails the address check below is refused as a value (`KqlNotUnderstood`),
  for every address property, so every `participants:` leaf that parses is a full address.
- A control character other than tab, line feed and carriage return, or a default-ignorable
  code point (zero-width space, bidirectional control), is refused anywhere in the query,
  and so is any control character inside a phrase: the terminal report removes them, so
  the guard must not classify text the operator cannot see. `--term` refuses them too,
  before `config.json` is read. `--since` and `--until` take exactly `YYYY-MM-DD`, as
  `sent` does.
- Tokens are separated only by ASCII space, tab, line feed and carriage return; other
  Unicode spaces are refused outside a phrase. A closing quote must be followed by a space,
  a parenthesis or the end, and a word must not be followed by a quote, so `"a"AND"b"` is
  refused. Property names and `kind:` values are folded to lower case as ASCII only.
- A web address is refused anywhere in a query, and in `--term`: `http://` or `https://` in
  any case, the same test `redact::urls_in_text` uses for every output of the tool. A URL
  can carry a signature in its query, and redacting it for display changed how the reported
  query parsed and was classified. With none in a query, `purview kql` prints the JSON
  `kql` as given (registered secrets are still redacted by every writer); the table's
  `kql:` line shows tabs, line feeds and carriage returns as spaces. Other schemes, such as
  `mailto:`, are not URLs to the redactor anywhere in the tool, and are not refused.
- Parentheses and `NOT` nest at most 64 deep, so that a hostile query cannot exhaust the
  stack.
- A refusal gives the column (characters from 1) and names the construct. It quotes the
  query only when the construct is ASCII punctuation, never a word, property name or value,
  following the rule that diagnostics do not repeat argument values or tenant text.
- The builder refuses a `"` or `*` in `--term`, a `--participant` or `--exclude-from` value
  that fails the address check, and `--since` later than `--until`, naming the flag and the
  value's position but not the value.
- The query builder emits only this subset. Its output goes through the same parser, so the
  flags and `--kql` get the same verdicts; a test runs both forms over one table of cases.

**Address check.** An address counts as narrowing only if:
- it matches
  ``^[A-Za-z0-9][A-Za-z0-9.!#$%&'+/=?^_`{|}~-]*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$``
  (the part before `@` starts with a letter or digit, settled in PR 1.6, so that no
  restriction reads `participants://…`);
- it has no `*`;
- the part before `@` is not empty;
- it is not quoted.

A bare domain is refused as a value.

**Term classification** (`classify.rs`). A phrase or word is split into tokens on
whitespace. Each token is trimmed of leading and trailing `.,;:!?'"()`, then classified.
First match wins:

1. Exact, case-insensitive match of the whole phrase:
   - in `guard.generic_terms` → generic (the generic list wins over the specific list);
   - in `guard.specific_terms` → specific.
2. A token in the built-in generic list below, compared case-insensitively after trimming →
   generic.
3. A token shorter than 4 characters → generic.
4. A token of digits only, such as `2025` → generic.
5. A trailing `*`: classify the stem, and a stem shorter than 6 characters → generic.
   Rules 2 to 4 see the token with its `*`, so `a*` is decided by rule 3.
6. A token holding a letter plus a digit, or plus one of `- _ . / @ :` with a letter or
   digit on each side of it (`orders-api`, `export_bucket`, `svc2`; not `retention-`) →
   specific. KQL may read such a separator as a space (Docs), so one at the edge of a word
   is not evidence of a name.
7. A token with at least one lower-case letter and an upper-case letter after its first
   character (`PagerDuty`, `GitHub`; not `RETENTION`) → specific.
8. Otherwise → generic.

**Built-in generic list** (authoritative; `src/kql/classify.rs` holds it as a constant, and
`docs/safety.md` reproduces it; a test asserts the two are identical). These are common words
that rule 6 would otherwise call specific, in trimmed lower-case form:

<!-- built-in-generic-list:start -->
```text
e-mail e-mails e-commerce e-learning e-signature e.g i.e etc a.m p.m n/a w/c and/or 24/7
sign-in sign-ins sign-on sign-up sign-out log-in log-on log-off opt-in opt-out
follow-up follow-ups set-up check-in check-ins check-out roll-out hand-over hand-off
add-on plug-in co-op co-operation co-ordinate co-ordination well-being ad-hoc
up-to-date in-house on-site off-site on-call part-time full-time mid-year year-end
month-end end-of-year end-of-month day-to-day one-to-one 1-to-1 face-to-face real-time
long-term short-term high-level low-level top-level cross-team re-send re-sent re-run
re-open pre-sales post-sales covid-19 wi-fi
```
<!-- built-in-generic-list:end -->

Changing the list needs a test change and a CHANGELOG entry.

A phrase is specific if at least one of its tokens is specific. Examples:
- `"orders-api migration"` is specific;
- `"2025 contract"`, `"stock report"` and `"follow-up meeting"` are generic.

`subject:` values are classified the same way.

**Verdict** (`guard.rs`). `narrowed(node)` is true when every message the node can match
must also match a narrowing leaf:

| Node | `narrowed` |
|---|---|
| specific phrase or word, `subject:` with a specific value | true |
| `participants:` with a valid address | true |
| generic phrase or word, `from:`/`to:`/`cc:`/`bcc:`, `kind:`, `sent` | false |
| `NOT x` | false |
| `a AND b AND …` | true if any child is narrowed |
| `a OR b OR …` | true only if every child is narrowed |
| parentheses | same as the inner node |

The query passes if `narrowed(root)`. For example:
- `"retention" AND participants:alex@contoso.example` passes;
- `NOT "orders-api"`, `kind:email`, `subject:retention` and
  `(participants:alex@contoso.example OR kind:email) AND "retention"` fail.

Only `participants:` counts towards narrowing, for two reasons. The operating rule this
tool enforces names `participants:`. And how `from:` and `to:` treat Teams messages has not
been observed. To restrict by sender, write `participants:x AND from:x`.

Known errors:
- single-word product names (`Okta`) are refused;
- some broad hyphenated words not on the list are accepted.

The remedies are the config lists and the reasoned override. `purview kql` shows each leaf's
class and the rule that decided it.

### 6.4 Action preflight on an existing search

`estimate`, `report` and `export create` all run these steps before planning:

1. Resolve `<search>` by id, or by an exact name that must be unique.
2. `GET` the search. Its `dataSourceScopes` must equal `allTenantMailboxes` exactly. If it
   is absent or has any other value, the action is refused with `ScopeUnverified` or
   `ScopeNotAllowed`. These have no override.
3. `GET` the search's `custodianSources`, `noncustodialSources` and `additionalSources`
   (Docs). Each must return an empty `value`, read to its last page. If any has an entry, the
   action is refused with `SearchHasSources`. If any read fails, it is refused with
   `ScopeUnverified`.
4. Run the guard on the current `contentQuery`. A missing query is refused. A query outside
   the supported subset is refused with `KqlNotUnderstood`, whoever created the search. A
   query that is not narrowed is refused unless `--allow-generic --reason` is given.
5. The plan shows the scope, the full KQL and the guard verdict.

When the override is used, the reason goes into the operation's `description` for `report`
and `export create` (Docs: the export actions accept `description`; the trace showed it null
when not sent, Observed (trace)). An estimate has no description field, so the reason is
recorded only in the plan output and in the download manifest.

Whether `GET` on a search returns `dataSourceScopes`, and whether the three source reads
work on v1.0, is observed in PR 1.4 before any action ships. If one of them is not
available, the actions stay refused, with that check named, until a reviewed design replaces
it.

### 6.5 No holds

- The search body's `dataSourceScopes` has a type that can only serialise to
  `"allTenantMailboxes"` (section 7.5).
- No write route touches custodians, sources or holds (section 4.3). The reads that close,
  the action preflight and the inventory need are `GET` routes.
- Every create plan says "Places no hold", and so does the default case description.
- The Graph documentation's sample custodian response shows `holdStatus: applied` (Docs).
  That is why custodians stay out of every phase.

### 6.6 Teams context and the row-count warning

`additionalOptions: teamsAndYammerConversations` is on by default for `report` and
`export create`. It collects the conversation around each Teams hit. Turning it off is
experimental until observed (section 3.5). The plan always shows the setting.

The `report` plan warns that rows can far exceed the estimate. In one observed tenant:
- a small report held about 10 rows per estimated item;
- a large one about 37, or about 3 unique items per estimated item.

The estimate seems to count a Teams conversation once, while the report lists each message
and each mailbox copy (Derived).

### 6.7 Duplicates and unclear outcomes

**Concurrent operations.** The operations list has no search identifier and shows reports
as `exportResult` (Observed). So the preflight for an action lists the case's operations and
looks for any `notStarted` or `running` operation that might be a duplicate:
- for `estimate`: any active `estimateStatistics`;
- for `report` or `export create`: any active `exportResult`.

The plan names each one with id and creation time, as "may be a duplicate". Approval then
also needs `--allow-concurrent`; `--yes` alone is not enough.

PR 1.4 checks whether `GET …/operations/{id}?$expand=search` (Docs: estimate and export
operations have a `search` relationship) returns the search. If it does, the preflight
resolves active operations and warns only about those on the same search.

**Unclear write outcomes.** After a timeout, reset, 5xx or 429 on a POST, the tool does not
retry. It lists what might have been created, as candidates, and exits 1 with
`WriteOutcomeUnknown`:
- `case create`: cases with the same name;
- `search create`: searches with the same name in the case;
- an action: operations created by the signed-in account since the request was sent. For
  `estimate`, those listed as `estimateStatistics`. For `report` and `export create`, the
  list shows both as `exportResult`, so each candidate is resolved by a single GET (at most
  10) and shown with its true action. Any left unresolved are shown as "report or export".
- `case close`: a `GET` on the case, reporting its current status.

Names are not unique, so a match is only a candidate. The user decides whether to run the
command again.

Settled in PR 2.2: reconciliation keeps the entries of pages read before a page failed, and
names each candidate by id with its status (a case) or creation date. Notes follow the
candidates: that none was listed, that the list stopped early, that some entries had no
readable name. A failed check is reported by its error code and HTTP status only, because
the message can hold text Graph quoted back.

### 6.8 Secrets

- Tokens persist only in the operating-system credential store. No command prints a token.
  There is no `auth token` command and no `--print` flag. This rules out the prototype's
  token-printing helper.
- Secrets are held in `SecretString` from the moment they are received.
- **The Redactor.** It holds every secret value the process has seen, until it exits:
  access tokens of both kinds, refresh tokens (including ones already superseded by
  rotation) and the device code. Every sink writes through it: stdout,
  stderr, trace files and the manifest. It replaces those values, and any string matching the
  JSON Web Token pattern `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`, with
  `[redacted]`. URLs pass through `redact::url` (section 4.9).
- **Error details are allow-listed.**
  - OAuth errors keep `error`, `error_description` (after redaction), `error_codes`,
    `trace_id`, `correlation_id` and `timestamp`.
  - Graph errors keep `code`, `message` (after redaction), `innerError.request-id` and
    `innerError.date`.
  - Download errors keep the status and the kept headers.
- **Canary tests** (section 8.5). Distinct marker values for the access tokens, refresh
  tokens and download token are put through success, failure, redirect, refresh rotation
  and timeout paths. After a refresh rotation, a mock reflects the *old* refresh-token and
  access-token canaries back in an error body. Afterwards, stdout, stderr, the trace
  directory, the config directory and the data directory are scanned byte by byte, and none
  of the markers may appear.

---

## 7. Data model

### 7.1 Wire records and validated inputs

Two layers, so a sparse or changed response does not break a whole list:

- **Wire records** (`model/wire.rs`). Every field is optional or has a default; no field is
  required. Each record is read field by field from a `serde_json::Value` rather than
  derived with serde, so a field of an unexpected type becomes `None` instead of failing the
  record, and an element that is not an object is left out of a list with a warning. Each
  record keeps the original JSON in `raw: serde_json::Value` for full views and `--json`.
  Negative or fractional values where a count is expected become `None`, with a warning that
  names the field.
- **Validated inputs** (`model/valid.rs`). A command turns a wire record into what it needs,
  with a targeted error if something is missing:
  - `CaseRef` (id required);
  - `SearchForAction` (id, `contentQuery` and `dataSourceScopes` required);
  - `PollTarget` (id and status);
  - `DownloadableFile` (`fileName` and a `downloadUrl` that passes section 4.7).

  A file with a missing `downloadUrl` still shows in `operation get`; `download` then leaves
  that file out with a `FileNotDownloadable` reason and exit 4 (section 3.5).

Because records are read by hand, no Cargo feature is added for them.

### 7.2 Helpers

The code reads each field from the JSON object with `graph_time` and `read_count` in
`model/wire.rs`, which follow the rules below; the serde forms are kept as the statement of
those rules.

```rust
pub mod graph_time {
    /// Graph timestamps. `0001-01-01T00:00:00Z`, sent for incomplete operations (Observed), and "" become None.
    pub fn option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        let raw: Option<String> = Option::deserialize(d)?;
        Ok(match raw.as_deref() {
            None | Some("") => None,
            Some(s) => DateTime::parse_from_rfc3339(s).ok()
                .map(|t| t.with_timezone(&Utc))
                .filter(|t| t.year() > 1),
        })
    }
}

/// Counts: tolerate null, negative and fractional values. `size: 0` on estimate files means unknown (Observed).
pub fn count<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Ok(match Option::<serde_json::Number>::deserialize(d)? {
        Some(n) => n.as_i64().filter(|v| *v > 0).map(|v| v as u64),
        None => None,
    })
}

pub fn null_to_default<'de, D, T>(d: D) -> Result<T, D::Error>
where D: Deserializer<'de>, T: Default + Deserialize<'de> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
```

`count` maps 0 to `None` everywhere. For item counts that loses the difference between zero
and unknown, so counts use `count_or_zero`, which keeps 0, and file sizes use `count`. An
unparseable timestamp becomes `None` rather than an error.

### 7.3 Resources

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CaseStatus { Active, Closing, Closed, #[default] Missing, Other(String) } // from String

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRecord {
    #[serde(default)] pub id: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")] pub display_name: String,
    #[serde(default)] pub description: Option<String>,
    #[serde(default, deserialize_with = "status::case")] pub status: CaseStatus,
    #[serde(default, deserialize_with = "graph_time::option")] pub created_date_time: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "graph_time::option")] pub closed_date_time: Option<DateTime<Utc>>, // Docs
    #[serde(default)] pub created_by: Option<serde_json::Value>, // read through identity::upn(&Value)
    #[serde(skip)] pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRecord {
    #[serde(default)] pub id: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")] pub display_name: String,
    #[serde(default)] pub description: Option<String>,
    #[serde(default)] pub content_query: Option<String>,
    #[serde(default)] pub data_source_scopes: Option<String>, // flags enum as comma-separated string (Docs)
    #[serde(default, deserialize_with = "graph_time::option")] pub created_date_time: Option<DateTime<Utc>>,
    #[serde(default)] pub created_by: Option<serde_json::Value>,
    #[serde(skip)] pub raw: serde_json::Value,
}
```

`raw` is filled by a wrapper that deserialises from a `Value`, clones it, and parses the
record from the clone. Identities stay as `Value` so that new fields survive into JSON
output. `identity::upn` and `identity::display_name` read them.

### 7.4 Operations

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OperationStatus { NotStarted, Running, Succeeded, PartiallySucceeded, Failed, SubmissionFailed, #[default] Missing, Other(String) }

impl OperationStatus {
    pub fn is_terminal(&self) -> bool { !matches!(self, Self::NotStarted | Self::Running) }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationRecord {
    #[serde(rename = "@odata.type", default)] pub odata_type: Option<String>,
    #[serde(default)] pub id: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")] pub action: String,
    #[serde(default, deserialize_with = "status::operation")] pub status: OperationStatus,
    #[serde(default, deserialize_with = "count_or_zero")] pub percent_progress: Option<u64>,
    #[serde(default, deserialize_with = "graph_time::option")] pub created_date_time: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "graph_time::option")] pub completed_date_time: Option<DateTime<Utc>>,
    #[serde(default)] pub created_by: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "result_info::tolerant")] pub result_info: Option<ResultInfo>, // Docs; the prototype read it
    #[serde(skip)] pub raw: serde_json::Value,
}

/// Graph documents `code` and `subcode` as Int32 (Docs). `tolerant` reads the field as a `Value`,
/// keeps it in `raw`, and fills each member only when it has the expected type; a member of any
/// other type becomes None, so an unexpected shape never hides the operation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResultInfo { pub code: Option<i32>, pub subcode: Option<i32>, pub message: Option<String>, pub raw: serde_json::Value }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source { List, Single }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Action { Estimate, ExportReport, ExportResult, ExportReportOrResult, Other(String) }

impl OperationRecord {
    /// The list shows exportReport as "exportResult" (Observed); only the single GET tells them apart.
    pub fn action(&self, source: Source) -> Action {
        match (self.action.as_str(), source) {
            ("estimateStatistics", _) => Action::Estimate,
            ("exportReport", _) => Action::ExportReport,
            ("exportResult", Source::Single) => Action::ExportResult,
            ("exportResult", Source::List) => Action::ExportReportOrResult,
            (other, _) => Action::Other(other.to_owned()),
        }
    }
    /// Dispatch on `@odata.type` (Observed on single GETs); None when absent, as in list entries.
    pub fn detail(&self) -> Option<OperationDetail>;
}

pub enum OperationDetail { Estimate(EstimateDetail), SearchExport(ExportDetail) }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimateDetail {               // "#microsoft.graph.security.ediscoveryEstimateOperation" (Observed)
    #[serde(default, deserialize_with = "count_or_zero")] pub indexed_item_count: Option<u64>,
    #[serde(default, deserialize_with = "count_or_zero")] pub indexed_items_size: Option<u64>,
    #[serde(default, deserialize_with = "count_or_zero")] pub unindexed_item_count: Option<u64>,
    #[serde(default, deserialize_with = "count_or_zero")] pub unindexed_items_size: Option<u64>,
    #[serde(default, deserialize_with = "count_or_zero")] pub mailbox_count: Option<u64>, // locations with hits
    #[serde(default, deserialize_with = "count_or_zero")] pub site_count: Option<u64>,
    #[serde(default)] pub report_file_metadata: Vec<FileRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDetail {                 // "#microsoft.graph.security.ediscoverySearchExportOperation" (Observed)
    #[serde(default)] pub display_name: Option<String>,
    #[serde(default)] pub description: Option<String>,
    #[serde(default)] pub export_criteria: Option<String>,
    #[serde(default)] pub export_location: Option<String>,
    #[serde(default)] pub additional_options: Option<String>,
    #[serde(default)] pub export_format: Option<String>, // shown, never used to decide the action
    #[serde(default)] pub export_file_metadata: Vec<FileRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    #[serde(default)] pub file_name: Option<String>,
    #[serde(default, deserialize_with = "count")] pub size: Option<u64>,
    #[serde(default)] pub download_url: Option<String>, // validated into DownloadableFile at download time
}
```

The trace showed `exportFormat: "pst"` on `exportReport` operations (Observed (trace)). The
action therefore comes only from `action` on the single GET, which the notes support.

### 7.5 Request bodies

```rust
/// Serialises only as "allTenantMailboxes".
#[derive(Debug, Clone, Copy, Default)]
pub struct AllTenantMailboxes;
impl Serialize for AllTenantMailboxes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str("allTenantMailboxes") }
}

#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct CreateCase<'a> { pub display_name: &'a str, pub description: &'a str }

#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct CreateSearch<'a> {
    pub display_name: &'a str, pub description: &'a str, pub content_query: &'a str,
    pub data_source_scopes: AllTenantMailboxes,
}

#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct EstimateRequest { pub statistics_options: &'static str } // "includeQueryStats"

#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct ExportReportRequest<'a> {
    pub display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")] pub description: Option<&'a str>,
    pub export_criteria: &'static str,  // "searchHits"
    pub export_location: &'static str,  // "responsiveLocations"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_options: Option<&'static str>, // Some("teamsAndYammerConversations") by default
}

#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct ExportResultRequest<'a> {
    pub display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")] pub description: Option<&'a str>,
    pub export_criteria: &'static str,
    pub export_location: &'static str,
    pub additional_options: &'static str, // "teamsAndYammerConversations,includeReport" or "includeReport"
    pub export_format: MsgFormat,         // serialises only as "msg"
}
```

### 7.6 Report and export types

```rust
pub struct LocationRow { pub location: String, pub location_id: Option<String>, pub location_type: String,
                         pub sub_type: String, pub count: Option<u64>, pub size: Option<u64>, pub status: String,
                         pub error_warning: Option<String> }
pub struct FailedLocation { pub location: String, pub sub_type: String, pub message: String }
pub enum Collection { Complete, Incomplete { failed: usize }, Unchecked }
pub struct SummaryFile { pub groups: Vec<Vec<Vec<String>>>, pub values: BTreeMap<String, String> }
pub struct SlimItem { pub class: String, pub date: Option<DateTime<Utc>>, pub sender: Option<String>,
                      pub title: Option<String>, pub conversation_type: Option<String>, pub recipient_count: Option<u32>,
                      pub workload: Option<String>, pub has_attachment: Option<bool>,
                      pub internet_message_id: Option<String>, pub immutable_id: Option<String>,
                      pub target_path: Option<String> }
pub struct UniqueAgg { pub first: SlimItem, pub copies: u32, pub locations: Vec<u32> }
pub enum KeyKind { InternetMessageId, ImmutableId, Hash }
pub struct ExportJoinRow { pub part: String, pub entry: String, pub row: SlimItem }
pub fn normalise_target_path(p: &str) -> Option<(String /* part */, String /* entry */)>;
```

### 7.7 Message types (phase 5)

```rust
pub struct MsgItem {
    pub class: Option<String>, pub subject: Option<String>, pub internet_message_id: Option<String>,
    pub from: Option<Mailbox>, pub to: Vec<Mailbox>, pub cc: Vec<Mailbox>, pub bcc: Vec<Mailbox>,
    pub sent: Option<DateTime<Utc>>, pub received: Option<DateTime<Utc>>,
    pub headers: Option<String>, pub body: Option<Body>, pub attachments: Vec<AttachmentInfo>,
}
pub struct Mailbox { pub name: Option<String>, pub address: Option<String> }
pub enum Body { Html(String), Text(String), RtfOnly }
pub struct AttachmentInfo { pub name: Option<String>, pub size: Option<u64> }
pub fn parse_msg(bytes: &[u8]) -> Result<MsgItem, MsgError>; // pure, no I/O
```

---

## 8. Testing and fixtures

### 8.1 Rules and the fixture lint

- Only synthetic data:
  - `contoso.example` and `fabrikam.example` addresses;
  - GUIDs of the form `00000000-0000-4000-8000-0000000000NN`;
  - operation ids such as `aaaaaaaa…0001`.
- No real credential store (tests use an in-memory `CredentialStore`) and no live Graph.
- Real traces are never copied into fixtures. Fixtures are written by hand from the
  documented shapes.
- **Public-data lint.** `tests/fixture_lint.rs` scans every tracked file under `tests/`,
  `docs/`, `contrib/`, `README.md`, `SKILL.md`, `AGENTS.md` and `CHANGELOG.md`. It fails on:
  - a GUID that is not synthetic and not one of the allowed Microsoft constants (Graph app
    id, eDiscovery app id, the published scope ids, the zero role id);
  - an email address outside `*.example`;
  - a URL whose host and path, compared separately, do not match an allowed pair:

    | Host | Allowed paths |
    |---|---|
    | `graph.microsoft.com` | `/v1.0/…`; an empty path or `/`; permission-scope paths (`/<Name>.<Name>…`, `/.default`) |
    | `login.microsoftonline.com` | any |
    | `*.proxyservice.ediscovery.svc.cloud.microsoft` | `/ediscovery/api/proxy/…` |
    | `learn.microsoft.com` | any |
    | `aka.ms` | any |
    | `github.com` | `/aberoham/…` only |
    | `img.shields.io` | `/github/…` only, with the exact owner/repository pair `aberoham/ms-purview-cli` or `aberoham/ms-entra-cli` as consecutive path segments |
    | `*.example`, `localhost`, `127.0.0.1` | any |

  - **the presence of `docs/reviews/`**, or of any file that names the maintainer's private
    notes or prototype by path. Review history is private and lives outside the published
    tree.
- The lint runs in its own workflow, `public-data.yml`, on every pull request and push to
  `main`, including docs-only changes. `ci.yml` keeps ignoring Markdown, but this workflow
  does not.

### 8.2 Harness

- **`Env`** (`#[doc(hidden)] pub`) carries:
  - the Graph origin and base URL;
  - the token endpoint;
  - the download host pattern and port rule;
  - the credential store, clock, stdin, stdout and stderr, and whether each is a terminal.

  `cli::execute_with(Env, args) -> Outcome` runs the whole command in-process. The release
  binary builds `Env::production()` and reads no environment variable that could change an
  endpoint, so the binary has no test path that could send a token to another host.
- **Origins.** Graph, the token endpoint, the download origin and "foreign" origins each run
  as a separate `wiremock::MockServer` on its own port. `Env` carries a resolver map, passed
  to `reqwest::ClientBuilder::resolve`, so test hostnames reach those listeners. The test
  `Env` also allows `http` for the download scheme.
  - **Sibling-host case.** Two distinct hostnames that both match the production host
    pattern, `alpha.proxyservice.ediscovery.svc.cloud.microsoft` and
    `beta.proxyservice.ediscovery.svc.cloud.microsoft`, map to two listeners. The operation
    names `alpha`; a redirect points to `beta`. The test asserts zero requests at the `beta`
    listener.
  - **Changed-port case.** The same hostname on a second listener's port; the test asserts
    zero requests there.
- **Replay.** `support/replay.rs` mounts an `exchanges/*.json` sequence. Successive polls
  return successive states (`up_to_n_times(1)` with priorities).
- **Generators.**
  - `support/zipgen.rs` builds zips from CSV text.
  - `support/msggen.rs` builds `.msg` files with `cfb`'s writer.
  - `support/items_header.rs` builds a 162-column `Items` header from the observed column
    names plus synthetic `Unobserved column NN` names, so the parser cannot depend on the
    column count or positions.

  The repository holds no binary zips and no binary `.msg` files.

### 8.3 Fixture files

```text
tests/fixtures/graph/
  cases-list.json                 active, closing and closed cases; a duplicate name across statuses; one entry with null displayName; one without id
  cases-list-page1.json, -page2.json
  cases-list-foreign-nextlink.json
  case-get.json                   with the marker in the description
  case-create-201.json
  searches-list.json
  search-get-mailboxes.json       dataSourceScopes "allTenantMailboxes"
  search-get-no-scope.json        dataSourceScopes absent
  search-get-sites.json           "allTenantMailboxes,allTenantSites"
  search-get-portal-generic.json  contentQuery "retention"
  search-sources-empty.json, search-sources-one.json
  search-create-201.json
  operations-list.json            base fields only; exportReport shown as "exportResult"; placeholder completedDateTime
  operation-estimate-running.json, -succeeded.json   (size 0, ?downloadType=Report)
  operation-exportreport-succeeded.json, operation-exportresult-running.json
  operation-exportresult-succeeded.json              two files
  operation-partially-succeeded.json, -failed.json, -submission-failed.json   (shapes: Assumption, with numeric resultInfo code and subcode)
  operation-failed-resultinfo-strings.json   (resultInfo code as a string: the operation still parses, code becomes None, raw kept)
  operation-unknown-status.json
  operation-missing-id.json, operation-file-missing-url.json, operation-negative-count.json
  action-202-keyform.json, action-202-pathform.json, action-202-wrong-case.json, action-202-foreign-host.json
  case-holds-empty.json (custodians, noncustodialDataSources, legalHolds), case-holds-one.json, case-holds-paged.json
  error-403.json, error-404.json, error-429.json, error-503-retry-after-date.json, error-401.json
tests/fixtures/auth/
  device-code.json, token-graph.json, token-download.json (rotated refresh token), token-poll-window.json (expires_in 360: valid past the 5-minute pre-POST threshold, so the POST goes out without a refresh, then expires during polling)
  id-claims-preferred.json, id-claims-upn-only.json, id-claims-none.json   (JWTs built at runtime)
  aadsts65001.json, aadsts65002.json, authorization-pending.json
tests/fixtures/zips/estimate/      Locations.csv (BOM, primary/archive/system, two Failed), Statistics.csv, Summary.csv, Settings.csv
tests/fixtures/zips/report-small/  Items_0.csv rows (header generated), Locations.csv with one Failed, Summary.csv with all tables, Settings.csv
tests/fixtures/zips/report-multi/  Items_0, Items_1, Items_2, Items_10 rows
tests/fixtures/zips/no-bom/        Locations.csv
tests/fixtures/zips/hostile/       manifest for generated zips: "../evil.csv", 1,001 entries, 2,000:1 entry, lying header size, 70 MiB record
tests/fixtures/export/             report Items_0.csv with Target path rows (one missing part, one duplicate, one unjoined), entries list for the items zip
tests/fixtures/msg/                generator specs: HTML-only with VML text, text-only, UTF-16 HTML, cp1252 binary HTML, quoted history,
                                   Teams message, Teams system message, RTF-only, broken sector chain, recipients and attachments, headers
tests/fixtures/exchanges/          estimate-flow, report-flow, export-flow, token-expiry-mid-poll, post-timeout-reconcile
```

### 8.4 Unit tests

- **KQL** (one table for builder and raw forms):
  - every grammar production, and every refused construct (juxtaposition, lowercase
    operators, `NEAR`, `-x`, `property:(…)`, `body:`, wildcard inside a word, `*` in an
    address, unbalanced quotes and parentheses);
  - every classification rule, including `RETENTION` (generic), `PagerDuty` (specific),
    `"2025 contract"` (generic), `"follow-up meeting"` (generic) and `"orders-api migration"`
    (specific);
  - config precedence;
  - every verdict row of section 6.3;
  - `--allow-generic` without `--reason`, or with a blank reason, refused;
  - `--allow-generic` with a parse error refused.
- **Origins and redaction:**
  - exact-origin equality: scheme, host, port, user information, trailing dot;
  - the download host pattern;
  - `redact::url` keeps only the allowed query keys;
  - the Redactor replaces live secrets and JSON Web Tokens.
- **`Location`:** key form and path form, mixed case, a wrong case id, a foreign host and a
  malformed operation id each give the expected result or error.
- **Routes:** `WriteRoute::ALL` equals the six pairs; the source scan finds no
  `PATCH`/`PUT`/`DELETE`.
- **Model:**
  - placeholder date and seven-digit fractions;
  - size 0, negative and fractional counts;
  - null `displayName`; missing `id` in a list does not fail the list;
  - action resolution for list and single GET;
  - `exportFormat: "pst"` on a report does not change its action;
  - `detail()` with and without `@odata.type`;
  - `resultInfo`;
  - `raw` keeps unknown fields, including inside identities.
- **Polling** (fake clock):
  - each status;
  - the deadline enforced during a long `Retry-After` and during a request that hangs;
  - 404 grace only for fresh submissions;
  - Ctrl-C;
  - the interval schedule.
- **Tokens:**
  - lazy refresh at 60 s, and at 5 minutes before a POST;
  - one refresh shared by concurrent callers;
  - a 401 on GET triggers one refresh and one retry;
  - the download token is fetched only after polling;
  - a missing `download` entry triggers one silent refresh;
  - `Debug` of every secret-holding type shows `[redacted]`.
- **File names:** Unicode cut on a character boundary, `.zip` kept, Windows characters and
  reserved names, collisions, `..`.
- **Zip:** each hostile case is refused by the actual-byte counters, and the export entry
  limit is separate from the report limit.
- **CSV:** BOM present and absent; two-field rows; a record over budget; numeric `Items_N`
  order; named missing columns; Summary groups and dates.
- **Items:** dedup key preference; hash fallback counted; copies and distinct locations
  across files; `--max-unique`.
- **Profile:** classes, thread-id senders, domain aliases, local-part merging only within
  internal domains, Teams titles, UTC buckets, filters.
- **Estimate parsing:** the union of failure sources; `Collection` values.
- **Export join:** `normalise_target_path`; duplicate, missing-part and unjoined counts.
- **Naming:** each variable; `{requester}` falls back to `{user}`; unknown variables
  refused.
- **Safety:** plan contents; the digest matches the bytes sent; `--dry-run` wins over
  `--yes`; a read-only session refuses writes; `--allow-concurrent` is needed when a possible
  duplicate exists.

### 8.5 In-process flows (`tests/flows.rs`)

Each flow runs through `cli::execute_with` against separate mock origins.

1. **`case create`:** a name used by a closed case is refused; success with `--yes`; exit 3
   without it; the body is checked byte for byte.
2. **`search create`:** a guard refusal sends no request; success; no request reaches any
   custodian, source or hold path with a method other than `GET`.
3. **Actions on existing searches:**
   - a search without a scope and one with a sites scope are refused;
   - a portal search with a generic query is refused, then accepted with a reason;
   - a search with sources is refused.
4. **`estimate`:**
   - POST, then polls, then download;
   - the download carries the download token and `X-AllowWithAADToken`;
   - the Graph token never reaches the download origin, and the download token never reaches
     Graph;
   - failed locations give `collection: incomplete`, and `--strict` gives exit 4;
   - `--no-download` gives `unchecked`; `--strict` with `--no-download` or `--no-wait` is
     refused by Clap;
   - the same three collection paths are tested for `report` and `export create`, including
     a report zip without `Locations-*.csv`, which gives `unchecked`, or exit 4 under
     `--strict`.
5. **Token expiry mid-poll.** The flow starts with `token-poll-window.json`, so the POST goes
   out with no refresh. The fake clock then moves past expiry during polling, and the test
   asserts:
   - one token-endpoint refresh before the next poll;
   - zero requests at the download listener until `succeeded` (the operation-metadata GETs
     go to Graph and are not counted);
   - the download-token request comes after the last poll.
6. **Download:**
   - 401;
   - a same-origin redirect is followed;
   - a redirect to a sibling host, a changed port or `http` is refused, and the foreign mock
     records zero requests;
   - a truncated body leaves no final file and no temporary file;
   - a size overrun is aborted;
   - an existing target without `--overwrite` is refused before any request;
   - a symlink target is refused;
   - a file created under the final name by another writer while the download runs is kept,
     and the command gives `TargetAppeared`;
   - a manifest write failure after publication gives `ManifestWriteFailed`, and the next
     run recovers the entry;
   - `operation get --check` followed by `download` fetches the evidence file once.
7. **POST timeout:** exactly one POST is recorded; the candidate list is printed; exit 1
   with `WriteOutcomeUnknown`. The same holds for 503 with `Retry-After` and for 429.
8. **`case close`:**
   - refused when holds exist;
   - refused when a hold list has a second page that fails;
   - refused without the marker;
   - typed confirmation through injected stdin;
   - a POST timeout reconciles through `GET` on the case;
   - a `--wait` deadline gives the case-close timeout shape.
9. **`operation list`:** `--action report` without `--resolve` is refused.
10. **Canary sweep.** Flows 4 to 7 run with canary tokens and `--trace` and `--verbose` on.
    Then stdout, stderr and every file under the trace, config and data directories are
    scanned.
11. **Exit-code shapes.**
    - For document-producing commands, exit 0 (including writes and dry runs), 3, 4, 5 and
      130 each give exactly one parseable JSON document on stdout, in the shape section 3.3
      gives.
    - For JSONL commands with a partial failure, stdout holds one valid record per line and
      no trailing error document, and the reasons are on stderr.
12. **Parse pool window** (phase 5). The first item is made slow and the next 1,000 fast.
    The test asserts that no more than `2 × jobs` items are ever admitted and not yet
    written.
13. **`export index` without a report** exits 0 with `joined: null` on every record.

### 8.6 Process tests (`tests/cli.rs`, `assert_cmd`)

Offline contracts only, as in `entra`:
- `version`;
- argument errors as JSON;
- `--no-write` refuses before sign-in;
- `kql` verdicts and exit codes;
- `parse` on generated zips with an empty config directory;
- `export read` refuses a terminal stdout (the test sets a terminal flag through
  `execute_with`, so this one lives in `flows.rs`).

### 8.7 Body reader tests (phase 5)

- Each `msggen` case gives the expected record.
- VML style text never appears in `body`.
- A cp1252 HTML body decodes correctly.
- `--cut-quoted` and `--thread-dedup` give the same results for `--jobs 1` and `--jobs 8`.
- A broken container gives `cfbInvalid`, and the run continues with exit 4.
- **Memory test** (ignored by default): 20,000 generated items of about 300 KB, spread over
  three items zips, read with peak resident memory under 300 MB.
- **CI cross-check:** `contrib/msg-bodies.py` runs on the generated zip. Subject, sender,
  sent date and normalised body text must match the Rust reader, apart from the documented
  `unsupportedClass` cases.

---

## 9. Documentation set

- **`README.md`:** what the tool finds, with commands; a sample `parse locations` table on
  `contoso.example`; Platforms; Why it exists; Install (Homebrew `aberoham/tap/purview`,
  Windows checksum steps, from source); Set up; Safety; Documentation; Licence.
- **`docs/auth.md`:**
  - permissions table and the Purview role;
  - app registration, by hand and with the script, including the script's dry-run and
    `--apply` contract;
  - consent choices;
  - sign-in flows;
  - token storage;
  - the two-resource refresh, and why `auth refresh` never changes scopes;
  - `AADSTS65001` and `AADSTS65002`;
  - environment variables;
  - Microsoft references.
- **`docs/api-notes.md`:**
  - the observed behaviour, each entry labelled and dated;
  - ratios, timings and orders of magnitude, never one tenant's counts;
  - the "not yet observed" list from section 12.

  Every PR that depends on a new observation updates it.
- **`docs/command-reference.md`:** every command with its class, required permission,
  flags, output columns (the source for `--select`), exit codes and JSON shapes.
- **`docs/safety.md`:** section 6 in full, including the KQL grammar, the classifier rules,
  the built-in generic list and the known errors.
- **`docs/troubleshooting.md`:**
  - 401 on download;
  - 403 without the role;
  - `ScopeUnverified`;
  - `WriteOutcomeUnknown`;
  - `closing` status;
  - credential-store prompts after an upgrade;
  - device code blocked by Conditional Access;
  - a run that succeeded with failed locations;
  - `CrossOriginRedirect`.
- **`docs/macos-signing.md`:** copied from `entra`, with identifier `com.aberoham.purview`.
- **`SKILL.md`** (`name: purview-cli`, generic). It tells the agent to:
  - ask the requester before creating a case;
  - search the whole tenant only for exact system or vendor names, and use generic words
    only with `--participant`;
  - never place holds;
  - use the naming templates, and close the case when the question is answered;
  - keep Teams context on, and narrow with terms and participants;
  - check `collection` before trusting a count;
  - deduplicate before counting;
  - run `--dry-run`, show the plan, then `--yes`;
  - send `export read` output to a file in the data directory, and hand over summaries and
    references rather than message text.
- **`AGENTS.md`:** structured as `entra`'s:
  - data rules for a public repository, and the public-data lint; review history and
    private notes stay outside the published tree;
  - the architecture map;
  - output contracts and exit codes;
  - transport guarantees, including origins and the no-POST-retry rule;
  - the write allow list and how to change it;
  - credential compatibility;
  - verification commands;
  - "a passing suite does not show the tenant behaves this way; report live checks
    separately and update `docs/api-notes.md`".
- **`CHANGELOG.md`:** as in `entra`.

---

## 10. Release, CI and dependencies

All workflows pin actions by SHA, set `permissions: contents: read` (raised per job only
where needed) and use `persist-credentials: false`. Each sets a `concurrency` group with a
workflow-specific prefix, as `entra`'s do. A newer push cancels an older CI run; release
runs are never cancelled.

**`ci.yml`.** It runs on pushes to `main` and on pull requests, ignoring `**.md` and
`docs/**`.
- **`quality`:**
  - `cargo fmt --check`, `cargo check --all-targets --locked`,
    `cargo clippy --all-targets --locked -- -D warnings`;
  - `actionlint` and `zizmor`;
  - from PR 1.2: `shellcheck contrib/*.sh` and the fake-`az` provisioning tests;
  - from PR 1.7: the signing-script test.
- **`test`:** a matrix of Ubuntu, macOS and Windows, running
  `cargo test --all-targets --locked` and `cargo build --release --locked`.
- **`msg-crosscheck`** (from PR 5.3): Ubuntu, `astral-sh/setup-uv` pinned by SHA, runs
  `contrib/msg-bodies.py` on the generated zips and compares.

**`public-data.yml`** (from PR 0.1). It runs on every pull request and every push to `main`,
with no path filter, so docs-only changes are checked. It runs the public-data lint only
(section 8.1).

**`release.yml`** (tag `v*`, from PR 1.7):
1. Verify the tag against the `Cargo.toml` version.
2. Call CI and the public-data lint.
3. Build `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`,
   `aarch64-unknown-linux-musl` and `x86_64-pc-windows-msvc`. Check that the Linux binaries
   are statically linked.
4. Package `bin/purview` and `share/doc/purview/`: `README.md`, `LICENSE`, `NOTICE`,
   `CHANGELOG.md`, `docs/` (without anything private; the lint has already refused
   `docs/reviews/`), and `contrib/create-purview-app.sh` (plus `contrib/resign.sh` in the
   Unix archives).
5. Smoke-test each archive with the commands that release ships (section 11 lists them per
   release), and run them again on the signed Apple silicon binary after notarisation.
6. Sign the macOS builds, as `entra` does:
   - Developer ID, stable identifier `com.aberoham.purview`, hardened runtime and a secure
     timestamp;
   - a temporary keychain under `RUNNER_TEMP`, always removed;
   - signing fails closed if credentials are missing or the signature does not match the
     configured team and identity;
   - notarisation with the team API key, which fails unless Apple returns `Accepted`.
7. Generate checksums, attest build provenance and publish the release.

**Release protection.** This is server-side setup, applied before the workflow is enabled.
`docs/macos-signing.md` records it as `entra`'s does:
- a `release` environment holds the signing and notarisation secrets, restricted to
  release tags, requiring the maintainer's approval, with administrator bypass disabled;
- a ruleset restricts creating, updating or deleting `v*` tags to administrators.

The `aberoham/homebrew-tap` formula `purview` reads releases, as it does for `entra`.

**Cargo dependencies.** Added in the PR that first uses each one:

| Crate | Features | From |
|---|---|---|
| `clap` | `derive`, `env` | 0.1 |
| `serde` | `derive` | 0.1 |
| `serde_json` | (default features) | 0.1 |
| `thiserror` | | 0.1 |
| `tokio` | `rt-multi-thread`, `macros`, `time`, `net`, `io-util`, `fs`, `signal`; `sync` added in 1.1 with the token provider's mutex | 0.1 |
| `dirs` | | 0.1 |
| `keyring` | `apple-native`, `linux-native`, `windows-native` | 1.1 |
| `security-framework` (macOS) | | 1.1 |
| `reqwest` | `json`, `rustls-tls`, `gzip`; no default features. `stream` is added in 1.5 with the download client, which turns gzip off | 1.1 |
| `url`, `uuid`, `chrono` | (default features); add `serde` only where a later PR serialises one of these types | 1.1 |
| `base64` | | 1.1 |
| `async-trait` | | 1.1 |
| `sha2` | | 1.1 (account lock file names) |
| `getrandom` | | 1.2 (PKCE) |
| (no browser crate) | `auth login --browser` runs the platform's opener (`open`, `rundll32 url.dll,FileProtocolHandler`, `xdg-open`) with null standard streams, so a browser cannot write into the command's output | 1.2 |
| `zip` | no default features; `deflate-flate2-zlib-rs` only, which reads and writes deflate without the compression-only `zopfli` that `deflate` adds (plus `deflate64` only if PR 4.1 finds it) | 1.5 |
| `regex` | | 1.6 |
| `csv` | | 2.3 |
| `cfb` | | 5.1 |
| `crossbeam-channel` | | 5.2 |
| `encoding_rs` | | 5.2 |
| `html2text` | | 5.2 |

Dev-dependencies: `wiremock`, `assert_cmd`, `predicates`, `tempfile`.

The release profile is `lto = true`, `codegen-units = 1`, `strip = true`. `Cargo.toml` declares the
minimum Rust version; local rustup builds and CI use the release pinned in
`rust-toolchain.toml`, raised in its own pull request.

---

## 11. Phased implementation plan

Each PR comes with its tests and documentation, runs the `AGENTS.md` verification set, and
gets an independent review before it opens. A "live check" is run by the maintainer on a test
tenant. Its results go into `docs/api-notes.md` and synthetic fixtures, never as traces. If a
live check a feature depends on cannot be done, the feature is left out of that release.

### Phase 0: scaffold

**PR 0.1: Skeleton.**
- Scope: `Cargo.toml`, `main.rs`, `lib.rs`, `env.rs`, `cli.rs` with `version` only,
  `error.rs`, `output.rs`, `config.rs`, `redact.rs`, LICENSE and NOTICE, `AGENTS.md`,
  `ci.yml`, `public-data.yml` and the lint. No stubs for later commands.
- Tests: version contract; JSON argument errors; fixture lint; Redactor units.
- Acceptance: CI passes on three operating systems.

### Phase 1: core read paths

**PR 1.1: Credentials and device-code sign-in.**
- Scope: `secrets.rs`, `token.rs`, `auth.rs` (device code, two-resource redemption, id-token
  claims); `auth login`, `auth refresh`, `auth list`, `auth logout`; `--read-only`.
- Also: create `docs/api-notes.md` with the observations already made (section 12.4
  sources, in public form) and this PR's sign-in check. Every later live check appends to it.
- Tests: token endpoint mocks, rotation, `AADSTS65001` on the download resource, claim
  fallbacks, `SecretString`, in-memory store.
- Acceptance: live check of sign-in with both tokens stored.

**PR 1.2: Browser sign-in and provisioning.**
- Scope: `--browser` with PKCE; `contrib/create-purview-app.sh` with dry-run and `--apply`;
  `docs/auth.md`; the `shellcheck` and fake-`az` CI steps.
- Tests: PKCE units; fake-`az` script tests (section 5.2).
- Acceptance: live check that `--browser` works with the loopback redirect, and that the
  script's dry run on a test tenant changes nothing.

**PR 1.3: Transport, trace and `auth status`.**
- Scope: `origin.rs`, `graph.rs` (GET, paging, retry), `routes.rs` (`ReadRoute`, and the
  `WriteRoute` enum with its allow-list test), `trace.rs`; `auth status`. `send_write`
  arrives in PR 2.1.
- Tests: origins, retries, paging, the routes test, trace redaction, the first canary sweep.
- Acceptance: live `auth status`.

**PR 1.4: Read commands, model, polling, and observations.**
- Scope: `model/`, `poll.rs`; `case list`, `case get`, `search list`, `search get`,
  `operation list`, `operation get` with `--wait` (`--check` arrives in 2.3); Ctrl-C;
  `--wrap-untrusted` for case and search fields.
- Live checks, all read-only, recorded in `docs/api-notes.md`:
  - whether `GET` on a search returns `dataSourceScopes`;
  - the three search source reads;
  - `$expand=search` on operations;
  - a missing role gives 403;
  - a `--read-only` session can list and get. This says nothing about actions. (Observed:
    it can, and its token still carried `eDiscovery.ReadWrite.All`, because the identity
    platform grants every consented scope; see `docs/api-notes.md`.)

  The `Location` form is not checked here: an existing operation cannot reproduce the
  original 202 header. PR 2.3 checks it.
- Tests: model, polling, `operation list` refusal. The read flows live in `tests/reads.rs`,
  and the `Poller` tests over a mock Graph in `tests/graph.rs`.
- Acceptance: tables and JSON match the fixtures; the observations are recorded.

**PR 1.5: Download.**
- Scope: `download.rs`, `purview download`, temporary-file publishing, manifest, file names;
  adds `zip` (deflate through `flate2`) for the central-directory check.
- Tests: download flows (section 8.5, item 6), file names, canary sweep.
- Acceptance: live download of an existing estimate file with redirects disabled; whether a
  redirect happened is recorded. (Observed: none; the proxy answered 200 directly. See
  `docs/api-notes.md`.)

**PR 1.6: KQL parser and guard.**
- Scope: `kql/`; `purview kql`; `docs/safety.md` (guard section).
- Tests: the KQL table (section 8.4).
- Acceptance: every v1 bypass from the reviews is a test that now fails the guard.

**PR 1.7: Release pipeline and documents.**
- Scope: `release.yml` with the signing, hardening and protection rules in section 10;
  `.github/scripts/` signing helper and its CI test; `contrib/install.sh` and
  `contrib/resign.sh`; `docs/macos-signing.md`; `docs/troubleshooting.md`; the tap formula PR
  in `aberoham/homebrew-tap`.
- Acceptance: the `release` environment and tag ruleset are in place; a pre-release tag
  builds, signs, notarises and smoke-tests.

**Release v0.1.0** (read-only). Smoke test: `purview version`, `purview --help`,
`purview kql --term orders-api --participant alex@contoso.example`.

### Phase 2: writes

**PR 2.1: Safety framework.**
- Scope: `safety.rs`, `WritePlan`, approval, `ApprovedWrite` and
  `GraphClient::send_write`; `--yes`, `--dry-run`, `--no-write` with `WriteRefused`; the
  write-success envelope and exit 3 JSON; read-only refusal; `naming.rs`.
- Tests: section 8.4 safety; a stub write in tests only proves no POST is sent before
  approval, and that an expired-token dry run refreshes without a Graph write.

**PR 2.2: `case create` and `search create`.**
- Scope: preflight, name checks, the guard on create, the body checks, reconciliation for
  unclear outcomes.
- Tests: flows 1, 2 and 7.
- Acceptance: live creation of a case and a search.

**PR 2.3: Action preflight, `estimate` and estimate parsing.**
- Scope: section 6.4 preflight; section 6.7 concurrency check; `estimate`;
  `operation get --check`; `report/csvread.rs`, `estimate.rs`, `summary.rs`;
  `parse locations`, `parse failures`, `parse summary`; `Collection`.
- Tests: flows 3, 4 and 5; CSV and estimate units.
- Acceptance: a live estimate gives `collection` and failed locations. The live 202's
  `Location` header form is recorded in `docs/api-notes.md`. If it matches neither accepted
  form, the actions stay unreleased until the parser is updated.

**PR 2.4: `report`.**
- Scope: `exportReport` with Teams context on; `collection` from `Locations`; the row-count
  warning.
- Tests: report flow.
- Acceptance: a live small report is downloaded.

**PR 2.5: Observation: report without Teams context.**
- Scope: live check only. Run `exportReport` with no `additionalOptions` and record the
  result. If it works, `--no-teams-context` leaves experimental status for `report`;
  otherwise the flag is removed from `report`.

**PR 2.6: Observation: close and hold reads.**
- Scope: live check only, on a case created by the tool.
  - Run the three hold reads and confirm they return an empty `value`.
  - Run `POST …/close` and record the status code and body, and the time from `closing` to
    `closed`.
- The PR does not call `reopen`. A case closed by mistake is reopened by hand in the portal,
  outside the tool.

**PR 2.7: `case close`.**
- Scope: preflight, typed confirmation, `--wait`. Holds are refused whenever `value` is not
  empty, so no shape of a non-empty response is needed.
- Tests: flow 8.
- Acceptance: a live close of a case created by the tool.

**Release v0.2.0.** Smoke test:
- the v0.1.0 commands;
- `parse summary` on a bundled synthetic estimate zip;
- `purview --no-write --json case create --topic smoke`, which must exit 1 with
  `error.code` equal to `WriteRefused`, so an argument error cannot pass for a refusal.

If PR 2.6 cannot be completed, v0.2.0 ships without `case close`.

### Phase 3: item report parsing

**PR 3.1: Item reader.**
- Scope: `items.rs`, the dedup aggregation, filters, `parse items` with `--all-rows` and
  `--max-unique`.
- Tests: items units; a 200,000-row generated file in under 10 s (ignored by default).
- Acceptance: on the maintainer's private large report, unique counts match the earlier
  Python analysis. Checked locally and reported; nothing is committed.

**PR 3.2: Profile.**
- Scope: `profile.rs`, `parse profile`, `identity` config, `report --profile`,
  `--wrap-untrusted` on item fields.
- Tests: profile units.

**Release v0.3.0.** Smoke test adds `parse items` and `parse profile` on a bundled
synthetic report zip.

### Phase 4: export and index

**PR 4.1: `export create` and several-part downloads.**
- Scope: the `exportResult` body; downloads of `Items.*.zip` parts; the manifest linking
  report and parts.
- Live checks:
  - `includeReport` without Teams context;
  - `Range` support;
  - whether `downloadUrl` expires (download again after 1 hour and after 24 hours);
  - a download that outlasts its token;
  - compression methods and Zip64 in a real items zip, recorded without contents.
- Conditional deliverable: if the proxy honours `Range`, `download --resume` continues a
  partial temporary file, checked against the final size and SHA-256. If it does not, the
  flag is not added, and `docs/api-notes.md` says so.
- Tests: export flow; a generated 3 GB stream at constant memory (ignored by default);
  resume tests only if `Range` works.

**PR 4.2: `export index`.**
- Scope: `export/join.rs`, `export/index.rs`, and the export zip entry limit.
- Tests: join units and the export fixtures; with a report, partial-failure fixtures give
  exit 4 with the counts; without one, the listing exits 0 (flow 13).
- Acceptance: on the maintainer's private export, every row joins, checked locally.

**Release v0.4.0.** Smoke test adds `export index` on a bundled synthetic export.

### Phase 5: reading message bodies

**PR 5.1: MAPI reader.**
- Scope: `msg/cfbread.rs`, `msg/props.rs`, headers and addresses (no bodies); records the
  `cfb` version and its release date.
- Tests: the property tests from `msggen`.

**PR 5.2: Bodies and `export read`.**
- Scope: `msg/body.rs`, `export/read.rs` with the admission window and reorder buffer,
  `--cut-quoted`, `--thread-dedup`, `--jsonl`/`--json`, the stderr summary, and the refusal
  of terminal stdout.
- Tests: section 8.7 except the Python cross-check; memory test; flow 12.
- Acceptance: on the private export, the failures are no more than `extract-msg`'s and no
  VML text appears, checked locally.

**PR 5.3: Python fallback and CI cross-check.**
- Scope: `contrib/msg-bodies.py`, the `msg-crosscheck` job, `SKILL.md` guidance on handling
  bodies.
- Tests and acceptance: the section 8.7 cross-check passes in CI.

**Release v0.5.0.** Smoke test adds `export read` on a bundled synthetic export, written to
a file.

### Phase 6: old-case inventory (read-only)

**PR 6.1: Observation of hold reads at scale.**
- Scope: live check only.
  - Read `legalHolds`, `userSources` and `siteSources` on cases that hold content.
  - Find out whether Graph lists case types other than eDiscovery (Premium), and whether
    their holds are readable.
  - Record throttling behaviour at concurrency 4 over a few hundred cases.

**PR 6.2: `inventory cases`.** Tests with 30 synthetic cases, mixed holds, one 403.

**PR 6.3: `inventory holds`.** `WriteRoute::ALL` is unchanged.

**Release v0.6.0.** Smoke test adds `inventory --help`. The inventory itself has no offline
mode.

Any later hold-release command needs its own design and review. It is not in this plan.

---

## 12. Risks and open questions

### 12.1 Trace-only claims and their gates

No design decision depends on these. Each one either has a live gate, or is handled in a way
that does not depend on whether the claim is true. The table says which:

| Claim (Observed (trace)) | How the design copes | Gate |
|---|---|---|
| `Location` uses `ediscoverycases('…')/operations('…')` | parser accepts key and path forms | PR 2.3 live (the first new action) |
| Operation lists had no `nextLink` | paging handled anyway | none: handling is independent of the claim |
| `percentProgress` only 0 or 100 | shown as a hint only | none: handling is independent of the claim |
| Export download URLs lack `?downloadType=Report`; `FolderType: Packages` | diagnostic display only | none: handling is independent of the claim |
| Timestamps with seven fractional digits | RFC 3339 parser accepts them | none: handling is independent of the claim |
| Counts null while running | all counts optional | none: handling is independent of the claim |
| `exportFormat: "pst"` on `exportReport` | action comes from `action` only | none: handling is independent of the claim |
| `description: null` on export operations | description is optional | PR 2.4 live (override reason) |

### 12.2 Not yet observed

1. Search `GET` fields and source reads (PR 1.4). Actions stay refused without them.
2. `$expand=search` on operations (PR 1.4). Without it, duplicate warnings stay
   case-wide.
3. `eDiscovery.Read.All` reach. PR 1.4 checks list and get. Whether actions would be
   accepted is not tested, because the tool refuses them under a read-only session.
4. Redirects on download. PR 1.5 saw none for an estimate report; export parts are not
   checked until PR 4.1.
5. Reports and exports without Teams context (PR 2.5, PR 4.1).
6. Case close on a case with holds, and hold reads on an empty case (PR 2.6). Observed for a
   case with no holds or custodians: `POST .../close` returned 204 with an empty body and no
   `Location` header, and the case listed as `closed` within seconds, without passing
   through `closing`.
7. Throttling: no 429 seen. POSTs are never retried, so a 429 on a write is reported, not
   repeated.
8. Failure-state shapes: `failed`, `partiallySucceeded`, `submissionFailed`, `resultInfo`.
   Synthetic fixtures are marked Assumption.
9. `Range` support, URL expiry and long downloads (PR 4.1).
10. Zip64 and compression methods in large exports (PR 4.1).
11. Numbering of `Items.1.NNN` parts. Only `.001` has been seen.
12. Teams message bodies in `.msg` form, HTML or text (PR 5.2), and compressed-RTF-only
    items.
13. Whether the Summary date format follows locale.
14. Hold reads at scale and case types beyond Premium (PR 6.1).
15. Case delete. Graph v1.0 documents none: the Microsoft Learn page for it returned 404.
    No delete call has been made. The tool does not implement delete.

### 12.3 Risks

- **The guard is a heuristic over a narrow grammar.** Some legitimate queries need the
  config lists or a reasoned override. Some broad hyphenated terms pass. Queries written in
  the portal with syntax outside the subset cannot be run through the tool at all. That is
  deliberate, and `docs/safety.md` says so.
- **An unclear write outcome is left to the user.** Without automatic replay, a timeout on a
  POST means the user has to look at the candidate list and decide. This is slower but
  cannot create duplicates by itself.
- **Data on disk.** Zips, traces and `export read` output hold colleagues' and outside
  senders' messages. The defaults are 0700 directories outside repositories, warnings, and a
  refusal to write bodies to a terminal. Encryption at rest is left to the operating system.
- **Untrusted text.** Subjects, names and bodies come from outside. The defences are
  sanitising and `--wrap-untrusted`.
- **Undocumented quirks may change.** The handling for the list's action label,
  `size: 0`, the placeholder date and report `exportFormat` is tolerant, and keeps raw JSON.
- **Our own MAPI reader** may miss property variants that `extract-msg` handles. The
  mitigations are per-item errors, the Python fallback and the CI cross-check.
- **Test-tenant access.** Every live check needs a tenant where the maintainer may create
  cases. Without one, those checks happen in a production tenant, in cases made for the
  purpose and closed afterwards. That needs the organisation's approval and lies outside
  this repository.
- **Code copied from `entra`** (`secrets.rs`, `output.rs`, parts of `auth.rs`) will drift
  over time. A shared crate is not a goal here; each `AGENTS.md` names the other repository
  as the source.

### 12.4 Sources

- The maintainer's private API notes, 2026-11-25 (Observed), including the item export
  section.
- The raw traces of the same day, read for shapes only (Observed (trace)).
- The private Python prototype and token helper (Prototype).
- The private operating skill.
- A prior read-only hold inventory, which informs phase 6.
- `aberoham/ms-entra-cli` v0.6.0.
- Microsoft Learn (Docs).

Nothing specific to an organisation from these sources appears in this document.
