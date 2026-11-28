# Safety

This page describes how `purview` plans and approves a write, what each
write command changes and checks, and how it keeps a tenant-wide search
narrow. The rest of the safety design (the action preflight, holds and
concurrent operations) is added here with the commands that need it. Until
then, `docs/SPEC.md` section 6 is the design.

## Plan, approve, send

Every write runs the same steps, in this order:

1. **Before sign-in.** The arguments are checked, and a query given with the
   query flags is built. Then `--no-write` (or `PURVIEW_NO_WRITE=true`)
   refuses the command with `WriteRefused`. Then the naming templates and
   the guard's lists in `config.json` are read, and the guard checks a query
   given on the command line.
2. **The session.** The stored credential must record a read-write sign-in.
   A `--read-only` sign-in, or a credential from v0.1 that records neither,
   is refused with `ReadOnlySession` before any request is sent. See
   `docs/auth.md`.
3. **Preflight.** The command reads what it needs from Graph. Only GET
   requests, and token refreshes from the identity platform, are sent.
4. **The plan.** The account and tenant, the method and path, the body as
   it will be sent, a SHA-256 digest of method, path and body, the effects as
   plain sentences, warnings, and what the preflight found.
5. **Approval.**
   - `--dry-run` prints the plan and sends nothing (exit 0). It wins over
     `--yes`.
   - `--yes` (or `PURVIEW_YES=true`) approves.
   - Otherwise, when standard input and standard error are both terminals
     and `--no-input` is not given, the plan is shown on standard error
     followed by `Apply? [y/N]`. Only `y` or `yes` approves. `case close`
     asks for the case's name instead, and only that name, typed as Graph
     gives it or as shown, approves; a name that shows as nothing is
     confirmed by the case id.
   - Otherwise nothing is sent, and the command exits 3 with
     `ConfirmationRequired`; a declined prompt exits 3 with `Declined`.
6. **Send.** The approved request is sent once, exactly as planned. It is
   never sent again automatically. If Graph refuses it (a 4xx), the command
   fails with Graph's error, and nothing changed. If the outcome is not clear
   (no answer, a timeout, HTTP 429 or a 5xx, or an answer that cannot be
   read), the command lists what the write may have created and fails with
   `WriteOutcomeUnknown`. Check those before running the command again.

The code makes the order hard to break: the only request method that can
send a POST takes an approved plan, and only the approval step can make
one. A test fails the build if a POST is built anywhere else.

Under `--json`, exit 0 prints `{"results": {"applied", "plan", "result"},
"count": 1}`, with `applied` false and `result` null after a dry run, and
exit 3 prints `{"plan", "applied": false, "error": {"code", "status",
"message"}}` whatever `--results-only` says. In a table, a dry run prints the
plan on standard output; exit 3 puts the plan and the reason on standard
error.

## What each write changes

| Command | What it changes |
|---|---|
| `case create` | A new case, visible to eDiscovery administrators. No custodians, data sources or holds. |
| `case close` | The case's status, to `closing` then `closed`. Changes no hold, custodian or data source, since a case with any is refused. The tool never reopens a case; reopening is done by hand in the Purview portal. |
| `search create` | A search over every tenant mailbox in an active case. Nothing runs until an estimate, report or export is started. No custodians, data sources or holds. |
| `estimate` | Runs a search over every tenant mailbox, adding an estimate operation and its report file to the case. Reads no item content and places no hold. |
| `report` | Runs a search over every tenant mailbox, adding an item report operation and its zip to the case: one row of metadata (sender, recipients, subject, dates, location) per copy of each item found. Collects no message bodies or attachments and places no hold. |
| `export create` | Runs a search over every tenant mailbox, adding an export operation to the case that collects a copy of every item found, with its body and attachments, as `.msg` files, and the item report beside them. The command downloads every part into the data directory. Changes no mailbox and places no hold. |

### `case create`

- `naming.marker` must not be blank.
- The name is `naming.case_name` rendered with `--topic` (by default
  `Records research - {topic} {yyyy_mm}`), or `--name`. The description is
  `naming.case_description`, or `--description`; `naming.marker` is added
  to it when it does not hold the marker already, so that a later
  `case close` can tell the case was made by `purview`.
- Preflight lists every case, to the last page. If any case has the name,
  whatever its status, nothing is sent and the command fails with
  `CaseNameInUse`, listing each match's id and status but not the name.
  Two cases with one name would make every later lookup by that name
  ambiguous. A list that stops before its last page refuses too, and so
  does an entry whose name cannot be read.
- `--reuse-existing`: if exactly one case has the name and it is active,
  the command shows it and exits 0 without sending anything
  (`"reused": true`, `"applied": false`). A closed or closing match, or
  several matches, are still refused.

### `case close`

- The case must be active, and must carry `naming.marker` in its
  description or have been created by the signed-in account, unless
  `--any-case` is given; a case allowed by `--any-case` alone gets a
  warning in the plan. Case records in
  the observed tenant carry no `createdBy`, so the marker is what shows a
  case is the tool's.
- Preflight reads the case's custodians, non-custodial data sources and
  legal holds, each to its last page. Any entry refuses with
  `CaseHasHolds`, giving the counts but no entry. A read that is denied,
  malformed or stops before its last page refuses with
  `ClosePrecheckFailed`, as does a case that is not active.
- After approval, and before the POST, the case and the three lists are
  read again, because holds may have been added while the person answered.
- The POST has no body. `--wait` reads the case until it is `closed`; at
  the deadline (default 15 minutes) or on Ctrl-C the command prints the
  last status and `purview case get <case>`, and exits 5 or 130.

### `search create`

- The query is built from the query flags, or taken from `--kql`, and the
  guard below checks it before sign-in. A query that is not narrowed is
  refused with `GenericQuery` unless `--allow-generic` gives a `--reason`;
  the reason is then recorded in the search's description, and the plan
  carries a warning. A query outside the grammar (`KqlNotUnderstood`) is
  refused with or without the override.
- Preflight reads the case, which must be the case asked for and active
  (`CaseNotActive` otherwise), and lists its searches to the last page. A
  search with the same name, or one whose name cannot be read, refuses
  (`SearchNameInUse` for the first).
- The body's `dataSourceScopes` is always `allTenantMailboxes`: the request
  type has no other value and no field for custodians or other sources.
- The description is `naming.search_description` (by default the first 200
  characters of the query, then the marker), or `--description`, with the
  marker added as for a case.
- After a 201, the echoed `contentQuery` and `dataSourceScopes` are
  compared with what was sent; a difference is a warning on standard
  error. Check the search with `purview search get` before running an
  action on it.

### Actions on a search: `estimate`, `report` and `export create`

Every action runs these checks before its plan, on whatever search it is
given, whoever created it:

- The search is named by id, or by an exact name that only one search in
  the case has, and is read by its id.
- Its `dataSourceScopes` must be exactly `allTenantMailboxes`. Absent, the
  action is refused with `ScopeUnverified`; any other value with
  `ScopeNotAllowed`. There is no override.
- Its custodian, non-custodial and additional source lists must each be
  empty, read to the last page. An entry refuses with `SearchHasSources`;
  a list that cannot be read refuses with `ScopeUnverified`.
- Its current query goes through the guard below. A query outside the
  grammar is always refused; one that is not narrowed is refused unless
  `--allow-generic` gives a `--reason`, which the plan shows. A report
  or export sends the reason as its `description`; an estimate has no description
  to record it in.
- An estimate of the case (for `estimate`), or an item report or export
  (for `report` and `export create`), that is not known to be finished may be a
  duplicate: the operation list does not say which search an operation
  runs, and an entry whose action or status cannot be read counts too. The plan names each one, and the action is refused with
  `ConcurrentOperation` unless `--allow-concurrent` is given; `--yes` alone
  is not enough. A dry run shows the plan either way.

After approval, and before anything is sent, the search is read again
with the same checks, and nothing is sent if it no longer passes them
(with the check's own error, such as `ScopeNotAllowed` or
`SearchHasSources`) or if its query or the guard's verdict differ from the
plan (`SearchChanged`). Without
`--allow-concurrent`, the case's operations are listed again too, so an
estimate (for `estimate`), or an item report or export (for `report`
and `export create`),
that someone else started while the prompt was open is refused as a
possible duplicate. A change made after these reads is still possible. The action is then sent once.
Its answer must be a 202 naming the new operation in the `Location`
header, on the Graph origin and for the case posted to, and the operation
must be of the action sent (an estimate, an item report or an export); anything
else stops the command with `UnexpectedLocation` before any download, and
the operation may still be running (`purview operation list <case>
--action estimate`, or `--action report --resolve` or `--action export
--resolve`, shows it). The command
then waits for the operation, downloads its report zip and reads it:

- `collection` is `complete` when no location failed, `incomplete` when
  `Locations-*.csv` has a `Status=Failed` row or, for an estimate,
  `Statistics-*.csv` a `StatType=Error` row, and `unchecked` when the zip was not read
  (`--no-download`), a file or a column it needs is missing, a row has no
  location, status or `StatType`, or the zip holds two Locations or
  Statistics files. Failures found are listed either way.
- An estimate can succeed while locations failed (Observed), and a report
  is taken to do the same (Assumption); the command warns, and `--strict` makes it exit 4 (`FailedLocations`, or
  `EvidenceMissing` when the collection is unchecked).
- `volume` compares the estimate with the limits under `volume` in
  `config.json`: more than `warn_hits` estimated items (default 5,000), a
  location with more than `warn_hits_per_location` hits (default 1,000),
  or an `indexedItemsSize` above `max_export_size` (default 10 GiB). Each
  limit passed is a `warning: VOLUME:` line on stderr and an entry in
  `volume.over`. A count that is missing or unreadable leaves its limit
  in `volume.unchecked`. Hits per location are checked only when the
  estimate `succeeded`, `collection` is `complete` and every location has
  a count. An estimate
  whose status is neither `succeeded` nor `partiallySucceeded` has every
  limit there, with no warning. The warning does not change the exit code: it is
  there so that a person narrows the query or confirms the scope before a
  report or export. With Teams context on, an export held about four
  times the estimated count (Observed, one run), so it can be several
  times larger than the estimate's size.
- At the wait deadline it exits 5, and on Ctrl-C (during the wait or the
  download) 130, with the command that resumes: `operation get --wait
  --check`, or `operation get --check` when Ctrl-C stopped the download of
  a finished operation. The check fetches only the evidence file of the
  operation's own action, and nothing when its detail is not that of its
  action; it never fetches an `Items.*.zip` part. It is never `download`. `--wait-timeout` covers the wait; the download
  has its own timeouts.

`report` also compares the search's latest estimate with
`volume.max_export_size` in `config.json` (default 10 GiB) before its
plan, read from the search's `lastEstimateStatisticsOperation` (Observed). It refuses with `TooLarge` when the estimate's
`indexedItemsSize` is above the limit, and with `VolumeUnchecked` when no
size can be compared: Graph has no estimate of the search or answers with
no operation, the latest one
is not finished or did not succeed, it only partly succeeded and its size
is within the limit (a partial size is a lower bound), the search was
changed after it ran, or a time or the size is missing. `--allow-large`
with `--reason` overrides both, and the plan then warns `VOLUME:`; the
reason goes into the report's `description` with any `--allow-generic`
one, since one `--reason` serves both. `--allow-concurrent` does not cover
the size, and no flag covers a token that cannot be refreshed. Only
`volume.max_export_size` is read for a report. A dry run shows the plan either way. The latest estimate is read
again after approval and must be the one the plan showed
(`SearchChanged`). The estimate undercounts what a report collects: one
tenant's reports held about 10 to 37 rows per estimated item with Teams
context on (Observed), and the plan says so with the estimate's count.

A report asks for the messages around each Teams hit
(`additionalOptions: teamsAndYammerConversations`, Observed).
`--no-teams-context`, or `defaults.teams_context: false`, leaves it out;
that body has not been observed, so the flag is experimental and the
plan warns. Its zip has no Statistics file (Observed), so its
`collection` comes from `Locations-*.csv` alone.

A stopped report resumes with `operation get <case> <op> --wait --check`
(or `--check` alone after Ctrl-C during the download), never `download`, which would fetch an export's item content if the
`Location` header had named one.

`export create` runs every check of `report`, the size limit included,
and posts `exportResult` with `exportFormat: msg` and `additionalOptions:
teamsAndYammerConversations,includeReport` (Observed);
`--no-teams-context` sends `includeReport` alone, which has not been
observed. The plan warns that an export can hold several times the items
the estimate counts (about four times in one run with Teams context on,
Observed) and that the download is large and holds message content. The
command downloads every part, into the data directory unless `--out` is
given (a directory it creates is mode 0700; an existing one keeps its
mode), and reads only the `Reports-…zip` part's Locations file for
`collection`. The download checks each zip's central directory, but no
entry of an `Items.*.zip` part is read, and item content is never
printed. Remove the directory when the work is done.

`purview operation get <case> <op> --check` runs the same collection
check on an existing operation, downloading its evidence file into the
data directory; a later `download` reuses that file.

### Unclear outcomes

If the POST gets no answer, times out, or gets HTTP 429 or a 5xx, it is not
sent again. `case create` lists the cases with the planned name,
`search create` the case's searches with the planned name, `case close`
reads the case once and shows its status, `estimate`
the estimates of the case created since just before the request by the
signed-in account (or with no creator recorded), and `report` and
`export create` the item
reports and exports created the same way, each of the first 10 read on its
own to tell a report from an export (the list shows both as
`exportResult`), and the command fails
with `WriteOutcomeUnknown`, naming each by id. Entries on pages read
before a page failed are still shown, with a note that the list stopped
early. Names are not unique,
so a match is only a candidate: check it with `purview case get` or
`purview search get` before running the command again. Purview may not list
a new case or search at once.

## The guard against generic tenant-wide searches

Every search this tool creates covers every mailbox in the tenant. A search
on a common word reads a large amount of unrelated mail and Teams
messages. The guard refuses such a query before anything is sent:

> Every branch of the query that can match a message must be narrowed. A
> branch is narrowed by a positive specific term, or by a positive
> `participants:` restriction on a full address.

The guard catches mistakes. It is not a security control: anyone with the
Purview eDiscovery role can run the same search in the portal.

`purview kql` runs the guard locally, with no sign-in, and shows its
reasons:

```console
$ purview kql --term orders-api --participant alex@contoso.example
kql: "orders-api" AND participants:alex@contoso.example
COLUMN  FIELD         VALUE                 NEGATED  CLASS      RULE
1       term          "orders-api"                   specific   6: a letter with a digit, or with - _ . / @ : between two characters
18      participants  alex@contoso.example           narrowing  participants: on a full address
verdict: narrowed
```

It exits 0 when the query is narrowed. Otherwise it prints the same report,
then fails with exit 1 and the error code `GenericQuery`, naming the column
of a branch that is not narrowed. A query outside the supported grammar
fails with `KqlNotUnderstood` and the column of the construct. Under
`--json`, a narrowed query prints `{"results": {…}, "count": 1}`; a query
that is not narrowed prints one document holding both
`{"analysis": {…}, "error": {…}}`, with or without `--results-only`.

`purview kql` takes no override: it reports what the guard would decide.
`purview search create` accepts `--allow-generic` with a `--reason` that
is not blank, and records the reason in the search description. The
override never accepts a query outside the grammar. The actions on a
search, from a later release, will take the same override.

### Building a query from flags

`purview kql` and `purview search create` take the same query flags. The groups are ANDed in this order:

| Flag | KQL |
|---|---|
| `--term T` (repeatable) | each quoted, all ORed. A `"`, a `*`, a web address (`http://` or `https://`), or a control or invisible character inside a term is refused |
| `--participant ADDR` (repeatable) | `participants:ADDR`, all ORed. Each must be a full address |
| `--since YYYY-MM-DD` | `sent>=YYYY-MM-DD` |
| `--until YYYY-MM-DD` | `sent<=YYYY-MM-DD` |
| `--kind email\|teams` | `kind:email` or `kind:microsoftteams` |
| `--exclude-from ADDR` (repeatable) | `NOT from:ADDR`, each ANDed |
| `--kql RAW` | raw query; cannot be combined with any flag above |

A group of more than one value is put in parentheses:

```text
("orders-api" OR "orders_export_bucket") AND (participants:alex@contoso.example OR participants:sam@contoso.example) AND sent>=2025-01-01 AND NOT from:noreply@notify.example
```

The built query goes through the same parser as `--kql`, so both forms get
the same verdict.

### Supported grammar

The guard parses the query with a small recursive-descent parser. It
accepts exactly this grammar, in Extended Backus–Naur Form (EBNF), and
refuses everything else:

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

- `AND` binds more tightly than `OR`, and `NOT` applies to the operand that
  follows it. Use parentheses to say anything else.
- `AND`, `OR` and `NOT` must be upper case.
- The unquoted words `and`, `or`, `not`, `near` and `onear`, in any case,
  are refused, because KQL might read them as operators. Quote them to
  search for them.
- Two operands with no operator between them are refused. KQL would join
  them with an implicit operator that is easy to misread.
- Refused outright: a prefix `+` or `-`; `NEAR` and `ONEAR`;
  `property:(…)`; ranges with `..`; any property not in the grammar, such
  as `body:`, `recipients:` or `title:`; `=`, `<` and `>`; a wildcard
  anywhere but the end of a word, or in a phrase; a quoted address;
  unbalanced quotes or parentheses; any control character other than tab,
  line feed and carriage return, and any of them inside a phrase; invisible
  characters such as a zero-width space or a bidirectional control, anywhere;
  a web address (`http://` or `https://` in any case, anywhere), which can
  carry a signature in its query: search for its host name or path without
  the scheme;
  and parentheses or `NOT` nested more than 64 deep.
- A digit is any character Unicode counts as numeric, in words and in the
  classifier alike.
- A restriction is written with no space after the `:` or the comparison.
- Tokens are separated by spaces, tabs or line breaks; other Unicode spaces,
  such as a no-break space, are refused outside a phrase. A quote must not
  touch a word or an operator: `"a"AND"b"` is refused.
- Property names are compared ignoring case. Values keep their case.
- `kind:` accepts `email` and `microsoftteams` in any case.
- A `sent` date must be a real date written as `YYYY-MM-DD`.

The forms `participants:`, `from:`, `NOT from:`, `sent>=`, `sent<=`,
`kind:email`, `kind:microsoftteams`, quoted phrases and nested parentheses
were accepted at search creation (Observed). `to:`, `cc:`, `bcc:` and
`subject:` are standard KQL (Docs) and have not been observed.

Error messages give the column, counted in characters from 1, and name the
construct. They do not repeat a word or a value from the query, because a
value pasted into the wrong place could be a secret. They quote only the
grammar's fixed symbols, such as `-` or `=`.

### Addresses

Every address in `participants:`, `from:`, `to:`, `cc:` and `bcc:`, and every
`--participant` and `--exclude-from` value, must be a full address:

- it matches
  ``^[A-Za-z0-9][A-Za-z0-9.!#$%&'+/=?^_`{|}~-]*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$``,
  so the part before `@` starts with a letter or digit;
- it has no `*`;
- the part before `@` is not empty;
- it is not quoted.

Anything else, including a bare domain such as `contoso.example`, is
refused as a value. Only `participants:` narrows a query.

### Term classification

A phrase, a word or a `subject:` value is split into tokens on whitespace.
Each token is trimmed of leading and trailing `.,;:!?'"()`, then
classified. The first rule that matches wins:

1. The whole text, compared ignoring case:
   - in `guard.generic_terms` → generic (the generic list wins over the
     specific list);
   - in `guard.specific_terms` → specific.
2. A token in the built-in generic list below, compared ignoring case →
   generic.
3. A token shorter than 4 characters → generic.
4. A token of digits only, such as `2025` → generic.
5. A trailing `*`: a stem shorter than 6 characters → generic; otherwise
   the stem is classified by rules 2 to 8. Rules 2 to 4 see the token with
   its `*`, so `a*` is decided by rule 3.
6. A token holding a letter plus a digit, or plus one of `- _ . / @ :` with a letter or
   digit on each side of it (`orders-api`, `export_bucket`, `svc2`; not `retention-`) →
   specific. KQL may read such a separator as a space (Docs), so one at the edge of a word
   is not evidence of a name.
7. A token with at least one lower-case letter and an upper-case letter
   after its first character (`PagerDuty`, `GitHub`; not `RETENTION`) →
   specific.
8. Otherwise → generic.

A phrase is specific if at least one of its tokens is specific. For
example, `"orders-api migration"` is specific; `"2025 contract"`,
`"stock report"` and `"follow-up meeting"` are generic.

Rule 1 compares the whole text, not each token: `guard.specific_terms:
["Okta"]` makes `Okta` specific, but not `"Okta rollout"`.

#### Built-in generic list

These are common words that rule 6 would otherwise call specific, in
trimmed lower-case form. `src/kql/classify.rs` holds the same list, and a
test asserts that the two are identical. Changing the list needs a test
change and a `CHANGELOG.md` entry.

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

### The verdict

A node is narrowed when every message it can match must also match a
narrowing leaf:

| Node | Narrowed |
|---|---|
| specific phrase or word, `subject:` with a specific value | yes |
| `participants:` with a full address | yes |
| generic phrase or word, `from:`, `to:`, `cc:`, `bcc:`, `kind:`, `sent` | no |
| `NOT x` | no |
| `a AND b AND …` | if any child is narrowed |
| `a OR b OR …` | only if every child is narrowed |
| parentheses | as the inner node |

The query passes if its root is narrowed. For example:

- `"retention" AND participants:alex@contoso.example` passes;
- `NOT "orders-api"`, `kind:email`, `subject:retention` and
  `(participants:alex@contoso.example OR kind:email) AND "retention"` fail.

Only `participants:` narrows, for two reasons. The operating rule this tool
enforces names `participants:`. And how `from:` and `to:` treat Teams
messages has not been observed. To restrict by sender, write
`participants:x AND from:x`.

### Settings

`config.json` in the configuration directory can name terms the
classifier gets wrong:

```json
{
  "guard": {
    "specific_terms": ["Okta", "Jamf"],
    "generic_terms": ["orders"]
  }
}
```

Both lists are compared with the whole text of a phrase, word or
`subject:` value, ignoring case. A term in both lists is generic. A missing
list, or `null`, is empty; any other value that is not a list of non-blank
strings is an error.

### Known errors

- Single-word product names, such as `Okta`, are refused. Add them to
  `guard.specific_terms`, or search with `--participant`.
- Some broad hyphenated or numbered words that are not on the built-in
  list are accepted, such as `pre-approval` or `q3-2025`. Add them to
  `guard.generic_terms`.
- A bare domain or address searched as free text, such as
  `contoso.example`, is specific by rule 6.

The remedies are the settings above and, for the search commands, the
reasoned override.
