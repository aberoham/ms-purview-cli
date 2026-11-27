# Safety

This page describes how `purview` keeps a tenant-wide search narrow. The
rest of the safety design (what each write changes, the plan and approval
step, the action preflight, holds, duplicates and secrets) is added here
with the write commands. Until then, `docs/SPEC.md` section 6 is the
design.

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
1       term          "orders-api"                   specific   6: a letter with - _ . / @ : or a digit
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
The search commands of a later release accept `--allow-generic` with a
`--reason` that is not blank, and record the reason in the search
description. The override never accepts a query outside the grammar.

### Building a query from flags

`purview kql` and, from a later release, `purview search create` take the
same query flags. The groups are ANDed in this order:

| Flag | KQL |
|---|---|
| `--term T` (repeatable) | each quoted, all ORed. A `"` or `*` inside a term is refused |
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
  unbalanced quotes or parentheses; control characters in a phrase; and
  parentheses or `NOT` nested more than 64 deep.
- A restriction is written with no space after the `:` or the comparison.
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
  ``^[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$``;
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
   the stem is classified by rules 2 to 8.
6. A token holding a letter plus at least one of `- _ . / @ :` or a digit
   (`orders-api`, `export_bucket`, `svc2`) → specific.
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
