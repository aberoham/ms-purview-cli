# Microsoft Purview eDiscovery API notes

These notes record how the service behaved when it was called, in public form. They hold
ratios, timings and orders of magnitude, never one tenant's counts, identifiers or names.
Every pull request that depends on a new observation adds to them.

Each entry carries an evidence label, as in `docs/SPEC.md`:

| Label | Meaning |
|---|---|
| **Observed** | Recorded in the maintainer's private API notes of 2026-11-25, from live calls against one tenant |
| **Observed (trace)** | Seen in the raw request and response recordings of the same day, not written into the notes |
| **Prototype** | What the maintainer's private Python prototype does in its source code |
| **Docs** | Microsoft Learn only |
| **Derived** | Inferred from observations |
| **Assumption** | Not checked against the service |

Entries without a date of their own are from 2026-11-25.

## Sign-in and tokens

- An app registration of the user's own, a public client with no secret, gets both tokens
  from one refresh token: a Microsoft Graph token with `eDiscovery.ReadWrite.All`, and a
  token for the Purview eDiscovery app (`b26e684c-5068-4120-a679-64a5d2c909d9`). (Observed)
- The download token was requested with the scope
  `b26e684c-5068-4120-a679-64a5d2c909d9/.default` (Prototype). A download with the resulting
  token succeeded. (Observed)
- The Azure command-line interface's public client cannot get a token for the eDiscovery app:
  the request fails with `AADSTS65002`, because first-party apps need pre-authorisation by
  the API owner, which consent cannot provide. (Observed)
- The Microsoft Graph Command Line Tools client gets a Graph token with
  `eDiscovery.ReadWrite.All` after per-user consent, but `AADSTS65001` for the eDiscovery
  app, so it can search but not download. (Observed)
- The observed consent used the read-write Graph scope set: `eDiscovery.ReadWrite.All
  offline_access openid profile`. (Observed) Whether a session with `eDiscovery.Read.All`
  can list and get is checked in PR 1.4.
- Consent was given per user, as one `oauth2PermissionGrant` per resource with
  `consentType: Principal`: Graph with `eDiscovery.ReadWrite.All offline_access openid
  profile`, and the eDiscovery service principal with `eDiscovery.Download.Read`.
  (Observed) A per-user grant takes a user, not a group. (Docs)
- The observed account held the eDiscovery Administrator role group. (Observed)

## App registration

- The observed tenant had no service principal for the eDiscovery app.
  `az ad sp create --id b26e684c-5068-4120-a679-64a5d2c909d9` created it as
  `MicrosoftPurviewEDiscovery`. It exposes the delegated, admin-consent scope
  `eDiscovery.Download.Read` (`c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2`) and an application
  role of the same name. (Observed)
- The working app had `signInAudience: AzureADMyOrg`, `isFallbackPublicClient: true`, the
  public-client redirect `http://localhost/callback`, no credentials, and in
  `requiredResourceAccess` Graph `eDiscovery.ReadWrite.All`
  (`acb8f680-0834-4146-b69e-4ab1b39745ad`) and the eDiscovery scope above. (Observed)
- A Graph `POST /applications` did not add the caller as an owner. (Observed)
- The app's service principal had `appRoleAssignmentRequired: true`, and users were
  assigned the default role `00000000-0000-0000-0000-000000000000`. (Observed)

## Cases, searches and operations

- Case display names are not unique. (Observed) Some cases were in `closing` status at the
  time of a snapshot; whether they were stuck there is not known. (Observed)
- Creating a case returned 201 with `status: active`. (Observed)
- Closing a case with no holds or custodians returned 204 with an empty body and no
  `Location` header. The case listed as `closed` within seconds, without passing through
  `closing`. (Observed)
- Creating a search runs nothing until an action is posted. (Observed) The `contentQuery`
  was echoed unchanged. (Observed)
- Search creation accepted `participants:`, `from:`, `NOT from:`, `sent>=`, `sent<=`,
  `kind:email`, `kind:microsoftteams`, quoted phrases and nested parentheses. (Observed)
- Every action returned 202 with a `Location` header naming the operation. (Observed) The
  header had the key form `…/ediscoverycases('<case>')/operations('<op>')`. (Observed
  (trace))
- Operation ids are 32 hexadecimal characters with no hyphens. (Observed)
- The operation list has base fields only, and shows an `exportReport` operation with
  `action: exportResult`. (Observed) A single GET of the operation carries the typed object
  with counts and files. (Observed)
- A running operation has `completedDateTime` of `0001-01-01T00:00:00Z`. (Observed)
  `percentProgress` was only ever 0 or 100. (Observed (trace))
- An operation can report `succeeded` while some locations failed. (Observed) A tenant-wide
  estimate covered on the order of ten thousand locations, and a handful failed with a
  transient cancellation error. (Observed)
- No 429 was seen. (Observed)

## Timings

From the queries sampled in one tenant (Observed):

- estimates took about 5 minutes, for queries of one to ten terms;
- small item reports took 2 to 4 minutes, and one took 18;
- one large item report took about 50 minutes, most of it queued (Derived from its zip entry
  times);
- one export with its downloads took about 10 minutes.

## Downloads

- The download host was `eur.proxyservice.ediscovery.svc.cloud.microsoft`. (Observed) `eur`
  is read as the tenant's region (Derived); other regions are assumed to share the suffix.
  (Assumption)
- `Authorization: Bearer <download token>` with `X-AllowWithAADToken: true` returned 200. A
  Graph token returned 401. (Observed)
- The prototype followed redirects without inspecting them, so whether any occur is not
  known. PR 1.5 checks this.
- Estimate report files had `size: 0` and were well under a megabyte; item report zips had
  their real size. (Observed)
- An export's `exportFileMetadata` listed two files: a `Reports-…zip` in the item report
  layout, on the order of a megabyte, and an `Items.1.001.<export name>.zip`, on the order of
  gigabytes for a few thousand items. (Observed) The `1.001` suggests numbered parts for
  larger exports. (Derived)
- Server file names embed the case, search and export names. (Observed) In the prototype,
  the caller's local time ended up in an export file name. (Observed)

## Report and export contents

- CSV files are UTF-8 with a byte-order mark. (Observed)
- `Summary-*.csv` has no header: key, value and description rows with blank lines between
  groups. Item-report summaries add a help link, `Export Name`, an item count table, an
  "Informational" table and a "Consumption summary". (Observed)
- `Settings-*.csv` has the header `"Setting Name","Value","Description"`, and some rows have
  two fields. (Observed)
- An item report has 162 columns and no body text, with one row per copy of an item in each
  mailbox. A large report held about 37 rows per estimated item and about 12.6 rows per
  unique item. (Observed, one report)
- A large item report was tens of megabytes compressed and about eleven times larger
  uncompressed, split into items files of about 200 MB each. (Observed)
- `Subject/Title` is empty for Teams messages; `Conversation name` labels them. `Sender`
  is sometimes a Teams thread id. The same person was seen under an old and a new domain.
  (Observed)
- With Teams context on, an export held roughly four times the estimated count. (Observed,
  one run)
- An export's report CSV has one row per exported file, and every row had
  `Status: Successful`. `Target path` has the form
  `Items.1.001.<export name>.zip\Exchange\Items\<id>.msg`. Items zips hold one flat folder,
  `Exchange/Items/<32 hex>.msg`, plus two directory entries, and every row matched exactly
  one file. (Observed)
- Mail bodies in the exported `.msg` files are often only HTML. `extract-msg` read every item
  except Teams system messages (`IPM.SkypeTeams.SystemMessage`). Quoted reply history
  repeats in every message of a thread. (Observed)

## Not yet observed

1. Search `GET` fields and source reads (PR 1.4).
2. `$expand=search` on operations (PR 1.4).
3. What an `eDiscovery.Read.All` session can reach (PR 1.4 checks list and get).
4. Redirects on download (PR 1.5).
5. Reports and exports without Teams context (PR 2.5, PR 4.1).
6. Case close on a case with holds, and hold reads on an empty case (PR 2.6).
7. Throttling.
8. The shapes of `failed`, `partiallySucceeded`, `submissionFailed` and `resultInfo`.
9. `Range` support, URL expiry and long downloads (PR 4.1).
10. Zip64 and compression methods in large exports (PR 4.1).
11. Numbering of `Items.1.NNN` parts beyond `.001`.
12. Teams message bodies in `.msg` form, and compressed-RTF-only items (PR 5.2).
13. Whether the Summary date format follows locale.
14. Hold reads at scale, and case types beyond Premium (PR 6.1).
15. Case delete: Graph v1.0 documents none, and the tool implements none.

## Live checks

### PR 1.1: device-code sign-in with both tokens stored

Status: **run on 26 November 2026**, with the signed and notarised `v0.1.0-rc.1` build
installed from the Homebrew tap, against a production tenant through a single-tenant
public-client registration whose only assignee was the signing-in account.

- **Sign-in:** the device-code flow succeeded on the first attempt. Login printed
  `downloadReady: true`; no `AADSTS65001` warning appeared.
- **Graph scope returned:** `openid profile email https://graph.microsoft.com/eDiscovery.ReadWrite.All`
  for both the sign-in and each refresh. The sign-in request named `offline_access`, which
  the response omitted, and did not name `email`, which the response added. A refresh token was
  issued all the same. The permission set compared by the tool did not change between
  sign-in and refresh, so the refresh was accepted.
- **Account claims:** the id token carried `preferred_username`, `tid`, `oid` and `name`,
  and no `upn`; login printed `upn: null`.
- **Refresh:** two `auth refresh --json` runs a few seconds apart both succeeded, and both
  `graphExpiresAt` and `downloadExpiresAt` moved later. The download token's lifetime
  differed from the Graph token's.
- **Credential store (macOS):** one generic-password item, service `purview`, account
  `purview:token:<email>`, label `purview — <email>`, description
  `Microsoft Purview eDiscovery token`.
- **Not observed:** the `scope` string of the download-resource response, and whether the
  download redemption returned a new refresh token. The CLI did not report either value,
  and the stored credential was not read.
- **Permissions:** on macOS the local data directory is the configuration directory. The
  per-account lock created `account-locks/` and its parent with mode 0755, and lock files
  0644, before the configuration was first saved; login then warned and narrowed the
  configuration directory to 0700. A later code change creates lock folders 0700 and
  lock files 0600, and refuses a linked lock folder.

### PR 1.2: browser sign-in and the setup script's dry run

Status: **run on 26 November 2026** from a local build of the PR 1.2 branch, signed with a
local code-signing identity, against the same tenant and registration as the PR 1.1 check.

- **Browser sign-in:** `auth login --browser --json` succeeded on the first attempt. The
  registration lists the public-client redirect `http://localhost/callback` without a port;
  the authorization request named `http://localhost:<port>/callback` with the port the
  listener was given, and the identity platform redirected to it. (Observed) Login printed
  `downloadReady: true`.
- **Graph scope returned:** `openid profile email https://graph.microsoft.com/eDiscovery.ReadWrite.All`,
  the same as after device-code sign-in. (Observed)
- **Credential compatibility:** the `v0.1.0-rc.1` release build then ran `auth refresh`
  on the credential the branch build had stored, and it succeeded without a keychain
  prompt. (Observed)
- **Assignment required:** the same sign-in address, opened by the tool in the default
  browser, landed in a profile signed in to a different account, which was not assigned to
  the app. The identity platform refused it with `AADSTS50105` (the user is not assigned to
  the application) before any consent prompt. (Observed)
- **Not observed:** whether the browser reached the listener over IPv4 or IPv6.
- **Setup script, dry run:** `contrib/create-purview-app.sh` without `--apply`, with
  `CLIENT_ID` naming the existing registration and the signed-in account in
  `ASSIGN_USERS`, exited 0 and found the existing owner, service principal, assignment,
  redirect and both per-user grants. Its plan proposed one change: adding `offline_access`,
  `openid` and `profile` to `requiredResourceAccess`, which held only the Graph eDiscovery
  permission and the eDiscovery download scope. (Observed) Reading the registration back
  afterwards showed it unchanged. (Observed)
