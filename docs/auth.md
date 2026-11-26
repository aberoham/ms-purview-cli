# Authentication and permissions

`purview` signs in as a person, with delegated permissions, through an app
registration in that person's own tenant. It has no registration of its own and
no secret. This page covers what the registration needs, how to create it, how
sign-in works and where the tokens are kept.

Each claim about the service carries an evidence label, as in `docs/SPEC.md`:
**Observed** (seen in one tenant, recorded in `docs/api-notes.md`), **Docs**
(Microsoft Learn), **Derived** (follows from the other two) or **Assumption**
(not yet checked).

## Permissions and the Purview role

A sign-in gets two tokens from one refresh token:

| Token | Resource | Delegated permission | Used for |
|---|---|---|---|
| Graph | Microsoft Graph | `eDiscovery.ReadWrite.All`, or `eDiscovery.Read.All` with `--read-only` | every case, search and operation request |
| Download | Purview eDiscovery app (`b26e684c-5068-4120-a679-64a5d2c909d9`) | `eDiscovery.Download.Read`, requested as `.default` | downloading export and report files only |

The Graph sign-in also asks for `offline_access`, `openid` and `profile`, for
the refresh token and the account name. A Graph token cannot download an export:
the download URL answers 401 (Observed).

A read-only session (`--read-only`) refuses every write before any request is
sent. Whether the service would accept an action under `eDiscovery.Read.All` is
not known, and the tool does not try.

Permissions are not enough on their own. The person signing in also needs a
Purview role: membership of the eDiscovery Manager or eDiscovery Administrator
subgroup of the eDiscovery Manager role group, assigned in the Microsoft Purview
portal under Settings, Role groups (Docs). The observed
account was an eDiscovery Administrator (Observed).

## Why an app registration of your own

The well-known public clients cannot get the download token (Observed):

- the Azure command-line interface's client fails with `AADSTS65002`, because a
  first-party app must be pre-authorised by the API's owner, and consent cannot
  do that;
- the Microsoft Graph Command Line Tools client gets the Graph token after
  consent, but fails with `AADSTS65001` for the eDiscovery app.

A public-client registration in your tenant, with both permissions consented,
gets both tokens (Observed).

## Create the app registration

The registration is a single-tenant public client with no credentials. Two ways
to make it follow. Both give the same result.

### With the setup script

`contrib/create-purview-app.sh` uses the Azure command-line interface (`az`). Sign
in to the target tenant first, as someone who can create applications and grant
admin consent (Cloud Application Administrator, Application Administrator or a
higher role):

```bash
az login --tenant <tenant-id>
TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh
```

**It changes nothing unless you pass `--apply`.** Without it, the script makes
only read-only `az` calls and prints a plan:

- the target tenant, which must be the tenant `az` is signed in to;
- whether it will create an app or update the one `CLIENT_ID` names;
- the service principals it will create;
- the full `requiredResourceAccess`;
- each assignee, resolved to its object id and user principal name;
- who may sign in: `appRoleAssignmentRequired` and what it means;
- the consent it will grant, by type and scope for each resource.

Read the plan, then run the same command with `--apply`. Argument errors exit
2, other failures 1. The script never
prompts, so it also runs where there is no terminal.

With `--apply` it carries out the plan in this order: the eDiscovery app's
service principal, the application and its owner, the application's service
principal, assignment, then consent. Assignment comes before consent, so a run
that stops part way never leaves a consented app that everyone can use. It
follows three rules:

- **Each change is sent once.** Nothing is retried automatically.
- **Readiness is checked with reads.** After creating a service principal it
  reads it back every 5 seconds, for up to 60 seconds, before the next change.
- **An unclear result is read back.** If a change times out, is throttled, gets
  a server error or fails without a definite reason, the script reads back the
  object it meant to create, says whether it exists, names the step and stops
  with a non-zero exit. Running it again is then safe: every step reads the
  current state first and skips what already matches.

Without `CLIENT_ID`, the script refuses to create an app when one with the same
display name already exists, and lists its application id. Set `CLIENT_ID` to
that id to update it instead.

On an update it changes only what differs from the plan. It adds the redirect
URI without removing others, and adds the signed-in user as owner only when
the app has no owner at all, which is what an interrupted create leaves. It
never removes a scope from a consent grant: switching an existing app to
`READ_ONLY=1` leaves `eDiscovery.ReadWrite.All` on its grants, and the plan
says so. Remove that scope from the grant by hand if the read-only setup must
be strict.

#### Variables

| Variable | Meaning |
|---|---|
| `TENANT_ID` | Directory (tenant) id. Required |
| `CLIENT_ID` | Application (client) id of an existing registration to update |
| `APP_NAME` | Display name of a new registration: letters, digits, spaces and `( ) . _ -`, up to 120 characters. Default `Purview CLI (eDiscovery)` |
| `ASSIGN_USERS` | Space-separated user principal names or object ids to assign. Give a guest whose name holds `#` by object id |
| `GROUP_OBJECT_ID` | A group's object id to assign. Needs `CONSENT=tenant` |
| `READ_ONLY=1` | Ask for `eDiscovery.Read.All` instead of `eDiscovery.ReadWrite.All` |
| `CONSENT` | `principal` (default) or `tenant` |
| `ALLOW_ALL_TENANT_USERS=1` | Let every user in the tenant sign in. Needs `CONSENT=tenant` and no assignment |

### By hand

These are the steps the script automates (`docs/SPEC.md` section 5.2):

1. **The eDiscovery app's service principal.** The tenant may not have one; the
   observed tenant did not (Observed). Create it:
   `az ad sp create --id b26e684c-5068-4120-a679-64a5d2c909d9`. It appears as
   `MicrosoftPurviewEDiscovery` and exposes the delegated, admin-consent scope
   `eDiscovery.Download.Read` (`c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2`)
   (Observed).
2. **The application.**
   - Supported account types: this organisational directory only
     (`signInAudience: AzureADMyOrg`) (Observed).
   - Platform "Mobile and desktop applications" with the redirect URI
     `http://localhost/callback`, and "Allow public client flows" on
     (`isFallbackPublicClient: true`) (Observed).
   - No certificates or secrets (Observed).
   - API permissions, all delegated: Microsoft Graph `eDiscovery.ReadWrite.All`
     (`acb8f680-0834-4146-b69e-4ab1b39745ad`) or `eDiscovery.Read.All`
     (`99201db3-7652-4d5a-809a-bdb94f85fe3c`), with `offline_access`, `openid`
     and `profile`; and, under "APIs my organization uses",
     `MicrosoftPurviewEDiscovery` `eDiscovery.Download.Read`.
     `eDiscovery.ReadWrite.All` and the eDiscovery scope are Observed. The id
     of `eDiscovery.Read.All` is Observed, but its use here is an Assumption.
     Listing the OpenID Connect scopes here is an Assumption too, because the
     observed registration had them only on its consent grant.
   - Add yourself, or whoever maintains it, as an owner. Creating an
     application through Graph does not add the caller as owner (Observed).
3. **The application's service principal** (its enterprise application), with
   "Assignment required" on (`appRoleAssignmentRequired: true`). Assign each
   user with the default role (Observed).
4. **Consent**, one of the choices below.

## Consent choices

- **Per user (`CONSENT=principal`, the default).** One `oauth2PermissionGrant`
  per resource for each assigned user, with `consentType: Principal`: Graph
  with `eDiscovery.ReadWrite.All offline_access openid profile`, and the
  eDiscovery app with `eDiscovery.Download.Read`. This is the observed setup;
  sign-in then showed no consent prompt (Observed). A per-user grant names a
  user, not a group (Docs), so this choice cannot be used with
  `GROUP_OBJECT_ID`.
- **Tenant-wide (`CONSENT=tenant`).** One grant per resource with
  `consentType: AllPrincipals`. With "Assignment required" on, a user who is not
  assigned can neither sign in nor get a token, except a Global Administrator
  (Docs; not observed). This is the choice for a group
  assignment.
- **Every user (`ALLOW_ALL_TENANT_USERS=1` with `CONSENT=tenant`).** Assignment
  is not required, so every user in the tenant can sign in through the app
  (Docs). Purview roles still decide what each person can see (Docs), but use
  this only when that is the intent.

Without consent for the eDiscovery app, sign-in still succeeds with a warning,
and download commands fail with `DownloadNotConsented` until consent is granted
and `purview auth refresh` succeeds.

## Sign in

```bash
purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
```

`PURVIEW_CLIENT_ID` and `PURVIEW_TENANT_ID` can stand in for the two flags.
Both ids must be GUIDs. `common` and `organizations` are refused, because a
single-tenant registration accepts sign-in only through its own tenant
(Docs). The registration is saved with the account, so a
later sign-in needs neither.

`--no-input` refuses `auth login` before any request, because sign-in needs a
person at a browser.

### Device code (the default)

`auth login` prints an address and a code on stderr. Open the address in any
browser, on any device, and enter the code. The command waits until sign-in
finishes or the code expires.

### Browser (`--browser`)

`auth login --browser` uses the authorization code flow with Proof Key for Code
Exchange (PKCE, RFC 7636) on a loopback redirect:

1. It starts a listener on `127.0.0.1` on a port the system picks, and on `::1`
   on the same port when it can, because a browser may try `localhost` over
   IPv6 first. If another program holds that port on `::1`, it picks another
   port. It opens the sign-in page in the default browser, through `open` on
   macOS, the URL handler on Windows or `xdg-open` elsewhere, with none of the
   command's output streams, so nothing the browser prints reaches the
   command's output. It also prints the address on stderr, in case the browser
   does not open.
2. After sign-in, the identity platform sends the browser to
   `http://localhost:<port>/callback` with an authorization code. The listener
   accepts only an answer that carries the random `state` of this sign-in.
   Any other request gets an error page, a connection that sends nothing is
   closed after 10 seconds, and it keeps waiting. Connections are served side
   by side, so one the browser opens and never uses holds nothing up.
3. It redeems the code with the PKCE verifier, which never left the process,
   then redeems the refresh token for the download token, as the device-code
   flow does.

The browser must run on the same computer, because the redirect goes to the
loopback address. Over a remote shell, use the device code. The command waits
up to 15 minutes. The page asks which account to use (`prompt=select_account`).

The registration lists `http://localhost/callback` without a port. The identity
platform ignores the port when it compares a loopback redirect with the
registration (Docs), so any port the listener gets is accepted. The redirect
uses `localhost`, not the `127.0.0.1` that Microsoft recommends, because the
observed registration lists `localhost`, and a `127.0.0.1` redirect would need
its own entry, which the portal cannot add (Docs). An IPv6 literal (`[::1]`) cannot be registered (Docs). That the
observed registration accepts a redirect with a port is an Assumption until
the PR 1.2 live check is recorded in `docs/api-notes.md`.

### Choosing the account

With `--account` (or `PURVIEW_ACCOUNT`) naming a stored account, the sign-in
must return that account's recorded tenant and object ids; otherwise the
returned account name or user principal name must equal the name given,
ignoring case. On a mismatch nothing is stored.

## Token storage

The operating system's credential store is the only place a token is kept:
the macOS keychain, the Windows Credential Manager or the Linux kernel keyring.
Each account has one entry, under the service `purview` and the key
`purview:token:<email>`, holding JSON with the refresh token, both access
tokens, the principal's tenant and object ids, and the app registration that
issued them (`docs/SPEC.md` section 5.1).

Account metadata (`accounts/<email>.json`) and `config.json` live in the
configuration directory, `purview` under the platform's configuration
directory, or `PURVIEW_CONFIG_DIR`. They hold no secret: saving refuses a value
that looks like one. On macOS and Linux the files are mode 0600 and the
directories 0700. On Windows they rely on the profile directory's default
access control list. Links (on Windows, any reparse point) are refused.

`purview auth logout --account <email>` removes the credential and the account
file. `purview auth list` shows the stored accounts and marks the default.

## Refresh

`purview auth refresh` redeems the stored refresh token twice: for Graph, with
the scopes already stored, then for the download token. Each result is stored
before the next step. It never adds or removes a scope, and refuses a Graph
response whose permissions differ from the stored set. Sign in again with
`auth login`, with or without `--read-only`, to change them.

Every refresh uses the app registration recorded in the credential, never the
one in `config.json` or the account file. If those disagree, a sign-in stopped
part way, and `auth refresh` asks you to sign in again rather than guess.

## `AADSTS65001` and `AADSTS65002`

- **`AADSTS65001`** (consent required) on the download redemption means the app
  has no consent for `eDiscovery.Download.Read` (Observed with another client). `auth login` warns and stores
  the Graph token; `auth refresh` fails with `DownloadNotConsented`. Grant the
  consent (run the script again, or grant admin consent in the Microsoft Entra
  admin center), then run `purview auth refresh`.
- **`AADSTS65002`** means the client is a first-party Microsoft app that the
  eDiscovery API has not pre-authorised. Consent cannot fix it (Observed). Use
  your own registration.

## Environment variables

| Variable | Meaning |
|---|---|
| `PURVIEW_CLIENT_ID` | Default for `auth login --client-id` |
| `PURVIEW_TENANT_ID` | Default for `auth login --tenant-id` |
| `PURVIEW_ACCOUNT` | Default for `--account` |
| `PURVIEW_NO_INPUT` | Default for `--no-input` |
| `PURVIEW_CONFIG_DIR` | Configuration directory, instead of the platform default |

An empty variable counts as unset.

## Microsoft references

- Authorization code flow: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow
- Device code flow: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code
- Redirect URI rules, including loopback ports: https://learn.microsoft.com/entra/identity-platform/reply-url
- Restrict an app to a set of users: https://learn.microsoft.com/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users
- `oauth2PermissionGrant`: https://learn.microsoft.com/graph/api/resources/oauth2permissiongrant
- eDiscovery permissions in Microsoft Purview: https://learn.microsoft.com/purview/edisc-permissions
