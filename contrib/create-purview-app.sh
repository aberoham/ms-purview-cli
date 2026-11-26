#!/usr/bin/env bash
set -euo pipefail
# ASSIGN_USERS is split on spaces. A wildcard in it must stay a literal word,
# not expand to file names in the current directory.
set -f

# Creates or updates the single-tenant public-client app registration that
# `purview` signs in through, and the service principals, user assignments
# and consent grants it needs. docs/SPEC.md section 5.2 is the contract.
#
# Usage:
#   TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh
#   TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh --apply
#
# Without --apply the script is a dry run: it sends only read requests and
# prints the plan. With --apply it prints the same plan and then carries it
# out. It never prompts, so it runs in sessions without a terminal.
#
# Safety rules under --apply:
#   - Each change is sent once and never retried.
#   - After creating a service principal, the script polls `az ad sp show`
#     every 5 seconds for up to 60 seconds before the next change.
#   - If a change fails with an unclear outcome (a timeout, throttling, a
#     server error, or a failure that az does not explain), the script reads
#     the object back and stops. It reports one of three results: found, not
#     found by a successful read, or not checked because the read failed.
#     Every step reads the current state first and skips what already
#     matches, so a later run carries on from where this one stopped.
#   - Just before an update that replaces a list (API permissions, redirect
#     URIs, a grant's scope), the script reads it again and stops if it
#     changed since planning.
#   - It never removes a grant or a scope. The plan lists every existing
#     grant on the two resources and warns about any that gives more than
#     the plan asks for.
#   - Assignment is required and the users are assigned before any consent is
#     granted, so an interrupted run never leaves a consented app that every
#     user in the tenant may sign in to.
#
# Variables:
#   TENANT_ID        directory (tenant) id; required. `az account show` must
#                    report the same tenant.
#   CLIENT_ID        application (client) id of an existing registration to
#                    update. Without it, the script creates a new one and
#                    refuses if any application already has APP_NAME.
#   APP_NAME         display name of a new registration
#                    (default "Purview CLI (eDiscovery)").
#   ASSIGN_USERS     space-separated user principal names or object ids of
#                    the users who may sign in.
#   GROUP_OBJECT_ID  object id of a group whose members may sign in. Needs
#                    CONSENT=tenant, because a per-user grant takes a user,
#                    not a group.
#   READ_ONLY=1      request eDiscovery.Read.All instead of
#                    eDiscovery.ReadWrite.All.
#   CONSENT          principal (default): one grant per assigned user.
#                    tenant: one grant for all users; assignment still decides
#                    who may sign in.
#   ALLOW_ALL_TENANT_USERS=1
#                    let every user in the tenant sign in. Needs
#                    CONSENT=tenant and no ASSIGN_USERS or GROUP_OBJECT_ID.
#
# Requires the az CLI, signed in with `az login --tenant <tenant-id>` as a user
# who may create applications and grant consent (Cloud Application
# Administrator, Application Administrator or a higher role).

readonly GRAPH_APP_ID=00000003-0000-0000-c000-000000000000
readonly EDISCOVERY_APP_ID=b26e684c-5068-4120-a679-64a5d2c909d9
# eDiscovery.Download.Read on the Purview eDiscovery application (Observed,
# docs/SPEC.md section 5.2 step 1). Used in the plan when the tenant has no
# eDiscovery service principal yet; checked again once it exists.
readonly EDISCOVERY_DOWNLOAD_SCOPE_ID=c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2
readonly DEFAULT_APP_ROLE_ID=00000000-0000-0000-0000-000000000000
readonly GRAPH=https://graph.microsoft.com/v1.0
readonly REDIRECT_URI=http://localhost/callback
readonly POLL_INTERVAL=5
readonly POLL_LIMIT=60

# These queries are fixed strings; tests/scripts/fake-bin/az answers them.
readonly SP_ROW_QUERY='[].[id, appRoleAssignmentRequired]'
readonly SCOPES_QUERY='oauth2PermissionScopes[].[value, id]'
readonly APP_ROW_QUERY='[].[id, signInAudience, isFallbackPublicClient, displayName]'
readonly RRA_QUERY="requiredResourceAccess[].[resourceAppId, join(',', resourceAccess[].join(':', [id, type]))]"
# The fields read from each consent grant; get_pages builds the query.
readonly GRANT_FIELDS='id, resourceId, consentType, principalId, scope'
# Graph's limit on an oauth2PermissionGrant scope (Docs).
readonly GRANT_SCOPE_LIMIT=3850
# Collections are read to their last page; this caps a runaway loop.
readonly PAGE_LIMIT=200

readonly GUID_RE='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
# A user principal name of plain characters. Guest names that contain '#'
# must be given as object ids.
readonly UPN_RE='^[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
readonly APP_NAME_RE='^[A-Za-z0-9][A-Za-z0-9 ()._-]{0,119}$'
readonly SCOPE_WORD_RE='^[A-Za-z0-9._-]+$'
readonly GRANT_ID_RE='^[A-Za-z0-9_-]+$'
# Characters allowed in an existing redirect URI that is copied into an
# update. Anything else stops the script before it builds the request.
readonly REDIRECT_RE='^[A-Za-z0-9:/._~?&=%+-]+$'
# Characters allowed in the part of a continuation link after the Graph
# v1.0 prefix. The link goes to az as an argument, never into a body.
readonly NEXT_LINK_RE='^[A-Za-z0-9/._~?&=%+$,:()'"'"'-]+$'

usage() {
  cat <<'EOF'
Usage: create-purview-app.sh [--apply]

Creates or updates the app registration that purview signs in through.
Without --apply it is a dry run: it only reads, and prints the plan.

  --apply     carry out the plan
  -h, --help  show this help

Variables: TENANT_ID (required), CLIENT_ID, APP_NAME, ASSIGN_USERS,
GROUP_OBJECT_ID, READ_ONLY=1, CONSENT=principal|tenant,
ALLOW_ALL_TENANT_USERS=1. See the comments at the top of the script.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

is_guid() { [[ "$1" =~ $GUID_RE ]]; }

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# sanitize removes control characters from a value read from the tenant
# before it reaches the terminal.
sanitize() { printf '%s' "$1" | tr -d '\000-\037\177'; }

# none_to_empty turns az's "None" for a null value into an empty string.
none_to_empty() {
  if [ "$1" = None ]; then
    printf ''
  else
    printf '%s' "$1"
  fi
}

# field N LINE prints the Nth tab-separated field of LINE. cut keeps empty
# fields, which `read` with a tab in IFS would merge.
field() { cut -f "$1" <<<"$2"; }

first_line() { sed -n 1p <<<"$1"; }

# --- Arguments --------------------------------------------------------------

apply=false
if [ "$#" -gt 1 ]; then
  echo "error: expected at most one argument" >&2
  usage >&2
  exit 2
fi
case "${1:-}" in
  "") ;;
  --apply) apply=true ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown argument %q\n' "$1" >&2
    usage >&2
    exit 2
    ;;
esac

# --- Variables and branch rules ---------------------------------------------
# Every value below goes into a request body, a URL, an OData filter or a
# JMESPath query, so each is checked before the first az call.

TENANT_ID="${TENANT_ID:-}"
CLIENT_ID="${CLIENT_ID:-}"
APP_NAME="${APP_NAME:-Purview CLI (eDiscovery)}"
ASSIGN_USERS="${ASSIGN_USERS:-}"
GROUP_OBJECT_ID="${GROUP_OBJECT_ID:-}"
READ_ONLY="${READ_ONLY:-}"
CONSENT="${CONSENT:-principal}"
ALLOW_ALL_TENANT_USERS="${ALLOW_ALL_TENANT_USERS:-}"

[ -n "$TENANT_ID" ] || fail "TENANT_ID is required (the directory id of the tenant)."
is_guid "$TENANT_ID" || fail "TENANT_ID must be a GUID."
TENANT_ID=$(lower "$TENANT_ID")
if [ -n "$CLIENT_ID" ]; then
  is_guid "$CLIENT_ID" || fail "CLIENT_ID must be a GUID (the application (client) id)."
  CLIENT_ID=$(lower "$CLIENT_ID")
fi
[[ "$APP_NAME" =~ $APP_NAME_RE ]] ||
  fail "APP_NAME may hold only letters, digits, spaces and ( ) . _ -, up to 120 characters."
if [ -n "$GROUP_OBJECT_ID" ]; then
  is_guid "$GROUP_OBJECT_ID" || fail "GROUP_OBJECT_ID must be a group object id (a GUID)."
  GROUP_OBJECT_ID=$(lower "$GROUP_OBJECT_ID")
fi
case "$READ_ONLY" in
  "" | 0) READ_ONLY=0 ;;
  1) ;;
  *) fail "READ_ONLY must be 1 or unset." ;;
esac
case "$CONSENT" in
  principal | tenant) ;;
  *) fail "CONSENT must be 'principal' or 'tenant'." ;;
esac
case "$ALLOW_ALL_TENANT_USERS" in
  "" | 0) ALLOW_ALL_TENANT_USERS=0 ;;
  1) ;;
  *) fail "ALLOW_ALL_TENANT_USERS must be 1 or unset." ;;
esac

assign_words=()
for word in $ASSIGN_USERS; do
  if is_guid "$word"; then
    assign_words+=("$(lower "$word")")
  elif [[ "$word" =~ $UPN_RE ]]; then
    assign_words+=("$word")
  else
    printf 'error: %q in ASSIGN_USERS is neither a user principal name nor an object id.\n' "$word" >&2
    echo "Give a guest user (a name containing '#') by object id." >&2
    exit 1
  fi
done
user_count=${#assign_words[@]}

if [ "$ALLOW_ALL_TENANT_USERS" = 1 ]; then
  if [ "$user_count" -gt 0 ] || [ -n "$GROUP_OBJECT_ID" ]; then
    fail "ALLOW_ALL_TENANT_USERS=1 lets every user sign in, so it cannot be combined with ASSIGN_USERS or GROUP_OBJECT_ID. Set one or the other."
  fi
  if [ "$CONSENT" != tenant ]; then
    fail "ALLOW_ALL_TENANT_USERS=1 needs CONSENT=tenant: per-user consent needs a list of users."
  fi
  restricted=false
else
  if [ "$user_count" -eq 0 ] && [ -z "$GROUP_OBJECT_ID" ]; then
    echo "error: no assignment given." >&2
    echo "Set ASSIGN_USERS to the users who may sign in (or GROUP_OBJECT_ID with CONSENT=tenant)." >&2
    echo "To let every user in the tenant sign in, set ALLOW_ALL_TENANT_USERS=1 and CONSENT=tenant." >&2
    exit 1
  fi
  if [ "$CONSENT" = principal ] && [ -n "$GROUP_OBJECT_ID" ]; then
    echo "error: GROUP_OBJECT_ID cannot be used with per-user consent (CONSENT=principal)." >&2
    echo "A per-user consent grant takes a user, not a group." >&2
    echo "Set CONSENT=tenant to keep the group, or list the users in ASSIGN_USERS instead." >&2
    exit 1
  fi
  restricted=true
fi

if [ "$READ_ONLY" = 1 ]; then
  graph_main_scope=eDiscovery.Read.All
else
  graph_main_scope=eDiscovery.ReadWrite.All
fi
graph_grant_scope="$graph_main_scope offline_access openid profile"
edisc_grant_scope=eDiscovery.Download.Read

err_file=$(mktemp "${TMPDIR:-/tmp}/create-purview-app.XXXXXX")
trap 'rm -f "$err_file"' EXIT

# show_az_error prints az's error, indented, on stderr. It keeps line breaks
# but removes every other control character, and ends with exactly one
# newline whether or not az's output did. The loop, not sed, adds the
# indent, because BSD and GNU sed treat a missing final newline differently.
show_az_error() {
  local text line
  text=$(tr -d '\000-\011\013-\037\177' <"$err_file")
  while IFS= read -r line; do
    printf '    %s\n' "$line" >&2
  done <<<"$text"
}

# read_az WHAT ARGS... runs one read and prints its output. A failed read
# stops the script: nothing after it can be planned safely.
read_az() {
  local what=$1
  shift
  if ! az "$@" 2>"$err_file"; then
    echo "error: could not read $what." >&2
    show_az_error
    exit 1
  fi
}

# --- Tenant -----------------------------------------------------------------

current_tenant=$(az account show --query tenantId -o tsv 2>"$err_file" || true)
current_tenant=$(lower "$(sanitize "$current_tenant")")
if [ "$current_tenant" != "$TENANT_ID" ]; then
  echo "error: az is signed in to tenant '${current_tenant:-none}', not '$TENANT_ID'." >&2
  echo "Run: az login --tenant $TENANT_ID" >&2
  exit 1
fi

# --- Reads ------------------------------------------------------------------
# Long az output goes to awk, sed and grep through here-strings, not pipes.
# A reader that stops early would end a pipe's writer with SIGPIPE, and
# pipefail would turn that into a silent exit.

# scope_id LIST VALUE prints the id paired with VALUE in "value<TAB>id" lines.
scope_id() {
  awk -F '\t' -v want="$2" '!found && $1 == want { print $2; found = 1 }' <<<"$1"
}

# get_pages URL FIELDS reads a Graph collection to its last page and prints
# one tab-separated line of FIELDS per item. Each page's continuation link
# must stay on the Graph v1.0 endpoint. It returns 1, with the reason in
# err_file, if a page cannot be read.
get_pages() {
  local url=$1 query out next pages=0
  query="[[['next', \"@odata.nextLink\"]], value[].['row', $2]][]"
  while :; do
    out=$(az rest --method GET --url "$url" --query "$query" -o tsv 2>"$err_file") || return 1
    awk -F '\t' '$1 == "row" { sub(/^row\t/, ""); print }' <<<"$out"
    next=$(awk -F '\t' '$1 == "next" { print $2 }' <<<"$out")
    if [ -z "$next" ] || [ "$next" = None ]; then
      return 0
    fi
    case "$next" in
      "$GRAPH/"*) ;;
      *)
        echo "a continuation link left the Graph v1.0 endpoint" >"$err_file"
        return 1
        ;;
    esac
    if ! [[ "${next#"$GRAPH/"}" =~ $NEXT_LINK_RE ]]; then
      echo "a continuation link holds unexpected characters" >"$err_file"
      return 1
    fi
    pages=$((pages + 1))
    if [ "$pages" -ge "$PAGE_LIMIT" ]; then
      echo "the collection has more than $PAGE_LIMIT pages" >"$err_file"
      return 1
    fi
    url=$next
  done
}

# read_pages WHAT URL FIELDS is get_pages for planning: a failure stops the
# script.
read_pages() {
  local what=$1
  shift
  if ! get_pages "$@"; then
    echo "error: could not read $what." >&2
    show_az_error
    exit 1
  fi
}

graph_sp_id=$(read_az "the Microsoft Graph service principal" \
  ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)
is_guid "$graph_sp_id" || fail "the Microsoft Graph service principal has no readable object id."
graph_sp_id=$(lower "$graph_sp_id")
graph_scopes=$(read_az "the Microsoft Graph delegated scopes" \
  ad sp show --id "$GRAPH_APP_ID" --query "$SCOPES_QUERY" -o tsv)
# Bash turns off errexit inside a command substitution, so the status of
# each scope_id call is checked here rather than left to set -e.
resolve_graph_scope() {
  local id
  id=$(scope_id "$graph_scopes" "$1") || fail "could not search the Microsoft Graph scope list for $1."
  is_guid "$id" || fail "Microsoft Graph does not expose the delegated scope $1."
  lower "$id"
}
graph_main_id=$(resolve_graph_scope "$graph_main_scope")
offline_access_id=$(resolve_graph_scope offline_access)
openid_id=$(resolve_graph_scope openid)
profile_id=$(resolve_graph_scope profile)

# check_download_scope LIST stops the script unless the eDiscovery service
# principal gives eDiscovery.Download.Read the id this script expects.
check_download_scope() {
  local found
  found=$(scope_id "$1" eDiscovery.Download.Read) ||
    fail "could not search the Purview eDiscovery scope list."
  found=$(lower "$found")
  if [ "$found" != "$EDISCOVERY_DOWNLOAD_SCOPE_ID" ]; then
    fail "the Purview eDiscovery service principal gives eDiscovery.Download.Read the id '$(sanitize "$found")', not $EDISCOVERY_DOWNLOAD_SCOPE_ID. Nothing was changed by this check; report it before running again."
  fi
}

edisc_row=$(read_az "the Purview eDiscovery service principal" \
  ad sp list --filter "appId eq '$EDISCOVERY_APP_ID'" --query "$SP_ROW_QUERY" -o tsv)
edisc_sp_id=$(none_to_empty "$(field 1 "$(first_line "$edisc_row")")")
edisc_download_id=$EDISCOVERY_DOWNLOAD_SCOPE_ID
if [ -n "$edisc_sp_id" ]; then
  is_guid "$edisc_sp_id" || fail "the Purview eDiscovery service principal has no readable object id."
  edisc_sp_id=$(lower "$edisc_sp_id")
  create_edisc_sp=false
  edisc_scopes=$(read_az "the Purview eDiscovery delegated scopes" \
    ad sp show --id "$EDISCOVERY_APP_ID" --query "$SCOPES_QUERY" -o tsv)
  check_download_scope "$edisc_scopes"
else
  create_edisc_sp=true
fi

# The application.
app_obj_id=""
app_id=""
app_display=""
need_fallback=false
need_redirect=false
current_redirects=""
current_rra=""
current_rra_lines=""
if [ -n "$CLIENT_ID" ]; then
  app_row=$(read_az "application $CLIENT_ID" \
    ad app list --filter "appId eq '$CLIENT_ID'" --query "$APP_ROW_QUERY" -o tsv)
  app_row=$(first_line "$app_row")
  [ -n "$app_row" ] || fail "no application with appId $CLIENT_ID in tenant $TENANT_ID. Check CLIENT_ID, or unset it to create a new registration."
  app_obj_id=$(field 1 "$app_row")
  is_guid "$app_obj_id" || fail "application $CLIENT_ID has no readable object id."
  app_obj_id=$(lower "$app_obj_id")
  audience=$(field 2 "$app_row")
  if [ "$audience" != AzureADMyOrg ]; then
    fail "application $CLIENT_ID has signInAudience '$(sanitize "$audience")'; purview needs a single-tenant app (AzureADMyOrg). Use another CLIENT_ID, or unset it to create one."
  fi
  fallback=$(lower "$(field 3 "$app_row")")
  [ "$fallback" = true ] || need_fallback=true
  app_display=$(sanitize "$(field 4- "$app_row")")
  app_id=$CLIENT_ID
  # The default access role that assignments use is valid only on an app
  # that declares no app roles (Docs, appRoleAssignment resource).
  if [ "$restricted" = true ]; then
    roles=$(read_az "the app roles of application $CLIENT_ID" \
      ad app show --id "$CLIENT_ID" --query "appRoles[].id" -o tsv)
    if [ -n "$roles" ]; then
      fail "application $CLIENT_ID declares app roles, so the default access role this script assigns is not valid for it. Use a registration without app roles, or unset CLIENT_ID to create one."
    fi
  fi
  current_redirects=$(read_az "the redirect URIs of application $CLIENT_ID" \
    ad app show --id "$CLIENT_ID" --query publicClient.redirectUris -o tsv)
  if ! grep -qxF "$REDIRECT_URI" <<<"$current_redirects"; then
    need_redirect=true
    while IFS= read -r uri; do
      [ -n "$uri" ] || continue
      [[ "$uri" =~ $REDIRECT_RE ]] ||
        fail "application $CLIENT_ID has a public-client redirect URI with unexpected characters. Add $REDIRECT_URI by hand, then run this script again."
    done <<<"$current_redirects"
  fi
  current_rra=$(read_az "the API permissions of application $CLIENT_ID" \
    ad app show --id "$CLIENT_ID" --query "$RRA_QUERY" -o tsv)
else
  same_name=$(read_az "applications named '$APP_NAME'" \
    ad app list --filter "displayName eq '$APP_NAME'" --query "[].appId" -o tsv)
  if [ -n "$same_name" ]; then
    echo "error: an application named '$APP_NAME' already exists in this tenant:" >&2
    while IFS= read -r existing; do
      if is_guid "$existing"; then
        echo "    appId $existing" >&2
      else
        echo "    (an appId that is not a GUID)" >&2
      fi
    done <<<"$same_name"
    echo "Set CLIENT_ID to update one of them, or choose another APP_NAME." >&2
    exit 1
  fi
fi
create_app=false
[ -n "$app_id" ] || create_app=true

# The intended requiredResourceAccess as "resourceAppId id type" lines, in
# plan order and sorted for comparison, and as the JSON value sent to Graph.
intended_rra_plan=$(printf '%s\n' \
  "$GRAPH_APP_ID $graph_main_id Scope" \
  "$GRAPH_APP_ID $offline_access_id Scope" \
  "$GRAPH_APP_ID $openid_id Scope" \
  "$GRAPH_APP_ID $profile_id Scope" \
  "$EDISCOVERY_APP_ID $edisc_download_id Scope")
intended_rra=$(sort <<<"$intended_rra_plan")
rra_json() {
  printf '[{"resourceAppId":"%s","resourceAccess":[' "$GRAPH_APP_ID"
  printf '{"id":"%s","type":"Scope"},' "$graph_main_id" "$offline_access_id" "$openid_id"
  printf '{"id":"%s","type":"Scope"}]},' "$profile_id"
  printf '{"resourceAppId":"%s","resourceAccess":[{"id":"%s","type":"Scope"}]}]' \
    "$EDISCOVERY_APP_ID" "$edisc_download_id"
}

# normalize_rra turns the RRA_QUERY rows ("app<TAB>id:type,id:type") into
# sorted "app id type" lines.
normalize_rra() {
  awk -F '\t' '
    NF == 0 { next }
    {
      n = split($2, parts, ",")
      for (i = 1; i <= n; i++) {
        if (parts[i] == "") continue
        split(parts[i], pair, ":")
        print tolower($1) " " tolower(pair[1]) " " pair[2]
      }
    }' <<<"$1" | sort
}
need_rra=false
if [ "$create_app" = false ]; then
  current_rra_lines=$(normalize_rra "$current_rra")
  [ "$current_rra_lines" = "$intended_rra" ] || need_rra=true
fi

# The application's own service principal.
app_sp_id=""
current_required=""
if [ "$create_app" = false ]; then
  app_sp_row=$(read_az "the service principal of application $app_id" \
    ad sp list --filter "appId eq '$app_id'" --query "$SP_ROW_QUERY" -o tsv)
  app_sp_row=$(first_line "$app_sp_row")
  app_sp_id=$(none_to_empty "$(field 1 "$app_sp_row")")
  if [ -n "$app_sp_id" ]; then
    is_guid "$app_sp_id" || fail "the service principal of application $app_id has no readable object id."
    app_sp_id=$(lower "$app_sp_id")
    current_required=$(lower "$(field 2 "$app_sp_row")")
  fi
fi
create_app_sp=false
[ -n "$app_sp_id" ] || create_app_sp=true
if [ "$restricted" = true ]; then
  intended_required=true
else
  intended_required=false
fi
need_required=false
if [ "$create_app_sp" = false ] && [ "$current_required" != "$intended_required" ]; then
  need_required=true
fi

# Owners. A Graph create adds no owner (Observed, docs/SPEC.md section 5.2
# step 2), so a new app gets the signed-in user. An existing app with no
# owner at all, which an interrupted create leaves, gets one too. An app that
# already has owners is left as it is.
need_owner=false
owner_note=""
if [ "$create_app" = true ]; then
  need_owner=true
else
  owners=$(read_pages "the owners of application $app_id" \
    "$GRAPH/applications/$app_obj_id/owners?\$select=id" id)
  if [ -z "$owners" ]; then
    need_owner=true
  else
    owner_note="the application already has owners; unchanged"
  fi
fi
me_id=""
me_upn=""
if [ "$need_owner" = true ]; then
  me=$(read_az "the signed-in user" ad signed-in-user show --query "[id, userPrincipalName]" -o tsv)
  me_id=$(first_line "$me")
  me_upn=$(sanitize "$(sed -n 2p <<<"$me")")
  is_guid "$me_id" || fail "the signed-in user has no readable object id; sign in to az as a user."
  me_id=$(lower "$me_id")
fi

# Assignees: object ids, labels and whether each is already assigned.
existing_assignments=""
if [ "$create_app_sp" = false ] && [ "$restricted" = true ]; then
  existing_assignments=$(read_pages "the assignments of application $app_id" \
    "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo?\$top=999" "principalId, appRoleId")
fi
is_assigned() {
  awk -F '\t' -v p="$1" -v r="$DEFAULT_APP_ROLE_ID" \
    'tolower($1) == p && tolower($2) == r { found = 1 } END { exit !found }' <<<"$existing_assignments"
}

a_ids=()
a_labels=()
a_kinds=()
a_assigned=()
unresolved=0
unresolved_lines=()
add_assignee() { # id label kind
  local i=0
  while [ "$i" -lt "${#a_ids[@]}" ]; do
    [ "${a_ids[$i]}" != "$1" ] || return 0
    i=$((i + 1))
  done
  a_ids+=("$1")
  a_labels+=("$2")
  a_kinds+=("$3")
  if is_assigned "$1"; then
    a_assigned+=(true)
  else
    a_assigned+=(false)
  fi
}
# unresolved_lookup LABEL NOT_FOUND records an assignee that did not resolve.
# A definite not-found from az records NOT_FOUND. Any other failure, such as
# a refusal, throttling, an expired session or a network error, shows az's
# error and records that the lookup could not be checked.
unresolved_lookup() {
  unresolved=$((unresolved + 1))
  if grep -Eq 'Request_ResourceNotFound|does not exist or one of its queried reference-property objects are not present|(^|ERROR: )Not Found(\(|$)' "$err_file"; then
    unresolved_lines+=("$1: $2")
    return 0
  fi
  echo "error: could not look up $1:" >&2
  show_az_error
  unresolved_lines+=("$1: the lookup could not be checked; az's error is shown above")
}
for word in ${assign_words[@]+"${assign_words[@]}"}; do
  if user=$(az ad user show --id "$word" --query "[id, userPrincipalName]" -o tsv 2>"$err_file"); then
    uid=$(first_line "$user")
    upn=$(sanitize "$(sed -n 2p <<<"$user")")
    if is_guid "$uid"; then
      add_assignee "$(lower "$uid")" "$upn" user
      continue
    fi
    echo "az returned no readable object id" >"$err_file"
  fi
  unresolved_lookup "$word" "no directory user found (check the sign-in name, which may differ from the mail address)"
done
if [ -n "$GROUP_OBJECT_ID" ]; then
  if group=$(az rest --method GET --url "$GRAPH/groups/$GROUP_OBJECT_ID?\$select=id,displayName" \
    --query "[id, displayName]" -o tsv 2>"$err_file"); then
    if is_guid "$(first_line "$group")"; then
      add_assignee "$GROUP_OBJECT_ID" "group $(sanitize "$(sed -n 2p <<<"$group")")" group
    else
      echo "az returned no readable object id" >"$err_file"
      unresolved_lookup "group $GROUP_OBJECT_ID" "no group found"
    fi
  else
    unresolved_lookup "group $GROUP_OBJECT_ID" "no group found"
  fi
fi

# Consent grants: one per resource, per assigned user or for all principals.
grants_url() { printf '%s' "$GRAPH/oauth2PermissionGrants?\$filter=clientId%20eq%20'$app_sp_id'"; }
existing_grants=""
if [ "$create_app_sp" = false ]; then
  existing_grants=$(read_pages "the consent grants of application $app_id" \
    "$(grants_url)" "$GRANT_FIELDS")
fi

# join_words TEXT prints the words of TEXT joined by single spaces. It
# returns 1 if a word holds a character no scope name has.
join_words() {
  local word out=""
  for word in $1; do
    [[ "$word" =~ $SCOPE_WORD_RE ]] || return 1
    out="$out${out:+ }$word"
  done
  printf '%s' "$out"
}

# find_grant RESOURCE_ID TYPE PRINCIPAL sets found_grant_id and the raw
# found_grant_scope from existing_grants, or leaves them empty.
find_grant() {
  local line
  found_grant_id=""
  found_grant_scope=""
  [ -n "$1" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [ "$(lower "$(field 2 "$line")")" = "$1" ] || continue
    [ "$(field 3 "$line")" = "$2" ] || continue
    if [ "$2" = Principal ] && [ "$(lower "$(field 4 "$line")")" != "$3" ]; then
      continue
    fi
    found_grant_id=$(field 1 "$line")
    found_grant_scope=$(none_to_empty "$(field 5- "$line")")
    return 0
  done <<<"$existing_grants"
}

# grant_scope_by_id ID prints the raw scope of the grant with that id in
# existing_grants, and returns 1 if there is none.
grant_scope_by_id() {
  local line
  while IFS= read -r line; do
    if [ -n "$line" ] && [ "$(field 1 "$line")" = "$1" ]; then
      none_to_empty "$(field 5- "$line")"
      return 0
    fi
  done <<<"$existing_grants"
  return 1
}

# words_missing WANTED HAVE prints the words of WANTED that HAVE lacks.
words_missing() {
  local w h found out=""
  for w in $1; do
    found=false
    for h in $2; do
      [ "$h" != "$w" ] || found=true
    done
    [ "$found" = true ] || out="$out${out:+ }$w"
  done
  printf '%s' "$out"
}

g_res=()       # graph or edisc
g_type=()      # Principal or AllPrincipals
g_principal=() # user object id, or empty
g_who=()       # label for the plan
g_action=()    # present, create or update
g_grant_id=()
g_old_scope=() # the existing scope, words joined by single spaces
g_scope=()     # the scope the grant will hold
plan_grant() { # res type principal label
  local res_id wanted old missing scope
  if [ "$1" = graph ]; then
    res_id=$graph_sp_id
    wanted=$graph_grant_scope
  else
    res_id=$edisc_sp_id
    wanted=$edisc_grant_scope
  fi
  find_grant "$res_id" "$2" "$3"
  g_res+=("$1")
  g_type+=("$2")
  g_principal+=("$3")
  g_who+=("$4")
  if [ -z "$found_grant_id" ]; then
    g_action+=(create)
    g_grant_id+=("")
    g_old_scope+=("")
    g_scope+=("$wanted")
    return 0
  fi
  [[ "$found_grant_id" =~ $GRANT_ID_RE ]] || fail "a consent grant of application $app_id has an id of unexpected characters."
  old=$(join_words "$found_grant_scope") ||
    fail "a consent grant of application $app_id holds a scope of unexpected characters."
  missing=$(words_missing "$wanted" "$old")
  scope="$old${old:+${missing:+ }}$missing"
  if [ "${#scope}" -gt "$GRANT_SCOPE_LIMIT" ]; then
    fail "the consent grant $found_grant_id would hold ${#scope} characters of scope, more than Graph's $GRANT_SCOPE_LIMIT. Remove unused scopes from it by hand first."
  fi
  g_grant_id+=("$found_grant_id")
  g_old_scope+=("$old")
  g_scope+=("$scope")
  if [ -z "$missing" ]; then
    g_action+=(present)
  else
    g_action+=(update)
  fi
}
if [ "$CONSENT" = tenant ]; then
  plan_grant graph AllPrincipals "" "all users"
  plan_grant edisc AllPrincipals "" "all users"
else
  i=0
  while [ "$i" -lt "${#a_ids[@]}" ]; do
    if [ "${a_kinds[$i]}" = user ]; then
      plan_grant graph Principal "${a_ids[$i]}" "${a_labels[$i]}"
      plan_grant edisc Principal "${a_ids[$i]}" "${a_labels[$i]}"
    fi
    i=$((i + 1))
  done
fi

# --- Plan -------------------------------------------------------------------

scope_name() {
  case "$1" in
    "$graph_main_id") echo "$graph_main_scope" ;;
    "$offline_access_id") echo offline_access ;;
    "$openid_id") echo openid ;;
    "$profile_id") echo profile ;;
    "$edisc_download_id") echo eDiscovery.Download.Read ;;
    *) echo "(other)" ;;
  esac
}
resource_name() {
  case "$1" in
    "$GRAPH_APP_ID") echo "Microsoft Graph" ;;
    "$EDISCOVERY_APP_ID") echo "Purview eDiscovery" ;;
    *) echo "(other resource)" ;;
  esac
}
print_rra() {
  local app id type
  while read -r app id type; do
    [ -n "$app" ] || continue
    app=$(sanitize "$app")
    id=$(sanitize "$id")
    type=$(sanitize "$type")
    printf '      %-20s %-26s %s %s\n' "$(resource_name "$app")" "$(scope_name "$id")" "$id" "$type"
  done <<<"$1"
}

# principal_label ID names an assignee in this plan, or gives the object id.
principal_label() {
  local i=0
  while [ "$i" -lt "${#a_ids[@]}" ]; do
    if [ "${a_ids[$i]}" = "$1" ]; then
      printf '%s' "${a_labels[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  printf 'user %s (not in this plan)' "$(sanitize "$1")"
}

# is_planned_user ID reports whether ID is one of the users this plan assigns.
is_planned_user() {
  local i=0
  while [ "$i" -lt "${#a_ids[@]}" ]; do
    if [ "${a_ids[$i]}" = "$1" ] && [ "${a_kinds[$i]}" = user ]; then
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# print_removal_advice ID gives the command that removes a grant whose
# audience is definitely outside the plan. It gives none under --apply,
# because the run may change the grants it is about, and none while an
# assignee lookup is unresolved, because the plan's users are then not known.
print_removal_advice() {
  if [ "$apply" = true ]; then
    return 0
  fi
  if [ "$unresolved" -gt 0 ]; then
    echo "      No removal command is given while an assignee lookup is unresolved."
    return 0
  fi
  if ! [[ "$1" =~ $GRANT_ID_RE ]]; then
    echo "      Its id holds unexpected characters; remove it in the Entra admin center if that is wanted."
    return 0
  fi
  echo "      To remove the whole grant by hand:"
  echo "        az rest --method DELETE --url $GRAPH/oauth2PermissionGrants/$1"
}

# print_existing_grants lists every grant the application already holds on
# Graph and on the eDiscovery app, and warns about each one that gives more
# than this plan asks for. It gives no command that narrows a grant: a
# narrowed scope list worked out from this run's state could remove scopes
# that an --apply run adds. It sets broader_grants to the number of warnings.
broader_grants=0
print_existing_grants() {
  local line id res type principal scope res_label wanted who extra reasons wrong_audience
  echo "  Existing consent grants of this application on these two resources:"
  if [ -z "$existing_grants" ]; then
    echo "    none"
    return 0
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    id=$(sanitize "$(field 1 "$line")")
    res=$(lower "$(field 2 "$line")")
    type=$(sanitize "$(field 3 "$line")")
    principal=$(lower "$(none_to_empty "$(field 4 "$line")")")
    scope=$(sanitize "$(tr '\t' ' ' <<<"$(none_to_empty "$(field 5- "$line")")")")
    if [ "$res" = "$graph_sp_id" ]; then
      res_label="Microsoft Graph"
      wanted=$graph_grant_scope
    elif [ -n "$edisc_sp_id" ] && [ "$res" = "$edisc_sp_id" ]; then
      res_label="Purview eDiscovery"
      wanted=$edisc_grant_scope
    else
      continue
    fi
    if [ "$type" = AllPrincipals ]; then
      who="all users (AllPrincipals)"
    else
      who="$(principal_label "$principal") (Principal)"
    fi
    echo "    - $res_label, $who, grant $id: $scope"
    reasons=""
    wrong_audience=false
    if [ "$CONSENT" = principal ]; then
      if [ "$type" = AllPrincipals ]; then
        wrong_audience=true
        reasons="it covers every user in the tenant, but the plan asks for per-user consent"
      elif ! is_planned_user "$principal"; then
        if [ "$unresolved" -gt 0 ]; then
          echo "      NOTE: this grant's user is not among the assignees that resolved. An assignee"
          echo "      lookup did not resolve, so whether the grant is for a user outside the plan"
          echo "      could not be checked."
        else
          wrong_audience=true
          reasons="it is for a user this plan does not assign"
        fi
      fi
    fi
    extra=$(words_missing "$scope" "$wanted")
    if [ -n "$extra" ]; then
      reasons="$reasons${reasons:+; }it also holds $extra, which the plan does not ask for"
    fi
    [ -n "$reasons" ] || continue
    broader_grants=$((broader_grants + 1))
    echo "      WARNING: this grant gives more than the plan asks for: $reasons."
    echo "      The script never removes a grant or a scope: this grant's existing scopes are kept."
    if [ -n "$extra" ]; then
      echo "      To narrow it, remove the extra scopes by hand in the Entra admin center or with"
      echo "      Microsoft Graph, if that is wanted."
    fi
    if [ "$wrong_audience" = true ]; then
      print_removal_advice "$id"
    fi
  done <<<"$existing_grants"
}

changes=0
count() { [ "$1" != true ] || changes=$((changes + 1)); }

if [ "$apply" = true ]; then
  echo "Plan"
else
  echo "Plan (dry run: nothing is changed)"
fi
echo "  Tenant: $TENANT_ID (az is signed in to it)"
if [ "$create_app" = true ]; then
  echo "  Application: create '$APP_NAME' (single tenant, public client, no credentials)"
else
  echo "  Application: update $app_id ('$app_display', object id $app_obj_id)"
fi
if [ "$need_owner" = true ]; then
  if [ "$create_app" = true ]; then
    echo "  Owner: add the signed-in user $me_upn ($me_id)"
  else
    echo "  Owner: the application has no owner; add the signed-in user $me_upn ($me_id)"
  fi
else
  echo "  Owner: $owner_note"
fi
echo "  Service principals to create:"
if [ "$create_edisc_sp" = true ]; then
  echo "    - Purview eDiscovery (MicrosoftPurviewEDiscovery, appId $EDISCOVERY_APP_ID)"
  echo "      The tenant has none yet. Its scope id $EDISCOVERY_DOWNLOAD_SCOPE_ID is checked once it exists."
fi
if [ "$create_app_sp" = true ]; then
  echo "    - the application's own service principal"
fi
if [ "$create_edisc_sp" = false ] && [ "$create_app_sp" = false ]; then
  echo "    none"
fi
echo "  requiredResourceAccess (the full list the application will hold):"
print_rra "$intended_rra_plan"
if [ "$create_app" = false ]; then
  if [ "$need_rra" = true ]; then
    echo "    Current list differs, and will be replaced. Current:"
    if [ -n "$current_rra_lines" ]; then
      print_rra "$current_rra_lines"
    else
      echo "      (empty)"
    fi
  else
    echo "    Current list matches; unchanged."
  fi
fi
if [ "$create_app" = true ]; then
  echo "  Public client: redirect URI $REDIRECT_URI, isFallbackPublicClient true"
else
  if [ "$need_redirect" = true ]; then
    echo "  Redirect URI $REDIRECT_URI: missing; will be added, other redirect URIs kept"
  else
    echo "  Redirect URI $REDIRECT_URI: present"
  fi
  if [ "$need_fallback" = true ]; then
    echo "  isFallbackPublicClient: not true; will be set to true"
  else
    echo "  isFallbackPublicClient: true"
  fi
fi

echo "  Assignees:"
if [ "$restricted" = false ]; then
  echo "    none (ALLOW_ALL_TENANT_USERS=1)"
fi
i=0
while [ "$i" -lt "${#a_ids[@]}" ]; do
  if [ "${a_assigned[$i]}" = true ]; then
    state="already assigned"
  else
    state="will be assigned"
  fi
  echo "    - ${a_labels[$i]} -> ${a_ids[$i]}: $state"
  i=$((i + 1))
done
for line in ${unresolved_lines[@]+"${unresolved_lines[@]}"}; do
  echo "    - UNRESOLVED $line"
done

echo "  Effective assignment state:"
if [ "$create_app_sp" = true ]; then
  echo "    appRoleAssignmentRequired: $intended_required (set when the service principal is created)"
elif [ "$need_required" = true ]; then
  echo "    appRoleAssignmentRequired: $intended_required (currently ${current_required:-unset}; will be changed)"
else
  echo "    appRoleAssignmentRequired: $intended_required (unchanged)"
fi
if [ "$restricted" = true ]; then
  echo "    Who may sign in: only the assignees listed above, any principals assigned earlier, and"
  echo "    Global Administrators, whom Microsoft does not hold to the assignment requirement."
else
  echo "    Who may sign in: EVERY USER IN THE TENANT can sign in through this app."
fi

echo "  Consent (granted after assignment):"
if [ "$CONSENT" = tenant ]; then
  echo "    Type: tenant-wide (AllPrincipals); assignment decides who may sign in."
else
  echo "    Type: per user (Principal), one grant per resource for each assigned user."
fi
i=0
while [ "$i" -lt "${#g_res[@]}" ]; do
  if [ "${g_res[$i]}" = graph ]; then
    res_label="Microsoft Graph"
    wanted=$graph_grant_scope
  else
    res_label="Purview eDiscovery"
    wanted=$edisc_grant_scope
  fi
  case "${g_action[$i]}" in
    present) state="present" ;;
    create) state="will be granted" ;;
    update) state="will be extended to: ${g_scope[$i]}" ;;
  esac
  echo "    - $res_label for ${g_who[$i]}: $wanted ($state)"
  i=$((i + 1))
done
if [ "${#g_res[@]}" -eq 0 ]; then
  echo "    none"
fi
print_existing_grants

count "$create_edisc_sp"
count "$create_app"
count "$need_rra"
count "$need_redirect"
count "$need_fallback"
count "$need_owner"
count "$create_app_sp"
count "$need_required"
i=0
while [ "$i" -lt "${#a_ids[@]}" ]; do
  [ "${a_assigned[$i]}" = true ] || changes=$((changes + 1))
  i=$((i + 1))
done
i=0
while [ "$i" -lt "${#g_res[@]}" ]; do
  [ "${g_action[$i]}" = present ] || changes=$((changes + 1))
  i=$((i + 1))
done
echo "  Changes: $changes"
echo

if [ "$broader_grants" -gt 0 ]; then
  echo "warning: $broader_grants existing consent grant(s) give more than this plan asks for; see WARNING above." >&2
fi

if [ "$unresolved" -gt 0 ]; then
  echo "error: $unresolved assignee(s) could not be resolved; see UNRESOLVED above. Nothing was changed." >&2
  exit 1
fi

if [ "$apply" = false ]; then
  echo "Dry run: nothing was changed."
  if [ "$changes" -gt 0 ]; then
    echo "To carry out this plan, run the same command with --apply."
  fi
  exit 0
fi

# --- Apply ------------------------------------------------------------------

print_login() {
  local read_only_flag=""
  [ "$READ_ONLY" != 1 ] || read_only_flag=" --read-only"
  echo
  echo "Sign in with:"
  echo "    purview auth login --client-id $app_id --tenant-id $TENANT_ID$read_only_flag"
  echo "Add --browser to sign in through a browser on this machine instead of with a device code."
  echo "Later runs of this script for this application need CLIENT_ID=$app_id."
  echo "Each user also needs the eDiscovery Manager or eDiscovery Administrator role group in the Purview portal."
  # The warnings came from the state before this run, which may have changed
  # those grants, so --apply gives no grant advice of its own.
  if [ "$broader_grants" -gt 0 ]; then
    echo
    echo "$broader_grants consent grant(s) gave more than the plan asks for when this run started; see WARNING above."
    echo "This run may have changed them. Run the dry run again to see them as they are now, with removal commands where they apply."
  fi
}

if [ "$changes" -eq 0 ]; then
  echo "Nothing to change."
  print_login
  exit 0
fi

# is_unclear reports whether the failure in err_file leaves the outcome
# unknown. az rest reports an HTTP error as its reason phrase followed by the
# body in parentheses. Throttling, timeouts and server errors are unclear;
# other client errors and az's own refusals are definite. Anything not
# recognised counts as unclear, so that it is read back.
is_unclear() {
  if grep -Eq '(^|ERROR: )(Too Many Requests|Request Timeout|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout)(\(|$)' "$err_file"; then
    return 0
  fi
  if grep -Eq '(^|ERROR: )(Bad Request|Unauthorized|Forbidden|Not Found|Method Not Allowed|Conflict|Gone|Precondition Failed|Request Entity Too Large|Unsupported Media Type|Unprocessable Entity)(\(|$)' "$err_file"; then
    return 1
  fi
  if grep -Eq "Insufficient privileges|Authorization_RequestDenied|az login" "$err_file"; then
    return 1
  fi
  return 0
}

current_step=""
# send STEP METHOD URL BODY [QUERY] sends one change, once. On success it
# returns 0 with az's output in sent_output. A definite failure stops the
# script. An unclear one returns 1 so that the caller reads the object back
# and then stops with stop_found, stop_absent or stop_unverified.
send() {
  local method=$2 url=$3 body=$4 query=${5:-}
  current_step=$1
  echo "==> $current_step"
  sent_output=""
  if [ -n "$query" ]; then
    if sent_output=$(az rest --method "$method" --url "$url" --body "$body" --query "$query" -o tsv 2>"$err_file"); then
      return 0
    fi
  else
    if az rest --method "$method" --url "$url" --body "$body" -o none 2>"$err_file"; then
      return 0
    fi
  fi
  show_az_error
  if ! is_unclear; then
    echo "error: step '$current_step' was refused, so it made no change. Earlier steps stand." >&2
    echo "Fix the cause, then run the script again; it skips what already matches." >&2
    exit 1
  fi
  echo "    The outcome is unclear. Reading the result back; nothing is resent." >&2
  return 1
}

# After an unclear outcome the read-back has one of three results, and each
# ends the run with its own message.
stop_found() {
  echo "error: the outcome of step '$current_step' was unclear. Read-back: found: $1." >&2
  echo "Nothing else was sent. Running the script again is safe: it reads the current state and skips what already matches." >&2
  exit 1
}
stop_absent() {
  echo "error: the outcome of step '$current_step' was unclear. Read-back: not found by a successful read: $1." >&2
  echo "Nothing else was sent. Directory changes can take a few minutes to show, so wait, then run the dry run again and check its plan before --apply." >&2
  exit 1
}
stop_unverified() {
  echo "    The read-back failed too:" >&2
  show_az_error
  echo "error: the outcome of step '$current_step' was unclear, and the read-back could not check $1." >&2
  echo "Nothing else was sent. Check the tenant, then run the dry run again before --apply." >&2
  exit 1
}

# read_back_sp APP_ID LABEL reports whether the service principal exists
# after an unclear create.
read_back_sp() {
  local out
  if ! out=$(az ad sp list --filter "appId eq '$1'" --query "[].id" -o tsv 2>"$err_file"); then
    stop_unverified "whether the $2 service principal exists"
  fi
  if is_guid "$(first_line "$out")"; then
    stop_found "the $2 service principal exists"
  fi
  stop_absent "the $2 service principal"
}

# wait_for_sp APP_ID LABEL polls with reads until the service principal is
# visible, then prints its object id.
wait_for_sp() {
  local waited=0 id
  while :; do
    if id=$(az ad sp show --id "$1" --query id -o tsv 2>"$err_file") && is_guid "$id"; then
      lower "$id"
      return 0
    fi
    if [ "$waited" -ge "$POLL_LIMIT" ]; then
      echo "error: the $2 service principal was created but is still not visible after ${POLL_LIMIT}s." >&2
      echo "Running the script again is safe: it finds the service principal and carries on." >&2
      exit 1
    fi
    sleep "$POLL_INTERVAL"
    waited=$((waited + POLL_INTERVAL))
  done
}

# 1. The Purview eDiscovery service principal.
if [ "$create_edisc_sp" = true ]; then
  if ! send "create the Purview eDiscovery service principal" POST "$GRAPH/servicePrincipals" \
    "{\"appId\":\"$EDISCOVERY_APP_ID\"}"; then
    read_back_sp "$EDISCOVERY_APP_ID" "Purview eDiscovery"
  fi
  edisc_sp_id=$(wait_for_sp "$EDISCOVERY_APP_ID" "Purview eDiscovery")
  echo "    object id $edisc_sp_id"
  edisc_scopes=$(read_az "the Purview eDiscovery delegated scopes" \
    ad sp show --id "$EDISCOVERY_APP_ID" --query "$SCOPES_QUERY" -o tsv)
  check_download_scope "$edisc_scopes"
  echo "    eDiscovery.Download.Read is $EDISCOVERY_DOWNLOAD_SCOPE_ID, as planned"
fi

# 2. The application.
sent_redirects=""
if [ "$create_app" = true ]; then
  body="{\"displayName\":\"$APP_NAME\",\"signInAudience\":\"AzureADMyOrg\",\"isFallbackPublicClient\":true,\"publicClient\":{\"redirectUris\":[\"$REDIRECT_URI\"]},\"requiredResourceAccess\":$(rra_json)}"
  if ! send "create application '$APP_NAME'" POST "$GRAPH/applications" "$body" "[id, appId]"; then
    if ! found=$(az ad app list --filter "displayName eq '$APP_NAME'" --query "[].appId" -o tsv 2>"$err_file"); then
      stop_unverified "whether an application named '$APP_NAME' exists"
    fi
    found=$(first_line "$found")
    if is_guid "$found"; then
      stop_found "an application named '$APP_NAME' exists with appId $(lower "$found"); run again with CLIENT_ID=$(lower "$found")"
    fi
    stop_absent "an application named '$APP_NAME'"
  fi
  app_obj_id=$(first_line "$sent_output")
  app_id=$(sed -n 2p <<<"$sent_output")
  if ! is_guid "$app_obj_id" || ! is_guid "$app_id"; then
    fail "the application was created but az did not return its ids. Find it by the name '$APP_NAME' and run again with CLIENT_ID set."
  fi
  app_obj_id=$(lower "$app_obj_id")
  app_id=$(lower "$app_id")
  echo "    appId $app_id, object id $app_obj_id"
elif [ "$need_rra" = true ] || [ "$need_redirect" = true ] || [ "$need_fallback" = true ]; then
  # The update replaces whole lists, so read them again just before it and
  # stop if another change landed since planning.
  now_rra=$(read_az "the API permissions of application $app_id" \
    ad app show --id "$app_id" --query "$RRA_QUERY" -o tsv)
  now_redirects=$(read_az "the redirect URIs of application $app_id" \
    ad app show --id "$app_id" --query publicClient.redirectUris -o tsv)
  if [ "$(normalize_rra "$now_rra")" != "$current_rra_lines" ] || [ "$now_redirects" != "$current_redirects" ]; then
    fail "application $app_id changed after this run read it: its API permissions or redirect URIs differ. Nothing was sent to it; run the script again to plan from the new state."
  fi
  parts=""
  if [ "$need_rra" = true ]; then
    parts="\"requiredResourceAccess\":$(rra_json)"
  fi
  if [ "$need_fallback" = true ]; then
    parts="$parts${parts:+,}\"isFallbackPublicClient\":true"
  fi
  if [ "$need_redirect" = true ]; then
    uris=""
    while IFS= read -r uri; do
      [ -n "$uri" ] || continue
      uris="$uris\"$uri\","
      sent_redirects="$sent_redirects$uri"$'\n'
    done <<<"$current_redirects"
    sent_redirects="$sent_redirects$REDIRECT_URI"
    parts="$parts${parts:+,}\"publicClient\":{\"redirectUris\":[$uris\"$REDIRECT_URI\"]}"
  fi
  if ! send "update application $app_id" PATCH "$GRAPH/applications/$app_obj_id" "{$parts}"; then
    if ! row=$(az ad app list --filter "appId eq '$app_id'" --query "$APP_ROW_QUERY" -o tsv 2>"$err_file") ||
      ! now_rra=$(az ad app show --id "$app_id" --query "$RRA_QUERY" -o tsv 2>"$err_file") ||
      ! now_redirects=$(az ad app show --id "$app_id" --query publicClient.redirectUris -o tsv 2>"$err_file"); then
      stop_unverified "whether application $app_id matches the plan"
    fi
    matches=true
    if [ "$need_rra" = true ] && [ "$(normalize_rra "$now_rra")" != "$intended_rra" ]; then
      matches=false
    fi
    if [ "$need_fallback" = true ] && [ "$(lower "$(field 3 "$(first_line "$row")")")" != true ]; then
      matches=false
    fi
    if [ "$need_redirect" = true ] && [ "$(sort <<<"$now_redirects")" != "$(sort <<<"$sent_redirects")" ]; then
      matches=false
    fi
    if [ "$matches" = true ]; then
      stop_found "every field of application $app_id that the update sets now matches the plan"
    fi
    stop_absent "the planned values in application $app_id"
  fi
fi

# 3. The owner.
if [ "$need_owner" = true ]; then
  if ! send "add the signed-in user as owner" POST "$GRAPH/applications/$app_obj_id/owners/\$ref" \
    "{\"@odata.id\":\"$GRAPH/directoryObjects/$me_id\"}"; then
    if ! owners=$(get_pages "$GRAPH/applications/$app_obj_id/owners?\$select=id" id); then
      stop_unverified "whether the signed-in user is an owner"
    fi
    if grep -qixF "$me_id" <<<"$owners"; then
      stop_found "the signed-in user is an owner"
    fi
    stop_absent "the signed-in user among the owners"
  fi
fi

# 4. The application's service principal. It is created with the intended
# appRoleAssignmentRequired, so a restricted app is never open in between.
if [ "$create_app_sp" = true ]; then
  if ! send "create the application's service principal" POST "$GRAPH/servicePrincipals" \
    "{\"appId\":\"$app_id\",\"appRoleAssignmentRequired\":$intended_required}"; then
    read_back_sp "$app_id" "application's"
  fi
  app_sp_id=$(wait_for_sp "$app_id" "application's")
  echo "    object id $app_sp_id"
fi

# 5. appRoleAssignmentRequired on an existing service principal.
if [ "$need_required" = true ]; then
  if ! send "set appRoleAssignmentRequired to $intended_required" PATCH \
    "$GRAPH/servicePrincipals/$app_sp_id" "{\"appRoleAssignmentRequired\":$intended_required}"; then
    if ! now=$(az ad sp list --filter "appId eq '$app_id'" --query "$SP_ROW_QUERY" -o tsv 2>"$err_file"); then
      stop_unverified "appRoleAssignmentRequired"
    fi
    if [ "$(lower "$(field 2 "$(first_line "$now")")")" = "$intended_required" ]; then
      stop_found "appRoleAssignmentRequired is $intended_required"
    fi
    stop_absent "appRoleAssignmentRequired set to $intended_required"
  fi
fi

# 6. Assignments.
i=0
while [ "$i" -lt "${#a_ids[@]}" ]; do
  if [ "${a_assigned[$i]}" = false ]; then
    principal=${a_ids[$i]}
    if ! send "assign ${a_labels[$i]} ($principal)" POST "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo" \
      "{\"principalId\":\"$principal\",\"resourceId\":\"$app_sp_id\",\"appRoleId\":\"$DEFAULT_APP_ROLE_ID\"}"; then
      if ! existing_assignments=$(get_pages "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo?\$top=999" \
        "principalId, appRoleId"); then
        stop_unverified "whether ${a_labels[$i]} is assigned"
      fi
      if is_assigned "$principal"; then
        stop_found "${a_labels[$i]} is assigned"
      fi
      stop_absent "an assignment for ${a_labels[$i]}"
    fi
  fi
  i=$((i + 1))
done

# 7. Consent.
i=0
while [ "$i" -lt "${#g_res[@]}" ]; do
  if [ "${g_res[$i]}" = graph ]; then
    res_id=$graph_sp_id
    res_label="Microsoft Graph"
  else
    res_id=$edisc_sp_id
    res_label="Purview eDiscovery"
  fi
  scope=${g_scope[$i]}
  ok=true
  case "${g_action[$i]}" in
    create)
      if [ "${g_type[$i]}" = Principal ]; then
        body="{\"clientId\":\"$app_sp_id\",\"consentType\":\"Principal\",\"principalId\":\"${g_principal[$i]}\",\"resourceId\":\"$res_id\",\"scope\":\"$scope\"}"
      else
        body="{\"clientId\":\"$app_sp_id\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"$res_id\",\"scope\":\"$scope\"}"
      fi
      send "grant $res_label consent for ${g_who[$i]}" POST "$GRAPH/oauth2PermissionGrants" "$body" || ok=false
      ;;
    update)
      # The update replaces the scope, so read the grant again just before
      # it and stop if its scope changed since planning.
      existing_grants=$(read_pages "the consent grants of application $app_id" "$(grants_url)" "$GRANT_FIELDS")
      if ! now_scope=$(grant_scope_by_id "${g_grant_id[$i]}") ||
        ! now_scope=$(join_words "$now_scope") ||
        [ "$now_scope" != "${g_old_scope[$i]}" ]; then
        fail "consent grant ${g_grant_id[$i]} changed after this run read it. Nothing was sent to it; run the script again to plan from the new state."
      fi
      send "extend $res_label consent for ${g_who[$i]}" PATCH \
        "$GRAPH/oauth2PermissionGrants/${g_grant_id[$i]}" "{\"scope\":\"$scope\"}" || ok=false
      ;;
  esac
  if [ "$ok" = false ]; then
    if ! existing_grants=$(get_pages "$(grants_url)" "$GRANT_FIELDS"); then
      stop_unverified "whether the $res_label grant for ${g_who[$i]} holds the planned scopes"
    fi
    find_grant "$res_id" "${g_type[$i]}" "${g_principal[$i]}"
    if [ -n "$found_grant_id" ] && [ -z "$(words_missing "$scope" "$found_grant_scope")" ]; then
      stop_found "the $res_label grant for ${g_who[$i]} holds every planned scope"
    fi
    stop_absent "a $res_label grant for ${g_who[$i]} with every planned scope"
  fi
  i=$((i + 1))
done

echo
echo "Done."
print_login
