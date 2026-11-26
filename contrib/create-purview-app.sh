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
#     the object back, reports whether it exists, and stops. Running it again
#     is safe: every step reads the current state first and skips what
#     already matches.
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
readonly ASSIGNMENTS_QUERY='value[].[principalId, appRoleId]'
readonly GRANTS_QUERY='value[].[id, resourceId, consentType, principalId, scope]'

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
field() { printf '%s\n' "$2" | cut -f "$1"; }

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

show_az_error() {
  sanitize "$(cat "$err_file")" | sed 's/^/    /' >&2
  echo >&2
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

# scope_id LIST VALUE prints the id paired with VALUE in "value<TAB>id" lines.
scope_id() {
  printf '%s\n' "$1" | awk -F '\t' -v want="$2" '$1 == want { print $2; exit }'
}

graph_sp_id=$(read_az "the Microsoft Graph service principal" \
  ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)
is_guid "$graph_sp_id" || fail "the Microsoft Graph service principal has no readable object id."
graph_sp_id=$(lower "$graph_sp_id")
graph_scopes=$(read_az "the Microsoft Graph delegated scopes" \
  ad sp show --id "$GRAPH_APP_ID" --query "$SCOPES_QUERY" -o tsv)
resolve_graph_scope() {
  local id
  id=$(scope_id "$graph_scopes" "$1")
  is_guid "$id" || fail "Microsoft Graph does not expose the delegated scope $1."
  lower "$id"
}
graph_main_id=$(resolve_graph_scope "$graph_main_scope")
offline_access_id=$(resolve_graph_scope offline_access)
openid_id=$(resolve_graph_scope openid)
profile_id=$(resolve_graph_scope profile)

edisc_row=$(read_az "the Purview eDiscovery service principal" \
  ad sp list --filter "appId eq '$EDISCOVERY_APP_ID'" --query "$SP_ROW_QUERY" -o tsv)
edisc_sp_id=$(none_to_empty "$(field 1 "$(printf '%s\n' "$edisc_row" | head -n 1)")")
if [ -n "$edisc_sp_id" ]; then
  is_guid "$edisc_sp_id" || fail "the Purview eDiscovery service principal has no readable object id."
  edisc_sp_id=$(lower "$edisc_sp_id")
  create_edisc_sp=false
  edisc_scopes=$(read_az "the Purview eDiscovery delegated scopes" \
    ad sp show --id "$EDISCOVERY_APP_ID" --query "$SCOPES_QUERY" -o tsv)
  edisc_download_id=$(scope_id "$edisc_scopes" eDiscovery.Download.Read)
  is_guid "$edisc_download_id" ||
    fail "the Purview eDiscovery service principal does not expose eDiscovery.Download.Read."
  edisc_download_id=$(lower "$edisc_download_id")
else
  create_edisc_sp=true
  edisc_download_id=$EDISCOVERY_DOWNLOAD_SCOPE_ID
fi

# The application.
app_obj_id=""
app_id=""
app_display=""
need_fallback=false
need_redirect=false
current_redirects=""
current_rra=""
if [ -n "$CLIENT_ID" ]; then
  app_row=$(read_az "application $CLIENT_ID" \
    ad app list --filter "appId eq '$CLIENT_ID'" --query "$APP_ROW_QUERY" -o tsv)
  app_row=$(printf '%s\n' "$app_row" | head -n 1)
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
  current_redirects=$(read_az "the redirect URIs of application $CLIENT_ID" \
    ad app show --id "$CLIENT_ID" --query publicClient.redirectUris -o tsv)
  if ! printf '%s\n' "$current_redirects" | grep -qxF "$REDIRECT_URI"; then
    need_redirect=true
    while IFS= read -r uri; do
      [ -n "$uri" ] || continue
      [[ "$uri" =~ $REDIRECT_RE ]] ||
        fail "application $CLIENT_ID has a public-client redirect URI with unexpected characters. Add $REDIRECT_URI by hand, then run this script again."
    done <<EOF
$current_redirects
EOF
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
    done <<EOF
$same_name
EOF
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
intended_rra=$(printf '%s\n' "$intended_rra_plan" | sort)
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
  printf '%s\n' "$1" | awk -F '\t' '
    NF == 0 { next }
    {
      n = split($2, parts, ",")
      for (i = 1; i <= n; i++) {
        if (parts[i] == "") continue
        split(parts[i], pair, ":")
        print tolower($1) " " tolower(pair[1]) " " pair[2]
      }
    }' | sort
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
  app_sp_row=$(printf '%s\n' "$app_sp_row" | head -n 1)
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
  owners=$(read_az "the owners of application $app_id" \
    rest --method GET --url "$GRAPH/applications/$app_obj_id/owners?\$select=id" \
    --query "value[].id" -o tsv)
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
  me_id=$(printf '%s\n' "$me" | sed -n 1p)
  me_upn=$(sanitize "$(printf '%s\n' "$me" | sed -n 2p)")
  is_guid "$me_id" || fail "the signed-in user has no readable object id; sign in to az as a user."
  me_id=$(lower "$me_id")
fi

# Assignees: object ids, labels and whether each is already assigned.
existing_assignments=""
if [ "$create_app_sp" = false ] && [ "$restricted" = true ]; then
  existing_assignments=$(read_az "the assignments of application $app_id" \
    rest --method GET --url "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo?\$top=999" \
    --query "$ASSIGNMENTS_QUERY" -o tsv)
fi
is_assigned() {
  printf '%s\n' "$existing_assignments" |
    awk -F '\t' -v p="$1" -v r="$DEFAULT_APP_ROLE_ID" 'tolower($1) == p && tolower($2) == r { found = 1 } END { exit !found }'
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
for word in ${assign_words[@]+"${assign_words[@]}"}; do
  if user=$(az ad user show --id "$word" --query "[id, userPrincipalName]" -o tsv 2>"$err_file"); then
    uid=$(printf '%s\n' "$user" | sed -n 1p)
    upn=$(sanitize "$(printf '%s\n' "$user" | sed -n 2p)")
    if is_guid "$uid"; then
      add_assignee "$(lower "$uid")" "$upn" user
      continue
    fi
  fi
  unresolved=$((unresolved + 1))
  unresolved_lines+=("$word: no directory user found (check the sign-in name, which may differ from the mail address)")
done
if [ -n "$GROUP_OBJECT_ID" ]; then
  if group=$(az rest --method GET --url "$GRAPH/groups/$GROUP_OBJECT_ID?\$select=id,displayName" \
    --query "[id, displayName]" -o tsv 2>"$err_file") &&
    is_guid "$(printf '%s\n' "$group" | sed -n 1p)"; then
    add_assignee "$GROUP_OBJECT_ID" "group $(sanitize "$(printf '%s\n' "$group" | sed -n 2p)")" group
  else
    unresolved=$((unresolved + 1))
    unresolved_lines+=("group $GROUP_OBJECT_ID: no group found")
  fi
fi

# Consent grants: one per resource, per assigned user or for all principals.
existing_grants=""
if [ "$create_app_sp" = false ]; then
  existing_grants=$(read_az "the consent grants of application $app_id" \
    rest --method GET --url "$GRAPH/oauth2PermissionGrants?\$filter=clientId%20eq%20'$app_sp_id'" \
    --query "$GRANTS_QUERY" -o tsv)
fi

# find_grant RESOURCE_ID TYPE PRINCIPAL sets found_grant_id and
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
  done <<EOF
$existing_grants
EOF
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
g_scope=()     # the scope the grant will hold
g_extra=()     # scopes the grant holds beyond the intended ones
plan_grant() { # res type principal label
  local res_id wanted
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
    g_scope+=("$wanted")
    g_extra+=("")
    return 0
  fi
  [[ "$found_grant_id" =~ $GRANT_ID_RE ]] || fail "a consent grant of application $app_id has an id of unexpected characters."
  local word missing
  for word in $found_grant_scope; do
    [[ "$word" =~ $SCOPE_WORD_RE ]] || fail "a consent grant of application $app_id holds a scope of unexpected characters."
  done
  g_grant_id+=("$found_grant_id")
  g_extra+=("$(words_missing "$found_grant_scope" "$wanted")")
  missing=$(words_missing "$wanted" "$found_grant_scope")
  if [ -z "$missing" ]; then
    g_action+=(present)
    g_scope+=("$found_grant_scope")
  else
    g_action+=(update)
    g_scope+=("$found_grant_scope${found_grant_scope:+ }$missing")
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
  done <<EOF
$1
EOF
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
  echo "    Who may sign in: only the assignees listed above, and any principals assigned earlier."
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
  else
    res_label="Purview eDiscovery"
  fi
  case "${g_action[$i]}" in
    present) state="present" ;;
    create) state="will be granted" ;;
    update) state="will be extended to: ${g_scope[$i]}" ;;
  esac
  echo "    - $res_label for ${g_who[$i]}: $(if [ "${g_res[$i]}" = graph ]; then echo "$graph_grant_scope"; else echo "$edisc_grant_scope"; fi) ($state)"
  if [ -n "${g_extra[$i]}" ]; then
    echo "      The grant also holds '${g_extra[$i]}'. This script never removes a scope; remove it by hand if it is not wanted."
  fi
  i=$((i + 1))
done
if [ "${#g_res[@]}" -eq 0 ]; then
  echo "    none"
fi

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
  echo
  echo "Sign in with:"
  echo "    purview auth login --client-id $app_id --tenant-id $TENANT_ID"
  echo "Add --browser to sign in through a browser on this machine instead of with a device code."
  echo "Later runs of this script for this application need CLIENT_ID=$app_id."
  echo "Each user also needs the eDiscovery Manager or eDiscovery Administrator role group in the Purview portal."
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
# and then calls stop_unclear.
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

# stop_unclear FINDING ends the run after an unclear outcome.
stop_unclear() {
  echo "error: the outcome of step '$current_step' was unclear. Read-back: $1." >&2
  echo "Nothing else was sent. Running the script again is safe: it reads the current state and skips what already matches." >&2
  exit 1
}

# sp_object_id APP_ID prints the service principal's object id, or nothing.
sp_object_id() {
  az ad sp list --filter "appId eq '$1'" --query "[].id" -o tsv 2>"$err_file" | head -n 1
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
    if [ -n "$(sp_object_id "$EDISCOVERY_APP_ID")" ]; then
      stop_unclear "the Purview eDiscovery service principal exists"
    fi
    stop_unclear "the Purview eDiscovery service principal does not exist"
  fi
  edisc_sp_id=$(wait_for_sp "$EDISCOVERY_APP_ID" "Purview eDiscovery")
  echo "    object id $edisc_sp_id"
  edisc_scopes=$(read_az "the Purview eDiscovery delegated scopes" \
    ad sp show --id "$EDISCOVERY_APP_ID" --query "$SCOPES_QUERY" -o tsv)
  found=$(lower "$(scope_id "$edisc_scopes" eDiscovery.Download.Read)")
  if [ "$found" != "$EDISCOVERY_DOWNLOAD_SCOPE_ID" ]; then
    fail "the new Purview eDiscovery service principal gives eDiscovery.Download.Read the id '$(sanitize "$found")', not $EDISCOVERY_DOWNLOAD_SCOPE_ID. Nothing else was changed; report this before running again."
  fi
  echo "    eDiscovery.Download.Read is $found, as planned"
fi

# 2. The application.
if [ "$create_app" = true ]; then
  body="{\"displayName\":\"$APP_NAME\",\"signInAudience\":\"AzureADMyOrg\",\"isFallbackPublicClient\":true,\"publicClient\":{\"redirectUris\":[\"$REDIRECT_URI\"]},\"requiredResourceAccess\":$(rra_json)}"
  if ! send "create application '$APP_NAME'" POST "$GRAPH/applications" "$body" "[id, appId]"; then
    found=$(az ad app list --filter "displayName eq '$APP_NAME'" --query "[].appId" -o tsv 2>"$err_file" | head -n 1 || true)
    if is_guid "$found"; then
      stop_unclear "an application named '$APP_NAME' exists with appId $(lower "$found"); run again with CLIENT_ID=$(lower "$found")"
    fi
    stop_unclear "no application named '$APP_NAME' exists"
  fi
  app_obj_id=$(printf '%s\n' "$sent_output" | sed -n 1p)
  app_id=$(printf '%s\n' "$sent_output" | sed -n 2p)
  if ! is_guid "$app_obj_id" || ! is_guid "$app_id"; then
    fail "the application was created but az did not return its ids. Find it by the name '$APP_NAME' and run again with CLIENT_ID set."
  fi
  app_obj_id=$(lower "$app_obj_id")
  app_id=$(lower "$app_id")
  echo "    appId $app_id, object id $app_obj_id"
elif [ "$need_rra" = true ] || [ "$need_redirect" = true ] || [ "$need_fallback" = true ]; then
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
    done <<EOF
$current_redirects
EOF
    parts="$parts${parts:+,}\"publicClient\":{\"redirectUris\":[$uris\"$REDIRECT_URI\"]}"
  fi
  if ! send "update application $app_id" PATCH "$GRAPH/applications/$app_obj_id" "{$parts}"; then
    now=$(az ad app show --id "$app_id" --query "$RRA_QUERY" -o tsv 2>"$err_file" || true)
    redirects=$(az ad app show --id "$app_id" --query publicClient.redirectUris -o tsv 2>"$err_file" || true)
    if [ "$(normalize_rra "$now")" = "$intended_rra" ] && printf '%s\n' "$redirects" | grep -qxF "$REDIRECT_URI"; then
      stop_unclear "the application's permissions and redirect URI now match the plan"
    fi
    stop_unclear "the application does not yet match the plan"
  fi
fi

# 3. The owner.
if [ "$need_owner" = true ]; then
  if ! send "add the signed-in user as owner" POST "$GRAPH/applications/$app_obj_id/owners/\$ref" \
    "{\"@odata.id\":\"$GRAPH/directoryObjects/$me_id\"}"; then
    owners=$(az rest --method GET --url "$GRAPH/applications/$app_obj_id/owners?\$select=id" \
      --query "value[].id" -o tsv 2>"$err_file" || true)
    if printf '%s\n' "$owners" | grep -qixF "$me_id"; then
      stop_unclear "the signed-in user is an owner"
    fi
    stop_unclear "the signed-in user is not an owner"
  fi
fi

# 4. The application's service principal. It is created with the intended
# appRoleAssignmentRequired, so a restricted app is never open in between.
if [ "$create_app_sp" = true ]; then
  if ! send "create the application's service principal" POST "$GRAPH/servicePrincipals" \
    "{\"appId\":\"$app_id\",\"appRoleAssignmentRequired\":$intended_required}"; then
    if [ -n "$(sp_object_id "$app_id")" ]; then
      stop_unclear "the application's service principal exists"
    fi
    stop_unclear "the application's service principal does not exist"
  fi
  app_sp_id=$(wait_for_sp "$app_id" "application's")
  echo "    object id $app_sp_id"
fi

# 5. appRoleAssignmentRequired on an existing service principal.
if [ "$need_required" = true ]; then
  if ! send "set appRoleAssignmentRequired to $intended_required" PATCH \
    "$GRAPH/servicePrincipals/$app_sp_id" "{\"appRoleAssignmentRequired\":$intended_required}"; then
    now=$(az ad sp list --filter "appId eq '$app_id'" --query "$SP_ROW_QUERY" -o tsv 2>"$err_file" || true)
    if [ "$(lower "$(field 2 "$(printf '%s\n' "$now" | head -n 1)")")" = "$intended_required" ]; then
      stop_unclear "appRoleAssignmentRequired is $intended_required"
    fi
    stop_unclear "appRoleAssignmentRequired is not yet $intended_required"
  fi
fi

# 6. Assignments.
i=0
while [ "$i" -lt "${#a_ids[@]}" ]; do
  if [ "${a_assigned[$i]}" = false ]; then
    principal=${a_ids[$i]}
    if ! send "assign ${a_labels[$i]} ($principal)" POST "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo" \
      "{\"principalId\":\"$principal\",\"resourceId\":\"$app_sp_id\",\"appRoleId\":\"$DEFAULT_APP_ROLE_ID\"}"; then
      existing_assignments=$(az rest --method GET --url "$GRAPH/servicePrincipals/$app_sp_id/appRoleAssignedTo?\$top=999" \
        --query "$ASSIGNMENTS_QUERY" -o tsv 2>"$err_file" || true)
      if is_assigned "$principal"; then
        stop_unclear "${a_labels[$i]} is assigned"
      fi
      stop_unclear "${a_labels[$i]} is not assigned"
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
      send "extend $res_label consent for ${g_who[$i]}" PATCH \
        "$GRAPH/oauth2PermissionGrants/${g_grant_id[$i]}" "{\"scope\":\"$scope\"}" || ok=false
      ;;
  esac
  if [ "$ok" = false ]; then
    existing_grants=$(az rest --method GET --url "$GRAPH/oauth2PermissionGrants?\$filter=clientId%20eq%20'$app_sp_id'" \
      --query "$GRANTS_QUERY" -o tsv 2>"$err_file" || true)
    find_grant "$res_id" "${g_type[$i]}" "${g_principal[$i]}"
    if [ -z "$found_grant_id" ]; then
      stop_unclear "no such grant exists"
    elif [ -z "$(words_missing "$scope" "$found_grant_scope")" ]; then
      stop_unclear "the grant exists with every planned scope"
    fi
    stop_unclear "the grant exists but lacks some planned scopes"
  fi
  i=$((i + 1))
done

echo
echo "Done."
print_login
