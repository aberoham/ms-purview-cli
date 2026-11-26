#!/usr/bin/env bash
set -euo pipefail

# Runs contrib/create-purview-app.sh against the fake az in fake-bin/ and
# checks its plans, its calls and its refusals (docs/SPEC.md section 5.2).
#
# Usage: tests/scripts/create-purview-app-test.sh [test name...]
# TEST_BASH names the shell that runs the script under test (default: bash),
# so the tests can run under macOS's /bin/bash 3.2 as well.

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
script="$root/contrib/create-purview-app.sh"
test_bash=${TEST_BASH:-bash}
work=$(mktemp -d "${TMPDIR:-/tmp}/create-purview-app-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Synthetic identifiers.
T=00000000-0000-4000-8000-000000000001
OTHER_T=00000000-0000-4000-8000-000000000009
GRAPH_APP=00000003-0000-0000-c000-000000000000
GRAPH_SP=00000000-0000-4000-8000-000000000011
EDISC_APP=b26e684c-5068-4120-a679-64a5d2c909d9
EDISC_SP=00000000-0000-4000-8000-000000000012
ALEX=00000000-0000-4000-8000-000000000021
SAM=00000000-0000-4000-8000-000000000022
GROUP=00000000-0000-4000-8000-000000000031
APP_OBJ=00000000-0000-4000-8000-000000000041
APP_ID=00000000-0000-4000-8000-000000000042
APP_SP=00000000-0000-4000-8000-000000000043
ROLE=00000000-0000-0000-0000-000000000000
RW=acb8f680-0834-4146-b69e-4ab1b39745ad
RO=99201db3-7652-4d5a-809a-bdb94f85fe3c
OFFLINE=7427e0e9-2fba-42fe-b0c0-848c9e6a8182
OPENID=37f7f235-527c-4136-accd-4a02d197296e
PROFILE=14dad69e-099b-42c9-810b-d002981feec1
DOWNLOAD=c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2
NEW1=00000000-0000-4000-8000-000000000061
NEW2=00000000-0000-4000-8000-000000000062
NEW3=00000000-0000-4000-8000-000000000063
NEW4=00000000-0000-4000-8000-000000000064
GRAPH_SCOPE="eDiscovery.ReadWrite.All offline_access openid profile"
G=https://graph.microsoft.com/v1.0

GRAPH_SP_JSON="{\"id\":\"$GRAPH_SP\",\"appId\":\"$GRAPH_APP\",\"scopes\":[
  [\"eDiscovery.ReadWrite.All\",\"$RW\"],[\"eDiscovery.Read.All\",\"$RO\"],
  [\"offline_access\",\"$OFFLINE\"],[\"openid\",\"$OPENID\"],[\"profile\",\"$PROFILE\"]]}"
EDISC_SP_JSON="{\"id\":\"$EDISC_SP\",\"appId\":\"$EDISC_APP\",\"scopes\":[[\"eDiscovery.Download.Read\",\"$DOWNLOAD\"]]}"
RRA="[{\"resourceAppId\":\"$GRAPH_APP\",\"resourceAccess\":[{\"id\":\"$RW\",\"type\":\"Scope\"},{\"id\":\"$OFFLINE\",\"type\":\"Scope\"},{\"id\":\"$OPENID\",\"type\":\"Scope\"},{\"id\":\"$PROFILE\",\"type\":\"Scope\"}]},{\"resourceAppId\":\"$EDISC_APP\",\"resourceAccess\":[{\"id\":\"$DOWNLOAD\",\"type\":\"Scope\"}]}]"
# A complete registration from an earlier run, restricted to alex with
# per-user consent.
DONE_APP="{\"id\":\"$APP_OBJ\",\"appId\":\"$APP_ID\",\"displayName\":\"Purview CLI (eDiscovery)\",
  \"signInAudience\":\"AzureADMyOrg\",\"isFallbackPublicClient\":true,
  \"publicClient\":{\"redirectUris\":[\"http://localhost/callback\"]},
  \"requiredResourceAccess\":$RRA,\"owners\":[\"$ALEX\"]}"
DONE_SP="{\"id\":\"$APP_SP\",\"appId\":\"$APP_ID\",\"appRoleAssignmentRequired\":true}"
DONE_ASSIGNMENT="{\"id\":\"a1\",\"principalId\":\"$ALEX\",\"resourceId\":\"$APP_SP\",\"appRoleId\":\"$ROLE\"}"
DONE_GRANTS="{\"id\":\"g1\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"$GRAPH_SCOPE\"},
  {\"id\":\"g2\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$EDISC_SP\",\"scope\":\"eDiscovery.Download.Read\"}"

failures=0
case_failed=0
case_name=""

# new_case NAME starts a test with an empty log and the default state: the
# tenant has Graph, two users and a group, and no eDiscovery service
# principal (the observed case). The variables below change the state.
new_case() {
  case_name=$1
  case_failed=0
  case_dir="$work/$case_name"
  mkdir -p "$case_dir"
  export FAKE_AZ_STATE="$case_dir/state.json"
  export FAKE_AZ_LOG="$case_dir/log"
  : >"$FAKE_AZ_LOG"
  AZ_TENANT=$T
  EXTRA_SPS=""
  APPS=""
  ASSIGNMENTS=""
  GRANTS=""
  FAULTS=""
  HIDDEN_POLLS=0
}

write_state() {
  cat >"$FAKE_AZ_STATE" <<EOF
{"tenant": "$AZ_TENANT", "signed_in": "$ALEX",
 "users": [{"id": "$ALEX", "userPrincipalName": "alex@contoso.example"},
           {"id": "$SAM", "userPrincipalName": "sam@contoso.example"}],
 "groups": [{"id": "$GROUP", "displayName": "eDiscovery users"}],
 "sps": [$GRAPH_SP_JSON${EXTRA_SPS:+,$EXTRA_SPS}],
 "apps": [$APPS], "assignments": [$ASSIGNMENTS], "grants": [$GRANTS],
 "faults": [$FAULTS], "new_sp_hidden_polls": $HIDDEN_POLLS, "next_id": 96}
EOF
}

# run VAR=value... [--apply] runs the script with only the given variables.
run() {
  local vars=() args=() arg
  for arg in "$@"; do
    case "$arg" in
      -*) args+=("$arg") ;;
      *) vars+=("$arg") ;;
    esac
  done
  status=0
  env -u TENANT_ID -u CLIENT_ID -u APP_NAME -u ASSIGN_USERS -u GROUP_OBJECT_ID \
    -u READ_ONLY -u CONSENT -u ALLOW_ALL_TENANT_USERS \
    PATH="$here/fake-bin:$PATH" ${vars[@]+"${vars[@]}"} \
    "$test_bash" "$script" ${args[@]+"${args[@]}"} >"$case_dir/out" 2>"$case_dir/err" || status=$?
}

problem() {
  echo "  $case_name: $*"
  case_failed=1
}

end_case() {
  if [ "$case_failed" -eq 0 ]; then
    echo "ok   $case_name"
  else
    echo "FAIL $case_name (output in $case_dir)"
    sed 's/^/     stdout: /' "$case_dir/out"
    sed 's/^/     stderr: /' "$case_dir/err"
    failures=$((failures + 1))
  fi
}

expect_status() {
  if [ "$1" = nonzero ]; then
    [ "$status" -ne 0 ] || problem "expected a non-zero exit, got 0"
  else
    [ "$status" -eq "$1" ] || problem "expected exit $1, got $status"
  fi
}

expect_out() { grep -qF -- "$1" "$case_dir/out" || problem "stdout lacks: $1"; }
expect_err() { grep -qF -- "$1" "$case_dir/err" || problem "stderr lacks: $1"; }
reject_out() { ! grep -qF -- "$1" "$case_dir/out" || problem "stdout should not contain: $1"; }

# az_calls prints the logged az calls, without the fake sleep lines.
az_calls() { grep -v '^sleep ' "$FAKE_AZ_LOG" || true; }

# mutations prints each logged change as "METHOD path body".
mutations() {
  az_calls | sed -nE "s#^rest --method (POST|PATCH|PUT|DELETE) --url $G([^ ]*) --body (\{.*\}) (--query|-o) .*\$#\1 \2 \3#p"
}

expect_mutations() {
  local expected="$case_dir/expected" actual="$case_dir/actual"
  cat >"$expected"
  mutations >"$actual"
  if ! diff -u "$expected" "$actual" >"$case_dir/diff"; then
    problem "changes differ from the expected list:"
    sed 's/^/    /' "$case_dir/diff"
  fi
}

expect_no_mutation() {
  local found
  found=$(mutations)
  [ -z "$found" ] || problem "expected no changes, got: $found"
}

# expect_at_most_account_show checks that the script stopped before any az
# call other than `az account show`.
expect_at_most_account_show() {
  local other
  other=$(az_calls | grep -v '^account show ' || true)
  [ -z "$other" ] || problem "unexpected az calls: $other"
}

# expect_reads_only checks every call against the read allow list and for a
# mutating subcommand word.
expect_reads_only() {
  local line words word
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "account show "* | "ad sp show "* | "ad sp list "* | "ad app show "* | "ad app list "* | \
        "ad user show "* | "ad signed-in-user show "* | "rest --method GET "*) ;;
      *) problem "call outside the read allow list: $line" ;;
    esac
    words=${line%% -*}
    for word in $words; do
      case "$word" in
        create | update | delete | add | grant | admin-consent)
          problem "mutating subcommand in: $line"
          ;;
      esac
    done
    case "$line" in
      *"--method POST"* | *"--method PATCH"* | *"--method PUT"* | *"--method DELETE"*)
        problem "mutating method in: $line"
        ;;
    esac
  done <<EOF
$(az_calls)
EOF
}

# count_calls PATTERN prints how many logged calls match the extended regex.
count_calls() { az_calls | grep -cE -- "$1" || true; }

# line_after PATTERN prints the call that follows the first match.
line_after() { az_calls | awk -v p="$1" 'found { print; exit } $0 ~ p { found = 1 }'; }

fault() { # match kind applied
  FAULTS="{\"match\": \"$1\", \"nth\": 1, \"kind\": \"$2\", \"applied\": $3}"
}

restricted_vars=("TENANT_ID=$T" "ASSIGN_USERS=alex@contoso.example sam@contoso.example")

# --- Dry runs ----------------------------------------------------------------

test_dry_run_sends_only_reads() {
  new_case dry_run_sends_only_reads
  write_state
  run "${restricted_vars[@]}"
  expect_status 0
  expect_reads_only
  [ -s "$FAKE_AZ_LOG" ] || problem "the dry run made no az call at all"
  expect_out "Plan (dry run: nothing is changed)"
  expect_out "Dry run: nothing was changed."
  expect_out "run the same command with --apply"
  end_case
}

test_dry_run_of_an_update_sends_only_reads() {
  new_case dry_run_of_an_update_sends_only_reads
  EXTRA_SPS="$EDISC_SP_JSON,{\"id\":\"$APP_SP\",\"appId\":\"$APP_ID\",\"appRoleAssignmentRequired\":false}"
  APPS="{\"id\":\"$APP_OBJ\",\"appId\":\"$APP_ID\",\"displayName\":\"Old name\",\"signInAudience\":\"AzureADMyOrg\",\"requiredResourceAccess\":[],\"owners\":[]}"
  GRANTS="{\"id\":\"g1\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"openid\"}"
  write_state
  run "${restricted_vars[@]}" "CLIENT_ID=$APP_ID"
  expect_status 0
  expect_reads_only
  expect_out "Application: update $APP_ID ('Old name'"
  expect_out "Current list differs, and will be replaced."
  end_case
}

test_restricted_plan() {
  new_case restricted_plan
  write_state
  run "${restricted_vars[@]}"
  expect_status 0
  expect_out "Tenant: $T (az is signed in to it)"
  expect_out "Application: create 'Purview CLI (eDiscovery)'"
  expect_out "Owner: add the signed-in user alex@contoso.example ($ALEX)"
  expect_out "Purview eDiscovery (MicrosoftPurviewEDiscovery, appId $EDISC_APP)"
  expect_out "the application's own service principal"
  expect_out "eDiscovery.ReadWrite.All   $RW Scope"
  expect_out "offline_access             $OFFLINE Scope"
  expect_out "openid                     $OPENID Scope"
  expect_out "profile                    $PROFILE Scope"
  expect_out "eDiscovery.Download.Read   $DOWNLOAD Scope"
  expect_out "alex@contoso.example -> $ALEX: will be assigned"
  expect_out "sam@contoso.example -> $SAM: will be assigned"
  expect_out "appRoleAssignmentRequired: true"
  expect_out "Who may sign in: only the assignees listed above"
  reject_out "EVERY USER"
  expect_out "Type: per user (Principal)"
  expect_out "Microsoft Graph for alex@contoso.example: $GRAPH_SCOPE (will be granted)"
  expect_out "Purview eDiscovery for sam@contoso.example: eDiscovery.Download.Read (will be granted)"
  end_case
}

test_all_users_plan() {
  new_case all_users_plan
  write_state
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1 CONSENT=tenant
  expect_status 0
  expect_reads_only
  expect_out "none (ALLOW_ALL_TENANT_USERS=1)"
  expect_out "appRoleAssignmentRequired: false"
  expect_out "Who may sign in: EVERY USER IN THE TENANT can sign in through this app."
  expect_out "Type: tenant-wide (AllPrincipals)"
  expect_out "Microsoft Graph for all users: $GRAPH_SCOPE (will be granted)"
  expect_out "Purview eDiscovery for all users: eDiscovery.Download.Read (will be granted)"
  end_case
}

test_read_only_plan_uses_read_scope() {
  new_case read_only_plan_uses_read_scope
  write_state
  run "${restricted_vars[@]}" READ_ONLY=1
  expect_status 0
  expect_out "eDiscovery.Read.All        $RO Scope"
  reject_out "eDiscovery.ReadWrite.All"
  end_case
}

test_unresolved_user_fails_the_dry_run() {
  new_case unresolved_user_fails_the_dry_run
  write_state
  run "TENANT_ID=$T" "ASSIGN_USERS=alex@contoso.example nobody@contoso.example"
  expect_status nonzero
  expect_reads_only
  expect_out "UNRESOLVED nobody@contoso.example"
  expect_err "1 assignee(s) could not be resolved"
  end_case
}

test_unresolved_user_stops_apply_before_any_change() {
  new_case unresolved_user_stops_apply_before_any_change
  write_state
  run "TENANT_ID=$T" "ASSIGN_USERS=nobody@contoso.example" --apply
  expect_status nonzero
  expect_reads_only
  expect_no_mutation
  end_case
}

# --- Apply -------------------------------------------------------------------

test_restricted_apply() {
  new_case restricted_apply
  HIDDEN_POLLS=2
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status 0
  expect_out "Plan"
  expect_out "purview auth login --client-id $NEW3 --tenant-id $T"
  expect_out "--browser"
  local grant_rw="\"scope\":\"$GRAPH_SCOPE\"}"
  local grant_dl="\"scope\":\"eDiscovery.Download.Read\"}"
  local principal="{\"clientId\":\"$NEW4\",\"consentType\":\"Principal\",\"principalId\""
  expect_mutations <<EOF
POST /servicePrincipals {"appId":"$EDISC_APP"}
POST /applications {"displayName":"Purview CLI (eDiscovery)","signInAudience":"AzureADMyOrg","isFallbackPublicClient":true,"publicClient":{"redirectUris":["http://localhost/callback"]},"requiredResourceAccess":$RRA}
POST /applications/$NEW2/owners/\$ref {"@odata.id":"$G/directoryObjects/$ALEX"}
POST /servicePrincipals {"appId":"$NEW3","appRoleAssignmentRequired":true}
POST /servicePrincipals/$NEW4/appRoleAssignedTo {"principalId":"$ALEX","resourceId":"$NEW4","appRoleId":"$ROLE"}
POST /servicePrincipals/$NEW4/appRoleAssignedTo {"principalId":"$SAM","resourceId":"$NEW4","appRoleId":"$ROLE"}
POST /oauth2PermissionGrants $principal:"$ALEX","resourceId":"$GRAPH_SP",$grant_rw
POST /oauth2PermissionGrants $principal:"$ALEX","resourceId":"$NEW1",$grant_dl
POST /oauth2PermissionGrants $principal:"$SAM","resourceId":"$GRAPH_SP",$grant_rw
POST /oauth2PermissionGrants $principal:"$SAM","resourceId":"$NEW1",$grant_dl
EOF
  # Each new service principal was hidden from two polls, so the script
  # slept twice after each create before it went on.
  [ "$(grep -c '^sleep 5$' "$FAKE_AZ_LOG")" -eq 4 ] || problem "expected 4 polling sleeps"
  end_case
}

test_all_users_apply() {
  new_case all_users_apply
  write_state
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1 CONSENT=tenant --apply
  expect_status 0
  expect_out "Who may sign in: EVERY USER IN THE TENANT can sign in through this app."
  local all="{\"clientId\":\"$NEW4\",\"consentType\":\"AllPrincipals\""
  expect_mutations <<EOF
POST /servicePrincipals {"appId":"$EDISC_APP"}
POST /applications {"displayName":"Purview CLI (eDiscovery)","signInAudience":"AzureADMyOrg","isFallbackPublicClient":true,"publicClient":{"redirectUris":["http://localhost/callback"]},"requiredResourceAccess":$RRA}
POST /applications/$NEW2/owners/\$ref {"@odata.id":"$G/directoryObjects/$ALEX"}
POST /servicePrincipals {"appId":"$NEW3","appRoleAssignmentRequired":false}
POST /oauth2PermissionGrants $all,"resourceId":"$GRAPH_SP","scope":"$GRAPH_SCOPE"}
POST /oauth2PermissionGrants $all,"resourceId":"$NEW1","scope":"eDiscovery.Download.Read"}
EOF
  end_case
}

test_group_with_tenant_consent_apply() {
  new_case group_with_tenant_consent_apply
  EXTRA_SPS="$EDISC_SP_JSON"
  write_state
  run "TENANT_ID=$T" "GROUP_OBJECT_ID=$GROUP" CONSENT=tenant --apply
  expect_status 0
  expect_out "group eDiscovery users -> $GROUP: will be assigned"
  local all="{\"clientId\":\"$NEW3\",\"consentType\":\"AllPrincipals\""
  expect_mutations <<EOF
POST /applications {"displayName":"Purview CLI (eDiscovery)","signInAudience":"AzureADMyOrg","isFallbackPublicClient":true,"publicClient":{"redirectUris":["http://localhost/callback"]},"requiredResourceAccess":$RRA}
POST /applications/$NEW1/owners/\$ref {"@odata.id":"$G/directoryObjects/$ALEX"}
POST /servicePrincipals {"appId":"$NEW2","appRoleAssignmentRequired":true}
POST /servicePrincipals/$NEW3/appRoleAssignedTo {"principalId":"$GROUP","resourceId":"$NEW3","appRoleId":"$ROLE"}
POST /oauth2PermissionGrants $all,"resourceId":"$GRAPH_SP","scope":"$GRAPH_SCOPE"}
POST /oauth2PermissionGrants $all,"resourceId":"$EDISC_SP","scope":"eDiscovery.Download.Read"}
EOF
  end_case
}

test_update_changes_only_what_differs() {
  new_case update_changes_only_what_differs
  EXTRA_SPS="$EDISC_SP_JSON,{\"id\":\"$APP_SP\",\"appId\":\"$APP_ID\",\"appRoleAssignmentRequired\":false}"
  APPS="{\"id\":\"$APP_OBJ\",\"appId\":\"$APP_ID\",\"displayName\":\"Old name\",\"signInAudience\":\"AzureADMyOrg\",
    \"isFallbackPublicClient\":true,\"publicClient\":{\"redirectUris\":[\"http://localhost:8400\"]},
    \"requiredResourceAccess\":[],\"owners\":[\"$SAM\"]}"
  ASSIGNMENTS="$DONE_ASSIGNMENT"
  GRANTS="{\"id\":\"g1\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"openid User.Read\"},
    {\"id\":\"g2\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$EDISC_SP\",\"scope\":\"eDiscovery.Download.Read\"}"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status 0
  expect_out "Owner: the application already has owners; unchanged"
  expect_out "alex@contoso.example -> $ALEX: already assigned"
  expect_out "The grant also holds 'User.Read'. This script never removes a scope"
  expect_out "purview auth login --client-id $APP_ID --tenant-id $T"
  expect_mutations <<EOF
PATCH /applications/$APP_OBJ {"requiredResourceAccess":$RRA,"publicClient":{"redirectUris":["http://localhost:8400","http://localhost/callback"]}}
PATCH /servicePrincipals/$APP_SP {"appRoleAssignmentRequired":true}
PATCH /oauth2PermissionGrants/g1 {"scope":"openid User.Read eDiscovery.ReadWrite.All offline_access profile"}
EOF
  end_case
}

test_rerun_after_success_changes_nothing() {
  new_case rerun_after_success_changes_nothing
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status 0
  : >"$FAKE_AZ_LOG"
  run "${restricted_vars[@]}" "CLIENT_ID=$NEW3" --apply
  expect_status 0
  expect_out "Changes: 0"
  expect_out "Nothing to change."
  expect_no_mutation
  expect_reads_only
  # Without CLIENT_ID the name is taken, so the script refuses.
  : >"$FAKE_AZ_LOG"
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "appId $NEW3"
  expect_no_mutation
  end_case
}

test_complete_registration_changes_nothing() {
  new_case complete_registration_changes_nothing
  EXTRA_SPS="$EDISC_SP_JSON,$DONE_SP"
  APPS="$DONE_APP"
  ASSIGNMENTS="$DONE_ASSIGNMENT"
  GRANTS="$DONE_GRANTS"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status 0
  expect_out "Nothing to change."
  expect_reads_only
  end_case
}

# --- Unclear and definite failures -------------------------------------------

# expect_one_then_readback PATTERN READBACK checks that exactly one call
# matched PATTERN and that the next call matched READBACK.
expect_one_then_readback() {
  local n next
  n=$(count_calls "$1")
  [ "$n" -eq 1 ] || problem "expected exactly one call matching '$1', got $n"
  next=$(line_after "$1")
  printf '%s\n' "$next" | grep -qE -- "$2" || problem "expected a read-back matching '$2' after it, got: $next"
}

test_timeout_on_create_is_read_back_once() {
  new_case timeout_on_create_is_read_back_once
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/applications --body' timeout false
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_one_then_readback '^rest --method POST --url [^ ]*/v1.0/applications ' \
    "^ad app list --filter displayName eq 'Purview CLI \\(eDiscovery\\)'"
  expect_err "step 'create application 'Purview CLI (eDiscovery)'' was unclear"
  expect_err "no application named 'Purview CLI (eDiscovery)' exists"
  expect_err "Running the script again is safe"
  [ "$(az_calls | tail -n 1 | cut -c1-11)" = "ad app list" ] || problem "a call followed the read-back"
  end_case
}

test_timeout_after_create_took_effect_reports_it() {
  new_case timeout_after_create_took_effect_reports_it
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/applications --body' timeout true
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "exists with appId $NEW3; run again with CLIENT_ID=$NEW3"
  # The suggested re-run finishes the job.
  : >"$FAKE_AZ_LOG"
  run "${restricted_vars[@]}" "CLIENT_ID=$NEW3" --apply
  expect_status 0
  expect_out "Owner: the application has no owner; add the signed-in user"
  end_case
}

test_throttle_on_assignment_is_read_back_once() {
  new_case throttle_on_assignment_is_read_back_once
  fault '^rest --method POST --url [^ ]*/appRoleAssignedTo' throttle false
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_one_then_readback '^rest --method POST --url [^ ]*/appRoleAssignedTo' \
    '^rest --method GET --url [^ ]*/appRoleAssignedTo'
  expect_err "Too Many Requests"
  expect_err "step 'assign alex@contoso.example ($ALEX)' was unclear"
  expect_err "alex@contoso.example is not assigned"
  [ "$(count_calls 'oauth2PermissionGrants --body')" -eq 0 ] || problem "consent was sent after the failure"
  end_case
}

test_server_error_on_grant_is_read_back_once() {
  new_case server_error_on_grant_is_read_back_once
  fault '^rest --method POST --url [^ ]*/oauth2PermissionGrants' server true
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_one_then_readback '^rest --method POST --url [^ ]*/oauth2PermissionGrants' \
    '^rest --method GET --url [^ ]*/oauth2PermissionGrants'
  expect_err "the grant exists with every planned scope"
  end_case
}

test_timeout_on_service_principal_is_read_back_once() {
  new_case timeout_on_service_principal_is_read_back_once
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/servicePrincipals --body' timeout true
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_one_then_readback '^rest --method POST --url [^ ]*/v1.0/servicePrincipals --body' \
    "^ad sp list --filter appId eq '$EDISC_APP'"
  expect_err "the Purview eDiscovery service principal exists"
  [ "$(count_calls '/applications --body')" -eq 0 ] || problem "the application was sent after the failure"
  end_case
}

test_definite_failure_stops_without_read_back() {
  new_case definite_failure_stops_without_read_back
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/applications --body' definite false
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  [ "$(count_calls '/v1.0/applications --body')" -eq 1 ] || problem "expected one create"
  [ -z "$(line_after '/v1.0/applications --body')" ] || problem "a call followed a definite failure"
  expect_err "Insufficient privileges"
  expect_err "was refused, so it made no change"
  end_case
}

# --- Refusals ----------------------------------------------------------------

test_group_with_principal_consent_is_refused() {
  new_case group_with_principal_consent_is_refused
  write_state
  run "TENANT_ID=$T" "GROUP_OBJECT_ID=$GROUP"
  expect_status nonzero
  expect_err "CONSENT=tenant"
  expect_err "ASSIGN_USERS"
  expect_at_most_account_show
  : >"$FAKE_AZ_LOG"
  run "TENANT_ID=$T" "GROUP_OBJECT_ID=$GROUP" ASSIGN_USERS=alex@contoso.example CONSENT=principal --apply
  expect_status nonzero
  expect_at_most_account_show
  end_case
}

test_all_users_with_assignment_is_refused() {
  new_case all_users_with_assignment_is_refused
  write_state
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1 CONSENT=tenant ASSIGN_USERS=alex@contoso.example
  expect_status nonzero
  expect_err "cannot be combined with ASSIGN_USERS or GROUP_OBJECT_ID"
  expect_at_most_account_show
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1 CONSENT=tenant "GROUP_OBJECT_ID=$GROUP"
  expect_status nonzero
  expect_at_most_account_show
  end_case
}

test_all_users_with_principal_consent_is_refused() {
  new_case all_users_with_principal_consent_is_refused
  write_state
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1
  expect_status nonzero
  expect_err "needs CONSENT=tenant"
  expect_at_most_account_show
  end_case
}

test_no_assignment_is_refused() {
  new_case no_assignment_is_refused
  write_state
  run "TENANT_ID=$T" --apply
  expect_status nonzero
  expect_err "no assignment given"
  expect_at_most_account_show
  end_case
}

test_wrong_tenant_is_refused() {
  new_case wrong_tenant_is_refused
  AZ_TENANT=$OTHER_T
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "az is signed in to tenant '$OTHER_T', not '$T'"
  expect_at_most_account_show
  end_case
}

test_existing_name_is_refused_without_client_id() {
  new_case existing_name_is_refused_without_client_id
  APPS="{\"id\":\"$APP_OBJ\",\"appId\":\"$APP_ID\",\"displayName\":\"Purview CLI (eDiscovery)\",\"signInAudience\":\"AzureADMyOrg\",\"owners\":[]}"
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "an application named 'Purview CLI (eDiscovery)' already exists"
  expect_err "appId $APP_ID"
  expect_err "Set CLIENT_ID"
  expect_reads_only
  end_case
}

test_multi_tenant_client_id_is_refused() {
  new_case multi_tenant_client_id_is_refused
  APPS="{\"id\":\"$APP_OBJ\",\"appId\":\"$APP_ID\",\"displayName\":\"Other\",\"signInAudience\":\"AzureADMultipleOrgs\",\"owners\":[]}"
  write_state
  run "${restricted_vars[@]}" "CLIENT_ID=$APP_ID" --apply
  expect_status nonzero
  expect_err "signInAudience 'AzureADMultipleOrgs'"
  expect_reads_only
  run "${restricted_vars[@]}" "CLIENT_ID=$NEW1" --apply
  expect_status nonzero
  expect_err "no application with appId $NEW1"
  expect_reads_only
  end_case
}

test_invalid_values_are_refused() {
  new_case invalid_values_are_refused
  write_state
  local bad
  for bad in "TENANT_ID=not-a-guid" "TENANT_ID=" \
    "CLIENT_ID=00000000-0000-4000-8000-00000000001" \
    "GROUP_OBJECT_ID=00000000-0000-4000-8000-0000000000zz" \
    "ASSIGN_USERS=alex@contoso.example x'@contoso.example" \
    "ASSIGN_USERS=alex_contoso.example#EXT#@fabrikam.example" \
    "APP_NAME=Name \"quoted\"" "READ_ONLY=yes" "CONSENT=everyone" \
    "ALLOW_ALL_TENANT_USERS=true"; do
    : >"$FAKE_AZ_LOG"
    case "$bad" in
      TENANT_ID=*) run "$bad" ASSIGN_USERS=alex@contoso.example CONSENT=tenant ;;
      *) run "TENANT_ID=$T" ASSIGN_USERS=alex@contoso.example CONSENT=tenant "$bad" ;;
    esac
    [ "$status" -ne 0 ] || problem "accepted $bad"
    [ ! -s "$FAKE_AZ_LOG" ] || problem "made an az call with $bad"
  done
  end_case
}

test_unknown_argument_is_refused() {
  new_case unknown_argument_is_refused
  write_state
  run "${restricted_vars[@]}" --aply
  expect_status 2
  expect_err "unknown argument"
  [ ! -s "$FAKE_AZ_LOG" ] || problem "made an az call"
  run "${restricted_vars[@]}" --help
  expect_status 0
  expect_out "Usage: create-purview-app.sh [--apply]"
  end_case
}

all_tests=$(declare -F | awk '$3 ~ /^test_/ { print $3 }')
selected=("$@")
for name in $all_tests; do
  if [ "${#selected[@]}" -gt 0 ]; then
    wanted=false
    for s in "${selected[@]}"; do
      [ "test_$s" != "$name" ] && [ "$s" != "$name" ] || wanted=true
    done
    [ "$wanted" = true ] || continue
  fi
  "$name"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all tests passed"
