#!/usr/bin/env bash
set -euo pipefail

# Runs contrib/create-purview-app.sh against the fake az in fake-bin/ and
# checks its plans, its calls and its refusals (docs/SPEC.md section 5.2).
#
# Usage: tests/scripts/create-purview-app-test.sh [test name...]
# TEST_BASH names the shell that runs the script under test (default: bash),
# so the tests can run under macOS's /bin/bash 3.2 as well. TEST_SCRIPT runs
# another copy of the script, such as a deliberately broken one.

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
script=${TEST_SCRIPT:-$root/contrib/create-purview-app.sh}
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
  : >"$case_dir/out"
  : >"$case_dir/err"
  AZ_TENANT=$T
  EXTRA_SPS=""
  APPS=""
  ASSIGNMENTS=""
  GRANTS=""
  FAULTS=""
  EDITS=""
  HIDDEN_POLLS=0
  PAGE_SIZE=100
  NEXT_LINK_BASE=$G
  GRAPH_SP_STATE=$GRAPH_SP_JSON
}

write_state() {
  cat >"$FAKE_AZ_STATE" <<EOF
{"tenant": "$AZ_TENANT", "signed_in": "$ALEX",
 "users": [{"id": "$ALEX", "userPrincipalName": "alex@contoso.example"},
           {"id": "$SAM", "userPrincipalName": "sam@contoso.example"}],
 "groups": [{"id": "$GROUP", "displayName": "eDiscovery users"}],
 "sps": [$GRAPH_SP_STATE${EXTRA_SPS:+,$EXTRA_SPS}],
 "apps": [$APPS], "assignments": [$ASSIGNMENTS], "grants": [$GRANTS],
 "faults": [$FAULTS], "edits": [$EDITS], "new_sp_hidden_polls": $HIDDEN_POLLS,
 "page_size": $PAGE_SIZE, "next_link_base": "$NEXT_LINK_BASE", "next_id": 96}
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

# az_calls prints the logged az calls, arguments joined by spaces, without
# the fake sleep lines.
az_calls() { python3 "$here/azlog.py" calls "$FAKE_AZ_LOG"; }

# mutations prints each Graph write as "METHOD path body", read from the
# exact arguments of each call.
mutations() { python3 "$here/azlog.py" mutations "$FAKE_AZ_LOG"; }

sleeps() { python3 "$here/azlog.py" sleeps "$FAKE_AZ_LOG"; }

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
  other=$(grep -v '^account show ' <<<"$(az_calls)" || true)
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
count_calls() { grep -cE -- "$1" <<<"$(az_calls)" || true; }

# line_after PATTERN prints the call that follows the first match.
line_after() { awk -v p="$1" 'found && !done { print; done = 1 } $0 ~ p { found = 1 }' <<<"$(az_calls)"; }

# fault MATCH KIND APPLIED [NTH] adds a fault on the NTH call matching MATCH.
fault() {
  FAULTS="$FAULTS${FAULTS:+,}{\"match\": \"$1\", \"nth\": ${4:-1}, \"kind\": \"$2\", \"applied\": $3}"
}

# edit MATCH NTH TARGET KEY SET changes an object just before the NTH call
# matching MATCH, as a concurrent administrator would.
edit() {
  EDITS="$EDITS${EDITS:+,}{\"match\": \"$1\", \"nth\": $2, \"target\": \"$3\", \"key\": \"$4\", \"set\": $5}"
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
  [ "$(sleeps)" -eq 4 ] || problem "expected 4 polling sleeps"
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
  expect_out "WARNING: this grant gives more than the plan asks for: it also holds User.Read"
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
  expect_err "Read-back: not found by a successful read: an application named 'Purview CLI (eDiscovery)'"
  expect_err "run the dry run again"
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
  expect_err "Read-back: not found by a successful read: an assignment for alex@contoso.example"
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
  expect_err "Read-back: found: the Microsoft Graph grant for alex@contoso.example holds every planned scope"
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

# --- Round-two cases ----------------------------------------------------------

# expect_line LINE checks that stdout holds LINE as a whole line.
expect_line() { grep -qxF -- "$1" "$case_dir/out" || problem "stdout lacks the line: $1"; }

RRA_RO="[{\"resourceAppId\":\"$GRAPH_APP\",\"resourceAccess\":[{\"id\":\"$RO\",\"type\":\"Scope\"},{\"id\":\"$OFFLINE\",\"type\":\"Scope\"},{\"id\":\"$OPENID\",\"type\":\"Scope\"},{\"id\":\"$PROFILE\",\"type\":\"Scope\"}]},{\"resourceAppId\":\"$EDISC_APP\",\"resourceAccess\":[{\"id\":\"$DOWNLOAD\",\"type\":\"Scope\"}]}]"

# app_json [key=json...] prints the completed registration's application
# record with the given fields replaced, for example
# app_json 'isFallbackPublicClient=false'.
app_json() {
  local fallback=true redirects='["http://localhost/callback"]' rra=$RRA
  local owners="[\"$ALEX\"]" roles='[]' pair
  for pair in "$@"; do
    case "$pair" in
      isFallbackPublicClient=*) fallback=${pair#*=} ;;
      redirectUris=*) redirects=${pair#*=} ;;
      requiredResourceAccess=*) rra=${pair#*=} ;;
      owners=*) owners=${pair#*=} ;;
      appRoles=*) roles=${pair#*=} ;;
      *) problem "app_json: unknown field $pair" ;;
    esac
  done
  printf '{"id":"%s","appId":"%s","displayName":"Purview CLI (eDiscovery)",' "$APP_OBJ" "$APP_ID"
  printf '"signInAudience":"AzureADMyOrg","isFallbackPublicClient":%s,' "$fallback"
  printf '"publicClient":{"redirectUris":%s},"requiredResourceAccess":%s,' "$redirects" "$rra"
  printf '"owners":%s,"appRoles":%s}' "$owners" "$roles"
}

# done_state sets up the complete registration from an earlier run.
done_state() {
  EXTRA_SPS="$EDISC_SP_JSON,$DONE_SP"
  APPS="$DONE_APP"
  ASSIGNMENTS="$DONE_ASSIGNMENT"
  GRANTS="$DONE_GRANTS"
}

test_large_scope_list_is_read_whole() {
  new_case large_scope_list_is_read_whole
  # Graph's real list runs to tens of kilobytes; this one is over 300, well
  # past any pipe buffer. The wanted scopes come first, so a reader that
  # stopped at the first match would end a pipe's writer with SIGPIPE.
  local fillers="" n=1
  while [ "$n" -le 6000 ]; do
    fillers="$fillers$(printf ',["Filler.Scope.%04d","00000000-0000-4000-8000-%012x"]' "$n" $((0x1000 + n)))"
    n=$((n + 1))
  done
  GRAPH_SP_STATE="{\"id\":\"$GRAPH_SP\",\"appId\":\"$GRAPH_APP\",\"scopes\":[
    [\"eDiscovery.ReadWrite.All\",\"$RW\"],[\"eDiscovery.Read.All\",\"$RO\"],
    [\"offline_access\",\"$OFFLINE\"],[\"openid\",\"$OPENID\"],[\"profile\",\"$PROFILE\"]$fillers]}"
  write_state
  run "${restricted_vars[@]}"
  expect_status 0
  expect_out "eDiscovery.ReadWrite.All   $RW Scope"
  expect_out "Dry run: nothing was changed."
  end_case
}

# unchecked_case NAME MESSAGE runs a restricted apply with the faults already
# set and expects a read-back that could not check MESSAGE.
unchecked_case() {
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "the read-back could not check $1"
  expect_err "The read-back failed too:"
  ! grep -qF "not found by a successful read" "$case_dir/err" || problem "a failed read was reported as absence"
  ! grep -qF "Read-back: found" "$case_dir/err" || problem "a failed read was reported as found"
}

test_failed_app_read_back_is_unchecked() {
  new_case failed_app_read_back_is_unchecked
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/applications --body' timeout true
  fault '^ad app list --filter displayName' server false 2
  unchecked_case "whether an application named 'Purview CLI (eDiscovery)' exists"
  end_case
}

test_failed_owner_read_back_is_unchecked() {
  new_case failed_owner_read_back_is_unchecked
  fault 'owners/[$]ref' timeout true
  fault '^rest --method GET --url [^ ]*/owners' server false
  unchecked_case "whether the signed-in user is an owner"
  end_case
}

test_failed_assignment_read_back_is_unchecked() {
  new_case failed_assignment_read_back_is_unchecked
  fault '^rest --method POST --url [^ ]*/appRoleAssignedTo' throttle false
  fault '^rest --method GET --url [^ ]*/appRoleAssignedTo' server false
  unchecked_case "whether alex@contoso.example is assigned"
  end_case
}

test_failed_grant_read_back_is_unchecked() {
  new_case failed_grant_read_back_is_unchecked
  fault '^rest --method POST --url [^ ]*/oauth2PermissionGrants' server true
  fault '^rest --method GET --url [^ ]*/oauth2PermissionGrants' timeout false
  unchecked_case "whether the Microsoft Graph grant for alex@contoso.example holds the planned scopes"
  end_case
}

test_tenant_wide_write_grant_is_shown_under_per_user_read_only() {
  new_case tenant_wide_write_grant_is_shown_under_per_user_read_only
  done_state
  GRANTS="{\"id\":\"gAll\",\"clientId\":\"$APP_SP\",\"consentType\":\"AllPrincipals\",\"principalId\":null,\"resourceId\":\"$GRAPH_SP\",\"scope\":\"$GRAPH_SCOPE\"},
    {\"id\":\"gAllDl\",\"clientId\":\"$APP_SP\",\"consentType\":\"AllPrincipals\",\"principalId\":null,\"resourceId\":\"$EDISC_SP\",\"scope\":\"eDiscovery.Download.Read\"}"
  write_state
  local vars=("TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example READ_ONLY=1)
  run "${vars[@]}"
  expect_status 0
  expect_out "Microsoft Graph, all users (AllPrincipals), grant gAll: $GRAPH_SCOPE"
  expect_out "WARNING: this grant gives more than the plan asks for: it covers every user in the tenant, but the plan asks for per-user consent; it also holds eDiscovery.ReadWrite.All, which the plan does not ask for."
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/gAll"
  expect_out "Purview eDiscovery, all users (AllPrincipals), grant gAllDl: eDiscovery.Download.Read"
  expect_err "2 existing consent grant(s) give more than this plan asks for"
  expect_reads_only
  : >"$FAKE_AZ_LOG"
  run "${vars[@]}" --apply
  expect_status 0
  local principal="{\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\""
  expect_mutations <<EOF
PATCH /applications/$APP_OBJ {"requiredResourceAccess":$RRA_RO}
POST /oauth2PermissionGrants $principal,"resourceId":"$GRAPH_SP","scope":"eDiscovery.Read.All offline_access openid profile"}
POST /oauth2PermissionGrants $principal,"resourceId":"$EDISC_SP","scope":"eDiscovery.Download.Read"}
EOF
  expect_line "    purview auth login --client-id $APP_ID --tenant-id $T --read-only"
  reject_out "az rest --method DELETE"
  expect_out "Run the dry run again to see them as they are now, with removal commands where they apply."
  end_case
}

test_read_only_login_command() {
  new_case read_only_login_command
  write_state
  run "${restricted_vars[@]}" READ_ONLY=1 --apply
  expect_status 0
  expect_line "    purview auth login --client-id $NEW3 --tenant-id $T --read-only"
  : >"$FAKE_AZ_LOG"
  run "${restricted_vars[@]}" READ_ONLY=1 "CLIENT_ID=$NEW3" --apply
  expect_status 0
  expect_out "Nothing to change."
  expect_line "    purview auth login --client-id $NEW3 --tenant-id $T --read-only"
  expect_no_mutation
  # Without READ_ONLY the command asks for nothing narrower.
  end_case
  new_case read_write_login_command
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status 0
  expect_line "    purview auth login --client-id $NEW3 --tenant-id $T"
  end_case
}

test_paging_finds_matches_on_later_pages() {
  new_case paging_finds_matches_on_later_pages
  done_state
  PAGE_SIZE=1
  APPS=$(app_json "owners=[\"$SAM\",\"$ALEX\"]")
  ASSIGNMENTS="{\"id\":\"a0\",\"principalId\":\"$SAM\",\"resourceId\":\"$APP_SP\",\"appRoleId\":\"$ROLE\"},$DONE_ASSIGNMENT"
  GRANTS="{\"id\":\"g0\",\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$SAM\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"$GRAPH_SCOPE\"},$DONE_GRANTS"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status 0
  expect_out "alex@contoso.example -> $ALEX: already assigned"
  expect_out "Microsoft Graph for alex@contoso.example: $GRAPH_SCOPE (present)"
  expect_out "Nothing to change."
  expect_no_mutation
  [ "$(count_calls 'appRoleAssignedTo.*skiptoken')" -ge 1 ] || problem "the second page was never read"
  end_case
}

test_continuation_link_off_graph_is_refused() {
  new_case continuation_link_off_graph_is_refused
  done_state
  PAGE_SIZE=1
  NEXT_LINK_BASE="https://graph.microsoft.com.contoso.example/v1.0"
  ASSIGNMENTS="{\"id\":\"a0\",\"principalId\":\"$SAM\",\"resourceId\":\"$APP_SP\",\"appRoleId\":\"$ROLE\"},$DONE_ASSIGNMENT"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "a continuation link left the Graph v1.0 endpoint"
  [ "$(count_calls 'contoso[.]example/v1.0')" -eq 0 ] || problem "the script followed a link off Graph"
  expect_no_mutation
  end_case
}

test_fallback_only_update_is_read_back() {
  new_case fallback_only_update_is_read_back
  done_state
  APPS=$(app_json isFallbackPublicClient=false)
  fault '^rest --method PATCH --url [^ ]*/applications/' timeout false
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_mutations <<EOF
PATCH /applications/$APP_OBJ {"isFallbackPublicClient":true}
EOF
  expect_err "Read-back: not found by a successful read: the planned values in application $APP_ID"
  # The same failure after the change took effect reads back as found.
  end_case
  new_case fallback_only_update_took_effect
  done_state
  APPS=$(app_json isFallbackPublicClient=false)
  fault '^rest --method PATCH --url [^ ]*/applications/' timeout true
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "Read-back: found: every field of application $APP_ID that the update sets now matches the plan"
  end_case
}

test_app_with_roles_is_refused() {
  new_case app_with_roles_is_refused
  done_state
  APPS=$(app_json 'appRoles=[{"id":"00000000-0000-4000-8000-000000000051"}]')
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=sam@contoso.example --apply
  expect_status nonzero
  expect_err "declares app roles"
  expect_reads_only
  end_case
}

test_restricted_plan_names_global_administrators() {
  new_case restricted_plan_names_global_administrators
  write_state
  run "${restricted_vars[@]}"
  expect_status 0
  expect_out "Global Administrators, whom Microsoft does not hold to the assignment requirement."
  end_case
  new_case all_users_plan_needs_no_exception
  write_state
  run "TENANT_ID=$T" ALLOW_ALL_TENANT_USERS=1 CONSENT=tenant
  reject_out "Global Administrators"
  end_case
}

test_permissions_changed_after_planning_stop_the_update() {
  new_case permissions_changed_after_planning_stop_the_update
  done_state
  APPS=$(app_json 'requiredResourceAccess=[]')
  edit '^ad app show --id [^ ]* --query requiredResourceAccess' 2 app "$APP_ID" \
    "{\"requiredResourceAccess\":[{\"resourceAppId\":\"$GRAPH_APP\",\"resourceAccess\":[{\"id\":\"$OPENID\",\"type\":\"Scope\"}]}]}"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "application $APP_ID changed after this run read it"
  expect_no_mutation
  end_case
}

test_redirects_changed_after_planning_stop_the_update() {
  new_case redirects_changed_after_planning_stop_the_update
  done_state
  APPS=$(app_json 'redirectUris=[]')
  edit '^ad app show --id [^ ]* --query publicClient.redirectUris' 2 app "$APP_ID" \
    "{\"publicClient\":{\"redirectUris\":[\"http://localhost:8400\"]}}"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_out "Redirect URI http://localhost/callback: missing"
  expect_err "application $APP_ID changed after this run read it"
  expect_no_mutation
  end_case
}

test_grant_changed_after_planning_stops_its_update() {
  new_case grant_changed_after_planning_stops_its_update
  done_state
  GRANTS="${DONE_GRANTS/\"scope\":\"$GRAPH_SCOPE\"/\"scope\":\"openid profile\"}"
  edit '^rest --method GET --url [^ ]*/oauth2PermissionGrants' 2 grant g1 '{"scope": "openid profile User.Read"}'
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "consent grant g1 changed after this run read it"
  expect_no_mutation
  end_case
}

test_grant_scope_is_rebuilt_from_single_words() {
  new_case grant_scope_is_rebuilt_from_single_words
  done_state
  GRANTS="${DONE_GRANTS/\"scope\":\"$GRAPH_SCOPE\"/\"scope\":\" openid\\tprofile\"}"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status 0
  expect_mutations <<EOF
PATCH /oauth2PermissionGrants/g1 {"scope":"openid profile eDiscovery.ReadWrite.All offline_access"}
EOF
  end_case
}

test_grant_scope_over_the_limit_is_refused() {
  new_case grant_scope_over_the_limit_is_refused
  done_state
  local long="openid" n=1
  while [ "$n" -le 383 ]; do
    long="$long $(printf 'Word.%04d' "$n")"
    n=$((n + 1))
  done
  GRANTS="${DONE_GRANTS/\"scope\":\"$GRAPH_SCOPE\"/\"scope\":\"$long\"}"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example
  expect_status nonzero
  expect_err "more than Graph's 3850"
  expect_reads_only
  end_case
}

test_unexpected_download_scope_id_is_refused() {
  new_case unexpected_download_scope_id_is_refused
  done_state
  EXTRA_SPS="${EDISC_SP_JSON/$DOWNLOAD/00000000-0000-4000-8000-000000000099},$DONE_SP"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "not $DOWNLOAD"
  expect_reads_only
  end_case
}

test_polling_gives_up_after_sixty_seconds() {
  new_case polling_gives_up_after_sixty_seconds
  HIDDEN_POLLS=100
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  expect_err "still not visible after 60s"
  [ "$(sleeps)" -eq 12 ] || problem "expected 12 polling sleeps, got $(sleeps)"
  [ "$(mutations | wc -l | tr -d ' ')" -eq 1 ] || problem "a change was sent before the principal was visible"
  end_case
}

test_unsafe_redirect_uri_is_refused() {
  new_case unsafe_redirect_uri_is_refused
  done_state
  APPS=$(app_json 'redirectUris=["http://localhost/a b"]')
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "redirect URI with unexpected characters"
  expect_reads_only
  end_case
}

test_fake_az_rejects_what_real_az_would() {
  new_case fake_az_rejects_what_real_az_would
  done_state
  write_state
  local s err="$case_dir/probe-err"
  # probe WANT_EXIT REASON ARGS... runs the fake directly and checks that it
  # fails with that exit and for that reason. Every probe passes a supported
  # -o, so a missing output format cannot be what refuses it.
  probe() {
    local want=$1 reason=$2
    shift 2
    s=0
    PATH="$here/fake-bin:$PATH" az "$@" >/dev/null 2>"$err" || s=$?
    [ "$s" -eq "$want" ] || problem "fake az gave exit $s, not $want, for: $*"
    if [ -n "$reason" ] && ! grep -qF -- "$reason" "$err"; then
      problem "fake az refused '$*' for another reason: $(cat "$err")"
    fi
  }
  # The same calls with nothing wrong are accepted, so each probe below fails
  # only for the fault it adds.
  probe 0 "" account show --query tenantId -o tsv
  probe 0 "" ad sp show --id "$APP_ID" --query id -o tsv
  probe 99 "unsupported command words" account show extra --query tenantId -o tsv
  probe 99 "unsupported option --bogus" ad sp show --id "$APP_ID" --bogus 1 -o tsv
  probe 99 "missing options ['--id']" ad sp show --query id -o tsv
  probe 99 "repeated option --filter" ad app list --filter x --filter y -o tsv
  probe 99 "unsupported output format: json" ad sp show --id "$APP_ID" --query id -o json
  local assignment grant
  assignment="{\"principalId\":\"$ALEX\",\"resourceId\":\"$APP_SP\",\"appRoleId\":\"$ROLE\"}"
  grant="{\"clientId\":\"$APP_SP\",\"consentType\":\"Principal\",\"principalId\":\"$ALEX\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"openid\"}"
  # A service principal PATCH by appId, an unknown body field, and duplicate
  # assignments, owners and grants.
  probe 3 "Service principal does not exist" rest --method PATCH --url "$G/servicePrincipals/$APP_ID" \
    --body '{"appRoleAssignmentRequired":true}' -o none
  probe 99 "unsupported body fields ['appId']" rest --method PATCH --url "$G/servicePrincipals/$APP_SP" \
    --body '{"appId":"x"}' -o none
  probe 1 "Permission being assigned already exists on the object" rest --method POST \
    --url "$G/servicePrincipals/$APP_SP/appRoleAssignedTo" --body "$assignment" -o none
  probe 1 "One or more added object references already exist" rest --method POST \
    --url "$G/applications/$APP_OBJ/owners/\$ref" --body "{\"@odata.id\":\"$G/directoryObjects/$ALEX\"}" -o none
  probe 1 "Permission entry already exists." rest --method POST --url "$G/oauth2PermissionGrants" \
    --body "$grant" -o none
  end_case
}

# --- Round-three cases --------------------------------------------------------

# grant_json ID TYPE PRINCIPAL RESOURCE SCOPE prints a grant of the app's
# service principal. PRINCIPAL is null for AllPrincipals.
grant_json() {
  printf '{"id":"%s","clientId":"%s","consentType":"%s","principalId":%s,"resourceId":"%s","scope":"%s"}' \
    "$1" "$APP_SP" "$2" "$3" "$4" "$5"
}

test_invalid_grant_id_is_refused() {
  new_case invalid_grant_id_is_refused
  done_state
  GRANTS="$(grant_json g/1 Principal "\"$ALEX\"" "$GRAPH_SP" openid),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" eDiscovery.Download.Read)"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "has an id of unexpected characters"
  expect_reads_only
  end_case
}

test_invalid_scope_word_is_refused() {
  new_case invalid_scope_word_is_refused
  done_state
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" "openid pro;file"),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" eDiscovery.Download.Read)"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "holds a scope of unexpected characters"
  expect_reads_only
  end_case
}

test_unreadable_reread_grant_scope_stops_its_update() {
  new_case unreadable_reread_grant_scope_stops_its_update
  done_state
  # The planned grant holds no scope at all, so a re-read whose scope cannot
  # be parsed must not compare equal to it.
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" ""),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" eDiscovery.Download.Read)"
  edit '^rest --method GET --url [^ ]*/oauth2PermissionGrants' 2 grant g1 '{"scope": "pro;file"}'
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status nonzero
  expect_err "consent grant g1 changed after this run read it"
  expect_no_mutation
  end_case
}

test_user_lookup_failure_is_not_reported_as_missing() {
  new_case user_lookup_failure_is_not_reported_as_missing
  fault '^ad user show --id sam@contoso.example' definite false
  write_state
  run "${restricted_vars[@]}"
  expect_status nonzero
  expect_out "UNRESOLVED sam@contoso.example: the lookup could not be checked; az's error is shown above"
  expect_err "error: could not look up sam@contoso.example:"
  expect_err "Insufficient privileges to complete the operation."
  reject_out "sam@contoso.example: no directory user found"
  expect_out "alex@contoso.example -> $ALEX: will be assigned"
  expect_reads_only
  end_case
  new_case missing_user_is_reported_as_not_found
  write_state
  run "TENANT_ID=$T" "ASSIGN_USERS=nobody@contoso.example"
  expect_status nonzero
  expect_out "UNRESOLVED nobody@contoso.example: no directory user found"
  reject_out "could not be checked"
  end_case
}

test_group_lookup_failure_is_not_reported_as_missing() {
  new_case group_lookup_failure_is_not_reported_as_missing
  fault '^rest --method GET --url [^ ]*/groups/' throttle false
  write_state
  run "TENANT_ID=$T" "GROUP_OBJECT_ID=$GROUP" CONSENT=tenant --apply
  expect_status nonzero
  expect_out "UNRESOLVED group $GROUP: the lookup could not be checked; az's error is shown above"
  expect_err "Too Many Requests"
  reject_out "no group found"
  expect_no_mutation
  end_case
  new_case missing_group_is_reported_as_not_found
  write_state
  run "TENANT_ID=$T" "GROUP_OBJECT_ID=00000000-0000-4000-8000-000000000032" CONSENT=tenant
  expect_status nonzero
  expect_out "UNRESOLVED group 00000000-0000-4000-8000-000000000032: no group found"
  reject_out "could not be checked"
  end_case
}

test_wrong_audience_grant_gets_only_removal_advice() {
  new_case wrong_audience_grant_gets_only_removal_advice
  done_state
  # Two tenant-wide grants under a per-user plan. Neither may get a command
  # that changes its scopes: only removal is offered, because any narrowed
  # version would still cover every user.
  GRANTS="$DONE_GRANTS,$(grant_json gAll AllPrincipals null "$GRAPH_SP" openid)"
  GRANTS="$GRANTS,$(grant_json gAllDl AllPrincipals null "$EDISC_SP" "eDiscovery.Download.Read User.Read")"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example
  expect_status 0
  expect_out "Microsoft Graph, all users (AllPrincipals), grant gAll: openid"
  expect_out "WARNING: this grant gives more than the plan asks for: it covers every user in the tenant, but the plan asks for per-user consent."
  expect_out "WARNING: this grant gives more than the plan asks for: it covers every user in the tenant, but the plan asks for per-user consent; it also holds User.Read, which the plan does not ask for."
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/gAll"
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/gAllDl"
  reject_out "PATCH"
  end_case
}

test_extra_scopes_get_no_command() {
  new_case extra_scopes_get_no_command
  done_state
  # Grants for the planned user with scopes beyond the plan, one of them with
  # none of the planned scopes. Their audience is right, so they get neither
  # a removal command nor a command that rewrites their scopes.
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" "$GRAPH_SCOPE User.Read Mail.Read"),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" User.Read)"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example
  expect_status 0
  expect_out "Microsoft Graph, alex@contoso.example (Principal), grant g1: $GRAPH_SCOPE User.Read Mail.Read"
  expect_out "WARNING: this grant gives more than the plan asks for: it also holds User.Read Mail.Read, which the plan does not ask for."
  expect_out "Purview eDiscovery, alex@contoso.example (Principal), grant g2: User.Read"
  expect_out "To narrow it, remove the extra scopes by hand in the Entra admin center or with"
  reject_out "az rest"
  reject_out "PATCH"
  end_case
}

test_former_assignee_grants_are_warned() {
  new_case former_assignee_grants_are_warned
  done_state
  # The completed setup is for alex; the plan now names sam instead.
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" "$GRAPH_SCOPE"),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" "eDiscovery.Download.Read User.Read")"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=sam@contoso.example
  expect_status 0
  expect_out "Microsoft Graph, user $ALEX (not in this plan) (Principal), grant g1: $GRAPH_SCOPE"
  expect_out "WARNING: this grant gives more than the plan asks for: it is for a user this plan does not assign."
  expect_out "WARNING: this grant gives more than the plan asks for: it is for a user this plan does not assign; it also holds User.Read, which the plan does not ask for."
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/g1"
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/g2"
  reject_out "PATCH"
  expect_err "2 existing consent grant(s) give more than this plan asks for"
  expect_reads_only
  end_case
  # Under tenant consent a per-user grant is narrower than the plan, so it
  # gets no warning.
  new_case per_user_grant_under_tenant_consent_is_not_warned
  done_state
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=sam@contoso.example CONSENT=tenant
  expect_status 0
  reject_out "WARNING"
  end_case
}

test_failed_lookup_gives_no_removal_commands() {
  new_case failed_lookup_gives_no_removal_commands
  done_state
  # The completed setup is for alex, and the plan names alex again, but the
  # lookup of alex is refused. Alex's own grants must not be taken for a
  # former assignee's, and no grant gets a removal command.
  GRANTS="$DONE_GRANTS,$(grant_json gAll AllPrincipals null "$GRAPH_SP" openid)"
  fault '^ad user show --id alex@contoso.example' definite false
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example
  expect_status nonzero
  expect_out "UNRESOLVED alex@contoso.example: the lookup could not be checked"
  expect_out "NOTE: this grant's user is not among the assignees that resolved. An assignee"
  expect_out "could not be checked."
  reject_out "it is for a user this plan does not assign"
  expect_out "it covers every user in the tenant, but the plan asks for per-user consent."
  expect_out "No removal command is given while an assignee lookup is unresolved."
  reject_out "az rest --method DELETE"
  expect_reads_only
  end_case
}

test_apply_gives_no_grant_advice() {
  new_case apply_gives_no_grant_advice
  done_state
  # The grant lacks planned scopes and holds an extra one, so --apply extends
  # it. Advice from the state before the run would be stale afterwards.
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" "openid User.Read"),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" eDiscovery.Download.Read)"
  GRANTS="$GRANTS,$(grant_json gAll AllPrincipals null "$GRAPH_SP" openid)"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example --apply
  expect_status 0
  expect_out "(will be extended to: openid User.Read eDiscovery.ReadWrite.All offline_access profile)"
  expect_out "this grant's existing scopes are kept."
  reject_out "stays as it is"
  reject_out "az rest"
  reject_out "PATCH the same URL"
  expect_out "2 consent grant(s) gave more than the plan asks for when this run started; see WARNING above."
  expect_out "Run the dry run again to see them as they are now, with removal commands where they apply."
  expect_mutations <<EOF
PATCH /oauth2PermissionGrants/g1 {"scope":"openid User.Read eDiscovery.ReadWrite.All offline_access profile"}
EOF
  end_case
  # The dry run afterwards describes the extended grant as it is now and
  # still offers no command that rewrites its scopes.
  new_case dry_run_after_apply_describes_the_new_state
  done_state
  GRANTS="$(grant_json g1 Principal "\"$ALEX\"" "$GRAPH_SP" "openid User.Read eDiscovery.ReadWrite.All offline_access profile"),$(grant_json g2 Principal "\"$ALEX\"" "$EDISC_SP" eDiscovery.Download.Read)"
  GRANTS="$GRANTS,$(grant_json gAll AllPrincipals null "$GRAPH_SP" openid)"
  write_state
  run "TENANT_ID=$T" "CLIENT_ID=$APP_ID" ASSIGN_USERS=alex@contoso.example
  expect_status 0
  expect_out "Microsoft Graph for alex@contoso.example: $GRAPH_SCOPE (present)"
  expect_out "it also holds User.Read, which the plan does not ask for."
  expect_out "az rest --method DELETE --url $G/oauth2PermissionGrants/gAll"
  reject_out "oauth2PermissionGrants/g1"
  reject_out "PATCH"
  end_case
}

test_multi_line_az_error_keeps_its_lines() {
  new_case multi_line_az_error_keeps_its_lines
  # az's error runs over three lines, holds a carriage return and a bell
  # character, and has no final newline.
  fault '^rest --method POST --url https://graph.microsoft.com/v1.0/applications --body' multiline false
  write_state
  run "${restricted_vars[@]}" --apply
  expect_status nonzero
  local err="$case_dir/err" after
  grep -qxF '    ERROR: Bad Gateway({"error":{"code":"badGateway"}})' "$err" ||
    problem "the first line of az's error is not on a line of its own"
  grep -qxF '    Second line of the error' "$err" || problem "the second line of az's error was not kept"
  grep -qxF '    Third line of the error' "$err" || problem "the last line of az's error was not kept"
  ! grep -q "$(printf '[\r\a]')" "$err" || problem "a control character reached the terminal"
  # Exactly one newline ends the error: the next message starts on the next
  # line, with no blank line between.
  after=$(awk 'found && !done { print; done = 1 } $0 == "    Third line of the error" { found = 1 }' "$err")
  [ "$after" = "    The outcome is unclear. Reading the result back; nothing is resent." ] ||
    problem "the error did not end with exactly one newline; next line: '$after'"
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
