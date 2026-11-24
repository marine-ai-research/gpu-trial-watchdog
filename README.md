# GPU trial watchdog

Publication candidate; not installed, armed or authorised. A small standard-library Python controller for one disposable Runpod Secure Cloud GPU Pod. It runs on a separate GitHub-hosted Linux runner. It never provisions resources, executes commands in a Pod, handles workload files, or performs inference. No third-party Python packages are needed.

## Scope and limits

- One approved name, pinned image digest, GPU type/count, data centre, ephemeral disk size, quoted price and exact startup fingerprint. ENTRYPOINT/CMD metadata must be explicit exec-form arrays; no shell parsing or fallback is used.
- Empty dedicated trial account required across six paginated resource categories.
- At most ten minutes to observe a new target, then an absolute 105-minute deadline from provider creation time, not from container readiness.
- Ports, persistent mounts and global networking must be absent. Unknown metadata stops the run.
- Policy drift, API failures and detected clock drift after binding attempt early exact-target deletion.
- An initial same-name configuration mismatch grants no cleanup receipt and causes no DELETE. Manual inspection is required. Only after full policy authorisation does the original exact ID become a cleanup target; other resources are never deleted.
- Three bounded deletion attempts, bounded absence verification, then resource-count reconciliation.
- Wall-clock drift cannot extend the monotonic deadline or prevent cleanup of the already authorised exact ID.
- Public output is fixed event names and resource counts only. No raw API bodies, identifiers, headers, policy values, exception messages or tracebacks are emitted by controller code. Transport refuses redirects and environment proxies.
- `all_billable_resources_verified` is always false. Console checks for unlisted products, reservations, delayed billing and residual charges remain mandatory.

A hosted-runner outage, hard kill, account suspension or provider API outage can defeat deletion. This is neither a service-level guarantee nor a total-spend cap. SIGINT/SIGTERM cleanup is best effort. Keep independent console access. Terminate the target before cancelling its watchdog. Missing or incompatible API metadata requires manual recovery, not relaxed validation.

## Files

`controller.py`, `terminate_trial.py`, `reconcile_resources.py`: reviewed runtime code.

`test_watchdog.py`: offline fake-transport/fake-clock tests, including a credential-free isolated entrypoint subprocess. No provider calls or credential are required.

`policy.example.json`: fictional, disabled configuration worksheet. Do not enter a credential in this file.

`PROVIDER-SCHEMA.md` and `fixtures/api-shapes.json`: documented response shapes and fictional offline fixtures, not live API captures. `BINDING-REVIEW.md` explains the initial authorisation boundary.

`policy-lock.json`: initially null; deliberately prevents operation. After separate approval, commit the SHA-256 of the reviewed canonical policy object. Canonical bytes are UTF-8 JSON with sorted keys, ASCII escaping, no spaces, no nonfinite numbers; the policy file's whitespace and trailing newline are not hashed. Keep real values out of the repository. Obtain and independently check the hash offline; do not use an online hashing website.

`.github/workflows/validate.yml`: manually dispatched, credential-free offline tests.

`.github/workflows/watchdog.yml`: manually dispatched fixed `inventory` or `watch` action. No arbitrary shell-command input, automatic triggers, workload transfer or nested archives.

## Approved setup from an iPad

Do not perform these steps until publication/account setup approval exists.

1. Use a dedicated GitHub Free account with two-factor authentication. Create public repository `gpu-trial-watchdog`, branch `main`. No unrelated repository, workload or actual account data belongs here.
2. Upload only the exact publication package files, retaining `.github/workflows/` paths. If creating workflow paths using the browser editor, independently verify their final bytes before any credential is supplied. Require read-only workflow token permissions. Retain the pinned checkout action, no self-hosted runners, no extra triggers or third-party actions. Protect main against force pushes/deletion. Only trusted maintainers may write.
3. Create environment `watchdog-approval`. Allow only branch `main`, no tags, and require an approved reviewer. Disable administrator bypass where available. If only the owner reviews their own run, do not claim two-person approval. Prevent self-review only when a separate authorised reviewer is available. Do not use repository-level API secrets.
4. Prepare the real private policy using the example's exact keys. Approval flags remain false until separately approved. Review its canonical hash and commit that hash only into `policy-lock.json`. Any policy/code change requires a newly reviewed commit.
5. Create repository variables `CONTROLLER_REPOSITORY` = exact `OWNER/gpu-trial-watchdog`, and `REVIEWED_CONTROLLER_COMMIT` = full reviewed 40-character commit SHA. Both are needed before job scheduling. Do not use environment variables for these two gates.
6. Configure the protected environment's policy fields from the table below. All must agree with the committed policy hash. Never put a JSON policy blob or credential in the repository. Only after separate credential approval add the real API token. Never enable debug logging.
7. After workflow execution approval, use Actions -> Offline source validation -> Run workflow -> main. This has no environment secret or provider access. Check the full job log and results.
8. Before using a real API token, perform a separately approved log canary test with a unique dummy token and fictional scalar policy secrets, while `policy-lock.json` remains null. Run GPU trial watchdog -> inventory. Expected: failed job, controller prints only `{"event": "STOP"}`, no API call, no dummy values in logs. Inspect all setup, environment and error logs. Clear dummy secrets afterwards. Restore/review the real lock and update the reviewed commit before any real operation. No tests here establish actual platform secret-release behaviour until the repository is configured and checked.
9. Only after separate authenticated/API approval, perform inventory and an empty-account watch rehearsal. Expected: `READY_EMPTY_ACCOUNT`, then `NO_RESOURCE_CREATED` after ten minutes, no deletion. Read scope is exercised; real deletion is not proven by an empty rehearsal.
10. For a separately approved paid trial, recheck capacity, quote and policy. Start a fresh watch and approve its environment release. Wait for `READY_EMPTY_ACCOUNT` before creating exactly the approved target within ten minutes. Do not queue unavailable capacity. Require `TARGET_BOUND`; otherwise immediately use the provider console. A queued or awaiting-review job is not armed.
11. Expect `TARGET_ABSENT` after scoped deletion and `RECONCILIATION` with zero counts. Inspect the provider console and later billing separately. On STOP, missing heartbeat, lost runner or ambiguous state, terminate/delete the exact target manually and verify absence. Do not close or cancel the watchdog first.

## Protected configuration

Environment secrets (individual scalar values, never a structured secret):

| Name | Meaning |
|---|---|
| `TRIAL_RUNPOD_TOKEN` | Approved restricted provider API credential |
| `POLICY_NAME` | Exact target name |
| `POLICY_IMAGE` | Full approved image reference including digest |
| `POLICY_DATA_CENTER` | Exact approved data-centre ID |
| `POLICY_GPU_TYPE` | Exact provider GPU identifier |
| `POLICY_MAX_HOURLY_USD` | Approved total hourly quote as a decimal string |

Environment variables:

| Name | Meaning |
|---|---|
| `POLICY_APPROVED` | `true` only after controller execution approval |
| `POLICY_BILLING_MODE` | `prepaid` |
| `POLICY_AUTO_PAY_DISABLED` | `true` only after confirmation |
| `POLICY_RISK_ACCEPTED` | `true` only after cap/residual-risk decision |
| `POLICY_GPU_COUNT` | `1` |
| `POLICY_CONTAINER_DISK_GB` | Approved integer, at most `50` |
| `POLICY_STARTUP_SHA256` | Reviewed SHA-256 of canonical JSON containing exact `entrypoint` and `cmd` arrays |

The API scopes required by the present six-category inventory and cleanup are `pods:read`, `pods:write`, `volumes:read`, `serverless:read`, `clusters:read`. Provider write scope is broader than exact-target deletion; code restrictions do not narrow the credential's capabilities. Never grant an untrusted contributor write access or approve modified code for secret release. Outsiders' forks do not receive this repository's environment secrets. Workflows reject wrong repository, event, branch and commit; server-side environment controls are also required. Owners, approved maintainers, GitHub and the provider remain trusted.

Standard GitHub-hosted public-repository runner compute is free under published terms; larger runners and other paid products are outside scope. No artifacts, caches, persistent runner or subscription are required. Runner timeout is 130 minutes; individual GitHub-hosted jobs support up to six hours. No statement here guarantees availability or changes provider billing terms.

## Offline validation

On an independently approved offline Python 3.10+ host, from this package directory:

```sh
python3 -I -B test_watchdog.py
```

The prepared source is deliberately inert with its null policy lock. Do not substitute dummy approvals to run against a real account. Real end-to-end deletion, API shape, scoped permission, environment-release and public-log checks remain commissioning prerequisites.

## Exact startup authorisation

The generic policy contains only `startup_sha256`, not private startup commands. Its value is SHA-256 over `canonical({"entrypoint": [...], "cmd": [...]})`, using the same sorted-key, ASCII-escaped compact JSON rules as the policy lock. Order, arguments, whitespace and empty arguments are significant. A hash is an identity check, not encryption; never put credentials into startup arguments. Record the reviewed hash as protected-environment variable `POLICY_STARTUP_SHA256`, and include it in the locked policy. Source, policy or fingerprint changes require a newly reviewed policy lock, manifest and commit pin. The example remains disabled and the public lock null.

Both native fields and raw `args` metadata must be present. A nonempty raw args string is accepted only as an exact JSON object containing both matching arrays; contradictory, malformed or shell-string representations stop. Empty raw args is not used to infer missing native arrays. Missing/incorrect startup metadata grants no receipt or deletion permission. Startup drift after valid binding still deletes only the original authorised ID.

Creation time is checked again against the bound receipt on subsequent readback, so metadata changes cannot renew the deadline. Explicit null runtime in documented list responses is accepted without claiming live port verification; missing runtime or known contradictory runtime mappings stops authorisation. The private command client uses the identical identity validator and additionally requires ready RUNNING status and known empty live mappings before exec.
