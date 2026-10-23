# Architecture

## Trust boundaries

| Actor | Holds | Can do | Cannot do |
|---|---|---|---|
| **Platform admin** (`COMMANDER_ADMIN_TOKEN`) | Provisioning rights | Create tenants, top up credits, verify the full audit log | Act inside a tenant's missions |
| **Operator** (`cmd_op_…`) | The macro ledger | Open/inspect missions, decide approvals, skip/kill, mint worker keys | Pull directives or submit proof (role split) |
| **Worker** (`cmd_live_…`) | One lease on one step | Pull the current directive, submit proof, request clearance | See later steps, other tenants, or the operator API |
| **Approver via link** | A signed capability | Make exactly one decision on one approval, until expiry | Do anything else; flip the decision; extend the link |
| **Guard hook** (`commander-guard`, on the developer's machine) | A worker key and a mission id, from its environment | Ask for a verdict on one native tool call, and block it on anything but `CLEARED` | Decide anything in remote mode; be trusted by the server beyond the worker role |
| **Witness runner** (inside Commander, or injected) | A workspace root and an executable allowlist | Run operator-defined argv and read files under the root | Run anything a worker names; leave the root; see Commander's environment |

Keys are stored as SHA-256 hashes. Every record lookup is tenant-checked, and a record in another tenant is
indistinguishable from one that does not exist (`NOT_FOUND`).

## Mission state machine

```
mission:  active ──(stage clearance)──► paused ──(decide)──► active
             │
             ├──(attempts exhausted)──► quarantined ──(authorize/redirect)──► active
             ├──(last step passes)────► completed
             └──(kill)────────────────► killed

step:     locked ─(pull)─► released ─(verifiers pass)─► passed
                              │
                              └─(attempts exhausted)─► quarantined ─(skip)─► skipped
```

- A step is **locked** until the previous step passes; the worker cannot name it, and a lease is bound to one step.
- Pulling a directive issues (or re-uses) a **lease**. Proof and clearance both require the live lease.
- Each rejected attempt rotates the **nonce**. Identical evidence is rejected as a **replay** and still spends an attempt,
  except on steps with independent checks, where the disk may have changed and the same worker evidence is judged afresh.
- Proof auditing is **asynchronous** because witness checks run commands. One audit per step at a time (a second
  submission gets `CONFLICT`), and mission, step and lease are re-validated after the await. A kill, pause or lease
  expiry mid-audit discards it with `LEASE_INVALID` and records no attempt.
- Quarantine revokes the lease, stages an approval, and pushes a card. Authorize or redirect re-opens the step with
  a fresh attempt budget (a redirect delivers the operator's note behind the Deductive Anchor). Kill ends the mission.
- A staged clearance pauses the whole mission. Authorize/redirect resumes it and extends the lease so a long wait does
  not strand the worker.

## Clearance pipeline

```
action ──► Sentinel rules ──► deny ───────────────────────────────► DENIED + redirect patch
                │                stage ─────────────────────────────► STAGED
                │                allow
                ▼
        risk tier = critical and action mutates? ─ yes ─► STAGED
                │ no
        risk tier = elevated and gate configured? ─ yes ─► gate (tighten only) ─► allow | stage | deny
                │ no
                ▼
             CLEARED
```

The gate is skipped for anything the rules already decided. After it returns, mission and lease are re-checked, because
the world can change while a model deliberates.

### Native tools: the guard path

```
Claude Code ──PreToolUse──► commander-guard ──► map tool call to an action ──► refuse locally? ─ yes ─► exit 2
   (Bash, Write, Edit,            │                (Bash→shell, file tools→fs write by path;        (credential in the content,
    MultiEdit, NotebookEdit)      │                 content is scanned on this machine only)         no command/path, over 16 KiB)
                                  ▼
              POST /v1/guard/clearance {mission_id, tool, action}      worker role; mission active;
                                  │                                    current step released with a live lease
                                  ▼
        an unused operator authorization of this exact action on this step? ─ yes ─► CLEARED (token consumed)
                                  │ no
                                  ▼
                       the pipeline above (STAGED pauses the mission; the card reads "NATIVE Bash: …")
                                  │
              CLEARED ► exit 0        DENIED / STAGED / REFUSED ► exit 2, stderr = Commander's directive
              server unreachable ► exit 2 (exit 0 only with COMMANDER_GUARD_FAIL_OPEN=1)
```

The hook cannot know the lease id, so the mission is the handle and the lease is looked up server-side. An operator's
authorization of a staged native action is a **single-use** pass: bound to mission, step and the whitespace-normalized
action, valid for one lease lifetime, minted only from guard-sourced clearances (an MCP-route clearance cannot be spent
by the guard).

### Independent verification

```
submit_proof ─► worker role · mission active · lease valid · no audit already running for the step (else CONFLICT)
             ─► step has witness checks but none is available to this tenant? ─► refused (CONFLICT), never passed
             ─► charge proof
             ─► phase 1: worker-evidence verifiers (+ replay check, unless the step is witnessed)
             ─► all passed and the step has witness checks? ─► charge witness
             ─► phase 2: witness_command / witness_file under one shared time budget (runs only operator-defined argv)
             ─► re-validate mission, current step and lease (else LEASE_INVALID, nothing recorded)
             ─► record ONE attempt holding both phases ─► PASSED | REJECTED | QUARANTINED
```

Witness commands are vetted at **mission-open** through the same Sentinel (`scan`, which is stateless and ignores the
strict-shell allowlist that governs workers), so a dangerous command is rejected up front rather than discovered at the
first submission. `Witness` is an interface (`run`, `inspect`); `LocalWitness` is the in-process implementation and the
seam for a container or remote runner.

## Data and persistence

- `state.json`: tenants, hashed keys, missions, approvals, clearances. Written atomically (tmp + rename), mode `0600`,
  coalesced to one write per event-loop turn.
- `audit.jsonl`: append-only. Record: `{seq, ts, tenantId, type, data, prev, hash}` with
  `hash = sha256(prev|seq|ts|tenantId|type|stableJSON(data))`. **One chain per tenant.** Records of different tenants
  interleave in the file but link only to their own history, so a tenant can verify its own chain without learning
  anything about anyone else, and one tenant's tamper cannot break another's verification.
- On load the whole chain is verified and a broken chain refuses to start. A torn final line (crash mid-append) is
  dropped and the file rewritten so the next append cannot fuse with it.
- Audit data never contains raw worker evidence, only hashes, counts and rule names (plus operator-authored titles and
  reasons). Raw logs are discarded after pruning.
- HUD metrics are *derived* from the audit tail and the ledger, never tracked separately, so they cannot drift.

## Threat model (what was designed against)

| Threat | Control | Residual risk |
|---|---|---|
| Worker claims success | `claim` is never read by a verifier; recorded for the operator only | Fabricated but consistent evidence (see README §2) |
| Worker replays old proof | Per-attempt nonce; replay detection by evidence hash | None known for replay; fabrication remains |
| Worker skips ahead | Steps are locked server-side; lease bound to one step; future steps never serialized to the worker | None known |
| Worker games visible checks | `hidden` verifiers, reported as `[hidden]` with no detail | Checks must still be well chosen |
| Runaway loop / token burn | Per-mission credit burn throttle; identical-action loop detection; attempt caps | Limits are per process |
| Destructive command | Tokenizing shell scan (quotes, wrappers, `bash -c`, `$()`, pipes), SQL scan, egress allowlist | Static analysis is bypassable; not a sandbox |
| Credential exfiltration | Secret-path read + egress in one command is denied; secrets redacted from operator cards and gate prompts | Obfuscated multi-step exfil |
| Prompt injection via worker output into persistent context | Manifests are built from verifier outcomes and whitelisted counters, never worker prose; ledger is framed as data | A directive author who is themselves malicious |
| Prompt injection into the reasoning gate | Worker text fenced as untrusted; gate can only tighten; fails to `stage` | Gate can be talked out of tightening, never into loosening |
| ReDoS in operator-defined regex | Each match runs in a throwaway VM context with a 100 ms watchdog | 100 ms CPU per hostile pattern per call |
| Link prefetch / unfurl triggers a decision | Decisions are `POST` only; the `GET` page is read-only | None known |
| Link forgery / replay / flip | HMAC-SHA256 over `approval:id:scope:exp`; per-decision scope; expiry; constant-time compare | Link leakage grants one decision until expiry |
| XSS in HUD / decision page | `textContent` only in the HUD; escaped server HTML; CSP `default-src 'none'`, no inline script | None known |
| Key guessing | Hashed keys; failed-auth throttle per address | Per-process, per-address |
| Cross-tenant access | Tenant check on every lookup; per-tenant audit chains; `NOT_FOUND` for foreign ids | None known |
| Audit tampering | Per-tenant hash chain; refuse-to-start on break | Tail truncation |
| Unreachable gate / notifier | Gate failure → staged; notifier failure → audited, never blocks | Operator may not see the push |
| Native tool call bypasses the Sentinel | Guard hook on `PreToolUse` for Bash/Write/Edit/MultiEdit/NotebookEdit; fails closed | Unguarded tools; anyone who can edit the settings can remove it; a tripwire, not a boundary |
| Agent disables its own guard | Mutation of `.claude/settings*.json` / `.claude/hooks/` denied; shell commands naming them or `claude-hook` staged | Obfuscated shell (split strings, scripts); a human or another process editing the file |
| Guard fails open during an outage | Fail-closed by default; fail-open is an explicit opt-in that excuses only "Commander unreachable", never a refusal, a bad key or an internal error | The operator who opts in |
| Malformed or non-object hook input | Anything that is not a JSON object with a usable command or path is refused | None known |
| Operator authorization replayed or transferred | Single-use, bound to mission + step + normalized action, expires after one lease lifetime, minted only from guard-sourced clearances | The window of one lease lifetime |
| Credential written into a file by the agent | Content scanned locally; the refusal names the kind and never repeats it; content never leaves the machine | Secret formats nobody has a pattern for |
| Worker fabricates results for a witnessed check | Commander runs the command and reads the disk itself | Weak or tamperable checks (a worker that edits the tests) |
| Witness executes worker-influenced code | Off by default; per-tenant opt-in; bare-name allowlist, no shell, scrubbed env, private `HOME`, process-group kill, output and concurrency caps | **Not a sandbox**: runs with Commander's OS privileges. Same trust domain only |
| Witness reads or runs outside the workspace | Relative paths only (schema-enforced); lexical and `realpath` confinement; `O_NOFOLLOW` on open | Check-then-open race against a concurrent hostile writer |
| Dangerous operator-authored witness command | Vetted through the Sentinel at mission-open; anything but `allow` is rejected | Static-analysis limits |
| Slow or huge witness runs exhaust the host | Per-check timeout, shared per-submission budget, output caps, concurrency plus queue limits (`THROTTLED`), one audit per step | Per-process limits |

## Decisions worth knowing

- **Stateless MCP transport.** All state is in the ledger, so each request builds a fresh server and transport. No
  session affinity; horizontally scalable once the store is shared.
- **Wire contract is snake_case, runtime state is camelCase.** Chosen because tool arguments are written by models.
- **Operators open missions; workers never do.** If the worker could write the plan, macro-context isolation would be
  decorative. Missions are opened over the operator API, and the worker is given only a handle.
- **Voice vs. record.** The persona governs outbound language. The ledger stays literal.
- **Snapshots, not an ORM.** The simplest thing that is correct for one instance; `Store` is the seam.
- **The guard is stateless and fails closed.** Each hook run is a fresh process, so all state (mission, lease, loop
  counts, authorizations) lives on the server. Keys are read from the environment and never written to a settings file.
- **Witnessing is off by default and never silently downgraded.** It executes code, so a deployment must opt in, and a
  mission that asks for it where it is unavailable is rejected at open and refused at submission.
- **`Witness` is an interface because isolation is the real product.** `LocalWitness` is honest about being the cheap
  version; the multi-tenant answer is a different implementation, not a flag.
