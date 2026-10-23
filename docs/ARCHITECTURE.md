# Architecture

## Trust boundaries

| Actor | Holds | Can do | Cannot do |
|---|---|---|---|
| **Platform admin** (`COMMANDER_ADMIN_TOKEN`) | Provisioning rights | Create tenants, top up credits, verify the full audit log | Act inside a tenant's missions |
| **Operator** (`cmd_op_…`) | The macro ledger | Open/inspect missions, decide approvals, skip/kill, mint worker keys | Pull directives or submit proof (role split) |
| **Worker** (`cmd_live_…`) | One lease on one step | Pull the current directive, submit proof, request clearance | See later steps, other tenants, or the operator API |
| **Approver via link** | A signed capability | Make exactly one decision on one approval, until expiry | Do anything else; flip the decision; extend the link |

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
- Each rejected attempt rotates the **nonce**. Identical evidence is rejected as a **replay** and still spends an attempt.
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

## Decisions worth knowing

- **Stateless MCP transport.** All state is in the ledger, so each request builds a fresh server and transport. No
  session affinity; horizontally scalable once the store is shared.
- **Wire contract is snake_case, runtime state is camelCase.** Chosen because tool arguments are written by models.
- **Operators open missions; workers never do.** If the worker could write the plan, macro-context isolation would be
  decorative. Missions are opened over the operator API, and the worker is given only a handle.
- **Voice vs. record.** The persona governs outbound language. The ledger stays literal.
- **Snapshots, not an ORM.** The simplest thing that is correct for one instance; `Store` is the seam.
