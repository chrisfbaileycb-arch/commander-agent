# Agent Commander

A supervisory control plane for third-party agents. Bring your own workers (Claude Code, Cursor, custom
scrapers, swarms). Commander sits above them as a single MCP endpoint and **will not let a workflow advance
without mechanical proof**.

It does not write code and it does not trust the worker's account of its own work. It holds the plan, releases
one step at a time, and discards "Task complete!" in favour of exit codes, schemas, hashes and nonces it can
check itself.

```
                    [ MACRO TASK LEDGER ]   (operator-held; the worker never sees it)
                              │
                    releases step N only
                              ▼
                    [ SUBORDINATE WORKER ]  ── asks clearance before risky actions ──► [ SENTINEL ] ─► allow / deny / stage
                              │
                    submits evidence (exit code, stdout, artifacts)
                              ▼
                 [ MECHANICAL PROOF AUDITOR ]
              all verifiers pass?       any fail?
                    │                       │
        unlock step N+1, write a      redirect patch, fresh nonce;
        1-line manifest to ledger     out of attempts → lease revoked, step quarantined, phone buzzes
```

## What is here

| Blueprint component | Where |
|---|---|
| Two-phase step-gated airlock, leases, quarantine | `src/airlock.ts` |
| Mechanical Proof Auditor (8 verifiers, hidden checks, nonces) | `src/verifiers.ts` |
| **Independent witnessing**: Commander runs the check and reads the disk itself | `src/witness.ts` |
| **Native-tool guard**: Claude Code `PreToolUse` hook through the Sentinel | `src/guard/`, `guard/claude-code/settings.json` |
| Inquisitor Diff Auditor (paths, secrets, size) | `src/inquisitor.ts` |
| Perimeter Sentinel (shell / SQL / HTTP / fs, egress allowlist, loop + burn detection) | `src/sentinel.ts`, `src/auth.ts` |
| Just-In-Time Markdown Pruning Filter | `src/pruner.ts` |
| Frontier Reasoning Interceptor Gate (Gemini, tighten-only) | `src/gate.ts` |
| MCP gateway + API-key facade + SaaS credit metering | `src/mcp.ts`, `src/http.ts`, `src/auth.ts` |
| Persona (`COMMANDER_SOUL.md`) and voice guard | `COMMANDER_SOUL.md`, `src/persona.ts` |
| Desktop/Web HUD | `src/hud/` (served at `/hud`) |
| Mobile Push Sentinel (Authorize / Redirect / Kill) | `src/approvals.ts`, signed links in `src/http.ts` |
| Tamper-evident audit ledger (hash-chained per tenant) | `src/store.ts` |

## Try it

```bash
npm install
npm test            # unit suites, an end-to-end run through the official MCP SDK client, and the real hook script as a subprocess
npm run demo        # a scripted worker lies, replays, is denied, is staged, and is approved by a signed link
```

The demo is the fastest way to see the behaviour. It asserts as it goes, so it doubles as a smoke test, and it
contains a complete example mission.

## Run it

```bash
export COMMANDER_ADMIN_TOKEN=$(openssl rand -hex 24)
export COMMANDER_LINK_SECRET=$(openssl rand -hex 32)
export COMMANDER_DATA_DIR=./data
npm run dev                      # or: npm run build && npm start
```

Provision a tenant, mint a worker key, open a mission:

```bash
# platform admin: create a tenant (returns the operator key once)
curl -s -X POST localhost:8787/v1/admin/tenants \
  -H "Authorization: Bearer $COMMANDER_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"acme","credits":1000}'

# operator: mint a worker key (cmd_live_…) and open a mission (see scripts/demo.ts for a full mission body)
curl -s -X POST localhost:8787/v1/operator/keys -H "Authorization: Bearer $OP" -H 'content-type: application/json' -d '{"label":"claude-code"}'
curl -s -X POST localhost:8787/v1/operator/missions -H "Authorization: Bearer $OP" -H 'content-type: application/json' -d @mission.json
```

Open `http://localhost:8787/hud` and paste the operator key.

### Point a worker at it

Standard MCP over HTTP. The client needs no Commander code, only a URL and a key:

```json
{
  "mcpServers": {
    "agent-commander": {
      "type": "http",
      "url": "https://commander.example.com/v1/mcp",
      "headers": { "Authorization": "Bearer cmd_live_…" }
    }
  }
}
```

Then tell the worker, in its system prompt, to work under Commander. A minimal version:

> You operate under Agent Commander for mission `msn_…`. Call `commander_get_directive` for your orders and execute only
> that step. Before any shell command, SQL, outbound request, file mutation, deploy or payment, call
> `commander_request_clearance` and do exactly what is cleared. Report real exit codes and raw output with
> `commander_submit_proof`. Claims of completion are discarded.

I have tested the server against the official MCP TypeScript SDK client. I have **not** yet tested it against
Claude Code or Cursor specifically; the transport is standard Streamable HTTP, so it should work, but verify.

## Guard Claude Code's native tools (PreToolUse hook)

Commander can only judge what a worker routes through it, and Claude Code's own `Bash`, `Write`, `Edit`, `MultiEdit`
and `NotebookEdit` tools never touch an MCP server. The guard closes that gap: a Claude Code `PreToolUse` hook that asks
Commander before each of those calls runs.

Claude Code runs the hook before every guarded call and passes the call as JSON on stdin. The hook maps it onto the
actions the Sentinel already understands (`Bash` becomes `shell`; the file tools become an `fs` write judged by path)
and asks the server. **Exit 0** lets the call proceed. **Exit 2** blocks it and hands stderr to the model, so
Commander's redirect patch becomes the model's next instruction.

```bash
npm run build                                   # produces dist/guard/claude-hook.js
node dist/guard/claude-hook.js --print-settings \
  --url https://commander.example.com --mission msn_…   # prints the settings fragment; merge it into .claude/settings.json
export COMMANDER_KEY=cmd_live_…                 # a worker key. Set it in the shell that runs Claude Code; it is never written to a file
```

`guard/claude-code/settings.json` is the same fragment as a template (it lives outside `.claude/` on purpose, so this
repository's own sessions are not guarded by a placeholder path). Register the MCP server as above as well: the agent
pulls its directive over MCP (which issues the lease) and the hook judges native calls against that mission's current
step.

| Variable | Meaning |
|---|---|
| `COMMANDER_URL`, `COMMANDER_KEY`, `COMMANDER_MISSION` | Remote mode: the server's rules, mission state and approvals apply. |
| `COMMANDER_GUARD_LOCAL=1` [`COMMANDER_GUARD_POLICY=/path/policy.json`] | Local mode: the same Sentinel rules on this machine, no server. Nothing can be staged, so a rule that would stage blocks instead, and loops are not detected across calls. |
| `COMMANDER_GUARD_FAIL_OPEN=1` | Allow the call when Commander is **unreachable**. Default is to block. |
| `COMMANDER_GUARD_TIMEOUT_MS` | Request timeout, default 10000. |

Behaviour worth knowing:

- **It fails closed.** An unreachable server, a server fault, a half-configured hook, malformed hook input or a bug in
  the hook all block the call. `FAIL_OPEN` excuses only "Commander is unreachable"; a rejected key, a held mission or a
  denial still blocks.
- **Staging works the same way as over MCP.** A production-impacting call pauses the mission and your phone shows
  `NATIVE Bash: …`. After you authorize, the model retries the same command and it is cleared **once**. The pass is bound
  to that mission, step and exact action (whitespace-normalized), expires after one lease lifetime, and cannot be
  created by an MCP-route clearance.
- **Writes are judged by path** (`.env`, `.git/**`, `.github/workflows/**`, system paths, traversal), and the content
  being written is scanned locally for credentials. File contents are never sent to Commander.
- **It protects itself.** A file-tool mutation of `.claude/settings*.json` or `.claude/hooks/` is denied, and a shell
  command that mentions those paths or `claude-hook` is staged for a human.

What it is not, stated plainly:

- **Not tested inside a real Claude Code session.** It is tested as the real script run as a subprocess against the real
  server, using Claude Code's documented hook contract (JSON on stdin, exit 2 plus stderr to block). Which tool names
  fire hooks, how subagents and permission modes interact with them, and the hook environment can differ by version.
  Verify on yours before you rely on it.
- **Five tools only.** `WebFetch`, other MCP servers' tools and anything else are untouched.
- **A tripwire on the developer's machine, run as the developer.** A shell command that is cleared can do anything the OS
  allows, including edits to the settings file that the static rule cannot see through. If the agent is not trusted,
  protect the settings with OS permissions or your organization's managed Claude Code settings.

## Independent witnessing: Commander checks the world itself

By default, evidence is whatever the worker says it is. A **witness** changes that for the checks you choose: you define
the verification command in the mission, and Commander runs it, collects the exit code directly, and inspects files on
disk, then compares what it saw with what the worker claimed.

```jsonc
"proof": [
  { "type": "exit_code" },                                    // what the worker reports: a cheap pre-filter
  { "type": "witness_command", "argv": ["npm", "test"], "cwd": "packages/api",
    "expected_exit": 0, "timeout_sec": 300, "stdout_regex": "\\d+ passed" },
  { "type": "witness_file", "path": "dist/app.js", "min_bytes": 1000, "sha256": "…",
    "regex": "…", "schema": { /* … */ }, "matches_artifact": "app.js" }   // the submitted artifact must equal the file on disk
]
```

- Only **operators** write witness commands. Nothing from a worker is ever interpolated into one. They run as an argv
  with no shell, and each is vetted by the Sentinel when the mission is opened; anything it would not allow is rejected.
- The witness runs **only if the worker-evidence verifiers pass**, so a bad submission costs no run. It is charged
  `credit_costs.witness`. Identical worker evidence is not a replay on a witnessed step, because the disk may have changed.
- A worker that reports `exit 0` while the build is broken is rejected with what Commander observed (unless the check is
  `hidden`). If the mission is killed or the lease lapses while the commands run, the audit is discarded and no attempt
  is recorded.
- It is **off by default**, and a mission that asks for it on a deployment without it is rejected at open, never
  silently downgraded.

```bash
COMMANDER_WITNESS_MODE=local
COMMANDER_WITNESS_ROOT=/srv/work/project     # every path and cwd is confined here, symlinks included
COMMANDER_WITNESS_ALLOW=node,npm,pytest      # bare executable names only
COMMANDER_WITNESS_TENANTS=ten_abc            # or * for a single-tenant deployment
```

**Trust model.** `LocalWitness` is **not a sandbox**. `npm test` runs code from a workspace the *worker* controls, with
Commander's OS privileges. Enable it only where the workspace and Commander share a trust domain (your own machine or CI
box). For anything multi-tenant, implement the `Witness` interface (`run`, `inspect`) with a container, microVM or remote
runner and pass it to `createApp({ witness })`. What `LocalWitness` does do: allowlist of bare names, no shell, a scrubbed
environment (no Commander secrets), a private `HOME`, process-group kill on timeout, output caps that keep draining,
bounded concurrency (excess runs get `THROTTLED`), and path confinement. That confinement is check-then-open, so a
hostile writer racing it could still win.

A witness proves "this command passes against this workspace", not "the tests are meaningful": a worker with write
access can edit them. Pin what matters with `witness_file` and a `sha256`, or add the test paths to the policy's
`forbidden_paths` and require a `diff_policy` check on the worker's patch.

## MCP tools (worker-facing)

| Tool | Purpose |
|---|---|
| `commander_get_directive` | The one step you may run, a lease, the proof required, and a ledger of closed steps. |
| `commander_submit_proof` | Evidence for that step. Returns `PASSED`, `REJECTED` (with a corrective patch), or `QUARANTINED`. |
| `commander_request_clearance` | Ask before a risky action. Returns `CLEARED`, `DENIED` (with a redirect patch), or `STAGED`. For filesystem actions, declare `intent: "read"` when it is one: an omitted intent is judged as a mutation. |
| `commander_clearance_status` | Poll a staged clearance. |
| `commander_mission_status` | Active / paused / quarantined / completed / killed. Reveals nothing about the plan. |

Operators use REST (`/v1/operator/*`): open and inspect missions, decide approvals, skip or kill, mint and revoke
worker keys, read the overview and audit tail. Platform admins use `/v1/admin/*`: provision tenants, top up
credits, verify the full audit log.

## Configuration

See `.env.example` and `policy.example.json`. The policy covers the egress allowlist, payment hosts, strict-shell
mode, forbidden paths, patch size, loop thresholds, lease TTL, burn limit and credit prices.

## Mission format

```jsonc
{
  "title": "Release 4.2",
  "steps": [{
    "title": "Run test suite",
    "directive": "Run the suite. Report the real exit code and raw output.",
    "proof": [                                   // at least one mechanical verifier is required
      { "type": "exit_code" },                   // expected defaults to 0
      { "type": "regex", "target": "stdout", "pattern": "\\d+ passed" },
      { "type": "json_schema", "target": "artifact:out.json", "schema": { /* … */ } },
      { "type": "artifact_hash", "name": "x.txt", "sha256": "…" },
      { "type": "diff_policy", "artifact": "patch.diff" },
      { "type": "regex", "target": "stdout", "pattern": "…", "hidden": true }   // hidden from the worker
    ],
    "max_attempts": 3,
    "risk_tier": "routine",                       // routine | elevated (gate consulted) | critical (every mutation staged)
    "require_nonce": true                         // fresh nonce per attempt; must appear in the evidence
  }]
}
```

Verifiers on worker evidence: `exit_code`, `json_valid`, `json_schema`, `regex`, `artifact_present`, `artifact_hash`,
`nonce_present`, `diff_policy`. Independent verifiers (Commander observes): `witness_command`, `witness_file`.

`diff_policy` audits a text unified diff and needs at least one complete hunk with a changed line for every file it
names: a bare `diff --git` header, a cut-off hunk, and binary or rename-only entries fail. `artifact:` targets must be
valid artifact names (no `..`), or the mission is rejected at open.

## What this does and does not guarantee

Read this before relying on it.

1. **Commander governs what is routed through it.** An MCP server cannot see a worker's native tools, so a worker that
   skips `commander_request_clearance` and runs `rm -rf` directly is invisible to the Sentinel. The optional guard hook
   routes five Claude Code tools through it, on one client, on the developer's machine, and holds only as far as the
   hook's configuration is protected from the agent. "Zero client footprint" and "enforce native actions" are in
   tension; the hook is the opt-in that trades the first for the second. The airlock holds either way: a step cannot
   close without proof.
2. **Proof is only as strong as its verifiers, and worker-supplied evidence is still a claim.** Commander re-checks
   everything it can see (schemas, regexes, hashes, nonce freshness, replay), but a worker can fabricate an exit code
   and matching stdout. Nonces prove the evidence was produced *after* the directive, not that a command truly ran.
   Witness checks move the exit code and the files from "claimed" to "observed", at the price of running code (see the
   trust model above), and they are opt-in. "Cascading failure is impossible" is true of the *state machine* (step N+1
   cannot unlock before step N's verifiers pass) and false of *reality* if a verifier is weak. Write verifiers that
   check an outcome (a schema, a hash, a hidden check, a witnessed file), not an assertion.
3. **The Sentinel is a tripwire, not a sandbox.** It parses declared actions (quoting, wrappers, `bash -c`, command
   substitution, pipelines) and denies known-bad patterns. A clean verdict means "no known-bad pattern", not "safe".
   Use `strict_shell` (allowlist, stage everything else) for unvetted workers, and run workers in a real sandbox.
   Wrapper options are parsed for `sudo`, `doas`, `env`, `timeout`, `nice`, `ionice`, `stdbuf`, `exec`, `time` and
   `xargs`, so `sudo -p prompt rm -rf /` is judged as `rm`; an option or wrapper outside those tables is not understood.
   SQL that opens with a `WITH` clause is judged by the statement after it and by every CTE body.
4. **The reasoning gate can only tighten.** It is never consulted for what the rules already denied or staged, and its
   verdict is combined with `max(severity)`. It reads worker-controlled text, so it is treated as a second opinion,
   not a boundary. If it is unreachable or malformed, the action is staged for a human.
5. **"Hard kill" is lease revocation.** Commander cannot terminate a process on your machine. It revokes the worker's
   lease, so every further call is refused, and it tells the worker to stop. A worker that ignores that keeps running
   locally; it just can no longer advance a mission.
6. **The audit log is tamper-evident, not tamper-proof.** Each tenant has a hash chain; edits, deletions in the middle
   and reordering are detected, and startup refuses a broken chain. Truncating the *tail* is not detectable from the
   log alone. Periodically anchor the latest hash somewhere you control.
7. **Single process, JSON snapshot.** State lives in memory with an atomic JSON snapshot and an append-only log. That
   is fine for one instance and not for HA. The `Store` boundary is where Postgres goes.
8. **Notifications use one global webhook.** Per-tenant webhook URLs would be a server-side request forgery surface, so
   they are deliberately not built yet. Treat this as a single-operator deployment until that is designed.
9. **The voice rules are a presentation layer.** Commander never apologises in anything it *says*; the audit ledger
   records what *happened* in plain terms. A ledger that was voiced would stop being evidence.

## Layout

```
src/
  airlock.ts      state machine: missions, leases, proof, clearance, quarantine, decisions
  verifiers.ts    mechanical verifiers          inquisitor.ts   diff + secret audit
  sentinel.ts     action rules + loop detection  pruner.ts       evidence -> manifest
  gate.ts         reasoning gate (Gemini)        persona.ts      voice + redirect patches
  approvals.ts    staging, signed links, push    metrics.ts      HUD telemetry
  auth.ts         keys, roles, credits, burn     store.ts        state + hash-chained audit
  mcp.ts          the five worker tools          http.ts         router, operator/admin APIs, HUD, links
  witness.ts      independent runner + verifiers render.ts       plain-text replies shared by MCP and the guard
  app.ts          composition root               index.ts        process entry
  guard/          Claude Code PreToolUse hook: map.ts (tool call -> action), hook.ts (verdict -> exit code), claude-hook.ts (CLI)
  hud/            static dashboard (strict CSP, no innerHTML)
test/             unit + end-to-end suites       scripts/demo.ts  scripted end-to-end run
```

## Roadmap, in the order I would do it

Done since the first cut: independent witnessing (local runner) and the Claude Code `PreToolUse` guard. Their follow-ups:

1. **An isolated `Witness` runner** (container or microVM) and signed attestations, which is what makes witnessing safe
   for multi-tenant use. `LocalWitness` is deliberately limited to one trust domain.
2. **Verify the guard against real Claude Code sessions**, then widen it: more tools (`WebFetch`, subagents, other MCP
   servers), other clients (Cursor), and an installer that pins the settings through managed configuration.
3. **Postgres store** and multi-instance leases; external anchoring of the audit head.
4. **Per-tenant notification endpoints** with an SSRF-safe egress policy; mobile app instead of ntfy-style relay.
5. **Planner**: optional model-assisted decomposition of a goal into a ledger (operator-approved before release).
6. **TTS layer** that honours the voice profile Commander already attaches to operator cards.
