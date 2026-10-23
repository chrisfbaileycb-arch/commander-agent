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
npm test            # unit suites plus an end-to-end run through the official MCP SDK client
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

## MCP tools (worker-facing)

| Tool | Purpose |
|---|---|
| `commander_get_directive` | The one step you may run, a lease, the proof required, and a ledger of closed steps. |
| `commander_submit_proof` | Evidence for that step. Returns `PASSED`, `REJECTED` (with a corrective patch), or `QUARANTINED`. |
| `commander_request_clearance` | Ask before a risky action. Returns `CLEARED`, `DENIED` (with a redirect patch), or `STAGED`. |
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

Verifiers: `exit_code`, `json_valid`, `json_schema`, `regex`, `artifact_present`, `artifact_hash`, `nonce_present`,
`diff_policy`.

## What this does and does not guarantee

Read this before relying on it.

1. **Commander governs what is routed through it.** An MCP server cannot see a worker's native tools. A worker that
   skips `commander_request_clearance` and runs `rm -rf` directly is invisible to the Sentinel. The airlock still
   holds (a step cannot close without proof), but enforcing the Sentinel on native tool calls needs a thin
   client-side hook (for example a Claude Code `PreToolUse` hook) that calls the same clearance logic. That reintroduces
   a small client footprint; "zero client footprint" and "enforce native actions" are in tension, and this version
   chooses the first.
2. **Proof is only as strong as its verifiers, and the evidence is still worker-supplied.** Commander re-checks
   everything it can see (schemas, regexes, hashes, nonce freshness, replay), but a worker can fabricate an exit code
   and matching stdout. Nonces prove the evidence was produced *after* the directive, not that a command truly ran.
   "Cascading failure is impossible" is true of the *state machine* (step N+1 cannot unlock before step N's verifiers
   pass) and false of *reality* if a verifier is weak. Write verifiers that check an outcome (a schema, a hash, a
   hidden check), not an assertion. Independent witnessing (Commander running the check itself, or a signed attestation
   from a runner) is the real fix and is on the roadmap.
3. **The Sentinel is a tripwire, not a sandbox.** It parses declared actions (quoting, wrappers, `bash -c`, command
   substitution, pipelines) and denies known-bad patterns. A clean verdict means "no known-bad pattern", not "safe".
   Use `strict_shell` (allowlist, stage everything else) for unvetted workers, and run workers in a real sandbox.
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
  app.ts          composition root               index.ts        process entry
  hud/            static dashboard (strict CSP, no innerHTML)
test/             unit + end-to-end suites       scripts/demo.ts  scripted end-to-end run
```

## Roadmap, in the order I would do it

1. **Independent witnessing**: let Commander (or a signed runner) execute verifiers itself instead of trusting
   submitted output. This is the largest remaining gap between "mechanical" and "verified".
2. **Native-action hook** for Claude Code/Cursor so the Sentinel covers tools Commander doesn't mediate.
3. **Postgres store** and multi-instance leases; external anchoring of the audit head.
4. **Per-tenant notification endpoints** with an SSRF-safe egress policy; mobile app instead of ntfy-style relay.
5. **Planner**: optional model-assisted decomposition of a goal into a ledger (operator-approved before release).
6. **TTS layer** that honours the voice profile Commander already attaches to operator cards.
