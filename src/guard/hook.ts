import { readFileSync } from 'node:fs';
import type { ClearanceResult } from '../airlock.js';
import { actionRedirectPatch } from '../persona.js';
import { renderClearance } from '../render.js';
import type { ActionRequest } from '../types.js';
import { GUARDED_TOOLS, mapToolCall, type HookInput } from './map.js';

/**
 * Client-side PreToolUse guard for Claude Code.
 *
 * Claude Code runs this before every Bash/Write/Edit call and passes the call as JSON on stdin. Exit code 0 lets the
 * call proceed (Claude Code's own permission flow still applies). Exit code 2 blocks it, and whatever is on stderr is
 * handed back to the model, so Commander's reason becomes the model's next instruction.
 *
 * The guard fails CLOSED: if Commander cannot be asked, the call is refused. `failOpen` exists for operators who
 * would rather lose enforcement than lose the session, and it applies only to "Commander is unreachable", never to a
 * rejected credential, a held mission, or a denial.
 */

export interface GuardVerdict {
  verdict: 'CLEARED' | 'DENIED' | 'STAGED' | 'REFUSED';
  /** What the model is told when the call is blocked. */
  text: string;
}

export type Evaluate = (action: ActionRequest, tool: string) => Promise<GuardVerdict>;

/** Commander could not be reached or failed server-side. The only condition fail-open may excuse. */
export class GuardUnavailable extends Error {}

export interface HookOutcome {
  exitCode: 0 | 2;
  stderr: string;
}

const ALLOW: HookOutcome = { exitCode: 0, stderr: '' };
const block = (text: string): HookOutcome => ({ exitCode: 2, stderr: `${text}\n` });

export async function runHook(raw: string, evaluate: Evaluate, opts: { failOpen?: boolean } = {}): Promise<HookOutcome> {
  let input: HookInput;
  try {
    const parsed: unknown = JSON.parse(raw);
    // Claude Code always sends an object. Anything else cannot be a tool call, so it is not waved through as "unguarded".
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
    input = parsed as HookInput;
  } catch {
    return block('COMMANDER GUARD // REFUSED\nHook input was not a JSON object. Refusing to proceed.');
  }

  const mapped = mapToolCall(input);
  if (!mapped) return ALLOW; // not a guarded tool

  if (mapped.blocked?.length || !mapped.action) {
    const reasons = (mapped.blocked ?? ['Call could not be understood.']).map((b) => ` - ${b}`).join('\n');
    return block(`COMMANDER GUARD // DENIED\nAction refused before it ran:\n${reasons}`);
  }

  try {
    const verdict = await evaluate(mapped.action, mapped.tool);
    return verdict.verdict === 'CLEARED' ? ALLOW : block(verdict.text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof GuardUnavailable && opts.failOpen) {
      return { exitCode: 0, stderr: `[commander-guard] Commander unavailable (${message}); allowing because COMMANDER_GUARD_FAIL_OPEN=1.\n` };
    }
    const hint = err instanceof GuardUnavailable ? ' Execution blocked. Set COMMANDER_GUARD_FAIL_OPEN=1 to proceed without enforcement when Commander is unreachable.' : ' Execution blocked.';
    return block(`COMMANDER GUARD // REFUSED\n${message}.${hint}`);
  }
}

// ---- evaluators -------------------------------------------------------------------------------

export interface RemoteConfig {
  url: string;
  key: string;
  mission: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/** Asks the Commander server. The rules, the mission state and the operator approvals all live there. */
export function remoteEvaluate(cfg: RemoteConfig): Evaluate {
  return async (action, tool) => {
    let res: Response;
    try {
      res = await (cfg.fetchImpl ?? fetch)(`${cfg.url.replace(/\/+$/, '')}/v1/guard/clearance`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.key}` },
        body: JSON.stringify({ mission_id: cfg.mission, tool, action }),
        signal: AbortSignal.timeout(cfg.timeoutMs ?? 10_000),
      });
    } catch (err) {
      throw new GuardUnavailable(`Commander could not be reached (${err instanceof Error ? err.message : String(err)})`);
    }
    if (res.status >= 500) throw new GuardUnavailable(`Commander failed with HTTP ${res.status}`);

    let body: Record<string, unknown> | undefined;
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      body = undefined;
    }
    if (res.status !== 200 || !body) {
      const code = typeof body?.error === 'string' ? body.error : String(res.status);
      const message = typeof body?.message === 'string' ? body.message : 'Request refused.';
      return { verdict: 'REFUSED', text: `COMMANDER // REFUSED [${code}]\n${message}` };
    }

    const r = body as unknown as ClearanceResult;
    let text = renderClearance(r);
    if (r.verdict === 'STAGED') {
      text += `\nRetry the same action once the operator has authorized it. The authorization is single-use. Clearance id: ${r.clearance_id}.`;
    }
    return { verdict: r.verdict, text };
  };
}

/**
 * The same Sentinel rules, run on this machine with no server. Useful offline and for trying the guard out.
 * Honest limits: no mission state, no loop detection across calls (each hook run is a fresh process), and nothing
 * can be staged for approval, so a rule that would stage is treated as a block.
 */
export async function localEvaluate(policyFile?: string): Promise<Evaluate> {
  const [{ Sentinel }, { PolicySchema, defaultPolicy }] = await Promise.all([import('../sentinel.js'), import('../config.js')]);
  const policy = policyFile ? PolicySchema.parse(JSON.parse(readFileSync(policyFile, 'utf8'))) : defaultPolicy();
  const sentinel = new Sentinel(policy, Date.now);

  return async (action) => {
    const decision = sentinel.scan(action);
    if (decision.verdict === 'allow') return { verdict: 'CLEARED', text: '' };
    const findings = decision.findings.map((f) => ({ rule: f.rule, reason: f.reason }));
    if (decision.verdict === 'deny') {
      return {
        verdict: 'DENIED',
        text: ['COMMANDER GUARD // DENIED', 'Action denied. Tripwire engaged. Do not retry this action.', '', actionRedirectPatch(findings)].join('\n'),
      };
    }
    return {
      verdict: 'STAGED',
      text: [
        'COMMANDER GUARD // STAGED (local rules)',
        'Action requires operator authorization. Local mode cannot request it. Configure COMMANDER_URL to stage approvals.',
        ...findings.map((f) => ` - [${f.rule}] ${f.reason}`),
      ].join('\n'),
    };
  };
}

// ---- configuration helper ---------------------------------------------------------------------

/** The Claude Code settings fragment that installs the guard. `COMMANDER_KEY` is deliberately never written to a file. */
export function settingsSnippet(hookPath: string, opts: { url?: string; mission?: string } = {}) {
  return {
    ...(opts.url || opts.mission
      ? { env: { COMMANDER_URL: opts.url ?? 'https://commander.example.com', COMMANDER_MISSION: opts.mission ?? 'msn_REPLACE_WITH_YOUR_MISSION_ID' } }
      : {}),
    hooks: {
      PreToolUse: [
        {
          matcher: GUARDED_TOOLS.join('|'),
          hooks: [{ type: 'command', command: `node ${JSON.stringify(hookPath)}`, timeout: 15 }],
        },
      ],
    },
  };
}
