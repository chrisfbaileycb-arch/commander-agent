#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { localEvaluate, remoteEvaluate, runHook, settingsSnippet, type Evaluate } from './hook.js';

/**
 * Entry point for the Claude Code PreToolUse hook (installed as the `commander-guard` bin).
 *
 *   remote mode (enforces your Commander server's rules, mission state and approvals):
 *     COMMANDER_URL, COMMANDER_KEY (a worker key), COMMANDER_MISSION
 *   local mode (this machine's Sentinel rules only; no staging, no loop detection):
 *     COMMANDER_GUARD_LOCAL=1  [COMMANDER_GUARD_POLICY=/path/policy.json]
 *   optional:
 *     COMMANDER_GUARD_FAIL_OPEN=1   allow when Commander is unreachable (default: block)
 *     COMMANDER_GUARD_TIMEOUT_MS    request timeout, default 10000
 *
 *   commander-guard --print-settings [--url URL] [--mission ID]   prints the Claude Code settings fragment
 */

const valueOf = (args: string[], flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

/** A misconfigured guard must still refuse guarded tools, so configuration errors surface when it is first asked. */
async function buildEvaluate(env: NodeJS.ProcessEnv): Promise<Evaluate> {
  const refuse = (why: string): Evaluate => async () => {
    throw new Error(why);
  };
  if (env.COMMANDER_URL) {
    if (!env.COMMANDER_KEY || !env.COMMANDER_MISSION) {
      return refuse('Guard misconfigured: COMMANDER_URL is set but COMMANDER_KEY or COMMANDER_MISSION is missing');
    }
    return remoteEvaluate({
      url: env.COMMANDER_URL,
      key: env.COMMANDER_KEY,
      mission: env.COMMANDER_MISSION,
      timeoutMs: Number(env.COMMANDER_GUARD_TIMEOUT_MS) || undefined,
    });
  }
  if (env.COMMANDER_GUARD_LOCAL === '1') return localEvaluate(env.COMMANDER_GUARD_POLICY || undefined);
  return refuse('Guard not configured: set COMMANDER_URL, COMMANDER_KEY and COMMANDER_MISSION, or COMMANDER_GUARD_LOCAL=1 for local rules only');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--print-settings')) {
    const hookPath = fileURLToPath(import.meta.url);
    process.stdout.write(`${JSON.stringify(settingsSnippet(hookPath, { url: valueOf(args, '--url'), mission: valueOf(args, '--mission') }), null, 2)}\n`);
    return;
  }

  const outcome = await runHook(await readStdin(), await buildEvaluate(process.env), { failOpen: process.env.COMMANDER_GUARD_FAIL_OPEN === '1' });
  // Exit only after stderr has flushed, or the model would lose the reason it is being given.
  if (outcome.stderr) process.stderr.write(outcome.stderr, () => process.exit(outcome.exitCode));
  else process.exit(outcome.exitCode);
}

main().then(
  () => {
    if (process.argv.includes('--print-settings')) process.exit(0);
  },
  (err: unknown) => {
    // Anything unexpected is a refusal, never a silent pass.
    process.stderr.write(`COMMANDER GUARD // REFUSED\n${err instanceof Error ? err.message : String(err)}. Execution blocked.\n`, () => process.exit(2));
  },
);
