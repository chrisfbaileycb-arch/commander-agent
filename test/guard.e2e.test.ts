import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createApp, type App } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { settingsSnippet } from '../src/guard/hook.js';
import { createHttpServer } from '../src/http.js';
import { CaptureNotifier, oneStep } from './helpers.js';

/**
 * The real hook script, run the way Claude Code runs it: a fresh process per tool call, JSON on stdin, the verdict in
 * the exit code and on stderr. The server is the real HTTP server over the real airlock.
 */

vi.setConfig({ testTimeout: 40_000 });

// Fake credentials are assembled at runtime so that no literal in the repository resembles a real one to a secret scanner.
const AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const NOT_A_KEY = ['cmd_live', '_not-a-real-key-0000'].join('');

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const HOOK = path.join(ROOT, 'src/guard/claude-hook.ts');
const WORK = '/work/app';

interface Ran {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Asynchronous on purpose: the Commander server lives in this process, so blocking on the child would deadlock it. */
function runGuard(input: unknown, env: Record<string, string> = {}, args: string[] = []): Promise<Ran> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', HOOK, ...args], {
      cwd: ROOT,
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => (stdout += c));
    child.stderr.on('data', (c: Buffer) => (stderr += c));
    child.stdin.on('error', () => undefined); // --print-settings exits without reading stdin
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`hook did not exit\n${stderr}`));
    }, 30_000);
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(typeof input === 'string' ? input : input === undefined ? '' : JSON.stringify(input));
  });
}

const envelope = { session_id: 's1', transcript_path: '/tmp/t.jsonl', cwd: WORK, permission_mode: 'default', hook_event_name: 'PreToolUse', tool_use_id: 'toolu_1' };
const bash = (command: string) => ({ ...envelope, tool_name: 'Bash', tool_input: { command, description: 'e2e' } });
const file = (tool: string, file_path: string, content = 'ok') => ({
  ...envelope,
  tool_name: tool,
  tool_input:
    tool === 'NotebookEdit'
      ? { notebook_path: file_path, new_source: content }
      : tool === 'Edit'
        ? { file_path, old_string: 'a', new_string: content }
        : tool === 'MultiEdit'
          ? { file_path, edits: [{ old_string: 'a', new_string: content }] }
          : { file_path, content },
});
const read = { ...envelope, tool_name: 'Read', tool_input: { file_path: '/etc/hosts' } };

let app: App;
let server: Server;
let base = '';
let tenantId = '';
let operatorKey = '';
const scratch: string[] = [];

beforeAll(async () => {
  app = createApp({ config: { ...loadConfig({}), linkSecret: 'e2e-guard-link-secret', publicUrl: 'http://commander.test' }, notifier: new CaptureNotifier() });
  server = createHttpServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const t = app.auth.createTenant('guard-e2e', 1_000_000);
  tenantId = t.tenant.id;
  operatorKey = t.operatorKey;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  for (const d of scratch) rmSync(d, { recursive: true, force: true });
});

const operator = () => app.auth.authenticate(`Bearer ${operatorKey}`);

/** A mission whose worker has pulled its directive, with the environment a developer would give the hook. */
function newMission(def: unknown = oneStep(), opts: { pull?: boolean } = {}) {
  const { key } = app.auth.issueKey(tenantId, 'worker');
  const worker = app.auth.authenticate(`Bearer ${key}`);
  const m = app.airlock.openMission(operator(), def);
  if (opts.pull !== false) app.airlock.getDirective(worker, m.id);
  const env = { COMMANDER_URL: base, COMMANDER_KEY: key, COMMANDER_MISSION: m.id };
  const clearances = () => app.store.tenantAudit(tenantId, 5000).filter((r) => r.type.startsWith('clearance.') && r.data.missionId === m.id);
  const pending = () => app.approvals.list(tenantId, 'pending').filter((a) => a.missionId === m.id);
  const status = () => app.airlock.getMission(operator(), m.id).status;
  return { m, key, worker, env, clearances, pending, status };
}

async function unusedPort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

/** A stand-in Commander that misbehaves in a chosen way. */
async function fakeServer(handler: Parameters<typeof createServer>[1]): Promise<{ url: string; close: () => Promise<void> }> {
  const s = createServer(handler);
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${(s.address() as AddressInfo).port}`,
    close: () => {
      s.closeAllConnections();
      return new Promise<void>((resolve) => s.close(() => resolve()));
    },
  };
}

// =================================================================================================
describe('remote mode: enforcing a live Commander', () => {
  it('lets ordinary work through silently', async () => {
    const { env } = newMission();
    const r = await runGuard(bash('ls -la'), env);
    expect(r).toEqual({ code: 0, stdout: '', stderr: '' });
  });

  it("blocks a destructive command with exit 2 and gives the model Commander's redirect", async () => {
    const { env, clearances } = newMission();
    const r = await runGuard(bash('rm -rf /'), env);
    expect(r.code).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('COMMANDER // CLEARANCE DENIED');
    expect(r.stderr).toContain('[shell.rm-destructive]');
    expect(r.stderr).toContain('REDIRECT PATCH');
    expect(clearances().map((c) => c.type)).toEqual(['clearance.denied']);
    expect(clearances()[0]!.data).toMatchObject({ via: 'guard', tool: 'Bash' });
  });

  it("stages a production change, holds the mission, and honours the operator's authorization exactly once", async () => {
    const { env, pending, status } = newMission();
    const deploy = bash('kubectl apply -f prod.yaml');

    const staged = await runGuard(deploy, env);
    expect(staged.code).toBe(2);
    expect(staged.stderr).toContain('CLEARANCE STAGED');
    expect(staged.stderr).toMatch(/single-use/);
    expect(status()).toBe('paused');
    expect(pending()).toHaveLength(1);
    expect(pending()[0]!.incident).toMatch(/^NATIVE Bash: kubectl apply/);

    // While the operator has not decided, every guarded call is held, including harmless ones.
    const held = await runGuard(bash('ls'), env);
    expect(held.code).toBe(2);
    expect(held.stderr).toContain('[HOLD]');

    app.airlock.decideApproval(tenantId, pending()[0]!.id, 'authorize', undefined, 'operator');
    expect(await runGuard(deploy, env)).toEqual({ code: 0, stdout: '', stderr: '' });

    // Spent. The same command is judged afresh.
    const again = await runGuard(deploy, env);
    expect(again.code).toBe(2);
    expect(again.stderr).toContain('CLEARANCE STAGED');
  });

  it('judges file tools by path, relative to the working directory the hook is given', async () => {
    const { env } = newMission();
    expect((await runGuard(file('Write', `${WORK}/src/a.ts`), env)).code).toBe(0);
    expect((await runGuard(file('Edit', `${WORK}/src/a.ts`), env)).code).toBe(0);
    expect((await runGuard(file('MultiEdit', `${WORK}/src/a.ts`), env)).code).toBe(0);
    expect((await runGuard(file('NotebookEdit', `${WORK}/nb/a.ipynb`), env)).code).toBe(0);

    const dotenv = await runGuard(file('Write', `${WORK}/config/.env.production`), env);
    expect(dotenv.code).toBe(2);
    expect(dotenv.stderr).toContain('CLEARANCE DENIED');
    expect((await runGuard(file('Write', '/etc/cron.d/job'), env)).code).toBe(2);
  });

  it('will not let the agent rewrite the guard that is guarding it', async () => {
    const { env } = newMission();
    for (const tool of ['Write', 'Edit', 'MultiEdit']) {
      const r = await runGuard(file(tool, `${WORK}/.claude/settings.json`), env);
      expect(r.code, tool).toBe(2);
      expect(r.stderr, tool).toContain('fs.agent-config');
    }
    const viaShell = await runGuard(bash("sed -i '/hooks/d' .claude/settings.json"), env);
    expect(viaShell.code).toBe(2);
    expect(viaShell.stderr).toContain('CLEARANCE STAGED');
  });

  it('refuses to write a credential into a file, without sending the content or the secret anywhere', async () => {
    const { env, clearances } = newMission();
    const r = await runGuard(file('Write', `${WORK}/notes.txt`, `aws_key = ${AWS_KEY}`), env);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('aws-access-key');
    expect(r.stderr).not.toContain(AWS_KEY);
    expect(clearances()).toHaveLength(0); // never asked the server
    expect(JSON.stringify(app.store.tenantAudit(tenantId, 5000))).not.toContain(AWS_KEY);
  });

  it('ignores tools it does not guard, without contacting the server', async () => {
    const dead = { COMMANDER_URL: `http://127.0.0.1:${await unusedPort()}`, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x' };
    expect(await runGuard(read, dead)).toEqual({ code: 0, stdout: '', stderr: '' });
  });

  describe('refusals from the server', () => {
    it('a rejected key blocks, even when the operator has chosen to fail open', async () => {
      const { env } = newMission();
      const modes: Record<string, string>[] = [{}, { COMMANDER_GUARD_FAIL_OPEN: '1' }];
      for (const failOpen of modes) {
        const r = await runGuard(bash('ls'), { ...env, COMMANDER_KEY: NOT_A_KEY, ...failOpen });
        expect(r.code).toBe(2);
        expect(r.stderr).toContain('[UNAUTHENTICATED]');
      }
    });

    it('an operator key is not a worker key', async () => {
      const { env } = newMission();
      const r = await runGuard(bash('ls'), { ...env, COMMANDER_KEY: operatorKey });
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('[FORBIDDEN]');
    });

    it('an unknown mission blocks', async () => {
      const { env } = newMission();
      const r = await runGuard(bash('ls'), { ...env, COMMANDER_MISSION: 'msn_does_not_exist' });
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('[NOT_FOUND]');
    });

    it('a mission whose directive has not been pulled has nothing to judge against, so it blocks', async () => {
      const { env } = newMission(oneStep(), { pull: false });
      const r = await runGuard(bash('ls'), env);
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('[CONFLICT]');
      expect(r.stderr).toContain('Pull one first');
    });

    it('a killed mission blocks everything', async () => {
      const { env, m } = newMission();
      app.airlock.intervene(operator(), m.id, { action: 'kill', reason: 'e2e' });
      const r = await runGuard(bash('ls'), { ...env, COMMANDER_GUARD_FAIL_OPEN: '1' });
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('[HOLD]');
    });
  });
});

// =================================================================================================
describe('when Commander cannot be reached', () => {
  it('fails closed by default, and says how to opt out', async () => {
    const env = { COMMANDER_URL: `http://127.0.0.1:${await unusedPort()}`, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x' };
    const r = await runGuard(bash('ls'), env);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('could not be reached');
    expect(r.stderr).toContain('COMMANDER_GUARD_FAIL_OPEN=1');
  });

  it('lets the call through only when the operator explicitly chose to', async () => {
    const env = { COMMANDER_URL: `http://127.0.0.1:${await unusedPort()}`, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x', COMMANDER_GUARD_FAIL_OPEN: '1' };
    const r = await runGuard(bash('ls'), env);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain('allowing because COMMANDER_GUARD_FAIL_OPEN=1');
  });

  it('still refuses credentials in file content when failing open: that decision never needed the server', async () => {
    const env = { COMMANDER_URL: `http://127.0.0.1:${await unusedPort()}`, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x', COMMANDER_GUARD_FAIL_OPEN: '1' };
    expect((await runGuard(file('Write', `${WORK}/n.txt`, AWS_KEY), env)).code).toBe(2);
  });

  it('gives up on a server that accepts the connection and never answers', async () => {
    const hang = await fakeServer(() => undefined);
    try {
      const env = { COMMANDER_URL: hang.url, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x', COMMANDER_GUARD_TIMEOUT_MS: '400' };
      const started = Date.now();
      const r = await runGuard(bash('ls'), env);
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('could not be reached');
      expect(Date.now() - started).toBeLessThan(15_000);
      expect((await runGuard(bash('ls'), { ...env, COMMANDER_GUARD_FAIL_OPEN: '1' })).code).toBe(0);
    } finally {
      await hang.close();
    }
  });

  it('treats a server fault as unreachable, not as a verdict', async () => {
    const broken = await fakeServer((_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' }).end('{"error":"FAULT"}');
    });
    try {
      const env = { COMMANDER_URL: broken.url, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x' };
      const r = await runGuard(bash('ls'), env);
      expect(r.code).toBe(2);
      expect(r.stderr).toContain('HTTP 500');
      expect((await runGuard(bash('ls'), { ...env, COMMANDER_GUARD_FAIL_OPEN: '1' })).code).toBe(0);
    } finally {
      await broken.close();
    }
  });

  it("never reads a clearance out of a response that is not Commander's", async () => {
    const liar = await fakeServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' }).end('<html>captive portal</html>');
    });
    try {
      const r = await runGuard(bash('ls'), { COMMANDER_URL: liar.url, COMMANDER_KEY: 'k'.repeat(24), COMMANDER_MISSION: 'msn_x' });
      expect(r.code).toBe(2);
    } finally {
      await liar.close();
    }
  });
});

// =================================================================================================
describe('configuration mistakes are refusals, never silent passes', () => {
  it('refuses a guarded tool when nothing is configured, but leaves other tools alone', async () => {
    const r = await runGuard(bash('ls'));
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('Guard not configured');
    expect((await runGuard(read)).code).toBe(0);
  });

  it.each([
    [{ COMMANDER_URL: 'http://127.0.0.1:1' }],
    [{ COMMANDER_URL: 'http://127.0.0.1:1', COMMANDER_KEY: 'k'.repeat(24) }],
    [{ COMMANDER_URL: 'http://127.0.0.1:1', COMMANDER_MISSION: 'msn_x' }],
  ])('refuses a half-configured remote guard: %j', async (env) => {
    const r = await runGuard(bash('ls'), { ...env, COMMANDER_GUARD_FAIL_OPEN: '1' });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('Guard misconfigured');
  });

  it.each([[''], ['{"tool_name":'], ['null'], ['["Bash"]']])('refuses hook input that is not a JSON object: %j', async (raw) => {
    const { env } = newMission();
    const r = await runGuard(raw, { ...env, COMMANDER_GUARD_FAIL_OPEN: '1' });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('COMMANDER GUARD // REFUSED');
  });
});

describe('local mode: the same rules with no server', () => {
  const local = { COMMANDER_GUARD_LOCAL: '1' };

  it('clears, denies and refuses to stage', async () => {
    expect((await runGuard(bash('ls'), local)).code).toBe(0);
    expect((await runGuard(file('Write', `${WORK}/src/a.ts`), local)).code).toBe(0);

    const rm = await runGuard(bash('rm -rf /'), local);
    expect(rm).toMatchObject({ code: 2, stdout: '' });
    expect(rm.stderr).toContain('COMMANDER GUARD // DENIED');
    expect(rm.stderr).toContain('[shell.rm-destructive]');

    const deploy = await runGuard(bash('kubectl apply -f prod.yaml'), local);
    expect(deploy.code).toBe(2);
    expect(deploy.stderr).toContain('local rules');
    expect((await runGuard(file('Write', `${WORK}/.env`), local)).code).toBe(2);
    expect((await runGuard(file('Write', `${WORK}/.claude/settings.json`), local)).code).toBe(2);
  });

  it('applies a policy file, and refuses to run on one it cannot use', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'guard-e2e-'));
    scratch.push(dir);
    const strict = path.join(dir, 'strict.json');
    writeFileSync(strict, JSON.stringify({ strict_shell: true, shell_allowlist: ['ls'] }));
    expect((await runGuard(bash('ls'), { ...local, COMMANDER_GUARD_POLICY: strict })).code).toBe(0);
    expect((await runGuard(bash('git status'), { ...local, COMMANDER_GUARD_POLICY: strict })).code).toBe(2);

    const missing = await runGuard(bash('ls'), { ...local, COMMANDER_GUARD_POLICY: path.join(dir, 'missing.json'), COMMANDER_GUARD_FAIL_OPEN: '1' });
    expect(missing.code).toBe(2);
    expect(missing.stderr).toContain('Execution blocked');

    const invalid = path.join(dir, 'invalid.json');
    writeFileSync(invalid, '{ not json');
    expect((await runGuard(bash('ls'), { ...local, COMMANDER_GUARD_POLICY: invalid })).code).toBe(2);
  });

  it('prefers the server when both are configured', async () => {
    const { env } = newMission();
    // A command only the live mission's state can judge: locally this is just "deploy", on the server it pauses the mission.
    const r = await runGuard(bash('kubectl apply -f prod.yaml'), { ...env, ...local });
    expect(r.stderr).toContain('CLEARANCE STAGED');
    expect(r.stderr).not.toContain('local rules');
  });
});

// =================================================================================================
describe('commander-guard --print-settings', () => {
  it('prints the Claude Code settings fragment for this install', async () => {
    const r = await runGuard(undefined, {}, ['--print-settings', '--url', 'https://commander.example.com', '--mission', 'msn_123']);
    expect(r.code).toBe(0);
    expect(r.stderr).toBe('');
    expect(JSON.parse(r.stdout)).toEqual(settingsSnippet(HOOK, { url: 'https://commander.example.com', mission: 'msn_123' }));
  });

  it('omits the env block unless asked, and never prints a key it happens to be holding', async () => {
    const held = ['cmd_live', '_do-not-print-me-0000'].join('');
    const r = await runGuard(undefined, { COMMANDER_KEY: held }, ['--print-settings']);
    expect(r.code).toBe(0);
    const settings = JSON.parse(r.stdout);
    expect(settings.env).toBeUndefined();
    expect(settings.hooks.PreToolUse[0].matcher).toBe('Bash|Write|Edit|MultiEdit|NotebookEdit');
    expect(r.stdout).not.toContain('do-not-print-me');
  });
});

// =================================================================================================
describe('POST /v1/guard/clearance', () => {
  const post = (key: string | undefined, body: unknown, method = 'POST') =>
    fetch(`${base}/v1/guard/clearance`, {
      method,
      headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: method === 'GET' ? undefined : JSON.stringify(body),
    });

  it('answers a valid request with the verdict', async () => {
    const { key, m } = newMission();
    const res = await post(key, { mission_id: m.id, tool: 'Bash', action: { kind: 'shell', payload: 'ls' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ verdict: 'CLEARED', findings: [] });
  });

  it('requires a credential, and a worker one', async () => {
    const { m } = newMission();
    const body = { mission_id: m.id, action: { kind: 'shell', payload: 'ls' } };
    expect((await post(undefined, body)).status).toBe(401);
    expect((await post(operatorKey, body)).status).toBe(403);
  });

  it('is POST only', async () => {
    const { key } = newMission();
    expect((await post(key, {}, 'GET')).status).toBe(404);
  });

  it.each([
    [{ action: { kind: 'shell', payload: 'ls' } }],
    [{ mission_id: 'm', action: { kind: 'shell' } }],
    [{ mission_id: 'm', action: { kind: 'shell', payload: 'x'.repeat(16_385) } }],
    [{ mission_id: 'm', tool: 't'.repeat(41), action: { kind: 'shell', payload: 'ls' } }],
    [{ mission_id: 'm' }],
  ])('rejects a malformed body with 400: %j', async (body) => {
    const { key } = newMission();
    expect((await post(key, body)).status).toBe(400);
  });
});
