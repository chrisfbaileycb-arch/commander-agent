import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { GuardUnavailable, localEvaluate, remoteEvaluate, runHook, settingsSnippet, type Evaluate, type GuardVerdict } from '../src/guard/hook.js';
import { GUARDED_TOOLS, mapToolCall } from '../src/guard/map.js';

// Fake credentials are assembled at runtime so that no literal in the repository resembles a real one to a secret scanner.
const AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const PEM_HEADER = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join('');

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// =================================================================================================
describe('mapToolCall: translating a Claude Code tool call into a Sentinel action', () => {
  it('vets the tools that change the machine, and nothing else', () => {
    expect([...GUARDED_TOOLS]).toEqual(['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
    for (const tool of ['Read', 'Grep', 'Glob', 'WebFetch', 'Task', 'mcp__github__create_issue', 'bash', '']) {
      expect(mapToolCall({ tool_name: tool, tool_input: { command: 'rm -rf /' } }), tool).toBeNull();
    }
    expect(mapToolCall({})).toBeNull();
  });

  describe('Bash', () => {
    it('hands the command to the shell rules exactly as written', () => {
      const cmd = 'cd app && npm test | tee out.txt';
      expect(mapToolCall({ tool_name: 'Bash', tool_input: { command: cmd } })).toEqual({ tool: 'Bash', action: { kind: 'shell', payload: cmd } });
    });

    it.each([[{}], [{ command: '' }], [{ command: '   \n' }], [{ command: 42 }], [{ cmd: 'ls' }]])('refuses a call with no usable command: %j', (ti) => {
      const m = mapToolCall({ tool_name: 'Bash', tool_input: ti })!;
      expect(m.action).toBeUndefined();
      expect(m.blocked?.[0]).toMatch(/without a command/);
    });

    it('refuses what it cannot vet instead of truncating it, and accepts the limit exactly', () => {
      const atLimit = mapToolCall({ tool_name: 'Bash', tool_input: { command: 'x'.repeat(16_384) } })!;
      expect(atLimit.action).toBeDefined();
      const over = mapToolCall({ tool_name: 'Bash', tool_input: { command: 'x'.repeat(16_385) } })!;
      expect(over.action).toBeUndefined();
      expect(over.blocked?.[0]).toMatch(/16385 characters.*16384/);
    });
  });

  describe('file tools', () => {
    it('maps writes to filesystem actions with write intent', () => {
      for (const [tool, ti] of [
        ['Write', { file_path: 'src/a.ts', content: 'x' }],
        ['Edit', { file_path: 'src/a.ts', old_string: 'a', new_string: 'b' }],
        ['MultiEdit', { file_path: 'src/a.ts', edits: [{ old_string: 'a', new_string: 'b' }] }],
        ['NotebookEdit', { notebook_path: 'src/a.ipynb', new_source: 'x' }],
      ] as const) {
        const m = mapToolCall({ tool_name: tool, tool_input: ti })!;
        expect(m.action, tool).toMatchObject({ kind: 'fs', intent: 'write' });
        expect(m.blocked, tool).toBeUndefined();
      }
      expect(mapToolCall({ tool_name: 'NotebookEdit', tool_input: { notebook_path: 'n/x.ipynb' } })!.action!.payload).toBe('n/x.ipynb');
    });

    it('makes absolute paths inside the working directory relative, so ".env" and ".git/**" rules apply as written', () => {
      const m = mapToolCall({ tool_name: 'Write', cwd: '/work/app', tool_input: { file_path: '/work/app/config/.env.production', content: '' } })!;
      expect(m.action!.payload).toBe('config/.env.production');
    });

    it('leaves paths outside the working directory absolute, and never rewrites a climb', () => {
      const outside = mapToolCall({ tool_name: 'Write', cwd: '/work/app', tool_input: { file_path: '/etc/hosts', content: '' } })!;
      expect(outside.action!.payload).toBe('/etc/hosts');
      const sibling = mapToolCall({ tool_name: 'Write', cwd: '/work/app', tool_input: { file_path: '/work/app-secrets/.env', content: '' } })!;
      expect(sibling.action!.payload).toBe('/work/app-secrets/.env');
      const climb = mapToolCall({ tool_name: 'Write', cwd: '/work/app', tool_input: { file_path: '/work/app/../x', content: '' } })!;
      expect(climb.action!.payload).toBe('/work/app/../x');
    });

    it('ignores a relative cwd and keeps relative paths as given', () => {
      expect(mapToolCall({ tool_name: 'Write', cwd: 'rel', tool_input: { file_path: '/rel/a', content: '' } })!.action!.payload).toBe('/rel/a');
      expect(mapToolCall({ tool_name: 'Edit', cwd: '/w', tool_input: { file_path: 'src/a.ts', new_string: '' } })!.action!.payload).toBe('src/a.ts');
    });

    it.each([[{}], [{ file_path: '' }], [{ file_path: '  ' }], [{ file_path: 7 }], [{ path: 'x' }]])('refuses a call with no usable path: %j', (ti) => {
      const m = mapToolCall({ tool_name: 'Write', tool_input: ti })!;
      expect(m.action).toBeUndefined();
      expect(m.blocked?.[0]).toMatch(/without a file path/);
    });

    it('refuses an unreadable tool_input rather than guessing', () => {
      for (const ti of [undefined, null, 'rm -rf /', 7, []]) {
        const m = mapToolCall({ tool_name: 'Write', tool_input: ti })!;
        expect(m.action, JSON.stringify(ti)).toBeUndefined();
        expect(m.blocked?.length, JSON.stringify(ti)).toBe(1);
      }
    });
  });

  describe('credentials in the content about to be written', () => {
    const cases: [string, Record<string, unknown>][] = [
      ['Write', { file_path: 'a.txt', content: `key=${AWS_KEY}` }],
      ['Edit', { file_path: 'a.txt', old_string: 'x', new_string: `key=${AWS_KEY}` }],
      ['MultiEdit', { file_path: 'a.txt', edits: [{ old_string: 'a', new_string: 'fine' }, { old_string: 'b', new_string: `k=${AWS_KEY}` }] }],
      ['NotebookEdit', { notebook_path: 'a.ipynb', new_source: `K="${AWS_KEY}"` }],
    ];
    it.each(cases)('stops %s before it writes one, naming the kind but never repeating the secret', (tool, ti) => {
      const m = mapToolCall({ tool_name: tool, tool_input: ti })!;
      expect(m.blocked).toHaveLength(1);
      expect(m.blocked![0]).toContain('aws-access-key');
      expect(JSON.stringify(m)).not.toContain(AWS_KEY);
    });

    it('reports each kind once, however many times it appears', () => {
      const m = mapToolCall({
        tool_name: 'MultiEdit',
        tool_input: { file_path: 'a', edits: [{ new_string: AWS_KEY }, { new_string: AWS_KEY }, { new_string: PEM_HEADER }] },
      })!;
      expect(m.blocked!.map((b) => /\((.+?)\)/.exec(b)![1])).toEqual(['aws-access-key', 'private-key']);
    });

    it('does not read the old text of an edit as content being written', () => {
      expect(mapToolCall({ tool_name: 'Edit', tool_input: { file_path: 'a', old_string: AWS_KEY, new_string: 'REDACTED' } })!.blocked).toBeUndefined();
    });

    it('survives malformed edit lists', () => {
      for (const edits of [null, 'x', [null, 7, { new_string: 3 }], {}]) {
        expect(() => mapToolCall({ tool_name: 'MultiEdit', tool_input: { file_path: 'a', edits } })).not.toThrow();
      }
    });
  });
});

// =================================================================================================
describe('runHook: the exit-code contract with Claude Code', () => {
  const payload = (over: Record<string, unknown> = {}) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, ...over });
  const verdict = (v: GuardVerdict['verdict'], text = `COMMANDER // ${v}`): GuardVerdict => ({ verdict: v, text });
  const answering = (v: GuardVerdict) => vi.fn<Evaluate>(async () => v);

  it('lets a cleared action proceed silently (exit 0, nothing on stderr)', async () => {
    const evaluate = answering(verdict('CLEARED', ''));
    expect(await runHook(payload(), evaluate)).toEqual({ exitCode: 0, stderr: '' });
    expect(evaluate).toHaveBeenCalledWith({ kind: 'shell', payload: 'ls' }, 'Bash');
  });

  it.each(['DENIED', 'STAGED', 'REFUSED'] as const)('blocks a %s action with exit 2 and hands Commander\'s directive to the model', async (v) => {
    const text = `COMMANDER // CLEARANCE ${v}\nSelect a safe alternative.`;
    expect(await runHook(payload(), answering(verdict(v, text)))).toEqual({ exitCode: 2, stderr: `${text}\n` });
  });

  it('passes every other tool straight through without asking anyone', async () => {
    const evaluate = answering(verdict('DENIED'));
    for (const tool of ['Read', 'Grep', 'WebSearch', 'mcp__x__y']) {
      expect(await runHook(payload({ tool_name: tool }), evaluate), tool).toEqual({ exitCode: 0, stderr: '' });
    }
    expect(evaluate).not.toHaveBeenCalled();
  });

  it('judges file tools by path and sends only the path, never the file contents', async () => {
    const evaluate = answering(verdict('CLEARED', ''));
    await runHook(payload({ tool_name: 'Write', cwd: '/w', tool_input: { file_path: '/w/src/a.ts', content: 'const private = 1;' } }), evaluate);
    expect(evaluate).toHaveBeenCalledWith({ kind: 'fs', payload: 'src/a.ts', intent: 'write' }, 'Write');
    expect(JSON.stringify(evaluate.mock.calls)).not.toContain('const private');
  });

  it('refuses locally, without asking Commander, when content carries a credential', async () => {
    const evaluate = answering(verdict('CLEARED', ''));
    const out = await runHook(payload({ tool_name: 'Write', tool_input: { file_path: 'notes.txt', content: AWS_KEY } }), evaluate);
    expect(out.exitCode).toBe(2);
    expect(out.stderr).toMatch(/COMMANDER GUARD \/\/ DENIED/);
    expect(out.stderr).toContain('aws-access-key');
    expect(out.stderr).not.toContain(AWS_KEY);
    expect(evaluate).not.toHaveBeenCalled();
  });

  it('refuses a call it cannot understand, without asking Commander', async () => {
    const evaluate = answering(verdict('CLEARED', ''));
    const out = await runHook(payload({ tool_input: {} }), evaluate);
    expect(out).toMatchObject({ exitCode: 2 });
    expect(out.stderr).toMatch(/without a command/);
    expect(evaluate).not.toHaveBeenCalled();
  });

  it.each([[''], ['not json'], ['{"tool_name":'], ['null'], ['42'], ['"Bash"'], ['[]'], ['[{"tool_name":"Bash"}]']])('refuses hook input that is not a JSON object: %j', async (raw) => {
    const evaluate = answering(verdict('CLEARED', ''));
    const out = await runHook(raw, evaluate);
    expect(out.exitCode).toBe(2);
    expect(out.stderr).toMatch(/REFUSED/);
    expect(evaluate).not.toHaveBeenCalled();
  });

  describe('when Commander cannot be asked', () => {
    const unavailable: Evaluate = async () => {
      throw new GuardUnavailable('Commander could not be reached (ECONNREFUSED)');
    };

    it('fails CLOSED by default, and says how to opt out', async () => {
      const out = await runHook(payload(), unavailable);
      expect(out.exitCode).toBe(2);
      expect(out.stderr).toContain('COMMANDER GUARD // REFUSED');
      expect(out.stderr).toContain('ECONNREFUSED');
      expect(out.stderr).toContain('COMMANDER_GUARD_FAIL_OPEN=1');
    });

    it('allows only when the operator explicitly chose to, and says so on stderr', async () => {
      const out = await runHook(payload(), unavailable, { failOpen: true });
      expect(out.exitCode).toBe(0);
      expect(out.stderr).toMatch(/allowing because COMMANDER_GUARD_FAIL_OPEN=1/);
    });

    it('never excuses anything except unavailability: a bug in the evaluator still blocks, even when failing open', async () => {
      const buggy: Evaluate = async () => {
        throw new TypeError('x is undefined');
      };
      for (const failOpen of [false, true]) {
        const out = await runHook(payload(), buggy, { failOpen });
        expect(out.exitCode, `failOpen=${failOpen}`).toBe(2);
        expect(out.stderr).toContain('x is undefined');
        expect(out.stderr).not.toContain('FAIL_OPEN');
      }
    });

    it('never excuses a refusal either: a bad key, a held mission or a denial stays blocked when failing open', async () => {
      for (const v of ['REFUSED', 'DENIED', 'STAGED'] as const) {
        expect((await runHook(payload(), answering(verdict(v)), { failOpen: true })).exitCode, v).toBe(2);
      }
    });
  });
});

// =================================================================================================
describe('remoteEvaluate: asking the Commander server', () => {
  const action = { kind: 'shell' as const, payload: 'ls' };
  const reply = (status: number, body: unknown) => (async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch;
  const mk = (fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) => remoteEvaluate({ url: 'https://commander.test', key: 'cmd_live_testkey', mission: 'msn_1', fetchImpl, ...extra });

  it('posts the mission, tool and action with the worker key as a bearer token', async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const f = (async (url: string, init: RequestInit) => {
      seen.push({ url, init });
      return new Response(JSON.stringify({ verdict: 'CLEARED', clearance_id: 'clr_1', message: 'ok', findings: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    await mk(f, { url: 'https://commander.test///' })(action, 'Bash');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe('https://commander.test/v1/guard/clearance');
    expect(seen[0]!.init.method).toBe('POST');
    expect(seen[0]!.init.headers).toMatchObject({ authorization: 'Bearer cmd_live_testkey', 'content-type': 'application/json' });
    expect(JSON.parse(seen[0]!.init.body as string)).toEqual({ mission_id: 'msn_1', tool: 'Bash', action });
  });

  it('turns each verdict into the text the model will read', async () => {
    const cleared = await mk(reply(200, { verdict: 'CLEARED', clearance_id: 'clr_1', message: 'Proceed.', findings: [] }))(action, 'Bash');
    expect(cleared.verdict).toBe('CLEARED');

    const denied = await mk(
      reply(200, { verdict: 'DENIED', clearance_id: 'clr_2', message: 'Denied.', findings: [{ rule: 'shell.rm-destructive', reason: 'No.' }], patch: 'REDIRECT PATCH\n 1. [shell.rm-destructive] No.' }),
    )(action, 'Bash');
    expect(denied.verdict).toBe('DENIED');
    expect(denied.text).toContain('CLEARANCE DENIED');
    expect(denied.text).toContain('REDIRECT PATCH');

    const staged = await mk(reply(200, { verdict: 'STAGED', clearance_id: 'clr_3', message: 'Held.', findings: [{ rule: 'shell.production-change', reason: 'Deploy.' }] }))(action, 'Bash');
    expect(staged.verdict).toBe('STAGED');
    expect(staged.text).toContain('[shell.production-change] Deploy.');
    expect(staged.text).toMatch(/Retry the same action once the operator has authorized it.*single-use.*clr_3/s);
  });

  it.each([
    [401, { error: 'UNAUTHENTICATED', message: 'Credential rejected.' }, 'UNAUTHENTICATED'],
    [403, { error: 'FORBIDDEN', message: 'Wrong role.' }, 'FORBIDDEN'],
    [404, { error: 'NOT_FOUND', message: 'No such mission.' }, 'NOT_FOUND'],
    [409, { error: 'LEASE_INVALID', message: 'Lease is dead.' }, 'LEASE_INVALID'],
    [423, { error: 'HOLD', message: 'Mission is paused.' }, 'HOLD'],
    [429, { error: 'THROTTLED', message: 'Slow down.' }, 'THROTTLED'],
  ])('reports a %i as a REFUSED verdict carrying Commander\'s own words', async (status, body, code) => {
    const v = await mk(reply(status, body))(action, 'Bash');
    expect(v.verdict).toBe('REFUSED');
    expect(v.text).toContain(`[${code}]`);
    expect(v.text).toContain(body.message);
  });

  it('treats a 200 it cannot read as a refusal, not a clearance', async () => {
    const v = await mk(reply(200, '<html>proxy error</html>'))(action, 'Bash');
    expect(v.verdict).toBe('REFUSED');
  });

  it('classes server faults and network failures as "unavailable", the only thing fail-open may excuse', async () => {
    await expect(mk(reply(500, { error: 'FAULT' }))(action, 'Bash')).rejects.toBeInstanceOf(GuardUnavailable);
    await expect(mk(reply(503, 'down'))(action, 'Bash')).rejects.toThrowError(/HTTP 503/);
    const refused = (async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    await expect(mk(refused)(action, 'Bash')).rejects.toThrowError(/could not be reached.*fetch failed/);
  });

  it('gives up after its timeout instead of hanging the developer\'s session', async () => {
    const hang = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)))) as unknown as typeof fetch;
    const started = Date.now();
    await expect(mk(hang, { timeoutMs: 40 })(action, 'Bash')).rejects.toBeInstanceOf(GuardUnavailable);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

// =================================================================================================
describe('localEvaluate: the same rules, offline', () => {
  const shell = (payload: string) => ({ kind: 'shell' as const, payload });

  it('clears ordinary work', async () => {
    const evaluate = await localEvaluate();
    expect((await evaluate(shell('ls -la'), 'Bash')).verdict).toBe('CLEARED');
    expect((await evaluate({ kind: 'fs', payload: 'src/index.ts', intent: 'write' }, 'Write')).verdict).toBe('CLEARED');
  });

  it('denies what the Sentinel denies, with the rule named', async () => {
    const evaluate = await localEvaluate();
    const rm = await evaluate(shell('rm -rf /'), 'Bash');
    expect(rm.verdict).toBe('DENIED');
    expect(rm.text).toContain('COMMANDER GUARD // DENIED');
    expect(rm.text).toContain('[shell.rm-destructive]');
    expect((await evaluate({ kind: 'fs', payload: '.env', intent: 'write' }, 'Write')).verdict).toBe('DENIED');
  });

  it('protects the guard configuration from the agent it guards', async () => {
    const evaluate = await localEvaluate();
    const w = await evaluate({ kind: 'fs', payload: '.claude/settings.json', intent: 'write' }, 'Write');
    expect(w.verdict).toBe('DENIED');
    expect(w.text).toContain('fs.agent-config');
    expect((await evaluate(shell('sed -i /hooks/d .claude/settings.json'), 'Bash')).verdict).toBe('STAGED');
  });

  it('cannot stage, so it says what staging would need rather than pretending', async () => {
    const evaluate = await localEvaluate();
    const v = await evaluate(shell('kubectl apply -f prod.yaml'), 'Bash');
    expect(v.verdict).toBe('STAGED');
    expect(v.text).toMatch(/local rules/);
    expect(v.text).toContain('COMMANDER_URL');
    expect(v.text).toContain('[shell.production-change]');
  });

  it('has no memory between calls (each hook run is a fresh process), so repetition is not detected', async () => {
    const evaluate = await localEvaluate();
    for (let i = 0; i < 12; i++) expect((await evaluate(shell('npm test'), 'Bash')).verdict).toBe('CLEARED');
  });

  describe('with a policy file', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'guard-policy-'));
    dirs.push(dir);
    const write = (name: string, content: unknown) => {
      const p = path.join(dir, name);
      writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content));
      return p;
    };

    it('applies it', async () => {
      const evaluate = await localEvaluate(write('strict.json', { strict_shell: true, shell_allowlist: ['ls'] }));
      expect((await evaluate(shell('ls'), 'Bash')).verdict).toBe('CLEARED');
      expect((await evaluate(shell('git status'), 'Bash')).verdict).toBe('STAGED');
    });

    it('refuses to start on a policy it cannot read or that is invalid, so a typo never silently loosens the guard', async () => {
      await expect(localEvaluate(path.join(dir, 'missing.json'))).rejects.toThrow();
      await expect(localEvaluate(write('broken.json', '{ nope'))).rejects.toThrow();
      await expect(localEvaluate(write('invalid.json', { repetition_threshold: 1 }))).rejects.toThrow();
    });
  });
});

// =================================================================================================
describe('settingsSnippet and the shipped Claude Code configuration', () => {
  it('registers one PreToolUse hook whose matcher is exactly the guarded tools', () => {
    const s = settingsSnippet('/opt/agent-commander/dist/guard/claude-hook.js');
    expect(s.hooks.PreToolUse).toHaveLength(1);
    const entry = s.hooks.PreToolUse[0]!;
    expect(entry.matcher).toBe(GUARDED_TOOLS.join('|'));
    expect(entry.hooks).toEqual([{ type: 'command', command: 'node "/opt/agent-commander/dist/guard/claude-hook.js"', timeout: 15 }]);
  });

  it('quotes the path so one with spaces or shell characters still runs as written', () => {
    const hookPath = '/Users/me/My Tools/$(id)/claude-hook.js';
    const cmd = settingsSnippet(hookPath).hooks.PreToolUse[0]!.hooks[0]!.command;
    expect(cmd.startsWith('node ')).toBe(true);
    expect(JSON.parse(cmd.slice('node '.length))).toBe(hookPath);
  });

  it('adds an env block only when asked, and never one that could hold the key', () => {
    expect('env' in settingsSnippet('/h.js')).toBe(false);
    const s = settingsSnippet('/h.js', { url: 'https://c.example', mission: 'msn_9' });
    expect(s.env).toEqual({ COMMANDER_URL: 'https://c.example', COMMANDER_MISSION: 'msn_9' });
    expect(JSON.stringify(s)).not.toMatch(/COMMANDER_KEY|cmd_live_|cmd_op_/);
  });

  describe('guard/claude-code/settings.json', () => {
    const file = JSON.parse(readFileSync(new URL('../guard/claude-code/settings.json', import.meta.url), 'utf8')) as ReturnType<typeof settingsSnippet> & { env: Record<string, string> };

    it('matches what the CLI prints, so the documentation cannot drift from the code', () => {
      const printed = settingsSnippet('/ABSOLUTE/PATH/TO/agent-commander/dist/guard/claude-hook.js', { url: file.env.COMMANDER_URL, mission: file.env.COMMANDER_MISSION });
      expect(file.hooks).toEqual(printed.hooks);
      expect(Object.keys(file.env).sort()).toEqual(['COMMANDER_MISSION', 'COMMANDER_URL']);
    });

    it('holds no credential and is clearly a template', () => {
      const raw = JSON.stringify(file);
      expect(raw).not.toMatch(/COMMANDER_KEY|cmd_live_|cmd_op_/);
      expect(raw).toContain('/ABSOLUTE/PATH/TO');
      expect(file.env.COMMANDER_MISSION).toMatch(/REPLACE/);
    });
  });
});
