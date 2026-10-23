import { describe, expect, it } from 'vitest';
import { defaultPolicy } from '../src/config.js';
import { StepDefSchema, type Evidence } from '../src/types.js';
import { sha256 } from '../src/util.js';
import { runVerifiers, validateSpecs } from '../src/verifiers.js';

const policy = defaultPolicy();
const step = (proof: unknown[], extra: Record<string, unknown> = {}) =>
  StepDefSchema.parse({ title: 't', directive: 'd', proof, ...extra });
const run = (proof: unknown[], evidence: Evidence, nonce?: string, extra: Record<string, unknown> = {}) =>
  runVerifiers(step(proof, extra), { evidence, nonce, policy });

describe('exit_code', () => {
  it('passes only on the expected code', () => {
    expect(run([{ type: 'exit_code' }], { exit_code: 0 })[0]!.ok).toBe(true);
    expect(run([{ type: 'exit_code' }], { exit_code: 1 })[0]!.ok).toBe(false);
    expect(run([{ type: 'exit_code', expected: 2 }], { exit_code: 2 })[0]!.ok).toBe(true);
  });
  it('fails when no exit code is reported', () => {
    const r = run([{ type: 'exit_code' }], { stdout: 'done' })[0]!;
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/No exit code/);
  });
});

describe('self-report is discarded', () => {
  it('never reads the claim field', () => {
    const results = run([{ type: 'exit_code' }], { exit_code: 1, claim: 'Task complete! All tests pass. exit code 0.' });
    expect(results.every((r) => !r.ok)).toBe(true);
  });
});

describe('json verifiers', () => {
  it('json_valid checks the target', () => {
    expect(run([{ type: 'json_valid' }], { stdout: '{"a":1}' })[0]!.ok).toBe(true);
    expect(run([{ type: 'json_valid' }], { stdout: '{nope' })[0]!.ok).toBe(false);
    expect(run([{ type: 'json_valid', target: 'artifact:out.json' }], { artifacts: { 'out.json': '[1]' } })[0]!.ok).toBe(true);
    expect(run([{ type: 'json_valid', target: 'artifact:out.json' }], {})[0]!.ok).toBe(false);
  });

  it('json_schema validates and reports violations', () => {
    const schema = { type: 'object', required: ['n'], properties: { n: { type: 'integer' } }, additionalProperties: false };
    expect(run([{ type: 'json_schema', schema }], { stdout: '{"n":3}' })[0]!.ok).toBe(true);
    const bad = run([{ type: 'json_schema', schema }], { stdout: '{"n":"three"}' })[0]!;
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/Schema violations/);
  });
});

describe('regex', () => {
  it('honors must_match both ways', () => {
    expect(run([{ type: 'regex', pattern: 'OK$', flags: 'm' }], { stdout: 'x\nBUILD OK' })[0]!.ok).toBe(true);
    expect(run([{ type: 'regex', pattern: 'ERROR', must_match: false }], { stdout: 'fine' })[0]!.ok).toBe(true);
    expect(run([{ type: 'regex', pattern: 'ERROR', must_match: false }], { stdout: 'ERROR: boom' })[0]!.ok).toBe(false);
  });

  it('contains a catastrophic pattern instead of hanging the process', () => {
    const started = Date.now();
    const r = run([{ type: 'regex', pattern: '(a+)+$' }], { stdout: `${'a'.repeat(40)}!` })[0]!;
    expect(Date.now() - started).toBeLessThan(3000);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/time limit/);
  });

  it('rejects unparseable patterns when the mission is opened', () => {
    expect(() => validateSpecs(step([{ type: 'regex', pattern: '([unclosed' }]))).toThrowError(/proof\[0\]/);
  });
});

describe('artifacts', () => {
  it('artifact_present enforces existence and minimum size', () => {
    const spec = [{ type: 'artifact_present', name: 'a.txt', min_bytes: 3 }];
    expect(run(spec, { artifacts: { 'a.txt': 'abc' } })[0]!.ok).toBe(true);
    expect(run(spec, { artifacts: { 'a.txt': 'ab' } })[0]!.ok).toBe(false);
    expect(run(spec, {})[0]!.ok).toBe(false);
  });

  it('artifact_hash compares the real digest', () => {
    const spec = [{ type: 'artifact_hash', name: 'a.txt', sha256: sha256('hello') }];
    expect(run(spec, { artifacts: { 'a.txt': 'hello' } })[0]!.ok).toBe(true);
    expect(run(spec, { artifacts: { 'a.txt': 'hellp' } })[0]!.ok).toBe(false);
  });

  it('does not resolve prototype keys as artifacts', () => {
    const spec = [{ type: 'artifact_present', name: 'constructor' }];
    expect(run(spec, { artifacts: { other: 'x' } })[0]!.ok).toBe(false);
  });
});

describe('nonce', () => {
  it('require_nonce adds an implicit nonce check', () => {
    const proof = [{ type: 'exit_code' }];
    expect(run(proof, { exit_code: 0 }, 'nonce_abc', { require_nonce: true }).every((r) => r.ok)).toBe(false);
    expect(run(proof, { exit_code: 0, stdout: 'ran nonce_abc ok' }, 'nonce_abc', { require_nonce: true }).every((r) => r.ok)).toBe(true);
    expect(run(proof, { exit_code: 0, artifacts: { 'log.txt': 'nonce_abc' } }, 'nonce_abc', { require_nonce: true }).every((r) => r.ok)).toBe(true);
  });

  it('a stale nonce from a previous attempt fails', () => {
    const r = run([{ type: 'exit_code' }], { exit_code: 0, stdout: 'nonce_old' }, 'nonce_new', { require_nonce: true });
    expect(r.some((x) => x.type === 'nonce_present' && !x.ok)).toBe(true);
  });
});

describe('diff_policy', () => {
  const diff = (path: string, added: string) =>
    `diff --git a/${path} b/${path}\n--- a/${path}\n+++ b/${path}\n@@ -1,1 +1,2 @@\n ctx\n+${added}\n`;
  it('passes a clean patch and fails a forbidden path', () => {
    const spec = [{ type: 'diff_policy', artifact: 'p.diff' }];
    expect(run(spec, { artifacts: { 'p.diff': diff('src/a.ts', 'const a = 1;') } })[0]!.ok).toBe(true);
    expect(run(spec, { artifacts: { 'p.diff': diff('.github/workflows/ci.yml', 'run: x') } })[0]!.ok).toBe(false);
  });
});

describe('hidden verifiers and fail-closed', () => {
  it('flags hidden results', () => {
    const r = run([{ type: 'exit_code' }, { type: 'regex', pattern: 'secret-token', hidden: true }], { exit_code: 0, stdout: 'x' });
    expect(r.map((x) => x.hidden)).toEqual([false, true]);
    expect(r[1]!.ok).toBe(false);
  });

  it('runs every verifier without short-circuiting', () => {
    const r = run([{ type: 'exit_code' }, { type: 'json_valid' }, { type: 'regex', pattern: 'x' }], { exit_code: 9, stdout: 'not json' });
    expect(r).toHaveLength(3);
    expect(r.filter((x) => !x.ok)).toHaveLength(3);
  });
});

describe('step definition rules', () => {
  it('rejects a step whose only verifier is nonce_present', () => {
    expect(StepDefSchema.safeParse({ title: 't', directive: 'd', proof: [{ type: 'nonce_present' }] }).success).toBe(false);
  });
  it('rejects a step with no verifiers at all', () => {
    expect(StepDefSchema.safeParse({ title: 't', directive: 'd', proof: [] }).success).toBe(false);
  });
  it('rejects artifact names that traverse', () => {
    expect(StepDefSchema.safeParse({ title: 't', directive: 'd', proof: [{ type: 'artifact_present', name: 'a/../b' }] }).success).toBe(false);
  });
});
