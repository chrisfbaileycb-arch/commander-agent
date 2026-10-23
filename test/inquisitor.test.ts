import { describe, expect, it } from 'vitest';
import { auditDiff, findSecrets, globToRegExp, matchesAnyGlob, parseUnifiedDiff, redactSecrets } from '../src/inquisitor.js';

const policy = { forbidden_paths: ['.env', '**/.env', '.git/**', '.github/workflows/**', '**/*.pem'], max_patch_lines: 20 };

// Fake credentials are assembled at runtime so that no literal in the repository resembles a real one to a secret scanner.
const AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const GH_TOKEN = ['ghp', '_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
const SLACK_TOKEN = ['xox', 'b-1234567890-abcdef'].join('');
const PEM_HEADER = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join('');

const diff = (path: string, added: string[], removed: string[] = []) =>
  [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -1,${1 + removed.length} +1,${1 + added.length} @@`,
    ' context',
    ...removed.map((l) => `-${l}`),
    ...added.map((l) => `+${l}`),
    '',
  ].join('\n');

describe('globs', () => {
  it('matches the shapes the policy relies on', () => {
    expect(globToRegExp('**/.env').test('a/b/.env')).toBe(true);
    expect(globToRegExp('**/.env').test('.env')).toBe(true);
    expect(globToRegExp('.git/**').test('.git/config')).toBe(true);
    expect(globToRegExp('*.pem').test('dir/x.pem')).toBe(false);
    expect(globToRegExp('**/*.pem').test('dir/x.pem')).toBe(true);
    expect(matchesAnyGlob('./.github/workflows/ci.yml', policy.forbidden_paths)).toBe('.github/workflows/**');
    expect(matchesAnyGlob('src/app.ts', policy.forbidden_paths)).toBeUndefined();
  });
  it('escapes regex metacharacters in the glob', () => {
    expect(globToRegExp('a+b.txt').test('a+b.txt')).toBe(true);
    expect(globToRegExp('a+b.txt').test('aab_txt')).toBe(false);
  });
});

describe('secrets', () => {
  it.each([
    ['aws', `key = ${AWS_KEY}`],
    ['private key', PEM_HEADER],
    ['github', GH_TOKEN],
    ['commander', 'cmd_live_abcdefghijklmnop1234'],
    ['slack', SLACK_TOKEN],
    ['assignment', 'api_key = "abcdefghij1234567890"'],
    ['conn string', 'postgres://admin:hunter22@db.internal/app'],
  ])('detects %s', (_n, text) => {
    expect(findSecrets(text).length).toBeGreaterThan(0);
  });
  it('does not flag ordinary code', () => {
    expect(findSecrets('const total = items.length; // token bucket')).toEqual([]);
  });
  it('redacts without leaking the value', () => {
    const out = redactSecrets(`use ${AWS_KEY} now`);
    expect(out).not.toContain(AWS_KEY);
    expect(out).toContain('[REDACTED:aws-access-key]');
  });
});

describe('parseUnifiedDiff', () => {
  it('counts added and removed lines per file', () => {
    const files = parseUnifiedDiff(diff('src/a.ts', ['x', 'y'], ['old']));
    expect(files).toHaveLength(1);
    expect(files[0]!.path).toBe('src/a.ts');
    expect(files[0]!.added).toEqual(['x', 'y']);
    expect(files[0]!.removed).toBe(1);
  });

  it('is hunk-aware: header lookalikes inside a hunk are content', () => {
    const text = [
      'diff --git a/q.sql b/q.sql',
      '--- a/q.sql',
      '+++ b/q.sql',
      '@@ -1,2 +1,2 @@',
      '--- removed sql comment',
      '+++ added line that looks like a header',
    ].join('\n');
    const files = parseUnifiedDiff(text);
    expect(files).toHaveLength(1);
    expect(files[0]!.removed).toBe(1);
    expect(files[0]!.added).toEqual(['++ added line that looks like a header']);
  });

  it('handles multiple files', () => {
    const files = parseUnifiedDiff(diff('a.ts', ['1']) + diff('b.ts', ['2']));
    expect(files.map((f) => f.path)).toEqual(['a.ts', 'b.ts']);
  });
});

describe('auditDiff', () => {
  it('passes a clean patch', () => {
    const r = auditDiff(diff('src/a.ts', ['const a = 1;']), policy);
    expect(r.ok).toBe(true);
    expect(r.linesChanged).toBe(1);
  });
  it('flags forbidden paths', () => {
    expect(auditDiff(diff('.env', ['A=1']), policy).violations.join()).toMatch(/forbidden path/);
    expect(auditDiff(diff('.github/workflows/ci.yml', ['x']), policy).ok).toBe(false);
  });
  it('flags secrets in added lines only', () => {
    expect(auditDiff(diff('src/a.ts', [`const k = "${AWS_KEY}";`]), policy).ok).toBe(false);
    expect(auditDiff(diff('src/a.ts', ['ok'], [`const k = "${AWS_KEY}";`]), policy).ok).toBe(true);
  });
  it('flags traversal and absolute paths', () => {
    expect(auditDiff(diff('../outside.txt', ['x']), policy).violations.join()).toMatch(/escapes/);
    expect(auditDiff(diff('/etc/passwd', ['x']), policy).ok).toBe(false);
  });
  it('enforces the size limit', () => {
    const big = Array.from({ length: 30 }, (_, i) => `line ${i}`);
    expect(auditDiff(diff('src/a.ts', big), policy).violations.join()).toMatch(/limit is 20/);
  });
  it('rejects text with no diff hunks', () => {
    expect(auditDiff('just some prose', policy).ok).toBe(false);
  });
});
