import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Auth } from '../src/auth.js';
import { defaultPolicy } from '../src/config.js';
import { GENESIS, Store, verifyChain, verifyChains, type AuditRecord } from '../src/store.js';
import { sha256 } from '../src/util.js';

const clock = () => 1_700_000_000_000;

function withDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'commander-test-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('audit chain (in memory)', () => {
  it('links records per tenant, each starting at the genesis hash', () => {
    const s = new Store({ clock });
    const a1 = s.audit('ten_a', 'x', { n: 1 });
    const b1 = s.audit('ten_b', 'x', { n: 1 });
    const a2 = s.audit('ten_a', 'y', { n: 2 });
    expect([a1.seq, b1.seq, a2.seq]).toEqual([1, 1, 2]);
    expect(a1.prev).toBe(GENESIS);
    expect(b1.prev).toBe(GENESIS);
    expect(a2.prev).toBe(a1.hash);
    expect(s.verify()).toEqual({ ok: true, count: 3 });
    expect(s.verify({ tenantId: 'ten_a' })).toEqual({ ok: true, count: 2 });
  });

  it('detects edited content, a deleted record, and reordering', () => {
    const build = () => {
      const s = new Store({ clock });
      for (let i = 0; i < 5; i++) s.audit('t', 'e', { i });
      return s;
    };

    const edited = build();
    edited.recent[2]!.data.i = 99;
    expect(edited.verify()).toMatchObject({ ok: false, brokenAt: 3, reason: 'record hash mismatch' });

    const deleted = build();
    deleted.recent.splice(2, 1);
    expect(deleted.verify()).toMatchObject({ ok: false, reason: 'chain link mismatch' });

    const reordered = build();
    [reordered.recent[1], reordered.recent[2]] = [reordered.recent[2]!, reordered.recent[1]!];
    expect(reordered.verify().ok).toBe(false);
  });

  it("tampering with one tenant's history does not break another's verification", () => {
    const s = new Store({ clock });
    for (let i = 0; i < 3; i++) {
      s.audit('ten_a', 'e', { i });
      s.audit('ten_b', 'e', { i });
    }
    const victim = s.recent.find((r) => r.tenantId === 'ten_b' && r.seq === 2)!;
    victim.data.i = 'forged';
    expect(s.verify({ tenantId: 'ten_a' }).ok).toBe(true);
    expect(s.verify({ tenantId: 'ten_b' })).toMatchObject({ ok: false, tenantId: 'ten_b' });
    expect(s.verify()).toMatchObject({ ok: false, tenantId: 'ten_b' });
  });

  it('keeps a bounded tail that still verifies, and keeps counting', () => {
    const s = new Store({ clock, recentLimit: 4 });
    let last!: AuditRecord;
    for (let i = 0; i < 30; i++) last = s.audit('t', 'e', { i });
    expect(s.recent.length).toBeLessThanOrEqual(5);
    expect(last.seq).toBe(30);
    expect(s.verify().ok).toBe(true);
  });

  it('rejects a forged genesis', () => {
    const s = new Store({ clock });
    const r = { ...s.audit('t', 'e'), prev: 'f'.repeat(64) };
    expect(verifyChain([r]).ok).toBe(false);
    expect(verifyChains([r]).ok).toBe(false);
  });
});

describe('persistence', () => {
  it('round-trips state and continues the chain across a restart, without storing plaintext keys', () => {
    withDir((dir) => {
      const s1 = new Store({ dir, clock });
      const auth1 = new Auth(s1, defaultPolicy(), clock);
      const { tenant, operatorKey } = auth1.createTenant('acme', 50);
      s1.flush();

      const stateRaw = readFileSync(join(dir, 'state.json'), 'utf8');
      expect(stateRaw).not.toContain(operatorKey);
      expect(stateRaw).toContain(sha256(operatorKey));
      expect(readFileSync(join(dir, 'audit.jsonl'), 'utf8')).not.toContain(operatorKey);

      const s2 = new Store({ dir, clock });
      expect(s2.state.tenants[tenant.id]?.credits).toBe(50);
      expect(new Auth(s2, defaultPolicy(), clock).authenticate(`Bearer ${operatorKey}`).tenantId).toBe(tenant.id);

      const before = s2.tenantAudit(tenant.id, 100).length;
      expect(s2.audit(tenant.id, 'after.restart').seq).toBe(before + 1);
      expect(s2.verify({ full: true })).toMatchObject({ ok: true });
    });
  });

  it.runIf(process.platform !== 'win32')('writes state and audit files readable by the owner only', () => {
    withDir((dir) => {
      const s = new Store({ dir, clock });
      new Auth(s, defaultPolicy(), clock).createTenant('acme', 1);
      s.flush();
      expect(statSync(join(dir, 'state.json')).mode & 0o777).toBe(0o600);
      expect(statSync(join(dir, 'audit.jsonl')).mode & 0o777).toBe(0o600);
    });
  });

  it('repairs a torn final line so later appends do not fuse with it', () => {
    withDir((dir) => {
      const s1 = new Store({ dir, clock });
      s1.audit('t1', 'a');
      s1.audit('t1', 'b');
      appendFileSync(join(dir, 'audit.jsonl'), '{"seq":3,"ts":"2026-0');

      const s2 = new Store({ dir, clock });
      expect(s2.audit('t1', 'c').seq).toBe(3);

      const s3 = new Store({ dir, clock });
      expect(s3.verify({ full: true })).toEqual({ ok: true, count: 3 });
    });
  });

  it('refuses to start on mid-file corruption', () => {
    withDir((dir) => {
      const s = new Store({ dir, clock });
      for (const t of ['a', 'b', 'c']) s.audit('t1', t);
      const path = join(dir, 'audit.jsonl');
      const lines = readFileSync(path, 'utf8').trim().split('\n');
      lines[1] = 'this is not json';
      writeFileSync(path, `${lines.join('\n')}\n`);
      expect(() => new Store({ dir, clock })).toThrowError(/corrupt at line 2/);
    });
  });

  it('refuses to start when a record was edited or removed after the fact', () => {
    withDir((dir) => {
      const s = new Store({ dir, clock });
      for (const t of ['a', 'b', 'c']) s.audit('t1', t);
      const path = join(dir, 'audit.jsonl');
      const original = readFileSync(path, 'utf8');

      writeFileSync(path, original.replace('"type":"b"', '"type":"forged"'));
      expect(() => new Store({ dir, clock })).toThrowError(/Audit chain broken/);

      const lines = original.trim().split('\n');
      writeFileSync(path, `${[lines[0], lines[2]].join('\n')}\n`);
      expect(() => new Store({ dir, clock })).toThrowError(/Audit chain broken/);
    });
  });
});
