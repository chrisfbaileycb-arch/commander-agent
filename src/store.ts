import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Approval, Clearance, KeyRec, Mission, TenantRec } from './types.js';
import { iso, sha256, stableStringify, type Clock } from './util.js';

export interface State {
  tenants: Record<string, TenantRec>;
  /** Keyed by sha256(key). Plaintext keys are never stored. */
  keys: Record<string, KeyRec>;
  missions: Record<string, Mission>;
  approvals: Record<string, Approval>;
  clearances: Record<string, Clearance>;
}

const emptyState = (): State => ({ tenants: {}, keys: {}, missions: {}, approvals: {}, clearances: {} });

export const GENESIS = '0'.repeat(64);

/**
 * One tamper-evident chain per tenant. Records of different tenants interleave in the log file, but each
 * tenant's `seq` and `prev` link only to that tenant's own history, so a tenant can verify its own record
 * without learning anything about anyone else's.
 */
export interface AuditRecord {
  seq: number;
  ts: string;
  tenantId: string;
  type: string;
  data: Record<string, unknown>;
  prev: string;
  hash: string;
}

function hashRecord(r: Omit<AuditRecord, 'hash'>): string {
  return sha256(`${r.prev}|${r.seq}|${r.ts}|${r.tenantId}|${r.type}|${stableStringify(r.data)}`);
}

export type ChainVerdict = { ok: true; count: number } | { ok: false; tenantId?: string; brokenAt: number; reason: string };

/** Verifies a single chain. The first record's `prev` is trusted as the anchor unless it is seq 1. */
export function verifyChain(records: AuditRecord[]): ChainVerdict {
  for (let i = 0; i < records.length; i++) {
    const r = records[i]!;
    const { hash, ...rest } = r;
    if (hashRecord(rest) !== hash) return { ok: false, brokenAt: r.seq, reason: 'record hash mismatch' };
    if (i > 0 && (r.prev !== records[i - 1]!.hash || r.seq !== records[i - 1]!.seq + 1)) {
      return { ok: false, brokenAt: r.seq, reason: 'chain link mismatch' };
    }
    if (i === 0 && r.seq === 1 && r.prev !== GENESIS) return { ok: false, brokenAt: r.seq, reason: 'bad genesis' };
  }
  return { ok: true, count: records.length };
}

/** Verifies every tenant's chain (or just `tenantId`'s) out of an interleaved record list. */
export function verifyChains(records: AuditRecord[], tenantId?: string): ChainVerdict {
  const byTenant = new Map<string, AuditRecord[]>();
  for (const r of records) {
    if (tenantId && r.tenantId !== tenantId) continue;
    const list = byTenant.get(r.tenantId) ?? [];
    list.push(r);
    byTenant.set(r.tenantId, list);
  }
  let count = 0;
  for (const [t, list] of byTenant) {
    const verdict = verifyChain(list);
    if (!verdict.ok) return { ...verdict, tenantId: t };
    count += verdict.count;
  }
  return { ok: true, count };
}

export interface StoreOptions {
  /** Directory for state.json + audit.jsonl. Omit for an in-memory store. */
  dir?: string;
  clock: Clock;
  recentLimit?: number;
}

export class Store {
  state: State = emptyState();
  /** Tail of the audit log across tenants, newest last. Metrics are derived from this. */
  readonly recent: AuditRecord[] = [];
  private readonly heads = new Map<string, { seq: number; hash: string }>();
  private dirty = false;
  private readonly statePath?: string;
  private readonly auditPath?: string;
  private readonly recentLimit: number;

  constructor(private readonly opts: StoreOptions) {
    this.recentLimit = opts.recentLimit ?? 20_000;
    if (!opts.dir) return;
    mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
    this.statePath = join(opts.dir, 'state.json');
    this.auditPath = join(opts.dir, 'audit.jsonl');
    if (existsSync(this.statePath)) this.state = { ...emptyState(), ...JSON.parse(readFileSync(this.statePath, 'utf8')) };
    if (existsSync(this.auditPath)) this.loadAudit(this.auditPath);
  }

  private loadAudit(path: string): void {
    const raw = readFileSync(path, 'utf8');
    const lines = raw.split('\n').filter((l) => l.length > 0);
    const records: AuditRecord[] = [];
    let torn = false;
    for (let i = 0; i < lines.length; i++) {
      try {
        records.push(JSON.parse(lines[i]!) as AuditRecord);
      } catch (err) {
        // A torn final line is a crash artifact; anything earlier is corruption.
        if (i === lines.length - 1) {
          torn = true;
          break;
        }
        throw new Error(`audit.jsonl is corrupt at line ${i + 1}: ${(err as Error).message}`);
      }
    }
    const verdict = verifyChains(records);
    if (!verdict.ok) {
      throw new Error(`Audit chain broken for ${verdict.tenantId ?? 'unknown tenant'} at seq ${verdict.brokenAt}: ${verdict.reason}. Refusing to start.`);
    }
    for (const r of records) this.heads.set(r.tenantId, { seq: r.seq, hash: r.hash });
    this.recent.push(...records.slice(-this.recentLimit));
    // Drop the torn tail so the next append starts on a fresh line instead of fusing with it.
    if (torn || (raw.length > 0 && !raw.endsWith('\n'))) {
      writeFileSync(path, records.map((r) => `${JSON.stringify(r)}\n`).join(''), { mode: 0o600 });
    }
  }

  audit(tenantId: string, type: string, data: Record<string, unknown> = {}): AuditRecord {
    const head = this.heads.get(tenantId) ?? { seq: 0, hash: GENESIS };
    const base = { seq: head.seq + 1, ts: iso(this.opts.clock()), tenantId, type, data, prev: head.hash };
    const rec: AuditRecord = { ...base, hash: hashRecord(base) };
    this.heads.set(tenantId, { seq: rec.seq, hash: rec.hash });
    this.recent.push(rec);
    if (this.recent.length > this.recentLimit * 1.25) this.recent.splice(0, this.recent.length - this.recentLimit);
    if (this.auditPath) appendFileSync(this.auditPath, `${JSON.stringify(rec)}\n`, { mode: 0o600 });
    return rec;
  }

  /** Marks state dirty; writes are coalesced to one per event-loop turn. */
  touch(): void {
    if (!this.statePath || this.dirty) return;
    this.dirty = true;
    queueMicrotask(() => this.flush());
  }

  flush(): void {
    if (!this.statePath || !this.dirty) return;
    this.dirty = false;
    const tmp = `${this.statePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
    renameSync(tmp, this.statePath);
  }

  /**
   * Verifies chains over the in-memory tail (cheap, bounded). Pass `full` to re-read the entire log from
   * disk, which is O(log size): reserve it for platform administrators.
   */
  verify(opts: { tenantId?: string; full?: boolean } = {}): ChainVerdict {
    let records: AuditRecord[] = this.recent;
    if (opts.full && this.auditPath && existsSync(this.auditPath)) {
      records = readFileSync(this.auditPath, 'utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as AuditRecord);
    }
    return verifyChains(records, opts.tenantId);
  }

  tenantAudit(tenantId: string, limit = 50): AuditRecord[] {
    const out: AuditRecord[] = [];
    for (let i = this.recent.length - 1; i >= 0 && out.length < limit; i--) {
      const r = this.recent[i]!;
      if (r.tenantId === tenantId) out.push(r);
    }
    return out;
  }
}
