import type { Policy } from './config.js';
import { CommanderError } from './errors.js';
import { say } from './persona.js';
import type { Store } from './store.js';
import type { KeyRec, Principal, Role, TenantRec } from './types.js';
import { iso, newId, newSecret, sha256, type Clock } from './util.js';

export type MeterOp = 'directive' | 'proof' | 'clearance' | 'gate';

const PREFIX: Record<Role, string> = { worker: 'cmd_live_', operator: 'cmd_op_' };

export class Auth {
  /** Per-mission credit burn inside the trailing minute. */
  private readonly burn = new Map<string, { ts: number; c: number }[]>();

  constructor(
    private readonly store: Store,
    private readonly policy: Policy,
    private readonly clock: Clock,
  ) {}

  createTenant(name: string, credits: number): { tenant: TenantRec; operatorKey: string } {
    const tenant: TenantRec = { id: newId('ten'), name, credits, createdAt: iso(this.clock()) };
    this.store.state.tenants[tenant.id] = tenant;
    this.store.audit(tenant.id, 'tenant.created', { name, credits });
    const { key } = this.issueKey(tenant.id, 'operator', 'bootstrap');
    return { tenant, operatorKey: key };
  }

  /** The plaintext key is returned once and never stored. */
  issueKey(tenantId: string, role: Role, label?: string): { record: KeyRec; key: string } {
    if (!this.store.state.tenants[tenantId]) throw new CommanderError('NOT_FOUND', say.notFound());
    const key = newSecret(PREFIX[role]);
    const record: KeyRec = { id: newId('key'), tenantId, role, label, createdAt: iso(this.clock()) };
    this.store.state.keys[sha256(key)] = record;
    this.store.audit(tenantId, 'key.issued', { keyId: record.id, role, label });
    this.store.touch();
    return { record, key };
  }

  revokeKey(tenantId: string, keyId: string): void {
    const rec = Object.values(this.store.state.keys).find((k) => k.id === keyId && k.tenantId === tenantId);
    if (!rec) throw new CommanderError('NOT_FOUND', say.notFound());
    rec.revokedAt = iso(this.clock());
    this.store.audit(tenantId, 'key.revoked', { keyId });
    this.store.touch();
  }

  authenticate(header: string | undefined): Principal {
    const m = /^Bearer\s+(\S+)$/i.exec(header ?? '');
    const token = m?.[1];
    if (!token || !(token.startsWith(PREFIX.worker) || token.startsWith(PREFIX.operator))) {
      throw new CommanderError('UNAUTHENTICATED', say.unauthenticated());
    }
    const rec = this.store.state.keys[sha256(token)];
    if (!rec || rec.revokedAt || !this.store.state.tenants[rec.tenantId]) {
      throw new CommanderError('UNAUTHENTICATED', say.unauthenticated());
    }
    return { tenantId: rec.tenantId, keyId: rec.id, role: rec.role };
  }

  requireRole(p: Principal, role: Role): void {
    if (p.role !== role) throw new CommanderError('FORBIDDEN', say.forbidden());
  }

  balance(tenantId: string): number {
    return this.store.state.tenants[tenantId]?.credits ?? 0;
  }

  topUp(tenantId: string, amount: number): number {
    const tenant = this.store.state.tenants[tenantId];
    if (!tenant) throw new CommanderError('NOT_FOUND', say.notFound());
    if (!Number.isFinite(amount) || amount <= 0) throw new CommanderError('INVALID', say.invalid('Amount must be positive.'));
    tenant.credits += amount;
    this.store.audit(tenantId, 'credits.topup', { amount, balance: tenant.credits });
    this.store.touch();
    return tenant.credits;
  }

  /** Meters one operation. Throws THROTTLED before spending anything if the mission is burning too fast. */
  charge(p: Principal, op: MeterOp, missionId?: string): number {
    const cost = this.policy.credit_costs[op];
    const tenant = this.store.state.tenants[p.tenantId];
    if (!tenant) throw new CommanderError('NOT_FOUND', say.notFound());
    const now = this.clock();

    if (missionId) {
      const window = (this.burn.get(missionId) ?? []).filter((e) => now - e.ts < 60_000);
      const spent = window.reduce((a, e) => a + e.c, 0);
      if (spent + cost > this.policy.burn_limit_per_min) {
        const retryAfter = Math.max(1, Math.ceil((60_000 - (now - (window[0]?.ts ?? now))) / 1000));
        this.store.audit(p.tenantId, 'sentinel.throttle', { missionId, op, spent, limit: this.policy.burn_limit_per_min });
        throw new CommanderError('THROTTLED', say.throttled(retryAfter), { retryAfter });
      }
      window.push({ ts: now, c: cost });
      this.burn.set(missionId, window);
    }

    if (tenant.credits < cost) {
      this.store.audit(p.tenantId, 'meter.exhausted', { op, balance: tenant.credits });
      throw new CommanderError('CREDITS_EXHAUSTED', say.creditsExhausted());
    }
    tenant.credits -= cost;
    this.store.audit(p.tenantId, 'meter.charge', { op, credits: cost, missionId, balance: tenant.credits });
    this.store.touch();
    return cost;
  }
}
