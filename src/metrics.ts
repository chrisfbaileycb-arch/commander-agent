import type { Store } from './store.js';

/** HUD telemetry for one tenant. Everything is derived from the audit chain and the ledger, never tracked separately. */

const ERROR_EVENTS = new Set(['proof.rejected', 'clearance.denied', 'sentinel.throttle', 'meter.exhausted']);

export interface Metrics {
  activeAgents: number;
  spend: {
    balance: number;
    creditsLastMinute: number;
    creditsLastHour: number;
    /** Estimated tokens removed from persistent context by the pruning filter, all time. */
    tokensSaved: number;
  };
  errorVelocity: { last10Min: number; perMinute: number };
  stagedApprovals: number;
  missions: { active: number; paused: number; quarantined: number; completed: number; killed: number };
}

export function computeMetrics(store: Store, tenantId: string, now: number): Metrics {
  let creditsLastMinute = 0;
  let creditsLastHour = 0;
  let errors = 0;
  for (let i = store.recent.length - 1; i >= 0; i--) {
    const r = store.recent[i]!;
    const age = now - Date.parse(r.ts);
    if (age > 3_600_000) break;
    if (r.tenantId !== tenantId) continue;
    if (r.type === 'meter.charge') {
      const c = Number(r.data.credits ?? 0);
      creditsLastHour += c;
      if (age <= 60_000) creditsLastMinute += c;
    }
    if (age <= 600_000 && ERROR_EVENTS.has(r.type)) errors++;
  }

  const missions = { active: 0, paused: 0, quarantined: 0, completed: 0, killed: 0 };
  let activeAgents = 0;
  let tokensSaved = 0;
  for (const m of Object.values(store.state.missions)) {
    if (m.tenantId !== tenantId) continue;
    missions[m.status]++;
    const step = m.steps[m.current];
    if ((m.status === 'active' || m.status === 'paused') && step?.lease && !step.lease.revoked && step.lease.expiresAt > now) {
      activeAgents++;
    }
    for (const s of m.steps) for (const a of s.attempts) tokensSaved += Math.max(0, a.rawTokens - a.prunedTokens);
  }

  return {
    activeAgents,
    spend: {
      balance: store.state.tenants[tenantId]?.credits ?? 0,
      creditsLastMinute,
      creditsLastHour,
      tokensSaved,
    },
    errorVelocity: { last10Min: errors, perMinute: Math.round((errors / 10) * 100) / 100 },
    stagedApprovals: Object.values(store.state.approvals).filter((a) => a.tenantId === tenantId && a.status === 'pending').length,
    missions,
  };
}
