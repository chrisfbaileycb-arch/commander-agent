import { describe, expect, it } from 'vitest';
import { tighten, type GateVerdict, type ReasoningGate } from '../src/gate.js';
import { computeMetrics } from '../src/metrics.js';
import { ANCHOR } from '../src/persona.js';
import { addTenant, codeOf, codeOfAsync, goodBuild, makeHarness, oneStep, pull, threeStep, type Harness } from './helpers.js';

const open = (h: Harness, def: unknown = threeStep()) => h.app.airlock.openMission(h.operator, def);
const proof = (h: Harness, missionId: string, leaseId: string, evidence: unknown) =>
  h.app.airlock.submitProof(h.worker, missionId, { lease_id: leaseId, evidence });
const clear = (h: Harness, missionId: string, leaseId: string, action: unknown) =>
  h.app.airlock.requestClearance(h.worker, missionId, { lease_id: leaseId, action });

describe('macro-context isolation', () => {
  it('shows a worker only the current step', async () => {
    const h = makeHarness();
    const m = open(h);
    const d = pull(h, m.id);
    const wire = JSON.stringify(d);
    expect(d.directive).toBe('Run the build and report.');
    expect(d.ledger).toEqual([]);
    expect(wire).not.toContain('SECRET-STEP-TWO');
    expect(wire).not.toContain('SECRET-STEP-THREE');
    expect(wire).not.toContain('Seal');
  });

  it('worker mission status reveals nothing about the plan', async () => {
    const h = makeHarness();
    const m = open(h);
    const s = h.app.airlock.missionStatus(h.worker, m.id);
    expect(Object.keys(s).sort()).toEqual(['message', 'mission_id', 'status']);
  });

  it('refuses proof for a step that was never released', async () => {
    const h = makeHarness();
    const m = open(h);
    expect(await codeOfAsync(() => proof(h, m.id, 'lse_made_up', { exit_code: 0 }))).toBe('CONFLICT');
  });

  it('step N+1 cannot be reached by guessing: a lease is bound to one step', async () => {
    const h = makeHarness();
    const m = open(h);
    const d1 = pull(h, m.id);
    await proof(h, m.id, d1.lease_id, goodBuild(d1.nonce));
    // The step-1 lease is revoked on pass; replaying it against step 2 must fail.
    pull(h, m.id);
    expect(await codeOfAsync(() => proof(h, m.id, d1.lease_id, { stdout: '{"total":1}' }))).toBe('LEASE_INVALID');
  });
});

describe('mechanical proof over self-report', () => {
  it('walks a lying worker through rejection, replay detection, and a real pass', async () => {
    const h = makeHarness();
    const m = open(h);
    const d = pull(h, m.id);
    expect(d.nonce).toBeTruthy();

    const lie = { exit_code: 1, stdout: 'BUILD FAILED', claim: 'All good, task complete!' };
    const r1 = await proof(h, m.id, d.lease_id, lie);
    expect(r1.verdict).toBe('REJECTED');
    expect(r1.checks.map((c) => c.type)).toEqual(['exit_code', 'regex', 'nonce_present']);
    expect(r1.checks.every((c) => !c.ok)).toBe(true);
    expect(r1.patch).toContain('[exit_code]');
    expect(r1.attempts_remaining).toBe(2);
    expect(r1.nonce).toBeTruthy();
    expect(r1.nonce).not.toBe(d.nonce);

    const r2 = await proof(h, m.id, d.lease_id, lie);
    expect(r2.verdict).toBe('REJECTED');
    expect(r2.checks.map((c) => c.type)).toEqual(['replay']);
    expect(r2.patch).toContain('Identical evidence');
    expect(r2.attempts_remaining).toBe(1);

    const r3 = await proof(h, m.id, d.lease_id, goodBuild(r2.nonce));
    expect(r3.verdict).toBe('PASSED');
    expect(r3.mission_complete).toBe(false);
    expect(r3.manifest).toContain('14 passed');

    const d2 = pull(h, m.id);
    expect(d2.directive).toContain('SECRET-STEP-TWO');
    expect(d2.attempt).toBe(1);
    expect(d2.ledger).toEqual([r3.manifest]);
  });

  it('a stale nonce from an earlier attempt does not pass', async () => {
    const h = makeHarness();
    const m = open(h);
    const d = pull(h, m.id);
    await proof(h, m.id, d.lease_id, { exit_code: 1, stdout: 'x' });
    expect((await proof(h, m.id, d.lease_id, goodBuild(d.nonce))).verdict).toBe('REJECTED');
  });

  it('records the untrusted claim for the operator but never lets it decide', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    const r = await proof(h, m.id, d.lease_id, { exit_code: 3, claim: 'exit code was 0' });
    expect(r.verdict).toBe('REJECTED');
    expect(h.app.airlock.getMission(h.operator, m.id).steps[0]!.attempts[0]!.claim).toBe('exit code was 0');
  });

  it('keeps hidden checks hidden from the worker, in the directive and in the patch', async () => {
    const h = makeHarness();
    const m = open(h, oneStep({ proof: [{ type: 'exit_code' }, { type: 'regex', pattern: 'topsecret-marker', hidden: true }] }));
    const d = pull(h, m.id);
    expect(d.hidden_checks).toBe(1);
    expect(JSON.stringify(d.proof_required)).not.toContain('topsecret');
    const r = await proof(h, m.id, d.lease_id, { exit_code: 0, stdout: 'nope' });
    expect(r.verdict).toBe('REJECTED');
    expect(r.checks.map((c) => c.type)).toEqual(['exit_code', 'hidden']);
    expect(JSON.stringify(r)).not.toContain('topsecret');
    // The operator sees everything.
    expect(JSON.stringify(h.app.airlock.getMission(h.operator, m.id))).toContain('topsecret-marker');
  });

  it('completes the mission after the last step and then refuses everything', async () => {
    const h = makeHarness();
    const m = open(h);
    const d1 = pull(h, m.id);
    await proof(h, m.id, d1.lease_id, goodBuild(d1.nonce));
    const d2 = pull(h, m.id);
    expect((await proof(h, m.id, d2.lease_id, { stdout: '{"total":"x"}' })).verdict).toBe('REJECTED');
    expect((await proof(h, m.id, d2.lease_id, { stdout: '{"total": 3}' })).verdict).toBe('PASSED');
    const d3 = pull(h, m.id);
    const last = await proof(h, m.id, d3.lease_id, { artifacts: { 'seal.txt': 'sealed' } });
    expect(last.verdict).toBe('PASSED');
    expect(last.mission_complete).toBe(true);
    expect(last.message).toMatch(/Mission closed/);

    expect(h.app.airlock.getDirective(h.worker, m.id).state).toBe('COMPLETE');
    expect(await codeOfAsync(() => proof(h, m.id, d3.lease_id, { artifacts: { 'seal.txt': 'again' } }))).toBe('CONFLICT');
    expect(h.app.airlock.getMission(h.operator, m.id).status).toBe('completed');
  });

  it('rejects malformed and oversize evidence', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 'zero' }))).toBe('INVALID');
    const big = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`f${i}.txt`, 'x'.repeat(200_000)]));
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 0, artifacts: big }))).toBe('PAYLOAD_TOO_LARGE');
  });
});

describe('leases', () => {
  it('rejects a wrong lease and an expired lease, then reissues on the next pull', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    expect(await codeOfAsync(() => proof(h, m.id, 'lse_wrong', { exit_code: 0 }))).toBe('LEASE_INVALID');

    h.clock.advance(1801 * 1000);
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 0 }))).toBe('LEASE_INVALID');
    const d2 = pull(h, m.id);
    expect(d2.lease_id).not.toBe(d.lease_id);
    expect((await proof(h, m.id, d2.lease_id, { exit_code: 0 })).verdict).toBe('PASSED');
  });

  it('pulling twice inside one lease is idempotent', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    expect(pull(h, m.id).lease_id).toBe(pull(h, m.id).lease_id);
  });
});

describe('quarantine', () => {
  const quarantined = async () => {
    const h = makeHarness();
    const m = open(h, oneStep({ max_attempts: 1 }));
    const d = pull(h, m.id);
    const r = await proof(h, m.id, d.lease_id, { exit_code: 1 });
    return { h, m, d, r };
  };

  it('revokes the lease, holds the mission, and stages an approval with a push card', async () => {
    const { h, m, d, r } = await quarantined();
    expect(r.verdict).toBe('QUARANTINED');
    const hold = h.app.airlock.getDirective(h.worker, m.id);
    expect(hold).toMatchObject({ state: 'HOLD', reason: 'quarantined' });
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 0 }))).toBe('HOLD');

    const pending = h.app.approvals.list(h.tenantId, 'pending');
    expect(pending).toHaveLength(1);
    expect(pending[0]!.kind).toBe('quarantine');
    expect(h.notifier.cards).toHaveLength(1);
    expect(h.notifier.cards[0]!.actions.map((a) => a.decision)).toEqual(['authorize', 'redirect', 'kill']);
    expect(h.notifier.cards[0]!.voice.class).toBe('Ursa');
  });

  it('authorize re-opens the step with a fresh attempt budget and a new lease', async () => {
    const { h, m, d } = await quarantined();
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    const d2 = pull(h, m.id);
    expect(d2.lease_id).not.toBe(d.lease_id);
    expect(d2.attempt).toBe(2);
    expect(d2.max_attempts).toBe(2);
    const done = await proof(h, m.id, d2.lease_id, { exit_code: 0 });
    expect(done.verdict).toBe('PASSED');
    expect(done.mission_complete).toBe(true);
  });

  it('redirect re-opens the step and delivers the operator note behind the Deductive Anchor', async () => {
    const { h, m } = await quarantined();
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'redirect', 'Use the replica database.', 'operator');
    const d2 = pull(h, m.id);
    expect(d2.directive).toContain(ANCHOR);
    expect(d2.directive).toContain('Use the replica database.');
  });

  it('kill terminates the mission for good', async () => {
    const { h, m } = await quarantined();
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'kill', undefined, 'operator');
    expect(h.app.airlock.getDirective(h.worker, m.id).state).toBe('TERMINATED');
    expect(h.app.airlock.getMission(h.operator, m.id).status).toBe('killed');
    expect(h.app.approvals.get(h.tenantId, a.id).status).toBe('killed');
  });

  it('a decision applies exactly once', async () => {
    const { h } = await quarantined();
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    expect(codeOf(() => h.app.airlock.decideApproval(h.tenantId, a.id, 'kill', undefined, 'operator'))).toBe('CONFLICT');
  });

  it('operator skip closes a quarantined step without proof and says so in the ledger', async () => {
    const h = makeHarness();
    const m = open(h, {
      title: 'Two',
      steps: [
        { title: 'Flaky', directive: 'a', proof: [{ type: 'exit_code' }], max_attempts: 1 },
        { title: 'Next', directive: 'b', proof: [{ type: 'exit_code' }] },
      ],
    });
    const d = pull(h, m.id);
    await proof(h, m.id, d.lease_id, { exit_code: 1 });
    h.app.airlock.intervene(h.operator, m.id, { action: 'skip', reason: 'known flaky upstream' });
    expect(h.app.approvals.list(h.tenantId, 'pending')).toHaveLength(0);
    const d2 = pull(h, m.id);
    expect(d2.directive).toBe('b');
    expect(d2.ledger[0]).toMatch(/skipped by operator/);
  });

  it('skip is only for quarantined steps, and every intervention needs a reason', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    pull(h, m.id);
    expect(codeOf(() => h.app.airlock.intervene(h.operator, m.id, { action: 'skip', reason: 'because' }))).toBe('CONFLICT');
    expect(codeOf(() => h.app.airlock.intervene(h.operator, m.id, { action: 'kill', reason: '   ' }))).toBe('INVALID');
    h.app.airlock.intervene(h.operator, m.id, { action: 'kill', reason: 'stop' });
    expect(codeOf(() => h.app.airlock.intervene(h.operator, m.id, { action: 'kill', reason: 'again' }))).toBe('CONFLICT');
  });
});

describe('roles and tenant isolation', () => {
  it('workers cannot operate and operators cannot work', async () => {
    const h = makeHarness();
    expect(codeOf(() => h.app.airlock.openMission(h.worker, oneStep()))).toBe('FORBIDDEN');
    const m = open(h, oneStep());
    expect(codeOf(() => h.app.airlock.getDirective(h.operator, m.id))).toBe('FORBIDDEN');
    expect(codeOf(() => h.app.airlock.listMissions(h.worker))).toBe('FORBIDDEN');
  });

  it("another tenant sees nothing: every lookup of someone else's record is NOT_FOUND", async () => {
    const h = makeHarness();
    const rival = addTenant(h);
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    expect(codeOf(() => h.app.airlock.getDirective(rival.worker, m.id))).toBe('NOT_FOUND');
    expect(codeOf(() => h.app.airlock.getMission(rival.operator, m.id))).toBe('NOT_FOUND');
    expect(h.app.airlock.listMissions(rival.operator)).toEqual([]);
    expect(await codeOfAsync(() => h.app.airlock.submitProof(rival.worker, m.id, { lease_id: d.lease_id, evidence: { exit_code: 0 } }))).toBe('NOT_FOUND');

    const c = await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE t ADD c int' });
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    expect(codeOf(() => h.app.airlock.clearanceStatus(rival.worker, c.clearance_id))).toBe('NOT_FOUND');
    expect(codeOf(() => h.app.airlock.decideApproval(rival.operator.tenantId, a.id, 'authorize', undefined, 'operator'))).toBe('NOT_FOUND');
  });

  it('prototype-chain ids are just unknown ids', async () => {
    const h = makeHarness();
    for (const id of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(codeOf(() => h.app.airlock.getDirective(h.worker, id))).toBe('NOT_FOUND');
    }
  });
});

describe('mission definition validation', () => {
  it.each([
    ['no steps', { title: 'x', steps: [] }],
    ['no title', { steps: [{ title: 't', directive: 'd', proof: [{ type: 'exit_code' }] }] }],
    ['unparseable regex', oneStep({ proof: [{ type: 'regex', pattern: '([bad' }] })],
    ['uncompilable schema', oneStep({ proof: [{ type: 'json_schema', schema: { type: 'not-a-type' } }] })],
    ['nonce-only proof', oneStep({ proof: [{ type: 'nonce_present' }] })],
    ['unknown verifier', oneStep({ proof: [{ type: 'vibes_check' }] })],
  ])('rejects %s', (_name, def) => {
    const h = makeHarness();
    expect(codeOf(() => open(h, def))).toBe('INVALID');
  });
});

describe('metering and burn throttling', () => {
  it('charges per operation and refuses at zero', async () => {
    const h = makeHarness({ credits: 3 });
    const m = open(h, {
      title: 'Two',
      steps: [
        { title: 'a', directive: 'a', proof: [{ type: 'exit_code' }] },
        { title: 'b', directive: 'b', proof: [{ type: 'exit_code' }] },
      ],
    });
    const d = pull(h, m.id);
    expect(h.app.auth.balance(h.tenantId)).toBe(2);
    await proof(h, m.id, d.lease_id, { exit_code: 0 });
    expect(h.app.auth.balance(h.tenantId)).toBe(0);
    expect(codeOf(() => h.app.airlock.getDirective(h.worker, m.id))).toBe('CREDITS_EXHAUSTED');
  });

  it('does not charge for holds or for refused requests', async () => {
    const h = makeHarness({ credits: 100 });
    const m = open(h, oneStep({ max_attempts: 1 }));
    const d = pull(h, m.id);
    await proof(h, m.id, d.lease_id, { exit_code: 1 });
    const before = h.app.auth.balance(h.tenantId);
    for (let i = 0; i < 5; i++) h.app.airlock.getDirective(h.worker, m.id);
    await codeOfAsync(() => proof(h, m.id, 'lse_wrong', { exit_code: 0 }));
    expect(h.app.auth.balance(h.tenantId)).toBe(before);
  });

  it('throttles a mission that burns too fast, spends nothing while throttled, and recovers', async () => {
    const h = makeHarness({ policy: { burn_limit_per_min: 3 }, credits: 100 });
    const m = open(h, oneStep());
    for (let i = 0; i < 3; i++) pull(h, m.id);
    const balance = h.app.auth.balance(h.tenantId);
    let err: unknown;
    try {
      h.app.airlock.getDirective(h.worker, m.id);
    } catch (e) {
      err = e;
    }
    expect((err as { code: string }).code).toBe('THROTTLED');
    expect((err as { details: { retryAfter: number } }).details.retryAfter).toBeGreaterThanOrEqual(1);
    expect(h.app.auth.balance(h.tenantId)).toBe(balance);
    h.clock.advance(61_000);
    expect(pull(h, m.id).state).toBe('DIRECTIVE');
  });
});

describe('action clearance', () => {
  const start = (def: unknown = oneStep(), h = makeHarness()) => {
    const m = open(h, def);
    const d = pull(h, m.id);
    return { h, m, d };
  };

  it('denies a destructive action with a redirect patch and stages nothing', async () => {
    const { h, m, d } = start();
    const r = await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'DROP TABLE users;' });
    expect(r.verdict).toBe('DENIED');
    expect(r.patch).toContain('sql.drop');
    expect(h.app.approvals.list(h.tenantId)).toHaveLength(0);
    expect(h.app.airlock.clearanceStatus(h.worker, r.clearance_id).status).toBe('DENIED');
    expect(h.app.airlock.missionStatus(h.worker, m.id).status).toBe('active');
  });

  it('clears routine work immediately', async () => {
    const { h, m, d } = start();
    const r = await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' });
    expect(r.verdict).toBe('CLEARED');
    expect(h.app.airlock.clearanceStatus(h.worker, r.clearance_id).status).toBe('CLEARED');
  });

  it('stages a schema change: pauses the mission, pushes a card, then resumes on authorize', async () => {
    const { h, m, d } = start();
    const r = await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE users ADD COLUMN age int' });
    expect(r.verdict).toBe('STAGED');
    expect(h.app.airlock.clearanceStatus(h.worker, r.clearance_id).status).toBe('PENDING');
    expect(h.app.airlock.missionStatus(h.worker, m.id).status).toBe('paused');
    expect(h.app.airlock.getDirective(h.worker, m.id)).toMatchObject({ state: 'HOLD', reason: 'awaiting_operator' });
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 0 }))).toBe('HOLD');

    expect(h.notifier.cards).toHaveLength(1);
    expect(h.notifier.cards[0]!.incident).toContain('ALTER TABLE');
    expect(h.notifier.cards[0]!.reason).toMatch(/Schema change/);

    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    const status = h.app.airlock.clearanceStatus(h.worker, r.clearance_id);
    expect(status.status).toBe('CLEARED');
    expect(status.message).toMatch(/Operator authorized/);
    expect((await proof(h, m.id, d.lease_id, { exit_code: 0 })).verdict).toBe('PASSED');
  });

  it('keeps the lease alive across a long approval wait', async () => {
    const { h, m, d } = start();
    await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE t ADD c int' });
    h.clock.advance(1700 * 1000);
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    h.clock.advance(1700 * 1000);
    expect((await proof(h, m.id, d.lease_id, { exit_code: 0 })).verdict).toBe('PASSED');
  });

  it('a redirect denies the clearance and carries the note behind the Deductive Anchor', async () => {
    const { h, m, d } = start();
    const r = await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE t ADD c int' });
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'redirect', 'Add the column in the migration file instead.', 'operator');
    const status = h.app.airlock.clearanceStatus(h.worker, r.clearance_id);
    expect(status.status).toBe('DENIED');
    expect(status.message).toContain(ANCHOR);
    expect(status.message).toContain('migration file');
    expect(h.app.airlock.missionStatus(h.worker, m.id).status).toBe('active');
  });

  it('a kill from the approval terminates the mission and revokes the lease', async () => {
    const { h, m, d } = start();
    const r = await clear(h, m.id, d.lease_id, { kind: 'payment', payload: 'refund order 42' });
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'kill', undefined, 'operator');
    expect(h.app.airlock.clearanceStatus(h.worker, r.clearance_id).status).toBe('TERMINATED');
    expect(h.app.airlock.getDirective(h.worker, m.id).state).toBe('TERMINATED');
    expect(await codeOfAsync(() => proof(h, m.id, d.lease_id, { exit_code: 0 }))).toBe('HOLD');
  });

  it('redacts credentials from what the operator is shown', async () => {
    const { h, m, d } = start();
    await clear(h, m.id, d.lease_id, {
      kind: 'sql',
      payload: '-- connect postgres://admin:hunter22@db.internal/app\nALTER TABLE t ADD c int',
    });
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    expect(a.incident).not.toContain('hunter22');
    expect(JSON.stringify(h.notifier.cards)).not.toContain('hunter22');
  });

  it('critical steps stage every mutating action, but not declared reads', async () => {
    const { h, m, d } = start(oneStep({ risk_tier: 'critical' }));
    expect((await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'ls', intent: 'read' })).verdict).toBe('CLEARED');
    const r = await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'ls -la' });
    expect(r.verdict).toBe('STAGED');
    expect(r.findings.some((f) => f.rule === 'tier.critical')).toBe(true);
  });

  it('requires a live lease and a well-formed action', async () => {
    const { h, m, d } = start();
    expect(await codeOfAsync(() => clear(h, m.id, 'lse_wrong', { kind: 'shell', payload: 'ls' }))).toBe('LEASE_INVALID');
    expect(await codeOfAsync(() => clear(h, m.id, d.lease_id, { kind: 'bogus', payload: 'ls' }))).toBe('INVALID');
    expect(await codeOfAsync(() => clear(h, m.id, d.lease_id, { kind: 'shell', payload: '' }))).toBe('INVALID');
  });

  it('a repeated identical action is treated as a loop and denied', async () => {
    const { h, m, d } = start(oneStep(), makeHarness({ policy: { repetition_threshold: 3 } }));
    const act = { kind: 'shell', payload: 'npm test' };
    expect((await clear(h, m.id, d.lease_id, act)).verdict).toBe('CLEARED');
    expect((await clear(h, m.id, d.lease_id, act)).verdict).toBe('CLEARED');
    const third = await clear(h, m.id, d.lease_id, act);
    expect(third.verdict).toBe('DENIED');
    expect(third.patch).toContain('loop.repetition');
  });
});

describe('reasoning gate', () => {
  class SpyGate implements ReasoningGate {
    readonly active = true;
    calls = 0;
    constructor(
      private readonly verdict: GateVerdict,
      private readonly onReview?: () => void,
    ) {}
    async review() {
      this.calls++;
      this.onReview?.();
      return { verdict: this.verdict, rationale: 'because I said so' };
    }
  }
  const elevated = () => oneStep({ risk_tier: 'elevated' });

  it('can tighten an allowed action to denied, and meters the review', async () => {
    const gate = new SpyGate('deny');
    const h = makeHarness({ gate, credits: 100 });
    const m = open(h, elevated());
    const d = pull(h, m.id);
    const before = h.app.auth.balance(h.tenantId);
    const r = await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' });
    expect(r.verdict).toBe('DENIED');
    expect(r.findings.some((f) => f.rule === 'gate.reasoning')).toBe(true);
    expect(gate.calls).toBe(1);
    expect(before - h.app.auth.balance(h.tenantId)).toBe(1 + 5);
  });

  it('can tighten an allowed action to staged', async () => {
    const h = makeHarness({ gate: new SpyGate('stage') });
    const m = open(h, elevated());
    const d = pull(h, m.id);
    expect((await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' })).verdict).toBe('STAGED');
  });

  it('is not consulted on routine steps', async () => {
    const gate = new SpyGate('deny');
    const h = makeHarness({ gate });
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    expect((await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' })).verdict).toBe('CLEARED');
    expect(gate.calls).toBe(0);
  });

  it('is never consulted for what the rules already denied, so it cannot loosen anything', async () => {
    const gate = new SpyGate('allow');
    const h = makeHarness({ gate });
    const m = open(h, elevated());
    const d = pull(h, m.id);
    expect((await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'rm -rf /' })).verdict).toBe('DENIED');
    expect((await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE t ADD c int' })).verdict).toBe('STAGED');
    expect(gate.calls).toBe(0);
  });

  it('an allow verdict from the gate does not grant more than the rules did', async () => {
    const h = makeHarness({ gate: new SpyGate('allow') });
    const m = open(h, elevated());
    const d = pull(h, m.id);
    expect((await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' })).verdict).toBe('CLEARED');
  });

  it('without a gate configured, elevated steps cost nothing extra', async () => {
    const h = makeHarness({ credits: 100 });
    const m = open(h, elevated());
    const d = pull(h, m.id);
    const before = h.app.auth.balance(h.tenantId);
    await clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' });
    expect(before - h.app.auth.balance(h.tenantId)).toBe(1);
  });

  it('refuses to act if the mission was killed while the gate deliberated', async () => {
    let missionId = '';
    let hh: Harness | undefined;
    const gate = new SpyGate('allow', () => hh!.app.airlock.intervene(hh!.operator, missionId, { action: 'kill', reason: 'operator pulled the plug' }));
    const h = makeHarness({ gate });
    hh = h;
    const m = open(h, elevated());
    missionId = m.id;
    const d = pull(h, m.id);
    expect(await codeOfAsync(() => clear(h, m.id, d.lease_id, { kind: 'shell', payload: 'npm test' }))).toBe('LEASE_INVALID');
    expect(Object.keys(h.app.store.state.clearances)).toHaveLength(0);
  });

  it('tighten() only ever moves toward the stricter verdict', async () => {
    const order: GateVerdict[] = ['allow', 'stage', 'deny'];
    for (const a of order) for (const b of order) {
      expect(tighten(a, b)).toBe(order[Math.max(order.indexOf(a), order.indexOf(b))]);
    }
  });
});

describe('telemetry and audit', () => {
  it('derives HUD metrics from the ledger', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    const noisy = Array.from({ length: 200 }, (_, i) => `line ${i} of chatter`).join('\n');
    await proof(h, m.id, d.lease_id, { exit_code: 1, stdout: noisy });
    await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'DROP TABLE users' });
    await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'ALTER TABLE t ADD c int' });

    const x = computeMetrics(h.app.store, h.tenantId, h.clock.now());
    expect(x.activeAgents).toBe(1);
    expect(x.stagedApprovals).toBe(1);
    expect(x.errorVelocity.last10Min).toBe(2);
    expect(x.spend.creditsLastMinute).toBe(1 + 2 + 1 + 1);
    expect(x.spend.tokensSaved).toBeGreaterThan(0);
    expect(x.missions.paused).toBe(1);
  });

  it('keeps a verifiable, hash-chained record of everything above', async () => {
    const h = makeHarness();
    const m = open(h, oneStep());
    const d = pull(h, m.id);
    await proof(h, m.id, d.lease_id, { exit_code: 1 });
    await clear(h, m.id, d.lease_id, { kind: 'sql', payload: 'DROP TABLE users' });
    await proof(h, m.id, d.lease_id, { exit_code: 0 });
    const types = h.app.store.tenantAudit(h.tenantId, 100).map((r) => r.type);
    for (const t of ['mission.opened', 'directive.issued', 'proof.rejected', 'clearance.denied', 'proof.accepted', 'mission.completed', 'meter.charge']) {
      expect(types).toContain(t);
    }
    expect(h.app.store.verify()).toMatchObject({ ok: true });
  });
});
