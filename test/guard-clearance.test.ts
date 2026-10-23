import { describe, expect, it } from 'vitest';
import type { GateInput, GateOutput, ReasoningGate } from '../src/gate.js';
import type { ActionRequest } from '../src/types.js';
import { addTenant, codeOfAsync, makeHarness, oneStep, pull } from './helpers.js';

// Fake credentials are assembled at runtime so that no literal in the repository resembles a real one to a secret scanner.
const AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');

const sh = (payload: string, extra: Partial<ActionRequest> = {}): ActionRequest => ({ kind: 'shell', payload, ...extra });
const DEPLOY = 'kubectl apply -f prod.yaml';

/** A mission whose worker has pulled its directive (and so holds a lease), asked about native actions as the hook would. */
function setup(over: Parameters<typeof makeHarness>[0] = {}, def: unknown = oneStep()) {
  const h = makeHarness(over);
  const m = h.app.airlock.openMission(h.operator, def);
  const d = pull(h, m.id);
  const guard = (action: ActionRequest, tool = 'Bash') => h.app.airlock.requestGuardClearance(h.worker, m.id, { action, tool });
  const mcp = (action: ActionRequest) => h.app.airlock.requestClearance(h.worker, m.id, { lease_id: d.lease_id, action });
  const pending = () => h.app.approvals.list(h.tenantId, 'pending');
  const authorize = () => {
    const a = pending().at(-1)!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    return a;
  };
  const audit = (type: string) => h.app.store.tenantAudit(h.tenantId, 200).filter((r) => r.type === type);
  const status = () => h.app.airlock.getMission(h.operator, m.id).status;
  return { h, m, d, guard, mcp, pending, authorize, audit, status };
}

describe('requestGuardClearance: judging a native tool call', () => {
  it('clears ordinary work without being given a lease id, and records that it came from the guard', async () => {
    const { guard, audit } = setup();
    const r = await guard(sh('ls -la'));
    expect(r.verdict).toBe('CLEARED');
    const rec = audit('clearance.allowed')[0]!;
    expect(rec.data).toMatchObject({ via: 'guard', tool: 'Bash', kind: 'shell' });
  });

  it('denies with the same redirect patch the MCP route gives, and stages nothing', async () => {
    const { guard, pending, status } = setup();
    const r = await guard(sh('rm -rf /'));
    expect(r.verdict).toBe('DENIED');
    expect(r.patch).toContain('[shell.rm-destructive]');
    expect(pending()).toHaveLength(0);
    expect(status()).toBe('active');
  });

  it('judges file tools by path', async () => {
    const { guard } = setup();
    expect((await guard({ kind: 'fs', payload: 'src/a.ts', intent: 'write' }, 'Write')).verdict).toBe('CLEARED');
    expect((await guard({ kind: 'fs', payload: 'config/.env.production', intent: 'write' }, 'Edit')).verdict).toBe('DENIED');
    const cfg = await guard({ kind: 'fs', payload: '.claude/settings.json', intent: 'write' }, 'Write');
    expect(cfg.verdict).toBe('DENIED');
    expect(cfg.findings.map((f) => f.rule)).toContain('fs.agent-config');
  });

  it('refuses the agent the ability to edit the guard through the shell, by staging it for a human', async () => {
    const { guard } = setup();
    const r = await guard(sh("sed -i '/PreToolUse/d' .claude/settings.json"));
    expect(r.verdict).toBe('STAGED');
    expect(r.findings.map((f) => f.rule)).toContain('shell.agent-config');
  });

  it('applies loop detection to native calls too', async () => {
    const { guard } = setup({ policy: { repetition_threshold: 3 } });
    expect((await guard(sh('npm test'))).verdict).toBe('CLEARED');
    expect((await guard(sh('npm test'))).verdict).toBe('CLEARED');
    const third = await guard(sh('npm test'));
    expect(third.verdict).toBe('DENIED');
    expect(third.findings.map((f) => f.rule)).toContain('loop.repetition');
  });

  it('charges the clearance fee and refuses when the tenant is out of credits', async () => {
    const { h, guard } = setup({ credits: 3 }); // 1 spent on the directive
    const before = h.app.auth.balance(h.tenantId);
    await guard(sh('ls'));
    expect(before - h.app.auth.balance(h.tenantId)).toBe(1);
    await guard(sh('ls src'));
    expect(await codeOfAsync(() => guard(sh('ls docs')))).toBe('CREDITS_EXHAUSTED');
  });

  it('rejects an action it cannot parse', async () => {
    const { guard } = setup();
    for (const bad of [{ kind: 'shell' }, { kind: 'shell', payload: '' }, { kind: 'teleport', payload: 'x' }, 'ls', null]) {
      expect(await codeOfAsync(() => guard(bad as unknown as ActionRequest)), JSON.stringify(bad)).toBe('INVALID');
    }
  });

  describe('who may ask, and when', () => {
    it('is a worker call: an operator key is refused', async () => {
      const { h, m } = setup();
      expect(await codeOfAsync(() => h.app.airlock.requestGuardClearance(h.operator, m.id, { action: sh('ls') }))).toBe('FORBIDDEN');
    });

    it("cannot reach another tenant's mission", async () => {
      const { h, m } = setup();
      const rival = addTenant(h);
      expect(await codeOfAsync(() => h.app.airlock.requestGuardClearance(rival.worker, m.id, { action: sh('ls') }))).toBe('NOT_FOUND');
      expect(await codeOfAsync(() => h.app.airlock.requestGuardClearance(h.worker, 'msn_nope', { action: sh('ls') }))).toBe('NOT_FOUND');
    });

    it('needs a released step and a live lease: nothing is cleared before the worker has pulled a directive', async () => {
      const h = makeHarness();
      const m = h.app.airlock.openMission(h.operator, oneStep());
      // The step is not released yet, so there is nothing for the action to be judged against.
      await expect(h.app.airlock.requestGuardClearance(h.worker, m.id, { action: sh('ls') })).rejects.toMatchObject({
        code: 'CONFLICT',
        message: expect.stringContaining('Pull one first'),
      });
      pull(h, m.id);
      expect((await h.app.airlock.requestGuardClearance(h.worker, m.id, { action: sh('ls') })).verdict).toBe('CLEARED');
    });

    it('stops clearing once the lease has expired, and resumes after a fresh directive', async () => {
      const { h, m, guard } = setup();
      h.clock.advance(1801 * 1000);
      expect(await codeOfAsync(() => guard(sh('ls')))).toBe('LEASE_INVALID');
      pull(h, m.id);
      expect((await guard(sh('ls'))).verdict).toBe('CLEARED');
    });

    it('holds while the mission is paused, killed or finished', async () => {
      const paused = setup();
      await paused.guard(sh(DEPLOY));
      expect(await codeOfAsync(() => paused.guard(sh('ls')))).toBe('HOLD');

      const killed = setup();
      killed.h.app.airlock.intervene(killed.h.operator, killed.m.id, { action: 'kill', reason: 'enough' });
      expect(await codeOfAsync(() => killed.guard(sh('ls')))).toBe('HOLD');

      const done = setup();
      await done.h.app.airlock.submitProof(done.h.worker, done.m.id, { lease_id: done.d.lease_id, evidence: { exit_code: 0 } });
      expect(done.status()).toBe('completed');
      expect(await codeOfAsync(() => done.guard(sh('ls')))).toBe('CONFLICT');
    });
  });
});

describe('requestGuardClearance: staging and single-use operator authorization', () => {
  it('stages a production-impacting call, pauses the mission and pushes a card naming it as a native call', async () => {
    const { h, guard, pending, status, audit } = setup();
    const r = await guard(sh(DEPLOY));
    expect(r.verdict).toBe('STAGED');
    expect(r.findings.map((f) => f.rule)).toContain('shell.production-change');
    expect(status()).toBe('paused');
    expect(pending()).toHaveLength(1);
    expect(pending()[0]!.incident).toMatch(/^NATIVE Bash: kubectl apply/);
    expect(JSON.stringify(h.notifier.cards)).toContain('NATIVE Bash');
    expect(audit('clearance.staged')[0]!.data).toMatchObject({ via: 'guard', tool: 'Bash' });
  });

  it('never puts a credential from the command into the approval or the notification', async () => {
    const { h, guard, pending } = setup();
    const r = await guard(sh(`${DEPLOY} # token=${AWS_KEY}`));
    expect(r.verdict).toBe('STAGED');
    expect(JSON.stringify([pending(), h.notifier.cards, h.app.store.tenantAudit(h.tenantId, 200)])).not.toContain(AWS_KEY);
  });

  it('lets the authorized retry through exactly once', async () => {
    const { guard, authorize, status, audit, pending } = setup();
    await guard(sh(DEPLOY));
    authorize();
    expect(status()).toBe('active');

    const retry = await guard(sh(DEPLOY));
    expect(retry.verdict).toBe('CLEARED');
    expect(audit('clearance.allowed').at(-1)!.data).toMatchObject({ via: 'guard', authorized: true });

    // The pass is spent. The same action is judged afresh and staged again.
    const again = await guard(sh(DEPLOY));
    expect(again.verdict).toBe('STAGED');
    expect(pending()).toHaveLength(1);
  });

  it('covers only that action: a different one is staged on its own merits', async () => {
    const { guard, authorize } = setup();
    await guard(sh(DEPLOY));
    authorize();
    expect((await guard(sh('kubectl apply -f other.yaml'))).verdict).toBe('STAGED');
  });

  it('treats the same action written with different spacing as the same action', async () => {
    const { guard, authorize } = setup();
    await guard(sh(DEPLOY));
    authorize();
    expect((await guard(sh(`  kubectl   apply  -f   prod.yaml `))).verdict).toBe('CLEARED');
  });

  it('is not a pass for other actions of the same kind', async () => {
    const { guard, authorize } = setup();
    await guard(sh('kubectl delete pod web-1'));
    authorize();
    expect((await guard(sh('kubectl delete pod web-2'))).verdict).toBe('STAGED');
  });

  it('expires with the lease lifetime: an authorization nobody used does not linger', async () => {
    const { h, m, guard, authorize } = setup();
    await guard(sh(DEPLOY));
    authorize();
    h.clock.advance(1801 * 1000);
    expect(await codeOfAsync(() => guard(sh(DEPLOY)))).toBe('LEASE_INVALID');
    pull(h, m.id);
    expect((await guard(sh(DEPLOY))).verdict).toBe('STAGED'); // the old authorization is not honoured
  });

  it('is still honoured late in its lifetime', async () => {
    const { h, guard, authorize } = setup();
    await guard(sh(DEPLOY));
    authorize();
    h.clock.advance(1700 * 1000);
    expect((await guard(sh(DEPLOY))).verdict).toBe('CLEARED');
  });

  it('is not forged by an MCP-route clearance: only an authorization of a native call counts', async () => {
    const { guard, mcp, authorize } = setup();
    expect((await mcp(sh(DEPLOY))).verdict).toBe('STAGED');
    authorize();
    expect((await guard(sh(DEPLOY))).verdict).toBe('STAGED');
  });

  it('does not survive a redirect or a kill', async () => {
    const redirected = setup();
    await redirected.guard(sh(DEPLOY));
    const a = redirected.pending()[0]!;
    redirected.h.app.airlock.decideApproval(redirected.h.tenantId, a.id, 'redirect', 'Use the staging cluster.', 'operator');
    expect((await redirected.guard(sh(DEPLOY))).verdict).toBe('STAGED');

    const killed = setup();
    await killed.guard(sh(DEPLOY));
    killed.h.app.airlock.decideApproval(killed.h.tenantId, killed.pending()[0]!.id, 'kill', undefined, 'operator');
    expect(await codeOfAsync(() => killed.guard(sh(DEPLOY)))).toBe('HOLD');
  });

  it('is scoped to its step: it does not carry over to the next', async () => {
    const two = { title: 't', steps: [oneStep().steps[0], { title: 'Second', directive: 'Next.', proof: [{ type: 'exit_code' }] }] };
    const { h, m, d, guard, authorize } = setup({}, two);
    await guard(sh(DEPLOY));
    authorize();
    await h.app.airlock.submitProof(h.worker, m.id, { lease_id: d.lease_id, evidence: { exit_code: 0 } });
    pull(h, m.id);
    expect((await guard(sh(DEPLOY))).verdict).toBe('STAGED');
  });
});

describe('requestGuardClearance: risk tiers and the reasoning gate', () => {
  it('stages every mutating native call on a critical step, even a harmless-looking one', async () => {
    const { guard } = setup({}, oneStep({ risk_tier: 'critical' }));
    const r = await guard(sh('ls'));
    expect(r.verdict).toBe('STAGED');
    expect(r.findings.map((f) => f.rule)).toContain('tier.critical');
    const read = setup({}, oneStep({ risk_tier: 'critical' }));
    expect((await read.guard(sh('ls', { intent: 'read' }))).verdict).toBe('CLEARED');
  });

  it('consults the reasoning gate on elevated steps, and the gate can only tighten', async () => {
    const seen: GateInput[] = [];
    const gate = (verdict: GateOutput['verdict']): ReasoningGate => ({
      active: true,
      review: async (input) => {
        seen.push(input);
        return { verdict, rationale: `gate says ${verdict}` };
      },
    });

    const denies = setup({ gate: gate('deny') }, oneStep({ risk_tier: 'elevated' }));
    const r = await denies.guard(sh('ls'));
    expect(r.verdict).toBe('DENIED');
    expect(r.findings.map((f) => f.rule)).toContain('gate.reasoning');
    expect(seen[0]!.action.payload).toBe('ls');

    const allows = setup({ gate: gate('allow') }, oneStep({ risk_tier: 'elevated' }));
    expect((await allows.guard(sh('ls'))).verdict).toBe('CLEARED');
    // A gate that says "allow" cannot rescue what the rules denied.
    expect((await allows.guard(sh('rm -rf /'))).verdict).toBe('DENIED');
  });

  it('skips the gate on routine steps', async () => {
    let calls = 0;
    const gate: ReasoningGate = {
      active: true,
      review: async () => {
        calls++;
        return { verdict: 'deny', rationale: 'x' };
      },
    };
    const { guard } = setup({ gate });
    expect((await guard(sh('ls'))).verdict).toBe('CLEARED');
    expect(calls).toBe(0);
  });
});

describe('clearance status', () => {
  it('reports a guard clearance by id like any other', async () => {
    const { h, guard, authorize } = setup();
    const staged = await guard(sh(DEPLOY));
    expect(h.app.airlock.clearanceStatus(h.worker, staged.clearance_id).status).toBe('PENDING');
    authorize();
    expect(h.app.airlock.clearanceStatus(h.worker, staged.clearance_id).status).toBe('CLEARED');
  });
});
