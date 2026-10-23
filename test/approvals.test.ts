import { describe, expect, it, vi } from 'vitest';
import { LinkSigner, WebhookNotifier, type ActionCard, type Notifier } from '../src/approvals.js';
import { VOICE_PROFILE } from '../src/persona.js';
import { makeHarness, oneStep, pull } from './helpers.js';

describe('LinkSigner', () => {
  const signer = new LinkSigner('secret-a');
  const now = Date.UTC(2026, 0, 1, 12);
  const exp = Math.floor(now / 1000) + 600;
  const sig = signer.sign('apr_1', 'authorize', exp);

  it('accepts a fresh, correctly scoped signature', () => {
    expect(signer.verify('apr_1', 'authorize', exp, sig, now)).toBe(true);
  });
  it('rejects expiry, including the exact expiry instant', () => {
    expect(signer.verify('apr_1', 'authorize', exp, sig, exp * 1000)).toBe(false);
    expect(signer.verify('apr_1', 'authorize', exp, sig, (exp + 1) * 1000)).toBe(false);
  });
  it('binds the signature to the decision, the approval and the secret', () => {
    expect(signer.verify('apr_1', 'kill', exp, sig, now)).toBe(false);
    expect(signer.verify('apr_2', 'authorize', exp, sig, now)).toBe(false);
    expect(new LinkSigner('secret-b').verify('apr_1', 'authorize', exp, sig, now)).toBe(false);
  });
  it('binds the signature to the expiry, so a link cannot be extended', () => {
    expect(signer.verify('apr_1', 'authorize', exp + 3600, sig, now)).toBe(false);
  });
  it('rejects tampered, truncated, empty and malformed input without throwing', () => {
    const flipped = sig.slice(0, -1) + (sig.endsWith('A') ? 'B' : 'A');
    expect(signer.verify('apr_1', 'authorize', exp, flipped, now)).toBe(false);
    expect(signer.verify('apr_1', 'authorize', exp, sig.slice(0, 10), now)).toBe(false);
    expect(signer.verify('apr_1', 'authorize', exp, '', now)).toBe(false);
    expect(signer.verify('apr_1', 'authorize', Number.NaN, sig, now)).toBe(false);
    expect(signer.verify('apr_1', 'authorize', exp + 0.5, sig, now)).toBe(false);
  });
});

describe('Approvals.links', () => {
  it('issues a view link and one signed POST endpoint per decision', () => {
    const h = makeHarness();
    const links = h.app.approvals.links('apr_x');
    const now = h.clock.now();

    const view = new URL(links.view);
    expect(view.pathname).toBe('/a/apr_x');
    const vsig = view.searchParams.get('sig')!;
    expect(h.app.approvals.signer.verify('apr_x', 'view', links.exp, vsig, now)).toBe(true);
    expect(h.app.approvals.signer.verify('apr_x', 'authorize', links.exp, vsig, now)).toBe(false);

    expect(links.actions.map((a) => a.decision)).toEqual(['authorize', 'redirect', 'kill']);
    for (const a of links.actions) {
      const u = new URL(a.url);
      expect(u.pathname).toBe('/a/apr_x/decide');
      expect(u.searchParams.get('d')).toBe(a.decision);
      const s = u.searchParams.get('sig')!;
      expect(h.app.approvals.signer.verify('apr_x', a.decision, links.exp, s, now)).toBe(true);
      const other = a.decision === 'kill' ? 'authorize' : 'kill';
      expect(h.app.approvals.signer.verify('apr_x', other, links.exp, s, now)).toBe(false);
    }
  });
});

describe('WebhookNotifier', () => {
  const card: ActionCard = {
    approvalId: 'apr_1',
    kind: 'clearance',
    title: 'STAGED · Mission · Step',
    incident: 'SQL: ALTER TABLE t ADD c int',
    reason: 'Schema change.',
    url: 'https://c.example/a/apr_1?exp=1&sig=x',
    actions: [
      { decision: 'authorize', label: 'Authorize', url: 'https://c.example/a/apr_1/decide?d=authorize' },
      { decision: 'redirect', label: 'Redirect', url: 'https://c.example/a/apr_1/decide?d=redirect' },
      { decision: 'kill', label: 'Kill', url: 'https://c.example/a/apr_1/decide?d=kill' },
    ],
    voice: VOICE_PROFILE,
  };

  it('posts an ntfy-shaped card with POST actions and the voice profile', async () => {
    const f = vi.fn(async () => new Response('ok', { status: 200 }));
    await new WebhookNotifier('https://hooks.example/commander', 'ops', f as unknown as typeof fetch).notify(card);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(url).toBe('https://hooks.example/commander');
    expect(init.method).toBe('POST');
    expect(body.topic).toBe('ops');
    expect(body.title).toBe(card.title);
    expect(body.click).toBe(card.url);
    expect(body.message).toContain(card.incident);
    expect(body.actions).toHaveLength(3);
    expect(body.actions.every((a: { action: string; method: string }) => a.action === 'http' && a.method === 'POST')).toBe(true);
    expect(body.commander.voice).toMatchObject({ class: 'Ursa', register: 'low', pitchVariance: 0 });
  });

  it('omits the topic when none is configured and caps the message size', async () => {
    const f = vi.fn(async () => new Response('ok', { status: 200 }));
    await new WebhookNotifier('https://hooks.example/x', undefined, f as unknown as typeof fetch).notify({ ...card, incident: 'x'.repeat(10_000) });
    const body = JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect('topic' in body).toBe(false);
    expect(body.message.length).toBeLessThanOrEqual(3500);
  });

  it('surfaces a non-2xx response as an error', async () => {
    const f = vi.fn(async () => new Response('nope', { status: 502 }));
    await expect(new WebhookNotifier('https://hooks.example/x', undefined, f as unknown as typeof fetch).notify(card)).rejects.toThrow(/502/);
  });
});

describe('a broken notifier never breaks the control plane', () => {
  const stage = async (notifier: Notifier) => {
    const h = makeHarness({ notifier });
    const m = h.app.airlock.openMission(h.operator, oneStep());
    const d = pull(h, m.id);
    const r = await h.app.airlock.requestClearance(h.worker, m.id, { lease_id: d.lease_id, action: { kind: 'sql', payload: 'ALTER TABLE t ADD c int' } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    return { h, r };
  };

  it('survives an asynchronously failing webhook and records the failure', async () => {
    const { h, r } = await stage({ notify: async () => Promise.reject(new Error('webhook down')) });
    expect(r.verdict).toBe('STAGED');
    expect(h.app.approvals.list(h.tenantId, 'pending')).toHaveLength(1);
    expect(h.app.store.tenantAudit(h.tenantId, 50).some((x) => x.type === 'notify.failed')).toBe(true);
  });

  it('survives a notifier that throws synchronously', async () => {
    const { h, r } = await stage({
      notify: () => {
        throw new Error('sync boom');
      },
    } as unknown as Notifier);
    expect(r.verdict).toBe('STAGED');
    expect(h.app.store.tenantAudit(h.tenantId, 50).some((x) => x.type === 'notify.failed')).toBe(true);
  });

  it('the staged approval still works after the failed push', async () => {
    const { h, r } = await stage({ notify: async () => Promise.reject(new Error('down')) });
    const a = h.app.approvals.list(h.tenantId, 'pending')[0]!;
    h.app.airlock.decideApproval(h.tenantId, a.id, 'authorize', undefined, 'operator');
    expect(h.app.airlock.clearanceStatus(h.worker, r.clearance_id).status).toBe('CLEARED');
  });
});
