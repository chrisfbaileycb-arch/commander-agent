import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp, type App } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createHttpServer } from '../src/http.js';
import { ANCHOR } from '../src/persona.js';
import { CaptureNotifier } from './helpers.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = Record<string, any>;

const ADMIN = 'admin-token-for-tests';
const notifier = new CaptureNotifier();
let app: App;
let server: Server;
let base = '';

beforeAll(async () => {
  app = createApp({ config: { ...loadConfig({}), adminToken: ADMIN, linkSecret: 'e2e-link-secret', publicUrl: 'http://commander.test' }, notifier });
  server = createHttpServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function call(method: string, path: string, opts: { key?: string; body?: unknown; raw?: string; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...(opts.key ? { authorization: `Bearer ${opts.key}` } : {}), ...opts.headers };
  let body: string | undefined = opts.raw;
  if (opts.body !== undefined) {
    headers['content-type'] ??= 'application/json';
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(base + path, { method, headers, body });
  const text = await res.text();
  let json: Json = {};
  try {
    json = JSON.parse(text);
  } catch {
    /* not json */
  }
  return { status: res.status, json, text, headers: res.headers };
}

const text = (r: unknown): string => (r as { content: { text: string }[] }).content[0]!.text;
const sc = (r: unknown): Json => (r as { structuredContent: Json }).structuredContent;
const pathOf = (url: string): string => {
  const u = new URL(url);
  return u.pathname + u.search;
};

async function connect(key: string): Promise<Client> {
  const client = new Client({ name: 'e2e', version: '0.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/v1/mcp`), { requestInit: { headers: { authorization: `Bearer ${key}` } } }));
  return client;
}

async function newTenant(credits = 1000) {
  const t = await call('POST', '/v1/admin/tenants', { key: ADMIN, body: { name: 'e2e', credits } });
  expect(t.status).toBe(201);
  const w = await call('POST', '/v1/operator/keys', { key: t.json.operator_key, body: { label: 'worker' } });
  expect(w.status).toBe(201);
  return { id: t.json.tenant_id as string, op: t.json.operator_key as string, worker: w.json.key as string };
}

async function openMission(op: string, def: unknown) {
  const r = await call('POST', '/v1/operator/missions', { key: op, body: def });
  expect(r.status).toBe(201);
  return r.json.id as string;
}

const soloMission = { title: 'Solo', steps: [{ title: 'Only', directive: 'Do it.', proof: [{ type: 'exit_code' }] }] };

/** Opens a one-step mission, pulls its directive, and stages a clearance. */
async function stageOne(payload: string) {
  const t = await newTenant();
  const missionId = await openMission(t.op, soloMission);
  const client = await connect(t.worker);
  const d = sc(await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } }));
  const r = await client.callTool({
    name: 'commander_request_clearance',
    arguments: { mission_id: missionId, lease_id: d.lease_id, action: { kind: 'sql', payload } },
  });
  expect(sc(r).verdict).toBe('STAGED');
  return { t, missionId, client, d, clearanceId: sc(r).clearance_id as string, card: notifier.cards.at(-1)! };
}

describe('platform surface', () => {
  it('serves health and the HUD with a strict CSP and no dynamic-HTML sinks', async () => {
    expect((await call('GET', '/healthz')).json).toEqual({ ok: true });

    const hud = await call('GET', '/hud');
    expect(hud.status).toBe(200);
    expect(hud.text).toContain('AGENT COMMANDER');
    const csp = hud.headers.get('content-security-policy')!;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(hud.headers.get('x-content-type-options')).toBe('nosniff');

    const js = await call('GET', '/hud/app.js');
    expect(js.status).toBe(200);
    expect(js.headers.get('content-type')).toContain('javascript');
    expect(js.text).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(/);
    expect((await call('GET', '/hud/style.css')).status).toBe(200);
  });

  it('answers unknown routes with 404', async () => {
    expect((await call('GET', '/nope')).status).toBe(404);
    expect((await call('GET', '/v1/nope', { key: (await newTenant()).op })).status).toBe(404);
  });
});

describe('platform admin', () => {
  it('requires the admin token', async () => {
    expect((await call('POST', '/v1/admin/tenants', { body: { name: 'x', credits: 1 } })).status).toBe(401);
    expect((await call('POST', '/v1/admin/tenants', { key: 'wrong', body: { name: 'x', credits: 1 } })).status).toBe(401);
  });

  it('provisions tenants, tops up credits, and verifies the full audit chain', async () => {
    const bad = await call('POST', '/v1/admin/tenants', { key: ADMIN, body: { name: '', credits: -1 } });
    expect(bad.status).toBe(400);

    const t = await newTenant(5);
    expect(t.op.startsWith('cmd_op_')).toBe(true);
    expect(t.worker.startsWith('cmd_live_')).toBe(true);
    const top = await call('POST', `/v1/admin/tenants/${t.id}/credits`, { key: ADMIN, body: { amount: 10 } });
    expect(top.json.balance).toBe(15);
    expect((await call('POST', `/v1/admin/tenants/${t.id}/credits`, { key: ADMIN, body: { amount: -3 } })).status).toBe(400);

    const verify = await call('GET', '/v1/admin/audit/verify', { key: ADMIN });
    expect(verify.json.ok).toBe(true);
  });
});

describe('authentication and roles', () => {
  it('rejects missing, malformed, and wrongly-roled credentials', async () => {
    const t = await newTenant();
    expect((await call('GET', '/v1/operator/overview')).status).toBe(401);
    expect((await call('GET', '/v1/operator/overview', { headers: { authorization: 'Basic abc' } })).status).toBe(401);
    expect((await call('GET', '/v1/operator/overview', { key: 'cmd_op_notarealkey' })).status).toBe(401);
    expect((await call('GET', '/v1/operator/overview', { key: t.worker })).status).toBe(403);
    const ok = await call('GET', '/v1/operator/overview', { key: t.op });
    expect(ok.status).toBe(200);
    expect(ok.json.metrics).toMatchObject({ activeAgents: 0, stagedApprovals: 0 });
  });

  it('MCP needs a key and accepts POST only', async () => {
    const t = await newTenant();
    const noKey = await call('POST', '/v1/mcp', { body: { jsonrpc: '2.0', id: 1, method: 'ping' } });
    expect(noKey.status).toBe(401);
    expect((await call('GET', '/v1/mcp', { key: t.worker })).status).toBe(405);
  });

  it('a revoked key stops working immediately', async () => {
    const t = await newTenant();
    const minted = await call('POST', '/v1/operator/keys', { key: t.op, body: {} });
    const client = await connect(minted.json.key);
    await client.close();
    expect((await call('DELETE', `/v1/operator/keys/${minted.json.key_id}`, { key: t.op })).status).toBe(200);
    await expect(connect(minted.json.key)).rejects.toThrow();
  });

  it('an operator key is refused by the worker tools', async () => {
    const t = await newTenant();
    const missionId = await openMission(t.op, soloMission);
    const client = await connect(t.op);
    const r = await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(r.isError).toBe(true);
    expect(sc(r).error).toBe('FORBIDDEN');
  });
});

describe('MCP gateway end to end', () => {
  it('exposes exactly the five commander tools', async () => {
    const t = await newTenant();
    const client = await connect(t.worker);
    const { tools } = await client.listTools();
    expect(tools.map((x) => x.name).sort()).toEqual([
      'commander_clearance_status',
      'commander_get_directive',
      'commander_mission_status',
      'commander_request_clearance',
      'commander_submit_proof',
    ]);
    expect(tools.find((x) => x.name === 'commander_submit_proof')!.inputSchema.properties).toHaveProperty('evidence');
  });

  it('drives a mission: rejects the lie, passes the proof, denies, stages, authorizes by signed link', async () => {
    const t = await newTenant();
    const missionId = await openMission(t.op, {
      title: 'E2E',
      steps: [
        { title: 'Build', directive: 'build it', proof: [{ type: 'exit_code' }], require_nonce: true },
        { title: 'Migrate', directive: 'migrate', proof: [{ type: 'exit_code' }] },
      ],
    });
    const client = await connect(t.worker);

    const d1 = await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(text(d1)).toContain('COMMANDER // DIRECTIVE');
    expect(text(d1)).not.toContain('migrate');
    const first = sc(d1);

    const rejected = await client.callTool({
      name: 'commander_submit_proof',
      arguments: { mission_id: missionId, lease_id: first.lease_id, evidence: { exit_code: 1, claim: 'done!' } },
    });
    expect(text(rejected)).toContain('PROOF REJECTED');
    expect(sc(rejected).patch).toContain('[exit_code]');

    const passed = await client.callTool({
      name: 'commander_submit_proof',
      arguments: { mission_id: missionId, lease_id: first.lease_id, evidence: { exit_code: 0, stdout: `ok ${sc(rejected).nonce}` } },
    });
    expect(sc(passed).verdict).toBe('PASSED');

    const d2 = sc(await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } }));
    expect(d2.directive).toBe('migrate');

    const denied = await client.callTool({
      name: 'commander_request_clearance',
      arguments: { mission_id: missionId, lease_id: d2.lease_id, action: { kind: 'sql', payload: 'DROP TABLE users;' } },
    });
    expect(text(denied)).toContain('CLEARANCE DENIED');

    const staged = await client.callTool({
      name: 'commander_request_clearance',
      arguments: { mission_id: missionId, lease_id: d2.lease_id, action: { kind: 'sql', payload: 'ALTER TABLE users ADD COLUMN age int' } },
    });
    expect(text(staged)).toContain('CLEARANCE STAGED');

    const overview = await call('GET', '/v1/operator/overview', { key: t.op });
    expect(overview.json.approvals).toHaveLength(1);
    expect(overview.json.metrics.stagedApprovals).toBe(1);
    expect(overview.json.metrics.errorVelocity.last10Min).toBeGreaterThanOrEqual(2);

    const hold = await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(text(hold)).toContain('HOLD');

    const card = notifier.cards.at(-1)!;
    const authorize = card.actions.find((a) => a.decision === 'authorize')!;
    const decided = await call('POST', pathOf(authorize.url), { headers: { accept: 'application/json' } });
    expect(decided.status).toBe(200);
    expect(decided.json).toEqual({ ok: true, status: 'authorized' });
    expect((await call('POST', pathOf(authorize.url), { headers: { accept: 'application/json' } })).status).toBe(409);

    const status = await client.callTool({ name: 'commander_clearance_status', arguments: { clearance_id: sc(staged).clearance_id } });
    expect(text(status)).toContain('CLEARANCE CLEARED');

    const done = await client.callTool({
      name: 'commander_submit_proof',
      arguments: { mission_id: missionId, lease_id: d2.lease_id, evidence: { exit_code: 0 } },
    });
    expect(sc(done).mission_complete).toBe(true);
    expect((await call('GET', `/v1/operator/missions/${missionId}`, { key: t.op })).json.status).toBe('completed');
  });

  it('another tenant cannot see or touch a mission it does not own', async () => {
    const a = await newTenant();
    const b = await newTenant();
    const missionId = await openMission(a.op, soloMission);
    expect((await call('GET', `/v1/operator/missions/${missionId}`, { key: b.op })).status).toBe(404);
    const r = await (await connect(b.worker)).callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(r.isError).toBe(true);
    expect(sc(r).error).toBe('NOT_FOUND');
  });

  it('reports credit exhaustion as a refusal, not a crash', async () => {
    const t = await newTenant(1);
    const missionId = await openMission(t.op, soloMission);
    const client = await connect(t.worker);
    expect((await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } })).isError).toBeFalsy();
    const second = await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(second.isError).toBe(true);
    expect(sc(second).error).toBe('CREDITS_EXHAUSTED');
  });

  it('rejects malformed tool input at the schema boundary', async () => {
    const t = await newTenant();
    const client = await connect(t.worker);
    const r = await client
      .callTool({ name: 'commander_submit_proof', arguments: { mission_id: 'x', lease_id: 'y', evidence: { exit_code: 'zero' } } })
      .catch((e: Error) => e);
    const failed = r instanceof Error || (r as { isError?: boolean }).isError === true;
    expect(failed).toBe(true);
  });
});

describe('signed approval links', () => {
  it('renders an escaped, CSP-protected decision page', async () => {
    const { card } = await stageOne('ALTER TABLE <script>alert(1)</script> ADD c int');
    const page = await call('GET', pathOf(card.url));
    expect(page.status).toBe(200);
    expect(page.text).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(page.text).not.toContain('<script');
    const csp = page.headers.get('content-security-policy')!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(page.text.match(/<form /g)).toHaveLength(3);
    expect(page.text).toContain('name="note"');
  });

  it('rejects tampered, cross-scope, expired and unknown links', async () => {
    const { card } = await stageOne('ALTER TABLE t ADD c int');
    const authorize = new URL(card.actions.find((a) => a.decision === 'authorize')!.url);

    const tampered = new URL(authorize);
    const sig = tampered.searchParams.get('sig')!;
    tampered.searchParams.set('sig', sig.slice(0, -1) + (sig.endsWith('A') ? 'B' : 'A'));
    expect((await call('POST', tampered.pathname + tampered.search)).status).toBe(403);

    const crossScope = new URL(authorize);
    crossScope.searchParams.set('d', 'kill');
    expect((await call('POST', crossScope.pathname + crossScope.search)).status).toBe(403);

    const id = card.approvalId;
    const past = Math.floor(Date.now() / 1000) - 10;
    expect((await call('GET', `/a/${id}?exp=${past}&sig=${app.approvals.signer.sign(id, 'view', past)}`)).status).toBe(403);

    const future = Math.floor(Date.now() / 1000) + 600;
    expect((await call('GET', `/a/apr_nope?exp=${future}&sig=${app.approvals.signer.sign('apr_nope', 'view', future)}`)).status).toBe(404);
    expect((await call('GET', `/a/${id}`)).status).toBe(403);
  });

  it('a form post with a redirect note reaches the worker behind the Deductive Anchor', async () => {
    const { card, client, missionId, clearanceId } = await stageOne('ALTER TABLE t ADD c int');
    const redirect = card.actions.find((a) => a.decision === 'redirect')!;
    const res = await call('POST', pathOf(redirect.url), {
      headers: { accept: 'text/html', 'content-type': 'application/x-www-form-urlencoded' },
      raw: 'note=Use+the+migration+file+instead',
    });
    expect(res.status).toBe(200);
    expect(res.text).toContain('REDIRECTED');

    const status = await client.callTool({ name: 'commander_clearance_status', arguments: { clearance_id: clearanceId } });
    expect(text(status)).toContain(ANCHOR);
    expect(text(status)).toContain('Use the migration file instead');
    expect(text(await client.callTool({ name: 'commander_mission_status', arguments: { mission_id: missionId } }))).toContain('ACTIVE');
  });

  it('a JSON post carries its note too', async () => {
    const { card, client, clearanceId } = await stageOne('ALTER TABLE t ADD c int');
    const redirect = card.actions.find((a) => a.decision === 'redirect')!;
    const res = await call('POST', pathOf(redirect.url), { headers: { accept: 'application/json' }, body: { note: 'Ship it as a migration.' } });
    expect(res.json.status).toBe('redirected');
    const status = await client.callTool({ name: 'commander_clearance_status', arguments: { clearance_id: clearanceId } });
    expect(text(status)).toContain('Ship it as a migration.');
  });

  it('a kill link terminates the mission', async () => {
    const { card, missionId, client } = await stageOne('ALTER TABLE t ADD c int');
    const kill = card.actions.find((a) => a.decision === 'kill')!;
    expect((await call('POST', pathOf(kill.url), { headers: { accept: 'application/json' } })).json.status).toBe('killed');
    const r = await client.callTool({ name: 'commander_get_directive', arguments: { mission_id: missionId } });
    expect(text(r)).toContain('TERMINATED');
  });
});

describe('limits (these run last: they exhaust per-address throttles)', () => {
  it('rejects oversize bodies with 413', async () => {
    const t = await newTenant();
    const r = await call('POST', '/v1/operator/missions', {
      key: t.op,
      headers: { 'content-type': 'application/json' },
      raw: JSON.stringify({ title: 'x', pad: 'a'.repeat(2.2 * 1024 * 1024) }),
    });
    expect(r.status).toBe(413);
  });

  it('rejects invalid JSON with 400', async () => {
    const t = await newTenant();
    const r = await call('POST', '/v1/operator/missions', { key: t.op, headers: { 'content-type': 'application/json' }, raw: '{not json' });
    expect(r.status).toBe(400);
  });

  it('throttles repeated authentication failures from one address', async () => {
    const statuses: number[] = [];
    let retryAfter: string | null = null;
    for (let i = 0; i < 40; i++) {
      const r = await call('GET', '/v1/operator/overview', { key: `cmd_op_guess${i}` });
      statuses.push(r.status);
      retryAfter ??= r.headers.get('retry-after');
    }
    expect(statuses).toContain(401);
    expect(statuses).toContain(429);
    expect(retryAfter).toBeTruthy();
  });
});
