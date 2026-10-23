import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import type { Decision } from './approvals.js';
import type { App } from './app.js';
import { CommanderError } from './errors.js';
import { computeMetrics } from './metrics.js';
import { buildMcpServer } from './mcp.js';
import { say } from './persona.js';
import { ActionRequestSchema, type Principal } from './types.js';
import type { Clock } from './util.js';

const MAX_BODY = 2 * 1024 * 1024;

// ---- helpers ----------------------------------------------------------------------------------

class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; ts: number }>();
  constructor(
    private readonly perSec: number,
    private readonly burst: number,
    private readonly clock: Clock,
  ) {}

  take(key: string): boolean {
    const now = this.clock();
    const b = this.buckets.get(key) ?? { tokens: this.burst, ts: now };
    b.tokens = Math.min(this.burst, b.tokens + ((now - b.ts) / 1000) * this.perSec);
    b.ts = now;
    const allowed = b.tokens >= 1;
    if (allowed) b.tokens -= 1;
    this.buckets.set(key, b);
    if (this.buckets.size > 10_000) {
      for (const [k, v] of this.buckets) if (now - v.ts > 60_000) this.buckets.delete(k);
    }
    return allowed;
  }
}

function baseHeaders(res: ServerResponse): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('referrer-policy', 'no-referrer');
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), ...extra });
  res.end(payload);
}

function sendText(res: ServerResponse, status: number, type: string, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(body), ...headers });
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new CommanderError('PAYLOAD_TOO_LARGE', say.invalid('Body exceeds 2 MiB.'));
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const buf = await readBody(req);
  if (buf.length === 0) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new CommanderError('INVALID', say.invalid('Body is not valid JSON.'));
  }
}

function parse<T>(schema: z.ZodType<T>, data: unknown): T {
  const r = schema.safeParse(data);
  if (r.success) return r.data;
  const issue = r.error.issues[0];
  throw new CommanderError('INVALID', say.invalid(`${issue?.path.join('.') || 'body'}: ${issue?.message ?? 'malformed'}.`));
}

const digest = (s: string): Buffer => createHash('sha256').update(s).digest();

function isAdmin(header: string | undefined, token: string | undefined): boolean {
  if (!token) return false;
  const m = /^Bearer\s+(\S+)$/i.exec(header ?? '');
  return !!m && timingSafeEqual(digest(m[1]!), digest(token));
}

const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function loadHud(): Record<string, { type: string; body: string }> {
  const dir = new URL('./hud/', import.meta.url);
  const read = (f: string) => readFileSync(new URL(f, dir), 'utf8');
  return {
    '/hud': { type: 'text/html; charset=utf-8', body: read('index.html') },
    '/hud/app.js': { type: 'text/javascript; charset=utf-8', body: read('app.js') },
    '/hud/style.css': { type: 'text/css; charset=utf-8', body: read('style.css') },
  };
}

const HUD_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const LINK_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

// ---- schemas ----------------------------------------------------------------------------------

const DecisionBody = z.object({ decision: z.enum(['authorize', 'redirect', 'kill']), note: z.string().max(400).optional() });
const InterveneBody = z.object({ action: z.enum(['kill', 'skip']), reason: z.string().min(1).max(300) });
const KeyBody = z.object({ label: z.string().max(80).optional() });
const TenantBody = z.object({ name: z.string().min(1).max(100), credits: z.number().min(0).max(1e9) });
const TopUpBody = z.object({ amount: z.number().positive().max(1e9) });
const GuardBody = z.object({ mission_id: z.string().min(1).max(64), tool: z.string().min(1).max(40).optional(), action: ActionRequestSchema });

// ---- server -----------------------------------------------------------------------------------

export function createHttpServer(app: App): Server {
  const hud = loadHud();
  const authed = new RateLimiter(50, 100, app.clock);
  /** Meters failed authentication per remote address, to blunt key guessing. */
  const authFailures = new RateLimiter(5, 20, app.clock);

  function authenticate(req: IncomingMessage): Principal {
    try {
      return app.auth.authenticate(req.headers.authorization);
    } catch (err) {
      if (!authFailures.take(req.socket.remoteAddress ?? 'unknown')) throw new CommanderError('THROTTLED', say.throttled(1), { retryAfter: 1 });
      throw err;
    }
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    baseHeaders(res);
    const url = new URL(req.url ?? '/', 'http://commander.local');
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method ?? 'GET';

    if (path === '/healthz') return sendJson(res, 200, { ok: true });

    const page = hud[path];
    if (page && method === 'GET') return sendText(res, 200, page.type, page.body, { 'content-security-policy': HUD_CSP });

    let m: RegExpExecArray | null;

    // Signed approval links authenticate by signature, not by API key.
    if ((m = /^\/a\/([\w-]+)$/.exec(path)) && method === 'GET') return approvalPage(res, url, m[1]!);
    if ((m = /^\/a\/([\w-]+)\/decide$/.exec(path)) && method === 'POST') return approvalDecide(req, res, url, m[1]!);

    // Platform admin: tenant provisioning.
    if (path.startsWith('/v1/admin/')) {
      if (!isAdmin(req.headers.authorization, app.config.adminToken)) {
        if (!authFailures.take(req.socket.remoteAddress ?? 'unknown')) throw new CommanderError('THROTTLED', say.throttled(1), { retryAfter: 1 });
        throw new CommanderError('UNAUTHENTICATED', say.unauthenticated());
      }
      if (path === '/v1/admin/audit/verify' && method === 'GET') return sendJson(res, 200, app.store.verify({ full: true }));
      if (path === '/v1/admin/tenants' && method === 'POST') {
        const body = parse(TenantBody, await readJson(req));
        const { tenant, operatorKey } = app.auth.createTenant(body.name, body.credits);
        return sendJson(res, 201, { tenant_id: tenant.id, name: tenant.name, credits: tenant.credits, operator_key: operatorKey });
      }
      if ((m = /^\/v1\/admin\/tenants\/([\w-]+)\/credits$/.exec(path)) && method === 'POST') {
        const body = parse(TopUpBody, await readJson(req));
        return sendJson(res, 200, { balance: app.auth.topUp(m[1]!, body.amount) });
      }
      throw new CommanderError('NOT_FOUND', say.notFound());
    }

    if (!path.startsWith('/v1/')) throw new CommanderError('NOT_FOUND', say.notFound());

    const principal = authenticate(req);
    if (!authed.take(principal.keyId)) throw new CommanderError('THROTTLED', say.throttled(1), { retryAfter: 1 });

    // Native-tool guard: the client-side PreToolUse hook asks here before Bash/Write/Edit run.
    if (path === '/v1/guard/clearance') {
      if (method !== 'POST') throw new CommanderError('NOT_FOUND', say.notFound());
      const body = parse(GuardBody, await readJson(req));
      return sendJson(res, 200, await app.airlock.requestGuardClearance(principal, body.mission_id, { action: body.action, tool: body.tool }));
    }

    if (path === '/v1/mcp') {
      if (method !== 'POST') {
        return sendJson(res, 405, { jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }, { allow: 'POST' });
      }
      const body = await readJson(req);
      const server = buildMcpServer(principal, app.airlock);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }

    if (path.startsWith('/v1/operator/')) {
      app.auth.requireRole(principal, 'operator');
      const t = principal.tenantId;

      if (path === '/v1/operator/overview' && method === 'GET') {
        const approvals = app.approvals.list(t, 'pending').map((a) => {
          const mission = app.store.state.missions[a.missionId];
          return {
            id: a.id,
            kind: a.kind,
            incident: a.incident,
            reason: a.reason,
            created_at: a.createdAt,
            mission: mission?.title,
            step: mission?.steps.find((s) => s.id === a.stepId)?.def.title,
          };
        });
        return sendJson(res, 200, {
          metrics: computeMetrics(app.store, t, app.clock()),
          approvals,
          missions: app.airlock.listMissions(principal).slice(0, 20),
          audit: app.store.tenantAudit(t, 25).map((r) => ({ seq: r.seq, ts: r.ts, type: r.type, data: r.data })),
        });
      }
      if (path === '/v1/operator/missions' && method === 'POST') return sendJson(res, 201, app.airlock.openMission(principal, await readJson(req)));
      if (path === '/v1/operator/missions' && method === 'GET') return sendJson(res, 200, { missions: app.airlock.listMissions(principal) });
      if ((m = /^\/v1\/operator\/missions\/([\w-]+)$/.exec(path)) && method === 'GET') return sendJson(res, 200, app.airlock.getMission(principal, m[1]!));
      if ((m = /^\/v1\/operator\/missions\/([\w-]+)\/intervene$/.exec(path)) && method === 'POST') {
        return sendJson(res, 200, app.airlock.intervene(principal, m[1]!, parse(InterveneBody, await readJson(req))));
      }
      if (path === '/v1/operator/approvals' && method === 'GET') {
        const status = url.searchParams.get('status');
        const parsed = status ? parse(z.enum(['pending', 'authorized', 'redirected', 'killed']), status) : undefined;
        return sendJson(res, 200, { approvals: app.approvals.list(t, parsed) });
      }
      if ((m = /^\/v1\/operator\/approvals\/([\w-]+)\/decision$/.exec(path)) && method === 'POST') {
        const body = parse(DecisionBody, await readJson(req));
        return sendJson(res, 200, app.airlock.decideApproval(t, m[1]!, body.decision, body.note, 'operator'));
      }
      if (path === '/v1/operator/audit' && method === 'GET') {
        const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit') ?? 50) || 50));
        return sendJson(res, 200, { records: app.store.tenantAudit(t, limit) });
      }
      if (path === '/v1/operator/audit/verify' && method === 'GET') return sendJson(res, 200, app.store.verify({ tenantId: t }));
      if (path === '/v1/operator/keys' && method === 'POST') {
        const body = parse(KeyBody, await readJson(req));
        const { record, key } = app.auth.issueKey(t, 'worker', body.label);
        return sendJson(res, 201, { key_id: record.id, role: record.role, key });
      }
      if ((m = /^\/v1\/operator\/keys\/([\w-]+)$/.exec(path)) && method === 'DELETE') {
        app.auth.revokeKey(t, m[1]!);
        return sendJson(res, 200, { revoked: m[1] });
      }
    }

    throw new CommanderError('NOT_FOUND', say.notFound());
  }

  // ---- signed approval links ----

  function authorizeLink(id: string, scope: string, url: URL): void {
    const exp = Number(url.searchParams.get('exp'));
    const sig = url.searchParams.get('sig') ?? '';
    if (!app.approvals.signer.verify(id, scope, exp, sig, app.clock())) throw new CommanderError('FORBIDDEN', say.forbidden());
  }

  function approvalPage(res: ServerResponse, url: URL, id: string): void {
    authorizeLink(id, 'view', url);
    const a = app.approvals.byId(id);
    const mission = app.store.state.missions[a.missionId];
    const stepTitle = mission?.steps.find((s) => s.id === a.stepId)?.def.title ?? '';
    const exp = Number(url.searchParams.get('exp'));
    const action = (d: Decision) => `/a/${esc(id)}/decide?d=${d}&amp;exp=${exp}&amp;sig=${app.approvals.signer.sign(id, d, exp)}`;
    const pending = a.status === 'pending';
    const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Commander decision</title><style>
:root{color-scheme:dark;--bg:#0b0d10;--fg:#e8eaed;--mut:#9aa0a6;--line:#262b31;--ok:#2e7d32;--warn:#b26a00;--bad:#c62828}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:560px;margin:0 auto;padding:20px 16px 40px}h1{font-size:14px;letter-spacing:.14em;color:var(--mut);margin:0 0 16px}
.card{border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}.k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:12px}
pre{white-space:pre-wrap;word-break:break-word;margin:4px 0 0;font:14px/1.45 ui-monospace,monospace}
form{margin:0 0 12px}button{width:100%;min-height:56px;border:0;border-radius:10px;font:600 17px system-ui;color:#fff;cursor:pointer}
input{width:100%;min-height:44px;margin-bottom:8px;border-radius:8px;border:1px solid var(--line);background:#14181d;color:var(--fg);padding:0 12px;font:16px system-ui}
.a{background:var(--ok)}.r{background:var(--warn)}.x{background:var(--bad)}</style></head><body><main>
<h1>AGENT COMMANDER // DECISION</h1><div class="card">
<div class="k">Mission</div><div>${esc(mission?.title ?? '')} · ${esc(stepTitle)}</div>
<div class="k">Attempted</div><pre>${esc(a.incident)}</pre>
<div class="k">Reason</div><pre>${esc(a.reason)}</pre>
<div class="k">Status</div><div>${esc(a.status.toUpperCase())}</div></div>
${
  pending
    ? `<form method="post" action="${action('authorize')}"><button class="a" type="submit">Authorize</button></form>
<form method="post" action="${action('redirect')}"><input name="note" maxlength="400" placeholder="Redirect note (optional)" aria-label="Redirect note"><button class="r" type="submit">Redirect</button></form>
<form method="post" action="${action('kill')}"><button class="x" type="submit">Kill</button></form>`
    : '<p>Decision already recorded.</p>'
}</main></body></html>`;
    sendText(res, 200, 'text/html; charset=utf-8', body, { 'content-security-policy': LINK_CSP });
  }

  async function approvalDecide(req: IncomingMessage, res: ServerResponse, url: URL, id: string): Promise<void> {
    const decision = parse(z.enum(['authorize', 'redirect', 'kill']), url.searchParams.get('d'));
    authorizeLink(id, decision, url);

    const raw = (await readBody(req)).toString('utf8');
    let note: string | undefined;
    if ((req.headers['content-type'] ?? '').includes('application/json')) {
      try {
        const j = JSON.parse(raw || '{}') as { note?: unknown };
        note = typeof j.note === 'string' ? j.note : undefined;
      } catch {
        throw new CommanderError('INVALID', say.invalid('Body is not valid JSON.'));
      }
    } else if (raw) {
      note = new URLSearchParams(raw).get('note') ?? undefined;
    }

    const a = app.approvals.byId(id);
    const decided = app.airlock.decideApproval(a.tenantId, id, decision, note || undefined, 'link');
    if ((req.headers.accept ?? '').includes('text/html')) {
      sendText(
        res,
        200,
        'text/html; charset=utf-8',
        `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recorded</title><body style="font:18px system-ui;background:#0b0d10;color:#e8eaed;padding:24px"><p>Decision recorded: ${esc(decided.status.toUpperCase())}.</p></body>`,
        { 'content-security-policy': LINK_CSP },
      );
    } else {
      sendJson(res, 200, { ok: true, status: decided.status });
    }
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof CommanderError) {
        const extra: Record<string, string> = {};
        if (err.code === 'THROTTLED' && typeof err.details?.retryAfter === 'number') extra['retry-after'] = String(err.details.retryAfter);
        if (err.code === 'PAYLOAD_TOO_LARGE') extra.connection = 'close';
        sendJson(res, err.status, { error: err.code, message: err.message, ...(err.details ?? {}) }, extra);
        return;
      }
      console.error('[commander] unhandled', err);
      sendJson(res, 500, { error: 'FAULT', message: 'Internal fault. Request not processed.' });
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  return server;
}
