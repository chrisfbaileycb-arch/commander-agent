import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PolicySchema, defaultPolicy, loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  it('has safe defaults: loopback, in-memory, no admin surface, ephemeral link secret', () => {
    const c = loadConfig({});
    expect(c.host).toBe('127.0.0.1');
    expect(c.port).toBe(8787);
    expect(c.dataDir).toBeUndefined();
    expect(c.adminToken).toBeUndefined();
    expect(c.linkSecretEphemeral).toBe(true);
    expect(c.linkSecret.length).toBeGreaterThanOrEqual(32);
    expect(c.policy).toEqual(defaultPolicy());
  });

  it('treats empty strings as unset, so a copied .env.example does not enable anything by accident', () => {
    const c = loadConfig({
      COMMANDER_ADMIN_TOKEN: '',
      COMMANDER_LINK_SECRET: '',
      COMMANDER_NOTIFY_WEBHOOK: '',
      GEMINI_API_KEY: '',
      COMMANDER_POLICY_FILE: '',
      COMMANDER_DATA_DIR: '',
    });
    expect(c.adminToken).toBeUndefined();
    expect(c.linkSecretEphemeral).toBe(true);
    expect(c.notifyWebhook).toBeUndefined();
    expect(c.geminiApiKey).toBeUndefined();
    expect(c.dataDir).toBeUndefined();
  });

  it('refuses short secrets, including the placeholder in .env.example', () => {
    expect(() => loadConfig({ COMMANDER_LINK_SECRET: 'change-me' })).toThrowError(/COMMANDER_LINK_SECRET must be at least 16/);
    expect(() => loadConfig({ COMMANDER_ADMIN_TOKEN: 'change-me' })).toThrowError(/COMMANDER_ADMIN_TOKEN must be at least 16/);
    const ok = loadConfig({ COMMANDER_LINK_SECRET: 'x'.repeat(32), COMMANDER_ADMIN_TOKEN: 'y'.repeat(32) });
    expect(ok.linkSecretEphemeral).toBe(false);
    expect(ok.adminToken).toBe('y'.repeat(32));
  });

  it('validates PORT', () => {
    expect(loadConfig({ PORT: '9000' }).port).toBe(9000);
    expect(() => loadConfig({ PORT: 'abc' })).toThrowError(/Invalid PORT/);
    expect(() => loadConfig({ PORT: '70000' })).toThrowError(/Invalid PORT/);
  });

  it('trims a trailing slash from the public URL', () => {
    expect(loadConfig({ COMMANDER_PUBLIC_URL: 'https://c.example.com//' }).publicUrl).toBe('https://c.example.com');
  });

  it('loads and validates a policy file', () => {
    const c = loadConfig({ COMMANDER_POLICY_FILE: new URL('../policy.example.json', import.meta.url).pathname });
    expect(c.policy.egress_allowlist).toContain('registry.example.com');
    expect(c.policy.burn_limit_per_min).toBe(60);
  });
});

describe('loadConfig: independent witnessing', () => {
  const local = { COMMANDER_WITNESS_MODE: 'local', COMMANDER_WITNESS_ROOT: '/srv/work', COMMANDER_WITNESS_ALLOW: 'node,npm', COMMANDER_WITNESS_TENANTS: '*' };

  it('is off by default, and its other variables are inert while it is off', () => {
    expect(loadConfig({}).witness).toMatchObject({ mode: 'off', allow: [], tenants: [], concurrency: 2 });
    expect(loadConfig({ COMMANDER_WITNESS_ROOT: 'relative/ignored', COMMANDER_WITNESS_ALLOW: '/not/a/name' }).witness.mode).toBe('off');
  });

  it('enables local mode only with a root, an allowlist and a tenant scope, all stated explicitly', () => {
    const w = loadConfig(local).witness;
    expect(w).toMatchObject({ mode: 'local', root: '/srv/work', allow: ['node', 'npm'], tenants: '*', concurrency: 2 });
    for (const missing of ['COMMANDER_WITNESS_ROOT', 'COMMANDER_WITNESS_ALLOW', 'COMMANDER_WITNESS_TENANTS']) {
      const env: Record<string, string> = { ...local };
      delete env[missing];
      expect(() => loadConfig(env), missing).toThrowError(new RegExp(missing));
    }
  });

  it('rejects an unknown mode rather than guessing', () => {
    expect(() => loadConfig({ COMMANDER_WITNESS_MODE: 'docker' })).toThrowError(/must be "off" or "local"/);
  });

  it('requires an absolute root', () => {
    expect(() => loadConfig({ ...local, COMMANDER_WITNESS_ROOT: 'work' })).toThrowError(/absolute path/);
  });

  it.each([['/bin/sh'], ['./node'], ['../node'], ['sh -c'], ['node;id']])('takes bare executable names only: refuses %j', (name) => {
    expect(() => loadConfig({ ...local, COMMANDER_WITNESS_ALLOW: `node,${name}` })).toThrowError(/bare executable names only/);
  });

  it('accepts a list of tenants, and * wins when it is among them', () => {
    expect(loadConfig({ ...local, COMMANDER_WITNESS_TENANTS: 'ten_a, ten_b' }).witness.tenants).toEqual(['ten_a', 'ten_b']);
    expect(loadConfig({ ...local, COMMANDER_WITNESS_TENANTS: 'ten_a,*' }).witness.tenants).toBe('*');
  });

  it('bounds concurrency', () => {
    expect(loadConfig({ ...local, COMMANDER_WITNESS_CONCURRENCY: '16' }).witness.concurrency).toBe(16);
    for (const bad of ['0', '17', '1.5', 'many', '-1']) {
      expect(() => loadConfig({ ...local, COMMANDER_WITNESS_CONCURRENCY: bad }), bad).toThrowError(/CONCURRENCY must be an integer from 1 to 16/);
    }
  });

  it('treats every blank witness variable as unset, so a copied .env.example boots', () => {
    const blank = Object.fromEntries(
      ['MODE', 'ROOT', 'ALLOW', 'TENANTS', 'PATH', 'CONCURRENCY'].map((k) => [`COMMANDER_WITNESS_${k}`, '']),
    );
    expect(loadConfig(blank).witness).toMatchObject({ mode: 'off', allow: [], concurrency: 2 });
  });
});

describe('shipped example files stay valid', () => {
  it('.env.example, with its two placeholder secrets removed, loads cleanly and enables nothing', () => {
    const example = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
    const env: Record<string, string> = {};
    for (const line of example.split('\n')) {
      const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
      if (m) env[m[1]!] = m[2]!;
    }
    delete env.COMMANDER_LINK_SECRET; // deliberately refused until replaced
    delete env.COMMANDER_ADMIN_TOKEN;
    const c = loadConfig(env);
    expect(c.witness.mode).toBe('off');
    expect(c.geminiApiKey).toBeUndefined();
    expect(c.notifyWebhook).toBeUndefined();
  });

  it('policy.example.json parses against the schema', () => {
    const raw = JSON.parse(readFileSync(new URL('../policy.example.json', import.meta.url), 'utf8'));
    expect(PolicySchema.safeParse(raw).success).toBe(true);
  });

  it('policy schema rejects nonsense', () => {
    expect(PolicySchema.safeParse({ lease_ttl_sec: 1 }).success).toBe(false);
    expect(PolicySchema.safeParse({ repetition_threshold: 1 }).success).toBe(false);
    expect(PolicySchema.safeParse({ egress_allowlist: 'api.example.com' }).success).toBe(false);
  });

  it('.env.example documents every variable loadConfig reads', () => {
    const example = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
    const source = readFileSync(new URL('../src/config.ts', import.meta.url), 'utf8');
    const read = new Set([...source.matchAll(/env\.([A-Z_]+)/g)].map((m) => m[1]!));
    for (const name of read) expect(example, name).toContain(name);
  });
});
