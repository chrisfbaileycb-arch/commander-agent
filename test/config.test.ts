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

describe('shipped example files stay valid', () => {
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
