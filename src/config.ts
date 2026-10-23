import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { z } from 'zod';

export const PolicySchema = z.object({
  /** Hosts workers may reach. Exact host, or `*.example.com` for any subdomain. Empty = deny all egress. */
  egress_allowlist: z.array(z.string()).default([]),
  /** Hosts where any non-read call is a financial transaction and must be staged. */
  payment_hosts: z
    .array(z.string())
    .default(['*.stripe.com', '*.paypal.com', '*.plaid.com', '*.braintreegateway.com', '*.squareup.com']),
  /** When true, shell commands outside `shell_allowlist` are staged for approval. */
  strict_shell: z.boolean().default(false),
  shell_allowlist: z.array(z.string()).default([]),
  /** Glob patterns diffs may not touch and fs actions may not target. */
  forbidden_paths: z
    .array(z.string())
    .default(['.env', '**/.env', '**/.env.*', '.git/**', '.github/workflows/**', '**/id_rsa*', '**/*.pem']),
  max_patch_lines: z.number().int().min(1).default(800),
  repetition_threshold: z.number().int().min(2).default(5),
  repetition_window_sec: z.number().int().min(1).default(600),
  lease_ttl_sec: z.number().int().min(30).default(1800),
  /** Credits one mission may burn per minute before calls are throttled. */
  burn_limit_per_min: z.number().min(1).default(60),
  credit_costs: z
    .object({
      directive: z.number(),
      proof: z.number(),
      clearance: z.number(),
      gate: z.number(),
      /** Charged when a proof submission triggers independent verification. */
      witness: z.number().default(3),
    })
    .default({ directive: 1, proof: 2, clearance: 1, gate: 5, witness: 3 }),
  approval_link_ttl_sec: z.number().int().min(60).default(1800),
  /** Wall-clock budget one proof submission may spend on independent verification, across all its checks. */
  witness_budget_sec: z.number().int().min(10).max(3600).default(600),
  /** Per-stream cap on output captured from an independently executed command. */
  witness_max_output_bytes: z.number().int().min(1024).max(4_194_304).default(262_144),
});
export type Policy = z.infer<typeof PolicySchema>;
export const defaultPolicy = (): Policy => PolicySchema.parse({});

/**
 * Independent witnessing makes Commander execute operator-defined commands. In a multi-tenant cloud that is
 * remote code execution by design, so it is off unless explicitly enabled and then scoped to named tenants.
 */
export interface WitnessConfig {
  mode: 'off' | 'local';
  /** Absolute workspace root. Every witness path and working directory is confined to it. */
  root?: string;
  /** Bare executable names witness commands may run. */
  allow: string[];
  /** PATH used to resolve those executables. The worker's environment is never consulted. */
  path: string;
  /** Tenant ids allowed to define witness checks, or `*` for every tenant (single-tenant deployments). */
  tenants: string[] | '*';
  concurrency: number;
}

export interface Config {
  host: string;
  port: number;
  /** Undefined = in-memory (ephemeral). */
  dataDir?: string;
  publicUrl: string;
  linkSecret: string;
  linkSecretEphemeral: boolean;
  adminToken?: string;
  notifyWebhook?: string;
  notifyTopic?: string;
  geminiApiKey?: string;
  geminiModel: string;
  witness: WitnessConfig;
  policy: Policy;
}

/** Secrets that authorize things must be long enough that copying a placeholder from an example file fails loudly. */
function secret(name: string, value: string | undefined): string | undefined {
  if (!value) return undefined;
  if (value.length < 16) throw new Error(`${name} must be at least 16 characters. Generate one with: openssl rand -hex 32`);
  return value;
}

const list = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

function loadWitness(env: NodeJS.ProcessEnv): WitnessConfig {
  const mode = env.COMMANDER_WITNESS_MODE || 'off';
  if (mode !== 'off' && mode !== 'local') throw new Error(`COMMANDER_WITNESS_MODE must be "off" or "local", got "${mode}"`);
  const root = env.COMMANDER_WITNESS_ROOT || undefined;
  const allow = list(env.COMMANDER_WITNESS_ALLOW);
  const tenants = list(env.COMMANDER_WITNESS_TENANTS);
  // A blank value (a copied .env.example) means "default", like every other variable.
  const concurrency = Number(env.COMMANDER_WITNESS_CONCURRENCY || 2);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
    throw new Error(`COMMANDER_WITNESS_CONCURRENCY must be an integer from 1 to 16, got "${env.COMMANDER_WITNESS_CONCURRENCY}"`);
  }
  if (mode === 'local') {
    if (!root || !isAbsolute(root)) throw new Error('COMMANDER_WITNESS_ROOT must be an absolute path when COMMANDER_WITNESS_MODE=local');
    if (allow.length === 0) throw new Error('COMMANDER_WITNESS_ALLOW must list the executables witness commands may run (bare names, comma-separated)');
    const bad = allow.filter((a) => !/^[A-Za-z0-9._+-]+$/.test(a));
    if (bad.length > 0) throw new Error(`COMMANDER_WITNESS_ALLOW takes bare executable names only; rejected: ${bad.join(', ')}`);
    if (tenants.length === 0) {
      throw new Error('COMMANDER_WITNESS_TENANTS must name the tenants allowed to use witnessing (comma-separated ids, or * for every tenant)');
    }
  }
  return {
    mode,
    root,
    allow,
    path: env.COMMANDER_WITNESS_PATH || '/usr/local/bin:/usr/bin:/bin',
    tenants: tenants.includes('*') ? '*' : tenants,
    concurrency,
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const linkSecret = secret('COMMANDER_LINK_SECRET', env.COMMANDER_LINK_SECRET);
  const adminToken = secret('COMMANDER_ADMIN_TOKEN', env.COMMANDER_ADMIN_TOKEN);
  const policy = env.COMMANDER_POLICY_FILE
    ? PolicySchema.parse(JSON.parse(readFileSync(env.COMMANDER_POLICY_FILE, 'utf8')))
    : defaultPolicy();
  const port = Number(env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`Invalid PORT: ${env.PORT}`);
  const host = env.HOST ?? '127.0.0.1';
  return {
    host,
    port,
    dataDir: env.COMMANDER_DATA_DIR || undefined,
    publicUrl: (env.COMMANDER_PUBLIC_URL ?? `http://${host}:${port}`).replace(/\/+$/, ''),
    linkSecret: linkSecret ?? randomBytes(32).toString('hex'),
    linkSecretEphemeral: !linkSecret,
    adminToken,
    notifyWebhook: env.COMMANDER_NOTIFY_WEBHOOK || undefined,
    notifyTopic: env.COMMANDER_NOTIFY_TOPIC || undefined,
    geminiApiKey: env.GEMINI_API_KEY || undefined,
    geminiModel: env.COMMANDER_GEMINI_MODEL ?? 'gemini-2.5-flash',
    witness: loadWitness(env),
    policy,
  };
}
