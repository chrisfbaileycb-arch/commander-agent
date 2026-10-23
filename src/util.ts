import { createHash, randomBytes } from 'node:crypto';

export type Clock = () => number;

export const sha256 = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');

export const newId = (prefix: string): string => `${prefix}_${randomBytes(9).toString('base64url')}`;

export const newSecret = (prefix: string): string => `${prefix}${randomBytes(24).toString('base64url')}`;

export const iso = (ms: number): string => new Date(ms).toISOString();

export const byteLength = (s: string): number => Buffer.byteLength(s, 'utf8');

/** Deterministic JSON: object keys sorted recursively. Used for hashing and the audit chain. */
export function stableStringify(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

/** Strip terminal escapes and control characters; collapse whitespace; truncate. */
export function sanitizeLine(s: string, max = 160): string {
  const clean = s.replace(ANSI, '').replace(CONTROL, '').replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/** Rough token estimate (~4 chars/token). Used for the pruning metrics only, never for billing. */
export const estimateTokens = (s: string): number => Math.ceil(s.length / 4);

export function stripAnsi(s: string): string {
  return s.replace(ANSI, '');
}
