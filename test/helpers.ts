import { createApp, type App } from '../src/app.js';
import type { ActionCard, Notifier } from '../src/approvals.js';
import type { DirectiveResult } from '../src/airlock.js';
import { defaultPolicy, loadConfig, type Policy } from '../src/config.js';
import type { CommanderError } from '../src/errors.js';
import type { ReasoningGate } from '../src/gate.js';
import type { Principal } from '../src/types.js';
import type { FileInspection, RunRequest, RunResult, Witness } from '../src/witness.js';

export class FakeClock {
  t = Date.UTC(2026, 0, 1, 12, 0, 0);
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

export class CaptureNotifier implements Notifier {
  cards: ActionCard[] = [];
  async notify(card: ActionCard): Promise<void> {
    this.cards.push(card);
  }
}

/** A scriptable stand-in for an independent runner: records what it was asked and answers from canned data. */
export class FakeWitness implements Witness {
  readonly kind = 'fake';
  runs: RunRequest[] = [];
  inspections: string[] = [];
  files = new Map<string, FileInspection>();
  runImpl: (req: RunRequest) => RunResult | Promise<RunResult> = () => ({
    exitCode: 0,
    stdout: '',
    stderr: '',
    truncated: false,
    timedOut: false,
    durationMs: 1,
  });
  async run(req: RunRequest): Promise<RunResult> {
    this.runs.push(req);
    return this.runImpl(req);
  }
  async inspect(relPath: string): Promise<FileInspection> {
    this.inspections.push(relPath);
    return this.files.get(relPath) ?? { exists: false };
  }
}

export interface Harness {
  app: App;
  clock: FakeClock;
  notifier: CaptureNotifier;
  tenantId: string;
  operator: Principal;
  worker: Principal;
  operatorKey: string;
  workerKey: string;
}

export function makeHarness(
  opts: {
    policy?: Partial<Policy>;
    gate?: ReasoningGate;
    credits?: number;
    notifier?: Notifier;
    witness?: Witness;
    /** Which tenants may define witness checks. Defaults to every tenant. */
    witnessTenants?: string[] | '*';
  } = {},
): Harness {
  const clock = new FakeClock();
  const notifier = new CaptureNotifier();
  const config = {
    ...loadConfig({}),
    policy: { ...defaultPolicy(), ...opts.policy },
    linkSecret: 'test-link-secret',
    publicUrl: 'http://commander.test',
    dataDir: undefined,
    witness: { mode: 'off' as const, allow: [] as string[], path: '/usr/bin', tenants: opts.witnessTenants ?? ('*' as const), concurrency: 2 },
  };
  const app = createApp({ config, clock: clock.now, notifier: opts.notifier ?? notifier, gate: opts.gate, witness: opts.witness });
  const { tenant, operatorKey } = app.auth.createTenant('acme', opts.credits ?? 10_000);
  const { key: workerKey } = app.auth.issueKey(tenant.id, 'worker');
  return {
    app,
    clock,
    notifier,
    tenantId: tenant.id,
    operator: app.auth.authenticate(`Bearer ${operatorKey}`),
    worker: app.auth.authenticate(`Bearer ${workerKey}`),
    operatorKey,
    workerKey,
  };
}

/** A second, unrelated tenant on the same app. */
export function addTenant(h: Harness, name = 'rival'): { operator: Principal; worker: Principal } {
  const { tenant, operatorKey } = h.app.auth.createTenant(name, 10_000);
  const { key } = h.app.auth.issueKey(tenant.id, 'worker');
  return { operator: h.app.auth.authenticate(`Bearer ${operatorKey}`), worker: h.app.auth.authenticate(`Bearer ${key}`) };
}

export const threeStep = () => ({
  title: 'Ship feature',
  steps: [
    {
      title: 'Build',
      directive: 'Run the build and report.',
      proof: [{ type: 'exit_code' }, { type: 'regex', pattern: 'BUILD OK' }],
      require_nonce: true,
    },
    {
      title: 'Report',
      directive: 'SECRET-STEP-TWO-DIRECTIVE emit the report as JSON.',
      proof: [{ type: 'json_schema', schema: { type: 'object', required: ['total'], properties: { total: { type: 'integer' } } } }],
    },
    {
      title: 'Seal',
      directive: 'SECRET-STEP-THREE-DIRECTIVE write the seal.',
      proof: [{ type: 'artifact_present', name: 'seal.txt' }],
    },
  ],
});

export const oneStep = (extra: Record<string, unknown> = {}) => ({
  title: 'Solo',
  steps: [{ title: 'Only step', directive: 'Do the thing.', proof: [{ type: 'exit_code' }], ...extra }],
});

export const goodBuild = (nonce?: string) => ({ exit_code: 0, stdout: `BUILD OK\n14 passed${nonce ? `\n${nonce}` : ''}` });

export function pull(h: Harness, missionId: string, worker: Principal = h.worker): Extract<DirectiveResult, { state: 'DIRECTIVE' }> {
  const r = h.app.airlock.getDirective(worker, missionId);
  if (r.state !== 'DIRECTIVE') throw new Error(`expected DIRECTIVE, got ${r.state}`);
  return r;
}

export function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return (e as CommanderError).code ?? `NON_COMMANDER:${String(e)}`;
  }
  return undefined;
}

export async function codeOfAsync(fn: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await fn();
  } catch (e) {
    return (e as CommanderError).code ?? `NON_COMMANDER:${String(e)}`;
  }
  return undefined;
}
