import type { Approvals, Decision } from './approvals.js';
import type { Auth } from './auth.js';
import type { Policy } from './config.js';
import { CommanderError } from './errors.js';
import { tighten, type GateVerdict, type ReasoningGate } from './gate.js';
import { redactSecrets } from './inquisitor.js';
import { actionRedirectPatch, redirectPatch, say, type HoldReason } from './persona.js';
import { prune, rawEvidenceText } from './pruner.js';
import { normalizeAction, type Sentinel } from './sentinel.js';
import type { Store } from './store.js';
import {
  ActionRequestSchema,
  EvidenceSchema,
  MAX_EVIDENCE_BYTES,
  MissionDefSchema,
  isWitnessSpec,
  type ActionRequest,
  type Approval,
  type Attempt,
  type Clearance,
  type Evidence,
  type Finding,
  type Mission,
  type MissionDef,
  type Principal,
  type StepState,
  type VerifierResult,
  type VerifierSpec,
  type WitnessSpec,
} from './types.js';
import { byteLength, iso, newId, sanitizeLine, sha256, shellQuote, stableStringify, type Clock } from './util.js';
import { runVerifiers, validateSpecs } from './verifiers.js';
import { runWitnessVerifiers, type Witness } from './witness.js';

/**
 * The Step-Gated Airlock.
 *
 * The mission ledger is held here. A worker is only ever shown the CURRENT step, and step N+1 stays
 * locked until step N's mechanical verifiers pass. Everything that crosses to the worker is built here;
 * nothing the worker says about its own work is ever consulted.
 */

export interface AirlockDeps {
  store: Store;
  auth: Auth;
  sentinel: Sentinel;
  gate: ReasoningGate;
  approvals: Approvals;
  policy: Policy;
  clock: Clock;
  /** Present only when independent witnessing is enabled on this deployment. */
  witness?: { runner: Witness; allows: (tenantId: string) => boolean };
}

export interface ProofRequirement {
  type: string;
  requirement: string;
  schema?: Record<string, unknown>;
}

export type DirectiveResult =
  | {
      state: 'DIRECTIVE';
      message: string;
      step_ref: string;
      attempt: number;
      max_attempts: number;
      directive: string;
      proof_required: ProofRequirement[];
      hidden_checks: number;
      nonce?: string;
      lease_id: string;
      lease_expires_at: string;
      /** Manifests of closed steps. A record, not instructions. */
      ledger: string[];
    }
  | { state: 'HOLD'; reason: HoldReason; message: string }
  | { state: 'COMPLETE'; message: string }
  | { state: 'TERMINATED'; message: string };

export interface ProofResult {
  verdict: 'PASSED' | 'REJECTED' | 'QUARANTINED';
  message: string;
  attempt: number;
  checks: { type: string; ok: boolean }[];
  attempts_remaining?: number;
  patch?: string;
  nonce?: string;
  manifest?: string;
  mission_complete?: boolean;
  /** How many of the checks Commander ran itself rather than taking the worker's word. */
  witnessed?: number;
}

export interface ClearanceResult {
  verdict: 'CLEARED' | 'DENIED' | 'STAGED';
  clearance_id: string;
  message: string;
  findings: { rule: string; reason: string }[];
  patch?: string;
}

export interface ClearanceStatusResult {
  clearance_id: string;
  status: 'CLEARED' | 'DENIED' | 'PENDING' | 'TERMINATED';
  message: string;
}

function lookup<T extends { tenantId: string }>(table: Record<string, T>, id: string, tenantId: string): T {
  if (!Object.hasOwn(table, id)) throw new CommanderError('NOT_FOUND', say.notFound());
  const rec = table[id]!;
  if (rec.tenantId !== tenantId) throw new CommanderError('NOT_FOUND', say.notFound());
  return rec;
}

function describeSpec(spec: VerifierSpec): ProofRequirement | null {
  if (spec.hidden) return null;
  switch (spec.type) {
    case 'exit_code':
      return { type: spec.type, requirement: `Report exit_code equal to ${spec.expected}.` };
    case 'json_valid':
      return { type: spec.type, requirement: `${spec.target} must be a single valid JSON document.` };
    case 'json_schema':
      return { type: spec.type, requirement: `${spec.target} must be JSON that satisfies the attached schema.`, schema: spec.schema };
    case 'regex':
      return { type: spec.type, requirement: `${spec.target} must ${spec.must_match ? '' : 'not '}match /${spec.pattern}/${spec.flags}.` };
    case 'artifact_present':
      return { type: spec.type, requirement: `Submit artifact "${spec.name}" with at least ${spec.min_bytes} byte${spec.min_bytes === 1 ? '' : 's'}.` };
    case 'artifact_hash':
      return { type: spec.type, requirement: `Artifact "${spec.name}" must hash (sha256) to ${spec.sha256}.` };
    case 'nonce_present':
      return { type: spec.type, requirement: 'Include the attempt nonce verbatim in stdout, stderr, or an artifact.' };
    case 'diff_policy':
      return { type: spec.type, requirement: `Submit artifact "${spec.artifact}" as a unified diff that stays inside policy (no forbidden paths, no secrets, size limit).` };
    case 'witness_command': {
      const cmd = sanitizeLine(spec.argv.join(' '), 120);
      return {
        type: spec.type,
        requirement:
          `Commander will independently run "${cmd}"${spec.cwd ? ` in ${spec.cwd}` : ''} and require exit code ${spec.expected_exit}` +
          `${spec.stdout_regex ? ` with stdout matching /${spec.stdout_regex}/${spec.flags}` : ''}. Your reported exit code is not used.`,
      };
    }
    case 'witness_file': {
      const needs = [
        spec.min_bytes > 0 ? `at least ${spec.min_bytes} bytes` : '',
        spec.sha256 ? 'an exact hash' : '',
        spec.regex ? `content matching /${spec.regex}/${spec.flags}` : '',
        spec.schema ? 'JSON satisfying a schema' : '',
        spec.matches_artifact ? `to be identical to your artifact "${spec.matches_artifact}"` : '',
      ].filter(Boolean);
      return {
        type: spec.type,
        requirement: `Commander will independently inspect "${spec.path}" in the workspace and require ${needs.length ? needs.join(', ') : 'that it exists'}.`,
      };
    }
  }
}

export class Airlock {
  /** Steps whose proof is being audited right now. Guards the await inside independent verification. */
  private readonly auditing = new Set<string>();

  constructor(private readonly d: AirlockDeps) {}

  private get state() {
    return this.d.store.state;
  }

  // ---- operator: missions ---------------------------------------------------------------------

  openMission(p: Principal, input: unknown): ReturnType<typeof missionView> {
    this.d.auth.requireRole(p, 'operator');
    const parsed = MissionDefSchema.safeParse(input);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new CommanderError('INVALID', say.invalid(`${issue?.path.join('.') || 'body'}: ${issue?.message ?? 'malformed'}.`));
    }
    const def = parsed.data;
    for (const step of def.steps) validateSpecs(step);
    this.checkWitnessSteps(p, def);

    const now = iso(this.d.clock());
    const mission: Mission = {
      id: newId('msn'),
      tenantId: p.tenantId,
      title: def.title,
      status: 'active',
      current: 0,
      manifests: [],
      createdAt: now,
      updatedAt: now,
      steps: def.steps.map((s, index) => ({
        id: newId('stp'),
        index,
        def: s,
        status: 'locked',
        attempts: [],
        attemptBudget: s.max_attempts,
      })),
    };
    this.state.missions[mission.id] = mission;
    this.d.store.audit(p.tenantId, 'mission.opened', { missionId: mission.id, title: def.title, steps: def.steps.length });
    this.d.store.touch();
    return missionView(mission);
  }

  /**
   * Independent verification executes commands, so it is rejected up front, not discovered at the first
   * submission: it must be enabled for this tenant, and every command must pass the same static rules that
   * govern workers. Witness commands are read-only checks, so anything the Sentinel would stage is refused too.
   */
  private checkWitnessSteps(p: Principal, def: MissionDef): void {
    const commands: { step: string; argv: string[] }[] = [];
    let usesWitness = false;
    for (const step of def.steps) {
      for (const spec of step.proof) {
        if (!isWitnessSpec(spec)) continue;
        usesWitness = true;
        if (spec.type === 'witness_command') commands.push({ step: step.title, argv: spec.argv });
      }
    }
    if (!usesWitness) return;
    if (!this.d.witness) throw new CommanderError('INVALID', say.invalid('Independent witnessing is not enabled on this deployment.'));
    if (!this.d.witness.allows(p.tenantId)) throw new CommanderError('INVALID', say.invalid('Independent witnessing is not enabled for this tenant.'));
    for (const c of commands) {
      const scan = this.d.sentinel.scan({ kind: 'shell', payload: c.argv.map(shellQuote).join(' ') }, { ignoreStrict: true });
      if (scan.verdict !== 'allow') {
        const rules = scan.findings.map((f) => f.rule).join(', ');
        throw new CommanderError('INVALID', say.invalid(`Step "${sanitizeLine(c.step, 60)}": witness command is not a safe read-only check (${rules}).`));
      }
    }
  }

  listMissions(p: Principal): ReturnType<typeof missionView>[] {
    this.d.auth.requireRole(p, 'operator');
    return Object.values(this.state.missions)
      .filter((m) => m.tenantId === p.tenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(missionView);
  }

  getMission(p: Principal, id: string): ReturnType<typeof missionView> {
    this.d.auth.requireRole(p, 'operator');
    return missionView(lookup(this.state.missions, id, p.tenantId));
  }

  intervene(p: Principal, id: string, input: { action: 'kill' | 'skip'; reason: string }): ReturnType<typeof missionView> {
    this.d.auth.requireRole(p, 'operator');
    const m = lookup(this.state.missions, id, p.tenantId);
    if (m.status === 'killed' || m.status === 'completed') throw new CommanderError('CONFLICT', say.conflict('Mission is already closed.'));
    const reason = sanitizeLine(input.reason, 300);
    if (!reason) throw new CommanderError('INVALID', say.invalid('A reason is required.'));

    if (input.action === 'kill') {
      this.killMission(m, `operator:${p.keyId}`, reason);
      return missionView(m);
    }
    const step = m.steps[m.current]!;
    if (step.status !== 'quarantined') throw new CommanderError('CONFLICT', say.conflict('Only a quarantined step may be skipped.'));
    step.status = 'skipped';
    this.settleApprovals(m, step, 'authorized', `Skipped by operator: ${reason}`, 'operator');
    m.manifests.push(`- **${sanitizeLine(step.def.title, 100)}** — skipped by operator without proof.`);
    this.d.store.audit(p.tenantId, 'step.skipped', { missionId: m.id, stepId: step.id, by: p.keyId, reason });
    this.advance(m);
    return missionView(m);
  }

  // ---- worker: directive ----------------------------------------------------------------------

  getDirective(p: Principal, missionId: string): DirectiveResult {
    this.d.auth.requireRole(p, 'worker');
    const m = lookup(this.state.missions, missionId, p.tenantId);
    const closed = this.closedState(m);
    if (closed) return closed;

    this.d.auth.charge(p, 'directive', m.id);
    const now = this.d.clock();
    const step = m.steps[m.current]!;

    if (step.status === 'locked') {
      step.status = 'released';
      if (step.def.require_nonce) step.nonce = newId('nonce');
    }
    if (!step.lease || step.lease.revoked || step.lease.expiresAt <= now) {
      step.lease = { id: newId('lse'), issuedAt: now, expiresAt: now + this.d.policy.lease_ttl_sec * 1000, revoked: false };
      this.d.store.audit(p.tenantId, 'directive.issued', { missionId: m.id, stepId: step.id, leaseId: step.lease.id, attempt: step.attempts.length + 1 });
      this.touchMission(m);
    }

    const requirements = step.def.proof.map(describeSpec).filter((r): r is ProofRequirement => r !== null);
    if (step.def.require_nonce && !step.def.proof.some((s) => s.type === 'nonce_present')) {
      requirements.push({ type: 'nonce_present', requirement: 'Include the attempt nonce verbatim in stdout, stderr, or an artifact.' });
    }
    const attempt = step.attempts.length + 1;
    return {
      state: 'DIRECTIVE',
      message: say.directive(attempt, step.attemptBudget),
      step_ref: step.id,
      attempt,
      max_attempts: step.attemptBudget,
      directive: step.operatorPatch ? `${step.def.directive}\n\nOPERATOR NOTE: ${say.redirected(step.operatorPatch)}` : step.def.directive,
      proof_required: requirements,
      hidden_checks: step.def.proof.filter((s) => s.hidden).length,
      nonce: step.nonce,
      lease_id: step.lease.id,
      lease_expires_at: iso(step.lease.expiresAt),
      ledger: m.manifests,
    };
  }

  missionStatus(p: Principal, missionId: string): { mission_id: string; status: Mission['status']; message: string } {
    this.d.auth.requireRole(p, 'worker');
    const m = lookup(this.state.missions, missionId, p.tenantId);
    const message =
      m.status === 'active'
        ? 'Mission active. Pull the current directive.'
        : m.status === 'completed'
          ? say.hold('completed')
          : m.status === 'killed'
            ? say.hold('terminated')
            : m.status === 'quarantined'
              ? say.hold('quarantined')
              : say.hold('awaiting_operator');
    return { mission_id: m.id, status: m.status, message };
  }

  // ---- worker: proof --------------------------------------------------------------------------

  async submitProof(p: Principal, missionId: string, input: { lease_id: string; evidence: unknown }): Promise<ProofResult> {
    this.d.auth.requireRole(p, 'worker');
    const m = lookup(this.state.missions, missionId, p.tenantId);
    this.requireActive(m);
    const step = this.currentStep(m);
    this.requireLease(step, input.lease_id);
    if (this.auditing.has(step.id)) {
      throw new CommanderError('CONFLICT', say.conflict('A proof for this step is already being audited.'));
    }

    const parsed = EvidenceSchema.safeParse(input.evidence);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new CommanderError('INVALID', say.invalid(`evidence.${issue?.path.join('.') || 'body'}: ${issue?.message ?? 'malformed'}.`));
    }
    const evidence = parsed.data;
    if (byteLength(rawEvidenceText({ ...evidence, claim: undefined })) > MAX_EVIDENCE_BYTES) {
      throw new CommanderError('PAYLOAD_TOO_LARGE', say.invalid('Evidence exceeds 1 MiB.'));
    }

    // Fail closed: a step that demands independent checks never passes on worker evidence alone.
    const witnessSpecs = step.def.proof.filter(isWitnessSpec);
    if (witnessSpecs.length > 0 && !this.d.witness?.allows(p.tenantId)) {
      throw new CommanderError('CONFLICT', say.conflict('Independent verification is unavailable for this mission. Operator action required.'));
    }

    this.d.auth.charge(p, 'proof', m.id);

    // Reserved before the first await, so a second submission cannot interleave with the audit.
    this.auditing.add(step.id);
    try {
      return await this.auditProof(p, m, step, input.lease_id, evidence, witnessSpecs);
    } finally {
      this.auditing.delete(step.id);
    }
  }

  private async auditProof(p: Principal, m: Mission, step: StepState, leaseId: string, evidence: Evidence, witnessSpecs: WitnessSpec[]): Promise<ProofResult> {
    const evidenceHash = sha256(stableStringify({ ...evidence, claim: undefined }));
    // With independent checks, identical worker evidence is legitimate: the disk may have changed since the last attempt.
    const replay = witnessSpecs.length === 0 && step.attempts.some((a) => a.evidenceHash === evidenceHash);

    let results: VerifierResult[];
    let witnessed = 0;
    if (replay) {
      results = [{ type: 'replay', ok: false, hidden: false, reason: 'Identical evidence was already submitted.', fix: 'Regenerate the proof from a fresh run.' }];
    } else {
      results = runVerifiers(step.def, { evidence, nonce: step.nonce, policy: this.d.policy });
      // Only spend a (possibly slow) independent run on evidence that already holds up on its face.
      if (witnessSpecs.length > 0 && results.every((r) => r.ok)) {
        this.d.auth.charge(p, 'witness', m.id);
        const witnessResults = await runWitnessVerifiers(witnessSpecs, {
          witness: this.d.witness!.runner,
          evidence,
          budgetMs: this.d.policy.witness_budget_sec * 1000,
          maxOutputBytes: this.d.policy.witness_max_output_bytes,
          maxFileBytes: 1_048_576,
        });
        // The world may have moved while the commands ran. Discard the audit rather than record it against a dead lease.
        if (m.status !== 'active' || m.steps[m.current] !== step || !this.leaseValid(step, leaseId)) {
          throw new CommanderError('LEASE_INVALID', say.leaseInvalid());
        }
        results = [...results, ...witnessResults];
        witnessed = witnessResults.length;
      }
    }
    const passed = results.every((r) => r.ok);

    const n = step.attempts.length + 1;
    const pruned = prune({ stepTitle: step.def.title, attempt: n, passed, results, evidence, witnessed });
    const attempt: Attempt = {
      n,
      at: iso(this.d.clock()),
      verdict: passed ? 'pass' : 'fail',
      evidenceHash,
      results,
      manifest: pruned.manifest,
      rawTokens: pruned.rawTokens,
      prunedTokens: pruned.prunedTokens,
      claim: evidence.claim ? sanitizeLine(evidence.claim, 500) : undefined,
    };
    step.attempts.push(attempt);
    const checks = results.map((r) => ({ type: r.hidden ? 'hidden' : r.type, ok: r.ok }));
    const failedTypes = results.filter((r) => !r.ok).map((r) => r.type);
    this.d.store.audit(p.tenantId, passed ? 'proof.accepted' : 'proof.rejected', {
      missionId: m.id,
      stepId: step.id,
      attempt: n,
      evidenceHash,
      failed: failedTypes,
      witnessed,
      rawTokens: pruned.rawTokens,
      prunedTokens: pruned.prunedTokens,
    });

    if (passed) {
      step.status = 'passed';
      if (step.lease) step.lease.revoked = true;
      m.manifests.push(pruned.manifest);
      const complete = this.advance(m);
      return {
        verdict: 'PASSED',
        message: complete ? say.missionComplete() : say.accepted(),
        attempt: n,
        checks,
        manifest: pruned.manifest,
        mission_complete: complete,
        witnessed: witnessed || undefined,
      };
    }

    if (step.attempts.length >= step.attemptBudget) {
      step.status = 'quarantined';
      if (step.lease) step.lease.revoked = true;
      m.status = 'quarantined';
      const approval = this.d.approvals.create({
        tenantId: p.tenantId,
        missionId: m.id,
        stepId: step.id,
        kind: 'quarantine',
        incident: `Step "${step.def.title}" used all ${step.attemptBudget} attempts without passing mechanical proof.`,
        reason: `Failed checks on the last attempt: ${[...new Set(failedTypes)].join(', ')}.`,
        missionTitle: m.title,
        stepTitle: step.def.title,
      });
      m.pausedFor = approval.id;
      this.d.store.audit(p.tenantId, 'step.quarantined', { missionId: m.id, stepId: step.id, approvalId: approval.id });
      this.touchMission(m);
      return { verdict: 'QUARANTINED', message: say.quarantined(), attempt: n, checks };
    }

    if (step.def.require_nonce) step.nonce = newId('nonce');
    this.touchMission(m);
    const remaining = step.attemptBudget - step.attempts.length;
    return {
      verdict: 'REJECTED',
      message: say.rejected(failedTypes.length, n + 1, step.attemptBudget),
      attempt: n,
      checks,
      attempts_remaining: remaining,
      nonce: step.nonce,
      witnessed: witnessed || undefined,
      patch: redirectPatch({
        attempt: n + 1,
        max: step.attemptBudget,
        failures: results.filter((r) => !r.ok).map((r) => ({ type: r.type, hidden: r.hidden, reason: r.reason, fix: r.fix })),
        nonce: step.nonce,
        operatorPatch: step.operatorPatch,
      }),
    };
  }

  // ---- worker: action clearance ---------------------------------------------------------------

  /** Clearance requested through the MCP tool: the worker names its lease. */
  async requestClearance(p: Principal, missionId: string, input: { lease_id: string; action: unknown }): Promise<ClearanceResult> {
    this.d.auth.requireRole(p, 'worker');
    const m = lookup(this.state.missions, missionId, p.tenantId);
    this.requireActive(m);
    const step = this.currentStep(m);
    this.requireLease(step, input.lease_id);
    return this.adjudicate(p, m, step, input.lease_id, this.parseAction(input.action), { source: 'mcp' });
  }

  /**
   * Clearance requested by the client-side hook for a NATIVE tool call (Bash, Write, Edit...). The hook cannot know
   * the lease id, so the mission is the handle: the action is judged against the mission's current released step.
   */
  async requestGuardClearance(p: Principal, missionId: string, input: { action: unknown; tool?: string }): Promise<ClearanceResult> {
    this.d.auth.requireRole(p, 'worker');
    const m = lookup(this.state.missions, missionId, p.tenantId);
    this.requireActive(m);
    const step = this.currentStep(m);
    const lease = step.lease;
    if (!lease || lease.revoked || lease.expiresAt <= this.d.clock()) throw new CommanderError('LEASE_INVALID', say.leaseInvalid());
    return this.adjudicate(p, m, step, lease.id, this.parseAction(input.action), { source: 'guard', tool: input.tool });
  }

  private parseAction(raw: unknown): ActionRequest {
    const parsed = ActionRequestSchema.safeParse(raw);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      throw new CommanderError('INVALID', say.invalid(`action.${issue?.path.join('.') || 'body'}: ${issue?.message ?? 'malformed'}.`));
    }
    return parsed.data;
  }

  private async adjudicate(
    p: Principal,
    m: Mission,
    step: StepState,
    leaseId: string,
    action: ActionRequest,
    via: { source: 'mcp' | 'guard'; tool?: string },
  ): Promise<ClearanceResult> {
    this.d.auth.charge(p, 'clearance', m.id);

    // A native action the operator already authorized is cleared exactly once, without a second round trip.
    if (via.source === 'guard') {
      const token = this.takeAuthorization(m, step, action);
      if (token) {
        this.d.store.audit(p.tenantId, 'clearance.allowed', {
          missionId: m.id,
          stepId: step.id,
          clearanceId: token.id,
          kind: action.kind,
          actionHash: token.actionHash,
          via: via.source,
          tool: via.tool,
          authorized: true,
        });
        return { verdict: 'CLEARED', clearance_id: token.id, message: say.authorized(), findings: [] };
      }
    }

    const decision = this.d.sentinel.evaluate(m.id, action);
    let verdict: GateVerdict = decision.verdict;
    const findings: Finding[] = [...decision.findings];

    if (verdict === 'allow' && step.def.risk_tier === 'critical' && action.intent !== 'read') {
      verdict = 'stage';
      findings.push({ rule: 'tier.critical', verdict: 'stage', reason: 'Critical step: every mutating action requires operator authorization.' });
    }

    if (verdict === 'allow' && step.def.risk_tier !== 'routine' && this.d.gate.active) {
      this.d.auth.charge(p, 'gate', m.id);
      const review = await this.d.gate.review({ stepTitle: step.def.title, directive: step.def.directive, action, findings });
      // The world may have moved while the gate deliberated.
      if (m.status !== 'active' || !this.leaseValid(step, leaseId)) {
        throw new CommanderError('LEASE_INVALID', say.leaseInvalid());
      }
      verdict = tighten(verdict, review.verdict);
      if (review.verdict !== 'allow') {
        findings.push({ rule: 'gate.reasoning', verdict: review.verdict === 'deny' ? 'deny' : 'stage', reason: sanitizeLine(review.rationale, 200) });
      }
    }

    const summary = redactSecrets(sanitizeLine(action.payload, 300));
    const clearance: Clearance = {
      id: newId('clr'),
      tenantId: p.tenantId,
      missionId: m.id,
      stepId: step.id,
      kind: action.kind,
      actionHash: decision.actionHash,
      summary,
      status: verdict === 'allow' ? 'allow' : verdict === 'deny' ? 'denied' : 'pending',
      findings,
      source: via.source,
      createdAt: iso(this.d.clock()),
    };
    this.state.clearances[clearance.id] = clearance;
    const shown = findings.map((f) => ({ rule: f.rule, reason: f.reason }));
    const audit = {
      missionId: m.id,
      stepId: step.id,
      clearanceId: clearance.id,
      kind: action.kind,
      actionHash: decision.actionHash,
      rules: findings.map((f) => f.rule),
      via: via.source,
      tool: via.tool,
    };

    if (verdict === 'deny') {
      this.d.store.audit(p.tenantId, 'clearance.denied', audit);
      this.d.store.touch();
      return { verdict: 'DENIED', clearance_id: clearance.id, message: say.denied(), findings: shown, patch: actionRedirectPatch(shown) };
    }

    if (verdict === 'stage') {
      const label = via.source === 'guard' ? `NATIVE ${via.tool ?? action.kind}` : action.kind.toUpperCase();
      const approval = this.d.approvals.create({
        tenantId: p.tenantId,
        missionId: m.id,
        stepId: step.id,
        kind: 'clearance',
        incident: `${label}: ${summary}`,
        reason: findings.map((f) => f.reason).join(' ').slice(0, 400),
        clearanceId: clearance.id,
        missionTitle: m.title,
        stepTitle: step.def.title,
      });
      clearance.approvalId = approval.id;
      m.status = 'paused';
      m.pausedFor = approval.id;
      this.d.store.audit(p.tenantId, 'clearance.staged', { ...audit, approvalId: approval.id });
      this.touchMission(m);
      return { verdict: 'STAGED', clearance_id: clearance.id, message: say.staged(), findings: shown };
    }

    this.d.store.audit(p.tenantId, 'clearance.allowed', audit);
    this.d.store.touch();
    return { verdict: 'CLEARED', clearance_id: clearance.id, message: say.cleared(), findings: shown };
  }

  /**
   * An operator authorization of a staged native action is a single-use pass for that exact action on that exact
   * step, valid for one lease lifetime. Anything else, including the same action later, is judged afresh.
   */
  private takeAuthorization(m: Mission, step: StepState, action: ActionRequest): Clearance | undefined {
    const hash = sha256(normalizeAction(action));
    const now = this.d.clock();
    for (const c of Object.values(this.state.clearances)) {
      if (c.source !== 'guard' || c.consumed || c.status !== 'allow' || !c.approvalId) continue;
      if (c.missionId !== m.id || c.stepId !== step.id || c.actionHash !== hash) continue;
      const decidedAt = this.state.approvals[c.approvalId]?.decidedAt;
      if (!decidedAt || now - Date.parse(decidedAt) > this.d.policy.lease_ttl_sec * 1000) continue;
      c.consumed = true;
      this.d.store.touch();
      return c;
    }
    return undefined;
  }

  clearanceStatus(p: Principal, clearanceId: string): ClearanceStatusResult {
    this.d.auth.requireRole(p, 'worker');
    const c = lookup(this.state.clearances, clearanceId, p.tenantId);
    const base = { clearance_id: c.id };
    switch (c.status) {
      case 'allow':
        return { ...base, status: 'CLEARED', message: c.approvalId ? say.authorized() : say.cleared() };
      case 'denied':
        return { ...base, status: 'DENIED', message: c.note ? say.redirected(c.note) : say.denied() };
      case 'killed':
        return { ...base, status: 'TERMINATED', message: say.killed() };
      case 'pending':
        return { ...base, status: 'PENDING', message: say.hold('awaiting_operator') };
    }
  }

  // ---- operator: decisions --------------------------------------------------------------------

  decideApproval(tenantId: string, approvalId: string, decision: Decision, note: string | undefined, via: 'operator' | 'link'): Approval {
    const a = this.d.approvals.get(tenantId, approvalId);
    if (a.status !== 'pending') throw new CommanderError('CONFLICT', say.conflict('Approval already decided.'));
    const m = lookup(this.state.missions, a.missionId, tenantId);
    if ((m.status === 'killed' || m.status === 'completed') && decision !== 'kill') {
      throw new CommanderError('CONFLICT', say.conflict('Mission is already closed.'));
    }

    let cleanNote = note ? sanitizeLine(note, 400) : undefined;
    if (decision === 'redirect' && !cleanNote) cleanNote = 'Operator redirect. Re-plan the approach and proceed.';
    a.status = decision === 'authorize' ? 'authorized' : decision === 'redirect' ? 'redirected' : 'killed';
    a.note = cleanNote;
    a.decidedAt = iso(this.d.clock());
    a.decidedVia = via;
    this.d.store.audit(tenantId, 'approval.decided', { approvalId: a.id, decision, via, kind: a.kind, missionId: m.id });

    if (decision === 'kill') {
      const c = a.clearanceId ? this.state.clearances[a.clearanceId] : undefined;
      if (c) c.status = 'killed';
      this.killMission(m, `operator:${via}`, cleanNote ?? 'Killed from approval.');
      return a;
    }

    if (a.kind === 'clearance') {
      const c = a.clearanceId ? this.state.clearances[a.clearanceId] : undefined;
      if (c) {
        c.status = decision === 'authorize' ? 'allow' : 'denied';
        c.note = decision === 'redirect' ? cleanNote : undefined;
      }
      m.status = 'active';
      m.pausedFor = undefined;
      const step = m.steps[m.current];
      if (step?.lease && !step.lease.revoked) step.lease.expiresAt = this.d.clock() + this.d.policy.lease_ttl_sec * 1000;
    } else {
      const step = m.steps[m.current]!;
      step.attemptBudget += step.def.max_attempts;
      step.status = 'released';
      step.lease = undefined;
      step.operatorPatch = decision === 'redirect' ? cleanNote : undefined;
      if (step.def.require_nonce) step.nonce = newId('nonce');
      m.status = 'active';
      m.pausedFor = undefined;
    }
    this.touchMission(m);
    return a;
  }

  // ---- internals ------------------------------------------------------------------------------

  private closedState(m: Mission): DirectiveResult | undefined {
    switch (m.status) {
      case 'completed':
        return { state: 'COMPLETE', message: say.hold('completed') };
      case 'killed':
        return { state: 'TERMINATED', message: say.hold('terminated') };
      case 'quarantined':
        return { state: 'HOLD', reason: 'quarantined', message: say.hold('quarantined') };
      case 'paused':
        return { state: 'HOLD', reason: 'awaiting_operator', message: say.hold('awaiting_operator') };
      case 'active':
        return undefined;
    }
  }

  private requireActive(m: Mission): void {
    if (m.status === 'active') return;
    if (m.status === 'completed') throw new CommanderError('CONFLICT', say.hold('completed'));
    const reason: HoldReason = m.status === 'killed' ? 'terminated' : m.status === 'quarantined' ? 'quarantined' : 'awaiting_operator';
    throw new CommanderError('HOLD', say.hold(reason), { reason });
  }

  private currentStep(m: Mission): StepState {
    const step = m.steps[m.current];
    if (!step || step.status !== 'released') throw new CommanderError('CONFLICT', say.conflict('No directive is released. Pull one first.'));
    return step;
  }

  private leaseValid(step: StepState, leaseId: string): boolean {
    const l = step.lease;
    return !!l && l.id === leaseId && !l.revoked && l.expiresAt > this.d.clock();
  }

  private requireLease(step: StepState, leaseId: string): void {
    if (!this.leaseValid(step, leaseId)) throw new CommanderError('LEASE_INVALID', say.leaseInvalid());
  }

  private touchMission(m: Mission): void {
    m.updatedAt = iso(this.d.clock());
    this.d.store.touch();
  }

  /** Moves past the current step. Returns true when the mission is complete. */
  private advance(m: Mission): boolean {
    m.current++;
    m.status = 'active';
    m.pausedFor = undefined;
    const complete = m.current >= m.steps.length;
    if (complete) {
      m.status = 'completed';
      m.current = m.steps.length - 1;
      this.d.store.audit(m.tenantId, 'mission.completed', { missionId: m.id });
    }
    this.touchMission(m);
    return complete;
  }

  private settleApprovals(m: Mission, step: StepState, status: Approval['status'], note: string, via: 'operator' | 'link'): void {
    for (const a of Object.values(this.state.approvals)) {
      if (a.missionId === m.id && a.stepId === step.id && a.status === 'pending') {
        a.status = status;
        a.note = note;
        a.decidedAt = iso(this.d.clock());
        a.decidedVia = via;
      }
    }
  }

  private killMission(m: Mission, actor: string, reason: string): void {
    m.status = 'killed';
    m.pausedFor = undefined;
    for (const s of m.steps) if (s.lease) s.lease.revoked = true;
    for (const a of Object.values(this.state.approvals)) {
      if (a.missionId === m.id && a.status === 'pending') {
        a.status = 'killed';
        a.note = 'Mission terminated.';
        a.decidedAt = iso(this.d.clock());
      }
    }
    for (const c of Object.values(this.state.clearances)) if (c.missionId === m.id && c.status === 'pending') c.status = 'killed';
    this.d.store.audit(m.tenantId, 'mission.killed', { missionId: m.id, by: actor, reason });
    this.touchMission(m);
  }
}

/** Full operator-side rendering of a mission, including every step. Workers never receive this. */
export function missionView(m: Mission) {
  return {
    id: m.id,
    title: m.title,
    status: m.status,
    current_index: m.current,
    created_at: m.createdAt,
    updated_at: m.updatedAt,
    paused_for: m.pausedFor,
    ledger: m.manifests,
    steps: m.steps.map((s) => ({
      id: s.id,
      index: s.index,
      title: s.def.title,
      directive: s.def.directive,
      status: s.status,
      risk_tier: s.def.risk_tier,
      attempt_budget: s.attemptBudget,
      attempts: s.attempts.map((a) => ({
        n: a.n,
        at: a.at,
        verdict: a.verdict,
        manifest: a.manifest,
        claim: a.claim,
        tokens: { raw: a.rawTokens, pruned: a.prunedTokens },
        results: a.results.map((r) => ({ type: r.type, ok: r.ok, hidden: r.hidden, reason: r.reason })),
      })),
    })),
  };
}
