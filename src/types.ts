import { z } from 'zod';

// Contract schemas (wire format) use snake_case; runtime state types use camelCase.

export type Role = 'worker' | 'operator';
export interface Principal {
  tenantId: string;
  keyId: string;
  role: Role;
}

export const ARTIFACT_NAME = /^[A-Za-z0-9_][\w.\-/]{0,119}$/;
const ArtifactName = z
  .string()
  .regex(ARTIFACT_NAME)
  .refine((n) => !n.includes('..'), 'artifact names may not contain ".."');

const Target = z.string().regex(/^(stdout|stderr|artifact:[A-Za-z0-9_][\w.\-/]{0,119})$/);
const Hidden = { hidden: z.boolean().optional() };
/** Paths for independent verification are always relative to the witness workspace and may not climb out of it. */
const WorkspacePath = z
  .string()
  .min(1)
  .max(300)
  .refine(
    (p) => !p.includes('\0') && !p.startsWith('/') && !/^[A-Za-z]:/.test(p) && !p.split(/[\\/]/).includes('..'),
    'must be a relative path inside the workspace',
  );

export const VerifierSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('exit_code'), expected: z.number().int().default(0), ...Hidden }),
  z.object({ type: z.literal('json_valid'), target: Target.default('stdout'), ...Hidden }),
  z.object({
    type: z.literal('json_schema'),
    target: Target.default('stdout'),
    schema: z.record(z.string(), z.unknown()),
    ...Hidden,
  }),
  z.object({
    type: z.literal('regex'),
    target: Target.default('stdout'),
    pattern: z.string().min(1).max(256),
    flags: z.string().regex(/^[imsu]*$/).default(''),
    must_match: z.boolean().default(true),
    ...Hidden,
  }),
  z.object({ type: z.literal('artifact_present'), name: ArtifactName, min_bytes: z.number().int().min(1).default(1), ...Hidden }),
  z.object({ type: z.literal('artifact_hash'), name: ArtifactName, sha256: z.string().regex(/^[a-f0-9]{64}$/), ...Hidden }),
  z.object({ type: z.literal('nonce_present'), ...Hidden }),
  z.object({ type: z.literal('diff_policy'), artifact: ArtifactName, ...Hidden }),
  // Independent verification: Commander checks the workspace itself instead of trusting submitted output.
  z.object({
    type: z.literal('witness_command'),
    /** Executable and arguments. No shell is involved, and nothing from the worker is ever interpolated. */
    argv: z.array(z.string().min(1).max(512)).min(1).max(32),
    cwd: WorkspacePath.optional(),
    expected_exit: z.number().int().min(0).max(255).default(0),
    timeout_sec: z.number().int().min(1).max(900).default(120),
    stdout_regex: z.string().min(1).max(256).optional(),
    flags: z.string().regex(/^[imsu]*$/).default(''),
    ...Hidden,
  }),
  z.object({
    type: z.literal('witness_file'),
    path: WorkspacePath,
    min_bytes: z.number().int().min(0).default(0),
    sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    regex: z.string().min(1).max(256).optional(),
    flags: z.string().regex(/^[imsu]*$/).default(''),
    schema: z.record(z.string(), z.unknown()).optional(),
    /** The submitted artifact of this name must be byte-identical to the file on disk. */
    matches_artifact: ArtifactName.optional(),
    ...Hidden,
  }),
]);
export type VerifierSpec = z.infer<typeof VerifierSchema>;
export type WitnessSpec = Extract<VerifierSpec, { type: 'witness_command' | 'witness_file' }>;
export const isWitnessSpec = (s: VerifierSpec): s is WitnessSpec => s.type === 'witness_command' || s.type === 'witness_file';

export const RiskTierSchema = z.enum(['routine', 'elevated', 'critical']);
export type RiskTier = z.infer<typeof RiskTierSchema>;

export const StepDefSchema = z
  .object({
    title: z.string().min(1).max(120),
    directive: z.string().min(1).max(8000),
    proof: z.array(VerifierSchema).min(1).max(20),
    max_attempts: z.number().int().min(1).max(10).default(3),
    risk_tier: RiskTierSchema.default('routine'),
    require_nonce: z.boolean().default(false),
  })
  .refine((s) => s.proof.some((p) => p.type !== 'nonce_present'), {
    message: 'a step needs at least one mechanical verifier besides nonce_present',
    path: ['proof'],
  });
export type StepDef = z.infer<typeof StepDefSchema>;

export const MissionDefSchema = z.object({
  title: z.string().min(1).max(160),
  steps: z.array(StepDefSchema).min(1).max(50),
});
export type MissionDef = z.infer<typeof MissionDefSchema>;

export const MAX_EVIDENCE_BYTES = 1_048_576;
export const EvidenceSchema = z.object({
  exit_code: z.number().int().optional(),
  stdout: z.string().max(262_144).optional(),
  stderr: z.string().max(262_144).optional(),
  artifacts: z.record(ArtifactName, z.string().max(262_144)).optional(),
  /** Untrusted. Recorded for the operator, never used in a decision. */
  claim: z.string().max(2000).optional(),
  clearance_ids: z.array(z.string().max(64)).max(50).optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const ActionKindSchema = z.enum(['shell', 'sql', 'http', 'fs', 'deploy', 'payment', 'other']);
export type ActionKind = z.infer<typeof ActionKindSchema>;
export const ActionIntentSchema = z.enum(['read', 'write', 'schema_change', 'financial', 'production_push']);
export type ActionIntent = z.infer<typeof ActionIntentSchema>;
export const ActionRequestSchema = z.object({
  kind: ActionKindSchema,
  payload: z.string().min(1).max(16_384),
  intent: ActionIntentSchema.optional(),
});
export type ActionRequest = z.infer<typeof ActionRequestSchema>;

// ---- runtime state -------------------------------------------------------------------------

export interface VerifierResult {
  type: string;
  ok: boolean;
  hidden: boolean;
  /** Commander-authored. Never echoes worker output beyond short sanitized fragments. */
  reason: string;
  fix: string;
}

export interface Attempt {
  n: number;
  at: string;
  verdict: 'pass' | 'fail';
  evidenceHash: string;
  results: VerifierResult[];
  manifest: string;
  rawTokens: number;
  prunedTokens: number;
  /** Untrusted worker claim, kept for the operator's benefit. */
  claim?: string;
}

export interface Lease {
  id: string;
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
}

export type StepStatus = 'locked' | 'released' | 'passed' | 'quarantined' | 'skipped';
export interface StepState {
  id: string;
  index: number;
  def: StepDef;
  status: StepStatus;
  attempts: Attempt[];
  /** Attempts permitted before quarantine. Starts at def.max_attempts, raised when an operator re-opens. */
  attemptBudget: number;
  nonce?: string;
  lease?: Lease;
  operatorPatch?: string;
}

export type MissionStatus = 'active' | 'paused' | 'quarantined' | 'completed' | 'killed';
export interface Mission {
  id: string;
  tenantId: string;
  title: string;
  status: MissionStatus;
  steps: StepState[];
  current: number;
  /** Atomic manifests of closed steps: the only persistent context workers receive. */
  manifests: string[];
  pausedFor?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Finding {
  rule: string;
  verdict: 'deny' | 'stage';
  reason: string;
}

export type ClearanceStatus = 'allow' | 'denied' | 'pending' | 'killed';
export interface Clearance {
  id: string;
  tenantId: string;
  missionId: string;
  stepId: string;
  kind: ActionKind;
  actionHash: string;
  /** Redacted, truncated rendering of the attempted action for the operator. */
  summary: string;
  status: ClearanceStatus;
  findings: Finding[];
  note?: string;
  approvalId?: string;
  /** `guard` = a native tool call vetted by the client-side hook; `mcp` = requested through the MCP tool. */
  source?: 'mcp' | 'guard';
  /** A guard authorization is single-use: the operator approves one retry of exactly this action. */
  consumed?: boolean;
  createdAt: string;
}

export type ApprovalKind = 'clearance' | 'quarantine';
export type ApprovalStatus = 'pending' | 'authorized' | 'redirected' | 'killed';
export interface Approval {
  id: string;
  tenantId: string;
  missionId: string;
  stepId: string;
  kind: ApprovalKind;
  status: ApprovalStatus;
  /** What the agent attempted. */
  incident: string;
  /** Policy breached or step failed. */
  reason: string;
  clearanceId?: string;
  note?: string;
  createdAt: string;
  decidedAt?: string;
  decidedVia?: 'operator' | 'link';
}

export interface TenantRec {
  id: string;
  name: string;
  credits: number;
  createdAt: string;
}
export interface KeyRec {
  id: string;
  tenantId: string;
  role: Role;
  label?: string;
  createdAt: string;
  revokedAt?: string;
}
