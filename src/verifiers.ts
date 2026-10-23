import { runInNewContext } from 'node:vm';
import { Ajv, type ValidateFunction } from 'ajv';
import type { Policy } from './config.js';
import { CommanderError } from './errors.js';
import { auditDiff } from './inquisitor.js';
import type { Evidence, StepDef, VerifierResult, VerifierSpec } from './types.js';
import { byteLength, sanitizeLine, sha256, stableStringify } from './util.js';

/**
 * Mechanical verifiers. A verifier never consults the worker's opinion of its own work: the `claim`
 * field of the evidence is not read here. Any verifier that throws is a failed verifier (fail closed).
 */

export interface VerifyContext {
  evidence: Evidence;
  /** Nonce issued for the current attempt, if the step uses one. */
  nonce?: string;
  policy: Pick<Policy, 'forbidden_paths' | 'max_patch_lines'>;
}

const ajv = new Ajv({ allErrors: true, strict: false });
const compiled = new Map<string, ValidateFunction>();
const REGEX_TIMEOUT_MS = 100;
const MAX_SCHEMA_BYTES = 65_536;

function compileSchema(schema: Record<string, unknown>): ValidateFunction {
  const raw = stableStringify(schema);
  if (byteLength(raw) > MAX_SCHEMA_BYTES) throw new Error('schema exceeds 64 KiB');
  const key = sha256(raw);
  let fn = compiled.get(key);
  if (!fn) {
    fn = ajv.compile(schema);
    if (compiled.size > 500) compiled.clear();
    compiled.set(key, fn);
  }
  return fn;
}

/** Evaluated in a throwaway VM context with a watchdog so a pathological pattern cannot stall the process. */
function regexTest(pattern: string, flags: string, input: string): boolean {
  return runInNewContext('new RegExp(p, f).test(s)', { p: pattern, f: flags, s: input }, { timeout: REGEX_TIMEOUT_MS }) as boolean;
}

/** Rejects unusable step definitions at mission-open time, not at the worker's first submission. */
export function validateSpecs(def: StepDef): void {
  def.proof.forEach((spec, i) => {
    const where = `step "${def.title}" proof[${i}] (${spec.type})`;
    try {
      if (spec.type === 'json_schema') compileSchema(spec.schema);
      if (spec.type === 'regex') new RegExp(spec.pattern, spec.flags);
    } catch (err) {
      throw new CommanderError('INVALID', `${where}: ${sanitizeLine((err as Error).message, 200)}`);
    }
  });
}

function resolveTarget(evidence: Evidence, target: string): string | undefined {
  if (target === 'stdout') return evidence.stdout;
  if (target === 'stderr') return evidence.stderr;
  const name = target.slice('artifact:'.length);
  const artifacts = evidence.artifacts;
  return artifacts && Object.hasOwn(artifacts, name) ? artifacts[name] : undefined;
}

const result = (spec: VerifierSpec, ok: boolean, reason: string, fix: string): VerifierResult => ({
  type: spec.type,
  ok,
  hidden: spec.hidden ?? false,
  reason,
  fix,
});

function missing(spec: VerifierSpec, target: string): VerifierResult {
  return result(spec, false, `No ${target} was supplied.`, `Include ${target} in the evidence.`);
}

function verifyOne(spec: VerifierSpec, ctx: VerifyContext): VerifierResult {
  const { evidence } = ctx;
  switch (spec.type) {
    case 'exit_code': {
      if (evidence.exit_code === undefined) {
        return result(spec, false, 'No exit code was reported.', 'Run the command and report its real exit code in exit_code.');
      }
      const ok = evidence.exit_code === spec.expected;
      return result(
        spec,
        ok,
        ok ? `Exit code ${spec.expected}.` : `Required exit code ${spec.expected}; received ${evidence.exit_code}.`,
        'Resolve the failure, re-run, and report the true exit code. A different number is not a fix.',
      );
    }
    case 'json_valid': {
      const text = resolveTarget(evidence, spec.target);
      if (text === undefined) return missing(spec, spec.target);
      try {
        JSON.parse(text);
        return result(spec, true, `${spec.target} parses as JSON.`, '');
      } catch {
        return result(spec, false, `${spec.target} is not valid JSON.`, `Emit only a single valid JSON document in ${spec.target}.`);
      }
    }
    case 'json_schema': {
      const text = resolveTarget(evidence, spec.target);
      if (text === undefined) return missing(spec, spec.target);
      let doc: unknown;
      try {
        doc = JSON.parse(text);
      } catch {
        return result(spec, false, `${spec.target} is not valid JSON.`, `Emit a valid JSON document in ${spec.target}.`);
      }
      const validate = compileSchema(spec.schema);
      if (validate(doc)) return result(spec, true, 'Schema satisfied.', '');
      const errs = (validate.errors ?? [])
        .slice(0, 3)
        .map((e) => sanitizeLine(`${e.instancePath || '/'} ${e.message ?? 'invalid'}`, 80))
        .join('; ');
      return result(spec, false, `Schema violations: ${errs}.`, 'Conform the document to the required schema.');
    }
    case 'regex': {
      const text = resolveTarget(evidence, spec.target);
      if (text === undefined) return missing(spec, spec.target);
      let hit: boolean;
      try {
        hit = regexTest(spec.pattern, spec.flags, text);
      } catch {
        return result(spec, false, 'Pattern evaluation exceeded its time limit.', 'Reduce the size or complexity of the output.');
      }
      const ok = hit === spec.must_match;
      return result(
        spec,
        ok,
        ok
          ? 'Pattern requirement satisfied.'
          : spec.must_match
            ? `Required pattern /${spec.pattern}/ not found in ${spec.target}.`
            : `Forbidden pattern /${spec.pattern}/ present in ${spec.target}.`,
        spec.must_match ? `Produce output in ${spec.target} that matches the required pattern.` : `Remove the offending output from ${spec.target}.`,
      );
    }
    case 'artifact_present': {
      const content = resolveTarget(evidence, `artifact:${spec.name}`);
      if (content === undefined) return result(spec, false, `Artifact ${spec.name} was not submitted.`, `Submit ${spec.name} in artifacts.`);
      const size = byteLength(content);
      const ok = size >= spec.min_bytes;
      return result(
        spec,
        ok,
        ok ? `Artifact ${spec.name} present (${size} bytes).` : `Artifact ${spec.name} is ${size} bytes; minimum is ${spec.min_bytes}.`,
        `Submit the complete contents of ${spec.name}.`,
      );
    }
    case 'artifact_hash': {
      const content = resolveTarget(evidence, `artifact:${spec.name}`);
      if (content === undefined) return result(spec, false, `Artifact ${spec.name} was not submitted.`, `Submit ${spec.name} in artifacts.`);
      const ok = sha256(content) === spec.sha256;
      return result(
        spec,
        ok,
        ok ? `Artifact ${spec.name} hash verified.` : `Artifact ${spec.name} does not match the required hash.`,
        `Submit the exact required contents of ${spec.name}.`,
      );
    }
    case 'nonce_present': {
      if (!ctx.nonce) return result(spec, false, 'No nonce is active for this attempt.', 'Pull a fresh directive.');
      const haystacks = [evidence.stdout, evidence.stderr, ...Object.values(evidence.artifacts ?? {})];
      const ok = haystacks.some((h) => h?.includes(ctx.nonce!));
      return result(
        spec,
        ok,
        ok ? 'Nonce present.' : 'Attempt nonce not found in the evidence.',
        'Print the attempt nonce verbatim from the command you are proving, or write it into an artifact.',
      );
    }
    case 'diff_policy': {
      const diff = resolveTarget(evidence, `artifact:${spec.artifact}`);
      if (diff === undefined) return result(spec, false, `Patch artifact ${spec.artifact} was not submitted.`, `Submit the unified diff as ${spec.artifact}.`);
      const audit = auditDiff(diff, ctx.policy);
      const shown = audit.violations.slice(0, 3).map((v) => sanitizeLine(v, 100)).join('; ');
      return result(
        spec,
        audit.ok,
        audit.ok ? `Patch within policy (${audit.files} files, ${audit.linesChanged} lines).` : `Patch rejected: ${shown}.`,
        'Resubmit a patch that stays inside policy: no forbidden paths, no secrets, within the size limit.',
      );
    }
  }
}

/** Runs every verifier (no short-circuit) so the redirect patch can name every failure at once. */
export function runVerifiers(def: StepDef, ctx: VerifyContext): VerifierResult[] {
  const specs: VerifierSpec[] = [...def.proof];
  if (def.require_nonce && !specs.some((s) => s.type === 'nonce_present')) specs.push({ type: 'nonce_present' });
  return specs.map((spec) => {
    try {
      return verifyOne(spec, ctx);
    } catch {
      return result(spec, false, 'Verifier fault. Treated as failed.', 'Resubmit well-formed evidence.');
    }
  });
}
