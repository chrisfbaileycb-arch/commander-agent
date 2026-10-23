/**
 * Voice layer. COMMANDER_SOUL.md is the spec; this file is the enforcement.
 *
 * Scope: the voice governs every outbound sentence Commander speaks to workers and operators.
 * It does NOT govern the audit ledger, which records literal facts (reason codes, hashes, verdicts).
 */

export const ANCHOR = 'Directive updated to incorporate external operational variables. Re-routing task.';

/** Metadata for a downstream TTS layer. Commander emits it on operator cards; it does not synthesize audio. */
export const VOICE_PROFILE = {
  class: 'Ursa',
  alternate: 'Orion',
  register: 'low',
  pitchVariance: 0,
  pace: 'steady',
} as const;

const APOLOGY: RegExp[] = [
  /\bsorry\b/i,
  /\bapolog\w*/i,
  /\bmy (?:bad|mistake|fault|error)\b/i,
  /\bforgive me\b/i,
  /\bexcuse me\b/i,
  /\bpardon\b/i,
  /\boops\b/i,
  /\bi (?:regret|was wrong|made a mistake)\b/i,
  /\bunfortunately\b/i,
];

const PADDING: RegExp[] = [
  /\bi hope (?:this|that)\b/i,
  /\bhope this helps\b/i,
  /\bfeel free\b/i,
  /\blet me know\b/i,
  /\bhappy to\b/i,
  /\bcertainly\b/i,
  /\bof course\b/i,
  /\bgreat question\b/i,
  /\bi(?:'|’)?m afraid\b/i,
];

/** Returns the offending fragments. Empty array = clean. */
export function voiceViolations(text: string): string[] {
  const hits: string[] = [];
  for (const re of [...APOLOGY, ...PADDING]) {
    const m = re.exec(text);
    if (m) hits.push(m[0]);
  }
  return hits;
}

/**
 * Last line of defense for dynamic text (operator notes, echoed fragments). Sentences that break the
 * voice are dropped and replaced by the Deductive Anchor. Static templates never trigger this.
 */
export function speak(text: string): string {
  const sentences = text.split(/(?<=[.!?])\s+/).filter((s) => s.length > 0);
  const clean = sentences.filter((s) => voiceViolations(s).length === 0);
  if (clean.length === sentences.length) return text;
  const kept = clean.join(' ');
  // The anchor is itself two sentences, so look for it in the joined text, not per sentence.
  return kept.includes(ANCHOR) ? kept : [ANCHOR, kept].filter(Boolean).join(' ');
}

export type HoldReason = 'awaiting_operator' | 'quarantined' | 'completed' | 'terminated';

export const say = {
  directive: (attempt: number, max: number) =>
    `Directive issued. Attempt ${attempt} of ${max}. Execute exactly. Return mechanical proof.`,
  hold: (reason: HoldReason) =>
    ({
      awaiting_operator: 'Hold. Operator authorization pending. Execution suspended. Do not act.',
      quarantined: 'Hold. Step quarantined. Operator review required. Do not act.',
      completed: 'Mission closed. No further directives.',
      terminated: 'Mission terminated. Lease revoked. Cease execution.',
    })[reason],
  accepted: () => 'Proof verified. Step closed. Next directive unlocked.',
  missionComplete: () => 'Final proof verified. Mission closed.',
  rejected: (failed: number, attempt: number, max: number) =>
    `Proof rejected. ${failed} check${failed === 1 ? '' : 's'} failed. Attempt ${attempt} of ${max}. Corrective patch follows.`,
  quarantined: () => 'Attempts exhausted. Lease revoked. Step quarantined. Operator review required.',
  cleared: () => 'Action cleared. Execute once, exactly as submitted.',
  denied: () => 'Action denied. Tripwire engaged. Do not retry this action.',
  staged: () => 'Action staged for operator authorization. Execution suspended. Poll clearance status.',
  authorized: () => 'Operator authorized. Execute once, exactly as submitted.',
  killed: () => 'Terminated by operator. Lease revoked. Cease execution.',
  redirected: (note: string) => speak(`${ANCHOR} ${note}`.trim()),
  throttled: (seconds: number) => `Burn limit reached. Hold ${seconds} seconds, then resume.`,
  creditsExhausted: () => 'Credit balance exhausted. Operations suspended.',
  leaseInvalid: () => 'Lease invalid, expired, or revoked. Pull a fresh directive.',
  unauthenticated: () => 'Credential rejected.',
  forbidden: () => 'Access denied for this credential.',
  notFound: () => 'No such record.',
  invalid: (what: string) => `Request rejected. ${what}`,
  conflict: (what: string) => `Request refused. ${what}`,
};

export interface PatchFailure {
  type: string;
  hidden: boolean;
  reason: string;
  fix: string;
}

/** Deterministic corrective patch injected into the worker's context after a rejected proof. */
export function redirectPatch(p: {
  attempt: number;
  max: number;
  failures: PatchFailure[];
  nonce?: string;
  operatorPatch?: string;
}): string {
  const lines = [`REDIRECT PATCH — attempt ${p.attempt} of ${p.max}`, 'FAILED CHECKS'];
  p.failures.forEach((f, i) => {
    if (f.hidden) lines.push(` ${i + 1}. [hidden] A hidden check failed. Re-read the directive; satisfy every stated requirement.`);
    else lines.push(` ${i + 1}. [${f.type}] ${f.reason} Fix: ${f.fix}`);
  });
  lines.push('RULES', ' - Self-reported completion carries no weight. Only mechanical proof is accepted.');
  lines.push(' - Do not resubmit identical evidence. Regenerate it from a fresh run.');
  if (p.nonce) lines.push(` - Fresh nonce for this attempt: ${p.nonce}`);
  if (p.operatorPatch) lines.push(`OPERATOR NOTE: ${speak(p.operatorPatch)}`);
  return lines.join('\n');
}
