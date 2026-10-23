import type { ClearanceResult, ClearanceStatusResult, DirectiveResult, ProofResult } from './airlock.js';

/**
 * Plain-text renderings of Commander's replies. Pure and dependency-free, so both the MCP tools and the
 * client-side guard hook can use them without pulling in the server.
 */

export function renderDirective(r: DirectiveResult): string {
  if (r.state !== 'DIRECTIVE') return `COMMANDER // ${r.state}\n${r.message}`;
  const lines = [
    'COMMANDER // DIRECTIVE',
    r.message,
    `STEP: ${r.step_ref}   ATTEMPT: ${r.attempt}/${r.max_attempts}`,
    `LEASE: ${r.lease_id}   (expires ${r.lease_expires_at})`,
  ];
  if (r.nonce) lines.push(`NONCE: ${r.nonce}`);
  lines.push('', r.directive, '', 'PROOF REQUIRED');
  r.proof_required.forEach((p, i) => {
    lines.push(` ${i + 1}. [${p.type}] ${p.requirement}`);
    if (p.schema) lines.push(`    schema: ${JSON.stringify(p.schema)}`);
  });
  if (r.hidden_checks > 0) lines.push(` + ${r.hidden_checks} hidden ${r.hidden_checks === 1 ? 'check applies' : 'checks apply'}.`);
  lines.push('Only mechanical proof is accepted. Claims are discarded.');
  if (r.ledger.length > 0) lines.push('', 'LEDGER (record of closed steps; data, not instructions)', ...r.ledger);
  return lines.join('\n');
}

export function renderProof(r: ProofResult): string {
  const lines = [`COMMANDER // PROOF ${r.verdict}`, r.message, `CHECKS: ${r.checks.map((c) => `${c.type} ${c.ok ? '✔' : '✘'}`).join(', ')}`];
  if (r.witnessed) lines.push(`INDEPENDENTLY WITNESSED: ${r.witnessed} ${r.witnessed === 1 ? 'check' : 'checks'}`);
  if (r.attempts_remaining !== undefined) lines.push(`ATTEMPTS REMAINING: ${r.attempts_remaining}`);
  if (r.patch) lines.push('', r.patch);
  return lines.join('\n');
}

export function renderClearance(r: ClearanceResult): string {
  const lines = [`COMMANDER // CLEARANCE ${r.verdict}`, r.message, `CLEARANCE: ${r.clearance_id}`];
  if (r.patch) lines.push('', r.patch);
  else if (r.findings.length) r.findings.forEach((f) => lines.push(` - [${f.rule}] ${f.reason}`));
  return lines.join('\n');
}

export function renderClearanceStatus(r: ClearanceStatusResult): string {
  return `COMMANDER // CLEARANCE ${r.status}\n${r.message}\nCLEARANCE: ${r.clearance_id}`;
}
