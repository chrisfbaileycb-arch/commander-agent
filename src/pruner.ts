import type { Evidence, VerifierResult } from './types.js';
import { byteLength, estimateTokens, sanitizeLine, sha256, stripAnsi } from './util.js';

/**
 * Just-In-Time Markdown Pruning Filter.
 *
 * Turns a worker's verbose evidence into one atomic markdown manifest. The manifest is built from
 * verifier outcomes and whitelisted counters, not from the worker's prose, so persistent context
 * cannot be steered by whatever text the worker chose to print.
 */

export interface PruneInput {
  stepTitle: string;
  attempt: number;
  passed: boolean;
  results: VerifierResult[];
  evidence: Evidence;
  /** How many of `results` came from independent verification rather than worker-supplied evidence. */
  witnessed?: number;
}

export interface PruneOutput {
  manifest: string;
  rawTokens: number;
  prunedTokens: number;
}

const md = (s: string): string => sanitizeLine(s, 100).replace(/[`*_|\\[\]<>]/g, '');

export function rawEvidenceText(e: Evidence): string {
  return [e.stdout, e.stderr, e.claim, ...Object.values(e.artifacts ?? {})].filter(Boolean).join('\n');
}

/** Whitelisted counters only. Each pattern yields a number, never free text. */
function metrics(text: string): string[] {
  const clean = stripAnsi(text);
  const out: string[] = [];
  const last = (re: RegExp): string | undefined => [...clean.matchAll(re)].at(-1)?.[1];
  const passed = last(/\b(\d{1,7})\s+(?:tests?\s+)?passed\b/gi);
  const failed = last(/\b(\d{1,7})\s+(?:tests?\s+)?failed\b/gi);
  const errors = last(/\b(\d{1,7})\s+errors?\b/gi);
  const warnings = last(/\b(\d{1,7})\s+warnings?\b/gi);
  if (passed) out.push(`${passed} passed`);
  if (failed) out.push(`${failed} failed`);
  if (errors) out.push(`${errors} errors`);
  if (warnings) out.push(`${warnings} warnings`);
  return out;
}

function artifactFacts(e: Evidence): string[] {
  return Object.entries(e.artifacts ?? {})
    .slice(0, 4)
    .map(([name, content]) => {
      const bytes = byteLength(content);
      const size = bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
      return `\`${md(name)}\` (${size} · ${sha256(content).slice(0, 8)})`;
    });
}

function firstErrorLine(e: Evidence): string | undefined {
  for (const text of [e.stderr, e.stdout]) {
    const line = stripAnsi(text ?? '')
      .split('\n')
      .find((l) => /\b(error|fail(?:ed|ure)?|exception|traceback|fatal)\b/i.test(l));
    if (line) return md(line);
  }
  return undefined;
}

export function prune(input: PruneInput): PruneOutput {
  const { stepTitle, attempt, passed, results, evidence } = input;
  const title = md(stepTitle);
  const rawTokens = estimateTokens(rawEvidenceText(evidence));
  let manifest: string;

  if (passed) {
    const exit = evidence.exit_code === undefined ? '' : `, exit ${evidence.exit_code}`;
    const facts = [...metrics(`${evidence.stdout ?? ''}\n${evidence.stderr ?? ''}`), ...artifactFacts(evidence)];
    manifest =
      `- **${title}** — verified on attempt ${attempt}; ${results.length}/${results.length} checks passed` +
      `${input.witnessed ? ` (${input.witnessed} independently witnessed)` : ''}${exit}.` +
      (facts.length ? ` Evidence: ${facts.join('; ')}.` : '');
  } else {
    const failed = results.filter((r) => !r.ok);
    const err = firstErrorLine(evidence);
    manifest =
      `- **${title}** — rejected on attempt ${attempt}; ${failed.length} of ${results.length} checks failed (${[...new Set(failed.map((r) => r.type))].join(', ')}).` +
      (err ? ` Worker output: "${err}".` : '');
  }
  return { manifest, rawTokens, prunedTokens: estimateTokens(manifest) };
}
