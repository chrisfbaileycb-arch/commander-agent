import type { Policy } from './config.js';

/**
 * Inquisitor Diff Auditor: structural audit of patches and text artifacts before they pass downstream.
 * Everything here is deterministic. No model is consulted.
 */

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'commander-key', re: /\bcmd_(?:live|op)_[A-Za-z0-9_-]{16,}\b/ },
  { name: 'slack-token', re: /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'api-secret-key', re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  {
    name: 'credential-assignment',
    re: /\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i,
  },
  { name: 'connection-string-password', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]{3,}@/i },
];

const GLOBAL_PATTERNS = SECRET_PATTERNS.map((p) => ({ name: p.name, re: new RegExp(p.re.source, `${p.re.flags}g`) }));

/** Names of the secret patterns found in `text`. */
export function findSecrets(text: string): string[] {
  return SECRET_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.name);
}

export function redactSecrets(text: string): string {
  let out = text;
  for (const p of GLOBAL_PATTERNS) out = out.replace(p.re, `[REDACTED:${p.name}]`);
  return out;
}

export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/** Returns the first glob the path matches, if any. Paths are normalized to forward slashes without a leading "./". */
export function matchesAnyGlob(path: string, globs: string[]): string | undefined {
  const p = path.replace(/\\/g, '/').replace(/^\.\//, '');
  return globs.find((g) => globToRegExp(g).test(p));
}

export interface DiffFile {
  path: string;
  added: string[];
  removed: number;
  /** Hunks seen for this file. A header with none carries no content to audit. */
  hunks: number;
  /** A hunk ended before the line counts in its own header were met (a cut-off patch). */
  truncated: boolean;
}

const newFile = (path: string): DiffFile => ({ path, added: [], removed: 0, hunks: 0, truncated: false });

/** Hunk-aware unified diff parser: header-looking content lines inside a hunk are never mistaken for headers. */
export function parseUnifiedDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | undefined;
  let oldLeft = 0;
  let newLeft = 0;

  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop(); // the newline that ends the patch is not a context line

  for (const line of lines) {
    if (oldLeft > 0 || newLeft > 0) {
      const tag = line[0];
      if (tag === '+') {
        cur?.added.push(line.slice(1));
        newLeft--;
        continue;
      }
      if (tag === '-') {
        if (cur) cur.removed++;
        oldLeft--;
        continue;
      }
      if (tag === ' ' || line === '') {
        oldLeft--;
        newLeft--;
        continue;
      }
      if (tag === '\\') continue;
      if (cur) cur.truncated = true; // something other than hunk content arrived while lines were still owed
      oldLeft = 0;
      newLeft = 0;
    }
    const git = /^diff --git a\/(.+) b\/(.+)$/.exec(line);
    if (git) {
      cur = newFile(git[2]!);
      files.push(cur);
      continue;
    }
    if (line.startsWith('+++ ')) {
      const p = line.slice(4).trim().replace(/^b\//, '');
      if (p !== '/dev/null') {
        if (!cur || cur.hunks > 0) {
          cur = newFile(p);
          files.push(cur);
        } else cur.path = p;
      }
      continue;
    }
    const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      if (!cur) {
        cur = newFile('(unknown)');
        files.push(cur);
      }
      cur.hunks++;
      oldLeft = hunk[1] === undefined ? 1 : Number(hunk[1]);
      newLeft = hunk[2] === undefined ? 1 : Number(hunk[2]);
    }
  }
  if ((oldLeft > 0 || newLeft > 0) && cur) cur.truncated = true; // the patch ended mid-hunk
  return files;
}

export interface DiffAudit {
  ok: boolean;
  violations: string[];
  files: number;
  linesChanged: number;
}

export function auditDiff(text: string, policy: Pick<Policy, 'forbidden_paths' | 'max_patch_lines'>): DiffAudit {
  const files = parseUnifiedDiff(text);
  const violations: string[] = [];
  if (files.length === 0) violations.push('no parsable diff hunks');

  let linesChanged = 0;
  for (const f of files) {
    linesChanged += f.added.length + f.removed;
    // A patch that names a file but carries no complete change to it proves nothing about that file.
    if (f.hunks === 0 || f.added.length + f.removed === 0) violations.push(`no changed lines for ${f.path}`);
    else if (f.truncated) violations.push(`truncated hunk in ${f.path}`);
    const segments = f.path.split('/');
    if (f.path.startsWith('/') || segments.includes('..')) violations.push(`path escapes the workspace: ${f.path}`);
    const forbidden = matchesAnyGlob(f.path, policy.forbidden_paths);
    if (forbidden) violations.push(`forbidden path ${f.path} (matches ${forbidden})`);
    const secrets = new Set(f.added.flatMap(findSecrets));
    for (const s of secrets) violations.push(`possible secret (${s}) added in ${f.path}`);
  }
  if (linesChanged > policy.max_patch_lines) {
    violations.push(`patch changes ${linesChanged} lines; limit is ${policy.max_patch_lines}`);
  }
  return { ok: violations.length === 0, violations, files: files.length, linesChanged };
}
