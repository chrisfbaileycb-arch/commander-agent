import type { Policy } from './config.js';
import { matchesAnyGlob } from './inquisitor.js';
import type { ActionRequest, Finding } from './types.js';
import { sanitizeLine, sha256, type Clock } from './util.js';

/**
 * Perimeter Sentinel. A tripwire, not a sandbox.
 *
 * It parses what a worker DECLARES it is about to do and rules on it. It cannot see what a worker does
 * outside the gateway, and a determined adversary can obfuscate shell past any static parser. Treat a
 * clean verdict as "no known-bad pattern", never as "safe". Strict mode (allowlist + stage) is the
 * posture for hostile or unvetted workers.
 */

export interface SentinelDecision {
  verdict: 'allow' | 'deny' | 'stage';
  findings: Finding[];
  actionHash: string;
}

const deny = (rule: string, reason: string): Finding => ({ rule, verdict: 'deny', reason });
const stage = (rule: string, reason: string): Finding => ({ rule, verdict: 'stage', reason });

export const normalizeAction = (a: Pick<ActionRequest, 'kind' | 'payload'>): string =>
  `${a.kind}\0${a.payload.trim().replace(/\s+/g, ' ')}`;

// ---- shell ------------------------------------------------------------------------------------

interface ShellCmd {
  tokens: string[];
  /** Separator that follows this command. */
  sep: string;
}

/** Returns the contents of a balanced `$( ... )` starting just after the opening parenthesis. */
function readParen(s: string, start: number): [string, number] {
  let depth = 1;
  let i = start;
  for (; i < s.length && depth > 0; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') depth--;
  }
  return [s.slice(start, i - 1), i - 1];
}

/** Minimal POSIX-ish splitter: quotes, escapes, control operators, and command substitutions. */
function tokenize(line: string): { cmds: ShellCmd[]; subs: string[] } {
  const cmds: ShellCmd[] = [];
  const subs: string[] = [];
  let tokens: string[] = [];
  let cur = '';
  let inTok = false;
  let quote: '"' | "'" | null = null;

  const pushTok = () => {
    if (inTok) tokens.push(cur);
    cur = '';
    inTok = false;
  };
  const pushCmd = (sep: string) => {
    pushTok();
    if (tokens.length) cmds.push({ tokens, sep });
    tokens = [];
  };
  const substitution = (i: number): number | undefined => {
    if (line[i] === '$' && line[i + 1] === '(') {
      const [inner, end] = readParen(line, i + 2);
      subs.push(inner);
      return end;
    }
    if (line[i] === '`') {
      const end = line.indexOf('`', i + 1);
      if (end > i) {
        subs.push(line.slice(i + 1, end));
        return end;
      }
    }
    return undefined;
  };

  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote === "'") {
      if (c === "'") quote = null;
      else cur += c;
      continue;
    }
    if (c === '\\') {
      if (i + 1 < line.length) {
        cur += line[i + 1]!;
        inTok = true;
        i++;
      }
      continue;
    }
    const sub = c === '$' || c === '`' ? substitution(i) : undefined;
    if (sub !== undefined) {
      i = sub;
      inTok = true;
      continue;
    }
    if (quote === '"') {
      if (c === '"') quote = null;
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      inTok = true;
      continue;
    }
    if (c === ';') pushCmd(';');
    else if (c === '\n') pushCmd('\n');
    else if (c === '&' && (line[i - 1] === '>' || line[i + 1] === '>')) {
      cur += c; // redirection such as 2>&1 or &>file
      inTok = true;
    } else if (c === '&') {
      if (line[i + 1] === '&') {
        pushCmd('&&');
        i++;
      } else pushCmd('&');
    } else if (c === '|') {
      if (line[i + 1] === '|') {
        pushCmd('||');
        i++;
      } else pushCmd('|');
    } else if (/\s/.test(c)) pushTok();
    else {
      cur += c;
      inTok = true;
    }
  }
  pushCmd('');
  return { cmds, subs };
}

const base = (t: string): string => t.split('/').pop() ?? t;
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'nohup', 'time', 'nice', 'ionice', 'command', 'exec', 'builtin', 'stdbuf', 'timeout', 'setsid', 'xargs']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash']);
const INTERPRETERS = new Set([...SHELLS, 'python', 'python3', 'node', 'perl', 'ruby', 'php']);
const FETCHERS = new Set(['curl', 'wget', 'base64', 'openssl']);
const EGRESS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ftp', 'sftp', 'scp', 'rsync', 'ssh']);
const RAW_SOCKET = new Set(['nc', 'ncat', 'netcat', 'telnet', 'ssh', 'ftp', 'sftp', 'socat']);
const POWER = new Set(['shutdown', 'reboot', 'halt', 'poweroff']);
const DISK = new Set(['fdisk', 'parted', 'wipefs', 'sfdisk', 'mkswap']);

const DANGEROUS_TARGET = /^(?:\/(?:\*|bin|boot|dev|etc|home|lib\d*|opt|proc|root|sbin|srv|sys|usr|var)?\/?\*?|~\/?\*?|\$\{?HOME\}?\/?\*?|\*|\.{1,2}\/?\*?)$/;
const SECRET_PATH = /(?:\.ssh\/|\.aws\/credentials|\.netrc|\/etc\/shadow|\.git-credentials|\.kube\/config|id_rsa|id_ed25519|\.pem\b|(?:^|[^\w.])\.env(?:\.\w+)?\b)/;
const RAW_PATTERNS: [RegExp, Finding][] = [
  [/:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/, deny('shell.fork-bomb', 'Fork bomb pattern.')],
  [/(?:^|[\s;&|])(?:ba|z|da|k)?sh\s+<\(\s*(?:curl|wget)\b/, deny('shell.remote-exec', 'Remote script executed via process substitution.')],
  [/>\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk)\w*/, deny('shell.disk-overwrite', 'Redirect into a block device.')],
];

const PROD_RULES: { label: string; test: (name: string, args: string[]) => boolean }[] = [
  { label: 'package publish', test: (n, a) => ['npm', 'pnpm', 'yarn', 'cargo', 'twine'].includes(n) && ['publish', 'upload'].includes(a[0] ?? '') },
  { label: 'container push', test: (n, a) => ['docker', 'podman'].includes(n) && a.includes('push') },
  { label: 'cluster mutation', test: (n, a) => n === 'kubectl' && a.some((x) => ['apply', 'delete', 'rollout', 'scale', 'replace', 'patch', 'create'].includes(x)) },
  { label: 'infrastructure change', test: (n, a) => ['terraform', 'tofu'].includes(n) && a.some((x) => ['apply', 'destroy'].includes(x)) },
  { label: 'release change', test: (n, a) => n === 'helm' && a.some((x) => ['install', 'upgrade', 'uninstall', 'rollback'].includes(x)) },
  { label: 'deploy', test: (n, a) => ['pulumi', 'serverless', 'sls', 'vercel', 'fly', 'flyctl', 'cdk', 'netlify', 'wrangler'].includes(n) && a.some((x) => /^(?:up|deploy|destroy|publish)$/.test(x)) },
  { label: 'cloud resource mutation', test: (n, a) => ['aws', 'gcloud', 'az'].includes(n) && a.some((x) => /^(?:delete|terminate|remove|deregister|destroy|deploy)(?:-|$)/.test(x)) },
  { label: 'playbook run', test: (n) => n === 'ansible-playbook' },
];

const PROTECTED_REF = /^\+?(?:[\w./-]+:)?(?:refs\/heads\/)?(?:main|master|prod|production|release[\w./-]*)$/;

function hostAllowed(host: string, list: string[]): boolean {
  const h = host.toLowerCase();
  return list.some((entry) => {
    const e = entry.toLowerCase();
    return e.startsWith('*.') ? h.endsWith(e.slice(1)) : h === e;
  });
}

const isLoopback = (h: string): boolean => /^(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])$/i.test(h);
const isMetadata = (h: string): boolean => /^(?:169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254)$/i.test(h);

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

function urlHost(arg: string): string | undefined {
  if (!SCHEME.test(arg)) return undefined;
  try {
    return new URL(arg).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return undefined;
  }
}

/** scp/rsync/ssh style: user@host:path, host.tld:path, or user@host. */
function remoteHost(arg: string): string | undefined {
  const m = /^(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,}|localhost):/i.exec(arg) ?? /^[\w.-]+@([\w.-]+)$/.exec(arg);
  return m?.[1];
}

function bareHost(arg: string): string | undefined {
  return /^([\w-]+(?:\.[\w-]+)*\.[a-z]{2,})(?::\d+)?(?:\/|$)/i.exec(arg)?.[1];
}

const hostOf = (arg: string): string | undefined => urlHost(arg) ?? remoteHost(arg) ?? bareHost(arg);

/** Destination hosts of a network command. Explicit URLs win, so `-o out.json` is never mistaken for a host. */
function egressHosts(name: string, args: string[]): { hosts: string[]; unknown: boolean } {
  const urls = args.map(urlHost).filter((h): h is string => !!h);
  if (urls.length) return { hosts: urls, unknown: false };
  const remotes = args.map(remoteHost).filter((h): h is string => !!h);
  if (remotes.length) return { hosts: remotes, unknown: false };
  const positional = args.find((a) => !a.startsWith('-'));
  if (positional) {
    if (name === 'curl' || name === 'wget') {
      const host = bareHost(positional);
      if (host) return { hosts: [host], unknown: false };
    } else if (RAW_SOCKET.has(name)) {
      const host = positional.replace(/^[\w.-]+@/, '');
      if (/^[\w.-]+$/.test(host)) return { hosts: [host], unknown: false };
    }
  }
  return { hosts: [], unknown: true };
}

function stripWrappers(tokens: string[]): string[] {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (/^[A-Za-z_]\w*=/.test(t)) {
      i++;
      continue;
    }
    if (WRAPPERS.has(base(t))) {
      const wrapper = base(t);
      i++;
      while (i < tokens.length && (tokens[i]!.startsWith('-') || /^\d+[smhd]?$/.test(tokens[i]!))) {
        if (wrapper === 'sudo' && ['-u', '-g', '-C', '-D'].includes(tokens[i]!)) i++;
        i++;
      }
      continue;
    }
    break;
  }
  return tokens.slice(i);
}

function scanShell(line: string, policy: Policy, depth = 0): Finding[] {
  const findings: Finding[] = [];
  if (depth > 3) return [stage('shell.nesting', 'Command nesting too deep to verify.')];

  for (const [re, finding] of RAW_PATTERNS) if (re.test(line)) findings.push(finding);

  const { cmds, subs } = tokenize(line);
  for (const sub of subs) findings.push(...scanShell(sub, policy, depth + 1));

  let readsSecret = SECRET_PATH.test(line);
  let usesEgress = false;

  cmds.forEach((cmd, idx) => {
    const t = stripWrappers(cmd.tokens);
    if (t.length === 0) return;
    const name = base(t[0]!);
    const args = t.slice(1);
    const recursive = args.some((a) => /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(a) || a === '--recursive');

    if (SHELLS.has(name)) {
      const ci = args.findIndex((a) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
      const payload = ci >= 0 ? args[ci + 1] : undefined;
      if (payload) findings.push(...scanShell(payload, policy, depth + 1));
    }
    if (name === 'eval') findings.push(stage('shell.eval', 'eval executes opaque code.'));

    if (name === 'rm') {
      if (args.includes('--no-preserve-root')) findings.push(deny('shell.rm-destructive', 'rm with --no-preserve-root.'));
      else if (recursive && args.some((a) => !a.startsWith('-') && DANGEROUS_TARGET.test(a))) {
        findings.push(deny('shell.rm-destructive', 'Recursive delete aimed at a root, home, system, or wildcard target.'));
      }
    }
    if (['chmod', 'chown', 'chgrp'].includes(name) && recursive && args.some((a) => !a.startsWith('-') && DANGEROUS_TARGET.test(a))) {
      findings.push(deny('shell.mass-permission', 'Recursive permission change on a root, home, or system target.'));
    }
    if (name === 'dd' && args.some((a) => /^of=\/dev\//.test(a))) findings.push(deny('shell.disk-overwrite', 'dd writing to a device.'));
    if (name.startsWith('mkfs') || DISK.has(name) || (name === 'shred' && args.some((a) => a.startsWith('/dev/')))) {
      findings.push(deny('shell.disk-destructive', 'Disk formatting or partitioning command.'));
    }
    if (POWER.has(name) || (name === 'init' && ['0', '6'].includes(args[0] ?? '')) || (name === 'systemctl' && args.some((a) => ['poweroff', 'reboot', 'halt'].includes(a)))) {
      findings.push(deny('shell.power', 'Host power control.'));
    }
    if ((name === 'kill' && args.includes('-1')) || name === 'killall5') findings.push(deny('shell.mass-kill', 'Signal to every process.'));

    if (cmd.sep === '|') {
      const next = cmds[idx + 1] && base(stripWrappers(cmds[idx + 1]!.tokens)[0] ?? '');
      if (next && INTERPRETERS.has(next) && FETCHERS.has(name)) {
        findings.push(deny('shell.remote-exec', 'Fetched content piped into an interpreter.'));
      }
    }

    if (EGRESS.has(name)) {
      usesEgress = true;
      const { hosts, unknown } = egressHosts(name, args);
      if (unknown) findings.push(stage('shell.egress-unverifiable', `Network command ${name} with no verifiable destination.`));
      for (const host of hosts) {
        const shown = sanitizeLine(host, 80);
        if (isMetadata(host)) findings.push(deny('shell.metadata-endpoint', `Cloud metadata endpoint ${shown}.`));
        else if (isLoopback(host)) continue;
        else if (hostAllowed(host, policy.payment_hosts)) findings.push(stage('shell.financial-endpoint', `Payment provider ${shown}.`));
        else if (!hostAllowed(host, policy.egress_allowlist)) findings.push(deny('shell.egress-unlisted', `Egress to ${shown} is not on the allowlist.`));
      }
    }
    if (name === 'printenv') readsSecret = true;

    for (const rule of PROD_RULES) if (rule.test(name, args)) findings.push(stage('shell.production-change', `Production-impacting command: ${rule.label}.`));
    if (name === 'git' && args[0] === 'push') {
      const force = args.some((a) => a === '-f' || a === '--force' || a.startsWith('--force-with-lease') || a.startsWith('+'));
      const refs = args.slice(1).filter((a) => !a.startsWith('-'));
      if (force) findings.push(stage('shell.git-force-push', 'Forced push rewrites remote history.'));
      else if (refs.some((r) => PROTECTED_REF.test(r))) findings.push(stage('shell.production-change', 'Push to a protected branch.'));
    }

    if (policy.strict_shell && !policy.shell_allowlist.includes(name)) {
      findings.push(stage('shell.not-allowlisted', `Command ${sanitizeLine(name, 40)} is outside the strict allowlist.`));
    }
  });

  if (readsSecret && usesEgress) findings.push(deny('shell.exfiltration', 'Credential material and network egress in one command.'));
  return findings;
}

// ---- sql --------------------------------------------------------------------------------------

function stripSqlNoise(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/'(?:[^']|'')*'/g, "''");
}

function scanSql(sql: string): Finding[] {
  const findings: Finding[] = [];
  const statements = stripSqlNoise(sql)
    .split(';')
    .map((s) => s.trim().replace(/\s+/g, ' ').toUpperCase())
    .filter(Boolean);
  for (const s of statements) {
    const tautology = /\bWHERE\s+(?:1\s*=\s*1|TRUE)\b/.test(s);
    if (/^DROP (?:TABLE|DATABASE|SCHEMA)\b/.test(s)) findings.push(deny('sql.drop', 'DROP of a table, schema, or database.'));
    else if (/^TRUNCATE\b/.test(s)) findings.push(deny('sql.truncate', 'TRUNCATE destroys all rows.'));
    else if (/^DELETE FROM\b/.test(s) && (!/\bWHERE\b/.test(s) || tautology)) findings.push(deny('sql.unbounded-delete', 'DELETE without a restrictive WHERE.'));
    else if (/^UPDATE\b/.test(s) && (!/\bWHERE\b/.test(s) || tautology)) findings.push(deny('sql.unbounded-update', 'UPDATE without a restrictive WHERE.'));
    else if (/\bXP_CMDSHELL\b|\bCOPY\b.*\bPROGRAM\b|\bPG_READ_FILE\b|\bLOAD_FILE\b|\bINTO OUTFILE\b/.test(s)) findings.push(deny('sql.os-access', 'SQL reaching the host operating system.'));
    else if (/^(?:GRANT|REVOKE|CREATE (?:USER|ROLE)|ALTER (?:USER|ROLE))\b/.test(s)) findings.push(stage('sql.privilege-change', 'Privilege or role change.'));
    else if (/^(?:ALTER|CREATE|DROP|RENAME|COMMENT ON)\b/.test(s)) findings.push(stage('sql.schema-change', 'Schema change.'));
  }
  return findings;
}

// ---- http / fs --------------------------------------------------------------------------------

function scanHttp(payload: string, policy: Policy): Finding[] {
  const m = /^(?:(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+)?(\S+)/i.exec(payload.trim());
  const method = (m?.[1] ?? 'GET').toUpperCase();
  const host = m?.[2] ? hostOf(m[2]) : undefined;
  if (!host) return [stage('http.unverifiable', 'Destination could not be determined.')];
  const shown = sanitizeLine(host, 80);
  if (isMetadata(host)) return [deny('http.metadata-endpoint', `Cloud metadata endpoint ${shown}.`)];
  if (isLoopback(host)) return [];
  if (hostAllowed(host, policy.payment_hosts) && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return [stage('http.financial', `Mutating call to payment provider ${shown}.`)];
  }
  if (!hostAllowed(host, policy.egress_allowlist) && !hostAllowed(host, policy.payment_hosts)) {
    return [deny('http.egress-unlisted', `Egress to ${shown} is not on the allowlist.`)];
  }
  return [];
}

function scanFs(payload: string, intent: ActionRequest['intent'], policy: Policy): Finding[] {
  const path = payload.trim();
  const findings: Finding[] = [];
  if (path.split('/').includes('..')) findings.push(deny('fs.traversal', 'Path traversal segment.'));
  if (matchesAnyGlob(path, policy.forbidden_paths) || SECRET_PATH.test(path)) {
    findings.push(deny('fs.forbidden-path', 'Path is protected by policy.'));
  }
  const mutating = intent !== undefined && intent !== 'read';
  if (mutating && /^\/(?:etc|boot|sys|proc|dev|usr|bin|sbin|lib\d*)(?:\/|$)/.test(path)) {
    findings.push(deny('fs.system-path', 'Mutation of a system path.'));
  }
  return findings;
}

// ---- engine -----------------------------------------------------------------------------------

export class Sentinel {
  private readonly seen = new Map<string, number[]>();

  constructor(
    private readonly policy: Policy,
    private readonly clock: Clock,
  ) {}

  /** Rules on a declared action. Stateful only for repetition (loop) detection. */
  evaluate(missionId: string, action: ActionRequest): SentinelDecision {
    const findings: Finding[] = [];
    switch (action.kind) {
      case 'shell':
        findings.push(...scanShell(action.payload, this.policy));
        break;
      case 'sql':
        findings.push(...scanSql(action.payload));
        break;
      case 'http':
        findings.push(...scanHttp(action.payload, this.policy));
        break;
      case 'fs':
        findings.push(...scanFs(action.payload, action.intent, this.policy));
        break;
      case 'deploy':
        if (action.intent !== 'read') findings.push(stage('deploy.always-staged', 'Deployments require operator authorization.'));
        break;
      case 'payment':
        findings.push(stage('payment.always-staged', 'Financial transactions require operator authorization.'));
        break;
      case 'other':
        break;
    }

    // Declared intent can only escalate, never relax.
    if (action.intent === 'schema_change') findings.push(stage('intent.schema-change', 'Declared schema change.'));
    if (action.intent === 'financial') findings.push(stage('intent.financial', 'Declared financial transaction.'));
    if (action.intent === 'production_push') findings.push(stage('intent.production-push', 'Declared production push.'));

    const actionHash = sha256(normalizeAction(action));
    const repeated = this.observe(missionId, actionHash);
    if (repeated) findings.push(deny('loop.repetition', `Identical action issued ${repeated} times inside ${this.policy.repetition_window_sec}s.`));

    const unique = [...new Map(findings.map((f) => [`${f.rule}|${f.reason}`, f])).values()];
    const verdict = unique.some((f) => f.verdict === 'deny') ? 'deny' : unique.some((f) => f.verdict === 'stage') ? 'stage' : 'allow';
    return { verdict, findings: unique, actionHash };
  }

  /** Returns the occurrence count once the repetition threshold is reached, otherwise 0. */
  private observe(missionId: string, actionHash: string): number {
    const now = this.clock();
    const windowMs = this.policy.repetition_window_sec * 1000;
    const key = `${missionId}|${actionHash}`;
    const hits = (this.seen.get(key) ?? []).filter((t) => now - t < windowMs);
    hits.push(now);
    this.seen.set(key, hits);
    if (this.seen.size > 5000) {
      for (const [k, v] of this.seen) if (v.every((t) => now - t >= windowMs)) this.seen.delete(k);
    }
    return hits.length >= this.policy.repetition_threshold ? hits.length : 0;
  }
}
