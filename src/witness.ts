import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdtemp, open, realpath, rm, stat, type FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { CommanderError } from './errors.js';
import type { Evidence, VerifierResult, WitnessSpec } from './types.js';
import { sanitizeLine, sha256 } from './util.js';
import { compileSchema, regexTest, result } from './verifiers.js';

/**
 * Independent witnessing.
 *
 * Worker-supplied evidence is still a claim. A witness lets Commander check the world itself: it runs the
 * operator's verification command and reads the workspace on disk, then compares what it saw to what the worker said.
 *
 * Trust model, stated plainly:
 *  - Only OPERATORS define witness commands. Nothing from a worker is ever interpolated into one.
 *  - But the command runs against a workspace the WORKER controls (it can plant a Makefile, a test, a symlink).
 *    So a witness executes worker-influenced code. `LocalWitness` is therefore for deployments where the
 *    workspace and Commander share a trust domain. It is NOT a sandbox. For anything multi-tenant, implement
 *    `Witness` with a real isolation boundary (container, microVM, remote runner) and inject it.
 */

export interface RunRequest {
  /** Executable followed by its arguments. Never passed through a shell. */
  argv: string[];
  /** Working directory relative to the workspace root. */
  cwd?: string;
  timeoutMs: number;
  maxOutputBytes: number;
}

export interface RunResult {
  /** The exit code Commander observed itself. Null if the process never ran or was killed by a signal. */
  exitCode: number | null;
  signal?: string;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
  /** Set when the command could not be run at all (not permitted, cannot start, bad working directory). */
  error?: string;
}

export interface InspectOptions {
  /** Content is returned only up to this size. */
  maxContentBytes: number;
  wantContent: boolean;
}

export interface FileInspection {
  exists: boolean;
  isFile?: boolean;
  size?: number;
  sha256?: string;
  content?: string;
  error?: string;
}

export interface Witness {
  readonly kind: string;
  run(req: RunRequest): Promise<RunResult>;
  inspect(relPath: string, opts: InspectOptions): Promise<FileInspection>;
}

// ---- local runner -----------------------------------------------------------------------------

const DEFAULT_PATH = '/usr/local/bin:/usr/bin:/bin';
const EXEC_NAME = /^[A-Za-z0-9._+-]+$/;
const HASH_CAP = 64 * 1024 * 1024;

export interface LocalWitnessOptions {
  /** Absolute workspace root. */
  root: string;
  /** Bare executable names that may be run. */
  allow: string[];
  /** PATH used to resolve them. */
  searchPath?: string;
  maxConcurrency?: number;
  /** How many runs may wait for a free slot before new ones are refused. */
  maxQueue?: number;
}

class Capped {
  private readonly chunks: Buffer[] = [];
  private size = 0;
  truncated = false;
  constructor(private readonly max: number) {}

  /** Keeps draining the pipe after the cap so the child never blocks on a full buffer, but stops storing. */
  push(chunk: Buffer): void {
    if (this.size >= this.max) {
      this.truncated = true;
      return;
    }
    const room = this.max - this.size;
    if (chunk.length > room) {
      this.chunks.push(chunk.subarray(0, room));
      this.size = this.max;
      this.truncated = true;
    } else {
      this.chunks.push(chunk);
      this.size += chunk.length;
    }
  }

  text(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}

const isInside = (root: string, p: string): boolean => p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);

const failed = (error: string): RunResult => ({
  exitCode: null,
  stdout: '',
  stderr: '',
  truncated: false,
  timedOut: false,
  durationMs: 0,
  error,
});

export class LocalWitness implements Witness {
  readonly kind = 'local';
  private rootReal?: string;
  private running = 0;
  private readonly waiters: (() => void)[] = [];
  private readonly maxConcurrency: number;
  private readonly maxQueue: number;

  constructor(private readonly opts: LocalWitnessOptions) {
    if (process.platform === 'win32') throw new Error('LocalWitness relies on POSIX process groups and is not supported on Windows');
    if (!path.isAbsolute(opts.root)) throw new Error('LocalWitness root must be an absolute path');
    this.maxConcurrency = opts.maxConcurrency ?? 2;
    this.maxQueue = opts.maxQueue ?? 8;
  }

  private async root(): Promise<string> {
    this.rootReal ??= await realpath(this.opts.root);
    return this.rootReal;
  }

  /**
   * Resolves a workspace-relative path and proves it stays inside the workspace after symlinks are followed.
   * A missing leaf is fine (the caller learns the file does not exist) as long as its parent cannot lead out.
   */
  private async resolveInside(rel: string): Promise<{ real: string; exists: boolean }> {
    const root = await this.root();
    const lexical = path.resolve(root, rel);
    if (!isInside(root, lexical)) throw new Error('path escapes the workspace');
    try {
      const real = await realpath(lexical);
      if (!isInside(root, real)) throw new Error('path escapes the workspace');
      return { real, exists: true };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    let parent = path.dirname(lexical);
    for (;;) {
      try {
        const real = await realpath(parent);
        if (!isInside(root, real)) throw new Error('path escapes the workspace');
        break;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        if (parent === root) break;
        parent = path.dirname(parent);
      }
    }
    return { real: lexical, exists: false };
  }

  private async acquire(): Promise<void> {
    if (this.running < this.maxConcurrency) {
      this.running++;
      return;
    }
    if (this.waiters.length >= this.maxQueue) {
      throw new CommanderError('THROTTLED', 'Independent verification capacity is exhausted. Retry shortly.', { retryAfter: 5 });
    }
    // The slot is handed over directly by release(), so `running` is unchanged on wake-up.
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.running--;
  }

  async run(req: RunRequest): Promise<RunResult> {
    const [cmd, ...args] = req.argv;
    if (!cmd || !EXEC_NAME.test(cmd) || !this.opts.allow.includes(cmd)) {
      return failed(`executable "${sanitizeLine(cmd ?? '', 40)}" is not on the witness allowlist`);
    }
    let cwd: string;
    try {
      const resolved = await this.resolveInside(req.cwd ?? '.');
      if (!resolved.exists || !(await stat(resolved.real)).isDirectory()) return failed('working directory does not exist');
      cwd = resolved.real;
    } catch (err) {
      return failed((err as Error).message);
    }

    await this.acquire();
    let home: string | undefined;
    try {
      home = await mkdtemp(path.join(tmpdir(), 'commander-witness-'));
      return await this.exec(cmd, args, cwd, home, req);
    } catch (err) {
      return failed(sanitizeLine((err as Error).message, 160));
    } finally {
      this.release();
      if (home) await rm(home, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  private exec(cmd: string, args: string[], cwd: string, home: string, req: RunRequest): Promise<RunResult> {
    return new Promise<RunResult>((resolve) => {
      const started = Date.now();
      const out = new Capped(req.maxOutputBytes);
      const err = new Capped(req.maxOutputBytes);
      let timedOut = false;
      let settled = false;
      let child: ChildProcess;
      try {
        child = spawn(cmd, args, {
          cwd,
          // A scrubbed environment: Commander's own secrets and the worker's variables never reach the command.
          env: { PATH: this.opts.searchPath ?? DEFAULT_PATH, HOME: home, TMPDIR: home, CI: '1', NO_COLOR: '1', LANG: 'C.UTF-8' },
          shell: false,
          detached: true, // its own process group, so a timeout can take down everything it spawned
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (e) {
        resolve(failed((e as Error).message));
        return;
      }

      const killGroup = (): void => {
        try {
          if (child.pid) process.kill(-child.pid, 'SIGKILL');
        } catch {
          try {
            child.kill('SIGKILL');
          } catch {
            /* already gone */
          }
        }
      };
      const timer = setTimeout(() => {
        timedOut = true;
        killGroup();
      }, req.timeoutMs);

      const finish = (exitCode: number | null, signal: string | null | undefined, error?: string): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        killGroup(); // reap any background process the command left behind
        resolve({
          exitCode,
          signal: signal ?? undefined,
          stdout: out.text(),
          stderr: err.text(),
          truncated: out.truncated || err.truncated,
          timedOut,
          durationMs: Date.now() - started,
          error,
        });
      };

      child.stdout?.on('data', (c: Buffer) => out.push(c));
      child.stderr?.on('data', (c: Buffer) => err.push(c));
      child.on('error', (e) => finish(null, null, sanitizeLine(e.message, 160)));
      child.on('close', (code, signal) => finish(code, signal));
    });
  }

  async inspect(relPath: string, opts: InspectOptions): Promise<FileInspection> {
    let target: { real: string; exists: boolean };
    try {
      target = await this.resolveInside(relPath);
    } catch (err) {
      return { exists: false, error: (err as Error).message };
    }
    if (!target.exists) return { exists: false };

    let handle: FileHandle;
    try {
      // The path is already fully resolved; O_NOFOLLOW refuses a final-component symlink swapped in since.
      handle = await open(target.real, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    } catch (err) {
      return { exists: false, error: sanitizeLine((err as Error).message, 120) };
    }
    try {
      const st = await handle.stat();
      if (!st.isFile()) return { exists: true, isFile: false, size: st.size };
      if (st.size > HASH_CAP) return { exists: true, isFile: true, size: st.size, error: 'file is too large to inspect' };

      const hash = createHash('sha256');
      const keep: Buffer[] | undefined = opts.wantContent && st.size <= opts.maxContentBytes ? [] : undefined;
      const buf = Buffer.allocUnsafe(64 * 1024);
      let total = 0;
      for (;;) {
        const { bytesRead } = await handle.read(buf, 0, buf.length, null);
        if (bytesRead === 0) break;
        total += bytesRead;
        if (total > HASH_CAP) return { exists: true, isFile: true, size: total, error: 'file grew past the inspection limit' };
        const chunk = buf.subarray(0, bytesRead);
        hash.update(chunk);
        keep?.push(Buffer.from(chunk));
      }
      return { exists: true, isFile: true, size: total, sha256: hash.digest('hex'), content: keep ? Buffer.concat(keep).toString('utf8') : undefined };
    } finally {
      await handle.close();
    }
  }
}

// ---- verifiers --------------------------------------------------------------------------------

export interface WitnessRunContext {
  witness: Witness;
  /** Used only to cross-check submitted artifacts against what is on disk. */
  evidence: Evidence;
  /** Total wall-clock budget for all independent checks of one submission. */
  budgetMs: number;
  maxOutputBytes: number;
  maxFileBytes: number;
}

type CommandSpec = Extract<WitnessSpec, { type: 'witness_command' }>;
type FileSpec = Extract<WitnessSpec, { type: 'witness_file' }>;

const lastLine = (...texts: string[]): string | undefined => {
  for (const t of texts) {
    const line = t
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .at(-1);
    if (line) return sanitizeLine(line, 100);
  }
  return undefined;
};

async function verifyCommand(spec: CommandSpec, ctx: WitnessRunContext, remainingMs: number): Promise<VerifierResult> {
  const label = sanitizeLine(spec.argv.join(' '), 80);
  const r = await ctx.witness.run({
    argv: spec.argv,
    cwd: spec.cwd,
    timeoutMs: Math.min(spec.timeout_sec * 1000, remainingMs),
    maxOutputBytes: ctx.maxOutputBytes,
  });
  if (r.error) {
    return result(spec, false, `Independent run of "${label}" could not complete: ${sanitizeLine(r.error, 100)}.`, 'Make sure the command can run in the workspace.');
  }
  if (r.timedOut) {
    return result(spec, false, `Independent run of "${label}" timed out.`, 'Make the command finish within its time limit.');
  }

  const exitOk = r.exitCode === spec.expected_exit;
  let patternOk = true;
  let patternTimedOut = false;
  if (spec.stdout_regex) {
    try {
      patternOk = regexTest(spec.stdout_regex, spec.flags, r.stdout);
    } catch {
      patternOk = false;
      patternTimedOut = true;
    }
  }
  if (exitOk && patternOk) {
    return result(spec, true, `Independent run of "${label}" exited ${r.exitCode}${spec.stdout_regex ? ' with the required output' : ''}.`, '');
  }

  const problems: string[] = [];
  if (!exitOk) {
    problems.push(r.exitCode === null ? `was killed${r.signal ? ` by ${r.signal}` : ''}` : `exited ${r.exitCode} (expected ${spec.expected_exit})`);
  }
  if (!patternOk) problems.push(patternTimedOut ? 'output check exceeded its time limit' : 'output did not match the required pattern');
  const hint = lastLine(r.stderr, r.stdout);
  return result(
    spec,
    false,
    `Independent run of "${label}" ${problems.join('; ')}.${hint ? ` Last output: "${hint}".` : ''}`,
    'Fix the workspace so the command succeeds when Commander runs it. Reporting a different exit code changes nothing.',
  );
}

async function verifyFile(spec: FileSpec, ctx: WitnessRunContext): Promise<VerifierResult> {
  const where = sanitizeLine(spec.path, 100);
  const wantContent = Boolean(spec.regex || spec.schema);
  const info = await ctx.witness.inspect(spec.path, { maxContentBytes: ctx.maxFileBytes, wantContent });

  if (!info.exists) {
    return result(
      spec,
      false,
      info.error ? `Cannot inspect ${where}: ${sanitizeLine(info.error, 100)}.` : `Required file ${where} does not exist in the workspace.`,
      `Produce ${where} in the workspace.`,
    );
  }
  if (info.isFile === false) return result(spec, false, `${where} is not a regular file.`, `Provide a regular file at ${where}.`);
  if (info.error) return result(spec, false, `Cannot inspect ${where}: ${sanitizeLine(info.error, 100)}.`, 'Provide a smaller file.');

  const size = info.size ?? 0;
  if (size < spec.min_bytes) return result(spec, false, `${where} is ${size} bytes; minimum is ${spec.min_bytes}.`, `Write the complete contents of ${where}.`);
  if (spec.sha256 && info.sha256 !== spec.sha256) {
    return result(spec, false, `${where} does not match the required hash.`, `Provide the exact required contents of ${where}.`);
  }

  if (spec.matches_artifact) {
    const artifacts = ctx.evidence.artifacts;
    const submitted = artifacts && Object.hasOwn(artifacts, spec.matches_artifact) ? artifacts[spec.matches_artifact] : undefined;
    if (submitted === undefined) {
      return result(spec, false, `Artifact "${spec.matches_artifact}" was not submitted to compare with ${where}.`, `Submit ${spec.matches_artifact} in artifacts.`);
    }
    if (sha256(submitted) !== info.sha256) {
      return result(spec, false, `Submitted artifact "${spec.matches_artifact}" does not match ${where} on disk.`, 'Submit the artifact exactly as it exists in the workspace.');
    }
  }

  if (wantContent) {
    if (info.content === undefined) return result(spec, false, `${where} is too large to inspect (${size} bytes).`, 'Provide a smaller file.');
    if (spec.regex) {
      let ok = false;
      try {
        ok = regexTest(spec.regex, spec.flags, info.content);
      } catch {
        return result(spec, false, `Pattern check on ${where} exceeded its time limit.`, 'Provide a smaller or simpler file.');
      }
      if (!ok) return result(spec, false, `${where} does not contain the required pattern.`, `Make ${where} contain the required content.`);
    }
    if (spec.schema) {
      let doc: unknown;
      try {
        doc = JSON.parse(info.content);
      } catch {
        return result(spec, false, `${where} is not valid JSON.`, `Write valid JSON to ${where}.`);
      }
      const validate = compileSchema(spec.schema);
      if (!validate(doc)) {
        const errs = (validate.errors ?? [])
          .slice(0, 3)
          .map((e) => sanitizeLine(`${e.instancePath || '/'} ${e.message ?? 'invalid'}`, 80))
          .join('; ');
        return result(spec, false, `${where} violates the required schema: ${errs}.`, `Conform ${where} to the required schema.`);
      }
    }
  }
  return result(spec, true, `${where} verified on disk (${size} bytes).`, '');
}

/**
 * Runs independent checks one after another (they share one time budget). A fault inside a single check fails that
 * check, never the whole audit, and never passes. Capacity errors propagate so the worker is told to retry.
 */
export async function runWitnessVerifiers(specs: WitnessSpec[], ctx: WitnessRunContext): Promise<VerifierResult[]> {
  const deadline = Date.now() + ctx.budgetMs;
  const results: VerifierResult[] = [];
  for (const spec of specs) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      results.push(result(spec, false, 'Independent verification time budget exhausted.', 'Reduce the work the verification commands must do.'));
      continue;
    }
    try {
      results.push(spec.type === 'witness_command' ? await verifyCommand(spec, ctx, remaining) : await verifyFile(spec, ctx));
    } catch (err) {
      if (err instanceof CommanderError) throw err;
      results.push(result(spec, false, 'Independent verification fault. Treated as failed.', 'Retry; if it persists, contact the operator.'));
    }
  }
  return results;
}
