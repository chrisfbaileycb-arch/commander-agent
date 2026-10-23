import path from 'node:path';
import { findSecrets } from '../inquisitor.js';
import type { ActionRequest } from '../types.js';

/**
 * Maps a Claude Code PreToolUse payload onto the action vocabulary the Sentinel already understands.
 * Pure and dependency-light on purpose: the hook runs once per tool call on the developer's machine.
 */

/** Native tools the guard vets. Every other tool passes through untouched. */
export const GUARDED_TOOLS = ['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'] as const;

export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: unknown;
  cwd?: string;
}

export interface MappedCall {
  tool: string;
  /** What to ask the Sentinel. Absent when the call is refused locally. */
  action?: ActionRequest;
  /** Reasons the guard refuses without asking Commander at all. */
  blocked?: string[];
}

/** Matches ActionRequestSchema. Anything longer cannot be vetted, so it is refused rather than truncated. */
const MAX_PAYLOAD = 16_384;

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

/** Paths inside the working directory become relative, so the forbidden-path globs (".env", ".git/**") apply as written. */
function relativize(p: string, cwd: string | undefined): string {
  if (cwd && path.isAbsolute(p) && path.isAbsolute(cwd)) {
    const rel = path.relative(cwd, p);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel;
  }
  return p;
}

/** Content the model is about to write. Scanned locally: file contents never leave the machine. */
function writtenContent(tool: string, ti: Record<string, unknown>): string[] {
  const parts: (string | undefined)[] = [];
  if (tool === 'Write') parts.push(str(ti.content));
  else if (tool === 'Edit') parts.push(str(ti.new_string));
  else if (tool === 'NotebookEdit') parts.push(str(ti.new_source));
  else if (tool === 'MultiEdit' && Array.isArray(ti.edits)) {
    for (const e of ti.edits) parts.push(str((e as Record<string, unknown> | null)?.new_string));
  }
  return parts.filter((s): s is string => s !== undefined);
}

export function mapToolCall(input: HookInput): MappedCall | null {
  const tool = input.tool_name;
  if (!tool || !(GUARDED_TOOLS as readonly string[]).includes(tool)) return null;
  const ti = (typeof input.tool_input === 'object' && input.tool_input !== null ? input.tool_input : {}) as Record<string, unknown>;

  if (tool === 'Bash') {
    const command = str(ti.command);
    if (!command || !command.trim()) return { tool, blocked: ['Bash call without a command. Refusing to guess.'] };
    if (command.length > MAX_PAYLOAD) {
      return { tool, blocked: [`Command is ${command.length} characters, over the ${MAX_PAYLOAD} that can be vetted. Split it into smaller steps.`] };
    }
    return { tool, action: { kind: 'shell', payload: command } };
  }

  const rawPath = str(ti.file_path) ?? str(ti.notebook_path);
  if (!rawPath || !rawPath.trim()) return { tool, blocked: [`${tool} call without a file path. Refusing to guess.`] };
  const target = relativize(rawPath, input.cwd);
  if (target.length > MAX_PAYLOAD) return { tool, blocked: ['File path is too long to vet.'] };

  const secrets = new Set(writtenContent(tool, ti).flatMap(findSecrets));
  const blocked = [...secrets].map((s) => `Content to be written contains what looks like a credential (${s}). Keep it out of files: use an environment variable or a secret store.`);
  return { tool, action: { kind: 'fs', payload: target, intent: 'write' }, blocked: blocked.length > 0 ? blocked : undefined };
}
