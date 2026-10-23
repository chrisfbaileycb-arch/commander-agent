import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { Airlock } from './airlock.js';
import { CommanderError } from './errors.js';
import { renderClearance, renderClearanceStatus, renderDirective, renderProof } from './render.js';
import { ActionRequestSchema, EvidenceSchema, type Principal } from './types.js';

/**
 * The MCP face of Commander. To a client it is one coherent endpoint with five tools. Everything behind
 * the tools (ledger, verifiers, sentinel, gate) runs server-side; nothing proprietary ships to the client.
 *
 * Boundary worth stating plainly: an MCP server only governs what is routed through it. A worker that
 * skips `commander_request_clearance` and runs a command directly is not seen by the Sentinel here. The
 * airlock still holds, because a step cannot close without proof. Native Bash/Write/Edit calls are covered by
 * the client-side PreToolUse hook (src/guard), which asks the same Sentinel through /v1/guard/clearance.
 */

const ok = (rendered: string, data: object): CallToolResult => ({
  content: [{ type: 'text', text: rendered }],
  structuredContent: data as Record<string, unknown>,
});

async function guard(fn: () => CallToolResult | Promise<CallToolResult>): Promise<CallToolResult> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof CommanderError) {
      return {
        isError: true,
        content: [{ type: 'text', text: `COMMANDER // REFUSED [${err.code}]\n${err.message}` }],
        structuredContent: { error: err.code, message: err.message, ...(err.details ?? {}) },
      };
    }
    console.error('[commander] internal fault', err);
    return { isError: true, content: [{ type: 'text', text: 'COMMANDER // FAULT\nInternal fault. Request not processed.' }] };
  }
}

export function buildMcpServer(principal: Principal, airlock: Airlock): McpServer {
  const server = new McpServer({ name: 'agent-commander', version: '0.1.0' });

  server.registerTool(
    'commander_get_directive',
    {
      title: 'Get directive',
      description:
        'Pull the directive for the step you are cleared to execute. Returns only the current step, a lease id, the proof ' +
        'required, and a ledger of closed steps. Future steps are never disclosed. Call again for the next directive after proof is verified.',
      inputSchema: { mission_id: z.string().min(1).max(64).describe('Mission handle issued by your operator.') },
      annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false },
    },
    ({ mission_id }) => guard(() => {
      const r = airlock.getDirective(principal, mission_id);
      return ok(renderDirective(r), r);
    }),
  );

  server.registerTool(
    'commander_submit_proof',
    {
      title: 'Submit proof',
      description:
        'Submit mechanical evidence for the current directive: the real exit code, raw stdout/stderr, and file artifacts as text. ' +
        'Self-reported completion is discarded, and Commander may independently re-run checks and inspect the workspace itself. ' +
        'A rejected proof returns a corrective patch and, where required, a fresh nonce.',
      inputSchema: {
        mission_id: z.string().min(1).max(64),
        lease_id: z.string().min(1).max(64).describe('Lease id from the directive you are proving.'),
        evidence: EvidenceSchema,
      },
      annotations: { readOnlyHint: false, openWorldHint: false },
    },
    ({ mission_id, lease_id, evidence }) => guard(async () => {
      const r = await airlock.submitProof(principal, mission_id, { lease_id, evidence });
      return ok(renderProof(r), r);
    }),
  );

  server.registerTool(
    'commander_request_clearance',
    {
      title: 'Request clearance',
      description:
        'Request clearance BEFORE a risky action: shell command, SQL, outbound HTTP, file mutation, deploy, or payment. ' +
        'Returns CLEARED, DENIED with a redirect patch, or STAGED for operator authorization (then poll commander_clearance_status). ' +
        'Execute only what was cleared, exactly as submitted, once.',
      inputSchema: {
        mission_id: z.string().min(1).max(64),
        lease_id: z.string().min(1).max(64),
        action: ActionRequestSchema,
      },
      annotations: { readOnlyHint: false, openWorldHint: false },
    },
    ({ mission_id, lease_id, action }) => guard(async () => {
      const r = await airlock.requestClearance(principal, mission_id, { lease_id, action });
      return ok(renderClearance(r), r);
    }),
  );

  server.registerTool(
    'commander_clearance_status',
    {
      title: 'Clearance status',
      description: 'Poll a STAGED clearance. Returns CLEARED, DENIED (with any operator redirect), PENDING, or TERMINATED.',
      inputSchema: { clearance_id: z.string().min(1).max(64) },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    ({ clearance_id }) => guard(() => {
      const r = airlock.clearanceStatus(principal, clearance_id);
      return ok(renderClearanceStatus(r), r);
    }),
  );

  server.registerTool(
    'commander_mission_status',
    {
      title: 'Mission status',
      description: 'Check whether a mission is active, on hold, completed, or terminated. Reveals nothing about its plan.',
      inputSchema: { mission_id: z.string().min(1).max(64) },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    ({ mission_id }) => guard(() => {
      const r = airlock.missionStatus(principal, mission_id);
      return ok(`COMMANDER // MISSION ${r.status.toUpperCase()}\n${r.message}`, r);
    }),
  );

  return server;
}
