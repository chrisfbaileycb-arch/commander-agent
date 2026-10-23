import { createHmac, timingSafeEqual } from 'node:crypto';
import { CommanderError } from './errors.js';
import { VOICE_PROFILE, say } from './persona.js';
import type { Store } from './store.js';
import type { Approval, ApprovalKind, ApprovalStatus } from './types.js';
import { iso, newId, type Clock } from './util.js';

export type Decision = 'authorize' | 'redirect' | 'kill';
export const DECISIONS: readonly Decision[] = ['authorize', 'redirect', 'kill'];

/** HMAC-signed, expiring capability links. Each decision has its own signature so a link cannot be flipped. */
export class LinkSigner {
  constructor(private readonly secret: string) {}

  sign(approvalId: string, scope: string, expSec: number): string {
    return createHmac('sha256', this.secret).update(`approval:${approvalId}:${scope}:${expSec}`).digest('base64url');
  }

  verify(approvalId: string, scope: string, expSec: number, sig: string, nowMs: number): boolean {
    if (!Number.isInteger(expSec) || expSec * 1000 <= nowMs) return false;
    const want = Buffer.from(this.sign(approvalId, scope, expSec));
    const got = Buffer.from(sig);
    return want.length === got.length && timingSafeEqual(want, got);
  }
}

export interface ActionCard {
  approvalId: string;
  kind: ApprovalKind;
  title: string;
  /** What the agent attempted. */
  incident: string;
  /** Policy breached or step failed. */
  reason: string;
  /** Landing page showing the full incident. */
  url: string;
  /** One-tap endpoints. Each is a POST so link previewers cannot trigger a decision. */
  actions: { decision: Decision; label: string; url: string }[];
  voice: typeof VOICE_PROFILE;
}

export interface Notifier {
  notify(card: ActionCard): Promise<void>;
}

export class ConsoleNotifier implements Notifier {
  async notify(card: ActionCard): Promise<void> {
    // Dev fallback. The URL carries a signed capability: treat logs that contain it as secrets.
    console.log(`[commander] ${card.title}\n  ${card.incident}\n  ${card.reason}\n  decide: ${card.url}`);
  }
}

/** Posts an ntfy-shaped JSON card (title, message, click, http actions). Any relay can reshape it. */
export class WebhookNotifier implements Notifier {
  constructor(
    private readonly url: string,
    private readonly topic?: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs = 5000,
  ) {}

  async notify(card: ActionCard): Promise<void> {
    const body = {
      ...(this.topic ? { topic: this.topic } : {}),
      title: card.title,
      message: `${card.incident}\n${card.reason}`.slice(0, 3500),
      priority: 4,
      click: card.url,
      actions: card.actions.map((a) => ({ action: 'http', label: a.label, url: a.url, method: 'POST', clear: true })),
      commander: { approval_id: card.approvalId, kind: card.kind, voice: card.voice },
    };
    const res = await this.fetchImpl(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`webhook responded ${res.status}`);
  }
}

export interface ApprovalsConfig {
  publicUrl: string;
  linkTtlSec: number;
}

export interface CreateApproval {
  tenantId: string;
  missionId: string;
  stepId: string;
  kind: ApprovalKind;
  incident: string;
  reason: string;
  clearanceId?: string;
  missionTitle: string;
  stepTitle: string;
}

const LABEL: Record<Decision, string> = { authorize: 'Authorize', redirect: 'Redirect', kill: 'Kill' };

export class Approvals {
  constructor(
    private readonly store: Store,
    readonly signer: LinkSigner,
    private readonly notifier: Notifier,
    private readonly cfg: ApprovalsConfig,
    private readonly clock: Clock,
  ) {}

  create(input: CreateApproval): Approval {
    const approval: Approval = {
      id: newId('apr'),
      tenantId: input.tenantId,
      missionId: input.missionId,
      stepId: input.stepId,
      kind: input.kind,
      status: 'pending',
      incident: input.incident,
      reason: input.reason,
      clearanceId: input.clearanceId,
      createdAt: iso(this.clock()),
    };
    this.store.state.approvals[approval.id] = approval;
    this.store.audit(input.tenantId, 'approval.staged', {
      approvalId: approval.id,
      kind: input.kind,
      missionId: input.missionId,
      clearanceId: input.clearanceId,
    });
    this.store.touch();

    const links = this.links(approval.id);
    const card: ActionCard = {
      approvalId: approval.id,
      kind: input.kind,
      title: `${input.kind === 'quarantine' ? 'QUARANTINE' : 'STAGED'} · ${input.missionTitle} · ${input.stepTitle}`.slice(0, 120),
      incident: input.incident,
      reason: input.reason,
      url: links.view,
      actions: links.actions,
      voice: VOICE_PROFILE,
    };
    // Notification is best effort and must never block or fail the request that staged the approval,
    // whether the notifier rejects asynchronously or throws synchronously.
    const onFailure = (err: unknown): void => {
      this.store.audit(input.tenantId, 'notify.failed', { approvalId: approval.id, error: String(err).slice(0, 200) });
    };
    try {
      void this.notifier.notify(card).catch(onFailure);
    } catch (err) {
      onFailure(err);
    }
    return approval;
  }

  links(approvalId: string): { view: string; actions: { decision: Decision; label: string; url: string }[]; exp: number } {
    const exp = Math.floor(this.clock() / 1000) + this.cfg.linkTtlSec;
    const base = `${this.cfg.publicUrl}/a/${approvalId}`;
    return {
      exp,
      view: `${base}?exp=${exp}&sig=${this.signer.sign(approvalId, 'view', exp)}`,
      actions: DECISIONS.map((decision) => ({
        decision,
        label: LABEL[decision],
        url: `${base}/decide?d=${decision}&exp=${exp}&sig=${this.signer.sign(approvalId, decision, exp)}`,
      })),
    };
  }

  /** Looks up without a tenant check. Callers that hold a signed link authenticate by signature instead. */
  byId(id: string): Approval {
    if (!Object.hasOwn(this.store.state.approvals, id)) throw new CommanderError('NOT_FOUND', say.notFound());
    return this.store.state.approvals[id]!;
  }

  get(tenantId: string, id: string): Approval {
    const a = this.byId(id);
    if (a.tenantId !== tenantId) throw new CommanderError('NOT_FOUND', say.notFound());
    return a;
  }

  list(tenantId: string, status?: ApprovalStatus): Approval[] {
    return Object.values(this.store.state.approvals)
      .filter((a) => a.tenantId === tenantId && (!status || a.status === status))
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt));
  }

  pendingCount(tenantId: string): number {
    return this.list(tenantId, 'pending').length;
  }
}
