import { Airlock } from './airlock.js';
import { ConsoleNotifier, Approvals, LinkSigner, WebhookNotifier, type Notifier } from './approvals.js';
import { Auth } from './auth.js';
import type { Config } from './config.js';
import { GeminiGate, NullGate, type ReasoningGate } from './gate.js';
import { Sentinel } from './sentinel.js';
import { Store } from './store.js';
import type { Clock } from './util.js';

export interface App {
  config: Config;
  clock: Clock;
  store: Store;
  auth: Auth;
  approvals: Approvals;
  airlock: Airlock;
}

export interface AppOptions {
  config: Config;
  clock?: Clock;
  /** Override for tests and embedding. */
  notifier?: Notifier;
  gate?: ReasoningGate;
  fetchImpl?: typeof fetch;
}

/** Composition root: the only place concrete collaborators are chosen. */
export function createApp(opts: AppOptions): App {
  const { config } = opts;
  const clock = opts.clock ?? Date.now;
  const store = new Store({ dir: config.dataDir, clock });
  const auth = new Auth(store, config.policy, clock);
  const sentinel = new Sentinel(config.policy, clock);

  const gate =
    opts.gate ??
    (config.geminiApiKey
      ? new GeminiGate({ apiKey: config.geminiApiKey, model: config.geminiModel, fetchImpl: opts.fetchImpl })
      : new NullGate());
  const notifier =
    opts.notifier ??
    (config.notifyWebhook ? new WebhookNotifier(config.notifyWebhook, config.notifyTopic, opts.fetchImpl) : new ConsoleNotifier());

  const approvals = new Approvals(
    store,
    new LinkSigner(config.linkSecret),
    notifier,
    { publicUrl: config.publicUrl, linkTtlSec: config.policy.approval_link_ttl_sec },
    clock,
  );
  const airlock = new Airlock({ store, auth, sentinel, gate, approvals, policy: config.policy, clock });
  return { config, clock, store, auth, approvals, airlock };
}
