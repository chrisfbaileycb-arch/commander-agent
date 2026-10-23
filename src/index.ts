import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createHttpServer } from './http.js';

const config = loadConfig();
const app = createApp({ config });
const server = createHttpServer(app);

if (config.linkSecretEphemeral) {
  console.warn('[commander] COMMANDER_LINK_SECRET is unset: approval links will not survive a restart. Set it in production.');
}
if (!config.adminToken) {
  console.warn('[commander] COMMANDER_ADMIN_TOKEN is unset: tenant provisioning endpoints are disabled.');
}
if (!config.dataDir) {
  console.warn('[commander] COMMANDER_DATA_DIR is unset: state and audit log are in memory and will be lost on exit.');
}
if (!config.notifyWebhook) {
  console.warn('[commander] COMMANDER_NOTIFY_WEBHOOK is unset: staged approvals are logged to stdout instead of pushed.');
}

server.listen(config.port, config.host, () => {
  console.log(`[commander] listening on http://${config.host}:${config.port}  (MCP: /v1/mcp · HUD: /hud)`);
});

function shutdown(signal: string): void {
  console.log(`[commander] ${signal}: flushing state`);
  server.close(() => {
    app.store.flush();
    process.exit(0);
  });
  setTimeout(() => {
    app.store.flush();
    process.exit(1);
  }, 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
