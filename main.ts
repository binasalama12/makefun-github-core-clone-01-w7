// Entry lifecycle for the nimble-falcon-91 forge: bind an ephemeral port, register it with
// the trial environment, then poll the environment's done flag and exit 0 when it fires.
// The server itself lives in app.ts; this file only owns the conversation with the env.

import { createApp } from './app.ts';

const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envUrl === '') {
  process.stderr.write('[forge] MAKEFUN_ENV_URL is not set; nowhere to register\n');
  process.exit(1);
}

const TIMEOUT_MS = 30_000;
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const backoff = (attempt: number): number => Math.min(2_000, 250 * 2 ** Math.min(attempt, 8));

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register refused with HTTP ${res.status}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register refused')) throw err;
    }
    await wait(backoff(attempt));
  }
}

async function waitUntilDone(): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(`${envUrl}/done`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Poll again: a silent env is a running trial, not a finished one.
    }
    await wait(backoff(attempt));
  }
}

const server = createApp();
await new Promise<void>((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, () => resolve());
});
const address = server.address();
if (address === null || typeof address === 'string') {
  process.stderr.write('[forge] server did not bind a TCP port\n');
  process.exit(1);
}
process.stdout.write(`[forge] listening on ${address.port}\n`);
await register(address.port);
process.stdout.write('[forge] registered; serving until done\n');
await waitUntilDone();
server.close();
process.stdout.write('[forge] done\n');
process.exit(0);
