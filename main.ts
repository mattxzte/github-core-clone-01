// Entry lifecycle: bind, register, wait, exit.
//
// The suite's env owns the trial. This process only has to do four things, in order:
// bind an ephemeral port (never 8080, which the env owns), tell the env that port,
// wait until the env says the trial is done, then close and exit 0. Nothing here is
// scored except that the server it starts answers; the forge itself lives in app.ts.

import { createApp } from './app.ts';

const envOrigin = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envOrigin === '') {
  process.stderr.write('MAKEFUN_ENV_URL is not set, so there is no env to register with\n');
  process.exit(1);
}

const REQUEST_TIMEOUT = 30_000;
const FIRST_RETRY_WAIT = 250;
const LONGEST_RETRY_WAIT = 2_000;

const pause = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

function waitAfterFailures(failures: number): number {
  const doubled = FIRST_RETRY_WAIT * 2 ** Math.min(failures, 8);
  return Math.min(LONGEST_RETRY_WAIT, doubled);
}

async function tellEnvThePort(port: number): Promise<void> {
  let failures = 0;
  for (;;) {
    let answer: Response | null = null;
    try {
      answer = await fetch(`${envOrigin}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });
    } catch {
      answer = null;
    }
    if (answer !== null) {
      if (answer.status === 200 || answer.status === 409) return;
      if (answer.status === 400 || answer.status === 405) {
        throw new Error(`the env refused the registration with HTTP ${answer.status}: ${await answer.text()}`);
      }
    }
    await pause(waitAfterFailures(failures));
    failures += 1;
  }
}

async function waitUntilDone(): Promise<void> {
  let failures = 0;
  for (;;) {
    try {
      const answer = await fetch(`${envOrigin}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT) });
      if (answer.ok) {
        const payload = (await answer.json()) as { done?: unknown };
        if (payload.done === true) return;
      }
    } catch {
      // The env is still starting, or the poll timed out: either way it is not done yet.
    }
    await pause(waitAfterFailures(failures));
    failures += 1;
  }
}

async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const bound = server.address();
  if (bound === null || typeof bound === 'string') {
    throw new Error('the server did not bind a TCP port');
  }
  process.stdout.write(`listening on port ${bound.port}\n`);
  await tellEnvThePort(bound.port);
  process.stdout.write('registered; waiting for the env to finish the trial\n');
  await waitUntilDone();
  server.close();
  process.stdout.write('done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
