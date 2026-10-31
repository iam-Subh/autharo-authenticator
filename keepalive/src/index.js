// Keeps the Render free-plan API awake by requesting its health route on the
// cron schedule in wrangler.toml. The route returns "ok" and touches no data.

export default {
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(ping(env.HEALTH_URL));
  },

  // Opening the worker's URL runs one ping, which is how to check it by hand.
  async fetch(_request, env) {
    const result = await ping(env.HEALTH_URL);
    return Response.json(result, { status: result.ok ? 200 : 502 });
  },
};

async function ping(url) {
  const started = Date.now();
  try {
    // A cold start on Render can take close to a minute, so wait for it
    // instead of giving up and leaving the service asleep.
    const response = await fetch(url, {
      headers: { "user-agent": "authfactor-keepalive" },
      signal: AbortSignal.timeout(90_000),
    });
    const result = { ok: response.ok, status: response.status, ms: Date.now() - started };
    console.log(JSON.stringify(result));
    return result;
  } catch (error) {
    const result = { ok: false, error: String(error), ms: Date.now() - started };
    console.error(JSON.stringify(result));
    return result;
  }
}
