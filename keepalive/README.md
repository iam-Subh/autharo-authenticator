# Keep-alive worker

Render's free plan stops the API after 15 minutes without traffic, and the
next request then waits up to a minute for it to start. This Cloudflare Worker
requests `/v1/health` every 10 minutes so that never happens.

## Deploy

```sh
cd keepalive
npx wrangler login
npx wrangler deploy
```

Check it by opening the `*.workers.dev` URL that `deploy` prints. It runs one
ping and shows the result. Cron runs are under **Workers & Pages →
authfactor-keepalive → Logs** in the Cloudflare dashboard.

## Limits

- Cloudflare's free Workers plan allows 100,000 requests a day. This uses 144.
- Render's free plan gives 750 instance hours a month. One service awake all
  month uses about 744, so no other free Render service can stay awake too.
- If the API moves off Render, change `HEALTH_URL` in `wrangler.toml`.
