# External TCP Probe Worker

This Cloudflare Worker is an optional external TCP preflight executor for a home-hosted Control
Service. It receives only controller-resolved public IPv4 addresses, the signed node public port,
a timeout, and an unrelated request ID. It receives no node/member identity, REALITY material,
VLESS credential, database claim token, or administrator credential.

The Worker opens at most six raw outbound TCP sockets, sends no bytes, returns the first successful
address plus latency, and closes every socket. A success is only TCP evidence. Control Service does
not mark an endpoint verified until a separate VLESS + REALITY canary succeeds.

## Validate

```bash
npm install
npm run check
npm test
npx wrangler deploy --dry-run
```

## Deploy

Generate a unique secret of at least 32 bytes, store the same value in Control Service, and add it
to the Worker without committing it:

```bash
npx wrangler secret put PROBE_TOKEN
npm run deploy
```

Keep observability disabled for this Worker. Do not log request bodies, target addresses, or the
`Authorization` header. The endpoint is `POST /v1/tcp-probe` and requires that secret as a Bearer
token over HTTPS.
