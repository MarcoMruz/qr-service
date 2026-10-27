# qr-service

Password-protected page for turning a link or text into a downloadable QR code PNG. Go stdlib + `skip2/go-qrcode`, Alpine.js (CSP build) embedded in the binary.

## Configuration

| Env | Required | Default | Notes |
|---|---|---|---|
| `APP_PASSWORD` | yes | | Shared team password, ≥12 chars. Changing it signs everyone out. |
| `SESSION_SECRET` | yes | | ≥32 chars, e.g. `openssl rand -base64 48`. |
| `TRUST_PROXY` | no | `false` | Set `true` behind Coolify/Traefik so rate limits use the real client IP (last `X-Forwarded-For` hop). Leave `false` when exposed directly. |
| `ADDR` | no | `:8080` | Listen address. |

The service refuses to start without a password and secret.

## Run

```sh
APP_PASSWORD=local-example-password SESSION_SECRET=$(openssl rand -base64 48) go run .
go test -race ./...
node --test tests/app.test.cjs
```

## Deploy (Coolify)

Build pack: Dockerfile, port `8080`, set the env vars above with `TRUST_PROXY=true`. Don't publish port 8080 on the host: with `TRUST_PROXY=true`, direct clients could forge `X-Forwarded-For`. If Cloudflare proxies the domain, the last hop is a Cloudflare IP and per-IP limits become shared across users. The image is distroless, non-root, has a built-in `HEALTHCHECK` (`/qr-service -healthcheck`) and runs tests during build.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /` | | Login page, or the generator once signed in |
| `POST /login` | | Form login, sets a 30-day signed cookie |
| `POST /api/qr` | session | `{"text": "..."}` → `image/png` (max 1,000 characters) |
| `GET /robots.txt` | | Disallows all crawlers |
| `GET /healthz` | | Liveness |

## Security

- Signed `HttpOnly`, `Secure`, `SameSite=Strict` session cookie; constant-time password check.
- Cross-origin POSTs rejected (`http.CrossOriginProtection`).
- Rate limits per IP (IPv6 per /64): login 5/min, QR 30/min; plus 30 logins/min across all IPs. Tracked clients capped at 10k.
- Strict CSP (no inline script, no eval), `nosniff`, `DENY` framing, HSTS, `no-referrer`, `no-store`.
- Body size limits and server timeouts.
- Crawlers: `robots.txt`, `<meta name="robots">`, `X-Robots-Tag`, no outbound links.
- JSON logs to stdout: failed/limited logins, rejected requests, 5xx, panics, response-write failures. Client IPs, request paths, origins, input text and passwords are never logged.
