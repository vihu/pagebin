# pagebin

[![CI](https://github.com/vihu/pagebin/actions/workflows/ci.yml/badge.svg)](https://github.com/vihu/pagebin/actions/workflows/ci.yml)

Self-hosted static site sharing. Sign in, paste HTML or upload flat files, and share
a link on a separate viewer host, open or password-protected.

## Run

```sh
curl -fsSLO "https://raw.githubusercontent.com/vihu/pagebin/main/{docker-compose.yml,env.example}"
cp env.example .env   # set PAGEBIN_ADMIN_PASSWORD; the rest works locally as is
docker compose up -d
open http://localhost:5050/login
```

Admin UI is served on `PAGEBIN_ADMIN_HOST`, sites on `PAGEBIN_VIEW_HOST/s/{slug}/`.
Share links use `PAGEBIN_PUBLIC_URL`, so its port must match `PAGEBIN_PORT`.
Data lives in the `pagebin-data` volume at `/data`: `pagebin.db`, `sites/`, `secret.key`.

Native: `cargo run` in the same directory. It reads the same `.env`.

## Configuration

| Variable                 | Required | Default                               | Notes                                             |
| ------------------------ | -------- | ------------------------------------- | ------------------------------------------------- |
| `PAGEBIN_ADMIN_PASSWORD` | yes      |                                       | 1 to 131072 UTF-8 bytes, no NUL, CR, or LF        |
| `PAGEBIN_ADMIN_HOST`     | yes      | compose: `localhost`                  | Host only. No scheme, port, or path               |
| `PAGEBIN_VIEW_HOST`      | no       | compose: `view.localhost`             | Unset means single-host mode, local dev only      |
| `PAGEBIN_PORT`           | no       | `5050`                                | Listen port. Compose publishes it on 127.0.0.1    |
| `PAGEBIN_PUBLIC_URL`     | no       | compose: `http://view.localhost:5050` | Root URL in share links. HTTP only on loopback    |
| `PAGEBIN_SECRET`         | no       | generated into `secret.key`           | 64 hex chars. Required on non-Unix                |
| `PAGEBIN_TRUST_PROXY`    | no       | `false`                               | Use the last `X-Forwarded-For` entry as client IP |
| `PAGEBIN_MAX_UPLOAD_MB`  | no       | `50`                                  | Whole multipart body                              |
| `PAGEBIN_API_TOKEN`      | no       | unset, API disabled                   | Bearer token for `/api/sites`                     |
| `PAGEBIN_DATA_DIR`       | no       | `data`                                | Relative to the working directory. Leave unset    |
| `RUST_LOG`               | no       | `pagebin=info,tower_http=info`        |                                                   |

`cargo run` and Compose both read `.env`. Real environment variables win over it.

## Reverse proxy

Terminate TLS in front. Browser sessions use `Secure` cookies, so production needs HTTPS.
Caddy preserves `Host` and appends the client IP to `X-Forwarded-For`, so
`PAGEBIN_TRUST_PROXY=true` is safe when the listener is reachable only through it.

```caddyfile
pages.example.com, view.example.com {
    reverse_proxy 127.0.0.1:5050
}
```

Set `PAGEBIN_PUBLIC_URL=https://view.example.com`. Never serve uploaded HTML on the admin host.

## API

Set `PAGEBIN_API_TOKEN` to enable `/api/sites` on the admin host.

For publishing from pi or Claude Code, install the [Pagebin skill](skills/pagebin/SKILL.md#install-once).
It bundles an uploader for HTML files and static-site directories; credentials stay local.

```sh
curl -sS -H "Authorization: Bearer $PAGEBIN_API_TOKEN" \
  -F 'html=<index.html' -F title="Release notes" -F expires_in=7d \
  https://pages.example.com/api/sites
```

`POST /api/sites` and `PUT /api/sites/{slug}` take the create form's multipart fields: `html`, `files[]`, or `zip`, plus the settings.
`PATCH /api/sites/{slug}` takes JSON with any of `title`, `entry`, `visibility`, `password`, `expires_in`.
`DELETE /api/sites/{slug}` returns 204. `GET /api/sites` lists every site. Errors are `{"error": "..."}`.

## Non-goals

- Multi-user, OIDC, teams.
- Public index or discovery page.
- Custom domains per site.
- Versions, history, rollback.
- Object storage backends.
- Markdown or any server-side rendering. HTML in, HTML out.

## Check

```sh
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
just tailwind css && git diff --exit-code -- static/app.css
```

## License

AGPL-3.0-only. See `LICENSE`.
