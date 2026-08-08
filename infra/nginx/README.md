# Sentinel IDS - bare-metal nginx reverse proxy (Phase 12)

Serves the Sentinel IDS stack on a single host behind TLS: a static-IP /
bare-metal deployment where Docker Compose runs on loopback and nginx terminates
TLS on `:443`.

## What it does

| Location | Upstream                                  |
|----------|-------------------------------------------|
| `/`      | frontend (Vite/nginx) `http://127.0.0.1:5173` |
| `/api/`  | backend (FastAPI) `http://127.0.0.1:8000`     |
| `/ws/`   | backend WebSocket `/ws/incidents` with Upgrade |

Plus: TLS 1.2/1.3 termination, gzip, security headers (CSP, HSTS-ready),
`client_max_body_size 10m`, request timeouts (3600s for sockets), and a per-IP
rate limit zone (`api_limit`).

## Install

1. Confirm the stack is running on loopback:
   ```bash
   cd infra && docker compose up -d
   curl -fsS http://127.0.0.1:8000/health
   curl -fsS http://127.0.0.1:5173/
   ```

2. Install nginx and back up the distro config:
   ```bash
   sudo apt-get install -y nginx
   sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.dist
   ```

3. Install the config (this repo ships a full main-context file):
   ```bash
   sudo cp infra/nginx/nginx.conf /etc/nginx/nginx.conf
   ```

4. Certificates. The config expects Let's Encrypt paths under
   `/etc/letsencrypt/live/sentinel.example.com/`. Issue them with certbot
   (edit `server_name` / paths first if your domain differs):
   ```bash
   sudo certbot certonly --standalone -d sentinel.example.com
   ```
   Auto-renew via `sudo certbot renew --deploy-hook 'systemctl reload nginx'`
   (certbot adds this to a systemd timer by default).

5. Validate and reload:
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## Notes

- `server_name sentinel.example.com` and the TLS cert paths must be edited for
  your domain before first run.
- HSTS is commented out; enable it after confirming TLS works end to end.
- CSP `connect-src` allows `wss://sentinel.example.com` for the realtime feed;
  update it if the host differs.
- The API rate limit zone is `20r/s` with a burst of 40 - tune for expected
  traffic. Auth endpoints already have their own stricter limits in the app.
- The frontend and backend must be reachable on `127.0.0.1:5173` and
  `127.0.0.1:8000` (the Compose default ports). If they run on other hosts,
  change the `upstream` blocks.
- If you only want the reverse-proxy `server` blocks (e.g. split across files
  in `/etc/nginx/conf.d/`), copy from the first `server {}` block onward and
  keep the shared `upstream` blocks in the same file.
