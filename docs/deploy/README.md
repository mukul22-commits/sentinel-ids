# Sentinel IDS - deployment guide (Phase 12)

Sentinel IDS v3 ships four deployment flavors. Everything is CI-gated and
deployment-ready, but the deployment targets are NOT locally executable - this
repository is developed on a machine without Docker, `kubectl`, or Terraform,
so all commands in these guides must be run from the target environment.

## Options

| Flavor      | Where                                                        | Best for                                    | Entry point                                  |
|-------------|--------------------------------------------------------------|---------------------------------------------|----------------------------------------------|
| Docker Compose | `infra/docker-compose.yml`                                | Dev/staging, single host, fast iteration    | `cd infra && docker compose up -d`           |
| Kubernetes  | `infra/k8s/`                                                | Production, HA, autoscaling, self-managed   | `kubectl apply -k infra/k8s`                 |
| Bare metal  | `infra/nginx/nginx.conf`                                    | Static-IP host, TLS termination, gating Compose behind a reverse proxy | `sudo cp infra/nginx/nginx.conf /etc/nginx/nginx.conf` |
| AWS (ECS)   | `infra/terraform/aws/`                                      | Cloud production, managed services, IaC     | `terraform init && terraform apply`          |

## Quick start matrix

### Docker Compose (development)

```bash
cp .env.example .env
cd infra && docker compose up -d --build
# postgres :5432, redis :6379, backend :8000, worker, frontend :5173,
# prometheus :9090, grafana :3000, loki :3100
curl -fsS http://localhost:8000/health
```

### Kubernetes

```bash
kubectl config use-context <cluster>
# (install ingress-nginx + cert-manager; push images; set secrets)
kubectl apply -k infra/k8s
kubectl -n sentinel-ids rollout status deploy/backend
```

See `infra/k8s/README.md` for prerequisites, the secrets workflow, and the
`sentinel-tls` certificate setup.

### Bare metal reverse proxy

```bash
cd infra && docker compose up -d        # stack on loopback :5173 / :8000
sudo cp infra/nginx/nginx.conf /etc/nginx/nginx.conf
# edit server_name + cert paths, then:
sudo nginx -t && sudo systemctl reload nginx
```

See `infra/nginx/README.md`.

### AWS / ECS

```bash
cd infra/terraform/aws
terraform init && terraform plan && terraform apply
# populate AWS Secrets Manager secret "sentinel/env", push images to ECR,
# redeploy the services
```

See `infra/terraform/aws/README.md`.

## Shared pieces

- **Database**: TimescaleDB (`timescale/timescaledb:latest-pg16`), initialized
  from `infra/postgres/init/` (timescaledb extension). Backups: `scripts/`.
- **Backend**: FastAPI on :8000, health probes at `/health`,
  `/health/ready`, `/health/live`; realtime WebSocket at `/ws/incidents`.
- **Frontend**: React SPA, production image from `frontend/Dockerfile.prod`
  (nginx on :80), dev served by Vite on :5173.
- **Observability**: Prometheus + Grafana + Loki + Promtail ship with Compose;
  the backend exposes Prometheus metrics at `/metrics`.
- **Secrets**: never in git. Kubernetes uses a Secret template or generator;
  AWS uses Secrets Manager `sentinel/env`; bare metal uses the backend
  `.env`/`SECRET_KEY_FILE`/Vault resolution (`backend/app/services/secrets.py`).

## Ops

Day-2 operations live in `docs/deploy/runbooks.md`: service down, DB full,
Redis down, celery stuck, incident response, cert expiry, backup restore
drills, secrets rotation, scaling, and p99 latency degradation.
