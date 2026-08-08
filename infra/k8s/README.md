# Sentinel IDS - Kubernetes deployment (Phase 12)

Kubernetes manifests for the full Sentinel IDS stack: TimescaleDB Postgres,
Redis, the FastAPI backend, the Celery worker, the React frontend, and an
ingress-nginx Ingress.

> **Deployment status:** these manifests are CI-gated and deployment-ready.
> They are NOT locally executable - this repository is developed on a machine
> without `kubectl` or Docker, so every command below must be run from a
> workstation or CI runner that has cluster access.

## Layout

| File                  | Purpose                                                        |
|-----------------------|----------------------------------------------------------------|
| `namespace.yaml`      | `sentinel-ids` namespace                                       |
| `configmap.yaml`      | Non-secret env (`sentinel-config`) + Postgres identity (`postgres-config`) |
| `secret.example.yaml` | Secret template - placeholders, never real values              |
| `postgres.yaml`       | TimescaleDB StatefulSet + `postgres-data` PVC + Service        |
| `redis.yaml`          | Redis Deployment + Service                                     |
| `backend.yaml`        | API Deployment (2 replicas) + Service                          |
| `worker.yaml`         | Celery worker Deployment (no Service)                          |
| `frontend.yaml`       | SPA Deployment (from `frontend/Dockerfile.prod`) + Service     |
| `ingress.yaml`        | ingress-nginx Ingress + TLS                                    |
| `kustomization.yaml`  | Bundles everything for `kubectl apply -k`                      |

## Prerequisites

1. A Kubernetes cluster (EKS, kind, k3s, ...) and `kubectl` configured.
2. `ingress-nginx` installed (the Ingress uses `ingressClassName: nginx`):
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.1/deploy/static/provider/cloud/deploy.yaml
   ```
3. `cert-manager` for automatic TLS (recommended), or a pre-created `sentinel-tls`
   TLS Secret.
4. A default `StorageClass` for the Postgres PVC.
5. The `sentinel-backend` and `sentinel-frontend:prod` container images published
   to a registry reachable by the cluster (the CI `build` job builds them; push
   them and override the placeholders in `kustomization.yaml`).

## Applying

```bash
# Point kubectl at the right context first, e.g.:
kubectl config use-context <cluster>

# Dry-run against a live cluster (validates schemas + kustomize):
kubectl apply -k infra/k8s --dry-run=client

# Real apply:
kubectl apply -k infra/k8s

# Watch rollout:
kubectl -n sentinel-ids get pods -w
kubectl -n sentinel-ids rollout status deploy/backend
```

## Secrets

The bundle includes `secret.example.yaml` with `REPLACE_ME` placeholders so the
tree validates. Before a real deployment you MUST supply real values - either
replace them in that file, or enable the `secretGenerator` in
`kustomization.yaml` (see the comments there) to build a hashed Secret from a
gitignored `secrets.env`.

Required keys (see `secret.example.yaml` for the full list and generation
commands): `POSTGRES_PASSWORD`, `SECRET_KEY`, `JWT_SECRET_KEY`.
`SECRET_KEY` must be at least 32 characters when `ENVIRONMENT=prod`.

TLS Secret (`sentinel-tls`) with cert-manager:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: sentinel-tls
  namespace: sentinel-ids
spec:
  secretName: sentinel-tls
  dnsNames:
    - sentinel.example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
EOF
```

Or create it manually:

```bash
kubectl -n sentinel-ids create secret tls sentinel-tls \
  --cert=fullchain.pem --key=privkey.pem
```

## Health endpoints and probes

The backend exposes three probes (`backend/app/api/v1/endpoints/health.py`):

- `/health` - always 200 while the process is up (Compose compat probe)
- `/health/ready` - 503 unless PostgreSQL and Redis are reachable
- `/health/live` - always 200 while the process is alive

`backend.yaml` uses `/health/ready` for readiness and `/health/live` for
liveness, which is why pods only join the Service when their dependencies are
healthy.

## WebSockets

The realtime feed is served at `/ws/incidents` (root path, see
`backend/app/api/v1/routes/ws.py`). The Ingress routes `/ws` to the backend and
long proxy read/write timeouts (3600s) are set so sockets do not drop.
`frontend.yaml` has no websocket concern; the SPA connects directly to
`wss://<host>/ws/incidents`.

## Migrations

The backend image entrypoint (`backend/entrypoint.sh`) runs
`alembic upgrade head` before starting uvicorn, so each backend pod migrates on
startup. With 2 replicas the runs can briefly race; for strict deployments
replace this with a one-shot Job, e.g.:

```bash
kubectl -n sentinel-ids run migrate-once --rm -i \
  --image=<registry>/sentinel-ids-backend:<tag> \
  --env-from=sentinel-config --env-from=sentinel-secrets \
  --restart=Never --command -- alembic upgrade head
```

## Scaling

- Backend: `kubectl -n sentinel-ids scale deploy/backend --replicas=N` (uvicorn
  workers per pod via `UVICORN_WORKERS`). Mind the `cpu: 500m` / `memory: 512Mi`
  limit; scale pods before raising per-pod limits.
- Worker: scale `deploy/worker` to drain queues faster. Configure
  `CELERY_WORKER_CONCURRENCY` in the ConfigMap for per-pod throughput.
- Postgres: single-writer StatefulSet. Do not scale the StatefulSet; grow the
  PVC instead (`kubectl -n sentinel-ids edit sts postgres` or a storage-class
  resize). Backups: see `scripts/backup.sh` / `scripts/restore_test.sh`.
- Frontend: `scale deploy/frontend`.

## Connecting kubectl

```bash
# EKS
aws eks update-kubeconfig --name sentinel --region <region>

# Any cluster
kubectl config set-context --current --namespace=sentinel-ids
kubectl get all -n sentinel-ids
```

## Observability

The stack ships Prometheus / Grafana / Loki / Promtail for Docker Compose
(`infra/`). On Kubernetes, scrape `backend:8000/metrics` with a ServiceMonitor
and forward pod logs to Loki with the Helm `grafana/loki-stack` or
`grafana/promtail` chart.
