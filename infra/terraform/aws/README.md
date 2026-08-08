# Sentinel IDS - AWS Terraform deployment (Phase 12)

Terraform module that stands up the AWS flavor of Sentinel IDS: a VPC with
public/private subnets across two AZs, NAT gateways, an ALB, ECS Fargate
services for the backend and frontend, an ECR repository, and security groups
for the ALB / ECS / database.

> **Deployment status:** this targets a cloud deployment and is NOT runnable
> locally. It requires AWS credentials and the `terraform` CLI.

## Layout

| File          | Purpose                                                        |
|---------------|----------------------------------------------------------------|
| `main.tf`     | Provider, VPC, networking, SGs, ECR, ECS, ALB (single file)    |
| `variables.tf`| region, vpc_cidr, env, tags                                    |
| `outputs.tf`  | alb_dns_name, cluster_name, ecr_repo_url                      |

## Prerequisites

- Terraform >= 1.0
- AWS credentials (env vars, `~/.aws/credentials`, or an assumed role)
- AWS CLI (optional, for pushing images)

## Bootstrap remote state (recommended)

Remote state with S3 + DynamoDB locking keeps `plan`/`apply` safe for a team.
First create the bucket and lock table once, e.g.:

```bash
aws s3 mb s3://sentinel-tf-state-$ACCOUNT --region us-east-1
aws dynamodb create-table \
  --table-name sentinel-tf-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

Then add a `backend "s3"` block in `main.tf`:

```hcl
terraform {
  backend "s3" {
    bucket         = "sentinel-tf-state"
    key            = "sentinel-ids/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "sentinel-tf-locks"
    encrypt        = true
  }
}
```

For a single user, local state (`terraform.tfstate`) works fine.

## init / plan / apply

```bash
cd infra/terraform/aws
terraform init
terraform plan -var env=dev -var region=us-east-1
terraform apply -var env=dev -var region=us-east-1
terraform output alb_dns_name
```

## Wiring secrets via AWS Secrets Manager

The ECS tasks read their environment from the JSON secret **`sentinel/env`**
(one JSON object, values are base64-free plaintext). Create it before `apply`:

```bash
aws secretsmanager create-secret --name sentinel/env --secret-string '{
  "DATABASE_URL": "postgresql+asyncpg://sentinel:PASSWORD@<db-host>:5432/sentinel_ids",
  "REDIS_URL": "redis://<redis-host>:6379/0",
  "SECRET_KEY": "<random >= 32 chars>",
  "POSTGRES_PASSWORD": "<db password>"
}'
```

The keys actually injected are declared in `local.sentinel_env_keys` in
`main.tf`; add keys there (e.g. `SIEM_AUTH_TOKEN`, `HTTP_CONNECTOR_TOKEN`) as
the platform needs them. The ECS execution role gets a scoped
`secretsmanager:GetSecretValue` policy for exactly this secret.

**Pointing at AWS managed services:** the current config expects the backend to
reach Postgres and Redis itself (e.g. self-hosted on the VPC, or managed
ElastiCache / RDS). The RDS security group is provisioned and a commented
`aws_db_instance` block shows how to add managed Postgres - uncomment it and
point `DATABASE_URL` at the RDS endpoint.

## Building and pushing images

The task definitions reference `ECR_URL:backend` and `ECR_URL:frontend`.
Build and push after `apply`:

```bash
REGISTRY=$(terraform output -raw ecr_repo_url)
cd backend  && docker build -t $REGISTRY:backend . && docker push $REGISTRY:backend
cd frontend && docker build -f Dockerfile.prod -t $REGISTRY:frontend . && docker push $REGISTRY:frontend
```

Then force a new deployment:

```bash
aws ecs update-service --cluster <cluster_name> --service backend --force-new-deployment
```

## Caveats

- TLS: the HTTP listener is created by default; the HTTPS listener + ACM
  certificate are commented out in `main.tf`. Enable them once your domain is
  validated.
- Fargate networking requires private subnets to egress via the NAT gateways
  (one per AZ, costing money - drop to a single NAT for non-prod).
- Backups: run the `scripts/` pg_dump helpers against the managed/self-hosted
  database, or rely on RDS automated snapshots if you use RDS.
