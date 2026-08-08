# Sentinel IDS - AWS deployment (Phase 12)
#
# Single-file Terraform for the AWS flavor of the Sentinel IDS deployment:
# VPC (public + private subnets across 2 AZs), NAT, ALB, ECS Fargate services
# for backend + frontend, an ECR repository, and an RDS-capable security group.
#
# Env config for the containers is pulled from the AWS Secrets Manager secret
# "sentinel/env" (a JSON object). See infra/terraform/aws/README.md for how to
# populate it.
#
# Apply:  terraform init && terraform plan && terraform apply
# This targets a cloud deployment and is NOT runnable locally.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = var.tags
  }
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_secretsmanager_secret" "sentinel_env" {
  name = "sentinel/env"
}

data "aws_secretsmanager_secret_version" "sentinel_env" {
  secret_id = data.aws_secretsmanager_secret.sentinel_env.id
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "sentinel-${var.env}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "sentinel-${var.env}-igw" }
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "sentinel-${var.env}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 2)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "sentinel-${var.env}-private-${count.index + 1}" }
}

# One NAT gateway per AZ (ha). For a cheaper setup, use a single NAT.
resource "aws_eip" "nat" {
  count = 2
  domain = "vpc"

  tags = { Name = "sentinel-${var.env}-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "main" {
  count = 2

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "sentinel-${var.env}-nat-${count.index + 1}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "sentinel-${var.env}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count = 2

  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = { Name = "sentinel-${var.env}-private-rt-${count.index + 1}" }
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "sentinel-${var.env}-alb"
  description = "Sentinel IDS - ALB ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sentinel-${var.env}-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name        = "sentinel-${var.env}-ecs"
  description = "Sentinel IDS - ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "ALB to ECS"
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sentinel-${var.env}-ecs-sg" }
}

resource "aws_security_group" "rds" {
  name        = "sentinel-${var.env}-rds"
  description = "Sentinel IDS - database (5432 from ECS only)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sentinel-${var.env}-rds-sg" }
}

# Optional managed database. Uncomment to provision RDS Postgres 16
# (TimescaleDB is an AWS-supported extension). DATABASE_URL in the Secrets
# Manager secret must then point here, not at a self-hosted postgres.
# resource "aws_db_instance" "sentinel" {
#   identifier             = "sentinel-${var.env}"
#   engine                 = "postgres"
#   engine_version         = "16.4"
#   instance_class         = "db.t4g.micro"
#   allocated_storage      = 20
#   db_name                = "sentinel_ids"
#   username               = "sentinel"
#   password               = data.aws_secretsmanager_secret_version.sentinel_env.secret_string # JSON, use a reference instead
#   db_subnet_group_name   = aws_db_subnet_group.sentinel.name
#   vpc_security_group_ids = [aws_security_group.rds.id]
#   skip_final_snapshot    = false
#   final_snapshot_identifier = "sentinel-${var.env}-final"
#   storage_encrypted      = true
# }

# resource "aws_db_subnet_group" "sentinel" {
#   name       = "sentinel-${var.env}"
#   subnet_ids = aws_subnet.private[*].id
# }

# ---------------------------------------------------------------------------
# Container registry
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "sentinel" {
  name                 = "sentinel-ids"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "sentinel-ids" }
}

# ---------------------------------------------------------------------------
# ECS
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "sentinel" {
  name = "sentinel-${var.env}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "ecs_execution" {
  name = "sentinel-${var.env}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "sentinel-${var.env}-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [data.aws_secretsmanager_secret.sentinel_env.arn]
    }]
  })
}

locals {
  # Keys injected from the JSON secret "sentinel/env". Add more keys as needed.
  sentinel_env_keys = ["DATABASE_URL", "REDIS_URL", "SECRET_KEY", "POSTGRES_PASSWORD"]
  sentinel_env_secrets = [
    for key in local.sentinel_env_keys :
    {
      name      = key
      valueFrom = "${data.aws_secretsmanager_secret.sentinel_env.arn}:${key}::"
    }
  ]
}

# The awslogs driver requires the log group to exist before tasks can start.
resource "aws_cloudwatch_log_group" "sentinel" {
  name              = "/ecs/sentinel-${var.env}"
  retention_in_days = 14
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "sentinel-${var.env}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  container_definitions    = jsonencode([{
    name        = "backend"
    image       = "${aws_ecr_repository.sentinel.repository_url}:backend"
    essential   = true
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    secrets     = local.sentinel_env_secrets
    healthCheck = {
      # The python:3.12-slim backend image ships python, not curl.
      command     = ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=5).status == 200 else 1)\""]
      interval    = 10
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/sentinel-${var.env}"
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "backend"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "sentinel-${var.env}-frontend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  container_definitions    = jsonencode([{
    name         = "frontend"
    image        = "${aws_ecr_repository.sentinel.repository_url}:frontend"
    essential    = true
    portMappings = [{ containerPort = 80, protocol = "tcp" }]
    healthCheck  = {
      command     = ["CMD-SHELL", "wget -q -O - http://127.0.0.1:80/ >/dev/null 2>&1 || exit 1"]
      interval    = 10
      timeout     = 5
      retries     = 3
      startPeriod = 10
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/sentinel-${var.env}"
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "frontend"
      }
    }
  }])
}

# ---------------------------------------------------------------------------
# Load balancer
# ---------------------------------------------------------------------------

resource "aws_lb" "sentinel" {
  name               = "sentinel-${var.env}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "backend" {
  name        = "sentinel-${var.env}-backend"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health/ready"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }
}

resource "aws_lb_target_group" "frontend" {
  name        = "sentinel-${var.env}-frontend"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.sentinel.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

# /api and /ws go to the backend; everything else (/) goes to the frontend.
resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  condition {
    path_pattern {
      values = ["/api/*", "/ws/*"]
    }
  }
}

# Optional HTTPS listener; wire a certificate via ACM once the domain is set.
# resource "aws_acm_certificate" "sentinel" {
#   domain_name       = "sentinel.example.com"
#   validation_method = "DNS"
# }
#
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.sentinel.arn
#   port              = 443
#   protocol          = "HTTPS"
#   certificate_arn   = aws_acm_certificate.sentinel.arn
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.frontend.arn
#   }
# }

# ---------------------------------------------------------------------------
# ECS services
# ---------------------------------------------------------------------------

resource "aws_ecs_service" "backend" {
  name            = "backend"
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend.arn
    container_name   = "backend"
    container_port   = 8000
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
}

resource "aws_ecs_service" "frontend" {
  name            = "frontend"
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 80
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
}
