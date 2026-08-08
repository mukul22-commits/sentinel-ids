output "alb_dns_name" {
  description = "DNS name of the Sentinel IDS application load balancer"
  value       = aws_lb.sentinel.dns_name
}

output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.sentinel.name
}

output "ecr_repo_url" {
  description = "URL of the sentinel-ids ECR repository"
  value       = aws_ecr_repository.sentinel.repository_url
}
