variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the Sentinel IDS VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "env" {
  description = "Environment name (dev/staging/prod); used in resource names and tags"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
  default = {
    managed_by = "terraform"
    project    = "sentinel-ids"
  }
}

variable "domain_name" {
  description = "Public domain served by the ALB (e.g. ids.example.com). When set, an ACM certificate plus a 443 HTTPS listener are created and the HTTP listener redirects to HTTPS. Leave empty for HTTP-only dev deployments."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID used for DNS validation of the ACM certificate. Required when domain_name is set."
  type        = string
  default     = ""
}
