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
