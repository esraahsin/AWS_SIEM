variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "EC2 Key Pair name (optional, for SSH access)"
  type        = string
  default     = ""
}

variable "ssh_cidr" {
  description = "CIDR allowed to SSH into instances"
  type        = string
  default     = "0.0.0.0/0"
}

variable "elk_instance_type" {
  description = "t3.medium minimum — Elasticsearch will OOM on t2.micro"
  type        = string
  default     = "t3.medium"
}