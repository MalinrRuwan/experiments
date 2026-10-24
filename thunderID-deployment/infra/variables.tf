variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names. Keep it short and globally unique enough for S3/IAM names."
  type        = string
  default     = "thunderid"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "Use 2-21 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "domain_name" {
  description = "Public hostname for ThunderID, e.g. auth.example.com. It must be served by the Route 53 zone below."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.[a-z]{2,}$", var.domain_name))
    error_message = "Use a lowercase DNS name such as auth.example.com."
  }
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for domain_name. A subdomain zone delegated from Cloudflare is fine."
  type        = string
}

variable "control_plane_type" {
  description = "Instance type for the single kubeadm control-plane node."
  type        = string
  default     = "t4g.small"
}

variable "worker_type" {
  description = "Instance type for the three application/ingress workers."
  type        = string
  default     = "t4g.small"
}

variable "data_type" {
  description = "Instance type for the two PostgreSQL data nodes."
  type        = string
  default     = "t4g.small"
}

variable "kubernetes_minor" {
  description = "Kubernetes minor version from pkgs.k8s.io (the diagram says 1.31, which is EOL)."
  type        = string
  default     = "v1.36"

  validation {
    condition     = can(regex("^v1\\.[0-9]+$", var.kubernetes_minor))
    error_message = "Use a value such as v1.36."
  }
}
