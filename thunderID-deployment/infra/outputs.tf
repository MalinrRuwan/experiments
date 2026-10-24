output "nodes" {
  description = "Instance IDs, private IPs and roles. Use SSM Session Manager instead of SSH."
  value = {
    for name, node in aws_instance.node : name => {
      instance_id = node.id
      private_ip  = node.private_ip
      role        = local.nodes[name].role
    }
  }
}

output "api_endpoint" {
  description = "Internal NLB DNS name passed to kubeadm --control-plane-endpoint."
  value       = aws_lb.api.dns_name
}

output "alb_dns_name" {
  description = "AWS-generated ALB hostname (diagnostic only; clients use domain_name)."
  value       = aws_lb.auth.dns_name
}

output "auth_hostname" {
  description = "Public hostname served by the ALB."
  value       = var.domain_name
}

output "auth_url" {
  description = "Public HTTPS URL served by the ALB."
  value       = "https://${var.domain_name}"
}

output "backup_bucket" {
  description = "S3 bucket for PostgreSQL backups (Object Lock, 30-day default retention)."
  value       = aws_s3_bucket.backups.bucket
}

output "aws_region" {
  value = var.aws_region
}

output "vault_kms_key_id" {
  description = "KMS key ID used for Vault auto-unseal."
  value       = aws_kms_key.main.key_id
}

output "node_role_arn" {
  value = aws_iam_role.node.arn
}
