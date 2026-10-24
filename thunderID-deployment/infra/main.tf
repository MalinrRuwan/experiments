terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.name_prefix
      ManagedBy = "opentofu"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Two AZs are the minimum for an ALB/NLB. The diagram's /16 is split into
  # public, private-app and private-data ranges.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  vpc_cidr       = "10.42.0.0/16"
  public_subnets = ["10.42.0.0/20", "10.42.16.0/20"]
  app_subnets    = ["10.42.32.0/20", "10.42.48.0/20"]
  data_subnets   = ["10.42.64.0/20", "10.42.80.0/20"]

  backup_bucket = "${var.name_prefix}-pgbackups-${data.aws_caller_identity.current.account_id}"

  nodes = {
    "cp-01"     = { type = var.control_plane_type, subnet = 0, tier = "app", role = "control-plane" }
    "worker-01" = { type = var.worker_type, subnet = 0, tier = "app", role = "worker" }
    "worker-02" = { type = var.worker_type, subnet = 1, tier = "app", role = "worker" }
    "worker-03" = { type = var.worker_type, subnet = 0, tier = "app", role = "worker" }
    "data-01"   = { type = var.data_type, subnet = 0, tier = "data", role = "data" }
    "data-02"   = { type = var.data_type, subnet = 1, tier = "data", role = "data" }
  }

  control_plane_names = [for name, node in local.nodes : name if node.role == "control-plane"]
  worker_names        = [for name, node in local.nodes : name if node.role == "worker"]
}
