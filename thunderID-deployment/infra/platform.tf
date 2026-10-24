resource "aws_kms_key" "main" {
  description             = "ThunderID EBS, backups and Vault auto-unseal"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.main.key_id
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.name_prefix}-node"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

# SSM gives shell access without public IPs or an SSH bastion.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# EBS CSI runs with the node role on kubeadm (no IRSA/EKS).
resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

data "aws_iam_policy_document" "node_extra" {
  statement {
    sid = "Kms"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]
    resources = [aws_kms_key.main.arn]
  }

  statement {
    sid       = "BackupBucket"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.backups.arn]
  }

  statement {
    sid = "BackupObjects"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:GetObjectLegalHold",
      "s3:GetObjectRetention",
      "s3:PutObject",
      "s3:PutObjectLegalHold",
      "s3:PutObjectRetention",
    ]
    resources = ["${aws_s3_bucket.backups.arn}/*"]
  }
}

resource "aws_iam_role_policy" "node_extra" {
  name   = "${var.name_prefix}-node-extra"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.node_extra.json
}

resource "aws_iam_instance_profile" "node" {
  name = "${var.name_prefix}-node"
  role = aws_iam_role.node.name
}

resource "aws_s3_bucket" "backups" {
  bucket              = local.backup_bucket
  object_lock_enabled = true

  tags = { Name = local.backup_bucket }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

data "aws_iam_policy_document" "backups" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.backups.arn, "${aws_s3_bucket.backups.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id
  policy = data.aws_iam_policy_document.backups.json

  depends_on = [aws_s3_bucket_public_access_block.backups]
}
