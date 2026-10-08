# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  services = {
    frontend = 8080
    backend  = 8081
  }
  config_path = var.obi_config_path == null ? "${path.module}/../obi.yaml" : pathexpand(var.obi_config_path)
  binary_path = var.obi_binary_path == null ? null : pathexpand(var.obi_binary_path)
}

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name}-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "artifacts_tls" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls.json
}

resource "aws_s3_object" "app" {
  for_each               = local.services
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "apps/${each.key}.go"
  source                 = "${path.module}/../../http-header-enrichment-demo/app/cmd/${each.key}/main.go"
  source_hash            = filesha256("${path.module}/../../http-header-enrichment-demo/app/cmd/${each.key}/main.go")
  server_side_encryption = "AES256"
}

resource "aws_s3_object" "config" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "obi/config.yaml"
  source                 = local.config_path
  source_hash            = filesha256(local.config_path)
  server_side_encryption = "AES256"
}

resource "aws_s3_object" "environment" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "obi/environment.json"
  content                = jsonencode(var.obi_environment)
  server_side_encryption = "AES256"
}

resource "aws_s3_object" "binary" {
  count                  = local.binary_path == null ? 0 : 1
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "obi/obi"
  source                 = local.binary_path
  source_hash            = filesha256(local.binary_path)
  server_side_encryption = "AES256"
}
