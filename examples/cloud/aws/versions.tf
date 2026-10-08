# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project = var.name
      Purpose = "obi-local-tests"
    }
  }
}
