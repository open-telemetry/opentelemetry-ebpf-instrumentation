# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["eu-west-1a"] }
  }
  mock_data "aws_ec2_instance_type" {
    defaults = { supported_architectures = ["x86_64"] }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      id  = "obi-test-artifacts"
      arn = "arn:aws:s3:::obi-test-artifacts"
    }
  }
  mock_resource "aws_instance" {
    defaults = { private_ip = "10.42.0.10" }
  }
  mock_resource "aws_ssm_document" {
    defaults = { latest_version = "1" }
  }
}

run "default_deployment" {
  command = apply

  assert {
    condition     = length(aws_instance.demo) == 2 && length(aws_route53_record.demo) == 2
    error_message = "Deploy a frontend and a backend, both registered in Route53."
  }
  assert {
    condition     = strcontains(aws_instance.demo["frontend"].user_data, "BACKEND_URL=http://backend.obi-cloud.internal:8081")
    error_message = "The frontend must use the private Route53 backend name."
  }
  assert {
    condition     = alltrue([for instance in aws_instance.demo : instance.instance_type == "t3.micro" && instance.root_block_device[0].volume_size == 8 && instance.credit_specification[0].cpu_credits == "standard" && instance.instance_market_options[0].market_type == "spot"])
    error_message = "Default nodes must use small Spot instances without surplus CPU credit charges."
  }
  assert {
    condition     = alltrue([for instance in aws_instance.demo : strcontains(instance.user_data, "systemctl enable --now obi demo") && strcontains(instance.user_data, "sha256sum --check archive.sha256")])
    error_message = "Every node must automatically install and start OBI and its application."
  }
  assert {
    condition     = length(aws_s3_object.binary) == 0 && alltrue([for association in aws_ssm_association.ready : association.wait_for_success_timeout_seconds == 1200])
    error_message = "Release deployments must wait for startup without requiring a local binary."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.backend.from_port == 8081 && aws_vpc_security_group_ingress_rule.backend.referenced_security_group_id == aws_security_group.demo["frontend"].id
    error_message = "Only the frontend security group may reach the backend application port."
  }
}

run "development_overrides" {
  command = apply
  variables {
    use_spot        = false
    obi_version     = "v0.13.0"
    obi_config_path = "../obi-otlp.yaml"
    # Only the upload path is tested; no executable runs with this mock provider.
    obi_binary_path = "templates/obi-run.py"
    obi_environment = {
      OTEL_EXPORTER_OTLP_ENDPOINT = "https://collector.example:4317"
      OTEL_EXPORTER_OTLP_HEADERS  = "Authorization=Basic test-secret"
      TEST_VALUE                  = "quotes\" and newline\nwith $shell characters"
    }
  }

  assert {
    condition     = length(aws_s3_object.binary) == 1 && aws_s3_object.binary[0].source_hash == filesha256("templates/obi-run.py")
    error_message = "Terraform must upload and track the local binary contents."
  }
  assert {
    condition     = aws_s3_object.config.source_hash == filesha256("../obi-otlp.yaml")
    error_message = "The override must replace the entire OBI configuration."
  }
  assert {
    condition     = alltrue([for instance in aws_instance.demo : strcontains(instance.user_data, "s3://obi-test-artifacts/obi/obi") && !strcontains(instance.user_data, "releases/download") && !strcontains(instance.user_data, "test-secret") && length(instance.instance_market_options) == 0])
    error_message = "Local builds must skip release downloads and secrets must stay outside user data."
  }
  assert {
    condition     = tomap(jsondecode(aws_s3_object.environment.content)) == var.obi_environment
    error_message = "Environment overrides must preserve their exact values."
  }
}

run "return_to_release" {
  command = apply
  assert {
    condition     = length(aws_s3_object.binary) == 0 && alltrue([for instance in aws_instance.demo : strcontains(instance.user_data, "releases/download/v0.14.0")])
    error_message = "Removing the local binary override must restore release installation on both nodes."
  }
}

run "reject_arm_instances" {
  command = plan
  override_data {
    target = data.aws_ec2_instance_type.demo
    values = { supported_architectures = ["arm64"] }
  }
  variables {
    instance_type = "t4g.micro"
  }
  expect_failures = [aws_instance.demo["frontend"], aws_instance.demo["backend"]]
}

run "release_build_metadata" {
  command = plan
  variables {
    obi_version = "v0.14.0+build.123"
  }
  assert {
    condition     = alltrue([for instance in aws_instance.demo : strcontains(instance.user_data, "releases/download/v0.14.0+build.123") && strcontains(instance.user_data, "obi-v0.14.0+build.123-linux-amd64.tar.gz")])
    error_message = "Build metadata must be preserved in the release URL and archive name."
  }
}

run "prerelease_build_metadata" {
  command = plan
  variables {
    obi_version = "v0.14.0-rc.1+build.123"
  }
  assert {
    condition     = alltrue([for instance in aws_instance.demo : strcontains(instance.user_data, "releases/download/v0.14.0-rc.1+build.123") && strcontains(instance.user_data, "obi-v0.14.0-rc.1+build.123-linux-amd64.tar.gz")])
    error_message = "Prerelease tags may also include build metadata."
  }
}

run "reject_empty_build_metadata" {
  command = plan
  variables {
    obi_version = "v0.14.0+"
  }
  expect_failures = [var.obi_version]
}

run "reject_service_name_override" {
  command = plan
  variables {
    obi_environment = {
      CLOUD_SERVICE_NAME = "shared-service"
    }
  }
  expect_failures = [var.obi_environment]
}
