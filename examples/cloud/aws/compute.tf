# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
}

data "aws_ec2_instance_type" "demo" {
  instance_type = var.instance_type
}

resource "aws_instance" "demo" {
  for_each                    = local.services
  ami                         = nonsensitive(data.aws_ssm_parameter.ami.value)
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.demo.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.demo[each.key].id]
  iam_instance_profile        = aws_iam_instance_profile.demo.name
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/user-data.sh.tftpl", {
    region       = var.region
    bucket       = aws_s3_bucket.artifacts.id
    service      = each.key
    port         = each.value
    backend_host = "backend.${aws_route53_zone.demo.name}"
    obi_version  = var.obi_version
    local_binary = local.binary_path != null
    binary_hash  = local.binary_path == null ? "" : filesha256(local.binary_path)
    runner       = filebase64("${path.module}/templates/obi-run.py")
  })

  dynamic "instance_market_options" {
    for_each = var.use_spot ? [true] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type             = "one-time"
        instance_interruption_behavior = "terminate"
      }
    }
  }

  dynamic "credit_specification" {
    for_each = can(regex("^t[23][a-z]?\\.", var.instance_type)) ? [true] : []
    content {
      cpu_credits = "standard"
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "${var.name}-${each.key}" }

  lifecycle {
    precondition {
      condition     = contains(data.aws_ec2_instance_type.demo.supported_architectures, "x86_64")
      error_message = "The AMI and OBI binary require an x86_64 instance type."
    }
    replace_triggered_by = [aws_s3_object.app, aws_s3_object.config, aws_s3_object.environment]
  }

  depends_on = [
    aws_route_table_association.demo,
    aws_vpc_security_group_egress_rule.demo,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.read_artifacts,
    aws_s3_bucket_public_access_block.artifacts,
    aws_s3_bucket_policy.artifacts,
    aws_s3_object.app,
    aws_s3_object.config,
    aws_s3_object.environment,
    aws_s3_object.binary,
  ]
}

resource "aws_ssm_document" "ready" {
  name            = "${var.name}-ready"
  document_type   = "Command"
  document_format = "JSON"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Wait for cloud-init, OBI and the example applications"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "ready"
      inputs = {
        timeoutSeconds = "1200"
        runCommand = [
          "set -eu",
          "cloud-init status --wait",
          "systemctl is-active --quiet obi",
          "systemctl is-active --quiet demo",
          "test -e /sys/kernel/btf/vmlinux",
          "if test -f /etc/systemd/system/demo-traffic.timer; then curl --fail --silent --show-error --retry 60 --retry-all-errors --retry-delay 5 http://localhost:8080/checkout; else curl --fail --silent --show-error http://localhost:8081/healthz; fi",
          "systemctl is-active --quiet obi",
        ]
      }
    }]
  })
}

resource "aws_ssm_association" "ready" {
  for_each                         = local.services
  name                             = aws_ssm_document.ready.name
  association_name                 = "${var.name}-${each.key}-ready"
  wait_for_success_timeout_seconds = 1200
  document_version                 = aws_ssm_document.ready.latest_version
  targets {
    key    = "InstanceIds"
    values = [aws_instance.demo[each.key].id]
  }
  depends_on = [aws_route53_record.demo, aws_vpc_security_group_ingress_rule.backend]
}
