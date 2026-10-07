# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

output "instances" {
  description = "Instance IDs for SSM sessions and logs."
  value       = { for name, instance in aws_instance.demo : name => instance.id }
}

output "private_urls" {
  description = "Application URLs inside the VPC, resolved by Route53."
  value       = { for name, port in local.services : name => "http://${aws_route53_record.demo[name].fqdn}:${port}" }
}

output "frontend_tunnel" {
  description = "Forward localhost:8080 to the frontend with the AWS Session Manager plugin."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.demo["frontend"].id} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"8080\"],\"localPortNumber\":[\"8080\"]}'"
}

output "artifacts_bucket" {
  description = "Private temporary artifacts bucket, deleted by terraform destroy."
  value       = aws_s3_bucket.artifacts.id
}
