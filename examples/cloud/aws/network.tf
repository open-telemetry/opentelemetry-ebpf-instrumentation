# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_subnet" "demo" {
  vpc_id            = aws_vpc.demo.id
  cidr_block        = "10.42.0.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id
}

resource "aws_route_table" "demo" {
  vpc_id = aws_vpc.demo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }
}

resource "aws_route_table_association" "demo" {
  subnet_id      = aws_subnet.demo.id
  route_table_id = aws_route_table.demo.id
}

resource "aws_security_group" "demo" {
  for_each    = local.services
  name_prefix = "${var.name}-${each.key}-"
  description = "${each.key}: private application traffic; management through SSM"
  vpc_id      = aws_vpc.demo.id
}

resource "aws_vpc_security_group_ingress_rule" "backend" {
  security_group_id            = aws_security_group.demo["backend"].id
  referenced_security_group_id = aws_security_group.demo["frontend"].id
  ip_protocol                  = "tcp"
  from_port                    = 8081
  to_port                      = 8081
}

resource "aws_vpc_security_group_egress_rule" "demo" {
  for_each          = local.services
  security_group_id = aws_security_group.demo[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_route53_zone" "demo" {
  name = "${var.name}.internal"
  vpc {
    vpc_id = aws_vpc.demo.id
  }
}

resource "aws_route53_record" "demo" {
  for_each = local.services
  zone_id  = aws_route53_zone.demo.zone_id
  name     = "${each.key}.${aws_route53_zone.demo.name}"
  type     = "A"
  ttl      = 10
  records  = [aws_instance.demo[each.key].private_ip]
}
