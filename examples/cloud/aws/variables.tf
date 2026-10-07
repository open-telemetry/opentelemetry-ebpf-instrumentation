# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Prefix for resources; use a different name for parallel environments."
  type        = string
  default     = "obi-cloud"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.name))
    error_message = "Use 3 to 24 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "instance_type" {
  description = "Small x86_64 instance type for both nodes."
  type        = string
  default     = "t3.micro"
}

variable "use_spot" {
  description = "Use interruptible Spot instances to reduce compute cost."
  type        = bool
  default     = true
}

variable "obi_version" {
  description = "OBI release tag, ignored when obi_binary_path is set."
  type        = string
  default     = "v0.14.0"
  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9.-]+)?$", var.obi_version))
    error_message = "Use a release tag such as v0.14.0."
  }
}

variable "obi_binary_path" {
  description = "Optional local Linux amd64 OBI executable; Terraform uploads it to private S3."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.obi_binary_path == null ? true : fileexists(pathexpand(var.obi_binary_path))
    error_message = "obi_binary_path must point to an existing executable file."
  }
}

variable "obi_config_path" {
  description = "Optional OBI YAML file, replacing the default Config v2 document."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.obi_config_path == null ? true : fileexists(pathexpand(var.obi_config_path))
    error_message = "obi_config_path must point to an existing YAML file."
  }
}

variable "obi_environment" {
  description = "Environment supplied to OBI, including OTEL_EXPORTER_OTLP_HEADERS. Stored in Terraform state and encrypted private S3, never EC2 user data."
  type        = map(string)
  default     = {}
  sensitive   = true
  validation {
    condition     = alltrue([for key, value in var.obi_environment : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", key)) && !strcontains(value, "\u0000")])
    error_message = "Environment keys must be valid variable names and values must not contain NUL bytes."
  }
}
