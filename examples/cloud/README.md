# Cloud test environment

A small environment for testing OpenTelemetry eBPF Instrumentation (OBI) in the
cloud. AWS lives in `aws/`; future providers can have their own directories.

```text
automatic traffic -> frontend EC2 -> backend.<name>.internal -> backend EC2
                          OBI             Route53                 OBI
```

Terraform builds the existing [Go applications](../http-header-enrichment-demo/app/cmd)
on two Amazon Linux 2023 nodes and starts them with OBI. Traffic runs every two
seconds. OBI v0.14.0 writes traces to the journal and exposes Prometheus metrics
on port 9400 by default; no external collector is required.

## Deploy

Install Terraform 1.7+ and configure AWS credentials with permission to manage
EC2, VPC, IAM, S3, Route53 and SSM. From the repository root:

```sh
# Once, to install the Terraform provider.
terraform -chdir=examples/cloud/aws init

# Creates everything and waits for application and OBI startup checks.
terraform -chdir=examples/cloud/aws apply
```

`apply` waits for startup and frontend-to-backend checks. Allow up to 20 minutes;
the first Go compilation can take several minutes on these small nodes. No
application deployment steps are needed afterwards.

Defaults are two `t3.micro` Spot instances, 8 GB encrypted disks, and standard
CPU credits to avoid surplus credit charges. Spot capacity can be unavailable
or interrupted; use `-var='use_spot=false'` for on-demand instances. An interrupted
node is recreated by the next `apply`.

There is no NAT Gateway or load balancer. Public IPv4 addresses allow outbound
downloads and SSM, with no public inbound access. Compute, disks, IPv4, Route53
and S3 still incur charges: destroy the environment after testing.

## Overrides

Pass overrides to the same command:

```sh
terraform -chdir=examples/cloud/aws apply \
  -var='region=eu-west-1' \
  -var='name=obi-my-test' \
  -var='obi_version=v0.14.0' \
  -var='obi_config_path=../obi-otlp.yaml'
```

To test a local build, compile OBI for **Linux amd64**, then pass its path:

```sh
make compile GOOS=linux GOARCH=amd64
terraform -chdir=examples/cloud/aws apply -var="obi_binary_path=$PWD/bin/obi"
```

Terraform uploads the executable to private S3 instead of downloading a release.
`obi_config_path` replaces the whole YAML file. Paths are absolute or relative to
`examples/cloud/aws`. The supplied files use Config v2, requiring OBI v0.11.0+,
and are validated during startup.

Set `obi_environment` for exporter endpoints, secrets and other environment
values. For example, with the supplied `obi-otlp.yaml` and a gRPC collector:

```sh
export TF_VAR_obi_environment='{
  "OTEL_EXPORTER_OTLP_ENDPOINT": "https://your-collector:4317",
  "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Basic ..."
}'
terraform -chdir=examples/cloud/aws apply -var='obi_config_path=../obi-otlp.yaml'
```

For plain HTTP, also set `OTLP_INSECURE` to `"true"`. Config v2 references variables
explicitly in YAML; a legacy `OTEL_EBPF_*` variable alone does not override a v2
field. `CLOUD_SERVICE_NAME` is the node's role; the config path is deployment-managed.

Alternatively, copy `aws/terraform.tfvars.example` to `aws/terraform.tfvars`.
Keep the same overrides on subsequent `apply` and `destroy` commands.
Changes to the binary, configuration, environment or application source replace
the nodes automatically.

Secrets reach OBI through root-only files, not EC2 user data. They **are stored in
Terraform state and encrypted S3**: protect state and saved plans, and keep
credentials out of version control.

## Try it and clean up

In the AWS console, open **EC2 → Instances** in the account used for `apply` and
the configured region (`eu-west-1`, Ireland, by default). The nodes are named
`<name>-frontend` and `<name>-backend`, or `obi-cloud-frontend` and
`obi-cloud-backend` with the defaults. They are standalone EC2 instances.

For a browser shell, select an instance, then **Connect → Session Manager → Connect**.
Direct SSH is not configured: no SSH key or inbound port 22 is provisioned.

For local access, install the AWS CLI and
[Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html).
Run the command printed by:

```sh
terraform -chdir=examples/cloud/aws output -raw frontend_tunnel
```

In another terminal, `curl http://localhost:8080/checkout` returns the backend
inventory. Both services also expose `/healthz`.

Get instance IDs with `terraform -chdir=examples/cloud/aws output instances`:

```sh
aws ssm start-session --region eu-west-1 --target <instance-id>
# Inside the session:
sudo journalctl -u obi -f
```

Forward port 9400 instead of 8080 to inspect `/metrics`.

If `aws_ssm_association.ready` reports `Failed`, inspect the underlying startup
error through Session Manager:

```sh
sudo cloud-init status --long
sudo tail -n 80 /var/log/cloud-init-output.log
sudo journalctl -u obi -u demo --no-pager -n 50
```

In the AWS console, the check's output is also available under **Systems Manager
→ State Manager → the `<name>-frontend-ready` or `<name>-backend-ready` association
→ Execution history**.

```sh
terraform -chdir=examples/cloud/aws destroy
```

This also deletes the artifacts bucket. Local Terraform state is not removed.

## Validate without deploying

```sh
terraform -chdir=examples/cloud/aws fmt -check -recursive
terraform -chdir=examples/cloud/aws validate
terraform -chdir=examples/cloud/aws test
python3 examples/cloud/aws/tests/test_bootstrap.py
```

Terraform tests use a mocked AWS provider and create no cloud resources. The
bootstrap test requires Go and compiles both applications without `HOME`, as
cloud-init does.
