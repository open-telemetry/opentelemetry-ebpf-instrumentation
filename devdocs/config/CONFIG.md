# OBI Configuration Reference

Complete configuration reference for OpenTelemetry eBPF Instrumentation (OBI).
Configuration is provided via YAML file and/or environment variables.

Generated from [`config-schema.json`](config-schema.json).

---

## Table of Contents

- [Top-Level Properties](#top-level-properties)
- [`attributes`](#attributes)
- [`discovery`](#discovery)
- [`ebpf`](#ebpf)
- [`filter`](#filter)
- [`internal_metrics`](#internal-metrics)
- [`javaagent`](#javaagent)
- [`metrics`](#metrics)
- [`name_resolver`](#name-resolver)
- [`network`](#network)
- [`nodejs`](#nodejs)
- [`otel_metrics_export`](#otel-metrics-export)
- [`otel_traces_export`](#otel-traces-export)
- [`prometheus_export`](#prometheus-export)
- [`routes`](#routes)
- [`stats`](#stats)
- [Type Definitions](#type-definitions)

---

## Top-Level Properties

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
|  | `glob` | `OTEL_EBPF_AUTO_TARGET_EXE` |  | `app-*`, `service-??`, `prod-*-db`, etc |  | Selects the executable to instrument matching a Glob against the executable path. To set this value via YAML, use discovery > instrument. It also accepts OTEL_GO_AUTO_TARGET_EXE for compatibility with opentelemetry-go-instrumentation |
|  | `glob` | `OTEL_EBPF_AUTO_TARGET_LANGUAGE` |  | `app-*`, `service-??`, `prod-*-db`, etc |  | Selects the executable to instrument matching a Glob of chosen languages. To set this value via YAML, use discovery > instrument. |
| `channel_buffer_len` | `integer` | `OTEL_EBPF_CHANNEL_BUFFER_LEN` | `50` |  |  |  |
| `channel_send_timeout` | `duration` | `OTEL_EBPF_CHANNEL_SEND_TIMEOUT` | `1m` | `30s`, `5m`, `1ms`, etc |  |  |
| `channel_send_timeout_panic` | `boolean` | `OTEL_EBPF_CHANNEL_SEND_TIMEOUT_PANIC` | `false` |  |  |  |
| `enforce_sys_caps` | `boolean` | `OTEL_EBPF_ENFORCE_SYS_CAPS` | `false` |  |  | Check for required system capabilities and bail if they are not present. If set to 'false', OBI will still print a list of missing capabilities, but the execution will continue |
| `executable_path` | `regex` | `OTEL_EBPF_EXECUTABLE_PATH` |  | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Yes | Allows selecting the instrumented executable whose complete path contains the Exec value.  Use OTEL_EBPF_AUTO_TARGET_EXE |
| `log_config` | `string` | `OTEL_EBPF_LOG_CONFIG` |  | `json`, `yaml` |  | Enables the logging of the configuration on startup. |
| `log_format` | `string` | `OTEL_EBPF_LOG_FORMAT` | `text` | `json`, `text` |  |  |
| `log_level` | `string` | `OTEL_EBPF_LOG_LEVEL` | `INFO` | `DEBUG`, `ERROR`, `INFO`, `WARN` |  |  |
| `open_port` | [`IntEnum`](#intenum) | `OTEL_EBPF_OPEN_PORT` |  |  |  | Allows selecting the instrumented executable that owns the Port value. If this value is set (and different to zero), the value of the Exec property won't take effect. It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter will instrument all the service calls in all the ports, not only the port specified here. |
| `profile_port` | `integer` | `OTEL_EBPF_PROFILE_PORT` | `0` |  |  |  |
| `service_name` | `string` | `OTEL_SERVICE_NAME` |  |  | Yes | Specifies the name of the instrumented service, taken from either OTEL_EBPF_SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility). Using env and envDefault is a trick to get the value either from one of either variables.  Service name should be set in the instrumentation target (env vars, kube metadata...) as this is a reminiscence of past times when we only supported one executable per instance. |
| `service_namespace` | `string` | `OTEL_EBPF_SERVICE_NAMESPACE` |  |  | Yes | Service namespace should be set in the instrumentation target (env vars, kube metadata...) as this is a reminiscence of past times when we only supported one executable per instance. |
| `shutdown_timeout` | `duration` | `OTEL_EBPF_SHUTDOWN_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  | Timeout for a graceful shutdown |
| `target_pids` | [`IntEnum`](#intenum) | `OTEL_EBPF_TARGET_PID` |  |  |  | Selects processes by PID for instrumentation. When non-empty, only these PIDs are instrumented. Accepts YAML list (target_pids: [1234, 5678]), single number, or env OTEL_EBPF_TARGET_PID=1234,5678. Alternative to Exec or AutoTargetExe when PIDs are known. |
| `trace_printer` | `string` | `OTEL_EBPF_TRACE_PRINTER` | `disabled` | `counter`, `disabled`, `json`, `json_indent`, `text` |  |  |

## `attributes`

Attributes configures the decoration of some extra attributes that will be added to each span

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.extra_group_attributes` | [`ExtraGroupAttributesMap`](#extragroupattributesmap) |  |  |  |  | Map of attribute group names to arrays of attribute names. Only 'k8s_app_meta' is currently supported as a key. |
| `attributes.metric_span_names_limit` | `integer` | `OTEL_EBPF_METRIC_SPAN_NAMES_LIMIT` | `100` |  |  | Works PER SERVICE and only relates to span_metrics. When the span_name cardinality surpasses this limit, the span_name will be reported as AGGREGATED. If the value <= 0, it is disabled. |
| `attributes.rename_unresolved_hosts` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS` | `unresolved` |  |  | Will replace HostName and PeerName attributes when they are empty or contain unresolved IP addresses to reduce cardinality. Set this value to the empty string to disable this feature. |
| `attributes.rename_unresolved_hosts_incoming` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_INCOMING` | `incoming` |  |  |  |
| `attributes.rename_unresolved_hosts_outgoing` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_OUTGOING` | `outgoing` |  |  |  |
| `attributes.select` | `map[string]object` |  |  |  |  | Selection specifies which attributes are allowed for each metric. The key is the metric name (either in Prometheus or OpenTelemetry format) The value is the enumeration of included/excluded attribute globs |

### `attributes.host_id`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.host_id.override` | `string` | `OTEL_EBPF_HOST_ID` |  |  |  | Allows overriding the reported host.id in OBI |

### `attributes.instance_id`

InstanceIDConfig configures how OBI will get the Instance ID of the traces/metrics from the current hostname + the instrumented process PID

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.instance_id.dns` | `boolean` | `OTEL_EBPF_HOSTNAME_DNS_RESOLUTION` | `true` |  |  | Controls whether OBI uses the DNS to resolve the local hostname. If false, the local hostname is used as-is. |
| `attributes.instance_id.override_hostname` | `string` | `OTEL_EBPF_HOSTNAME` |  |  |  | Can be optionally set to avoid resolving any hostname and using this value. OBI will anyway attach the process ID to the given hostname for composing the instance ID. |

### `attributes.kubernetes`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.kubernetes.cluster_name` | `string` | `OTEL_EBPF_KUBE_CLUSTER_NAME` |  |  |  | Overrides cluster name. If empty, the NetO11y module will try to retrieve it from the Cloud Provider Metadata (EC2, GCP and Azure), and leave it empty if it fails to. |
| `attributes.kubernetes.disable_informers` | `string`[] | `OTEL_EBPF_KUBE_DISABLE_INFORMERS` |  |  |  | Allows selectively disabling some informers. Accepted value is a list that might contain node or service. Disabling any of them will cause metadata to be incomplete but will reduce the load of the Kube API. Pods informer can't be disabled. For that purpose, you should disable the whole kubernetes metadata decoration. |
| `attributes.kubernetes.drop_external` | `boolean` | `OTEL_EBPF_NETWORK_DROP_EXTERNAL` | `false` |  |  | Will drop, in NetO11y component, any flow where the source or destination IPs are not matched to any kubernetes entity, assuming they are cluster-external |
| `attributes.kubernetes.enable` | `string` | `OTEL_EBPF_KUBE_METADATA_ENABLE` | `autodetect` | `autodetect`, `false`, `true` |  |  |
| `attributes.kubernetes.informers_resync_period` | `duration` | `OTEL_EBPF_KUBE_INFORMERS_RESYNC_PERIOD` | `30m` | `30s`, `5m`, `1ms`, etc |  | Defaults to 30m. Higher values will reduce the load on the Kube API. |
| `attributes.kubernetes.informers_sync_timeout` | `duration` | `OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT` | `30s` | `30s`, `5m`, `1ms`, etc |  | Specifies the timeout for waiting for informers to sync on startup. |
| `attributes.kubernetes.kubeconfig_path` | `string` | `KUBECONFIG` |  |  |  | Specifies the path to the kubeconfig file. If unset, it will look in the usual location. |
| `attributes.kubernetes.meta_cache_address` | `string` | `OTEL_EBPF_KUBE_META_CACHE_ADDRESS` |  |  |  | Specifies the host:port address of the obi-k8s-cache service instance |
| `attributes.kubernetes.meta_restrict_local_node` | `boolean` | `OTEL_EBPF_KUBE_META_RESTRICT_LOCAL_NODE` | `false` |  |  | Will download only the metadata from the Pods that are located in the same node as the OBI instance. It will also restrict the Node information to the local node. |
| `attributes.kubernetes.reconnect_initial_interval` | `duration` | `OTEL_EBPF_KUBE_RECONNECT_INITIAL_INTERVAL` | `5s` | `30s`, `5m`, `1ms`, etc |  | Specifies the time to wait before reconnecting to the Kubernetes API after a connection loss. |
| `attributes.kubernetes.resource_labels` | `map[string]string[]` |  |  |  |  | Allows OBI overriding the OTEL Resource attributes from a map of user-defined labels. |
| `attributes.kubernetes.service_name_template` | `string` | `OTEL_EBPF_SERVICE_NAME_TEMPLATE` |  |  |  | Allows to override the service.name with a custom value. Uses the go template language. |

#### `attributes.kubernetes.meta_source_labels`

MetaSourceLabels allow overriding some metadata from kubernetes labels, Left for backwards-compatibility.

**Deprecated.**

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.kubernetes.meta_source_labels.service_name` | `string` | `OTEL_SERVICE_NAME` |  |  |  |  |
| `attributes.kubernetes.meta_source_labels.service_namespace` | `string` | `OTEL_EBPF_SERVICE_NAMESPACE` |  |  |  |  |

### `attributes.metadata_retry`

RetryConfig holds the retry policy for metadata fetch operations. It controls the exponential backoff used in physical node, cloud instance or local virtual machine.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.metadata_retry.max_interval` | `duration` | `OTEL_EBPF_METADATA_RETRY_MAX_INTERVAL` | `5s` | `30s`, `5m`, `1ms`, etc |  | Specifies the upper bound on the wait duration between consecutive retry attempts. |
| `attributes.metadata_retry.start_interval` | `duration` | `OTEL_EBPF_METADATA_RETRY_START_INTERVAL` | `500ms` | `30s`, `5m`, `1ms`, etc |  | Specifies the initial wait duration between the first and second retry attempt. |
| `attributes.metadata_retry.timeout` | `duration` | `OTEL_EBPF_METADATA_RETRY_TIMEOUT` | `30s` | `30s`, `5m`, `1ms`, etc |  | Specifies the maximum total time allowed for all retry attempts before giving up. |

## `discovery`

DiscoveryConfig for the discover.ProcessFinder pipeline

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `discovery.bpf_pid_filter_off` | `boolean` | `OTEL_EBPF_BPF_PID_FILTER_OFF` | `false` |  |  | Debugging only option. Make sure the kernel side doesn't filter any PIDs, force user space filtering. |
| `discovery.default_exclude_instrument` | [`GlobAttributes`](#globattributes)[] |  | `[{"cmd_args":{},"containers_only":false,"exe_path":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null},{"cmd_args":{},"containers_only":false,"exe_path":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null}]` |  |  | Defines the default exclusion patterns that prevent self-instrumentation of OBI as well as related observability tools. It must be set to an empty string or a different value if self-instrumentation is desired. |
| `discovery.default_exclude_services` | [`RegexSelector`](#regexselector)[] |  | `[{"cmd_args":{},"containers_only":false,"exe_path":{},"exe_path_regexp":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null},{"cmd_args":{},"containers_only":false,"exe_path":{},"exe_path_regexp":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null}]` |  | Yes | Defines the default exclusion patterns that prevent self-instrumentation of OBI as well as related observability tools. It must be set to an empty string or a different value if self-instrumentation is desired.  Use DefaultExcludeInstrument instead |
| `discovery.default_otlp_grpc_port` | `integer` | `OTEL_EBPF_DEFAULT_OTLP_GRPC_PORT` | `4317` |  |  | Specifies the default OTLP gRPC port (4317) to fallback on when missing environment variables on service, for checking for grpc export requests, defaults to 4317 |
| `discovery.disabled_route_harvesters` | `string`[] |  |  | `go`, `java`, `nodejs` |  |  |
| `discovery.exclude_instrument` | [`GlobAttributes`](#globattributes)[] |  |  |  |  | Works analogously to Instrument, but the applications matching this section won't be instrumented even if they match the Instrument selection. |
| `discovery.exclude_otel_instrumented_services` | `boolean` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES` | `true` |  |  | Disables instrumentation of services which are already instrumented |
| `discovery.exclude_otel_instrumented_services_span_metrics` | `boolean` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS` | `false` |  |  | Disables generation of span metrics of services which are already instrumented |
| `discovery.exclude_services` | [`RegexSelector`](#regexselector)[] |  |  |  | Yes | Works analogously to Services, but the applications matching this section won't be instrumented even if they match the Services selection.  Use ExcludeInstrument instead |
| `discovery.excluded_linux_system_paths` | `string`[] |  | `/lib/systemd/`, `/usr/lib/systemd/`, `/usr/libexec/`, `/sbin/`, `/usr/sbin/` |  |  | Executable paths for which we don't run language detection and cannot be selected using the path or language selection criteria |
| `discovery.instrument` | [`GlobAttributes`](#globattributes)[] |  |  |  |  | Selects the services to instrument via Globs. If this section is set, both the Services and ExcludeServices section is ignored. If the user defined the OTEL_EBPF_INSTRUMENT_COMMAND or OTEL_EBPF_INSTRUMENT_PORTS variables, they will be automatically added to the instrument criteria, with the lowest preference. |
| `discovery.min_process_age` | `duration` | `OTEL_EBPF_MIN_PROCESS_AGE` | `5s` | `30s`, `5m`, `1ms`, etc |  | Min process age to be considered for discovery. |
| `discovery.poll_interval` | `duration` | `OTEL_EBPF_DISCOVERY_POLL_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  | Specifies, for the poll service watcher, the interval time between process inspections |
| `discovery.route_harvester_timeout` | `duration` | `OTEL_EBPF_ROUTE_HARVESTER_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `discovery.services` | [`RegexSelector`](#regexselector)[] |  |  |  | Yes | Selection. If the user defined the OTEL_EBPF_EXECUTABLE_PATH or OTEL_EBPF_OPEN_PORT variables, they will be automatically added to the services definition criteria, with the lowest preference.  Use Instrument instead |
| `discovery.skip_go_specific_tracers` | `boolean` | `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS` | `false` |  |  | This can be enabled to use generic HTTP tracers only, no Go-specifics will be used: |

### `discovery.route_harvester_advanced`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `discovery.route_harvester_advanced.java_harvest_delay` | `duration` | `OTEL_EBPF_JAVA_ROUTE_HARVEST_DELAY` | `1m` | `30s`, `5m`, `1ms`, etc |  |  |

## `ebpf`

EBPFTracer configuration for eBPF programs

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.batch_length` | `integer` | `OTEL_EBPF_BPF_BATCH_LENGTH` | `100` |  |  | Allows specifying how many items (traces/metrics) will be batched at the initial stage before being forwarded to the next stage Must be at least 1 |
| `ebpf.batch_timeout` | `duration` | `OTEL_EBPF_BPF_BATCH_TIMEOUT` | `1s` | `30s`, `5m`, `1ms`, etc |  | Specifies the timeout to forward the data batch if it didn't reach the BatchLength size |
| `ebpf.bpf_debug` | `boolean` | `OTEL_EBPF_BPF_DEBUG` | `false` |  |  | Enables logging of eBPF program events |
| `ebpf.bpf_fs_path` | `string` | `OTEL_EBPF_BPF_FS_PATH` | `/sys/fs/bpf/` |  |  | BPF path used to pin eBPF maps |
| `ebpf.context_propagation` | `string` | `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` | `disabled` | ``, `all`, `disabled` |  | Enables distributed context propagation. Can be a combination of: headers, tcp (e.g., "headers,tcp" or "all") |
| `ebpf.couchbase_db_cache_size` | `integer` | `OTEL_EBPF_COUCHBASE_DB_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.disable_black_box_cp` | `boolean` | `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP` | `false` |  |  | Disables OBI black-box context propagation. Used for testing purposes only. |
| `ebpf.dns_request_timeout` | `duration` | `OTEL_EBPF_BPF_DNS_REQUEST_TIMEOUT` | `5s` | `30s`, `5m`, `1ms`, etc |  | DNS timeout after which we report failed event |
| `ebpf.force_bpf_map_reader` | `string` | `OTEL_EBPF_FORCE_BPF_MAP_READER` | `auto` | `auto`, `batch`, `legacy` |  | Forces the PerCPU HashMap operation of the Network Flows reader. The system will always try "batch", which is more efficient, but legacy systems like RHEL8-based will fallback to "legacy" (the slowest, more resource-consuming iterate&delete approach). |
| `ebpf.heuristic_sql_detect` | `boolean` | `OTEL_EBPF_HEURISTIC_SQL_DETECT` | `false` |  |  | Enables the heuristic based detection of SQL requests. This can be used to detect talking to databases other than the ones we recognize in OBI, like Postgres and MySQL |
| `ebpf.high_request_volume` | `boolean` | `OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME` | `false` |  |  | Optimizes for getting requests information immediately when request response is seen |
| `ebpf.http_request_timeout` | `duration` | `OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT` | `0s` | `30s`, `5m`, `1ms`, etc |  | Must be at least 0 |
| `ebpf.instrument_cuda` | `integer` | `OTEL_EBPF_INSTRUMENT_CUDA` | `auto` |  |  | Enables GPU instrumentation for CUDA kernel launches and allocations |
| `ebpf.kafka_topic_uuid_cache_size` | `integer` | `OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE` | `1024` |  |  | Kafka Topic UUID to Name cache size. |
| `ebpf.max_transaction_time` | `duration` | `OTEL_EBPF_BPF_MAX_TRANSACTION_TIME` | `5m` | `30s`, `5m`, `1ms`, etc |  | Maximum time allowed for two requests to be correlated as parent -> child Some programs (e.g. load generators) keep on generating requests from the same thread in perpetuity, which can generate very large traces. We want to mark the parent trace as invalid if this happens. |
| `ebpf.mongo_requests_cache_size` | `integer` | `OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE` | `1024` |  |  | MongoDB requests cache size. |
| `ebpf.mysql_prepared_statements_cache_size` | `integer` | `OTEL_EBPF_BPF_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE` | `1024` |  |  | MySQL prepared statements cache size. |
| `ebpf.override_bpfloop_enabled` | `boolean` | `OTEL_EBPF_OVERRIDE_BPF_LOOP_ENABLED` | `false` |  |  | Skips checking the kernel version for bpf_loop functionality. Some modified kernels have this backported prior to version 5.17. |
| `ebpf.postgres_prepared_statements_cache_size` | `integer` | `OTEL_EBPF_BPF_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE` | `1024` |  |  | Postgres prepared statements cache size. |
| `ebpf.protocol_debug_print` | `boolean` | `OTEL_EBPF_PROTOCOL_DEBUG_PRINT` | `false` |  |  | Enables debug printing of the protocol data |
| `ebpf.track_request_headers` | `boolean` | `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS` | `false` |  |  | Enables the kprobes based HTTP request tracking to start tracking the request headers to process any 'Traceparent' fields. |
| `ebpf.traffic_control_backend` | `string` | `OTEL_EBPF_BPF_TC_BACKEND` | `auto` | `auto`, `tc`, `tcx` |  | Select the TC attachment backend: accepted values are 'tc' (netlink), and 'tcx' |
| `ebpf.wakeup_len` | `integer` | `OTEL_EBPF_BPF_WAKEUP_LEN` | `500` |  |  | Specifies how many messages need to be accumulated in the eBPF ringbuffer before sending a wakeup request. High values of WakeupLen could add a noticeable metric delay in services with low requests/second. Must be at least 0 TODO: see if there is a way to force eBPF to wakeup userspace on timeout |

### `ebpf.buffer_sizes`

Per-protocol maximum bytes to capture per request per direction, sent to userspace via large buffer events. Values must stay aligned with MaxCapturedPayloadBytes and the k_large_buf_max_*_captured_bytes constants in bpf/common/large_buffers.h.  Default: 0 (disabled).

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.buffer_sizes.http` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_HTTP` | `0` |  |  |  |
| `ebpf.buffer_sizes.kafka` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA` | `0` |  |  |  |
| `ebpf.buffer_sizes.mysql` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL` | `0` |  |  |  |
| `ebpf.buffer_sizes.postgres` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES` | `0` |  |  |  |

### `ebpf.log_enricher`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.log_enricher.async_writer_channel_len` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_CHANNEL_LEN` | `500` |  |  | Defines the capacity of every shard's channel for the async log writer Default: 500 |
| `ebpf.log_enricher.async_writer_workers` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_WORKERS` | `8` |  |  | Defines the number of shards for the async log writer Default: 8 |
| `ebpf.log_enricher.cache_size` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_SIZE` | `128` |  |  | Defines the maximum number of cached file descriptors Default: 128 |
| `ebpf.log_enricher.cache_ttl` | `duration` | `OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_TTL` | `30m` | `30s`, `5m`, `1ms`, etc |  | Defines the TTL for cached file descriptors Default: 30m |
| `ebpf.log_enricher.services` | [`LogEnricherServiceConfig`](#logenricherserviceconfig)[] |  |  |  |  | Specifies the services to enable log enrichment for |

### `ebpf.maps_config`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.maps_config.global_scale_factor` | `integer` |  | `0` |  |  | Scales map sizes in powers of two:   > 0: grows size (2x per step)   < 0: shrinks size (1/2 per step)   = 0: no change |

### `ebpf.payload_extraction`

#### `ebpf.payload_extraction.http`

#### `ebpf.payload_extraction.http.aws`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.aws.enabled` | `boolean` | `OTEL_EBPF_HTTP_AWS_ENABLED` | `false` |  |  | Enable AWS services (S3, SQS, etc.) payload extraction and parsing |

#### `ebpf.payload_extraction.http.elasticsearch`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.elasticsearch.enabled` | `boolean` | `OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED` | `false` |  |  | Enable Elasticsearch payload extraction and parsing |

#### `ebpf.payload_extraction.http.enrichment`

EnrichmentConfig configures HTTP header and payload extraction with policy-based rules.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.enrichment.enabled` | `boolean` | `OTEL_EBPF_HTTP_ENRICHMENT_ENABLED` | `false` |  |  | Enable HTTP header and payload enrichment |
| `ebpf.payload_extraction.http.enrichment.rules` | [`HTTPParsingRule`](#httpparsingrule)[] |  |  |  |  | Is an ordered list of include/exclude/obfuscate rules. |

#### `ebpf.payload_extraction.http.enrichment.policy`

HTTPParsingPolicy defines the default action for http enrichment rules.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.enrichment.policy.default_action` | [`HTTPParsingDefaultAction`](#httpparsingdefaultaction) |  |  |  |  | Specifies what to do when no rule matches, per type. |
| `ebpf.payload_extraction.http.enrichment.policy.obfuscation_string` | `string` | `OTEL_EBPF_HTTP_ENRICHMENT_OBFUSCATION_STRING` | `***` |  |  | Is the replacement string used when a rule's action is "obfuscate" |

#### `ebpf.payload_extraction.http.genai`

#### `ebpf.payload_extraction.http.genai.anthropic`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.anthropic.enabled` | `boolean` | `OTEL_EBPF_HTTP_ANTHROPIC_ENABLED` | `false` |  |  | Enable Anthropic payload extraction and parsing |

#### `ebpf.payload_extraction.http.genai.bedrock`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.bedrock.enabled` | `boolean` | `OTEL_EBPF_HTTP_BEDROCK_ENABLED` | `false` |  |  | Enable AWS Bedrock payload extraction and parsing |

#### `ebpf.payload_extraction.http.genai.gemini`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.gemini.enabled` | `boolean` | `OTEL_EBPF_HTTP_GEMINI_ENABLED` | `false` |  |  | Enable Google AI Studio (Gemini) payload extraction and parsing |

#### `ebpf.payload_extraction.http.genai.openai`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.openai.enabled` | `boolean` | `OTEL_EBPF_HTTP_OPENAI_ENABLED` | `false` |  |  | Enable OpenAI payload extraction and parsing |

#### `ebpf.payload_extraction.http.graphql`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.graphql.enabled` | `boolean` | `OTEL_EBPF_HTTP_GRAPHQL_ENABLED` | `false` |  |  | Enable GraphQL payload extraction and parsing |

#### `ebpf.payload_extraction.http.jsonrpc`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.jsonrpc.enabled` | `boolean` | `OTEL_EBPF_HTTP_JSONRPC_ENABLED` | `false` |  |  | Enable JSON-RPC payload extraction and parsing |

#### `ebpf.payload_extraction.http.sqlpp`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.sqlpp.enabled` | `boolean` | `OTEL_EBPF_HTTP_SQLPP_ENABLED` | `false` |  |  | Enable SQL++ payload extraction and parsing |
| `ebpf.payload_extraction.http.sqlpp.endpoint_patterns` | `string`[] | `OTEL_EBPF_HTTP_SQLPP_ENDPOINT_PATTERNS` | `/query/service` |  |  | Specifies URL path patterns to detect SQL++ endpoints Example: ["/query/service", "/query"] |

### `ebpf.redis_db_cache`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.redis_db_cache.enabled` | `boolean` | `OTEL_EBPF_BPF_REDIS_DB_CACHE_ENABLED` | `false` |  |  |  |
| `ebpf.redis_db_cache.max_size` | `integer` | `OTEL_EBPF_BPF_REDIS_DB_CACHE_MAX_SIZE` | `1000` |  |  |  |

## `filter`

AttributesConfig stores the user-provided section for filtering either Application or Network records by attribute values

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `filter.application` | `map[string]object` |  |  |  |  | AttributeFamilyConfig maps, for a given record, each attribute with its MatchDefinition |
| `filter.network` | `map[string]object` |  |  |  |  | AttributeFamilyConfig maps, for a given record, each attribute with its MatchDefinition |
| `filter.stats` | `map[string]object` |  |  |  |  | AttributeFamilyConfig maps, for a given record, each attribute with its MatchDefinition |

## `internal_metrics`

InternalMetricsConfig options for the different metrics exporters

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.bpf_metric_scrape_interval` | `duration` | `OTEL_EBPF_BPF_METRIC_SCRAPE_INTERVAL` | `15s` | `30s`, `5m`, `1ms`, etc |  |  |
| `internal_metrics.exporter` | `string` | `OTEL_EBPF_INTERNAL_METRICS_EXPORTER` | `disabled` | `disabled`, `otel`, `prometheus` |  |  |

### `internal_metrics.prometheus`

TODO: TLS

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.prometheus.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `internal_metrics.prometheus.buckets` | [`Buckets`](#buckets) |  |  |  |  | Buckets defines the histograms bucket boundaries, and allows users to redefine them |
| `internal_metrics.prometheus.disable_build_info` | `boolean` | `OTEL_EBPF_PROMETHEUS_DISABLE_BUILD_INFO` | `false` |  |  |  |
| `internal_metrics.prometheus.exemplar_filter` | `string` | `OTEL_EBPF_PROMETHEUS_EXEMPLAR_FILTER` |  |  |  | Controls when exemplars are attached to metrics. Accepted values: "always_on", "always_off", "trace_based". Defaults to "always_off": do not attach exemplars. This mimics the OTEL_METRICS_EXEMPLAR_FILTER specification. |
| `internal_metrics.prometheus.extra_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to Prometheus metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute, you should add `deployment.environment`. |
| `internal_metrics.prometheus.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to Prometheus span metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute, you should add `deployment.environment`. |
| `internal_metrics.prometheus.features` | `string`[] | `OTEL_EBPF_PROMETHEUS_FEATURES` | `0` | `*`, `all`, `application`, `application_host`, `application_service_graph`, `application_span`, `application_span_otel`, `application_span_sizes`, `ebpf`, `network`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_rtt` | Yes | Features specifies which metric features to export. Accepted values: application, network, application_span, application_service_graph, ...  use top-level MetricsConfig.Features instead. |
| `internal_metrics.prometheus.instrumentations` | `string`[] | `OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS` | `*` | `*`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `redis`, `sql` |  | Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql... |
| `internal_metrics.prometheus.path` | `string` | `OTEL_EBPF_PROMETHEUS_PATH` | `/internal/metrics` |  |  |  |
| `internal_metrics.prometheus.port` | `integer` | `OTEL_EBPF_PROMETHEUS_PORT` | `0` |  |  |  |
| `internal_metrics.prometheus.service_cache_size` | `integer` |  | `10000` |  |  |  |
| `internal_metrics.prometheus.ttl` | `duration` | `OTEL_EBPF_PROMETHEUS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  | Specifies the time since a metric was updated for the last time until it is removed from the metrics set. |

## `javaagent`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `javaagent.attach_timeout` | `duration` | `OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `javaagent.debug` | `boolean` | `OTEL_EBPF_JAVAAGENT_DEBUG` | `false` |  |  |  |
| `javaagent.debug_instrumentation` | `boolean` | `OTEL_EBPF_JAVAAGENT_DEBUG_INSTRUMENTATION` | `false` |  |  |  |
| `javaagent.enabled` | `boolean` | `OTEL_EBPF_JAVAAGENT_ENABLED` | `true` |  |  |  |

## `metrics`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
|  | `integer` | `OTEL_METRIC_EXPORT_INTERVAL` | `60000` |  |  | Supports metric intervals as specified by the standard OTEL definition. OTEL_EBPF_METRICS_INTERVAL takes precedence over it. |
| `metrics.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `metrics.buckets` | [`Buckets`](#buckets) |  |  |  |  | Buckets defines the histograms bucket boundaries, and allows users to redefine them |
| `metrics.endpoint` | `uri` | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` |  |  |  |  |
| `metrics.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to OTEL span metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a OTEL resource attribute, you should add `deployment.environment`. |
| `metrics.features` | `string`[] | `OTEL_EBPF_METRICS_FEATURES` | `32` | `*`, `all`, `application`, `application_host`, `application_service_graph`, `application_span`, `application_span_otel`, `application_span_sizes`, `ebpf`, `network`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_rtt` | Yes | Specifies which metric features to export. Accepted values: application, network, application_span, application_service_graph, ... envDefault is provided to avoid breaking changes  use top-level MetricsConfig.Features instead. |
| `metrics.histogram_aggregation` | `string` | `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` | `explicit_bucket_histogram` | `base2_exponential_bucket_histogram`, `explicit_bucket_histogram` |  |  |
| `metrics.insecure_skip_verify` | `boolean` | `OTEL_EBPF_INSECURE_SKIP_VERIFY` | `false` |  |  | Enables skipping TLS certificate verification (not standard, so we don't follow the same naming convention) |
| `metrics.instrumentations` | `string`[] | `OTEL_EBPF_METRICS_INSTRUMENTATIONS` | `*` | `*`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `redis`, `sql` |  | Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql... |
| `metrics.interval` | `duration` | `OTEL_EBPF_METRICS_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `metrics.otel_sdk_log_level` | `string` | `OTEL_EBPF_SDK_LOG_LEVEL` |  |  |  | Works independently from the global LogLevel because it prints GBs of logs in Debug mode and the Info messages leak internal details that are not usually valuable for the final user. Accepted values: debug, info, warn, error (case-insensitive). |
| `metrics.protocol` | `string` | `OTEL_EXPORTER_OTLP_PROTOCOL` |  | ``, `debug`, `grpc`, `http/json`, `http/protobuf` |  |  |
| `metrics.reporters_cache_len` | `integer` | `OTEL_EBPF_METRICS_REPORT_CACHE_LEN` | `256` |  |  |  |
| `metrics.ttl` | `duration` | `OTEL_EBPF_METRICS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  | Specifies the time since a metric was updated for the last time until it is removed from the metrics set. |

## `name_resolver`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `name_resolver.cache_expiry` | `duration` | `OTEL_EBPF_NAME_RESOLVER_CACHE_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  | Specifies the time-to-live of a cached IP->hostname entry. After the cached entry becomes older than this time, the IP->hostname entry will be looked up again. |
| `name_resolver.cache_len` | `integer` | `OTEL_EBPF_NAME_RESOLVER_CACHE_LEN` | `1024` |  |  | Specifies the max size of the LRU cache that is checked before performing the name lookup. Default: 256 |
| `name_resolver.sources` | `string`[] | `OTEL_EBPF_NAME_RESOLVER_SOURCES` | `k8s` | `dns`, `k8s`, `kube`, `kubernetes`, `rdns` |  | Specifies the backends used for name resolving. Accepted values: dns, k8s, rdns |

## `network`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.agent_ip` | `ip` | `OTEL_EBPF_NETWORK_AGENT_IP` |  |  |  | Allows overriding the reported Agent IP address on each flow. |
| `network.agent_ip_iface` | `string` | `OTEL_EBPF_NETWORK_AGENT_IP_IFACE` | `external` | `external`, `local` |  | Specifies which interface should the agent pick the IP address from in order to report it in the AgentIP field on each flow. Accepted values are: external (default), local, or name:<interface name> (e.g. name:eth0). If the AgentIP configuration property is set, this property has no effect. |
| `network.agent_ip_type` | `string` | `OTEL_EBPF_NETWORK_AGENT_IP_TYPE` | `any` | `any`, `ipv4`, `ipv6` |  | Specifies which type of IP address (IPv4 or IPv6 or any) should the agent report in the AgentID field of each flow. Accepted values are: any (default), ipv4, ipv6. If the AgentIP configuration property is set, this property has no effect. |
| `network.cache_active_timeout` | `duration` | `OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT` | `5s` | `30s`, `5m`, `1ms`, etc |  | Specifies the maximum duration that flows are kept in the accounting cache before being flushed for its later export. |
| `network.cache_max_flows` | `integer` | `OTEL_EBPF_NETWORK_CACHE_MAX_FLOWS` | `5000` |  |  | Specifies how many flows can be accumulated in the accounting cache before being flushed for its later export. Default value is 5000. Decrease it if you see the "received message larger than max" error in OBI logs. |
| `network.cidrs` | `string`[] | `OTEL_EBPF_NETWORK_CIDRS` |  |  |  | List, to be set as the "src.cidr" and "dst.cidr" attribute as a function of the source and destination IP addresses. If an IP does not match any address here, the attributes won't be set. If an IP matches multiple CIDR definitions, the flow will be decorated with the narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there all the traffic that does not match any of the other CIDRs. |
| `network.deduper` | `string` | `OTEL_EBPF_NETWORK_DEDUPER` | `first_come` | `first_come`, `none` |  | Specifies the deduper type. Accepted values are "none" (disabled) and "first_come". When enabled, it will detect duplicate flows (flows that have been detected e.g. through both the physical and a virtual interface). "first_come" will forward only flows from the first interface the flows are received from. Default value: first_come |
| `network.deduper_fc_ttl` | `duration` | `OTEL_EBPF_NETWORK_DEDUPER_FC_TTL` | `0s` | `30s`, `5m`, `1ms`, etc |  | Specifies the expiry duration of the flows "first_come" deduplicator. After a flow hasn't been received for that expiry time, the deduplicator forgets it. That means that a flow from a connection that has been inactive during that period could be forwarded again from a different interface. If the value is not set, it will default to 2 * CacheActiveTimeout |
| `network.direction` | `string` | `OTEL_EBPF_NETWORK_DIRECTION` | `both` | `both`, `egress`, `ingress` |  | Allows selecting which flows to trace according to its direction. Accepted values are "ingress", "egress" or "both" (default). |
| `network.enable` | `boolean` | `OTEL_EBPF_NETWORK_METRICS` | `false` |  | Yes | Network metrics. Default value is false (disabled)  add "network" or "network_inter_zone" to OTEL_EBPF_METRICS_FEATURES  TODO OBI 3.0: remove |
| `network.exclude_interfaces` | `string`[] | `OTEL_EBPF_NETWORK_EXCLUDE_INTERFACES` | `lo` |  |  | Contains the interface names that will be excluded from flow tracing. Default: "lo" (loopback). If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression, otherwise it will be matched as a case-sensitive string. |
| `network.exclude_protocols` | `string`[] | `OTEL_EBPF_NETWORK_EXCLUDE_PROTOCOLS` |  |  |  | Causes OBI to drop flows whose transport protocol is in this list. If the Protocols list is already defined, ExcludeProtocols has no effect. |
| `network.guess_ports` | `string` | `OTEL_EBPF_NETWORK_GUESS_PORTS` | `disable` | `disable`, `ordinal` |  | Controls how OBI assigns server.port/client.port when the connection initiator is unknown. Accepted values are "ordinal" (assume highest port is client) and "disable" (default, do not guess and emit empty client/server port attributes for unknown-initiator flows). |
| `network.interfaces` | `string`[] | `OTEL_EBPF_NETWORK_INTERFACES` |  |  |  | Contains the interface names from where flows will be collected. If empty, the agent will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces. If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression, otherwise it will be matched as a case-sensitive string. |
| `network.listen_interfaces` | `string` | `OTEL_EBPF_NETWORK_LISTEN_INTERFACES` | `watch` | `poll`, `watch` |  | Specifies the mechanism used by the agent to listen for added or removed network interfaces. Accepted values are "watch" (default) or "poll". If the value is "watch", interfaces are traced immediately after they are created. This is the recommended setting for most configurations. "poll" value is a fallback mechanism that periodically queries the current network interfaces (frequency specified by ListenPollPeriod). |
| `network.listen_poll_period` | `duration` | `OTEL_EBPF_NETWORK_LISTEN_POLL_PERIOD` | `10s` | `30s`, `5m`, `1ms`, etc |  | Specifies the periodicity to query the network interfaces when the ListenInterfaces value is set to "poll". |
| `network.print_flows` | `boolean` | `OTEL_EBPF_NETWORK_PRINT_FLOWS` | `false` |  |  | Enables printing the network flows to the Standard Output |
| `network.protocols` | `string`[] | `OTEL_EBPF_NETWORK_PROTOCOLS` |  |  |  | Causes OBI to drop flows whose transport protocol is not in this list. |
| `network.sampling` | `integer` | `OTEL_EBPF_NETWORK_SAMPLING` | `0` |  |  | Holds the rate at which packets should be sampled and sent to the target collector. E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector. |
| `network.source` | `string` | `OTEL_EBPF_NETWORK_SOURCE` | `socket_filter` | `socket_filter`, `tc` |  | Specify the source type for network events, e.g tc or socket_filter. The tc implementation cannot be used when there are other tc eBPF probes, e.g. Cilium CNI. |

### `network.geo_ip`

GeoIP is currently experimental. It is kept disabled by default and will be hidden from the documentation. This means that it does not impact in the overall OBI performance.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.cache_expiry` | `duration` | `OTEL_EBPF_GEOIP_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_TTL for backwards-compatibility |
| `network.geo_ip.cache_len` | `integer` | `OTEL_EBPF_GEOIP_CACHE_LEN` | `512` |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_LEN for backwards-compatibility |

#### `network.geo_ip.ipinfo`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.ipinfo.path` | `string` | `OTEL_EBPF_GEOIP_IPINFO_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_IPINFO_PATH for backwards-compatibility |

#### `network.geo_ip.maxmind`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.maxmind.asn_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_ASN_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_ASN_PATH for backwards-compatibility |
| `network.geo_ip.maxmind.country_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_COUNTRY_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_COUNTRY_PATH for backwards-compatibility |

### `network.reverse_dns`

ReverseDNS is currently experimental. It is kept disabled by default and will be hidden from the documentation. This means that it does not impact in the overall OBI performance.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.reverse_dns.cache_expiry` | `duration` | `OTEL_EBPF_REVERSE_DNS_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  | Only applies to the "local" and "ebpf" ReverseDNS type. It specifies the time-to-live of a cached IP->hostname entry. After the cached entry becomes older than this time, the IP->hostname entry will be looked up again. It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL for backwards-compatibility |
| `network.reverse_dns.cache_len` | `integer` | `OTEL_EBPF_REVERSE_DNS_CACHE_LEN` | `256` |  |  | Only applies to the "local" and "ebpf" ReverseDNS type. It specifies the max size of the LRU cache that is checked before performing the name lookup. Default: 256 It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN for backwards-compatibility |
| `network.reverse_dns.type` | `string` | `OTEL_EBPF_REVERSE_DNS_TYPE` | `none` | `ebpf`, `local`, `none` |  | Specifies the ReverseDNS method. Values are "none" (default), "local" and "ebpf" It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE for backwards-compatibility |

## `nodejs`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `nodejs.enabled` | `boolean` | `OTEL_EBPF_NODEJS_ENABLED` | `true` |  |  |  |

## `otel_metrics_export`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
|  | `integer` | `OTEL_METRIC_EXPORT_INTERVAL` | `60000` |  |  | Supports metric intervals as specified by the standard OTEL definition. OTEL_EBPF_METRICS_INTERVAL takes precedence over it. |
| `otel_metrics_export.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `otel_metrics_export.buckets` | [`Buckets`](#buckets) |  |  |  |  | Buckets defines the histograms bucket boundaries, and allows users to redefine them |
| `otel_metrics_export.endpoint` | `uri` | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` |  |  |  |  |
| `otel_metrics_export.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to OTEL span metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a OTEL resource attribute, you should add `deployment.environment`. |
| `otel_metrics_export.features` | `string`[] | `OTEL_EBPF_METRICS_FEATURES` | `32` | `*`, `all`, `application`, `application_host`, `application_service_graph`, `application_span`, `application_span_otel`, `application_span_sizes`, `ebpf`, `network`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_rtt` | Yes | Specifies which metric features to export. Accepted values: application, network, application_span, application_service_graph, ... envDefault is provided to avoid breaking changes  use top-level MetricsConfig.Features instead. |
| `otel_metrics_export.histogram_aggregation` | `string` | `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` | `explicit_bucket_histogram` | `base2_exponential_bucket_histogram`, `explicit_bucket_histogram` |  |  |
| `otel_metrics_export.insecure_skip_verify` | `boolean` | `OTEL_EBPF_INSECURE_SKIP_VERIFY` | `false` |  |  | Enables skipping TLS certificate verification (not standard, so we don't follow the same naming convention) |
| `otel_metrics_export.instrumentations` | `string`[] | `OTEL_EBPF_METRICS_INSTRUMENTATIONS` | `*` | `*`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `redis`, `sql` |  | Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql... |
| `otel_metrics_export.interval` | `duration` | `OTEL_EBPF_METRICS_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_metrics_export.otel_sdk_log_level` | `string` | `OTEL_EBPF_SDK_LOG_LEVEL` |  |  |  | Works independently from the global LogLevel because it prints GBs of logs in Debug mode and the Info messages leak internal details that are not usually valuable for the final user. Accepted values: debug, info, warn, error (case-insensitive). |
| `otel_metrics_export.protocol` | `string` | `OTEL_EXPORTER_OTLP_PROTOCOL` |  | ``, `debug`, `grpc`, `http/json`, `http/protobuf` |  |  |
| `otel_metrics_export.reporters_cache_len` | `integer` | `OTEL_EBPF_METRICS_REPORT_CACHE_LEN` | `256` |  |  |  |
| `otel_metrics_export.ttl` | `duration` | `OTEL_EBPF_METRICS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  | Specifies the time since a metric was updated for the last time until it is removed from the metrics set. |

## `otel_traces_export`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `otel_traces_export.backoff_initial_interval` | `duration` | `OTEL_EBPF_BACKOFF_INITIAL_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  | Configuration options for BackOffConfig of the traces exporter. See <https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configretry/backoff.go> BackOffInitialInterval the time to wait after the first failure before retrying. |
| `otel_traces_export.backoff_max_elapsed_time` | `duration` | `OTEL_EBPF_BACKOFF_MAX_ELAPSED_TIME` | `0s` | `30s`, `5m`, `1ms`, etc |  | Specifies the maximum amount of time (including retries) spent trying to send a request/batch. |
| `otel_traces_export.backoff_max_interval` | `duration` | `OTEL_EBPF_BACKOFF_MAX_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  | Specifies the upper bound on backoff interval. |
| `otel_traces_export.batch_max_size` | `integer` | `OTEL_EBPF_OTLP_TRACES_BATCH_MAX_SIZE` | `4096` |  |  | Is the maximum number of spans that the batcher will accumulate before flushing a batch to the sending queue. |
| `otel_traces_export.batch_timeout` | `duration` | `OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT` | `15s` | `30s`, `5m`, `1ms`, etc |  | Is the time after which a batch will be sent regardless of its size. |
| `otel_traces_export.endpoint` | `uri` | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` |  |  |  |  |
| `otel_traces_export.insecure_skip_verify` | `boolean` | `OTEL_EBPF_INSECURE_SKIP_VERIFY` | `false` |  |  | Enables skipping TLS certificate verification (not standard, so we don't follow the same naming convention) |
| `otel_traces_export.instrumentations` | `string`[] | `OTEL_EBPF_TRACES_INSTRUMENTATIONS` | `http`, `grpc`, `sql`, `redis`, `kafka`, `mqtt`, `mongo`, `couchbase`, `memcached` | `*`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `redis`, `sql` |  | Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql... |
| `otel_traces_export.otel_sdk_log_level` | `string` | `OTEL_EBPF_SDK_LOG_LEVEL` |  |  |  | Works independently from the global LogLevel because it prints GBs of logs in Debug mode and the Info messages leak internal details that are not usually valuable for the final user. Accepted values: debug, info, warn, error (case-insensitive). dpanic/panic/fatal are mapped to error. |
| `otel_traces_export.protocol` | `string` | `OTEL_EXPORTER_OTLP_PROTOCOL` |  | ``, `debug`, `grpc`, `http/json`, `http/protobuf` |  |  |
| `otel_traces_export.queue_size` | `integer` | `OTEL_EBPF_OTLP_TRACES_QUEUE_SIZE` | `16384` |  |  | Is the maximum number of spans that the sending queue will hold before applying back-pressure. It must be >= `2 * BatchMaxSize`, otherwise the memory queue rejects every batch with "element size too large" and drops spans permanently. If left at 0 it defaults to `4 * BatchMaxSize`. |
| `otel_traces_export.reporters_cache_len` | `integer` | `OTEL_EBPF_TRACES_REPORT_CACHE_LEN` | `256` |  |  |  |

### `otel_traces_export.sampler`

Sampler standard configuration <https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler> We don't support, yet, the jaeger and xray samplers.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `otel_traces_export.sampler.arg` | `string` | `OTEL_TRACES_SAMPLER_ARG` |  |  |  |  |
| `otel_traces_export.sampler.name` | `string` | `OTEL_TRACES_SAMPLER` |  | `always_off`, `always_on`, `parentbased_always_off`, `parentbased_always_on`, `parentbased_traceidratio`, `traceidratio` |  |  |

## `prometheus_export`

TODO: TLS

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `prometheus_export.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `prometheus_export.buckets` | [`Buckets`](#buckets) |  |  |  |  | Buckets defines the histograms bucket boundaries, and allows users to redefine them |
| `prometheus_export.disable_build_info` | `boolean` | `OTEL_EBPF_PROMETHEUS_DISABLE_BUILD_INFO` | `false` |  |  |  |
| `prometheus_export.exemplar_filter` | `string` | `OTEL_EBPF_PROMETHEUS_EXEMPLAR_FILTER` |  |  |  | Controls when exemplars are attached to metrics. Accepted values: "always_on", "always_off", "trace_based". Defaults to "always_off": do not attach exemplars. This mimics the OTEL_METRICS_EXEMPLAR_FILTER specification. |
| `prometheus_export.extra_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to Prometheus metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute, you should add `deployment.environment`. |
| `prometheus_export.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  | Adds extra metadata labels to Prometheus span metrics from sources whose availability can't be known beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute, you should add `deployment.environment`. |
| `prometheus_export.features` | `string`[] | `OTEL_EBPF_PROMETHEUS_FEATURES` | `0` | `*`, `all`, `application`, `application_host`, `application_service_graph`, `application_span`, `application_span_otel`, `application_span_sizes`, `ebpf`, `network`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_rtt` | Yes | Features specifies which metric features to export. Accepted values: application, network, application_span, application_service_graph, ...  use top-level MetricsConfig.Features instead. |
| `prometheus_export.instrumentations` | `string`[] | `OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS` | `*` | `*`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `redis`, `sql` |  | Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql... |
| `prometheus_export.path` | `string` | `OTEL_EBPF_PROMETHEUS_PATH` | `/internal/metrics` |  |  |  |
| `prometheus_export.port` | `integer` | `OTEL_EBPF_PROMETHEUS_PORT` | `0` |  |  |  |
| `prometheus_export.service_cache_size` | `integer` |  | `10000` |  |  |  |
| `prometheus_export.ttl` | `duration` | `OTEL_EBPF_PROMETHEUS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  | Specifies the time since a metric was updated for the last time until it is removed from the metrics set. |

## `routes`

RoutesConfig allows grouping URLs sharing a given pattern.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `routes.ignore_mode` | `string` |  |  | `all`, `metrics`, `traces` | Yes | To be removed and replaced by a collector-like filtering mechanism |
| `routes.ignored_patterns` | `string`[] |  |  |  | Yes | To be removed and replaced by a collector-like filtering mechanism |
| `routes.max_path_segment_cardinality` | `integer` |  | `10` |  |  | Max allowed path segment cardinality (per service) for the heuristic matcher |
| `routes.patterns` | `string`[] |  |  |  |  | Defines the URL path patterns that will match to a route |
| `routes.unmatched` | `string` |  | `heuristic` | `heuristic`, `low-cardinality`, `path`, `unset`, `wildcard` |  | Specifies what to do when a route pattern is not matched |
| `routes.wildcard_char` | `string` |  | `*` |  |  | Character that will be used to replace route segments |

## `stats`

TODO: see if there is a way to merge common fields with NetworkConfig

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.agent_ip` | `ip` | `OTEL_EBPF_STATS_AGENT_IP` |  |  |  | Allows overriding the reported Agent IP address on each stat. |
| `stats.agent_ip_iface` | `string` | `OTEL_EBPF_STATS_AGENT_IP_IFACE` | `external` | `external`, `local` |  | Specifies which interface should the agent pick the IP address from in order to report it in the AgentIP field on each stat. Accepted values are: external (default), local, or name:<interface name> (e.g. name:eth0). If the AgentIP configuration property is set, this property has no effect. |
| `stats.agent_ip_type` | `string` | `OTEL_EBPF_STATS_AGENT_IP_TYPE` | `any` | `any`, `ipv4`, `ipv6` |  | Specifies which type of IP address (IPv4 or IPv6 or any) should the agent report in the AgentID field of each stat. Accepted values are: any (default), ipv4, ipv6. If the AgentIP configuration property is set, this property has no effect. |
| `stats.cidrs` | `string`[] | `OTEL_EBPF_STATS_CIDRS` |  |  |  | List, to be set as the "src.cidr" and "dst.cidr" attribute as a function of the source and destination IP addresses. If an IP does not match any address here, the attributes won't be set. If an IP matches multiple CIDR definitions, the stat will be decorated with the narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there all the traffic that does not match any of the other CIDRs. |
| `stats.print_stats` | `boolean` | `OTEL_EBPF_STATS_PRINT_STATS` | `false` |  |  | Enables printing the stats to the Standard Output |

### `stats.geo_ip`

GeoIP is currently experimental. It is kept disabled by default and will be hidden from the documentation. This means that it does not impact in the overall OBI performance.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.cache_expiry` | `duration` | `OTEL_EBPF_GEOIP_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_TTL for backwards-compatibility |
| `stats.geo_ip.cache_len` | `integer` | `OTEL_EBPF_GEOIP_CACHE_LEN` | `512` |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_LEN for backwards-compatibility |

#### `stats.geo_ip.ipinfo`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.ipinfo.path` | `string` | `OTEL_EBPF_GEOIP_IPINFO_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_IPINFO_PATH for backwards-compatibility |

#### `stats.geo_ip.maxmind`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.maxmind.asn_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_ASN_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_ASN_PATH for backwards-compatibility |
| `stats.geo_ip.maxmind.country_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_COUNTRY_PATH` |  |  |  | It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_COUNTRY_PATH for backwards-compatibility |

### `stats.reverse_dns`

ReverseDNS is currently experimental. It is kept disabled by default and will be hidden from the documentation. This means that it does not impact in the overall OBI performance.

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.reverse_dns.cache_expiry` | `duration` | `OTEL_EBPF_REVERSE_DNS_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  | Only applies to the "local" and "ebpf" ReverseDNS type. It specifies the time-to-live of a cached IP->hostname entry. After the cached entry becomes older than this time, the IP->hostname entry will be looked up again. It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL for backwards-compatibility |
| `stats.reverse_dns.cache_len` | `integer` | `OTEL_EBPF_REVERSE_DNS_CACHE_LEN` | `256` |  |  | Only applies to the "local" and "ebpf" ReverseDNS type. It specifies the max size of the LRU cache that is checked before performing the name lookup. Default: 256 It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN for backwards-compatibility |
| `stats.reverse_dns.type` | `string` | `OTEL_EBPF_REVERSE_DNS_TYPE` | `none` | `ebpf`, `local`, `none` |  | Specifies the ReverseDNS method. Values are "none" (default), "local" and "ebpf" It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE for backwards-compatibility |

---

## Type Definitions

### Buckets

Buckets defines the histograms bucket boundaries, and allows users to redefine them

| Field | Type | Values | Description |
|---|---|---|---|
| `duration_histogram` | `number`[] |  |  |
| `gen_ai_client_operation_duration_histogram` | `number`[] |  |  |
| `gen_ai_client_token_usage_histogram` | `number`[] |  |  |
| `request_size_histogram` | `number`[] |  |  |
| `response_size_histogram` | `number`[] |  |  |

### ExtraGroupAttributesMap

Map of attribute group names to arrays of attribute names. Only 'k8s_app_meta' is currently supported as a key.

**Known keys:** `k8s_app_meta`

**Value type:** `string[]`

### GlobAttributes

| Field | Type | Values | Description |
|---|---|---|---|
| `cmd_args` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Allows to limit by matching command line arguments |
| `container_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `containers_only` | `boolean` |  | Restricts the discovery to processes which are running inside a container |
| `exe_path` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Allows defining the regular expression matching the full executable path. |
| `exports` | `string`[] | `logs`, `metrics`, `traces` | Configures what to export. Allowed values are 'metrics', 'traces', or an empty array (disabled). An unspecified value (nil) will use the default configuration value |
| `k8s_container_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_cronjob_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_daemonset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_deployment_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_job_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_namespace` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_owner_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_pod_annotations` | `map[string]string` |  | Allows matching against the annotations of a pod |
| `k8s_pod_labels` | `map[string]string` |  | Allows matching against the labels of a pod |
| `k8s_pod_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_replicaset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_statefulset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `languages` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Language allows defining services to instrument based on the programming language they are written in. Use lowercase names, e.g. java,go |
| `metrics` | [`SvcMetricsConfig`](#svcmetricsconfig) |  | Configuration that is custom for this service match |
| `name` | `string` |  | Will define a name for the matching service. If unset, it will take the name of the executable process, from the OTEL_SERVICE_NAME env var of the instrumented process, or from other metadata like Kubernetes annotations.  Name should be set in the instrumentation target via kube metadata or standard env vars.  To be kept undocumented until we remove it. |
| `namespace` | `string` |  | Will define a namespace for the matching service. If unset, it will be left empty.  Namespace should be set in the instrumentation target via kube metadata or standard env vars.  To be kept undocumented until we remove it. |
| `open_ports` | [`IntEnum`](#intenum) |  | Allows defining a group of ports that this service could open. It accepts a comma-separated list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089) |
| `routes` | [`CustomRoutesConfig`](#customroutesconfig) |  |  |
| `sampler` | [`SamplerConfig`](#samplerconfig) |  | Sampler standard configuration <https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler> We don't support, yet, the jaeger and xray samplers. |
| `target_pids` | `integer`[] |  | Allows selecting processes by PID (static from config). When non-empty, the process PID must be in this list. |

### HTTPParsingDefaultAction

HTTPParsingDefaultAction specifies the default action per rule type.

| Field | Type | Values | Description |
|---|---|---|---|
| `body` | `string` | `exclude`, `include`, `obfuscate` |  |
| `headers` | `string` | `exclude`, `include`, `obfuscate` |  |

### HTTPParsingRule

HTTPParsingRule defines a single include/exclude/obfuscate rule for HTTP header and payload extraction.

| Field | Type | Values | Description |
|---|---|---|---|
| `action` | `string` | `exclude`, `include`, `obfuscate` | Of the rule: "include", "exclude", or "obfuscate" |
| `match` | [`HTTPParsingMatch`](#httpparsingmatch) |  | Defines the matching criteria for this rule |
| `scope` | `string` | `all`, `request`, `response` | Of the rule: "request", "response", or "all" |
| `type` | `string` | `body`, `headers` | Specifies what this rule matches against: "headers" or "body" |

### IntEnum

IntEnum defines an enumeration of integers (e.g. ports or PIDs). It allows a set of single values or ranges. When unmarshalled from text, it accepts a comma-separated list (e.g. 80,443,8000-8999). When unmarshalled from YAML, it accepts either a scalar (same as text) or a sequence (e.g. [1234, 5678]).

| Field | Type | Values | Description |
|---|---|---|---|
| `Ranges` | `string`[] | `1`, `1000`, `8080-8090`, `80,443,8000-8999`, etc |  |

### LogEnricherServiceConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `service` | [`GlobAttributes`](#globattributes)[] |  | Should also be contained in 'services' in the Discovery section |

### RegexSelector

RegexSelector that specify a given instrumented service. Each instance has to define either the OpenPorts or Path property, or both. These are used to match a given executable. If both OpenPorts and Path are defined, the inspected executable must fulfill both properties.

| Field | Type | Values | Description |
|---|---|---|---|
| `cmd_args` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Allows matching by command line arguments |
| `container_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `containers_only` | `boolean` |  | Restrict the discovery to processes which are running inside a container |
| `exe_path` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Allows defining the regular expression matching the full executable path. |
| `exe_path_regexp` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Please use Path (exe_path YAML attribute) |
| `exports` | `string`[] | `logs`, `metrics`, `traces` | Configures what to export. Allowed values are 'metrics', 'traces', or an empty array (disabled). An unspecified value (nil) will use the default configuration value |
| `k8s_container_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_cronjob_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_daemonset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_deployment_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_job_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_namespace` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_owner_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_pod_annotations` | `map[string]string` |  | Allows matching against the annotations of a pod |
| `k8s_pod_labels` | `map[string]string` |  | Allows matching against the labels of a pod |
| `k8s_pod_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_replicaset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_statefulset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `languages` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Language allows defining services to instrument based on the programming language they are written in. |
| `metrics` | [`SvcMetricsConfig`](#svcmetricsconfig) |  | Configuration that is custom for this service match |
| `name` | `string` |  | Will define a name for the matching service. If unset, it will take the name of the executable process, from the OTEL_SERVICE_NAME env var of the instrumented process, or from other metadata like Kubernetes annotations.  Name should be set in the instrumentation target via kube metadata or standard env vars.  To be kept undocumented until we remove it. |
| `namespace` | `string` |  | Will define a namespace for the matching service. If unset, it will be left empty.  Namespace should be set in the instrumentation target via kube metadata or standard env vars.  To be kept undocumented until we remove it. |
| `open_ports` | [`IntEnum`](#intenum) |  | Allows defining a group of ports that this service could open. It accepts a comma-separated list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089) |
| `routes` | [`CustomRoutesConfig`](#customroutesconfig) |  |  |
| `sampler` | [`SamplerConfig`](#samplerconfig) |  | Sampler standard configuration <https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler> We don't support, yet, the jaeger and xray samplers. |
| `target_pids` | `integer`[] |  | Allows selecting processes by PID. When non-empty, the process PID must be in this list (in addition to any path/port criteria). |

### CustomRoutesConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `incoming` | `string`[] |  |  |
| `outgoing` | `string`[] |  |  |

### HTTPParsingMatch

HTTPParsingMatch defines matching criteria for an HTTP parsing rule. Header rules use Patterns and CaseSensitive. Body rules use ObfuscationJSONPaths. URLPathPatterns and Methods are shared across both types.

| Field | Type | Values | Description |
|---|---|---|---|
| `case_sensitive` | `boolean` |  | Controls whether header matching is case-sensitive (headers only) |
| `methods` | `string`[] | `DELETE`, `GET`, `HEAD`, `OPTIONS`, `PATCH`, `POST`, `PUT` | Is a list of HTTP methods this rule applies to (shared). Empty means all methods. |
| `obfuscation_json_paths` | `string`[] | `$.password`, `$.user.name`, `$.items[0].id`, etc | Is a list of JSONPath expressions for fields to obfuscate (body only) |
| `patterns` | `glob`[] | `app-*`, `service-??`, `prod-*-db`, etc | Is a list of glob patterns to match header names against (headers only) |
| `url_path_patterns` | `glob`[] | `app-*`, `service-??`, `prod-*-db`, etc | Is a list of glob patterns to match the request path against (shared) |

### SamplerConfig

Sampler standard configuration <https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler> We don't support, yet, the jaeger and xray samplers.

| Field | Type | Values | Description |
|---|---|---|---|
| `arg` | `string` |  |  |
| `name` | `string` | `always_off`, `always_on`, `parentbased_always_off`, `parentbased_always_on`, `parentbased_traceidratio`, `traceidratio` |  |

### SvcMetricsConfig

SvcMetricsConfig is equivalent to MetricsConfig, but avoids defining environment variable, since this is a per-service configuration that needs to be defined exclusively in the service definition YAML.

| Field | Type | Values | Description |
|---|---|---|---|
| `features` | `string`[] | `*`, `all`, `application`, `application_host`, `application_service_graph`, `application_span`, `application_span_otel`, `application_span_sizes`, `ebpf`, `network`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_rtt` | Specifies which metric features to export. Accepted values: application, network, application_span, application_service_graph, ... envDefault is provided to avoid breaking changes |
