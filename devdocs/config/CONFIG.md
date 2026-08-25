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
- [`health_check`](#health-check)
- [`internal_metrics`](#internal-metrics)
- [`javaagent`](#javaagent)
- [`jvm_runtime_metrics`](#jvm-runtime-metrics)
- [`metrics`](#metrics)
- [`name_resolver`](#name-resolver)
- [`network`](#network)
- [`nodejs`](#nodejs)
- [`otel_metrics_export`](#otel-metrics-export)
- [`otel_traces_export`](#otel-traces-export)
- [`prometheus_export`](#prometheus-export)
- [`stats`](#stats)
- [Type Definitions](#type-definitions)

---

## Top-Level Properties

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
|  | `glob` | `OTEL_EBPF_AUTO_TARGET_EXE` |  | `app-*`, `service-??`, `prod-*-db`, etc |  | Glob pattern to match against the attribute value |
|  | `glob` | `OTEL_EBPF_AUTO_TARGET_LANGUAGE` |  | `app-*`, `service-??`, `prod-*-db`, etc |  | Glob pattern to match against the attribute value |
| `channel_buffer_len` | `integer` | `OTEL_EBPF_CHANNEL_BUFFER_LEN` | `50` |  |  |  |
| `channel_send_timeout` | `duration` | `OTEL_EBPF_CHANNEL_SEND_TIMEOUT` | `1m` | `30s`, `5m`, `1ms`, etc |  |  |
| `channel_send_timeout_panic` | `boolean` | `OTEL_EBPF_CHANNEL_SEND_TIMEOUT_PANIC` | `false` |  |  |  |
| `enforce_sys_caps` | `boolean` | `OTEL_EBPF_ENFORCE_SYS_CAPS` | `false` |  |  |  |
| `executable_path` | `regex` | `OTEL_EBPF_EXECUTABLE_PATH` |  | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc |  | Regular expression to match against the executable file path |
| `filter` | [`AttributesConfig`](#attributesconfig) |  |  |  |  |  |
| `log_config` | `string` | `OTEL_EBPF_LOG_CONFIG` |  | `json`, `yaml` |  |  |
| `log_format` | `string` | `OTEL_EBPF_LOG_FORMAT` | `text` | `json`, `text` |  |  |
| `log_level` | `string` | `OTEL_EBPF_LOG_LEVEL` | `INFO` | `DEBUG`, `ERROR`, `INFO`, `WARN` |  |  |
| `open_port` | [`IntEnum`](#intenum) | `OTEL_EBPF_OPEN_PORT` |  |  |  |  |
| `profile_port` | `integer` | `OTEL_EBPF_PROFILE_PORT` | `0` |  |  |  |
| `routes` | [`RoutesConfig`](#routesconfig) |  |  |  |  |  |
| `service_name` | `string` | `OTEL_SERVICE_NAME` |  |  |  |  |
| `service_namespace` | `string` | `OTEL_EBPF_SERVICE_NAMESPACE` |  |  |  |  |
| `shutdown_timeout` | `duration` | `OTEL_EBPF_SHUTDOWN_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `target_pids` | [`IntEnum`](#intenum) | `OTEL_EBPF_TARGET_PID` |  |  |  |  |
| `trace_printer` | `string` | `OTEL_EBPF_TRACE_PRINTER` | `disabled` | `counter`, `disabled`, `json`, `json_indent`, `text` |  |  |

## `attributes`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.extra_group_attributes` | [`ExtraGroupAttributesMap`](#extragroupattributesmap) |  |  |  |  | Map of attribute group names to arrays of attribute names. Only 'k8s_app_meta' is currently supported as a key. |
| `attributes.metric_span_names_limit` | `integer` | `OTEL_EBPF_METRIC_SPAN_NAMES_LIMIT` | `100` |  |  |  |
| `attributes.rename_unresolved_hosts` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS` | `unresolved` |  |  |  |
| `attributes.rename_unresolved_hosts_incoming` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_INCOMING` | `incoming` |  |  |  |
| `attributes.rename_unresolved_hosts_outgoing` | `string` | `OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_OUTGOING` | `outgoing` |  |  |  |
| `attributes.select` | `map[string]object` |  |  |  |  |  |
| `attributes.sensitive_query_params` | [`SensitiveQueryParamsConfig`](#sensitivequeryparamsconfig) |  |  |  |  |  |

### `attributes.host_id`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.host_id.override` | `string` | `OTEL_EBPF_HOST_ID` |  |  |  |  |

### `attributes.instance_id`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.instance_id.dns` | `boolean` | `OTEL_EBPF_HOSTNAME_DNS_RESOLUTION` | `true` |  |  |  |
| `attributes.instance_id.override_hostname` | `string` | `OTEL_EBPF_HOSTNAME` |  |  |  |  |

### `attributes.kubernetes`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.kubernetes.cluster_name` | `string` | `OTEL_EBPF_KUBE_CLUSTER_NAME` |  |  |  |  |
| `attributes.kubernetes.disable_informers` | `string`[] | `OTEL_EBPF_KUBE_DISABLE_INFORMERS` |  |  |  |  |
| `attributes.kubernetes.drop_external` | `boolean` | `OTEL_EBPF_NETWORK_DROP_EXTERNAL` | `false` |  |  |  |
| `attributes.kubernetes.enable` | `string` | `OTEL_EBPF_KUBE_METADATA_ENABLE` | `autodetect` | `autodetect`, `false`, `true` |  |  |
| `attributes.kubernetes.informers_resync_period` | `duration` | `OTEL_EBPF_KUBE_INFORMERS_RESYNC_PERIOD` | `30m` | `30s`, `5m`, `1ms`, etc |  |  |
| `attributes.kubernetes.informers_sync_timeout` | `duration` | `OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT` | `30s` | `30s`, `5m`, `1ms`, etc |  |  |
| `attributes.kubernetes.kubeconfig_path` | `string` | `KUBECONFIG` |  |  |  |  |
| `attributes.kubernetes.meta_cache_address` | `string` | `OTEL_EBPF_KUBE_META_CACHE_ADDRESS` |  |  |  |  |
| `attributes.kubernetes.meta_restrict_local_node` | `boolean` | `OTEL_EBPF_KUBE_META_RESTRICT_LOCAL_NODE` | `false` |  |  |  |
| `attributes.kubernetes.reconnect_initial_interval` | `duration` | `OTEL_EBPF_KUBE_RECONNECT_INITIAL_INTERVAL` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |
| `attributes.kubernetes.resource_labels` | `map[string]string[]` |  |  |  |  |  |
| `attributes.kubernetes.service_name_template` | `string` | `OTEL_EBPF_SERVICE_NAME_TEMPLATE` |  |  |  |  |

#### `attributes.kubernetes.meta_source_labels`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.kubernetes.meta_source_labels.service_name` | `string` | `OTEL_SERVICE_NAME` |  |  |  |  |
| `attributes.kubernetes.meta_source_labels.service_namespace` | `string` | `OTEL_EBPF_SERVICE_NAMESPACE` |  |  |  |  |

### `attributes.metadata_retry`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `attributes.metadata_retry.max_interval` | `duration` | `OTEL_EBPF_METADATA_RETRY_MAX_INTERVAL` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |
| `attributes.metadata_retry.start_interval` | `duration` | `OTEL_EBPF_METADATA_RETRY_START_INTERVAL` | `500ms` | `30s`, `5m`, `1ms`, etc |  |  |
| `attributes.metadata_retry.timeout` | `duration` | `OTEL_EBPF_METADATA_RETRY_TIMEOUT` | `30s` | `30s`, `5m`, `1ms`, etc |  |  |

## `discovery`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `discovery.bpf_pid_filter_off` | `boolean` | `OTEL_EBPF_BPF_PID_FILTER_OFF` | `false` |  |  |  |
| `discovery.default_exclude_instrument` | [`GlobAttributes`](#globattributes)[] |  | `[{"cmd_args":{},"containers_only":false,"exe_path":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null},{"cmd_args":{},"containers_only":false,"exe_path":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null}]` |  |  |  |
| `discovery.default_exclude_services` | [`RegexSelector`](#regexselector)[] |  | `[{"cmd_args":{},"containers_only":false,"exe_path":{},"exe_path_regexp":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null},{"cmd_args":{},"containers_only":false,"exe_path":{},"exe_path_regexp":{},"exports":{},"k8s_pod_annotations":null,"k8s_pod_labels":null,"languages":{},"metrics":{"features":0},"name":"","namespace":"","open_ports":{"Ranges":null},"routes":null,"sampler":null,"target_pids":null}]` |  |  |  |
| `discovery.default_otlp_grpc_port` | `integer` | `OTEL_EBPF_DEFAULT_OTLP_GRPC_PORT` | `4317` |  |  |  |
| `discovery.disabled_route_harvesters` | `string`[] |  |  | `go`, `java`, `nodejs` |  |  |
| `discovery.exclude_instrument` | [`GlobAttributes`](#globattributes)[] |  |  |  |  |  |
| `discovery.exclude_otel_instrumented_services` | `boolean` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES` | `true` |  |  |  |
| `discovery.exclude_otel_instrumented_services_span_metrics` | `boolean` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS` | `false` |  |  |  |
| `discovery.exclude_services` | [`RegexSelector`](#regexselector)[] |  |  |  |  |  |
| `discovery.excluded_linux_system_paths` | `string`[] |  | `/lib/systemd/`, `/usr/lib/systemd/`, `/usr/libexec/`, `/sbin/`, `/usr/sbin/` |  |  |  |
| `discovery.instrument` | [`GlobAttributes`](#globattributes)[] |  |  |  |  |  |
| `discovery.min_process_age` | `duration` | `OTEL_EBPF_MIN_PROCESS_AGE` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |
| `discovery.poll_interval` | `duration` | `OTEL_EBPF_DISCOVERY_POLL_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `discovery.process_context_poll_interval` | `duration` | `OTEL_EBPF_PROCESS_CONTEXT_POLL_INTERVAL` | `1s` | `30s`, `5m`, `1ms`, etc |  |  |
| `discovery.route_harvester_timeout` | `duration` | `OTEL_EBPF_ROUTE_HARVESTER_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `discovery.services` | [`RegexSelector`](#regexselector)[] |  |  |  |  |  |
| `discovery.skip_go_specific_tracers` | `boolean` | `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS` | `false` |  |  |  |

### `discovery.route_harvester_advanced`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `discovery.route_harvester_advanced.java_harvest_delay` | `duration` | `OTEL_EBPF_JAVA_ROUTE_HARVEST_DELAY` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |

## `ebpf`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.batch_length` | `integer` | `OTEL_EBPF_BPF_BATCH_LENGTH` | `100` |  |  |  |
| `ebpf.batch_timeout` | `duration` | `OTEL_EBPF_BPF_BATCH_TIMEOUT` | `1s` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.bpf_debug` | `boolean` | `OTEL_EBPF_BPF_DEBUG` | `false` |  |  |  |
| `ebpf.bpf_fs_path` | `string` | `OTEL_EBPF_BPF_FS_PATH` | `/sys/fs/bpf/` |  |  |  |
| `ebpf.context_propagation` | `string` | `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` | `disabled` | ``, `all`, `disabled` | deprecated values: `ip` | Configures distributed context propagation. Can be 'all' to enable all methods, 'disabled'/'' to disable, or a comma-separated list of methods: 'headers' for HTTP headers, 'tcp' for TCP options (e.g. "headers,tcp"). |
| `ebpf.couchbase_db_cache_size` | `integer` | `OTEL_EBPF_COUCHBASE_DB_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.disable_black_box_cp` | `boolean` | `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP` | `false` |  |  |  |
| `ebpf.dns_request_timeout` | `duration` | `OTEL_EBPF_BPF_DNS_REQUEST_TIMEOUT` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.force_bpf_map_reader` | `string` | `OTEL_EBPF_FORCE_BPF_MAP_READER` | `auto` | `auto`, `batch`, `legacy` |  |  |
| `ebpf.go_http_client_buffer_timeout` | `duration` | `OTEL_EBPF_BPF_GO_HTTP_CLIENT_BUFFER_TIMEOUT` | `1s` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.heuristic_sql_detect` | `boolean` | `OTEL_EBPF_HEURISTIC_SQL_DETECT` | `false` |  |  |  |
| `ebpf.high_request_volume` | `boolean` | `OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME` | `false` |  |  |  |
| `ebpf.http_request_timeout` | `duration` | `OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.instrument_cuda` | `integer` | `OTEL_EBPF_INSTRUMENT_CUDA` | `auto` |  |  |  |
| `ebpf.kafka_topic_uuid_cache_size` | `integer` | `OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.maps_config` | [`MapsConfig`](#mapsconfig) |  |  |  |  |  |
| `ebpf.max_transaction_time` | `duration` | `OTEL_EBPF_BPF_MAX_TRANSACTION_TIME` | `5m` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.mongo_requests_cache_size` | `integer` | `OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.mssql_prepared_statements_cache_size` | `integer` | `OTEL_EBPF_BPF_MSSQL_PREPARED_STATEMENTS_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.mysql_prepared_statements_cache_size` | `integer` | `OTEL_EBPF_BPF_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.override_bpfloop_enabled` | `boolean` | `OTEL_EBPF_OVERRIDE_BPF_LOOP_ENABLED` | `false` |  |  |  |
| `ebpf.postgres_prepared_statements_cache_size` | `integer` | `OTEL_EBPF_BPF_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE` | `1024` |  |  |  |
| `ebpf.protocol_debug_print` | `boolean` | `OTEL_EBPF_PROTOCOL_DEBUG_PRINT` | `false` |  |  |  |
| `ebpf.stats_wakeup_data_bytes` | `integer` | `OTEL_EBPF_STATS_WAKEUP_DATA_BYTES` | `4096` |  |  |  |
| `ebpf.track_request_headers` | `boolean` | `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS` | `false` |  |  |  |
| `ebpf.traffic_control_backend` | `string` | `OTEL_EBPF_BPF_TC_BACKEND` | `auto` | `auto`, `tc`, `tcx` |  |  |
| `ebpf.wakeup_len` | `integer` | `OTEL_EBPF_BPF_WAKEUP_LEN` | `500` |  |  |  |

### `ebpf.buffer_sizes`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.buffer_sizes.aerospike` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_AEROSPIKE` | `0` |  |  |  |
| `ebpf.buffer_sizes.http` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_HTTP` | `0` |  |  |  |
| `ebpf.buffer_sizes.kafka` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA` | `0` |  |  |  |
| `ebpf.buffer_sizes.mssql` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_MSSQL` | `0` |  |  |  |
| `ebpf.buffer_sizes.mysql` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL` | `0` |  |  |  |
| `ebpf.buffer_sizes.postgres` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES` | `0` |  |  |  |
| `ebpf.buffer_sizes.tcp` | `integer` | `OTEL_EBPF_BPF_BUFFER_SIZE_TCP` | `0` |  |  |  |

### `ebpf.log_enricher`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.log_enricher.async_writer_channel_len` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_CHANNEL_LEN` | `500` |  |  |  |
| `ebpf.log_enricher.async_writer_workers` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_WORKERS` | `8` |  |  |  |
| `ebpf.log_enricher.cache_size` | `integer` | `OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_SIZE` | `128` |  |  |  |
| `ebpf.log_enricher.cache_ttl` | `duration` | `OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_TTL` | `30m` | `30s`, `5m`, `1ms`, etc |  |  |
| `ebpf.log_enricher.field_names` | [`LogEnricherFieldNames`](#logenricherfieldnames) |  |  |  |  |  |
| `ebpf.log_enricher.plain_text` | [`LogEnricherPlainTextConfig`](#logenricherplaintextconfig) |  |  |  |  |  |
| `ebpf.log_enricher.services` | [`LogEnricherServiceConfig`](#logenricherserviceconfig)[] |  |  |  |  |  |

### `ebpf.payload_extraction`

#### `ebpf.payload_extraction.http`

#### `ebpf.payload_extraction.http.aws`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.aws.enabled` | `boolean` | `OTEL_EBPF_HTTP_AWS_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.elasticsearch`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.elasticsearch.enabled` | `boolean` | `OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.enrichment`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.enrichment.enabled` | `boolean` | `OTEL_EBPF_HTTP_ENRICHMENT_ENABLED` | `false` |  |  |  |
| `ebpf.payload_extraction.http.enrichment.rules` | [`HTTPParsingRule`](#httpparsingrule)[] |  |  |  |  |  |

#### `ebpf.payload_extraction.http.enrichment.policy`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.enrichment.policy.default_action` | [`HTTPParsingDefaultAction`](#httpparsingdefaultaction) |  |  |  |  |  |
| `ebpf.payload_extraction.http.enrichment.policy.obfuscation_string` | `string` | `OTEL_EBPF_HTTP_ENRICHMENT_OBFUSCATION_STRING` | `***` |  |  |  |

#### `ebpf.payload_extraction.http.genai`

#### `ebpf.payload_extraction.http.genai.anthropic`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.anthropic.enabled` | `boolean` | `OTEL_EBPF_HTTP_ANTHROPIC_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.bedrock`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.bedrock.enabled` | `boolean` | `OTEL_EBPF_HTTP_BEDROCK_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.embedding`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.embedding.enabled` | `boolean` | `OTEL_EBPF_HTTP_GENAI_EMBEDDING_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.gemini`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.gemini.enabled` | `boolean` | `OTEL_EBPF_HTTP_GEMINI_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.mcp`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.mcp.enabled` | `boolean` | `OTEL_EBPF_HTTP_MCP_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.ollama`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.ollama.enabled` | `boolean` | `OTEL_EBPF_HTTP_OLLAMA_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.openai`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.openai.enabled` | `boolean` | `OTEL_EBPF_HTTP_OPENAI_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.openai_compatible`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.openai_compatible.enabled` | `boolean` | `OTEL_EBPF_HTTP_OPENAI_COMPATIBLE_ENABLED` | `false` |  |  |  |
| `ebpf.payload_extraction.http.genai.openai_compatible.gateways` | [`OpenAICompatibleGateway`](#openaicompatiblegateway)[] |  |  |  |  |  |

#### `ebpf.payload_extraction.http.genai.qwen`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.qwen.enabled` | `boolean` | `OTEL_EBPF_HTTP_QWEN_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.rerank`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.rerank.enabled` | `boolean` | `OTEL_EBPF_HTTP_RERANK_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.genai.retrieval`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.genai.retrieval.enabled` | `boolean` | `OTEL_EBPF_HTTP_RETRIEVAL_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.graphql`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.graphql.enabled` | `boolean` | `OTEL_EBPF_HTTP_GRAPHQL_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.jsonrpc`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.jsonrpc.enabled` | `boolean` | `OTEL_EBPF_HTTP_JSONRPC_ENABLED` | `false` |  |  |  |

#### `ebpf.payload_extraction.http.sqlpp`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.payload_extraction.http.sqlpp.enabled` | `boolean` | `OTEL_EBPF_HTTP_SQLPP_ENABLED` | `false` |  |  |  |
| `ebpf.payload_extraction.http.sqlpp.endpoint_patterns` | `string`[] | `OTEL_EBPF_HTTP_SQLPP_ENDPOINT_PATTERNS` | `/query/service` |  |  |  |

### `ebpf.redis_db_cache`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `ebpf.redis_db_cache.enabled` | `boolean` | `OTEL_EBPF_BPF_REDIS_DB_CACHE_ENABLED` | `false` |  |  |  |
| `ebpf.redis_db_cache.max_size` | `integer` | `OTEL_EBPF_BPF_REDIS_DB_CACHE_MAX_SIZE` | `1000` |  |  |  |

## `health_check`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `health_check.listen_address` | `ip` | `OTEL_EBPF_HEALTH_CHECK_LISTEN_ADDRESS` | `127.0.0.1` |  |  |  |
| `health_check.port` | `integer` | `OTEL_EBPF_HEALTH_CHECK_PORT` | `0` |  |  |  |
| `health_check.unix_socket_path` | `string` | `OTEL_EBPF_HEALTH_CHECK_UNIX_SOCKET_PATH` |  |  |  |  |

## `internal_metrics`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.bpf_metric_scrape_interval` | `duration` | `OTEL_EBPF_BPF_METRIC_SCRAPE_INTERVAL` | `15s` | `30s`, `5m`, `1ms`, etc |  |  |
| `internal_metrics.exporter` | `string` | `OTEL_EBPF_INTERNAL_METRICS_EXPORTER` | `disabled` | `disabled`, `otel`, `prometheus` |  |  |

### `internal_metrics.avoided_services`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.avoided_services.disabled` | `boolean` | `OTEL_EBPF_INTERNAL_METRICS_AVOIDED_SERVICES_DISABLED` | `false` |  |  |  |
| `internal_metrics.avoided_services.limit` | `integer` | `OTEL_EBPF_INTERNAL_METRICS_AVOIDED_SERVICES_LIMIT` | `2000` |  |  |  |

### `internal_metrics.prometheus`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.prometheus.path` | `string` | `OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH` | `/internal/metrics` |  |  |  |
| `internal_metrics.prometheus.port` | `integer` | `OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT` | `0` |  |  |  |

## `javaagent`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `javaagent.attach_timeout` | `duration` | `OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `javaagent.debug` | `boolean` | `OTEL_EBPF_JAVAAGENT_DEBUG` | `false` |  |  |  |
| `javaagent.debug_instrumentation` | `boolean` | `OTEL_EBPF_JAVAAGENT_DEBUG_INSTRUMENTATION` | `false` |  |  |  |
| `javaagent.enabled` | `boolean` | `OTEL_EBPF_JAVAAGENT_ENABLED` | `true` |  |  |  |

## `jvm_runtime_metrics`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `jvm_runtime_metrics.sampling_interval` | `duration` | `OBI_JVM_RUNTIME_METRICS_SAMPLING_INTERVAL` | `1s` | `30s`, `5m`, `1ms`, etc |  |  |

## `metrics`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `metrics.features` | `string`[] | `OTEL_EBPF_METRICS_FEATURES` | `256` | `*`, `all`, `application`, `application_host`, `application_runtime`, `application_service_graph`, `application_span_otel`, `ebpf`, `network`, `network_flow_packets`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_io`, `stats_tcp_retransmits`, `stats_tcp_rtt`, `application_span` (deprecated), `application_span_sizes` (deprecated) |  | List of metric features to enable. |

## `name_resolver`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `name_resolver.cache_expiry` | `duration` | `OTEL_EBPF_NAME_RESOLVER_CACHE_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  |  |
| `name_resolver.cache_len` | `integer` | `OTEL_EBPF_NAME_RESOLVER_CACHE_LEN` | `1024` |  |  |  |
| `name_resolver.sources` | `string`[] | `OTEL_EBPF_NAME_RESOLVER_SOURCES` | `k8s` | `dns`, `k8s`, `kube`, `kubernetes`, `rdns` |  |  |

## `network`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.agent_ip` | `ip` | `OTEL_EBPF_NETWORK_AGENT_IP` |  |  |  |  |
| `network.agent_ip_iface` | `string` | `OTEL_EBPF_NETWORK_AGENT_IP_IFACE` | `external` | `external`, `local` |  | Specifies which interface should the agent pick the IP address from in order to report it in the AgentIP field on each flow. Accepted values are: external, local, or name:<interface name> (e.g. name:eth0). |
| `network.agent_ip_type` | `string` | `OTEL_EBPF_NETWORK_AGENT_IP_TYPE` | `any` | `any`, `ipv4`, `ipv6` |  |  |
| `network.cache_active_timeout` | `duration` | `OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT` | `5s` | `30s`, `5m`, `1ms`, etc |  |  |
| `network.cache_max_flows` | `integer` | `OTEL_EBPF_NETWORK_CACHE_MAX_FLOWS` | `5000` |  |  |  |
| `network.cidrs` | `string`[] | `OTEL_EBPF_NETWORK_CIDRS` |  |  |  | A list of CIDRs to be set as the "src.cidr" and "dst.cidr" attribute as a function of the source and destination IP addresses. Each entry can be a plain CIDR string or an object with "cidr" and "name" fields. |
| `network.deduper` | `string` | `OTEL_EBPF_NETWORK_DEDUPER` | `first_come` | `first_come`, `none` |  |  |
| `network.deduper_fc_ttl` | `duration` | `OTEL_EBPF_NETWORK_DEDUPER_FC_TTL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `network.direction` | `string` | `OTEL_EBPF_NETWORK_DIRECTION` | `both` | `both`, `egress`, `ingress` |  |  |
| `network.enable` | `boolean` | `OTEL_EBPF_NETWORK_METRICS` | `false` |  |  |  |
| `network.exclude_interfaces` | `string`[] | `OTEL_EBPF_NETWORK_EXCLUDE_INTERFACES` | `lo` |  |  |  |
| `network.exclude_protocols` | `string`[] | `OTEL_EBPF_NETWORK_EXCLUDE_PROTOCOLS` |  |  |  |  |
| `network.guess_ports` | `string` | `OTEL_EBPF_NETWORK_GUESS_PORTS` | `disable` | `disable`, `ordinal` |  |  |
| `network.interfaces` | `string`[] | `OTEL_EBPF_NETWORK_INTERFACES` |  |  |  |  |
| `network.listen_interfaces` | `string` | `OTEL_EBPF_NETWORK_LISTEN_INTERFACES` | `watch` | `poll`, `watch` |  |  |
| `network.listen_poll_period` | `duration` | `OTEL_EBPF_NETWORK_LISTEN_POLL_PERIOD` | `10s` | `30s`, `5m`, `1ms`, etc |  |  |
| `network.print_flows` | `boolean` | `OTEL_EBPF_NETWORK_PRINT_FLOWS` | `false` |  |  |  |
| `network.protocols` | `string`[] | `OTEL_EBPF_NETWORK_PROTOCOLS` |  |  |  |  |
| `network.sampling` | `integer` | `OTEL_EBPF_NETWORK_SAMPLING` | `0` |  |  |  |
| `network.source` | `string` | `OTEL_EBPF_NETWORK_SOURCE` | `socket_filter` | `socket_filter`, `tc` |  |  |

### `network.geo_ip`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.cache_expiry` | `duration` | `OTEL_EBPF_GEOIP_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  |  |
| `network.geo_ip.cache_len` | `integer` | `OTEL_EBPF_GEOIP_CACHE_LEN` | `512` |  |  |  |

#### `network.geo_ip.ipinfo`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.ipinfo.path` | `string` | `OTEL_EBPF_GEOIP_IPINFO_PATH` |  |  |  |  |

#### `network.geo_ip.maxmind`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.geo_ip.maxmind.asn_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_ASN_PATH` |  |  |  |  |
| `network.geo_ip.maxmind.country_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_COUNTRY_PATH` |  |  |  |  |

### `network.reverse_dns`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `network.reverse_dns.cache_expiry` | `duration` | `OTEL_EBPF_REVERSE_DNS_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  |  |
| `network.reverse_dns.cache_len` | `integer` | `OTEL_EBPF_REVERSE_DNS_CACHE_LEN` | `256` |  |  |  |
| `network.reverse_dns.type` | `string` | `OTEL_EBPF_REVERSE_DNS_TYPE` | `none` | `ebpf`, `local`, `none` |  |  |

## `nodejs`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `nodejs.enabled` | `boolean` | `OTEL_EBPF_NODEJS_ENABLED` | `true` |  |  |  |
| `nodejs.manual_spans` | `boolean` | `OTEL_EBPF_NODEJS_MANUAL_SPANS` | `false` |  |  |  |

## `otel_metrics_export`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
|  | `integer` | `OTEL_METRIC_EXPORT_INTERVAL` | `60000` |  |  |  |
| `otel_metrics_export.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `otel_metrics_export.buckets` | [`Buckets`](#buckets) |  |  |  |  |  |
| `otel_metrics_export.endpoint` | `uri` | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` |  |  |  |  |
| `otel_metrics_export.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  |  |
| `otel_metrics_export.features` | `string`[] |  | `0` | `*`, `all`, `application`, `application_host`, `application_runtime`, `application_service_graph`, `application_span_otel`, `ebpf`, `network`, `network_flow_packets`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_io`, `stats_tcp_retransmits`, `stats_tcp_rtt`, `application_span` (deprecated), `application_span_sizes` (deprecated) |  | List of metric features to enable. |
| `otel_metrics_export.histogram_aggregation` | `string` | `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` | `explicit_bucket_histogram` | `base2_exponential_bucket_histogram`, `explicit_bucket_histogram` |  |  |
| `otel_metrics_export.insecure_skip_verify` | `boolean` | `OTEL_EBPF_INSECURE_SKIP_VERIFY` | `false` |  |  |  |
| `otel_metrics_export.instrumentations` | `string`[] | `OTEL_EBPF_METRICS_INSTRUMENTATIONS` | `*` | `*`, `aerospike`, `amqp`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `nats`, `redis`, `sql`, `sunrpc` |  |  |
| `otel_metrics_export.interval` | `duration` | `OTEL_EBPF_METRICS_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_metrics_export.otel_sdk_log_level` | `string` | `OTEL_EBPF_SDK_LOG_LEVEL` |  |  |  |  |
| `otel_metrics_export.protocol` | `string` | `OTEL_EXPORTER_OTLP_PROTOCOL` |  | ``, `debug`, `grpc`, `http/json`, `http/protobuf` |  |  |
| `otel_metrics_export.reporters_cache_len` | `integer` | `OTEL_EBPF_METRICS_REPORT_CACHE_LEN` | `256` |  |  |  |
| `otel_metrics_export.ttl` | `duration` | `OTEL_EBPF_METRICS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  |  |

### `otel_metrics_export.exponential_histogram`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `otel_metrics_export.exponential_histogram.max_scale` | `integer` | `OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE` | `20` |  |  |  |
| `otel_metrics_export.exponential_histogram.max_size` | `integer` | `OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SIZE` | `160` |  |  |  |

## `otel_traces_export`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `otel_traces_export.backoff_initial_interval` | `duration` | `OTEL_EBPF_BACKOFF_INITIAL_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_traces_export.backoff_max_elapsed_time` | `duration` | `OTEL_EBPF_BACKOFF_MAX_ELAPSED_TIME` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_traces_export.backoff_max_interval` | `duration` | `OTEL_EBPF_BACKOFF_MAX_INTERVAL` | `0s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_traces_export.batch_max_size` | `integer` | `OTEL_EBPF_OTLP_TRACES_BATCH_MAX_SIZE` | `4096` |  |  |  |
| `otel_traces_export.batch_timeout` | `duration` | `OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT` | `15s` | `30s`, `5m`, `1ms`, etc |  |  |
| `otel_traces_export.endpoint` | `uri` | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` |  |  |  |  |
| `otel_traces_export.insecure_skip_verify` | `boolean` | `OTEL_EBPF_INSECURE_SKIP_VERIFY` | `false` |  |  |  |
| `otel_traces_export.instrumentations` | `string`[] | `OTEL_EBPF_TRACES_INSTRUMENTATIONS` | `http`, `grpc`, `sql`, `redis`, `kafka`, `mqtt`, `nats`, `amqp`, `mongo`, `couchbase`, `memcached`, `sunrpc`, `aerospike` | `*`, `aerospike`, `amqp`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `nats`, `redis`, `sql`, `sunrpc` |  |  |
| `otel_traces_export.otel_sdk_log_level` | `string` | `OTEL_EBPF_SDK_LOG_LEVEL` |  |  |  |  |
| `otel_traces_export.protocol` | `string` | `OTEL_EXPORTER_OTLP_PROTOCOL` |  | ``, `debug`, `grpc`, `http/json`, `http/protobuf` |  |  |
| `otel_traces_export.queue_size` | `integer` | `OTEL_EBPF_OTLP_TRACES_QUEUE_SIZE` | `16384` |  |  |  |
| `otel_traces_export.reporters_cache_len` | `integer` | `OTEL_EBPF_TRACES_REPORT_CACHE_LEN` | `256` |  |  |  |

### `otel_traces_export.sampler`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `otel_traces_export.sampler.arg` | `string` | `OTEL_TRACES_SAMPLER_ARG` |  |  |  |  |
| `otel_traces_export.sampler.name` | `string` | `OTEL_TRACES_SAMPLER` |  | `always_off`, `always_on`, `parentbased_always_off`, `parentbased_always_on`, `parentbased_traceidratio`, `traceidratio` |  |  |

## `prometheus_export`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `prometheus_export.allow_service_graph_self_references` | `boolean` | `OTEL_EBPF_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | `false` |  |  |  |
| `prometheus_export.buckets` | [`Buckets`](#buckets) |  |  |  |  |  |
| `prometheus_export.disable_build_info` | `boolean` | `OTEL_EBPF_PROMETHEUS_DISABLE_BUILD_INFO` | `false` |  |  |  |
| `prometheus_export.exemplar_filter` | `string` | `OTEL_EBPF_PROMETHEUS_EXEMPLAR_FILTER` |  |  |  |  |
| `prometheus_export.extra_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES` |  |  |  |  |
| `prometheus_export.extra_span_resource_attributes` | `string`[] | `OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES` |  |  |  |  |
| `prometheus_export.features` | `string`[] | `OTEL_EBPF_PROMETHEUS_FEATURES` | `0` | `*`, `all`, `application`, `application_host`, `application_runtime`, `application_service_graph`, `application_span_otel`, `ebpf`, `network`, `network_flow_packets`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_io`, `stats_tcp_retransmits`, `stats_tcp_rtt`, `application_span` (deprecated), `application_span_sizes` (deprecated) |  | List of metric features to enable. |
| `prometheus_export.instrumentations` | `string`[] | `OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS` | `*` | `*`, `aerospike`, `amqp`, `couchbase`, `dns`, `genai`, `gpu`, `grpc`, `http`, `kafka`, `memcached`, `mongo`, `mqtt`, `nats`, `redis`, `sql`, `sunrpc` |  |  |
| `prometheus_export.path` | `string` | `OTEL_EBPF_PROMETHEUS_PATH` | `/metrics` |  |  |  |
| `prometheus_export.port` | `integer` | `OTEL_EBPF_PROMETHEUS_PORT` | `0` |  |  |  |
| `prometheus_export.service_cache_size` | `integer` |  | `10000` |  |  |  |
| `prometheus_export.ttl` | `duration` | `OTEL_EBPF_PROMETHEUS_TTL` | `5m` | `30s`, `5m`, `1ms`, etc |  |  |

### `prometheus_export.native_histogram`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `prometheus_export.native_histogram.bucket_factor` | `number` | `OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_BUCKET_FACTOR` | `1.1` |  |  |  |
| `prometheus_export.native_histogram.max_bucket_number` | `integer` | `OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_MAX_BUCKET_NUMBER` | `100` |  |  |  |
| `prometheus_export.native_histogram.min_reset_duration` | `duration` | `OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_MIN_RESET_DURATION` | `60m` | `30s`, `5m`, `1ms`, etc |  |  |

## `stats`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.agent_ip` | `ip` | `OTEL_EBPF_STATS_AGENT_IP` |  |  |  |  |
| `stats.agent_ip_iface` | `string` | `OTEL_EBPF_STATS_AGENT_IP_IFACE` | `external` | `external`, `local` |  | Specifies which interface should the agent pick the IP address from in order to report it in the AgentIP field on each flow. Accepted values are: external, local, or name:<interface name> (e.g. name:eth0). |
| `stats.agent_ip_type` | `string` | `OTEL_EBPF_STATS_AGENT_IP_TYPE` | `any` | `any`, `ipv4`, `ipv6` |  |  |
| `stats.cidrs` | `string`[] | `OTEL_EBPF_STATS_CIDRS` |  |  |  | A list of CIDRs to be set as the "src.cidr" and "dst.cidr" attribute as a function of the source and destination IP addresses. Each entry can be a plain CIDR string or an object with "cidr" and "name" fields. |
| `stats.print_stats` | `boolean` | `OTEL_EBPF_STATS_PRINT_STATS` | `false` |  |  |  |

### `stats.geo_ip`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.cache_expiry` | `duration` | `OTEL_EBPF_GEOIP_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  |  |
| `stats.geo_ip.cache_len` | `integer` | `OTEL_EBPF_GEOIP_CACHE_LEN` | `512` |  |  |  |

#### `stats.geo_ip.ipinfo`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.ipinfo.path` | `string` | `OTEL_EBPF_GEOIP_IPINFO_PATH` |  |  |  |  |

#### `stats.geo_ip.maxmind`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.geo_ip.maxmind.asn_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_ASN_PATH` |  |  |  |  |
| `stats.geo_ip.maxmind.country_path` | `string` | `OTEL_EBPF_GEOIP_MAXMIND_COUNTRY_PATH` |  |  |  |  |

### `stats.reverse_dns`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `stats.reverse_dns.cache_expiry` | `duration` | `OTEL_EBPF_REVERSE_DNS_CACHE_TTL` | `60m` | `30s`, `5m`, `1ms`, etc |  |  |
| `stats.reverse_dns.cache_len` | `integer` | `OTEL_EBPF_REVERSE_DNS_CACHE_LEN` | `256` |  |  |  |
| `stats.reverse_dns.type` | `string` | `OTEL_EBPF_REVERSE_DNS_TYPE` | `none` | `ebpf`, `local`, `none` |  |  |

---

## Type Definitions

### AttributesConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `application` | [`AttributeFamilyConfig`](#attributefamilyconfig) |  |  |
| `network` | [`AttributeFamilyConfig`](#attributefamilyconfig) |  |  |
| `stats` | [`AttributeFamilyConfig`](#attributefamilyconfig) |  |  |

### Buckets

| Field | Type | Values | Description |
|---|---|---|---|
| `duration_histogram` | `number`[] |  |  |
| `gen_ai_client_operation_duration_histogram` | `number`[] |  |  |
| `gen_ai_client_token_usage_histogram` | `number`[] |  |  |
| `request_size_histogram` | `number`[] |  |  |
| `response_size_histogram` | `number`[] |  |  |
| `stat_tcp_rtt_histogram` | `number`[] |  |  |

### ExtraGroupAttributesMap

Map of attribute group names to arrays of attribute names. Only 'k8s_app_meta' is currently supported as a key.

**Known keys:** `k8s_app_meta`

**Value type:** `string[]`

### GlobAttributes

| Field | Type | Values | Description |
|---|---|---|---|
| `cmd_args` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `container_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `containers_only` | `boolean` |  |  |
| `exe_path` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `exports` | `string`[] | `logs`, `metrics`, `traces` | List of signals to export. If undefined or null, all signals are exported. If an empty list, no signals are exported. |
| `k8s_container_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_cronjob_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_daemonset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_deployment_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_job_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_namespace` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_owner_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_pod_annotations` | `map[string]string` |  |  |
| `k8s_pod_labels` | `map[string]string` |  |  |
| `k8s_pod_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_replicaset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `k8s_statefulset_name` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `languages` | `glob` | `app-*`, `service-??`, `prod-*-db`, etc | Glob pattern to match against the attribute value |
| `metrics` | [`SvcMetricsConfig`](#svcmetricsconfig) |  |  |
| `name` | `string` |  |  |
| `namespace` | `string` |  |  |
| `open_ports` | [`IntEnum`](#intenum) |  |  |
| `routes` | [`CustomRoutesConfig`](#customroutesconfig) |  |  |
| `sampler` | [`SamplerConfig`](#samplerconfig) |  |  |
| `target_pids` | `integer`[] |  |  |

### HTTPParsingDefaultAction

| Field | Type | Values | Description |
|---|---|---|---|
| `body` | `string` | `exclude`, `include`, `obfuscate` |  |
| `headers` | `string` | `exclude`, `include`, `obfuscate` |  |

### HTTPParsingRule

| Field | Type | Values | Description |
|---|---|---|---|
| `action` | `string` | `exclude`, `include`, `obfuscate` |  |
| `match` | [`HTTPParsingMatch`](#httpparsingmatch) |  |  |
| `obfuscation_string` | `string` |  |  |
| `scope` | `string` | `all`, `request`, `response` |  |
| `type` | `string` | `body`, `headers` |  |

### IntEnum

| Field | Type | Values | Description |
|---|---|---|---|
| `Ranges` | `string`[] | `1`, `1000`, `8080-8090`, `80,443,8000-8999`, etc |  |

### LogEnricherFieldNames

| Field | Type | Values | Description |
|---|---|---|---|
| `span_id` | `string` |  |  |
| `trace_id` | `string` |  |  |

### LogEnricherPlainTextConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `enabled` | `boolean` |  |  |
| `multiline` | `string` | `each_line`, `first_line`, `last_line` |  |
| `placement` | `string` | `prefix`, `suffix` |  |

### LogEnricherServiceConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `service` | [`GlobAttributes`](#globattributes)[] |  |  |

### MapsConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `global_scale_factor` | `integer` |  |  |

### OpenAICompatibleGateway

| Field | Type | Values | Description |
|---|---|---|---|
| `host` | `string` |  |  |
| `port` | `integer` |  |  |
| `provider` | `string` |  |  |

### RegexSelector

| Field | Type | Values | Description |
|---|---|---|---|
| `cmd_args` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `container_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `containers_only` | `boolean` |  |  |
| `exe_path` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `exe_path_regexp` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `exports` | `string`[] | `logs`, `metrics`, `traces` | List of signals to export. If undefined or null, all signals are exported. If an empty list, no signals are exported. |
| `k8s_container_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_cronjob_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_daemonset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_deployment_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_job_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_namespace` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_owner_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_pod_annotations` | `map[string]string` |  |  |
| `k8s_pod_labels` | `map[string]string` |  |  |
| `k8s_pod_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_replicaset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `k8s_statefulset_name` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `languages` | `regex` | `^app-.*`, `^service-..$`, `^prod-.*-db$`, etc | Regular expression to match against the executable file path |
| `metrics` | [`SvcMetricsConfig`](#svcmetricsconfig) |  |  |
| `name` | `string` |  |  |
| `namespace` | `string` |  |  |
| `open_ports` | [`IntEnum`](#intenum) |  |  |
| `routes` | [`CustomRoutesConfig`](#customroutesconfig) |  |  |
| `sampler` | [`SamplerConfig`](#samplerconfig) |  |  |
| `target_pids` | `integer`[] |  |  |

### RoutesConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `ignore_mode` | `string` | `all`, `metrics`, `traces` |  |
| `ignored_patterns` | `string`[] |  |  |
| `max_path_segment_cardinality` | `integer` |  |  |
| `patterns` | `string`[] |  |  |
| `unmatched` | `string` | `heuristic`, `low-cardinality`, `path`, `unset`, `wildcard` |  |
| `wildcard_char` | `string` |  |  |

### SensitiveQueryParamsConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `add` | `string`[] |  |  |
| `remove` | `string`[] |  |  |

### AttributeFamilyConfig

**Value type:** `object`

### CustomRoutesConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `incoming` | `string`[] |  |  |
| `outgoing` | `string`[] |  |  |

### HTTPParsingMatch

| Field | Type | Values | Description |
|---|---|---|---|
| `case_sensitive` | `boolean` |  |  |
| `methods` | `string`[] | `DELETE`, `GET`, `HEAD`, `OPTIONS`, `PATCH`, `POST`, `PUT` |  |
| `obfuscation_json_paths` | `string`[] | `$.password`, `$.user.name`, `$.items[0].id`, etc |  |
| `patterns` | `glob`[] | `app-*`, `service-??`, `prod-*-db`, etc |  |
| `response_status_code` | [`NumericRange`](#numericrange) |  |  |
| `url_path_patterns` | `glob`[] | `app-*`, `service-??`, `prod-*-db`, etc |  |

### SamplerConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `arg` | `string` |  |  |
| `name` | `string` | `always_off`, `always_on`, `parentbased_always_off`, `parentbased_always_on`, `parentbased_traceidratio`, `traceidratio` |  |

### SvcMetricsConfig

| Field | Type | Values | Description |
|---|---|---|---|
| `features` | `string`[] | `*`, `all`, `application`, `application_host`, `application_runtime`, `application_service_graph`, `application_span_otel`, `ebpf`, `network`, `network_flow_packets`, `network_inter_zone`, `stats`, `stats_tcp_failed_connections`, `stats_tcp_io`, `stats_tcp_retransmits`, `stats_tcp_rtt`, `application_span` (deprecated), `application_span_sizes` (deprecated) | List of metric features to enable. |

### NumericRange

| Field | Type | Values | Description |
|---|---|---|---|
| `equals` | `integer` |  |  |
| `greater_equals` | `integer` |  |  |
| `greater_than` | `integer` |  |  |
| `less_equals` | `integer` |  |  |
| `less_than` | `integer` |  |  |
| `not_equals` | `integer` |  |  |
