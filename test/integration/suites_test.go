// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
	"go.opentelemetry.io/obi/test/integration/components/docker"
)

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=(pingclient|testserver)`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("RED JSON RPC metrics", testREDMetricsJSONRPCHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("HTTP traces (no traceID)", testHTTPTracesNoTraceID)
	t.Run("HTTP traces (manual spans)", testHTTPTracesNestedManualSpans)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("GRPC TLS RED metrics", testREDMetricsGRPCTLS)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	t.Run("Exemplars exist", testExemplarsExist)
	t.Run("Testing Host Info metric", testHostInfo)
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)

	require.NoError(t, compose.Close())
}

func TestSuiteNestedTraces(t *testing.T) {
	// We run the test depending on what the host environment is. If the host is in lockdown mode integrity
	// the nesting of spans will be limited. If we are in none (which should be in any non secure boot environment, e.g. Virtual Machines or CI)
	// then we expect full nesting of trace spans in this test.

	// Echo (server) -> echo (client) -> EchoBack (server)
	lockdown := KernelLockdownMode()
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-nested.log"))
	require.NoError(t, err)

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}
	require.NoError(t, compose.Up())
	if !lockdown {
		t.Run("HTTP traces (all spans nested)", testHTTPTracesNestedClientWithContextPropagation)
		t.Run("HTTP -> gRPC traces (all spans nested)", testHTTP2GRPCTracesNestedCallsWithContextPropagation)
	} else {
		t.Run("HTTP traces (nested client span)", testHTTPTracesNestedClient)
		t.Run("HTTP -> gRPC traces (nested client span)", testHTTP2GRPCTracesNestedCallsNoPropagation)
	}
	require.NoError(t, compose.Close())
}

func TestSuiteClientPromScrape(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client-promscrape.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=pingclient`)
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
	)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibraryNoTraces)
	t.Run("Testing OBI Build Info metric", testPrometheusOBIBuildInfo)
	t.Run("Testing Host Info metric", testHostInfo)

	require.NoError(t, compose.Close())
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_NoDebugInfo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-nodebug.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_nodebug`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	require.NoError(t, compose.Close())
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_StaticCompilation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-static.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_static`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	require.NoError(t, compose.Close())
}

func TestSuite_OldestGoVersion(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-1.17.yml", path.Join(pathOutput, "test-suite-oldest-go.log"))
	require.NoError(t, err)

	compose.Env = []string{`OTEL_GO_AUTO_TARGET_EXE=*testserver`}
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsOldHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("HTTP traces (manual spans)", testHTTPTracesNestedManualSpans)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	require.NoError(t, compose.Close())
}

func TestSuite_UnsupportedGoVersion(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose-1.16.yml", path.Join(pathOutput, "test-suite-unsupported-go.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsUnsupportedHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_SkipGoTracers(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-skip-go-tracers.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsShortHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_GRPCExport(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-grpc-export.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("trace HTTP service and export as GRPC traces", testHTTPTraces)
	t.Run("trace GRPC service and export as GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)

	require.NoError(t, compose.Close())
}

func TestSuite_GRPCExportKProbes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-grpc-export-kprobes.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	compose.Env = append(compose.Env, `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, compose.Up())

	waitForTestComponents(t, instrumentedServiceStdURL)

	t.Run("trace GRPC service and export as GRPC traces - kprobes", testGRPCKProbeTraces)
	t.Run("GRPC RED metrics - kprobes", testREDMetricsGRPC)

	require.NoError(t, compose.Close())
}

// Instead of submitting metrics via OTEL, exposes them as an obi:8999/metrics endpoint
// that is scraped by the Prometheus server
func TestSuite_PrometheusScrape(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-promscrape.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`OTEL_EBPF_OPEN_PORT=8082,8999`, // force OBI self-instrumentation to ensure we don't do it
	)

	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	t.Run("Testing OBI Build Info metric", testPrometheusOBIBuildInfo)
	t.Run("Testing for no OBI self metrics", testPrometheusNoOBIEvents)
	t.Run("Testing BPF metrics", testPrometheusBPFMetrics)

	require.NoError(t, compose.Close())
}

func TestSuite_Java(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-pid.yml", path.Join(pathOutput, "test-suite-java-pid.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java-openport.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	require.NoError(t, compose.Close())
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-host.yml", path.Join(pathOutput, "test-suite-java-host-network.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaOTelSDK(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-agent.yml", path.Join(pathOutput, "test-suite-java-agent.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-jar`, `JAVA_OPEN_PORT=8085`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics with OTel SDK injection", testREDMetricsJavaOTelSDKHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_Rust(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8090`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8091:8090`)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_RustSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTPS)
	require.NoError(t, compose.Close())
}

// The actix server that we built our Rust example will enable HTTP2 for SSL automatically if the client supports it.
// We use this feature to implement our kprobes HTTP2 tests, with special http client settings that triggers the Go
// client to attempt http connection.
func TestSuite_RustHTTP2(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-http2.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`)

	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP2)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`, `NODE_APP=app`)
	require.NoError(t, compose.Up())
	t.Run("NodeJS RED metrics", testREDMetricsNodeJSHTTP)
	t.Run("HTTP traces (kprobes)", testHTTPTracesKProbes)
	t.Run("HTTP nested traces large HTTPS (kprobes)", testHTTPTracesNestedNodeJSLargeHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3033`, `OTEL_EBPF_EXECUTABLE_PATH=`, `NODE_APP=app_tls`)
	require.NoError(t, compose.Up())
	t.Run("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_Rails(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3043`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TEST_SERVICE_PORTS=3044:3043`)
	require.NoError(t, compose.Up())
	t.Run("Rails SSL RED metrics", testREDMetricsRailsHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_DotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=5266`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("DotNet RED metrics", testREDMetricsDotNetHTTP)
	require.NoError(t, compose.Close())
}

// Disabled for now as we randomly fail to register 3 events, but only get 2
// Issue: https://github.com/grafana/beyla/issues/208
func TestSuite_DotNetTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=7033`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	// Add these above if you want to get the trace_pipe output in the test logs: `INSTRUMENT_DOCKERFILE_SUFFIX=_dbg`, `INSTRUMENT_COMMAND_SUFFIX=_wrapper.sh`
	require.NoError(t, compose.Up())
	t.Run("DotNet SSL RED metrics", testREDMetricsDotNetHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_Python(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8380`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8380`)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonPostgres(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-postgresql.yml", path.Join(pathOutput, "test-suite-python-postgresql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Postgres tests", testPythonPostgres)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMySQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mysql.yml", path.Join(pathOutput, "test-suite-python-mysql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python MySQL tests", testPythonMySQL)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonKafka(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-kafka.yml", path.Join(pathOutput, "test-suite-python-kafka.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python Kafka tests", testREDMetricsPythonKafkaOnly)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafka(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-kafka-400.yml", path.Join(pathOutput, "test-suite-java-kafka.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", testJavaKafka)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonRedis(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-redis.yml", path.Join(pathOutput, "test-suite-python-redis.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Redis metrics", testREDMetricsPythonRedisOnly)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMongo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mongo.yml", path.Join(pathOutput, "test-suite-python-mongo.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Mongo metrics", testREDMetricsPythonMongoOnly)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSQLSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql-ssl.yml", path.Join(pathOutput, "test-suite-python-sql-ssl.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLSSL)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8380`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8380`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSelfReference(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-self.yml", path.Join(pathOutput, "test-suite-python-self.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=7771`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("Python Traces with self-references", testHTTPTracesNestedSelfCalls)
	t.Run("Python Traces transaction too long", testHTTPTracesNestedCallsTooLong)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonGraphQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-graphql.yml", path.Join(pathOutput, "test-suite-python-graphql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python GraphQL", testPythonGraphQL)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonElasticsearch(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elasticsearch.yml", path.Join(pathOutput, "test-suite-elasticsearch.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Elasticsearch", testPythonElasticsearch)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAWSS3(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-aws-s3.yml", path.Join(pathOutput, "test-suite-python-aws-s3.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python AWS S3", testPythonAWSS3)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSDist(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs-dist.yml", path.Join(pathOutput, "test-suite-nodejs-dist.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("NodeJS Distributed Traces with multiple chained calls", testHTTPTracesNestedNodeJSDistCalls)
	require.NoError(t, compose.Close())
}

func TestSuite_DisableKeepAlives(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-disablekeepalives.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	// Run tests with keepalives disabled:
	setHTTPClientDisableKeepAlives(true)
	t.Run("RED metrics", testREDMetricsHTTP)

	t.Run("HTTP DisableKeepAlives traces", testHTTPTraces)
	t.Run("Internal Prometheus DisableKeepAlives metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	// Reset to defaults for any tests run afterward
	setHTTPClientDisableKeepAlives(false)

	require.NoError(t, compose.Close())
}

func TestSuite_OverrideServiceName(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-override-svcname.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-override-svcname")
	require.NoError(t, compose.Up())

	// Just few simple test cases to verify that the tracers properly override the service name
	// according to the configuration
	t.Run("RED metrics", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "overridden-svc-name", "integration-test")
	})
	t.Run("GRPC traces", func(t *testing.T) {
		testGRPCTracesForServiceName(t, "overridden-svc-name")
	})

	require.NoError(t, compose.Close())
}

func TestSuiteNodeClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	require.NoError(t, compose.Close())
}

func TestSuiteNodeClientTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client_tls`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-no-routes.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-no-route")
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTPNoRoute)
	require.NoError(t, compose.Close())
}

func TestSuite_Elixir(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elixir.yml", path.Join(pathOutput, "test-suite-elixir.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Elixir RED metrics", testREDMetricsElixirHTTP)
	require.NoError(t, compose.Close())
}

// Helpers

var lockdownPath = "/sys/kernel/security/lockdown"

func KernelLockdownMode() bool {
	// If we can't find the file, assume no lockdown
	if _, err := os.Stat(lockdownPath); err == nil {
		f, err := os.Open(lockdownPath)
		if err != nil {
			return true
		}

		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			lockdown := scanner.Text()
			switch {
			case strings.Contains(lockdown, "[none]"):
				return false
			case strings.Contains(lockdown, "[integrity]"):
				return true
			case strings.Contains(lockdown, "[confidentiality]"):
				return true
			default:
				return true
			}
		}

		return true
	}

	return false
}
