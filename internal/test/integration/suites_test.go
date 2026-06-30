// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// Digest-pinned obi-testimg references. These were previously selected at
// compose-time via `${JAVA_TEST_MODE}` / `${TESTSERVER_IMAGE_SUFFIX}`
// interpolation in the tag, which made it impossible to pin by sha256 and
// left the integration suite vulnerable to a compromise of the OBI ghcr
// publish workflow swapping in a malicious image.
const (
	obiTestImgJavaNative = "ghcr.io/open-telemetry/obi-testimg:java-native-0.1.1@sha256:063c5013cc4cccfd015a054d2595a4a09105eba549cb96e1a2aac7456f831b5b"
	obiTestImgJavaJar    = "ghcr.io/open-telemetry/obi-testimg:java-jar-0.1.1@sha256:474c4c5a836c99aa023ca8fb16693cd5f9edb5c22501c17069992fd4e87aaf48"
	obiTestImgRust       = "ghcr.io/open-telemetry/obi-testimg:rust-0.1.1@sha256:c818c207ff40f474e8f7cd183f58d47a0dce8030c89cf1b44bfc18a7f625da28"
	obiTestImgRustSSL    = "ghcr.io/open-telemetry/obi-testimg:rust-ssl-0.1.1@sha256:52868bb841454f657a3797c4d7cd255d5fa25e84e1d97be0c9ef6c59502a0a9b"
	obiTestImgRails      = "ghcr.io/open-telemetry/obi-testimg:rails-0.1.1@sha256:d51943f3b10e73a8e924c4cf2f06815172a7332ecfa4618765b2ba342dd7c10f"
	obiTestImgRailsSSL   = "ghcr.io/open-telemetry/obi-testimg:rails-ssl-0.1.1@sha256:770361b1480c2301829951c83230caa268a0761de255cdd2ef79885180f3245f"
)

func TestSuite_Go(t *testing.T) {
	type testCase struct {
		name string
		env  []string
	}

	for _, tc := range []testCase{
		{name: "go-old-supported"},
		{name: "go-latest", env: []string{"TESTSERVER_DOCKERFILE_SUFFIX=_latest", "PINGSERVER_DOCKERFILE_SUFFIX=_latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-"+tc.name+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=(pingclient|testserver)`)
			compose.Env = append(compose.Env, tc.env...)
			require.NoError(t, compose.Up())

			// Cleanups run LIFO: register `compose.Close()` first so it runs
			// last, *after* runWeaverValidation has had a chance to /stop the
			// still-running weaver container.
			t.Cleanup(func() {
				require.NoError(t, compose.Close())
			})
			t.Cleanup(func() {
				runWeaverValidation(t)
			})

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
			t.Run("Harvested auto routes", testREDMetricsHTTPAutoRoutes)
		})
	}
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
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteGoGeneric(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-generic.yml", path.Join(pathOutput, "test-suite-go-generic.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Generic Go HTTP/TCP traces (all spans nested)", testGoGenericHTTPTraces)
	t.Run("Generic Go HTTPS/TCP(TLS) traces (all spans nested)", testGoGenericHTTPSTraces)
	runWeaverValidation(t)
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

	runWeaverValidation(t)

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

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_OldestGoVersion(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-1.17.yml", path.Join(pathOutput, "test-suite-oldest-go.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_GO_AUTO_TARGET_EXE=*testserver`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsOldHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("HTTP traces (manual spans)", testHTTPTracesNestedManualSpans)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_SkipGoTracers(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-skip-go-tracers.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsShortHTTP)
	runWeaverValidation(t)
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

	runWeaverValidation(t)

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

	runWeaverValidation(t)

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
	t.Run("Exemplars exist", testExemplarsExist)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	t.Run("Testing OBI Build Info metric", testPrometheusOBIBuildInfo)
	t.Run("Testing for no OBI self metrics", testPrometheusNoOBIEvents)
	t.Run("Testing BPF metrics", testPrometheusBPFMetrics)

	require.NoError(t, compose.Close())
}

func TestSuite_Java(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `TESTSERVER_IMAGE=`+obiTestImgJavaNative)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-pid.yml", path.Join(pathOutput, "test-suite-java-pid.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=`+obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java-openport.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=`+obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-host.yml", path.Join(pathOutput, "test-suite-java-host-network.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `TESTSERVER_IMAGE=`+obiTestImgJavaNative)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Rust(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8090`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8091:8090`, `TESTSERVER_IMAGE=`+obiTestImgRust)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RustSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE=`+obiTestImgRustSSL)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

// The actix server that we built our Rust example will enable HTTP2 for SSL automatically if the client supports it.
// We use this feature to implement our kprobes HTTP2 tests, with special http client settings that triggers the Go
// client to attempt http connection.
func TestSuite_RustHTTP2(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-http2.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE=`+obiTestImgRustSSL)

	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP2)
	runWeaverValidation(t)
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
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3033`, `OTEL_EBPF_EXECUTABLE_PATH=`, `NODE_APP=app_tls`)
	require.NoError(t, compose.Up())
	t.Run("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Rails(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`, `TESTSERVER_IMAGE=`+obiTestImgRails)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsNginxSupportFloor(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-nginx-floor.log"))
	require.NoError(t, err)

	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=3040,443`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=3041:3040`,
		`NGINX_IMAGE=`+nginxReverseProxySupportFloorImage,
		`TESTSERVER_IMAGE=`+obiTestImgRails,
	)
	require.NoError(t, compose.Up())

	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsRuby302Puma5(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby-3.0.2-puma5.yml", path.Join(pathOutput, "test-suite-ruby-3.0.2-puma5.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, compose.Up())
	t.Run("Ruby/Puma support contract", func(t *testing.T) {
		assertRubyPumaSupportVersion(t, compose, "3.0.2", "5.6.6")
	})
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsNginxSQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby-nginx-sql.yml", path.Join(pathOutput, "test-suite-ruby-nginx-sql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX SQL traces nested", testHTTPTracesNestedNginxSQL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3043`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=`+obiTestImgRailsSSL, `TEST_SERVICE_PORTS=3044:3043`)
	require.NoError(t, compose.Up())
	t.Run("Rails SSL RED metrics", testREDMetricsRailsHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_DotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=5266`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("DotNet RED metrics", testREDMetricsDotNetHTTP)
	runWeaverValidation(t)
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
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Python(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python.log"))
	require.NoError(t, err)

	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`INSTRUMENTER_CONFIG_SUFFIX=-java`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonProm(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-prom.log"))
	require.NoError(t, err)

	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonPostgres(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-postgresql.yml", path.Join(pathOutput, "test-suite-python-postgresql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Postgres tests", testPythonPostgres)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMySQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mysql.yml", path.Join(pathOutput, "test-suite-python-mysql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python MySQL tests", testPythonMySQL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMSSQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mssql.yml", path.Join(pathOutput, "test-suite-python-mssql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python MSSQL tests", testPythonMSSQL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonKafka(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-kafka.yml", path.Join(pathOutput, "test-suite-python-kafka.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python Kafka tests", testREDMetricsPythonKafkaOnly)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_GoKafkaTraceparent(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-kafka-traceparent.yml", path.Join(pathOutput, "test-suite-go-kafka-traceparent.log"))
	// Discover by executable name: the Kafka broker and Zookeeper are Java processes
	// (Zookeeper's admin server also listens on 8080), so port-based discovery is
	// ambiguous under pid:host. Match only the Go "testserver" binary.
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=`, `OTEL_EBPF_EXECUTABLE_PATH=testserver`, `TEST_SERVICE_PORTS=8389:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Go Kafka stale traceparent contamination (#2046)", testGoKafkaTraceparent)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMQTT(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mqtt.yml", path.Join(pathOutput, "test-suite-python-mqtt.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python MQTT publish tests", testREDMetricsPythonMQTT)
	t.Run("Python MQTT subscribe tests", testREDMetricsPythonMQTTSubscribe)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_GoMQTT(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-mqtt.yml", path.Join(pathOutput, "test-suite-go-mqtt.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Go MQTT publish tests", testREDMetricsGoMQTT)
	require.NoError(t, compose.Close())
}

func TestSuite_GoSunRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-sunrpc.yml", path.Join(pathOutput, "test-suite-go-sunrpc.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Go SunRPC tests", testREDMetricsGoSunRPC)
	t.Run("Go SunRPC Prometheus metrics", testREDMetricsGoSunRPCPrometheus)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafka(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-kafka-400.yml", path.Join(pathOutput, "test-suite-java-kafka.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9092, "javakafka") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-kafka-400-tls.yml", path.Join(pathOutput, "test-suite-java-kafka.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9094, "java") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaLargeBuffer(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-kafka-400-lb.yml", path.Join(pathOutput, "test-suite-java-kafka-lb.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 large buffer tests", testJavaKafkaLargeBuffer)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAsyncUvloop_3_9(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-async-uvloop-3.9.yml", path.Join(pathOutput, "test-suite-python-async-uvloop-3_9.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Sequential", testPythonAsyncSequential)
	t.Run("Concurrent", testPythonAsyncConcurrent)
	t.Run("To Thread", testPythonAsyncToThread)
	t.Run("Nested", testPythonAsyncNested)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAsyncUvloop_3_14(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-async-uvloop-3.14.yml", path.Join(pathOutput, "test-suite-python-async-uvloop-3_14.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Sequential", testPythonAsyncSequential)
	t.Run("Concurrent", testPythonAsyncConcurrent)
	t.Run("To Thread", testPythonAsyncToThread)
	t.Run("Nested", testPythonAsyncNested)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonRedis(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-redis.yml", path.Join(pathOutput, "test-suite-python-redis.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Redis metrics", testREDMetricsPythonRedisOnly)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMongo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mongo.yml", path.Join(pathOutput, "test-suite-python-mongo.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Mongo metrics", testREDMetricsPythonMongoOnly)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonCouchbase(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-couchbase.yml", path.Join(pathOutput, "test-suite-python-couchbase.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Couchbase metrics", testREDMetricsPythonCouchbaseOnly)
	t.Run("Python Couchbase default collection", testREDMetricsPythonCouchbaseDefaultCollection)
	t.Run("Python Couchbase error", testREDMetricsPythonCouchbaseError)
	t.Run("Python Couchbase SQL++ metrics", testREDMetricsPythonCouchbaseSQLPP)
	t.Run("Python Couchbase SQL++ with context", testREDMetricsPythonCouchbaseSQLPPWithContext)
	t.Run("Python Couchbase SQL++ error", testREDMetricsPythonCouchbaseSQLPPError)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSQLSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql-ssl.yml", path.Join(pathOutput, "test-suite-python-sql-ssl.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLSSL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-tls.log"))
	require.NoError(t, err)

	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`TESTSERVER_DOCKERFILE_SUFFIX=_tls`,
		`INSTRUMENTER_CONFIG_SUFFIX=-java`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSelfReference(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-self.yml", path.Join(pathOutput, "test-suite-python-self.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=7771`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("Python Traces with self-references", testHTTPTracesNestedSelfCalls)
	t.Run("Python Traces transaction too long", testHTTPTracesNestedCallsTooLong)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonGraphQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-graphql.yml", path.Join(pathOutput, "test-suite-python-graphql.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python GraphQL", testPythonGraphQL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonJsonRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-jsonrpc.yml", path.Join(pathOutput, "test-suite-python-jsonrpc.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python JSON-RPC server span", testPythonJSONRPCServer)
	t.Run("Python JSON-RPC RPC metrics", testPythonJSONRPCMetrics)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMCP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-mcp.yml", path.Join(pathOutput, "test-suite-python-mcp.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python MCP server span", testPythonMCPServer)
	t.Run("Python MCP initialize", testPythonMCPInitialize)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonElasticsearch(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elasticsearch.yml", path.Join(pathOutput, "test-suite-elasticsearch.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python Elasticsearch", func(t *testing.T) {
		testPythonElasticsearch(t, "elasticsearch")
	})
	t.Run("Python Opensearch", func(t *testing.T) {
		testPythonElasticsearch(t, "opensearch")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAWSS3(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-aws.yml", path.Join(pathOutput, "test-suite-python-aws-s3.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python AWS S3", testPythonAWSS3)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAWSSQS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-aws.yml", path.Join(pathOutput, "test-suite-python-aws-sqs.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, compose.Up())
	t.Run("Python AWS SQS", testPythonAWSSQS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSDist(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs-dist.yml", path.Join(pathOutput, "test-suite-nodejs-dist.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())
	t.Run("NodeJS Distributed Traces with multiple chained calls", testHTTPTracesNestedNodeJSDistCalls)
	runWeaverValidation(t)
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

	runWeaverValidation(t)

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

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuiteNodeClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNodeClientTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient-tls.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client_tls`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-no-routes.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-no-route")
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTPNoRoute)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutesLowCardinality(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-no-routes-low-cardinality.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-no-route-lc")
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTPNoRouteLowCardinality)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Elixir(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elixir.yml", path.Join(pathOutput, "test-suite-elixir.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Elixir RED metrics", testREDMetricsElixirHTTP)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherHTTP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-http.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8380`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher HTTP", func(t *testing.T) {
		testLogEnricher(t, logEnricherHTTPConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherGoGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-go-grpc.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=50051`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Go gRPC", func(t *testing.T) {
		testLogEnricher(t, logEnricherGoGRPCConstants)
	})
	t.Run("Log Enricher Go writev clamp", func(t *testing.T) {
		testLogEnricherWritevClamp(t, logEnricherGoWritevRegressionConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherNodeJS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-nodejs.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Node.js", func(t *testing.T) {
		testLogEnricherNodeJS(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherJava(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-java.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8085`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Java", func(t *testing.T) {
		testLogEnricherJava(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherRuby(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-ruby.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Ruby puts (writev)", func(t *testing.T) {
		testLogEnricherRuby(t, logEnricherRubyWritevConstants)
	})
	t.Run("Log Enricher Ruby syswrite (write)", func(t *testing.T) {
		testLogEnricherRuby(t, logEnricherRubyWriteConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherDotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-dotnet.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=5266`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher .NET", func(t *testing.T) {
		testLogEnricherDotNet(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherPythonAsync(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-pythonasync.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8391`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Python async", func(t *testing.T) {
		testLogEnricherPythonAsync(t)
	})
	// Must run after the regular Python async test: this subtest causes OBI to
	// flag the service as OTel-exporting, which persists for the rest of the
	// container's lifetime.
	t.Run("Log Enricher Python async OTel-instrumented", func(t *testing.T) {
		testLogEnricherPythonAsyncOTelInstrumented(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherMultiSegWritev(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-log-enricher.yml", path.Join(pathOutput, "test-suite-log-enricher-multiseg-writev.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8388`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher multi-seg writev", func(t *testing.T) {
		testLogEnricherMultiSegWritev(t)
	})
	t.Run("Log Enricher shipper filters", func(t *testing.T) {
		testLogEnricherShipperFilters(t)
	})
	require.NoError(t, compose.Close())
}

// The idea behind this test suite is to make sure that when an HTTP request is bigger than 1KB,
// the traceparent is detected and parsed correctly during an ingress flow (protocol_http kprob)
// and an egress flow (tpinjector sk_msg kprobe).
// In previous versions of OBI, tpinjector.c:obi_packet_extender_find_existing_tp()
// and protocol_http.h:__obi_continue_protocol_http_tp() had problematic bitwise operations that
// can change or corrupt the traceparent header when parsing a 1KB+ HTTP request.
func TestSuite_LargeHTTPRequest(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-large-http-req.yml", path.Join(pathOutput, "test-suite-large-http-req.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Large HTTP Request egress flow (kprobe: tpinjector[sk_msg])", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:3035")
		testLargeHTTPRequestEgress(t)
	})

	t.Run("Large HTTP Request ingress flow (kprobe: protocol_http)", func(t *testing.T) {
		testLargeHTTPRequestIngress(t)
	})

	t.Run("Large HTTP Request egress flow with arbitrary size (kprobe: tpinjector[sk_msg])", func(t *testing.T) {
		testLargeHTTPRequestEgressArbitrarySize(t)
	})

	t.Run("Large HTTP Request ingress flow with arbitrary size (kprobe: protocol_http)", func(t *testing.T) {
		testLargeHTTPRequestIngressArbitrarySize(t)
	})

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
