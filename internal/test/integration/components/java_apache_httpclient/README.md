# Apache HttpClient 4 integration fixture

The fixture forwards requests through an uninstrumented TLS HTTP/1.1 proxy to an
OpenTelemetry-instrumented downstream. Tests compare the received headers with
OBI's exported client span and the downstream parent. They cover enabled/disabled
propagation, overloads, pooling, retries, redirects, authentication, reentrancy,
header preservation, excluded writes, and recovery after failures.

Build the agent and OBI, then run the transport suite from the repository root:

```sh
make docker-generate
make java-docker-build
make compile
make testoutput
go test -v -count=1 -run '^TestJavaApacheHTTPClientTraceparent$' -timeout 20m ./internal/test/integration/
```

`JAVA_APACHE_RUNTIME_IMAGE` selects a digest-pinned JDK image.
`JAVA_APACHE_HTTPCLIENT_VERSION` selects the dependency (default: 4.5.14).
CI tests 4.3 on Java 8 and 4.5.14 on Java 11/17/21, on native amd64 and arm64.
To run against the minimum version:

```sh
JAVA_APACHE_HTTPCLIENT_VERSION=4.3 go test -v -count=1 -run '^TestJavaApacheHTTPClientTraceparent$' -timeout 20m ./internal/test/integration/
```

Agent tests also accept `gradle :agent:test -PapacheHttpClientVersion=4.3` from
`pkg/internal/java`.
