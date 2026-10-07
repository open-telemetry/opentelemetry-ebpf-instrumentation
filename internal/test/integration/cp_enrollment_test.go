// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// a connection opened before OBI started, one opened after OBI loaded but before the process was
// discovered, and one opened after discovery, from processes in every combination of host and
// container pid and network namespaces, next to bystanders OBI must leave alone
func TestCPEnrollmentGoTracer(t *testing.T) {
	runCPEnrollment(t, cpMode{name: "go-tracer", cp: "headers", seccomp: "none"})
}

func TestCPEnrollmentGeneric(t *testing.T) {
	runCPEnrollment(t, cpMode{name: "generic", cp: "headers", skipGo: true, seccomp: "none"})
}

func TestCPEnrollmentTCPOptions(t *testing.T) {
	runCPEnrollment(t, cpMode{name: "tcp-options", cp: "tcp", skipGo: true, seccomp: "none"})
}

// without pidfd_getfd OBI enrolls every client socket
func TestCPEnrollmentFallbackGlobal(t *testing.T) {
	runCPEnrollment(t, cpMode{name: "fallback-global", cp: "headers", skipGo: true, seccomp: "all"})
}

// pidfd_getfd denied for the processes themselves: OBI walks their network namespaces instead
func TestCPEnrollmentFallbackPerProcess(t *testing.T) {
	runCPEnrollment(t, cpMode{name: "fallback-per-process", cp: "headers", skipGo: true, seccomp: "probe-only"})
}

type cpMode struct {
	name    string
	cp      string
	skipGo  bool
	seccomp string
}

// what each mode must do; nil means the mode makes no promise
type cpExpectations struct {
	scoped bool
	// enrolled when connected before OBI started, or before the process was discovered
	appFirstEnrolled, preDiscoveryEnrolled bool
	// bystanders connected before OBI started, sharing an app's network namespace or not
	bystanderSharedNetnsEnrolled, bystanderOwnNetnsEnrolled *bool
	bystanderSpawnedEnrolled                                *bool
	// headers echoed back by the server, or server spans parented by the client's
	headersCP, tcpCP bool
	// the child an app forks is instrumented through its parent
	grandchildCP bool
	logLine      string
}

func cpExpectationsFor(t *testing.T, mode cpMode) cpExpectations {
	iterators := kernelAtLeast(t, 6, 4)
	no, yes := false, true
	ifIterators := &iterators

	switch mode.seccomp {
	case "all":
		return cpExpectations{
			appFirstEnrolled:             iterators,
			preDiscoveryEnrolled:         true,
			bystanderSharedNetnsEnrolled: ifIterators,
			// no instrumented process makes OBI walk that namespace
			bystanderOwnNetnsEnrolled: &no,
			bystanderSpawnedEnrolled:  &yes,
			headersCP:                 true,
			grandchildCP:              true,
			logLine:                   "cannot duplicate the sockets of other processes",
		}
	case "probe-only":
		return cpExpectations{
			scoped:                       true,
			appFirstEnrolled:             iterators,
			preDiscoveryEnrolled:         iterators,
			bystanderSharedNetnsEnrolled: ifIterators,
			bystanderOwnNetnsEnrolled:    &no,
			// spawned before its app, so the walk at the app's discovery finds it
			bystanderSpawnedEnrolled: ifIterators,
			headersCP:                true,
			grandchildCP:             true,
			logLine:                  "can't duplicate the process's sockets",
		}
	default:
		return cpExpectations{
			scoped:                       true,
			appFirstEnrolled:             true,
			preDiscoveryEnrolled:         true,
			bystanderSharedNetnsEnrolled: &no,
			bystanderOwnNetnsEnrolled:    &no,
			bystanderSpawnedEnrolled:     &no,
			headersCP:                    mode.cp == "headers",
			tcpCP:                        mode.cp == "tcp",
			// the Go tracer filters pids in user space, so it doesn't trace an unselected child
			grandchildCP: mode.cp == "headers" && mode.skipGo,
		}
	}
}

func kernelAtLeast(t *testing.T, major, minor int) bool {
	var uts unix.Utsname
	require.NoError(t, unix.Uname(&uts))
	release := unix.ByteSliceToString(uts.Release[:])
	parts := strings.SplitN(release, ".", 3)
	require.GreaterOrEqual(t, len(parts), 2, release)
	gotMajor, err := strconv.Atoi(parts[0])
	require.NoError(t, err, release)
	gotMinor, err := strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	require.NoError(t, err, release)
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

const cpPollInterval = 500 * time.Millisecond

// launchers spawn clients inside one container, sharing its namespaces
type cpSite struct {
	name                                 string
	launcher                             int
	spawnedApp, spawnedBystander, forked int
}

var cpSites = []cpSite{
	{name: "site-container", launcher: 18200, spawnedApp: 18001, spawnedBystander: 18101, forked: 18102},
	{name: "site-hostnet", launcher: 18201, spawnedApp: 18011, spawnedBystander: 18111, forked: 18112},
	{name: "site-hostpid", launcher: 18202, spawnedApp: 18021, spawnedBystander: 18121, forked: 18122},
	{name: "site-host", launcher: 18203, spawnedApp: 18031, spawnedBystander: 18131, forked: 18132},
}

// clients that are pid 1 in their own container, reached through a published port
const (
	cpPID1App     = "site-pid1-app"
	cpPID1AppPort = 18140
	cpPID1ByPort  = 18141
)

type cpConn struct {
	Cookie      uint64 `json:"cookie"`
	Dials       int    `json:"dials"`
	Traceparent bool   `json:"traceparent"`
}

type cpClient struct {
	Name    string   `json:"name"`
	PID     int      `json:"pid"`
	NSInode uint64   `json:"nsInode"`
	Conns   []cpConn `json:"conns"`
}

func cpGet(ct require.TestingT, url string, into any) {
	resp, err := http.Get(url)
	require.NoError(ct, err)
	defer resp.Body.Close()
	require.Equal(ct, http.StatusOK, resp.StatusCode, url)
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(into))
}

func cpPost(t *testing.T, url string) {
	t.Helper()
	resp, err := http.Post(url, "text/plain", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, url)
}

func cpSiteClient(ct require.TestingT, site cpSite, name string) cpClient {
	children := map[string]cpClient{}
	cpGet(ct, fmt.Sprintf("http://localhost:%d/children", site.launcher), &children)
	client, found := children[name]
	require.True(ct, found, "%s is not running in %s", name, site.name)
	return client
}

func cpPortClient(ct require.TestingT, port int) cpClient {
	var client cpClient
	cpGet(ct, fmt.Sprintf("http://localhost:%d/status", port), &client)
	return client
}

// runs the OBI image's test tool, which prints one number per line
func cpTool(ct require.TestingT, compose *docker.Compose, args ...string) map[uint64]bool {
	out, err := compose.ExecOutput("obi", append([]string{"/obitesttool"}, args...)...)
	require.NoError(ct, err, out)
	values := map[uint64]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if line == "" {
			continue
		}
		value, err := strconv.ParseUint(line, 10, 64)
		require.NoError(ct, err, line)
		values[value] = true
	}
	return values
}

func cpBPFKeys(ct require.TestingT, compose *docker.Compose, mapName string) map[uint64]bool {
	return cpTool(ct, compose, "map-keys", mapName)
}

func cpInstrumentedPIDs(ct require.TestingT, compose *docker.Compose) map[uint64]bool {
	return cpTool(ct, compose, "bitmap-pids", "instrumented_pids")
}

// the pid OBI's /proc numbers the client with, the one its filters hold
func cpHostPID(ct require.TestingT, compose *docker.Compose, client cpClient) uint64 {
	pids := cpTool(ct, compose, "host-pid", strconv.FormatUint(client.NSInode, 10), strconv.Itoa(client.PID))
	require.Len(ct, pids, 1, client.Name)
	for pid := range pids {
		return pid
	}
	return 0
}

type cpGetter func(require.TestingT) cpClient

type cpSuite struct {
	t       *testing.T
	compose *docker.Compose
	mode    cpMode
	exp     cpExpectations
}

// waits until the client's process is instrumented, when the mode tracks processes
func (s *cpSuite) waitInstrumented(get cpGetter) {
	s.t.Helper()
	if !s.exp.scoped {
		return
	}
	require.EventuallyWithT(s.t, func(ct *assert.CollectT) {
		client := get(ct)
		assert.True(ct, cpInstrumentedPIDs(ct, s.compose)[cpHostPID(ct, s.compose, client)], "%s is not instrumented", client.Name)
	}, testTimeout, cpPollInterval)
}

// checks one connection; it must still be the first one dialed, or it isn't the scenario under test
func (s *cpSuite) checkConn(get cpGetter, conn int, enrolled *bool, headersCP bool) {
	s.t.Helper()
	if enrolled == nil && !headersCP {
		return
	}
	require.EventuallyWithT(s.t, func(ct *assert.CollectT) {
		client := get(ct)
		require.Greater(ct, len(client.Conns), conn, client.Name)
		c := client.Conns[conn]
		assert.Equal(ct, 1, c.Dials, "%s connection %d was redialed", client.Name, conn)
		if enrolled != nil {
			assert.Equal(ct, *enrolled, cpBPFKeys(ct, s.compose, "sock_dir")[c.Cookie], "%s connection %d enrollment", client.Name, conn)
		}
		if headersCP {
			assert.True(ct, c.Traceparent, "%s connection %d got no traceparent", client.Name, conn)
		}
	}, testTimeout, cpPollInterval)
}

// server spans parented by the client's prove the TCP option reached the server
func (s *cpSuite) checkTCPCP(service string) {
	s.t.Helper()
	require.EventuallyWithT(s.t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=" + service + "&limit=1000")
		require.NoError(ct, err)
		defer resp.Body.Close()
		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		assert.True(ct, cpServerChildOf(traces, service), "no server span parented by %s", service)
	}, testTimeout, cpPollInterval)
}

func cpServerChildOf(traces jaeger.TracesQuery, client string) bool {
	for _, trace := range traces.Data {
		for _, span := range trace.Spans {
			if trace.Processes[span.ProcessID].ServiceName != client {
				continue
			}
			for _, child := range trace.ChildrenOf(span.SpanID) {
				if trace.Processes[child.ProcessID].ServiceName == "tpinjector-server" {
					return true
				}
			}
		}
	}
	return false
}

func runCPEnrollment(t *testing.T, mode cpMode) {
	compose, err := docker.ComposeSuite("docker-compose-cp-enrollment.yml", path.Join(pathOutput, "test-suite-cp-enrollment-"+mode.name+".log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		"CP_MODE="+mode.cp, "SKIP_GO="+strconv.FormatBool(mode.skipGo), "OBI_SECCOMP="+mode.seccomp)
	require.NoError(t, compose.Up())
	defer func() { require.NoError(t, compose.Close()) }()

	s := &cpSuite{t: t, compose: compose, mode: mode, exp: cpExpectationsFor(t, mode)}
	siteClient := func(site cpSite, name string) cpGetter {
		return func(ct require.TestingT) cpClient { return cpSiteClient(ct, site, name) }
	}
	portClient := func(port int) cpGetter {
		return func(ct require.TestingT) cpClient { return cpPortClient(ct, port) }
	}

	apps := map[string]cpGetter{cpPID1App: portClient(cpPID1AppPort)}
	for _, site := range cpSites {
		apps[site.name+"-app"] = siteClient(site, site.name+"-app")
	}

	t.Run("connected before OBI started", func(t *testing.T) {
		s.t = t
		for _, get := range apps {
			s.waitInstrumented(get)
			s.checkConn(get, 0, &s.exp.appFirstEnrolled, s.exp.headersCP && s.exp.appFirstEnrolled)
		}
	})

	t.Run("bystanders connected before OBI started", func(t *testing.T) {
		s.t = t
		for _, site := range cpSites {
			s.checkConn(siteClient(site, site.name+"-bystander"), 0, s.exp.bystanderSharedNetnsEnrolled, false)
		}
		s.checkConn(portClient(cpPID1ByPort), 0, s.exp.bystanderOwnNetnsEnrolled, false)
		if !s.exp.scoped {
			return
		}
		instrumented := cpInstrumentedPIDs(t, compose)
		bystanders := []cpGetter{portClient(cpPID1ByPort)}
		for _, site := range cpSites {
			bystanders = append(bystanders, siteClient(site, site.name+"-bystander"))
		}
		for _, get := range bystanders {
			bystander := get(t)
			assert.False(t, instrumented[cpHostPID(t, compose, bystander)], "%s is instrumented", bystander.Name)
		}
	})

	t.Run("connected after OBI loaded, before discovery", func(t *testing.T) {
		s.t = t
		for _, site := range cpSites {
			// the bystander first, so a namespace walk at the app's discovery covers it
			cpPost(t, fmt.Sprintf("http://localhost:%d/spawn?name=%s-spawned-bystander&port=%d", site.launcher, site.name, site.spawnedBystander))
			cpPost(t, fmt.Sprintf("http://localhost:%d/spawn?name=%s-spawned-app&port=%d", site.launcher, site.name, site.spawnedApp))
		}
		for _, site := range cpSites {
			app := siteClient(site, site.name+"-spawned-app")
			s.waitInstrumented(app)
			s.checkConn(app, 0, &s.exp.preDiscoveryEnrolled, s.exp.headersCP && s.exp.preDiscoveryEnrolled)
			if s.exp.tcpCP {
				s.checkTCPCP(site.name + "-spawned-app")
			}
			s.checkConn(siteClient(site, site.name+"-spawned-bystander"), 0, s.exp.bystanderSpawnedEnrolled, false)
		}
	})

	t.Run("connected after discovery", func(t *testing.T) {
		s.t = t
		for _, site := range cpSites {
			for _, name := range []string{site.name + "-app", site.name + "-spawned-app"} {
				cpPost(t, fmt.Sprintf("http://localhost:%d/do?name=%s&action=connect", site.launcher, name))
				s.checkConn(siteClient(site, name), 1, new(true), s.exp.headersCP)
			}
			if s.exp.tcpCP {
				// only now: its first connection predates OBI, so it can't carry the option
				s.checkTCPCP(site.name + "-app")
			}
		}
		cpPost(t, fmt.Sprintf("http://localhost:%d/connect", cpPID1AppPort))
		s.checkConn(portClient(cpPID1AppPort), 1, new(true), s.exp.headersCP)
		if s.exp.tcpCP {
			s.checkTCPCP(cpPID1App)
		}
	})

	t.Run("forked by an instrumented app", func(t *testing.T) {
		s.t = t
		for _, site := range cpSites {
			child := site.name + "-forked"
			cpPost(t, fmt.Sprintf("http://localhost:%d/do?name=%s-app&action=fork&child=%s&port=%d", site.launcher, site.name, child, site.forked))
			s.checkConn(siteClient(site, child), 0, new(true), s.exp.grandchildCP)
		}
	})

	if s.exp.logLine != "" {
		t.Run("fallback reported", func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				logs, err := compose.LogsOutput("obi")
				if assert.NoError(ct, err) {
					assert.Contains(ct, logs, s.exp.logLine)
				}
			}, testTimeout, cpPollInterval)
		})
	}

	if !s.exp.scoped {
		t.Run("no process tracked", func(t *testing.T) {
			assert.Empty(t, cpInstrumentedPIDs(t, compose))
		})
		return
	}

	t.Run("process exit", func(t *testing.T) {
		s.t = t
		for _, site := range cpSites {
			name := site.name + "-spawned-app"
			hostPID := cpHostPID(t, compose, cpSiteClient(t, site, name))
			cpPost(t, fmt.Sprintf("http://localhost:%d/do?name=%s&action=exit", site.launcher, name))
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				assert.False(ct, cpInstrumentedPIDs(ct, compose)[hostPID], "%s is still instrumented after exiting", name)
			}, testTimeout, cpPollInterval)
		}
	})

	if mode.seccomp != "none" || mode.cp != "headers" || !mode.skipGo {
		return
	}

	// every connection predates the new instance, so all of them depend on the backfill
	t.Run("OBI restarted", func(t *testing.T) {
		s.t = t
		cmd := exec.Command("docker", "compose", "-f", compose.Path, "restart", "obi")
		cmd.Env = compose.Env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		for _, get := range apps {
			s.waitInstrumented(get)
			s.checkConn(get, 0, new(true), false)
			s.checkConn(get, 1, new(true), false)
		}
		for _, site := range cpSites {
			s.checkConn(siteClient(site, site.name+"-bystander"), 0, new(false), false)
		}
		s.checkConn(portClient(cpPID1ByPort), 0, new(false), false)
	})
}
