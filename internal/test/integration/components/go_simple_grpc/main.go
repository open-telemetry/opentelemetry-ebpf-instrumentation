// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// ---- fake database/sql driver ----
// database/sql uprobes hook the stdlib (database/sql.(*DB).queryDC), so a
// trivial in-process driver is enough to produce a SQL client span.

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

type fakeConn struct{}

func (fakeConn) Prepare(string) (driver.Stmt, error) { return fakeStmt{}, nil }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type fakeStmt struct{}

func (fakeStmt) Close() error                               { return nil }
func (fakeStmt) NumInput() int                              { return 0 }
func (fakeStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (fakeStmt) Query([]driver.Value) (driver.Rows, error)  { return &fakeRows{}, nil }

type fakeRows struct{ done bool }

func (*fakeRows) Columns() []string { return []string{"n"} }
func (*fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(1)
	return nil
}

// set from main; used by the deep and nesting drivers and the A/B close sequence below
var (
	deepLog      func(string)
	deepGRPCCall func(string) error
	nestInnerDB  *sql.DB
	nestDB       *sql.DB
)

// more nested SQL spans than the BPF context stack can hold
const nestLevels = 5

// what the nesting driver runs at its last level
const (
	nestLeafFake = "fake"
	nestLeafGRPC = "grpcab"
)

// ---- deep driver: its Query logs and calls gRPC, so one goroutine nests
// server, SQL and gRPC spans. The request id is a bind parameter ----

type deepDriver struct{}

func (deepDriver) Open(string) (driver.Conn, error) { return deepConn{}, nil }

type deepConn struct{}

func (deepConn) Prepare(string) (driver.Stmt, error) { return deepStmt{}, nil }
func (deepConn) Close() error                        { return nil }
func (deepConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type deepStmt struct{}

func (deepStmt) Close() error                               { return nil }
func (deepStmt) NumInput() int                              { return 1 }
func (deepStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (deepStmt) Query(args []driver.Value) (driver.Rows, error) {
	id, _ := args[0].(string)
	deepLog("deep: driver before grpc " + id)
	if err := deepGRPCCall("deep: grpc handler " + id); err != nil {
		return nil, err
	}
	deepLog("deep: driver after grpc " + id)
	return &fakeRows{}, nil
}

// ---- nesting driver: its Query runs another database/sql query, so SQL spans
// nest. The remaining levels, the request id and the leaf are bind parameters:
// each level calls nestDB again, the last one runs the leaf ----

type nestDriver struct{}

func (nestDriver) Open(string) (driver.Conn, error) { return nestConn{}, nil }

type nestConn struct{}

func (nestConn) Prepare(string) (driver.Stmt, error) { return nestStmt{}, nil }
func (nestConn) Close() error                        { return nil }
func (nestConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type nestStmt struct{}

func (nestStmt) Close() error                               { return nil }
func (nestStmt) NumInput() int                              { return 3 }
func (nestStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (nestStmt) Query(args []driver.Value) (driver.Rows, error) {
	n, _ := args[0].(int64)
	id, _ := args[1].(string)
	leaf, _ := args[2].(string)

	var err error
	switch {
	case n > 0:
		err = nestQuery(n-1, id, leaf)
	case leaf == nestLeafGRPC:
		err = grpcCloseAB(id)
	default:
		err = fakeQuery()
	}
	if err != nil {
		return nil, err
	}
	// still inside this level's SQL span
	deepLog(fmt.Sprintf("samekind: driver after inner L%d %s", n, id))
	return &fakeRows{}, nil
}

// n+1 nested SQL spans, then the leaf
func nestQuery(n int64, id, leaf string) error {
	rows, err := nestDB.Query("SELECT nest", n, id, leaf)
	if err != nil {
		return err
	}
	return rows.Close()
}

func fakeQuery() error {
	rows, err := nestInnerDB.Query("SELECT n FROM fake")
	if err != nil {
		return err
	}
	return rows.Close()
}

// ---- A/B close: while an RPC on gRPC connection A is in flight, its
// interceptor closes connection B on the same goroutine. B's Close must leave
// A's context and A's client span alone ----

func grpcCloseAB(id string) error {
	connB, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	closeB := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		connB.Close()
		// still inside A's Invoke: this line belongs to A's client span
		deepLog("closeab: after close " + id)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	connA, err := grpc.Dial(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		grpc.WithUnaryInterceptor(closeB),
	)
	if err != nil {
		connB.Close()
		return err
	}
	defer connA.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	deepLog("closeab: before grpc " + id)
	var resp LogResponse
	if err := connA.Invoke(ctx, "/LogService/Log",
		&LogRequest{Message: "closeab: grpc handler " + id}, &resp); err != nil {
		return err
	}
	deepLog("closeab: after grpc " + id)
	return nil
}

// ---- JSON codec ----

type jsonCodec struct{}

func (jsonCodec) Name() string {
	return "json"
}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// ---- Request / Response ----

type LogRequest struct {
	Message string `json:"message"`
	Mode    string `json:"mode,omitempty"`
}

type LogResponse struct {
	Ok bool `json:"ok"`
}

// ---- Service interface ----

type LogService interface {
	Log(context.Context, *LogRequest) (*LogResponse, error)
}

// ---- Implementation ----

type logService struct{}

const writevRegressionLeakMarker = "writev-leak-marker-should-never-appear"

const (
	plainTextMultilineFirstMessage  = "plain-text first line"
	plainTextMultilineSecondMessage = "plain-text second line"
	ndjsonFirstMessage              = "ndjson first record"
	ndjsonSecondMessage             = "ndjson second record"
)

func writeWritevRegressionLog(message string) error {
	entry := fmt.Sprintf(`{"message":"%s","level":"INFO"}`, message)

	// The first iovec only exposes the JSON log line, but it is backed by a
	// larger buffer containing secret bytes immediately after that slice.
	// A vulnerable logenricher reads past the first iovec length and leaks the
	// marker; the fixed code clamps reads and writes to the first segment.
	backing := append([]byte(entry), []byte(writevRegressionLeakMarker+" ")...)
	first := backing[:len(entry)]
	padding := bytes.Repeat([]byte(" "), len(writevRegressionLeakMarker))

	_, err := unix.Writev(int(os.Stdout.Fd()), [][]byte{first, padding, []byte("\n")})
	return err
}

func (s *logService) Log(_ context.Context, req *LogRequest) (*LogResponse, error) {
	switch req.Mode {
	case "writev-regression":
		if err := writeWritevRegressionLog(req.Message); err != nil {
			return &LogResponse{Ok: false}, err
		}
		return &LogResponse{Ok: true}, nil
	case "plain-text-multiline":
		_, err := unix.Write(int(os.Stdout.Fd()), []byte(plainTextMultilineFirstMessage+"\n"+plainTextMultilineSecondMessage+"\n"))
		if err != nil {
			return &LogResponse{Ok: false}, err
		}
		return &LogResponse{Ok: true}, nil
	case "ndjson":
		entries := fmt.Sprintf("{\"message\":%q}\n{\"message\":%q}\n", ndjsonFirstMessage, ndjsonSecondMessage)
		_, err := unix.Write(int(os.Stdout.Fd()), []byte(entries))
		if err != nil {
			return &LogResponse{Ok: false}, err
		}
		return &LogResponse{Ok: true}, nil
	}

	entry := map[string]any{
		"message": req.Message,
		"level":   "INFO",
		"ts":      time.Now().UTC().Format(time.RFC3339),
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return &LogResponse{Ok: false}, err
	}

	fmt.Println(string(b))

	return &LogResponse{Ok: true}, nil
}

// ---- gRPC handler ----

//nolint:revive
func logHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	_ grpc.UnaryServerInterceptor,
) (any, error) {
	req := new(LogRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	return srv.(LogService).Log(ctx, req)
}

var logServiceDesc = grpc.ServiceDesc{
	ServiceName: "LogService",
	HandlerType: (*LogService)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Log",
			Handler:    logHandler,
		},
	},
}

// ---- main ----

func main() {
	// Register codec globally
	encoding.RegisterCodec(jsonCodec{})

	// gRPC server
	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatal(err)
		}

		s := grpc.NewServer(
			grpc.ForceServerCodec(jsonCodec{}),
		)
		s.RegisterService(&logServiceDesc, &logService{})

		log.Println("gRPC listening on :50051")
		log.Fatal(s.Serve(lis))
	}()

	// HTTP -> gRPC
	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.ForceCodec(jsonCodec{}),
			),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		err = conn.Invoke(
			ctx,
			"/LogService/Log",
			&LogRequest{Message: "hello!", Mode: r.URL.Query().Get("mode")},
			&resp,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte("ok\n"))
	})
	http.HandleFunc("/log_writev_regression", func(w http.ResponseWriter, _ *http.Request) {
		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.ForceCodec(jsonCodec{}),
			),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		err = conn.Invoke(
			ctx,
			"/LogService/Log",
			&LogRequest{
				Message: "go writev regression log",
				Mode:    "writev-regression",
			},
			&resp,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte("ok\n"))
	})
	// nested spans: the HTTP handler calls a gRPC client, which hits the gRPC
	// server, then runs SQL. Logs after each call must keep the server span
	sql.Register("fake", fakeDriver{})
	db, err := sql.Open("fake", "")
	if err != nil {
		log.Fatal(err)
	}
	jsonLog := func(msg string) {
		b, _ := json.Marshal(map[string]any{
			"message": msg,
			"level":   "INFO",
			"ts":      time.Now().UTC().Format(time.RFC3339),
		})
		fmt.Println(string(b))
	}
	http.HandleFunc("/nested_logger", func(w http.ResponseWriter, r *http.Request) {
		// the id lets the test pair log lines per request
		id := r.URL.Query().Get("id")
		jsonLog("nested: before grpc " + id)

		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		if err := conn.Invoke(ctx, "/LogService/Log",
			&LogRequest{Message: "nested: grpc handler " + id}, &resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonLog("nested: after grpc " + id)

		rows, err := db.Query("SELECT n FROM fake")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows.Close()

		jsonLog("nested: after sql " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	// fan-out variant: SQL on its own goroutine, handler blocks on a channel
	http.HandleFunc("/nested_logger_goroutine", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jsonLog("nestedg: before grpc " + id)

		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		if err := conn.Invoke(ctx, "/LogService/Log",
			&LogRequest{Message: "nestedg: grpc handler " + id}, &resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonLog("nestedg: after grpc " + id)

		sqlDone := make(chan error, 1)
		go func() {
			// a new goroutine has no span yet, so this line must not be enriched
			jsonLog("nestedg: child before sql " + id)
			rows, err := db.Query("SELECT n FROM fake")
			if err != nil {
				sqlDone <- err
				return
			}
			rows.Close()
			sqlDone <- nil
		}()
		if err := <-sqlDone; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonLog("nestedg: after sql " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	deepLog = jsonLog
	deepGRPCCall = func(msg string) error {
		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		)
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		return conn.Invoke(ctx, "/LogService/Log", &LogRequest{Message: msg}, &resp)
	}
	sql.Register("deepfake", deepDriver{})
	deepDB, err := sql.Open("deepfake", "")
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/nested_logger_deep", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jsonLog("deep: before sql " + id)

		rows, err := deepDB.Query("SELECT deep", id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows.Close()

		jsonLog("deep: after sql " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	sql.Register("nestfake", nestDriver{})
	nestInnerDB = db
	nestDB, err = sql.Open("nestfake", "")
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/nested_logger_samekind", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jsonLog("samekind: before sql " + id)

		if err := nestQuery(nestLevels, id, nestLeafFake); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonLog("samekind: after sql " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	// A/B close on one goroutine, after `sql` nested SQL spans: with enough of
	// them the context stack is full and A's span is only counted, not stored
	http.HandleFunc("/nested_logger_closeab", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		sqlDepth, _ := strconv.Atoi(r.URL.Query().Get("sql"))
		jsonLog("closeab: start " + id)

		var err error
		if sqlDepth > 0 {
			err = nestQuery(int64(sqlDepth-1), id, nestLeafGRPC)
		} else {
			err = grpcCloseAB(id)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonLog("closeab: done " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	// the gRPC connection is closed on another goroutine
	http.HandleFunc("/nested_logger_closeg", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jsonLog("closeg: before grpc " + id)

		conn, err := grpc.Dial(
			"localhost:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var resp LogResponse
		if err := conn.Invoke(ctx, "/LogService/Log",
			&LogRequest{Message: "closeg: grpc handler " + id}, &resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		closed := make(chan struct{})
		go func() {
			conn.Close()
			close(closed)
		}()
		<-closed

		jsonLog("closeg: after close " + id)

		_, _ = w.Write([]byte("ok\n"))
	})
	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	log.Println("HTTP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
