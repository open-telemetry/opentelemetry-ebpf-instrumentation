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
	// nested spans: HTTP server -> gRPC client -> gRPC server, plus SQL under
	// the HTTP server; logs after each return must keep the server span context
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
		// per-request id keeps the test's log-line pairing race-free
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
	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	log.Println("HTTP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
