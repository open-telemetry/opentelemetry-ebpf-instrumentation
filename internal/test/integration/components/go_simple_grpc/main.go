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
	"encoding/json"
	"fmt"
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
	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	log.Println("HTTP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
