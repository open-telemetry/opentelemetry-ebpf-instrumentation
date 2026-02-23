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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

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

func (s *logService) Log(_ context.Context, req *LogRequest) (*LogResponse, error) {
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
	http.HandleFunc("/log", func(w http.ResponseWriter, _ *http.Request) {
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
			&LogRequest{Message: "hello!"},
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
