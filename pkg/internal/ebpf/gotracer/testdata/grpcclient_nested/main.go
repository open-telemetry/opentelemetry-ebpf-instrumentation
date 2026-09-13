// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(value any) ([]byte, error) { return json.Marshal(value) }

func (jsonCodec) Unmarshal(data []byte, value any) error { return json.Unmarshal(data, value) }

type testReq struct {
	Depth int `json:"depth"`
}

type testResp struct {
	Message string `json:"message"`
}

type testService interface{}

func handleUnary(
	_ any,
	_ context.Context,
	decode func(any) error,
	_ grpc.UnaryServerInterceptor,
) (any, error) {
	var req testReq
	if err := decode(&req); err != nil {
		return nil, err
	}
	return &testResp{Message: fmt.Sprintf("ok-%d", req.Depth)}, nil
}

func handleStream(srv any, stream grpc.ServerStream) error {
	for {
		var req testReq
		if err := stream.RecvMsg(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.SendMsg(&testResp{Message: "stream-ack"}); err != nil {
			return err
		}
	}
}

var streamDesc = grpc.StreamDesc{
	StreamName:    "Stream",
	Handler:       handleStream,
	ServerStreams: true,
	ClientStreams: true,
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: "TestService",
	HandlerType: (*testService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Unary",
		Handler:    handleUnary,
	}},
	Streams: []grpc.StreamDesc{streamDesc},
}

func main() {
	encoding.RegisterCodec(jsonCodec{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	server.RegisterService(&serviceDesc, struct{}{})
	go func() { _ = server.Serve(listener) }()

	addr := listener.Addr().String()
	connA, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial connA error: %v\n", err)
		os.Exit(1)
	}
	defer connA.Close()

	connB, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial connB error: %v\n", err)
		os.Exit(1)
	}
	defer connB.Close()

	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cmd := scanner.Text()
		switch cmd {
		case "UNARY":
			var resp testResp
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := connA.Invoke(ctx, "/TestService/Unary", &testReq{Depth: 0}, &resp)
			cancel()
			report(cmd, err)

		case "NESTED_SAME_CONN":
			// Interceptor on connA that invokes connA again on the same goroutine
			var interceptor grpc.UnaryClientInterceptor = func(
				ctx context.Context,
				method string,
				req, reply any,
				cc *grpc.ClientConn,
				invoker grpc.UnaryInvoker,
				opts ...grpc.CallOption,
			) error {
				if r, ok := req.(*testReq); ok && r.Depth == 0 {
					var innerResp testResp
					innerCtx, innerCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer innerCancel()
					// Nested call on same connA
					if innerErr := cc.Invoke(innerCtx, "/TestService/Unary", &testReq{Depth: 1}, &innerResp, opts...); innerErr != nil {
						return innerErr
					}
				}
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			interceptedConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithUnaryInterceptor(interceptor),
			)
			if err != nil {
				report(cmd, err)
				continue
			}
			var resp testResp
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			callErr := interceptedConn.Invoke(ctx, "/TestService/Unary", &testReq{Depth: 0}, &resp)
			cancel()
			_ = interceptedConn.Close()
			report(cmd, callErr)

		case "NESTED_DIFF_CONN":
			// Interceptor on connA that invokes connB on the same goroutine
			var interceptor grpc.UnaryClientInterceptor = func(
				ctx context.Context,
				method string,
				req, reply any,
				cc *grpc.ClientConn,
				invoker grpc.UnaryInvoker,
				opts ...grpc.CallOption,
			) error {
				if r, ok := req.(*testReq); ok && r.Depth == 0 {
					var innerResp testResp
					innerCtx, innerCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer innerCancel()
					// Nested call on connB
					if innerErr := connB.Invoke(innerCtx, "/TestService/Unary", &testReq{Depth: 1}, &innerResp); innerErr != nil {
						return innerErr
					}
				}
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			interceptedConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithUnaryInterceptor(interceptor),
			)
			if err != nil {
				report(cmd, err)
				continue
			}
			var resp testResp
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			callErr := interceptedConn.Invoke(ctx, "/TestService/Unary", &testReq{Depth: 0}, &resp)
			cancel()
			_ = interceptedConn.Close()
			report(cmd, callErr)

		case "RECURSIVE_UNARY":
			// Overlapping recursive unary on connA using a guarded interceptor
			var interceptor grpc.UnaryClientInterceptor
			interceptor = func(
				ctx context.Context,
				method string,
				req, reply any,
				cc *grpc.ClientConn,
				invoker grpc.UnaryInvoker,
				opts ...grpc.CallOption,
			) error {
				r := req.(*testReq)
				if r.Depth < 2 { // triggers depths 0, 1, 2 (3 calls total)
					var innerResp testResp
					innerCtx, innerCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer innerCancel()
					if innerErr := cc.Invoke(innerCtx, "/TestService/Unary", &testReq{Depth: r.Depth + 1}, &innerResp, opts...); innerErr != nil {
						return innerErr
					}
				}
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			recursiveConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithUnaryInterceptor(interceptor),
			)
			if err != nil {
				report(cmd, err)
				continue
			}
			var resp testResp
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			callErr := recursiveConn.Invoke(ctx, "/TestService/Unary", &testReq{Depth: 0}, &resp)
			cancel()
			_ = recursiveConn.Close()
			report(cmd, callErr)

		case "STACK_OVERFLOW":
			var interceptor grpc.UnaryClientInterceptor
			interceptor = func(
				ctx context.Context,
				method string,
				req, reply any,
				cc *grpc.ClientConn,
				invoker grpc.UnaryInvoker,
				opts ...grpc.CallOption,
			) error {
				r := req.(*testReq)
				if r.Depth < 6 {
					var innerResp testResp
					innerCtx, innerCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer innerCancel()
					if innerErr := cc.Invoke(innerCtx, "/TestService/Unary", &testReq{Depth: r.Depth + 1}, &innerResp, opts...); innerErr != nil {
						return innerErr
					}
				}
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			overflowConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithUnaryInterceptor(interceptor),
			)
			if err != nil {
				report(cmd, err)
				continue
			}
			var resp testResp
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			callErr := overflowConn.Invoke(ctx, "/TestService/Unary", &testReq{Depth: 0}, &resp)
			cancel()
			_ = overflowConn.Close()
			report(cmd, callErr)

		case "STREAM_NORMAL":
			stream, err := connA.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
			if err != nil {
				report(cmd, err)
				continue
			}
			_ = stream.SendMsg(&testReq{Depth: 0})
			var resp testResp
			_ = stream.RecvMsg(&resp)
			_ = stream.CloseSend()
			for {
				var dummy testResp
				if err := stream.RecvMsg(&dummy); err != nil {
					break
				}
			}
			report(cmd, nil)

		case "STREAM_RACE_ALREADY_CANCELLED":
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // cancelled before stream creation
			stream, err := connA.NewStream(ctx, &streamDesc, "/TestService/Stream")
			if err == nil && stream != nil {
				<-stream.Context().Done()
			}
			report(cmd, nil)

		case "STREAM_RACE_QUICKLY_CANCELLED":
			for i := 0; i < 5; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					time.Sleep(10 * time.Nanosecond)
					cancel()
				}()
				stream, err := connA.NewStream(ctx, &streamDesc, "/TestService/Stream")
				if err == nil && stream != nil {
					<-stream.Context().Done()
				}
				cancel()
			}
			report(cmd, nil)

		case "STREAM_RACE_CONCURRENT_CLOSE":
			for i := 0; i < 5; i++ {
				raceConn, err := grpc.NewClient(
					addr,
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				)
				if err != nil {
					continue
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					time.Sleep(50 * time.Microsecond)
					_ = raceConn.Close()
				}()
				go func() {
					defer wg.Done()
					stream, streamErr := raceConn.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
					if streamErr == nil && stream != nil {
						<-stream.Context().Done()
					}
				}()
				wg.Wait()
			}
			report(cmd, nil)

		case "STREAM_FINISH_BEFORE_RETURN":
			var cancel context.CancelFunc
			var interceptor grpc.StreamClientInterceptor = func(
				ctx context.Context,
				desc *grpc.StreamDesc,
				cc *grpc.ClientConn,
				method string,
				streamer grpc.Streamer,
				opts ...grpc.CallOption,
			) (grpc.ClientStream, error) {
				cs, err := streamer(ctx, desc, cc, method, opts...)
				if err != nil {
					return nil, err
				}
				if cancel != nil {
					cancel()
				}
				time.Sleep(100 * time.Millisecond)
				return cs, nil
			}
			interceptedConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithStreamInterceptor(interceptor),
			)
			if err != nil {
				report(cmd, err)
				continue
			}
			var ctx context.Context
			ctx, cancel = context.WithCancel(context.Background())
			stream, streamErr := interceptedConn.NewStream(ctx, &streamDesc, "/TestService/Stream")
			if streamErr == nil && stream != nil {
				<-stream.Context().Done()
			}
			_ = interceptedConn.Close()
			report(cmd, nil)

		case "STREAM_FINISH_DURING_PUBLICATION":
			for i := 0; i < 20; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				go func(delay time.Duration) {
					time.Sleep(delay)
					cancel()
				}(time.Duration(i*5) * time.Microsecond)
				stream, err := connA.NewStream(ctx, &streamDesc, "/TestService/Stream")
				if err == nil && stream != nil {
					<-stream.Context().Done()
				}
				cancel()
			}
			report(cmd, nil)

		case "STREAM_CONCURRENT_MULTI_FINISH":
			for i := 0; i < 10; i++ {
				raceConn, err := grpc.NewClient(
					addr,
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				)
				if err != nil {
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				stream, streamErr := raceConn.NewStream(ctx, &streamDesc, "/TestService/Stream")
				if streamErr != nil || stream == nil {
					cancel()
					_ = raceConn.Close()
					continue
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					cancel()
				}()
				go func() {
					defer wg.Done()
					_ = raceConn.Close()
				}()
				wg.Wait()
				<-stream.Context().Done()
			}
			report(cmd, nil)

		case "EXIT":
			server.Stop()
			return
		}
	}
}

func report(cmd string, err error) {
	if err != nil {
		fmt.Printf("CMD=%s STATUS=ERR err=%v\n", cmd, err)
		return
	}
	fmt.Printf("CMD=%s STATUS=OK\n", cmd)
}
