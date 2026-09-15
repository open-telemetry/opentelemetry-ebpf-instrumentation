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
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/stats"
)

//go:linkname grpcClientStreamFinish google.golang.org/grpc.(*clientStream).finish
func grpcClientStreamFinish(cs unsafe.Pointer, err error)

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

type streamStatsHandler struct {
	streamA      grpc.ClientStream
	triggerOnTag bool
	once         sync.Once
	err          error
}

func (h *streamStatsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	if h.triggerOnTag {
		h.trigger()
	}
	return ctx
}

func (h *streamStatsHandler) HandleRPC(_ context.Context, rpcStats stats.RPCStats) {
	if h.triggerOnTag {
		return
	}
	if _, ok := rpcStats.(*stats.Begin); ok {
		h.trigger()
	}
}

func (h *streamStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (*streamStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

func (h *streamStatsHandler) trigger() {
	h.once.Do(func() {
		h.err = h.streamA.SendMsg(&testReq{Depth: 30})
	})
}

var (
	eofAlias error = io.EOF
	fakeEOF  error = errors.New("EOF")
)

func init() {
	if eofAlias == nil {
		panic("io.EOF alias was not initialized")
	}
	if fakeEOF == nil {
		panic("fake EOF was not initialized")
	}
}

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

func runStatsHandlerInterleaving(addr string, connA *grpc.ClientConn, triggerOnTag bool) error {
	streamA, err := connA.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
	if err != nil {
		return err
	}

	if err := streamA.SendMsg(&testReq{Depth: 0}); err != nil {
		return err
	}
	var response testResp
	if err := streamA.RecvMsg(&response); err != nil {
		return err
	}

	handler := &streamStatsHandler{streamA: streamA, triggerOnTag: triggerOnTag}
	connB, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		grpc.WithStatsHandler(handler),
	)
	if err != nil {
		return err
	}
	defer connB.Close()

	streamB, err := connB.NewStream(context.Background(), &streamDescB, "/TestService/StreamB")
	if err != nil {
		return err
	}
	if handler.err != nil {
		return handler.err
	}
	if err := streamB.SendMsg(&testReq{Depth: 1}); err != nil {
		return err
	}
	if err := streamB.RecvMsg(&response); err != nil {
		return err
	}
	if err := streamB.CloseSend(); err != nil {
		return err
	}
	for {
		if err := streamB.RecvMsg(&response); err != nil {
			break
		}
	}
	if err := streamA.CloseSend(); err != nil {
		return err
	}
	for {
		if err := streamA.RecvMsg(&response); err != nil {
			break
		}
	}
	return nil
}

var streamDesc = grpc.StreamDesc{
	StreamName:    "Stream",
	Handler:       handleStream,
	ServerStreams: true,
	ClientStreams: true,
}

var streamDescB = grpc.StreamDesc{
	StreamName:    "StreamB",
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
	Streams: []grpc.StreamDesc{streamDesc, streamDescB},
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

		case "STREAM_ERR_NEW_EOF":
			stream, err := connA.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
			if err != nil {
				report(cmd, err)
				continue
			}
			streamPtr := (*struct{ tab, data unsafe.Pointer })(unsafe.Pointer(&stream)).data
			grpcClientStreamFinish(streamPtr, fakeEOF)
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

		case "STREAM_INTERCEPTOR_BEFORE":
			// 1. Start long-lived stream A on connA
			streamA, err := connA.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
			if err != nil {
				report(cmd, err)
				continue
			}
			_ = streamA.SendMsg(&testReq{Depth: 0})
			var dummyA testResp
			_ = streamA.RecvMsg(&dummyA)

			// 2. Start stream B on intercepted connection, calling streamA.SendMsg inside interceptor before streamer()
			var interceptor grpc.StreamClientInterceptor = func(
				ctx context.Context,
				desc *grpc.StreamDesc,
				cc *grpc.ClientConn,
				method string,
				streamer grpc.Streamer,
				opts ...grpc.CallOption,
			) (grpc.ClientStream, error) {
				// B NewStream frame is active, but B's internal clientStream does not exist yet.
				// Exercising streamA invokes streamA.withRetry.
				if sendErr := streamA.SendMsg(&testReq{Depth: 1}); sendErr != nil {
					return nil, sendErr
				}
				return streamer(ctx, desc, cc, method, opts...)
			}
			interceptedConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithStreamInterceptor(interceptor),
			)
			if err != nil {
				_ = streamA.CloseSend()
				report(cmd, err)
				continue
			}

			streamB, err := interceptedConn.NewStream(context.Background(), &streamDescB, "/TestService/StreamB")
			if err != nil {
				_ = interceptedConn.Close()
				_ = streamA.CloseSend()
				report(cmd, err)
				continue
			}
			_ = streamB.SendMsg(&testReq{Depth: 10})
			var dummyB testResp
			_ = streamB.RecvMsg(&dummyB)

			// Close stream B
			_ = streamB.CloseSend()
			for {
				if err := streamB.RecvMsg(&dummyB); err != nil {
					break
				}
			}
			_ = interceptedConn.Close()

			// Close stream A
			_ = streamA.CloseSend()
			for {
				if err := streamA.RecvMsg(&dummyA); err != nil {
					break
				}
			}
			report(cmd, nil)

		case "STREAM_INTERCEPTOR_AFTER":
			// 1. Start long-lived stream A on connA
			streamA, err := connA.NewStream(context.Background(), &streamDesc, "/TestService/Stream")
			if err != nil {
				report(cmd, err)
				continue
			}
			_ = streamA.SendMsg(&testReq{Depth: 0})
			var dummyA testResp
			_ = streamA.RecvMsg(&dummyA)

			// 2. Start stream B on intercepted connection, calling streamA.SendMsg inside interceptor after streamer()
			var interceptor grpc.StreamClientInterceptor = func(
				ctx context.Context,
				desc *grpc.StreamDesc,
				cc *grpc.ClientConn,
				method string,
				streamer grpc.Streamer,
				opts ...grpc.CallOption,
			) (grpc.ClientStream, error) {
				cs, streamerErr := streamer(ctx, desc, cc, method, opts...)
				if streamerErr != nil {
					return nil, streamerErr
				}
				// B raw stream has already been established and constructor_active cleared.
				// B NewStream frame is still active until interceptor returns.
				// Exercising streamA invokes streamA.withRetry.
				if sendErr := streamA.SendMsg(&testReq{Depth: 2}); sendErr != nil {
					return nil, sendErr
				}
				return cs, nil
			}
			interceptedConn, err := grpc.NewClient(
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
				grpc.WithStreamInterceptor(interceptor),
			)
			if err != nil {
				_ = streamA.CloseSend()
				report(cmd, err)
				continue
			}

			streamB, err := interceptedConn.NewStream(context.Background(), &streamDescB, "/TestService/StreamB")
			if err != nil {
				_ = interceptedConn.Close()
				_ = streamA.CloseSend()
				report(cmd, err)
				continue
			}
			_ = streamB.SendMsg(&testReq{Depth: 20})
			var dummyB testResp
			_ = streamB.RecvMsg(&dummyB)

			// Close stream B
			_ = streamB.CloseSend()
			for {
				if err := streamB.RecvMsg(&dummyB); err != nil {
					break
				}
			}
			_ = interceptedConn.Close()

			// Close stream A
			_ = streamA.CloseSend()
			for {
				if err := streamA.RecvMsg(&dummyA); err != nil {
					break
				}
			}
			report(cmd, nil)

		case "STREAM_STATS_TAG":
			report(cmd, runStatsHandlerInterleaving(addr, connA, true))

		case "STREAM_STATS_BEGIN":
			report(cmd, runStatsHandlerInterleaving(addr, connA, false))

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
