package relay;

import com.sun.net.httpserver.HttpServer;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.stub.StreamObserver;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.channel.EventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioServerSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

public class RelayServer extends RelayGrpc.RelayImplBase {

    private final String nextHop;
    // Shared event loop so that the same Netty I/O thread handles both the
    // incoming server connection and the outgoing client connection.
    private final EventLoopGroup ioGroup;

    public RelayServer(String nextHop, EventLoopGroup ioGroup) {
        this.nextHop = nextHop;
        this.ioGroup = ioGroup;
    }

    @Override
    public void relay(RelayProto.RelayRequest request, StreamObserver<RelayProto.RelayResponse> responseObserver) {
        System.out.println("received Relay RPC");
        if (nextHop != null && !nextHop.isEmpty()) {
            ManagedChannel channel = NettyChannelBuilder.forTarget(nextHop)
                    .usePlaintext()
                    .eventLoopGroup(ioGroup)
                    .channelType(NioSocketChannel.class)
                    .build();
            try {
                RelayGrpc.RelayBlockingStub stub = RelayGrpc.newBlockingStub(channel)
                        .withDeadlineAfter(10, TimeUnit.SECONDS);
                stub.relay(RelayProto.RelayRequest.newBuilder().build());
            } finally {
                channel.shutdown();
                try {
                    channel.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        responseObserver.onNext(RelayProto.RelayResponse.newBuilder().build());
        responseObserver.onCompleted();
    }

    public static void main(String[] args) throws Exception {
        String grpcPort = System.getenv("GRPC_PORT");
        if (grpcPort == null || grpcPort.isEmpty()) {
            grpcPort = "50055";
        }
        String nextHop = System.getenv("NEXT_HOP");
        String healthPort = System.getenv("HEALTH_PORT");
        if (healthPort == null || healthPort.isEmpty()) {
            healthPort = "8093";
        }

        int port = Integer.parseInt(grpcPort);

        // Single-threaded NIO groups shared between server worker and client I/O.
        // Explicit NIO channel types avoid the Epoll/NIO mismatch on Linux when
        // only the worker group is overridden.
        // The same Netty thread that processes the incoming gRPC HEADERS (and whose
        // TID OBI records in server_traces) also performs the outgoing tcp_sendmsg,
        // so find_parent_process_trace can resolve the parent via server_traces[tid].
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup ioGroup = new NioEventLoopGroup(1);

        Server server = NettyServerBuilder.forPort(port)
                .bossEventLoopGroup(bossGroup)
                .workerEventLoopGroup(ioGroup)
                .channelType(NioServerSocketChannel.class)
                .addService(new RelayServer(nextHop, ioGroup))
                .build()
                .start();

        System.out.println("gRPC listening on :" + port);

        // Health check endpoint
        HttpServer health = HttpServer.create(new InetSocketAddress(Integer.parseInt(healthPort)), 0);
        health.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        health.start();
        System.out.println("health listening on :" + healthPort);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.shutdown();
            bossGroup.shutdownGracefully();
            ioGroup.shutdownGracefully();
        }));

        server.awaitTermination();
    }
}
