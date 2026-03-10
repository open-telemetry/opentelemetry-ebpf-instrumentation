package relay;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;

import java.util.concurrent.TimeUnit;

public class RelayServer extends RelayGrpc.RelayImplBase {

    private final String nextHop;

    public RelayServer(String nextHop) {
        this.nextHop = nextHop;
    }

    @Override
    public void relay(RelayProto.RelayRequest request, StreamObserver<RelayProto.RelayResponse> responseObserver) {
        System.out.println("received Relay RPC");
        if (nextHop != null && !nextHop.isEmpty()) {
            ManagedChannel channel = ManagedChannelBuilder.forTarget(nextHop)
                    .usePlaintext()
                    .build();
            try {
                RelayGrpc.RelayBlockingStub stub = RelayGrpc.newBlockingStub(channel)
                        .withDeadlineAfter(10, TimeUnit.SECONDS);
                stub.relay(RelayProto.RelayRequest.newBuilder().build());
            } finally {
                channel.shutdown();
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

        int port = Integer.parseInt(grpcPort);
        Server server = ServerBuilder.forPort(port)
                .addService(new RelayServer(nextHop))
                .build()
                .start();

        System.out.println("gRPC listening on :" + port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.shutdown();
        }));

        server.awaitTermination();
    }
}
