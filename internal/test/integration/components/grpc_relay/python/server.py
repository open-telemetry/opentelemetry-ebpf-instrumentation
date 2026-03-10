import grpc
import logging
import os
from concurrent import futures

import relay_pb2
import relay_pb2_grpc


class RelayServicer(relay_pb2_grpc.RelayServicer):
    def __init__(self, next_hop):
        self.next_hop = next_hop

    def Relay(self, request, context):
        logging.info("received Relay RPC")
        if self.next_hop:
            with grpc.insecure_channel(self.next_hop) as channel:
                stub = relay_pb2_grpc.RelayStub(channel)
                stub.Relay(relay_pb2.RelayRequest())
        return relay_pb2.RelayResponse()


def serve():
    port = os.environ.get("GRPC_PORT", "50051")
    next_hop = os.environ.get("NEXT_HOP", "")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    relay_pb2_grpc.add_RelayServicer_to_server(RelayServicer(next_hop), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    logging.info(f"gRPC listening on :{port}")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    serve()
