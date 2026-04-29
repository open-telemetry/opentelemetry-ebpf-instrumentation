import grpc
import logging
import os
import threading
from concurrent import futures
from http.server import HTTPServer, BaseHTTPRequestHandler

import relay_pb2
import relay_pb2_grpc


class RelayServicer(relay_pb2_grpc.RelayServicer):
    # Persistent downstream channel so concurrent inbound Relay calls
    # multiplex onto a single egress TCP connection (sk_msg coverage path)
    def __init__(self, next_hop):
        self.next_hop = next_hop
        self.stub = None
        if next_hop:
            self.channel = grpc.insecure_channel(next_hop)
            self.stub = relay_pb2_grpc.RelayStub(self.channel)

    def Relay(self, request, context):
        logging.info("received Relay RPC")
        if self.stub:
            self.stub.Relay(relay_pb2.RelayRequest())
        return relay_pb2.RelayResponse()


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def serve():
    port = os.environ.get("GRPC_PORT", "50051")
    next_hop = os.environ.get("NEXT_HOP", "")
    health_port = os.environ.get("HEALTH_PORT", "8090")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    relay_pb2_grpc.add_RelayServicer_to_server(RelayServicer(next_hop), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    logging.info(f"gRPC listening on :{port}")
    server.start()

    health = HTTPServer(("0.0.0.0", int(health_port)), HealthHandler)
    threading.Thread(target=health.serve_forever, daemon=True).start()
    logging.info(f"health listening on :{health_port}")

    server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    serve()
