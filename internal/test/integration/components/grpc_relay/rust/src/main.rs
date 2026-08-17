use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

use relay::relay_client::RelayClient;
use relay::relay_server::{Relay, RelayServer};
use relay::{RelayRequest, RelayResponse};

pub mod relay {
    tonic::include_proto!("relay");
}

struct RelayService {
    // Persistent tonic channel so requests 2+ emit HPACK dyn-table indexed names
    client: RelayClient<Channel>,
}

#[tonic::async_trait]
impl Relay for RelayService {
    async fn relay(
        &self,
        _req: TonicRequest<RelayRequest>,
    ) -> Result<TonicResponse<RelayResponse>, Status> {
        let mut c = self.client.clone();
        c.relay(TonicRequest::new(RelayRequest {})).await?;
        Ok(TonicResponse::new(RelayResponse {}))
    }
}

async fn health(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from_static(b"ok")))
        .unwrap())
}

async fn serve_health(port: u16) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(addr).await.expect("bind health");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(health))
                .await;
        });
    }
}

// current_thread: OBI's thread-keyed trace correlation needs ingress and egress on one thread
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let grpc_port: u16 = std::env::var("GRPC_PORT")
        .expect("GRPC_PORT")
        .parse()?;
    let next_hop = std::env::var("NEXT_HOP").expect("NEXT_HOP");
    let health_port: u16 = std::env::var("HEALTH_PORT")
        .expect("HEALTH_PORT")
        .parse()?;

    let endpoint = Endpoint::from_shared(format!("http://{}", next_hop))?;
    let channel = endpoint.connect_lazy();
    let svc = RelayService {
        client: RelayClient::new(channel),
    };

    tokio::spawn(serve_health(health_port));

    let addr: SocketAddr = ([0, 0, 0, 0], grpc_port).into();
    println!("rust-relay gRPC listening on {}", addr);
    Server::builder()
        .add_service(RelayServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}
