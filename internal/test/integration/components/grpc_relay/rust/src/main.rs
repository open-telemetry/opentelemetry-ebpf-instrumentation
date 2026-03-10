use tonic::{transport::Server, Request, Response, Status};

pub mod relay {
    tonic::include_proto!("relay");
}

use relay::relay_client::RelayClient;
use relay::relay_server::{Relay, RelayServer};
use relay::{RelayRequest, RelayResponse};

struct RelayService {
    next_hop: Option<String>,
}

#[tonic::async_trait]
impl Relay for RelayService {
    async fn relay(
        &self,
        _request: Request<RelayRequest>,
    ) -> Result<Response<RelayResponse>, Status> {
        println!("received Relay RPC");
        if let Some(ref next_hop) = self.next_hop {
            let mut client = RelayClient::connect(format!("http://{}", next_hop))
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            client
                .relay(Request::new(RelayRequest {}))
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(RelayResponse {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let grpc_port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50052".to_string());
    let next_hop = std::env::var("NEXT_HOP").ok().filter(|s| !s.is_empty());

    let addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    println!("gRPC listening on {}", addr);

    Server::builder()
        .add_service(RelayServer::new(RelayService { next_hop }))
        .serve(addr)
        .await?;

    Ok(())
}
