// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;

async fn serve() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("READY {}", listener.local_addr().unwrap());
    let (stream, _) = listener.accept().await.unwrap();
    tokio::spawn(async move {
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            if stream.read_line(&mut line).await.unwrap() == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
        }
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            println!("CHILD");
            // Keep both tasks live while the test inspects their contexts.
            let mut ack = [0; 1];
            let _ = stream.read_exact(&mut ack).await;
        })
        .await
        .unwrap();
    })
    .await
    .unwrap();
}

fn main() {
    let mut runtime = if std::env::var_os("OBI_RUST_CURRENT_THREAD").is_some() {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let mut runtime = tokio::runtime::Builder::new_multi_thread();
        runtime.worker_threads(2);
        runtime
    };
    runtime.enable_all().build().unwrap().block_on(serve());
}
