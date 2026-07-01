// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Rust HTTP server emitting USDT probes via the `usdt` crate. Mirrors the
// other custom_span samples so the integration suite has end-to-end
// coverage on a sixth runtime.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::Duration;

#[usdt::provider(provider = "custom_span_rust")]
mod custom_span_probes {
    fn order_start(_order_id: u64, _customer: &str) {}
    fn order_end(_order_id: u64, _status: i32) {}
    fn cache_hit(_key: &str) {}
}

fn process_order(order_id: u64, customer: &str) {
    custom_span_probes::order_start!(|| (order_id, customer));
    sleep(Duration::from_millis(5));
    custom_span_probes::order_end!(|| (order_id, 0_i32));
}

fn cache_lookup(key: &str) {
    custom_span_probes::cache_hit!(|| (key));
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

fn handle_client(mut stream: TcpStream) {
    let mut buf = [0_u8; 4096];
    let mut total = 0_usize;
    while total + 1 < buf.len() {
        let n = match stream.read(&mut buf[total..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = match std::str::from_utf8(&buf[..total]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut parts = req.split_whitespace();
    let _method = parts.next();
    let path_with_query = parts.next().unwrap_or("/");
    let (path, query) = path_with_query
        .split_once('?')
        .unwrap_or((path_with_query, ""));

    let body = match path {
        "/smoke" => "ok",
        "/order" => {
            let order_id = query_param(query, "id")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1);
            let customer = query_param(query, "customer").unwrap_or("anonymous");
            process_order(order_id, customer);
            "ok"
        }
        "/cache" => {
            let key = query_param(query, "key").unwrap_or("");
            cache_lookup(key);
            "ok"
        }
        _ => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn main() {
    usdt::register_probes().expect("register_probes");
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8398".to_string())
        .parse()
        .expect("PORT");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("custom_span_rust listening on {port}");
    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || handle_client(stream));
    }
}
