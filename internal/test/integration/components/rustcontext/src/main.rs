// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
#[cfg(not(feature = "server"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

fn outgoing_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    let request = client.get(url);
    if std::env::var_os("OBI_RUST_APP_HEADER").is_some() {
        let number = url.rsplit('/').next().unwrap().parse::<u64>().unwrap() + 1;
        request.header(
            "traceparent",
            format!("00-{number:032x}-1111111111111111-01"),
        )
    } else {
        request
    }
}

async fn fetch(client: reqwest::Client, url: String) {
    #[cfg(feature = "rustls_client")]
    {
        let _ = client;
        rustls_fetch(url).await;
    }
    #[cfg(not(any(feature = "reqwest_010", feature = "rustls_client")))]
    outgoing_request(&client, &url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    #[cfg(feature = "reqwest_010")]
    let task = {
        static RUNTIME: std::sync::OnceLock<std::sync::Mutex<tokio02::runtime::Runtime>> =
            std::sync::OnceLock::new();
        let runtime = RUNTIME
            .get_or_init(|| std::sync::Mutex::new(tokio02::runtime::Runtime::new().unwrap()))
            .lock()
            .unwrap();
        runtime.spawn(async move {
            outgoing_request(&client, &url)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
        })
    };
    #[cfg(feature = "reqwest_010")]
    task.await.unwrap();
}

#[cfg(feature = "rustls_client")]
enum RustlsClient {
    Http1(
        tokio::sync::Mutex<
            hyper::client::conn::http1::SendRequest<http_body_util::Empty<bytes::Bytes>>,
        >,
    ),
    Http2(
        tokio::sync::Mutex<
            hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>,
        >,
    ),
}

#[cfg(feature = "rustls_client")]
async fn rustls_fetch(url: String) {
    use http_body_util::BodyExt;
    #[cfg(not(feature = "rustls_client_legacy"))]
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    #[cfg(feature = "rustls_client_legacy")]
    use tokio_rustls::rustls::{Certificate, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    static CLIENT: tokio::sync::OnceCell<RustlsClient> = tokio::sync::OnceCell::const_new();
    let uri = reqwest::Url::parse(&url).unwrap();
    let client = CLIENT
        .get_or_init(|| async {
            let cert = std::fs::read(std::env::var("OBI_RUST_CERT").unwrap()).unwrap();
            let mut roots = RootCertStore::empty();
            #[cfg(not(feature = "rustls_client_legacy"))]
            roots.add(CertificateDer::from(cert)).unwrap();
            #[cfg(feature = "rustls_client_legacy")]
            roots.add(&Certificate(cert)).unwrap();
            #[cfg(not(feature = "rustls_client_legacy"))]
            let builder = ClientConfig::builder();
            #[cfg(feature = "rustls_client_legacy")]
            let builder = ClientConfig::builder().with_safe_defaults();
            let mut config = builder.with_root_certificates(roots).with_no_client_auth();
            let h2 = std::env::var_os("OBI_RUST_H2").is_some();
            config.alpn_protocols = vec![if h2 {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }];
            let socket = tokio::net::TcpStream::connect((
                uri.host_str().unwrap(),
                uri.port_or_known_default().unwrap(),
            ))
            .await
            .unwrap();
            #[cfg(not(feature = "rustls_client_legacy"))]
            let name = ServerName::try_from(uri.host_str().unwrap().to_owned()).unwrap();
            #[cfg(feature = "rustls_client_legacy")]
            let name = ServerName::try_from(uri.host_str().unwrap()).unwrap();
            let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, socket)
                .await
                .unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            if h2 {
                let (sender, connection) =
                    hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                        .await
                        .unwrap();
                tokio::spawn(async move {
                    connection.await.unwrap();
                });
                RustlsClient::Http2(tokio::sync::Mutex::new(sender))
            } else {
                let (sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
                tokio::spawn(async move {
                    connection.await.unwrap();
                });
                RustlsClient::Http1(tokio::sync::Mutex::new(sender))
            }
        })
        .await;
    let target = if matches!(client, RustlsClient::Http1(_)) {
        let mut path = uri.path().to_owned();
        if let Some(query) = uri.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    } else {
        url
    };
    let request = hyper::Request::builder()
        .uri(target)
        .header("host", uri.authority())
        .body(http_body_util::Empty::new())
        .unwrap();
    let response = match client {
        RustlsClient::Http1(sender) => {
            let mut sender = sender.lock().await;
            sender.ready().await.unwrap();
            let response = sender.send_request(request);
            drop(sender);
            response.await.unwrap()
        }
        RustlsClient::Http2(sender) => {
            let mut sender = sender.lock().await;
            sender.ready().await.unwrap();
            let response = sender.send_request(request);
            drop(sender);
            response.await.unwrap()
        }
    };
    response.into_body().collect().await.unwrap();
}

async fn serve() {
    let listen = std::env::var("OBI_RUST_LISTEN").unwrap_or_else(|_| "127.0.0.1:18090".to_owned());
    let listener = TcpListener::bind(listen).await.unwrap();
    let downstream = Arc::new(std::env::args().nth(1).expect("downstream URL"));
    let builder = reqwest::Client::builder();
    #[cfg(feature = "tls")]
    let builder = builder.danger_accept_invalid_certs(true);
    let builder = if std::env::var_os("OBI_RUST_H2C").is_some() {
        builder.http2_prior_knowledge()
    } else {
        builder
    };
    let client = builder.build().unwrap();
    #[cfg(feature = "server")]
    let acceptor = {
        #[cfg(not(feature = "server_legacy"))]
        use tokio_rustls::rustls::{
            pki_types::{CertificateDer, PrivateKeyDer},
            ServerConfig,
        };
        let cert = std::fs::read(std::env::var("OBI_RUST_CERT").unwrap()).unwrap();
        let key = std::fs::read(std::env::var("OBI_RUST_KEY").unwrap()).unwrap();
        #[cfg(not(feature = "server_legacy"))]
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        #[cfg(feature = "server_legacy")]
        let mut config = tokio_rustls::rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::Certificate(cert)],
                tokio_rustls::rustls::PrivateKey(key),
            )
            .unwrap();
        config.alpn_protocols = vec![if std::env::var_os("OBI_RUST_SERVER_HTTP1").is_some() {
            b"http/1.1".to_vec()
        } else {
            b"h2".to_vec()
        }];
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    };
    println!("READY {}", listener.local_addr().unwrap());
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        #[cfg(not(feature = "server"))]
        let mut stream = stream;
        let client = client.clone();
        let downstream = downstream.clone();
        #[cfg(feature = "server")]
        {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let client = client.clone();
                        let downstream = downstream.clone();
                        // Hyper's connection task invokes this before polling the returned future.
                        let child = tokio::spawn(async move {
                            tokio::task::yield_now().await;
                            sleep(Duration::from_millis(5)).await;
                            let path = request.uri().path();
                            fetch(client, format!("{downstream}{path}")).await;
                            use http_body_util::BodyExt;
                            let trailers = std::env::var_os("OBI_RUST_TRAILERS").is_some();
                            let body = http_body_util::Full::new(bytes::Bytes::from_static(b"ok"));
                            let body = if trailers {
                                body.with_trailers(async {
                                    let mut headers = hyper::HeaderMap::new();
                                    headers.insert("x-obi-trailer", "done".parse().unwrap());
                                    Some(Ok(headers))
                                })
                                .boxed()
                            } else {
                                body.boxed()
                            };
                            let mut response = hyper::Response::new(body);
                            if trailers {
                                response.headers_mut().insert(
                                    hyper::header::TRANSFER_ENCODING,
                                    "chunked".parse().unwrap(),
                                );
                                response.headers_mut().insert(
                                    hyper::header::TRAILER,
                                    "x-obi-trailer".parse().unwrap(),
                                );
                            }
                            Ok::<_, std::convert::Infallible>(response)
                        });
                        async move { child.await.unwrap() }
                    },
                );
                if std::env::var_os("OBI_RUST_SERVER_HTTP1").is_some() {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await
                        .unwrap();
                } else {
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await
                        .unwrap();
                }
            });
        }
        #[cfg(not(feature = "server"))]
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let len = stream.read(&mut chunk).await.unwrap();
                if len == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..len]);
            }
            let request = String::from_utf8(request).unwrap();
            let path = request.split_whitespace().nth(1).unwrap().to_owned();
            let child = tokio::spawn(async move {
                tokio::task::yield_now().await;
                sleep(Duration::from_millis(5)).await;
                let nested = tokio::spawn(async move {
                    fetch(client, format!("{downstream}{path}")).await;
                });
                nested.await.unwrap();
            });
            child.await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
    }
}

fn main() {
    let runtime = if std::env::var_os("OBI_RUST_CURRENT_THREAD").is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    };
    runtime.block_on(serve());
}
