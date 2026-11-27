// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use hyper::{body::Incoming, client::conn::http1::Connection, upgrade::Upgraded, Request};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

// Polling a concrete client makes rustc emit Hyper's private dispatch envelope,
// its Poll<Option<Envelope>> result, and the Tokio queue that carries it.
pub fn poll_http1(
    connection: Pin<&mut Connection<Upgraded, Incoming>>,
    context: &mut Context<'_>,
    _request: &Request<()>,
    _buffer: &Vec<u8>,
) -> Poll<hyper::Result<()>> {
    connection.poll(context)
}

// A body whose alignment can change the position of Request.head.
#[repr(align(64))]
pub struct AlignedBody([u8; 64]);

impl hyper::body::Body for AlignedBody {
    type Data = hyper::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::hint::black_box(&self.0);
        Poll::Ready(None)
    }
}

pub fn poll_aligned_http1(
    connection: Pin<&mut Connection<Upgraded, AlignedBody>>,
    context: &mut Context<'_>,
    _request: &Request<AlignedBody>,
) -> Poll<hyper::Result<()>> {
    connection.poll(context)
}
