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
