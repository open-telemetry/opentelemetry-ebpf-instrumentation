#!/usr/bin/env ruby
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# HTTP server emitting USDT probes via ruby-stapsdt (libstapsdt-backed).
# Mirrors the custom_span_c / custom_span_python routes so the integration test can
# exercise auto-discover against a runtime-generated .so produced from Ruby.

require "stapsdt"
require "webrick"

PORT = (ENV["PORT"] || "8393").to_i

provider = StapSDT::Provider.new("custom_span_rb")
order_start = provider.add_probe("order_start", Integer, String)
order_end   = provider.add_probe("order_end",   Integer, Integer)
cache_hit   = provider.add_probe("cache_hit",   String)
provider.load

def process_order(order_id, customer, order_start, order_end)
  order_start.fire(order_id, customer)
  sleep 0.02
  order_end.fire(order_id, 0)
end

server = WEBrick::HTTPServer.new(Port: PORT, BindAddress: "0.0.0.0", AccessLog: [], Logger: WEBrick::Log.new(File.open(File::NULL, "w")))

server.mount_proc "/smoke" do |_req, res|
  res.body = "ok"
end

server.mount_proc "/order" do |req, res|
  id = (req.query["id"] || "1").to_i
  id = 1 if id == 0
  customer = req.query["customer"] || "anonymous"
  process_order(id, customer, order_start, order_end)
  res.body = "ok"
end

server.mount_proc "/cache" do |req, res|
  key = req.query["key"] || "default"
  cache_hit.fire(key)
  res.body = "ok"
end

$stderr.puts "custom_span_ruby listening on :#{PORT}"
$stderr.flush
trap("INT") { server.shutdown }
server.start
