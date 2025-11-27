// Example httpdispatcher application
var http = require("http");
var dispatcher = require("httpdispatcher");

// String literal routes
dispatcher.onGet("/health", function (req, res) {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("OK");
});

dispatcher.onGet("/users", function (req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify([{ id: 1, name: "Alice" }]));
});

// Regex routes
dispatcher.onPost(/^\/ratings\/[0-9]*/, function (req, res) {
  res.writeHead(201, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ message: "Rating created" }));
});

dispatcher.onGet(/^\/ratings\/[0-9]*/, function (req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ id: 123, rating: 5 }));
});

dispatcher.onPut(/^\/api\/v1\/products\/[a-zA-Z0-9-]+$/, function (req, res) {
  res.writeHead(200);
  res.end("Product updated");
});

dispatcher.onDelete("/items/:id", function (req, res) {
  res.writeHead(204);
  res.end();
});

// More complex patterns
dispatcher.onGet(/^\/files\/.*\.pdf$/, function (req, res) {
  res.writeHead(200, { "Content-Type": "application/pdf" });
  res.end();
});

var server = http.createServer(function (req, res) {
  dispatcher.dispatch(req, res);
});

server.listen(8080, function () {
  console.log("Server listening on: http://localhost:8080");
});
