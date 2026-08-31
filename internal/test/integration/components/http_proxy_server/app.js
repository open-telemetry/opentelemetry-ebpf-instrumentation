var express = require("express");
const http = require("http");
const net = require("net");
const bodyParser = require("body-parser");
var app = express();
const port = 3030;

const jsonParser = bodyParser.json()

app.use(express.json({ limit: "50mb" }));

function send({ host, port, rawRequest }) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(port, host);
    let response = "";

    client.on("connect", () => {
      client.write(rawRequest);
    });

    client.on("data", (chunk) => {
      response += chunk.toString("utf-8");
    });

    client.on("end", () => {
      resolve(response);
    });

    client.on("error", (err) => {
      reject(err);
    });
  });
}

app.get("/smoke", (req, res, next) => {
  res.json("healthy");
})

app.get("/greeting", (req, res, next) => {
  res.json("Hello!");
});

app.get("/bye", (req, res, next) => {
  res.json(`Bye!`);
});

app.post("/dial", jsonParser, async (req, res, next) => {
  if (!req.body || !req.body.rawRequest || !req.body.host) {
    res.sendStatus(400);
  }

  try {
    const [host, port] = req.body.host.split(":");
    console.log("sending nested call: ", req.body.rawRequest);
    const response = await send({ host: host, port: parseInt(port), rawRequest: req.body.rawRequest });
    const status = response.split("\r\n")[0];
    // The body is returned so a caller can read what the far side actually
    // received — the only way to observe a header this process never wrote,
    // such as the traceparent an eBPF program injects on the way out.
    const body = response.split("\r\n\r\n").slice(1).join("\r\n\r\n");
    res.send({ status: status, body: body });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

app.get(/^\/arbitrary.{1}$/, (req, res) => {
  res.send(req.path);
});

// Reports the headers this server received, so a test can assert on a header
// that was added to the request after the sender wrote it.
app.get(/^\/echoheaders.{0,1}$/, (req, res) => {
  res.json(req.headers);
});

app.listen(port, () => {
  console.log("Server running on port " + port);
});
