const express = require('express');
const axios = require('axios');
const path = require('node:path');
const fs = require('node:fs');

const app = express();

app.get("/smoke", (req, res) => {
    res.sendStatus(200)
});

app.get('/b', async (req, res) => {
    try {
        // Making all requests in parallel using Promise.all
        const serviceCRequest = await axios.get('http://localhost:5006/p');
        const serviceRRequest = await axios.get('http://localhost:5006/r');
        const serviceQRequest = await axios.get(
            'http://localhost:5006/q',
            {
                query: '{ hello }'  // GraphQL query as JSON payload
            },
            {
                headers: { 'Content-Type': 'application/json' }
            }
        );

        // Wait for all requests to finish
        const [serviceCResponse, serviceRResponse, serviceQResponse] = await Promise.all([serviceCRequest, serviceRRequest, serviceQRequest]);

        // Combine results
        res.send(`
            Service B -> Service C -> ${serviceCResponse.data} <br>
            Service B -> Service R -> ${serviceRResponse.data} <br>
            Service B -> Service Q -> ${JSON.stringify(serviceQResponse.data)}
        `);
    } catch (error) {
        console.error('Error in Service B:', error.message);
        res.status(500).send('Service B encountered an error');
    }
});

function readAgent(file) {
  const source = fs.readFileSync(file, 'utf8');
  return source;
}

function installAgent() {
  const agentDir = path.resolve(__dirname, './agent');
  let source = readAgent(path.join(agentDir, 'fdextractor-fdopt.js'));

  eval(source + '\n//# sourceURL=obi-fdextractor.js');
}

installAgent();

app.listen(5001, () => console.log('Service B running on port 5001'));

