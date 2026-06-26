// Example Express.js app that registers routes using variables, template
// literals, and string concatenation — patterns the AST pass handles.
const express = require('express');
const app = express();

const API_BASE = '/api';
const VERSION = 'v1';

const usersPath = '/users';
app.get(usersPath, (req, res) => res.json([]));

app.get(`${API_BASE}/${VERSION}/products`, (req, res) => res.json([]));

app.delete(`/users/${id}`, (req, res) => res.status(204).send());

app.post('/api' + '/orders', (req, res) => res.json({ created: true }));

app.put(API_BASE + '/settings', (req, res) => res.json({ updated: true }));

router.get(healthPath, (req, res) => res.send('ok'));
const healthPath = '/health';

app.listen(3000);
