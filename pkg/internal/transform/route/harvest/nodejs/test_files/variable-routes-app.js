// Express application declaring route paths through constants, string
// concatenation and template literals
const express = require("express");
const app = express();
const server = require("restify").createServer();

// --- declarations -----------------------------------------------------------

const base = '/api';
const usersPath = "/users";
const itemsPath = `/items`;
export const version = 'v1';
let mutablePath = '/mutable';
var legacyPath = '/legacy';
const key = 'user:1';
const shadowed = '/outer';
const prefix = '/v2'; // current prefix
const health = "/health" /* liveness */

// constants built from other constants, numbers, comments and groups
const usersBase = base + usersPath;
const versioned = `${base}/${version}`;
const apiVersion = 2;
const legacyBase = /* v1 */ '/legacy-api';
const first = '/first', second = '/second';
const item = `${usersPath}/${itemId}`;
const m1 = '/m1'; const m2 = '/m2';

// a call spelled in a comment or a string is not a call
doWork(); // app.get(prefix
log('app.get(' + base);

// regular expression literals are not comments
const clean = (p) => p.replace(/\/*$/, '');
app.get(/^\/api\/*$/, regexHandler);

// --- route calls ------------------------------------------------------------

// a bare identifier argument
app.get(usersPath, listUsers);

// let and var may be reassigned, so their value is not trusted
app.get(mutablePath, getMutable);
app.get(legacyPath, getLegacy);

// concatenations and templates of constants and literals
app.post(base + '/users', createUser);
app.put(base + '/' + version + '/users', updateUser);
app.delete(`${base}/${version}/users/:id`, deleteUser);
app.get(base + `/items/${itemId}`, getItem);
app.get(prefix + health, getHealth);
app.get(`${prefix}/ready`, getReady);

// a template literal with an unknown interpolation, left as a placeholder
app.patch(`${base}/users/${req.params.id}`, patchUser);

// constants that were themselves resolved
app.get(usersBase + '/all', listAll);
app.get(`${versioned}/status`, getStatus);
app.get(`/v${apiVersion}/ping`, ping);
app.get(legacyBase + '/x', legacy);
app.get(first + second, firstSecond);
app.get(item + '/detail', itemDetail);
app.get(m1 + m2, m1m2);

// groups and expressions inside an interpolation
app.get((base + '/grouped'), grouped);
app.get(`${base + '/joined'}/x`, joined);

// a name declared in more than one scope is ambiguous and never resolved
function nested() {
  const shadowed = '/inner';
  app.head(shadowed, headInner);
}
app.head(shadowed, headOuter);

// a name declared later in the file is unknown here
app.options(later, optionsHandler);
const later = '/later';

// an unknown name anywhere in a chain leaves the route unresolved
app.get(unknownPrefix + '/orders', listOrders);

// route chaining and restify
app.route(base + '/books').get(listBooks).post(createBook);
server.del(base + itemsPath + '/:id', deleteItem);

// a value that is not a path is dropped
cache.get(key, loadUser);

// --- calls and comments spanning lines --------------------------------------

app.get(
  base + '/multi',
  multiHandler
);

app.get(base
  + '/split',
  splitHandler
);

app.get(
  base + '/compact', compactHandler);
app.get('/plain' +
  '/split', plainSplitHandler);

app.get(base + '/commented' /* create */, commentedHandler);
app.get(base + '/noted' // path
  , notedHandler);

/*
commented-out code neither declares nor shadows a constant
const base = '/old-api';
app.get(base + '/old', oldHandler);
*/

app.get(base + '/before', beforeHandler); /* opened after code
const base = '/dead';
*/ app.get(base + '/after', afterHandler);

app.listen(3000);
