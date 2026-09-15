// Express application declaring route paths through constants, string
// concatenation and template literals
const express = require("express");
const app = express();
const server = require("restify").createServer();

const base = '/api';
const usersPath = "/users";
const itemsPath = `/items`;
export const version = 'v1';
let mutablePath = '/mutable';
var legacyPath = '/legacy';
const key = 'user:1';
const shadowed = '/outer';

// a bare identifier argument
app.get(usersPath, listUsers);

// let and var may be reassigned, so their value is not trusted
app.get(mutablePath, getMutable);
app.get(legacyPath, getLegacy);

// concatenation of a constant and a literal
app.post(base + '/users', createUser);

// a constant, a literal and another constant
app.put(base + '/' + version + '/users', updateUser);

// a template literal whose interpolations are known constants
app.delete(`${base}/${version}/users/:id`, deleteUser);

// a template literal with an unknown interpolation, left as a placeholder
app.patch(`${base}/users/${req.params.id}`, patchUser);

// concatenation with a template literal
app.get(base + `/items/${itemId}`, getItem);

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

// route chaining
app.route(base + '/books').get(listBooks).post(createBook);

// restify
server.del(base + itemsPath + '/:id', deleteItem);

// a call spanning several lines
app.get(
  base + '/multi',
  multiHandler
);

// an argument cut by a line break
app.get(base
  + '/split',
  splitHandler
);

/*
commented-out code neither declares nor shadows a constant
const base = '/old-api';
app.get(base + '/old', oldHandler);
*/

// a value that is not a path is dropped
cache.get(key, loadUser);

app.listen(3000);
