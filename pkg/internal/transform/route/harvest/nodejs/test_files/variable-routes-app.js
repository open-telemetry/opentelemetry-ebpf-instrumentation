// Express application declaring route paths through variables, string
// concatenation and template literals
const express = require("express");
const app = express();
const server = require("restify").createServer();

const base = '/api';
let usersPath = "/users";
var itemsPath = `/items`;
export const version = 'v1';
const key = 'user:1';
const dup = '/first';
const dup = '/second';

// a bare identifier argument
app.get(usersPath, listUsers);

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

// the latest declaration of a name wins
app.head(dup, headHandler);

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

// a value that is not a path is dropped
cache.get(key, loadUser);

app.listen(3000);
