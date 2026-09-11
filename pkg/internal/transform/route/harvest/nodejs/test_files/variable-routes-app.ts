// Express application in TypeScript declaring route prefixes with type
// annotations and trailing comments
import express from 'express';

const app = express();

const base: string = '/api';
export const version: string = 'v2'; // current API version
const typed: Path = '/typed';
const chained: string = '/chained' as const;
const casted = <string>'/casted';
const checked = '/checked' satisfies string;

app.get(base + '/users', listUsers);
app.put(`${base}/${version}/users/:id`, updateUser);
app.post(base + '/orders' /* create */, createOrder);

// any annotation is accepted when the initializer resolves
app.get(typed + '/items', listTyped);

// type assertions, casts and non-null assertions have no runtime effect
app.get(chained + '/items', listChained);
app.get(casted + '/items', listCasted);
app.get((checked + '/items') as string, listChecked);
app.get(typed! + '/nn', nonNull);

app.listen(3000);
