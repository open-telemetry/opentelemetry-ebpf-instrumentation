# OBI MySQL protocol parser

This document describes connection state that the MySQL protocol parser tracks to set `db.namespace`. It comes from the [client/server protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html) traffic OBI observes on a connection, so connections opened before OBI attached report no namespace.

## Database namespace

OBI sets `db.namespace` to the connection's current database:

- The client's **HandshakeResponse41** gives the initial database when it sets `CLIENT_CONNECT_WITH_DB`. After an `SSLRequest`, the response sent over TLS is used, including when both are captured in one event.
- A `COM_INIT_DB`, or a `COM_QUERY` holding a single `USE <db>` statement, replaces the database when the server answers with an OK packet.
- The database is cleared instead when OBI cannot tell which database is now selected: after a `COM_CHANGE_USER`, a `COM_QUERY` that starts with `USE` but holds more than one statement, or a database change whose response was captured without its body (libmysqlclient over TLS reads the packet header separately), where OK and ERR cannot be told apart.

A database selected in other ways, such as a `USE` that is not the first statement of a multi-statement query, is not tracked. Statements that name no table use the namespace as their span name target, for example `SELECT db1`.

Go `database/sql` spans come from Go library instrumentation instead of the TCP parser, so they carry no namespace.
