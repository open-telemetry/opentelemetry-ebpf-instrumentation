// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package memsql // import "goshorturl/memsql"

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
)

type Storage struct {
	data map[string]string
	mux  *sync.RWMutex
}

func NewStorage() *Storage {
	return &Storage{
		data: map[string]string{},
		mux:  &sync.RWMutex{},
	}
}

func (s *Storage) get(hash string) string {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.data[hash]
}

func (s *Storage) add(hash, originalURL string) {
	if s.get(hash) != "" {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, exists := s.data[hash]; !exists {
		s.data[hash] = originalURL
	}
}

// MemDB holds the in-memory database instance
type MemDB struct {
	storage *Storage
}

// NewMemDB creates a new in-memory database
func NewMemDB() *MemDB {
	return &MemDB{storage: NewStorage()}
}

var memoryDB = NewMemDB()

func init() {
	sql.Register("sql-test-in-memory", &InMemoryDriver{db: memoryDB})
}

// InMemoryDriver implements the database driver interface
type InMemoryDriver struct {
	db *MemDB
}

// Open establishes a connection to the mock database
func (drv *InMemoryDriver) Open(dsn string) (driver.Conn, error) {
	return &Connection{backend: drv.db}, nil
}

// Connection represents a database connection
type Connection struct {
	backend *MemDB
}

// Close terminates the connection
func (c *Connection) Close() error {
	return nil
}

// Prepare creates a prepared statement (not supported)
func (c *Connection) Prepare(sql string) (driver.Stmt, error) {
	panic("prepared statements not supported")
}

// Begin starts a transaction (not supported)
func (c *Connection) Begin() (driver.Tx, error) {
	panic("transactions not supported")
}

// Ping verifies connection health
func (c *Connection) Ping(ctx interface{}) error {
	return nil
}

// Query executes a query that returns rows
func (c *Connection) Query(sql string, params []driver.Value) (driver.Rows, error) {
	hashKey := params[0].(string)
	originalURL := c.backend.storage.get(hashKey)

	if originalURL == "" {
		return nil, fmt.Errorf("no result for %s", hashKey)
	}

	return &ResultSet{
		records: [][]driver.Value{{originalURL}},
		cursor:  0,
	}, nil
}

// Exec executes a query that doesn't return rows
func (c *Connection) Exec(sql string, params []driver.Value) (driver.Result, error) {
	shortHash := params[0].(string)
	longURL := params[1].(string)
	c.backend.storage.add(longURL, shortHash)

	return &ExecResult{affectedRows: 1}, nil
}

// ResultSet implements driver.Rows for query results
type ResultSet struct {
	records [][]driver.Value
	cursor  int
}

// Columns returns column names
func (rs *ResultSet) Columns() []string {
	return []string{"original_url"}
}

// Close releases resources
func (rs *ResultSet) Close() error {
	return nil
}

// Next advances to the next row
func (rs *ResultSet) Next(destination []driver.Value) error {
	if rs.cursor >= len(rs.records) {
		return fmt.Errorf("end of result set")
	}
	copy(destination, rs.records[rs.cursor])
	rs.cursor++
	return nil
}

// ExecResult implements driver.Result for exec operations
type ExecResult struct {
	affectedRows int64
}

// LastInsertId returns the last inserted ID (not supported)
func (er *ExecResult) LastInsertId() (int64, error) {
	return 0, fmt.Errorf("LastInsertId not available")
}

// RowsAffected returns the number of affected rows
func (er *ExecResult) RowsAffected() (int64, error) {
	return er.affectedRows, nil
}
