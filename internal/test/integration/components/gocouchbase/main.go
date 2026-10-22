// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/couchbase/gocb/v2"
)

const (
	keyspace        = "`test-bucket`.`test-scope`.`test-collection`"
	insertStatement = "INSERT INTO " + keyspace + ` (KEY, VALUE) VALUES ("go::1", {"name": "Gopher", "type": "go-adhoc"})`
	deleteStatement = "DELETE FROM " + keyspace + ` WHERE META().id = "go::1"`
	preparedSelect  = "SELECT META().id FROM " + keyspace + " WHERE type = $1"
	preparedDelete  = "DELETE FROM " + keyspace + " WHERE META().id = $1"
)

func runQuery(cluster *gocb.Cluster, statement string, opts *gocb.QueryOptions) error {
	result, err := cluster.Query(statement, opts)
	if err != nil {
		return err
	}
	for result.Next() {
	}
	return result.Close()
}

func handler(queries func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if err := queries(); err != nil {
			log.Printf("query failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	cluster, err := gocb.Connect("couchbase://couchbase", gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{Username: "Administrator", Password: "password"},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := cluster.WaitUntilReady(60*time.Second, &gocb.WaitUntilReadyOptions{
		ServiceTypes: []gocb.ServiceType{gocb.ServiceTypeQuery},
	}); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/sqlpp-adhoc", handler(func() error {
		for _, statement := range []string{insertStatement, deleteStatement} {
			if err := runQuery(cluster, statement, &gocb.QueryOptions{Adhoc: true}); err != nil {
				return err
			}
		}
		return nil
	}))

	http.HandleFunc("/sqlpp-prepared", handler(func() error {
		if err := runQuery(cluster, preparedSelect, &gocb.QueryOptions{
			PositionalParameters: []any{"prepared-test"},
		}); err != nil {
			return err
		}
		return runQuery(cluster, preparedDelete, &gocb.QueryOptions{
			PositionalParameters: []any{"go::prepared"},
		})
	}))

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Println("Server running: port=8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
