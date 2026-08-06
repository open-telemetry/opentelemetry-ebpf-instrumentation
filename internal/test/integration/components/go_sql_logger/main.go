// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

const jsonLoggerMessage = "this is a json log after sql query"

func main() {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec("DROP TABLE IF EXISTS students"); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE students (name VARCHAR(80), id INT)"); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO students (name, id) VALUES ($1, $2)`, "Bob", 1); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/json_logger", func(w http.ResponseWriter, _ *http.Request) {
		rows, err := db.Query("SELECT * FROM students")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows.Close()

		entry := map[string]any{
			"message": jsonLoggerMessage,
			"level":   "INFO",
			"ts":      time.Now().UTC().Format(time.RFC3339),
		}
		b, err := json.Marshal(entry)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println(string(b))

		_, _ = w.Write([]byte("ok\n"))
	})

	log.Println("HTTP listening on :8090")
	log.Fatal(http.ListenAndServe(":8090", nil))
}
