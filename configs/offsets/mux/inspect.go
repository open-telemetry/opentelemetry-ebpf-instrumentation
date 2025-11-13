// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// User represents a user in our API
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// This example demonstrates how to create an HTTP server with Gorilla mux
// using a path prefix /api/v1 and a route /users/{id} where id is a URL parameter.
func main() {
	// Create a new router
	r := mux.NewRouter()

	// Create a subrouter with the /api/v1 prefix
	api := r.PathPrefix("/api/v1").Subrouter()

	// Register the /users/{id} route
	api.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Extract the id variable from the URL
		vars := mux.Vars(r)
		userID := vars["id"]

		// Create a sample user response
		user := User{
			ID:   userID,
			Name: fmt.Sprintf("User %s", userID),
		}

		// Set response header and encode JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	}).Methods("GET")

	// Start the server
	port := ":8090"
	log.Printf("Starting server on %s", port)
	log.Printf("Try: http://localhost%s/api/v1/users/123", port)
	log.Fatal(http.ListenAndServe(port, r))
}
