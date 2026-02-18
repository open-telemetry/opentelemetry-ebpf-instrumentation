// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
// Code based on https://github.com/jaihindhreddy/go-testebpf
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	_ "goshorturl/memsql"
)

type service struct {
	storage *sql.DB
	logger  *slog.Logger
}

func main() {
	serverPort := getPortFromEnv()
	database := initDatabase()
	defer database.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	svc := &service{storage: database, logger: logger}

	router := http.NewServeMux()
	router.HandleFunc("/shorten", svc.createShortURL)

	addr := ":" + strconv.Itoa(serverPort)
	fmt.Printf("Server listening on port %d\n", serverPort)
	log.Fatal(http.ListenAndServe(addr, router))
}

func getPortFromEnv() int {
	portStr := os.Getenv("PORT")
	if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
		return port
	}
	return 8081
}

func initDatabase() *sql.DB {
	conn, err := sql.Open("sql-test-in-memory", "memdb://localhost/short")
	if err != nil {
		log.Fatal("Database initialization failed:", err)
	}

	if err := conn.Ping(); err != nil {
		log.Fatal("Database ping failed:", err)
	}

	return conn
}

func (s *service) createShortURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	urlValue, err := s.extractURLFromRequest(r)
	if err != nil {
		s.respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	shortCode := computeShortCode(urlValue)

	if collision := s.checkForCollision(r, shortCode, urlValue); collision {
		s.respondWithError(w, "Hash collision detected", http.StatusInternalServerError)
		return
	}

	existing, _ := s.lookupExistingURL(r, shortCode)
	if existing == "" {
		if err := s.persistURL(r, urlValue, shortCode); err != nil {
			s.respondWithError(w, "Failed to save URL", http.StatusInternalServerError)
			return
		}
	}

	s.respondWithShortURL(w, shortCode)
}

func (s *service) extractURLFromRequest(r *http.Request) (string, error) {
	var urlValue string

	multipartErr := r.ParseMultipartForm(10 << 20)
	if multipartErr != nil {
		if formErr := r.ParseForm(); formErr != nil {
			return "", fmt.Errorf("Invalid request")
		}
		urlValue = r.FormValue("url")
	} else {
		if file, _, err := r.FormFile("url"); err == nil {
			defer file.Close()
			return "", fmt.Errorf("URL must be form field, not file")
		}
		urlValue = r.FormValue("url")
	}

	if urlValue == "" {
		return "", fmt.Errorf("URL is required")
	}

	return urlValue, nil
}

func (s *service) lookupExistingURL(r *http.Request, shortCode string) (string, error) {
	var original string
	query := "SELECT original FROM urls WHERE hash = $1"
	err := s.storage.QueryRowContext(r.Context(), query, shortCode).Scan(&original)
	return original, err
}

func (s *service) checkForCollision(r *http.Request, shortCode, expectedURL string) bool {
	existingURL, err := s.lookupExistingURL(r, shortCode)
	if err != nil {
		return false
	}
	return existingURL != expectedURL
}

func (s *service) persistURL(r *http.Request, originalURL, shortCode string) error {
	query := "INSERT INTO urls (original, hash) VALUES ($1, $2)"
	_, err := s.storage.ExecContext(r.Context(), query, originalURL, shortCode)
	return err
}

func (s *service) respondWithShortURL(w http.ResponseWriter, shortCode string) {
	w.Header().Set("Content-Type", "application/json")
	response := fmt.Sprintf(`{"short_url": "http://test.io/%s"}`, shortCode)
	fmt.Fprint(w, response)
}

func (s *service) respondWithError(w http.ResponseWriter, message string, statusCode int) {
	http.Error(w, message, statusCode)
	s.logger.Info("API request", "api-name", "shorten", "status", statusCode)
}

func computeShortCode(input string) string {
	digest := sha256.Sum256([]byte(input))
	encoded := hex.EncodeToString(digest[:])
	return encoded[:8]
}
