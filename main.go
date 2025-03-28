package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/erics1337/boot-dev-chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
}

type validateChirpRequest struct {
	Body string `json:"body"`
}

type validateChirpResponse struct {
	CleanedBody string `json:"cleaned_body,omitempty"`
	Error       string `json:"error,omitempty"`
}

type createUserRequest struct {
	Email string `json:"email"`
}

type createUserResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Email     string `json:"email"`
}

var profaneWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func cleanChirp(body string) string {
	words := strings.Fields(body)
	for i, word := range words {
		wordOnly := strings.TrimFunc(word, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
		})

		for _, profane := range profaneWords {
			if strings.ToLower(wordOnly) == strings.ToLower(profane) && wordOnly == word {
				words[i] = "****"
				break
			}
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error reading request body",
		})
		return
	}

	// Parse the request body
	var req createUserRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid JSON body",
		})
		return
	}

	// Create the user
	user, err := cfg.DB.CreateUser(context.Background(), req.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error creating user",
		})
		return
	}

	// Prepare the response
	resp := createUserResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Email:     user.Email,
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return created status
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func handlerValidateChirp(w http.ResponseWriter, r *http.Request) {
	// Debug: Log request method
	log.Printf("DEBUG: Received %s request to %s", r.Method, r.URL.Path)

	// Validate request method
	if r.Method != http.MethodPost {
		log.Printf("DEBUG: Invalid method %s", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(validateChirpResponse{
			Error: "Method not allowed",
		})
		return
	}

	// Debug: Log content type
	log.Printf("DEBUG: Content-Type: %s", r.Header.Get("Content-Type"))

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("DEBUG: Error reading body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validateChirpResponse{
			Error: "Error reading request body",
		})
		return
	}

	// Debug: Log raw request body
	log.Printf("DEBUG: Raw request body: %s", string(body))

	// Parse the request body
	var req validateChirpRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		log.Printf("DEBUG: Error parsing JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validateChirpResponse{
			Error: "Invalid JSON body",
		})
		return
	}

	// Debug: Log chirp length
	log.Printf("DEBUG: Chirp length: %d", len(req.Body))

	// Validate chirp length
	if len(req.Body) > 140 {
		log.Printf("DEBUG: Chirp too long: %d characters", len(req.Body))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validateChirpResponse{
			Error: "Chirp is too long",
		})
		return
	}

	// Clean the chirp
	cleaned := cleanChirp(req.Body)
	log.Printf("DEBUG: Cleaned chirp: %s", cleaned)

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(validateChirpResponse{
		CleanedBody: cleaned,
	})
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get database connection string
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is not set")
	}

	// Get platform
	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "dev" // Default to dev if not set
	}

	// Connect to the database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create database queries
	dbQueries := database.New(db)

	// Create a new apiConfig
	apiCfg := &apiConfig{
		DB:       dbQueries,
		Platform: platform,
	}

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add health check endpoint

	// Create a file server handler with metrics middleware
	fileServer := http.FileServer(http.Dir("."))
	wrappedHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fileServer))
	mux.Handle("/app/", wrappedHandler)

	// Add endpoints
	mux.HandleFunc("/api/healthz", handlerReadiness)
	mux.HandleFunc("/admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("/admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("/api/validate_chirp", handlerValidateChirp)
	mux.HandleFunc("/api/users", apiCfg.handlerCreateUser)

	// Create the server with the mux as handler
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	log.Printf("Server starting on %s", server.Addr)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
