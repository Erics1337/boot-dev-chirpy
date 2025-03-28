package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	// "sort" // Removed unused import
	"strings"
	"sync/atomic"
	"time"

	"github.com/erics1337/boot-dev-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
}

type createChirpRequest struct {
	Body   string `json:"body"`
	UserID string `json:"user_id"`
}

type createChirpResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
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

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error reading request body"})
		return
	}

	// Parse the request body
	var req createChirpRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	// Parse UserID string into uuid.UUID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid user_id format"})
		return
	}

	// Validate chirp length
	if len(req.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chirp is too long"})
		return
	}

	// Clean the chirp
	cleanedBody := cleanChirp(req.Body)

	// Prepare parameters for database query
	params := database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	}

	// Persist the chirp to the database
	chirp, err := cfg.DB.CreateChirp(context.Background(), params)
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not create chirp"})
		return
	}

	// Prepare the response using the data returned from the database
	resp := createChirpResponse{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
		UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return 201 Created status
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Fetch chirps from the database
	dbChirps, err := cfg.DB.GetChirps(context.Background())
	if err != nil {
		log.Printf("Error getting chirps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve chirps"})
		return
	}

	// Transform database chirps into response chirps
	respChirps := make([]createChirpResponse, 0, len(dbChirps))
	for _, dbChirp := range dbChirps {
		respChirps = append(respChirps, createChirpResponse{
			ID:        dbChirp.ID.String(),
			CreatedAt: dbChirp.CreatedAt.Format(time.RFC3339),
			UpdatedAt: dbChirp.UpdatedAt.Format(time.RFC3339),
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID.String(),
		})
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return 200 OK status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respChirps)
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
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		Email:     user.Email,
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return created status
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
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
	mux.HandleFunc("/api/users", apiCfg.handlerCreateUser)
	// Register both POST and GET handlers for /api/chirps
	mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			apiCfg.handlerCreateChirp(w, r)
		case http.MethodGet:
			apiCfg.handlerGetChirps(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

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
