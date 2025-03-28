package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors" // Need this for sql.ErrNoRows check
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/erics1337/boot-dev-chirpy/internal/auth" // Import the auth package
	"github.com/erics1337/boot-dev-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
	jwtSecret      string // Add JWT secret field
}

// Remove UserID, it will come from JWT
type createChirpRequest struct {
	Body string `json:"body"`
}

type createChirpResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"` // Add password field
}

type createUserResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Email     string `json:"email"`
}

// Add login request struct
type loginRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds *int   `json:"expires_in_seconds"` // Optional expiration
}

// Add login response struct
type loginResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Email     string `json:"email"`
	Token     string `json:"token"` // Add token field
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

	// --- Authentication ---
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		log.Printf("Error validating JWT: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	// --- End Authentication ---

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

	// Validate chirp length
	if len(req.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chirp is too long"})
		return
	}

	// Clean the chirp
	cleanedBody := cleanChirp(req.Body)

	// Prepare parameters for database query (using userID from token)
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
		UserID:    chirp.UserID.String(), // UserID from the created record
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

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Get chirpID from path parameter
	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid chirp ID format"})
		return
	}

	// Fetch chirp from the database
	chirp, err := cfg.DB.GetChirp(context.Background(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Chirp not found
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Chirp not found"})
		} else {
			// Other database error
			log.Printf("Error getting chirp by ID %s: %v", chirpIDStr, err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve chirp"})
		}
		return
	}

	// Prepare the response
	resp := createChirpResponse{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
		UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return 200 OK status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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

	// Hash the password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error processing password",
		})
		return
	}

	// Prepare parameters for database query
	params := database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	}

	// Create the user
	user, err := cfg.DB.CreateUser(context.Background(), params)
	if err != nil {
		log.Printf("Error creating user: %v", err) // Log the specific error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error creating user",
		})
		return
	}

	// Prepare the response (without password/hash)
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

// Add login handler
func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
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
	var req loginRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	// Get user by email
	user, err := cfg.DB.GetUserByEmail(context.Background(), req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect email or password"})
		} else {
			log.Printf("Error getting user by email: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Error logging in"})
		}
		return
	}

	// Check password hash
	err = auth.CheckPasswordHash(user.HashedPassword, req.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect email or password"})
		return
	}

	// Determine expiration duration
	expiresIn := time.Hour // Default: 1 hour
	if req.ExpiresInSeconds != nil {
		requestedSeconds := *req.ExpiresInSeconds
		if requestedSeconds > 0 && requestedSeconds <= 3600 { // Cap at 1 hour (3600 seconds)
			expiresIn = time.Duration(requestedSeconds) * time.Second
		} else if requestedSeconds > 3600 {
			expiresIn = time.Hour // Cap at 1 hour if requested > 1 hour
		}
		// If requestedSeconds <= 0, the default of 1 hour is used
	}

	// Generate JWT
	tokenString, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiresIn)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generating access token"})
		return
	}

	// Prepare the response
	resp := loginResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		Email:     user.Email,
		Token:     tokenString, // Include the token
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return OK status
	w.WriteHeader(http.StatusOK)
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

	// Get JWT secret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
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
		DB:        dbQueries,
		Platform:  platform,
		jwtSecret: jwtSecret, // Store the secret
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
	mux.HandleFunc("/api/login", apiCfg.handlerLogin) // Add login route

	// Register handlers for /api/chirps and /api/chirps/{chirpID}
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerCreateChirp)           // Now authenticated
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirpByID) // Added route

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
