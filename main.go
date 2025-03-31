package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors" // Need this for sql.ErrNoRows check
	"io"
	"log"
	"net/http"
	"os" // Added for in-memory sorting
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
	polkaAPIKey    string // Add Polka API key field
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
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Email       string `json:"email"`
	IsChirpyRed bool   `json:"is_chirpy_red"` // Added field
}

// Add login request struct
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Add login response struct
type loginResponse struct {
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	Email        string `json:"email"`
	IsChirpyRed  bool   `json:"is_chirpy_red"` // Added field
	Token        string `json:"token"`         // Access token
	RefreshToken string `json:"refresh_token"`
}

// Refresh response struct
type refreshResponse struct {
	Token string `json:"token"` // New access token
}

// Update user response struct
type updateUserResponse struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Email       string `json:"email"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

// Update user request struct
type updateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Polka webhook request structs
type polkaWebhookRequestData struct {
	UserID string `json:"user_id"` // Keep as string for initial parsing
}

type polkaWebhookRequest struct {
	Event string                  `json:"event"`
	Data  polkaWebhookRequestData `json:"data"`
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

	// Check for author_id query parameter
	authorIDStr := r.URL.Query().Get("author_id")
	var dbChirps []database.Chirp
	var err error

	if authorIDStr != "" {
		// If author_id is provided, parse it and fetch by author
		authorID, parseErr := uuid.Parse(authorIDStr)
		if parseErr != nil {
			log.Printf("Error parsing author_id '%s': %v", authorIDStr, parseErr)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid author ID format"})
			return
		}
		log.Printf("Fetching chirps for author_id: %s", authorID.String())
		dbChirps, err = cfg.DB.GetChirpsByAuthor(context.Background(), authorID)
	} else {
		// If author_id is not provided, fetch all chirps
		log.Println("Fetching all chirps")
		dbChirps, err = cfg.DB.GetChirps(context.Background())
	}

	// Handle potential database errors from either fetch
	if err != nil {
		log.Printf("Error getting chirps from database: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve chirps"})
		return
	}

	// Determine sort order (default to "asc")
	sortOrder := r.URL.Query().Get("sort")
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Sort the results in memory if "desc" is requested
	// Note: The database already returns them sorted ascending by default
	if sortOrder == "desc" {
		// Reverse the slice for descending order
		for i, j := 0, len(dbChirps)-1; i < j; i, j = i+1, j-1 {
			dbChirps[i], dbChirps[j] = dbChirps[j], dbChirps[i]
		}
	}
	// If sortOrder is "asc" or invalid, we use the default ascending order from the DB

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

// handlerChirpByID routes requests for /api/chirps/{chirpID} based on method
func (cfg *apiConfig) handlerChirpByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg.handlerGetChirpByIDGet(w, r)
	case http.MethodDelete:
		cfg.handlerDeleteChirp(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func (cfg *apiConfig) handlerGetChirpByIDGet(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	// Note: Method validation is now handled by handlerChirpByID, but keeping it here
	// doesn't hurt and provides a layer of defense if handlerChirpByID changes.
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

// handlerUsers routes requests for /api/users based on method
func (cfg *apiConfig) handlerUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cfg.handlerCreateUserPost(w, r)
	case http.MethodPut:
		cfg.handlerUpdateUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func (cfg *apiConfig) handlerCreateUserPost(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	// Note: Method validation is now handled by handlerUsers, but keeping it here
	// doesn't hurt and provides a layer of defense if handlerUsers changes.
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
		ID:          user.ID.String(),
		CreatedAt:   user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   user.UpdatedAt.Format(time.RFC3339),
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed, // Added field
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

	// --- Access Token ---
	// Access tokens expire after 1 hour
	accessTokenTTL := time.Hour
	accessTokenString, err := auth.MakeJWT(user.ID, cfg.jwtSecret, accessTokenTTL)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generating access token"})
		return
	}

	// --- Refresh Token ---
	refreshTokenString, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generating refresh token"})
		return
	}

	// Store refresh token in DB (expires in 60 days)
	refreshTokenTTL := time.Hour * 24 * 60 // 60 days
	refreshTokenExpiresAt := time.Now().UTC().Add(refreshTokenTTL)
	_, err = cfg.DB.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{
		Token:     refreshTokenString,
		UserID:    user.ID,
		ExpiresAt: refreshTokenExpiresAt,
	})
	if err != nil {
		log.Printf("Error storing refresh token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error saving session"})
		return
	}

	// Prepare the response
	resp := loginResponse{
		ID:           user.ID.String(),
		CreatedAt:    user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    user.UpdatedAt.Format(time.RFC3339),
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,   // Added field
		Token:        accessTokenString,  // Use the correct variable
		RefreshToken: refreshTokenString, // Add the refresh token
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return OK status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handlerRefresh handles the POST /api/refresh endpoint
func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Get refresh token from header
	refreshTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token for refresh: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Look up user by refresh token
	user, err := cfg.DB.GetUserForRefreshToken(context.Background(), refreshTokenString)
	if err != nil {
		// This covers token not found, expired, or revoked based on the query logic
		log.Printf("Error validating refresh token: %v", err) // Log the specific error
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid refresh token"})
		return
	}

	// Generate new access token (1 hour expiry)
	accessTokenTTL := time.Hour
	newAccessTokenString, err := auth.MakeJWT(user.ID, cfg.jwtSecret, accessTokenTTL)
	if err != nil {
		log.Printf("Error generating new access token during refresh: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generating access token"})
		return
	}

	// Prepare the response
	resp := refreshResponse{
		Token: newAccessTokenString,
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return OK status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handlerRevoke handles the POST /api/revoke endpoint
func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Get refresh token from header
	refreshTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token for revoke: %v", err)
		// Still return 204 even if header is bad, the goal is revocation
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Revoke the token in the database
	err = cfg.DB.RevokeRefreshToken(context.Background(), refreshTokenString)
	if err != nil {
		// Log the error, but still return 204 as the token is effectively unusable
		log.Printf("Error revoking refresh token '%s': %v", refreshTokenString, err)
	}

	// Respond with 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// handlerPolkaWebhook handles incoming webhooks from Polka
func (cfg *apiConfig) handlerPolkaWebhook(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// --- Authentication ---
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		log.Printf("Error getting API key from Polka webhook: %v", err)
		w.WriteHeader(http.StatusUnauthorized) // 401 for auth errors
		// Optionally send an error message, though Polka might ignore it
		// json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	if apiKey != cfg.polkaAPIKey {
		log.Printf("Invalid API key received from Polka webhook")
		w.WriteHeader(http.StatusUnauthorized) // 401 for incorrect key
		return
	}
	// --- End Authentication ---

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading Polka webhook body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error reading request body"})
		return
	}

	// Parse the request body
	var req polkaWebhookRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		log.Printf("Error unmarshalling Polka webhook JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	// Check the event type
	if req.Event != "user.upgraded" {
		// We only care about user.upgraded events
		w.WriteHeader(http.StatusNoContent) // 204
		return
	}

	// Parse the user ID
	userID, err := uuid.Parse(req.Data.UserID)
	if err != nil {
		log.Printf("Error parsing UserID from Polka webhook: %v", err)
		w.WriteHeader(http.StatusBadRequest) // Or maybe 400 Bad Request? Let's stick with 400 for invalid ID format.
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid user ID format"})
		return
	}

	// Upgrade the user in the database
	_, err = cfg.DB.UpgradeUserToChirpyRed(context.Background(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// User not found
			log.Printf("User not found for upgrade webhook: %s", userID)
			w.WriteHeader(http.StatusNotFound) // 404
			// Polka expects an empty body on failure too, apparently.
			return
		}
		// Other database error
		log.Printf("Error upgrading user %s to Chirpy Red: %v", userID, err)
		w.WriteHeader(http.StatusInternalServerError) // 500 - Polka might retry
		// Send an error message for internal debugging, though Polka might ignore it.
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to upgrade user"})
		return
	}

	// Success
	log.Printf("User %s successfully upgraded to Chirpy Red via webhook.", userID)
	w.WriteHeader(http.StatusNoContent) // 204
}

// handlerUpdateUser handles the PUT /api/users endpoint
func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// --- Authentication ---
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token for user update: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		log.Printf("Error validating JWT for user update: %v", err)
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
	var req updateUserRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password during update: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error processing password"})
		return
	}

	// Prepare parameters for database query
	params := database.UpdateUserParams{
		ID:             userID, // Use the ID from the validated token
		Email:          req.Email,
		HashedPassword: hashedPassword,
	}

	// Update the user in the database
	updatedUser, err := cfg.DB.UpdateUser(context.Background(), params)
	if err != nil {
		log.Printf("Error updating user %s: %v", userID.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error updating user"})
		return
	}

	// Prepare the response using the new updateUserResponse struct
	resp := updateUserResponse{
		ID:          updatedUser.ID.String(),
		CreatedAt:   updatedUser.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   updatedUser.UpdatedAt.Format(time.RFC3339),
		Email:       updatedUser.Email,
		IsChirpyRed: updatedUser.IsChirpyRed, // Added field
	}

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return OK status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handlerDeleteChirp handles the DELETE /api/chirps/{chirpID} endpoint
func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	// Validate request method (though routing should handle this)
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// --- Authentication ---
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token for chirp delete: %v", err)
		w.WriteHeader(http.StatusUnauthorized) // 401 for missing/malformed token
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	authenticatedUserID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		log.Printf("Error validating JWT for chirp delete: %v", err)
		w.WriteHeader(http.StatusUnauthorized) // 401 for invalid token
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	// --- End Authentication ---

	// Get chirpID from path parameter
	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest) // 400 for invalid UUID format
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid chirp ID format"})
		return
	}

	// --- Authorization ---
	// Fetch the chirp to check ownership
	chirp, err := cfg.DB.GetChirp(context.Background(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound) // 404 if chirp doesn't exist
			json.NewEncoder(w).Encode(map[string]string{"error": "Chirp not found"})
		} else {
			log.Printf("Error getting chirp %s for delete check: %v", chirpIDStr, err)
			w.WriteHeader(http.StatusInternalServerError) // 500 for other DB errors
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve chirp"})
		}
		return
	}

	// Check if the authenticated user is the author
	if chirp.UserID != authenticatedUserID {
		w.WriteHeader(http.StatusForbidden) // 403 if not the author
		json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden"})
		return
	}
	// --- End Authorization ---

	// Delete the chirp
	err = cfg.DB.DeleteChirp(context.Background(), chirpID)
	if err != nil {
		log.Printf("Error deleting chirp %s: %v", chirpIDStr, err)
		w.WriteHeader(http.StatusInternalServerError) // 500 if delete fails
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not delete chirp"})
		return
	}

	// Respond with 204 No Content on successful deletion
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	// Load environment variables from .env file if it exists.
	// Ignore "file not found" errors, as configuration might be provided
	// via actual environment variables (e.g., in Docker).
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		// Only fatal if the error is something other than the file not existing
		log.Fatalf("Error loading .env file: %v", err)
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

	// Get Polka API Key
	polkaKey := os.Getenv("POLKA_API_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_API_KEY environment variable is not set") // Fail if not set
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
		DB:          dbQueries,
		Platform:    platform,
		jwtSecret:   jwtSecret, // Store the secret
		polkaAPIKey: polkaKey,  // Store the Polka key
	}

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add health check endpoint

	// Create a file server handler for the root path, with metrics middleware
	fileServer := http.FileServer(http.Dir("."))
	// Apply middleware directly to the file server
	wrappedHandler := apiCfg.middlewareMetricsInc(fileServer)
	// Handle requests to the root path "/"
	mux.Handle("/", wrappedHandler)

	// Add endpoints
	mux.HandleFunc("/api/healthz", handlerReadiness)
	mux.HandleFunc("/admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("/admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("/api/users", apiCfg.handlerUsers)                      // Use the wrapper handler
	mux.HandleFunc("/api/login", apiCfg.handlerLogin)                      // Add login route
	mux.HandleFunc("/api/refresh", apiCfg.handlerRefresh)                  // Add refresh route
	mux.HandleFunc("/api/revoke", apiCfg.handlerRevoke)                    // Add revoke route
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerPolkaWebhook) // Add Polka webhook route

	// Register handlers for /api/chirps and /api/chirps/{chirpID}
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerCreateChirp)    // Now authenticated
	mux.HandleFunc("/api/chirps/{chirpID}", apiCfg.handlerChirpByID) // Use wrapper for GET/DELETE

	// Get port from environment variable, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	serverAddr := ":" + port

	// Create the server with the mux as handler
	server := &http.Server{
		Addr:    serverAddr, // Use the configured address
		Handler: mux,
	}

	// Start the server
	log.Printf("Server starting on %s", serverAddr) // Log the actual address
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
