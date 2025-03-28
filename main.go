package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

type validateChirpRequest struct {
	Body string `json:"body"`
}

type validateChirpResponse struct {
	Valid bool   `json:"valid,omitempty"`
	Error string `json:"error,omitempty"`
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

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(validateChirpResponse{
		Valid: true,
	})
}

func main() {
	// Create a new apiConfig
	apiCfg := &apiConfig{}

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

	// Create the server with the mux as handler
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	log.Printf("Server starting on %s", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
