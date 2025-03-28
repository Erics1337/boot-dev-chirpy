package main

import (
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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
	mux.HandleFunc("/api/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("/api/reset", apiCfg.handlerReset)

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
