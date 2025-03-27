package main

import (
	"log"
	"net/http"
)

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Create a file server handler for the current directory
	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/", fileServer)

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