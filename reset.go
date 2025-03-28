package main

import (
	"context"
	"log"
	"net/http"
)

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Check platform
	if cfg.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Reset endpoint is only available in dev environment"))
		return
	}

	// Reset hits
	cfg.fileserverHits.Store(0)

	// Delete all users
	err := cfg.DB.DeleteAllUsers(context.Background())
	if err != nil {
		log.Printf("Error deleting users: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error resetting database"))
		return
	}

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0 and users deleted"))
}
