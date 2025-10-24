package main

import (
	"net/http"

	"github.com/76dillon/chirpy/internal/auth"
)

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil || token == "" {
		respondWithError(w, http.StatusUnauthorized, "invalid or missing token", err)
		return
	}

	if err := cfg.db.RevokeRefreshToken(r.Context(), token); err != nil {
		// optionally still 204, but 500 is fine for DB errors
		respondWithError(w, http.StatusInternalServerError, "failed to revoke token", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
