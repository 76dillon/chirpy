package main

import (
	"net/http"
	"time"

	"github.com/76dillon/chirpy/internal/auth"
)

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {

	//Check to ensure refresh token in the header
	token, err := auth.GetBearerToken(r.Header)
	if err != nil || token == "" {
		respondWithError(w, http.StatusUnauthorized, "invalid or missing token", err)
		return
	}

	//Retrieve the user refresh token from db
	u, err := cfg.db.GetUserFromRefreshToken(r.Context(), token)
	if err != nil {
		// treat not found/expired/revoked as 401
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	//Create a new JWT access token which expires in one hour
	access, err := auth.MakeJWT(u.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "unable to mint access token", err)
		return
	}

	//Respond with token
	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": access,
	})

}
