package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/76dillon/chirpy/internal/auth"
	"github.com/76dillon/chirpy/internal/database"
)

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		User
	}

	//Decode request
	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't decode parameters", err)
		return
	}

	//Verify User and Password are present and not empty
	if params.Password == "" || params.Email == "" {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", nil)
		return
	}

	dbUser, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}

	//Compare password and hash
	ok, err := auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)

	//If password doesn't match, return 401 unauthorized error, otherwise, return 200 response
	if !ok || err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}

	//Determine the expiration duration
	expireSecs := 3600
	expireDuration := time.Duration(expireSecs) * time.Second

	//Create JWT
	token, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, expireDuration)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to generate JWT access token", err)
		return
	}

	//Create a refresh token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to generate refresh token", err)
		return
	}

	expiresAt := time.Now().Add(60 * 24 * time.Hour)
	if err := cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: expiresAt,
	}); err != nil {
		respondWithError(w, http.StatusInternalServerError, "unable to persist refresh token", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:           dbUser.ID,
			CreatedAt:    dbUser.CreatedAt,
			UpdatedAt:    dbUser.UpdatedAt,
			Email:        dbUser.Email,
			IsChirpyRed:  dbUser.IsChirpyRed,
			Token:        token,
			RefreshToken: refreshToken,
		},
	})
}
