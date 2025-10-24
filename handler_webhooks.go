package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/76dillon/chirpy/internal/auth"
	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerUpgradeUser(w http.ResponseWriter, r *http.Request) {

	//Verify ApiKey
	key, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid API key", err)
		return
	}

	//Check if header key matches one in env
	if cfg.polkaKey != key {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid API key", nil)
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	type response struct{}

	//Decode request
	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't decode parameters", err)
		return
	}

	//Verify if event is user.upgraded. If not, return a 204 status code
	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	//Upgrade user ID if it exists. If not, return 404 code or 500 error code for other errors
	_, err = cfg.db.UpgradeUser(r.Context(), params.Data.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "user not found", err)
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Couldn't update user", err)
		return
	}

	//JSON Response
	respondWithJSON(w, http.StatusNoContent, response{})

}
