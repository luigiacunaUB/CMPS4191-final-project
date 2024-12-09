package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

// -------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) createAuthenticationTokenHandler(w http.ResponseWriter, r *http.Request) {
	var incomingData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	data.ValidateEmail(v, incomingData.Email)
	data.ValidatePasswordPlaintext(v, incomingData.Password)

	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Is there an associated user for the provided email?
	user, err := a.UserModel.GetByEmail(incomingData.Email)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.invalidCredentialsResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	// The user is found. Does their password match?
	match, err := user.Password.Matches(incomingData.Password)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	// Wrong password
	// We will define invalidCredentialsResponse() later
	if !match {
		a.invalidCredentialsResponse(w, r)
		return
	}
	token, err := a.TokenModel.New(user.ID, 24*time.Hour, data.ScopeAuthentication)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return

	}

	data := envelope{
		"authentication_token": token,
		"Please use your ID when creating reviews and/or readinglist (YOUR USERID)": user.ID,
	}

	// Return the bearer token
	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}
