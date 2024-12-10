package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
)

func (a *applicationDependencies) CreatePasswordResetTokenHandler(w http.ResponseWriter, r *http.Request) {
	//the incoming data
	var incomingData struct {
		Email string `json:"email"`
	}

	//read the json to see that it is properly formed
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
	}

	//Check if the user exist
	//add stuff
	user, err := a.UserModel.GetByEmail(incomingData.Email)
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			// Do not disclose whether the email exists for security reasons
			http.Error(w, "Email not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !user.Activated {
		http.Error(w, "User is not activated", http.StatusUnauthorized)
		return
	}
	//generate a password reset token
	token, err := a.TokenModel.New(user.ID, time.Hour, data.ScopeAuthentication)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//send the email
	emailData := struct {
		UserID          int64
		ActivationToken string
	}{
		UserID:          user.ID,
		ActivationToken: token.Plaintext,
	}
	if err := a.mailer.Send(incomingData.Email, "password_reset.tmpl", emailData); err != nil {
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}

	//send the response back the user

	data := envelope{
		"message": "An email will be sent to you containing password reset instructions",
	}

	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

}
