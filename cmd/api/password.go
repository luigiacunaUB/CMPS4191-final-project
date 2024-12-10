package main

import (
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"golang.org/x/crypto/bcrypt"
)

const (
	ScopePasswordReset = "password-reset"
)

func (a *applicationDependencies) CreatePasswordResetTokenHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside CreatePasswordResetTokenHandler")
	//the incoming data
	var incomingData struct {
		Email string `json:"email"`
	}

	//read the json to see that it is properly formed
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	//Check if the user exist
	user, err := a.UserModel.GetByEmail(incomingData.Email)
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			// Do not disclose whether the email exists for security reasons
			logger.Error("EMAIL DOES NOT EXIST")
			return
		}
		a.serverErrorResponse(w, r, err)
		return
	}

	if !user.Activated {
		logger.Error("EMAIL DOES NOT ACTIVATED")
		return
	}
	//generate a password reset token
	token, err := a.TokenModel.New(user.ID, time.Hour, ScopePasswordReset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//send the email
	data := envelope{
		"message": "An email will be sent to you containing password reset instructions",
	}
	emailData := struct {
		UserID          int64
		ActivationToken string
	}{
		UserID:          user.ID,
		ActivationToken: token.Plaintext,
	}
	err = a.mailer.Send(incomingData.Email, "password_reset.tmpl", emailData)
	//a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.logger.Error(err.Error())
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}
	logger.Info("It Reaches Here")
	//need to fix this or maybe hotspot throwing it off
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	logger.Info("It Reaches Here 2")

}

// ------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) UpdateUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// The incoming data
	var incomingData struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	// Decode the JSON request body
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Validate the token and check the user
	tokenHash := sha256.Sum256([]byte(incomingData.Token))
	token, err := a.TokenModel.GetForToken(ScopePasswordReset, tokenHash[:])
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if token has expired
	if time.Now().After(token.Expiry) {
		http.Error(w, "Token has expired", http.StatusUnauthorized)
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(incomingData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Update the user's password in the database
	err = a.UserModel.UpdatePassword(token.UserID, hashedPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete all password reset tokens for the user
	err = a.TokenModel.DeleteAllForUser(ScopePasswordReset, token.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with success
	data := envelope{"message": "Your password was successfully reset"}
	a.writeJSON(w, http.StatusOK, data, nil)
}
