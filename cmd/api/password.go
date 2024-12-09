package main

import "net/http"

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

}
