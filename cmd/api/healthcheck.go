package main

import (
	"encoding/json"
	"net/http"
)

func (a *applicationDependencies) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	data := envelope{
		"status": "avaliable",
		"system_info": map[string]string{
			"enviroment": a.config.enviroment,
			"version":    appVersion,
		},
	}
	err := a.writeJSON(w, http.StatusOK, data, nil)
	jsResponse, err := json.Marshal(data)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

	jsResponse = append(jsResponse, '\n')
	w.Header().Set("Content-Type", "application-json")
	w.Write(jsResponse)
}
