package main

import (
	"fmt"
	"net/http"
)

func (a *applicationDependencies) Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the Root Page!\n")
}
