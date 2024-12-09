package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

func (a *applicationDependencies) AddReadingList(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside AddReadingList")
	//accept the incoming data
	var incomingData struct {
		ReadListName string `json:"name"`
		Books        []int  `json:"book_name"`
		CreatedBy    int    `json:"createdby"`
		Description  string `json:"description"`
		Status       string `json:"status"`
	}
	//check if the data is correctly formed
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
	}
	//assign the incoming data to a ReadingListModel
	list := &data.ReadingList{
		ReadListName: incomingData.ReadListName,
		Books:        incomingData.Books,
		Description:  incomingData.Description,
		Status:       incomingData.Status,
		CreatedBy:    incomingData.CreatedBy,
	}

	//do validation
	v := validator.New()
	data.ValidateReadingList(v, a.ReadingListModel, list)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}
	logger.Info("Error Here 1")
	//once the validation passes do the push to DB execution
	ans, err := a.ReadingListModel.AddReadingListToDatabase(*list)
	if err != nil {
		logger.Info("Error Here 2")
		a.serverErrorResponse(w, r, err)
	}
	logger.Info("Error Here 3")

	data := envelope{
		"Reading List ID": ans.ID,
		"Books":           ans.Books,
		"Created By User": ans.CreatedBy,
		"Description":     ans.Description,
		"Status":          ans.Status,
	}

	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) DeleteReadingListHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside DELETEREADINGLISTHANDLER")
	// Extract the reading list ID from the URL
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}
	logger.Info("ID to be deleted: ", id)

	err = a.ReadingListModel.DeleteReadingList(id)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

	// Respond with a success message
	err = a.writeJSON(w, http.StatusOK, envelope{
		"message": fmt.Sprintf("Reading list successfully deleted. ID: %d", id),
	}, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) ListAllReadingListsHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch all reading lists
	readingLists, err := a.ReadingListModel.GetAllReadingLists()
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with the reading lists
	err = a.writeJSON(w, http.StatusOK, envelope{
		"reading_lists": readingLists,
	}, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) GetReadingListHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the reading list ID from the URL
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Retrieve the specific reading list from the model
	readingList, err := a.ReadingListModel.GetReadingListByID(id)
	if err != nil {
		// Handle the error (not found or other)
		if err.Error() == fmt.Sprintf("Reading list with ID %d not found", id) {
			a.notFoundResponse(w, r)
		} else {
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// Respond with the reading list in JSON format
	data := envelope{
		"reading_list": readingList,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) AddBookToReadingListHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the reading list ID from the URL
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Parse the request body to get the book ID
	var incomingData struct {
		BookID int64 `json:"book_id"`
	}
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Add the book to the reading list
	err = a.ReadingListModel.AddBookToReadingList(id, incomingData.BookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with success message
	data := envelope{
		"message": "Book successfully added to reading list",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) DeleteBookFromReadingListHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the reading list ID from the URL
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Parse the request body to get the book ID
	var incomingData struct {
		BookID int64 `json:"book_id"`
	}
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Delete the book from the reading list
	err = a.ReadingListModel.DeleteBookFromReadingList(id, incomingData.BookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with a success message
	data := envelope{
		"message": "Book successfully removed from reading list",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) UpdateReadingListInfoHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the reading list ID from the URL
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Parse the request body
	var incomingData struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Construct the ReadingList struct with the updates
	list := &data.ReadingList{
		ID:           id,
		ReadListName: incomingData.Name,
		Description:  incomingData.Description,
		Status:       incomingData.Status,
	}

	// Update the reading list info
	err = a.ReadingListModel.UpdateReadingListInfo(*list)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with a success message
	data := envelope{
		"message": "Reading list successfully updated",
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}
