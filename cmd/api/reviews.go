package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

// --------------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) AddBookReviewHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside AddBookReviewHandler 1")

	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// set params for incoming data
	var incomingData struct {
		UserID int64  `json:"userid"`
		Review string `json:"review"`
		Rating int64  `json:"rating"`
	}
	//check if the JSON is correctly formed
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
	}

	review := &data.Review{
		BookID: id,
		UserID: incomingData.UserID,
		Review: incomingData.Review,
		Rating: incomingData.Rating,
	}
	book := &data.Book{
		ID: id,
	}
	//do the validation checks
	v := validator.New()

	//check if the book exist
	data.ValidateBookIDOnly(v, a.BookModel, book)
	//validate review
	data.ValidateReview(v, a.ReviewModel, review)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	//check if the user exist
	_, ans, err := a.UserModel.GetID(incomingData.UserID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		fmt.Printf("ans: %v\n", ans)
		return
	}

	//check if an review already exist for a user for the specfic book
	rcheck := a.ReviewModel.CheckIfReviewExistForUser(review.BookID, review.UserID)
	logger.Info("Review Exist?: ", rcheck)
	if rcheck {
		errmsg := "User has already reviewed this book" // Custom error message
		logger.Info("Returning error: ", errmsg)        // Log the error message
		http.Error(w, errmsg, http.StatusBadRequest)    // Send error response
		return                                          // Stop further processing
	}

	//insert the actual review
	results, err := a.ReviewModel.AddBookReview(*review)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

	//create the headers
	fmt.Fprintf(w, "%+v\n", incomingData)
	headers := make(http.Header)
	//making the apporiate header for GET /api/v1/books/api
	headers.Set("Location", fmt.Sprintf("/api/v1/books/%d/reviews", results.ID))

	data := envelope{
		"Location: /api/v1/books/": results.ID,
		"Review ID":                results.ID,
		"Book ID":                  results.BookID,
		"Review":                   results.Review,
		"Rating":                   results.Rating,
		"Created By":               results.UserID,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

// -----------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) UpdateBookReviewHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside UpdateBookReviewHandler 1")
	//get the review id
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}
	logger.Info("UpdatedBookReviewHandler ID: ", id)

	// set params for incoming data to be updated
	var incomingData struct {
		Review string `json:"review"`
		Rating int64  `json:"rating"`
	}
	//check if the JSON is correctly formed
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
	}

	review := &data.Review{
		ID:     id,
		Review: incomingData.Review,
		Rating: incomingData.Rating,
	}
	//do the validation checks
	v := validator.New()
	//validation checks
	data.ValidateReview(v, a.ReviewModel, review)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}
	//once validation is done do the update
	results, err := a.ReviewModel.UpdateReview(*review)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	data := envelope{
		"Review Updated for ID": results.ID,
		"New Review":            results.Review,
	}

	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

// --------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) ListAllReviewsByBookHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Call the ListAllReviews method
	result, err := a.ReviewModel.ListAllReviews(id)
	if err != nil {
		// Log the error and respond with a server error
		http.Error(w, "Unable to fetch reviews", http.StatusInternalServerError)
		return
	}

	data := envelope{
		"All Reviews": result,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) DeleteReviewHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside DeleteBookReviewHandler")

	// Get the review ID from the request parameters
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}
	logger.Info("DeleteBookReviewHandler ID: ", id)

	// Attempt to delete the review
	results, err := a.ReviewModel.DeleteReview(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// Respond with a success message
	data := envelope{
		"Review Deleted for ID": results.ID,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}
