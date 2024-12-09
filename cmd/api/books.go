package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

// ------------------------------------------------------------------------------------------
func (a *applicationDependencies) AddBookHandler(w http.ResponseWriter, r *http.Request) {
	//set the data coming from the curl command
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside AddBookHandler 1")
	var incomingData struct {
		Title           string    `json:"title"`
		Authors         []string  `json:"authors"`
		ISBN            string    `json:"isbn"`
		PublicationDate time.Time `json:"publication_date"`
		Genre           string    `json:"genre"`
		Description     string    `json:"description"`
		AverageRating   float64   `json:"average_rating"`
	}

	//read the data to see JSON is properly formed
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
	}
	//push the incoming data to book datatype
	book := &data.Book{
		Title:           incomingData.Title,
		Authors:         incomingData.Authors,
		ISBN:            incomingData.ISBN,
		PublicationDate: incomingData.PublicationDate,
		Genre:           incomingData.Genre,
		Description:     incomingData.Description,
		AverageRating:   incomingData.AverageRating,
	}
	//logs to check data
	logger.Info("Book Details", "Title", book.Title)
	logger.Info("Book Details", "Authors", incomingData.Authors)
	logger.Info("Book Details", "ISBN", incomingData.ISBN)
	logger.Info("Book Details", "Publication Date", incomingData.PublicationDate)
	logger.Info("Book Details", "Genre", incomingData.Genre)
	logger.Info("Book Details", "Description", incomingData.Description)
	logger.Info("Book Details", "Average Rating", incomingData.AverageRating)
	//call the validator to verify all fields match their specs
	v := validator.New()
	data.ValidateBook(v, a.BookModel, book)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	//search for title if it exist to prevent duplication
	var preResults []data.Book
	logger.Info("Just before SearchDatabase Title Search")
	preResults, err = a.BookModel.SearchDatabase(incomingData.Title, "", "")
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	//extracting only the title portion of preResults
	titles := make([]string, len(preResults))
	for i, book := range preResults {
		titles[i] = book.Title
	}
	logger.Info("Results Titles", slog.Any("titles", titles))

	//If title is found, return error
	for _, title := range titles {
		if title == incomingData.Title {
			a.errorResponseJSON(w, r, http.StatusConflict, "A book with this title already exists")
			return
		}
	}
	//if no book is found go ahead with addition
	logger.Info("Just Before AddBookToDatabase")
	bookID, err := a.BookModel.AddBookToDatabase(*book)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
	book.ID = bookID

	//create the headers
	fmt.Fprintf(w, "%+v\n", incomingData)
	headers := make(http.Header)
	//making the apporiate header for GET /api/v1/books/api
	headers.Set("Location", fmt.Sprintf("/api/v1/books/%d", book.ID))

	data := envelope{
		"Location: /api/v1/books/": book.ID,
		"Title":                    book.Title,
		"Authors":                  book.Authors,
		"ISBN":                     book.ISBN,
		"Publication Date":         book.PublicationDate,
		"Genre":                    book.Genre,
		"Description":              book.Description,
		"Average Rating":           book.AverageRating,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

// ----------------------------------------------------------------------------------------------------
func (a *applicationDependencies) SearchFunction(w http.ResponseWriter, r *http.Request) {
	//search for title,author,genre
	var queryParametersData struct {
		Title  string
		Author string
		Genre  string
	}

	queryParameters := r.URL.Query()

	queryParametersData.Title = a.getSingleQueryParameter(queryParameters, "title", "")
	queryParametersData.Author = a.getSingleQueryParameter(queryParameters, "author", "")
	queryParametersData.Genre = a.getSingleQueryParameter(queryParameters, "genre", "")

	var results []data.Book
	//pass search to SearchDatabase
	results, err := a.BookModel.SearchDatabase(queryParametersData.Title, queryParametersData.Author, queryParametersData.Genre)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Return the search results
	err = a.writeJSON(w, http.StatusOK, envelope{"results": results}, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// -----------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) UpdateBookHandler(w http.ResponseWriter, r *http.Request) {
	//read the id of the book that will updated
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	book, err := a.BookModel.GetBook(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
			return
		default:
			a.serverErrorResponse(w, r, err)
			return
		}
	}

	//incoming data of data that can be changed
	var incomingData struct {
		Title           string    `json:"title"`
		Authors         []string  `json:"authors"`
		ISBN            string    `json:"isbn"`
		PublicationDate time.Time `json:"publication_date"`
		Genre           string    `json:"genre"`
		Description     string    `json:"description"`
	}
	//make sure the JSON is within spec
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	//if no changes remain the same, if yes make it match the incoming data
	if incomingData.Title != "" {
		book.Title = incomingData.Title
	}
	if len(incomingData.Authors) > 0 {
		book.Authors = incomingData.Authors
	}
	if incomingData.ISBN != "" {
		book.ISBN = incomingData.ISBN
	}
	if !incomingData.PublicationDate.IsZero() {
		book.PublicationDate = incomingData.PublicationDate
	}
	if incomingData.Genre != "" {
		book.Genre = incomingData.Genre
	}
	if incomingData.Description != "" {
		book.Description = incomingData.Description
	}

	// Save the updated book back to the database.
	err = a.BookModel.UpdateBook(book)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with the updated book details.
	err = a.writeJSON(w, http.StatusOK, envelope{"book": book}, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

// --------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) DeleteBookHandler(w http.ResponseWriter, r *http.Request) {
	//get the ID
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}
	err = a.BookModel.DeleteBook(id)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
	err = a.writeJSON(w, http.StatusOK, envelope{"Book Deleted": id}, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) ListBookHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	book, err := a.BookModel.GetBook(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
			return
		default:
			a.serverErrorResponse(w, r, err)
			return
		}
	}

	// Create the response data
	data := envelope{
		"Location":         "/api/v1/books/" + fmt.Sprintf("%d", book.ID),
		"Title":            book.Title,
		"Authors":          book.Authors,
		"ISBN":             book.ISBN,
		"Publication Date": book.PublicationDate,
		"Genre":            book.Genre,
		"Description":      book.Description,
		"Average Rating":   book.AverageRating,
	}

	// Write only the data to the response without headers
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

// something to add
// -----------------------------------------------------------------------------------------------------------------------------------
func (a *applicationDependencies) ListAllHandler(w http.ResponseWriter, r *http.Request) {
	//struct for the Filters
	var queryParametersData struct {
		data.Filters
	}

	queryParameters := r.URL.Query()

	v := validator.New()
	//setting parameters for the pagination and sorting
	queryParametersData.Filters.Page = a.getSingleIntegerParameter(queryParameters, "page", 1, v)
	queryParametersData.Filters.PageSize = a.getSingleIntegerParameter(queryParameters, "page_size", 10, v)

	queryParametersData.Filters.Sort = a.getSingleQueryParameter(queryParameters, "sort", "id")
	queryParametersData.Filters.SortSafeList = []string{"id", "genre", "-id", "-genre"}

	data.ValidateFilters(v, queryParametersData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	result, metadata, err := a.BookModel.ListAllBooks(queryParametersData.Filters)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

	data := envelope{
		"books":     result,
		"@metadata": metadata,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}
