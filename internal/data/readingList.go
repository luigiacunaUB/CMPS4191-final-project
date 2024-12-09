package data

import (
	"database/sql"
	"log/slog"
	"os"

	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

type ReadingListModel struct {
	DB *sql.DB
}

type ReadingList struct {
	ID           int64  `json:"id"`
	ReadListName string `json:"name"`
	Books        []int  `json:"book_name"`
	CreatedBy    int    `json:"createdby"`
	Description  string `json:"description"`
	Status       string `json:"status"`
}

// --------------------------------------------------------------------------------------------------------------------
func ValidateReadingList(v *validator.Validator, rl ReadingListModel, list *ReadingList) {
	//Check the name of the Reading List
	v.Check(list.ReadListName != "", "Reading List:", "The name must not be empty")
	v.Check(len(list.ReadListName) <= 25, "Title", "Must not be more than 25 bytes long")
	//Book Validation Check
	v.Check(len(list.Books) > 0, "Books", "At least one book ID must be provided")
	for _, bookID := range list.Books {
		v.Check(bookID > 0, "Books", "Book ID must be a positive integer")
	}
	//Descritption Check
	v.Check(list.Description != "", "Description", "Must not be Empty")
	v.Check(len(list.Description) <= 100, "Description", "Must not be more than 100 bytes long")
	//Status Check
	validStatuses := []string{"currently reading", "completed"}
	v.Check(stringInSlice(list.Status, validStatuses), "Status", "Status must be either 'currently reading' or 'completed'")

}

func stringInSlice(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}

func (rl ReadingListModel) AddReadingListToDatabase(list ReadingList) (ReadingList, error) {
	// Begin a transaction
	tx, err := rl.DB.Begin()
	if err != nil {
		return list, err
	}

	defer tx.Rollback() // Rollback in case of an error

	// Insert into reading_lists
	query := `
		 INSERT INTO reading_lists (name, description, created_by, status)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id
	 `
	var id int64
	err = tx.QueryRow(query, list.ReadListName, list.Description, list.CreatedBy, list.Status).Scan(&id)
	if err != nil {
		return list, err
	}

	// Insert into reading_list_books
	for _, bookID := range list.Books {
		query = `
			 INSERT INTO reading_list_books (reading_list_id, book_id)
			 VALUES ($1, $2)
		 `
		_, err = tx.Exec(query, id, bookID)
		if err != nil {
			return list, err
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return list, err
	}

	// Return the updated ReadingList
	list.ID = id
	return list, nil
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) DeleteReadingList(readingListID int64) error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside DELETEREADINGLISTHANDLER SQL")
	logger.Info("ID to be deleted in SQL func: ", readingListID)
	// Delete the reading list
	query := `
        DELETE FROM reading_lists
        WHERE id = $1
    `
	result, err := m.DB.Exec(query, readingListID)
	if err != nil {
		return err
	}

	// Check if any row was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return err
	}

	return nil
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) GetAllReadingLists() ([]ReadingList, error) {
	// Query to fetch all reading lists and their associated book IDs
	query := `
        SELECT r.id, r.name, r.description, r.created_by, r.status, rb.book_id
        FROM reading_lists r
        LEFT JOIN reading_list_books rb ON r.id = rb.reading_list_id
        ORDER BY r.id ASC
    `
	rows, err := m.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Slice to hold the reading lists
	var readingLists []ReadingList
	var currentList *ReadingList

	// Loop through the result set and populate the slice
	for rows.Next() {
		var list ReadingList
		var bookID *int
		err := rows.Scan(&list.ID, &list.ReadListName, &list.Description, &list.CreatedBy, &list.Status, &bookID)
		if err != nil {
			return nil, err
		}

		// If a new reading list is encountered, add it to the slice
		if currentList == nil || currentList.ID != list.ID {
			// If there is a previous list, append it to the result slice
			if currentList != nil {
				readingLists = append(readingLists, *currentList)
			}
			// Start a new reading list
			currentList = &list
			currentList.Books = []int{}
		}

		// Append the book ID to the current reading list
		if bookID != nil {
			currentList.Books = append(currentList.Books, *bookID)
		}
	}

	// Append the last reading list if present
	if currentList != nil {
		readingLists = append(readingLists, *currentList)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return readingLists, nil
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) GetReadingListByID(id int64) (ReadingList, error) {
	// Query to fetch the reading list with its associated book IDs by reading list ID
	query := `
        SELECT r.id, r.name, r.description, r.created_by, r.status, rb.book_id
        FROM reading_lists r
        LEFT JOIN reading_list_books rb ON r.id = rb.reading_list_id
        WHERE r.id = $1
        ORDER BY r.id ASC
    `
	rows, err := m.DB.Query(query, id)
	if err != nil {
		return ReadingList{}, err
	}
	defer rows.Close()

	// Initialize a variable to store the reading list
	var readingList ReadingList
	var currentList *ReadingList
	var bookID *int

	// Loop through the result set and populate the reading list
	for rows.Next() {
		err := rows.Scan(&readingList.ID, &readingList.ReadListName, &readingList.Description, &readingList.CreatedBy, &readingList.Status, &bookID)
		if err != nil {
			return ReadingList{}, err
		}

		// If it's the first row, initialize the book list
		if currentList == nil {
			currentList = &readingList
			currentList.Books = []int{}
		}

		// Append the book ID to the current reading list if it's not NULL
		if bookID != nil {
			currentList.Books = append(currentList.Books, *bookID)
		}
	}

	if err = rows.Err(); err != nil {
		return ReadingList{}, err
	}

	// If no reading list was found, return an error
	if currentList == nil {
		return ReadingList{}, err
	}

	return *currentList, nil
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) AddBookToReadingList(readingListID, bookID int64) error {
	// Query to insert a new book into the reading_list_books table
	query := `
		INSERT INTO reading_list_books (reading_list_id, book_id)
		VALUES ($1, $2)
	`
	_, err := m.DB.Exec(query, readingListID, bookID)
	return err
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) DeleteBookFromReadingList(readingListID, bookID int64) error {
	// Query to delete a book from the reading_list_books table
	query := `
		DELETE FROM reading_list_books
		WHERE reading_list_id = $1 AND book_id = $2
	`
	_, err := m.DB.Exec(query, readingListID, bookID)
	return err
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------
func (m *ReadingListModel) UpdateReadingListInfo(list ReadingList) error {
	query := `
		UPDATE reading_lists
		SET
			name = COALESCE(NULLIF($1, ''), name),
			description = COALESCE(NULLIF($2, ''), description),
			status = COALESCE(NULLIF($3, ''), status)
		WHERE id = $4
	`
	_, err := m.DB.Exec(query, list.ReadListName, list.Description, list.Status, list.ID)
	return err
}
