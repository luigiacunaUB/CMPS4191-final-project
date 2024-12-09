package data

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/validator"
)

type BookModel struct {
	DB *sql.DB
}

type Book struct {
	ID              int64     `json:"id"`
	Title           string    `json:"title"`
	Authors         []string  `json:"authors"`
	ISBN            string    `json:"isbn"`
	PublicationDate time.Time `json:"publication_date"`
	Genre           string    `json:"genre"`
	Description     string    `json:"description"`
	AverageRating   float64   `json:"average_rating"`
}

// -----------------------------------------------------------------------------------------------------------------
func ValidateBook(v *validator.Validator, b BookModel, book *Book) {
	//Title Checks
	v.Check(book.Title != "", "Title", "Must not be Empty")
	v.Check(len(book.Title) <= 25, "Title", "Must not be more than 25 bytes long")

	//Author Checks
	v.Check(len(book.Authors) > 0, "Authors", "Atleast one author must be provided")
	for _, author := range book.Authors {
		v.Check(author != "", "Authors", "Author's name must not be empty")
		v.Check(len(author) <= 25, "Authors", "Author's name must not be more than 25 bytes")
	}

	//ISBN length -> following ISBN system 10 digits before 1 Jan 2007, 13 digits after
	v.Check(book.ISBN != "", "ISBN", "Cannot be empty")
	v.Check(len(book.ISBN) == 10 || len(book.ISBN) == 13, "ISBN", "Must be a 10 or 13 Digit Code")

	//Publication Date Checks, how does it parse time??
	v.Check(!book.PublicationDate.IsZero(), "Publication Date", "Must be a valid date")
	v.Check(book.PublicationDate.Before(time.Now()), "Publication Date", "Must not be set in the future")

	//Genre Checks
	v.Check(book.Genre != "", "Genre", "Must not be Empty")
	v.Check(len(book.Genre) <= 25, "Genre", "Must not be more than 25 bytes long")

	//Description Checks
	v.Check(book.Description != "", "Description", "Must not be Empty")
	v.Check(len(book.Description) <= 100, "Description", "Must not be more than 100 bytes long")

	//Rating Check
	v.Check(book.AverageRating >= 1 && book.AverageRating <= 5, "Ratings", "Ratings must between 1 and 5")
}

func ValidateBookIDOnly(v *validator.Validator, b BookModel, book *Book) {
	//check firstly if the book even exist
	//logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	v.Check(book.ID >= 1, "BookID", "BookID cannot be less than 1 this one")
}

// ---------------------------------------------------------------------------------------------------------------------
func (b BookModel) AddBookToDatabase(book Book) (int64, error) {

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside AddBookToDatabase")

	// Begin a transaction
	tx, err := b.DB.Begin()
	if err != nil {
		return 0, err
	}

	// Insert the book into the books table
	var bookID int64
	err = tx.QueryRow(
		`INSERT INTO books (title, isbn, publication_date, genre, description, average_rating) 
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		book.Title, book.ISBN, book.PublicationDate, book.Genre, book.Description, book.AverageRating,
	).Scan(&bookID)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	logger.Info("Finished Adding book pushing into authors")
	// Insert authors and the book-author relationship
	for _, author := range book.Authors {
		var authorID int
		// Check if the author already exists
		err = tx.QueryRow(`SELECT id FROM authors WHERE name = $1`, author).Scan(&authorID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Insert the author if they don't exist
				err = tx.QueryRow(
					`INSERT INTO authors (name) VALUES ($1) RETURNING id`,
					author,
				).Scan(&authorID)
				if err != nil {
					tx.Rollback()
					return 0, err
				}
			} else {
				tx.Rollback()
				return 0, err
			}
		}
		logger.Info("Finished insert authors")
		// Insert the relationship into the book_authors table
		_, err = tx.Exec(
			`INSERT INTO book_authors (book_id, author_id) VALUES ($1, $2)`,
			bookID, authorID,
		)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return bookID, nil
}

// --------------------------------------------------------------------------------------------------------------------
func (b BookModel) SearchDatabase(title string, author string, genre string) ([]Book, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Inside Search Database, starting search")

	formatQuery := func(query string) string {
		if query == "" {
			return ""
		}
		return strings.Join(strings.Fields(query), " & ")
	}

	formattedTitle := formatQuery(title)
	//formattedTitle := formatQuery("great")
	formattedAuthor := formatQuery(author)
	formattedGenre := formatQuery(genre)

	logger.Info("Formatted Title: ", formattedTitle)
	logger.Info("Formatted Author: ", formattedAuthor)
	logger.Info("Formatted Genre: ", formattedGenre)
	//using queries search to find ids
	query := `SELECT b.id
	 	FROM books b
		LEFT JOIN book_authors ba ON b.id = ba.book_id
		LEFT JOIN authors a ON ba.author_id = a.id
	 	WHERE
		($1 = '' OR to_tsvector('simple',b.title)@@ plainto_tsquery('simple',$1)) AND
		($2 = '' OR to_tsvector('simple', b.genre) @@ plainto_tsquery('simple', $2)) AND
		($3 = '' OR to_tsvector('simple', a.name) @@ plainto_tsquery('simple', $3))
		`

	rows, err := b.DB.Query(query, formattedTitle, formattedGenre, formattedAuthor)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bookIDs []int64

	for rows.Next() {
		var bookID int64
		if err := rows.Scan(&bookID); err != nil {
			logger.Error("Error scanning row", slog.String("error", err.Error()))
			return nil, err
		}
		bookIDs = append(bookIDs, bookID)
	}

	// Store the result in a variable (bookIDs)
	result := bookIDs // Here you store the result in the variable 'result'

	// Optionally log the results
	logger.Info("Found book IDs", slog.Any("book_ids", result))

	// If no books are found, return empty slice
	if len(bookIDs) == 0 {
		return nil, nil
	}

	query2 := `SELECT b.id, b.title, ARRAY_AGG(a.name) AS authors, b.isbn, b.publication_date, b.genre, b.description, b.average_rating
	FROM books b
	LEFT JOIN book_authors ba ON b.id = ba.book_id
	LEFT JOIN authors a ON ba.author_id = a.id
	WHERE b.id = ANY($1)
	GROUP BY b.id, b.title, b.isbn, b.publication_date, b.genre, b.description, b.average_rating`

	// Execute the second query
	rows2, err := b.DB.Query(query2, pq.Array(bookIDs))
	if err != nil {
		return nil, err
	}
	defer rows2.Close()

	// Prepare to collect the book details
	var books []Book
	for rows2.Next() {
		var book Book
		var authors []string
		if err := rows2.Scan(
			&book.ID,
			&book.Title,
			pq.Array(&authors),
			&book.ISBN,
			&book.PublicationDate,
			&book.Genre,
			&book.Description,
			&book.AverageRating,
		); err != nil {
			return nil, err
		}
		book.Authors = authors
		books = append(books, book)
	}

	// Check for any errors that occurred during iteration
	if err = rows2.Err(); err != nil {
		return nil, err
	}

	// Optionally log the book details for debugging
	for _, book := range books {
		logger.Info("Book details",
			slog.Int64("id", book.ID),
			slog.String("title", book.Title),
			slog.Float64("average_rating", book.AverageRating))
	}

	return books, nil
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
func (b BookModel) GetBook(id int64) (Book, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	//Gets the id and adds into book for use by update
	//check if the id is not less than 1
	if id < 1 {
		return Book{}, ErrRecordNotFound
	}

	//if the id more than 1 preform the query
	query := `SELECT b.id, b.title, ARRAY_AGG(a.name) AS authors, b.isbn, b.publication_date, b.genre, b.description, b.average_rating
	FROM books b
	LEFT JOIN book_authors ba ON b.id = ba.book_id
	LEFT JOIN authors a ON ba.author_id = a.id
	WHERE b.id = $1
	GROUP BY b.id, b.title, b.isbn, b.publication_date, b.genre, b.description, b.average_rating`

	// Prepare to store the book details.
	var book Book
	var authors []string

	// Execute the query to retrieve the book.
	err := b.DB.QueryRow(query, id).Scan(
		&book.ID,
		&book.Title,
		pq.Array(&authors),
		&book.ISBN,
		&book.PublicationDate,
		&book.Genre,
		&book.Description,
		&book.AverageRating,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Book{}, ErrRecordNotFound
		}
		return Book{}, err
	}

	// Assign authors to the book.
	book.Authors = authors

	// Log details of the book.
	logger.Info("Book details",
		slog.Int64("id", book.ID),
		slog.String("title", book.Title),
		slog.Float64("average_rating", book.AverageRating))

	return book, nil

}

// ----------------------------------------------------------------------------------------------------------------------------------------------
func (b BookModel) UpdateBook(book Book) error {
	// Start a transaction to ensure both the book and its authors are updated atomically.
	tx, err := b.DB.Begin()
	if err != nil {
		return err
	}

	// Rollback the transaction in case of an error.
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw the panic after rollback.
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	// Update the book details in the `books` table.
	query := `UPDATE books
	          SET title = $1, isbn = $2, publication_date = $3, genre = $4, 
	              description = $5, updated_at = NOW()
	          WHERE id = $6`
	_, err = tx.Exec(query,
		book.Title,
		book.ISBN,
		book.PublicationDate,
		book.Genre,
		book.Description,
		book.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update book: %w", err)
	}

	// Delete existing authors for the book in the `book_authors` table.
	_, err = tx.Exec(`DELETE FROM book_authors WHERE book_id = $1`, book.ID)
	if err != nil {
		return fmt.Errorf("failed to delete existing authors: %w", err)
	}

	// Insert new authors into the `book_authors` table.
	for _, author := range book.Authors {
		// Check if the author exists in the authors table.
		var authorID int64
		err = tx.QueryRow(`SELECT id FROM authors WHERE name = $1`, author).Scan(&authorID)

		if err == sql.ErrNoRows {
			// If the author doesn't exist, insert the author into the authors table.
			// Insert the author into the authors table.
			err = tx.QueryRow(`INSERT INTO authors (name) VALUES ($1) RETURNING id`, author).Scan(&authorID)
			if err != nil {
				return fmt.Errorf("failed to insert new author '%s': %w", author, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check if author exists: %w", err)
		}

		// Insert the author-book association into the `book_authors` table.
		_, err = tx.Exec(`INSERT INTO book_authors (book_id, author_id) VALUES ($1, $2)`,
			book.ID, authorID)
		if err != nil {
			return fmt.Errorf("failed to associate author '%s' with book: %w", author, err)
		}
	}

	return nil
}

// -------------------------------------------------------------------------------------------------------------------------------------
func (b BookModel) DeleteBook(id int64) error {
	if id < 1 {
		return ErrRecordNotFound
	}

	// Start a transaction to ensure both DELETE operations are atomic
	tx, err := b.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Step 1: Remove associations from book_authors
	_, err = tx.Exec(`
		DELETE FROM book_authors
		WHERE book_id = $1`, id)
	if err != nil {
		return err
	}

	// Step 2: Delete the book from the books table
	_, err = tx.Exec(`
		DELETE FROM books
		WHERE id = $1`, id)
	if err != nil {
		return err
	}

	// Commit the transaction
	return tx.Commit()

}

// -------------------------------------------------------------------------------------------------------------------------------------------
func (b BookModel) ListAllBooks(filters Filters) ([]Book, MetaData, error) {
	// query to display all details of books
	query := fmt.Sprintf(`SELECT COUNT (*) OVER (),
    	b.id AS book_id,
    	b.title,
    	b.isbn,
    	b.publication_date,
    	b.genre,
    	b.description,
    	b.average_rating,
    	ARRAY_AGG(a.name) AS authors
	FROM 
    	books b
	LEFT JOIN 
    	book_authors ba ON b.id = ba.book_id
	LEFT JOIN 
    	authors a ON ba.author_id = a.id
	GROUP BY 
    	b.id, b.title, b.isbn, b.publication_date, b.genre, b.description, b.average_rating
	ORDER BY 
    	b.%s %s
	LIMIT $1 OFFSET $2;`, filters.sortColumn(), filters.sortDirection())

	// Execute the query
	rows, err := b.DB.Query(query, filters.limit(), filters.offset())
	if err != nil {
		return nil, MetaData{}, err
	}
	defer rows.Close()
	totalRecords := 0

	// Prepare a slice to hold the books
	var books []Book

	// Iterate through the result set
	for rows.Next() {
		var book Book
		var authors []string

		// Scan the row into the book and authors variables
		err := rows.Scan(
			&totalRecords,
			&book.ID,
			&book.Title,
			&book.ISBN,
			&book.PublicationDate,
			&book.Genre,
			&book.Description,
			&book.AverageRating,
			pq.Array(&authors),
		)
		if err != nil {
			return nil, MetaData{}, err
		}

		// Assign authors to the book
		book.Authors = authors

		// Append the book to the slice
		books = append(books, book)
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		return nil, MetaData{}, err
	}
	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)

	return books, metadata, nil
}

// --------------------------------------------------------------------------------------------------------------------------------------------
func (b BookModel) SearchBookByID(id int64) (bool, error) {
	query := `SELECT id FROM books WHERE id=$1;`
	var foundID int
	err := b.DB.QueryRow(query, id).Scan(&foundID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Book with the given ID does not exist
			return false, nil
		}
		// An unexpected error occurred
		return false, err
	}

	// Book exists
	return true, nil
}
