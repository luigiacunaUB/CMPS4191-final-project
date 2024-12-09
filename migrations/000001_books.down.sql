-- Drop the book-author relationship table
DROP TABLE IF EXISTS book_authors;

-- Drop the authors table
DROP TABLE IF EXISTS authors;

-- Drop the books table
DROP TABLE IF EXISTS books;

-- Drop the trigger function for updating `updated_at`
DROP FUNCTION IF EXISTS update_updated_at;