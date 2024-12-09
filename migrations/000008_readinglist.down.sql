-- Drop the trigger for updating `updated_at` in `reading_lists`
DROP TRIGGER IF EXISTS set_reading_lists_updated_at ON reading_lists;

-- Drop the `reading_list_books` table (many-to-many relationship between reading lists and books)
DROP TABLE IF EXISTS reading_list_books;

-- Drop the `reading_lists` table
DROP TABLE IF EXISTS reading_lists;
