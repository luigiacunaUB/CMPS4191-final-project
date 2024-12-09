-- Create table for reading lists
CREATE TABLE reading_lists (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) CHECK (status IN ('currently reading', 'completed')) NOT NULL DEFAULT 'currently reading',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for many-to-many relationship between reading lists and books
CREATE TABLE reading_list_books (
    reading_list_id INT NOT NULL REFERENCES reading_lists(id) ON DELETE CASCADE,
    book_id INT NOT NULL REFERENCES books(id) ON DELETE CASCADE,
    PRIMARY KEY (reading_list_id, book_id)
);

-- Add triggers to update the `updated_at` field automatically for reading_lists table
CREATE OR REPLACE FUNCTION update_reading_lists_updated_at()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = CURRENT_TIMESTAMP;
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach the trigger to the `reading_lists` table
CREATE TRIGGER set_reading_lists_updated_at
BEFORE UPDATE ON reading_lists
FOR EACH ROW
EXECUTE FUNCTION update_reading_lists_updated_at();
