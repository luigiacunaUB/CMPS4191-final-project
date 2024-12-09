-- Create table for reviews
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,                -- Unique identifier for the review
    book_id INT NOT NULL REFERENCES books(id) ON DELETE CASCADE, -- Foreign key to books
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Foreign key to users
    rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5), -- Rating on a 1-5 scale
    review TEXT NOT NULL,                 -- Text of the book review
    review_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Date of the review
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- Record creation timestamp
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- Record last update timestamp
    UNIQUE (book_id, user_id)             -- Ensure one review per user per book
);

-- Create trigger function to update the `updated_at` field
CREATE OR REPLACE FUNCTION update_reviews_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach the trigger to the `reviews` table
CREATE TRIGGER set_reviews_updated_at
BEFORE UPDATE ON reviews
FOR EACH ROW
EXECUTE FUNCTION update_reviews_updated_at();
