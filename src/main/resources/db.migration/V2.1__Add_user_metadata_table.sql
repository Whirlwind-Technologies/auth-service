- V2.1__Add_user_metadata_table.sql
-- Migration to add user_metadata table for storing key-value pairs

CREATE TABLE user_metadata (
                               user_id UUID NOT NULL,
                               metadata_key VARCHAR(255) NOT NULL,
                               metadata_value TEXT,
                               PRIMARY KEY (user_id, metadata_key),
                               FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add index for faster lookups
CREATE INDEX idx_user_metadata_key ON user_metadata(metadata_key);
CREATE INDEX idx_user_metadata_user ON user_metadata(user_id);