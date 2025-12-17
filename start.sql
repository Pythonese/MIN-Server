CREATE TABLE users (
    id SMALLSERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    firstname VARCHAR(64) NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    profile_images VARCHAR(17)[] -- Array of image paths
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chat_settings BYTEA,
    parent_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    content VARCHAR(1024) NOT NULL, -- Can be a message text or a file name
    filepath VARCHAR(17),
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    is_hidden BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_messages_parent_created ON messages(parent_id, created_at DESC) WHERE is_deleted = false AND is_hidden = false;
CREATE INDEX idx_all_messages_parent_created ON messages(parent_id, created_at DESC) WHERE is_deleted = false;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX idx_messages_content_trigram ON messages USING gin(content gin_trgm_ops);
