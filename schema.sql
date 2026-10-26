CREATE DATABASE IF NOT EXISTS unihub;
USE unihub;

CREATE TABLE IF NOT EXISTS accounts (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(128) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Use this after registering to confirm that the account was stored.
-- The password shown here will be a protected hash, not the original password.
SELECT user_id, username, email, created_at FROM accounts;
