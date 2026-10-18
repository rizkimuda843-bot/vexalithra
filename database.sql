CREATE DATABASE IF NOT EXISTS vexalithra;
USE vexalithra;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    display_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(255) NOT NULL,
    owner VARCHAR(100) NOT NULL,
    permission_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    reproduction TEXT,
    remediation TEXT,
    raw_code TEXT,
    evidence_path VARCHAR(255) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    assigned_to INT,
    found_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Akun Admin (Password: vexalithra2026)
INSERT INTO users (username, password, role, display_name) VALUES 
('admin', '$2y$10$wW5tXk1B5xQ.2Z3e4R5t6u7I8o9P0a1S2d3F4g5H6j7K8l9M0n1O2p3Q4r5S6t7U8v', 'admin', 'Administrator');