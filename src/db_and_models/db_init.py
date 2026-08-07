from mysql.connector import connect  # type: ignore[import-not-found]
from mysql.connector.abstracts import MySQLConnectionAbstract
from dotenv import load_dotenv
from typing import Final
from os import getenv


def _get_db_password() -> str:
    """Load .env and return the DB_PASSWORD, raising if not set."""
    load_dotenv(".env")
    password: Final[str | None] = getenv("DB_PASSWORD")
    if password is None:
        raise ValueError("DB_PASSWORD not found in environment")
    return password


def create_connection():
    """Create and return a MySQL database connection."""
    return connect(
        host="localhost",
        user="root",
        password=_get_db_password(),
        database="logging_system",
    )


def create_tables(connection) -> None:
    """Create all application tables if they don't already exist."""
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            account_state ENUM('active', 'pending_removal', 'removed') NOT NULL DEFAULT 'active',
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            created_at DATETIME NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bans (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            banned_at DATETIME NOT NULL,
            banned_until DATETIME NOT NULL,
            reason VARCHAR(255),
            banned_by VARCHAR(36),
            revoked_at DATETIME DEFAULT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,

            FOREIGN KEY (banned_by)
                REFERENCES users(id)
                ON DELETE SET NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            expires_at DATETIME NOT NULL,
            revoked_at DATETIME,
            created_at DATETIME NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            created_at DATETIME NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS MFA_setups (
            user_id VARCHAR(36) PRIMARY KEY,
            user_phone_number VARCHAR(32) UNIQUE NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS MFA_login_requests (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            code_hash VARCHAR(256) NOT NULL,
            expires_at DATETIME NOT NULL,
            confirmed_at DATETIME,
            created_at DATETIME NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    connection.commit()
    cursor.close()


def init_db() -> None:
    """Full database initialisation: connect + create tables."""
    connection = create_connection()
    try:
        create_tables(connection)
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
