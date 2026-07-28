if __name__ == '__main__':
    from mysql.connector import connect
    from dotenv import load_dotenv
    from typing import Final
    from os import getenv


    load_dotenv(".env")
    DB_PASSWORD: Final[str] = getenv("DB_PASSWORD")
    if DB_PASSWORD is None:
        raise ValueError("Password not read")


    connection = connect(
        host="localhost",
        user="root",
        password=DB_PASSWORD,
        database="logging_system"
    )
    conn_cursor = connection.cursor()


    conn_cursor.execute("""
        CREATE TABLE users (
            id VARCHAR(36) PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            account_state ENUM('active', 'pending_removal', 'removed') NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL
        );
    """)

    conn_cursor.execute("""
        CREATE TABLE user_roles (
            user_id VARCHAR(36) PRIMARY KEY,
            role VARCHAR(20) NOT NULL,
    
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    conn_cursor.execute("""
        CREATE TABLE bans (
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

    conn_cursor.execute("""
        CREATE TABLE refresh_tokens (
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

    conn_cursor.execute("""
        CREATE TABLE password_reset_requests (
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

    conn_cursor.execute("""
        CREATE TABLE MFA_setups (
            user_id VARCHAR(36) PRIMARY KEY,
            user_phone_number VARCHAR(32) UNIQUE NOT NULL,
    
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    conn_cursor.execute("""
        CREATE TABLE MFA_login_requests (
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
    conn_cursor.close()
    connection.close()