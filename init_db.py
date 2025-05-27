import sqlite3

def init_database():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        cursor.execute("DROP TABLE IF EXISTS users")

        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                course TEXT NOT NULL,
                section TEXT NOT NULL CHECK(section IN ('2A', '2B', '2C')),
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        print("Database initialized successfully!")

if __name__ == "__main__":
    init_database()
