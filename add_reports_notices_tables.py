import sqlite3

DATABASE = "recipes.db"

def create_reports_and_notices_tables():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipe_id INTEGER NOT NULL,
        reported_user_id INTEGER NOT NULL,
        reporting_user_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY (recipe_id) REFERENCES recipes(id),
        FOREIGN KEY (reported_user_id) REFERENCES users(id),
        FOREIGN KEY (reporting_user_id) REFERENCES users(id)
    )
    """)

    # Create notices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_status INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()
    print("Reports and Notices tables created successfully.")

if __name__ == "__main__":
    create_reports_and_notices_tables()
