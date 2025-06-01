import sqlite3

DATABASE = "recipes.db"

def add_image_path_column():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE recipes ADD COLUMN image_path TEXT")
        conn.commit()
        print("The 'image_path' column has been added successfully!")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    add_image_path_column()
