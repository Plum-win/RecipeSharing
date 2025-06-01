import sqlite3

DATABASE = "recipes.db"

def check_table_schema():
    """Fetch and validate the schema of the 'recipes' table."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        # Fetch table schema
        cursor.execute("PRAGMA table_info(recipes);")
        columns = cursor.fetchall()

        print("\n=== Schema of 'recipes' Table ===")
        if columns:
            for column in columns:
                print(f"Column: {column[1]}, Type: {column[2]}, Not Null: {bool(column[3])}")
        else:
            print("No columns found in the 'recipes' table. Ensure the table exists.")

        # Verify required columns
        required_columns = ["title", "category", "food_type", "ingredients", "instructions", "image_path", "user_id"]
        existing_columns = [column[1] for column in columns]
        missing_columns = [col for col in required_columns if col not in existing_columns]

        if missing_columns:
            print("\n🚨 Missing Columns Detected!")
            for col in missing_columns:
                print(f"ALTER TABLE recipes ADD COLUMN {col} TEXT;" if col != "user_id" else "ALTER TABLE recipes ADD COLUMN user_id INTEGER;")

        else:
            print("\n✅ Schema is correct! No missing columns.")

    except sqlite3.Error as e:
        print(f"\nError checking schema: {e}")

    finally:
        conn.close()

if __name__ == "__main__":
    check_table_schema()