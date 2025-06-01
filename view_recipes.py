import sqlite3

# Database connection
DATABASE = "recipes.db"

def view_recipes():
    """Fetch and display all recipes in the database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        # Fetch column information
        cursor.execute("PRAGMA table_info(recipes);")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]

        # Ensure required columns exist
        required_columns = ["title", "category", "food_type", "ingredients", "instructions", "image_path", "user_id"]
        missing_columns = [col for col in required_columns if col not in column_names]

        if missing_columns:
            print(f"Missing columns in `recipes` table: {', '.join(missing_columns)}")
            print("Use the following SQL commands to add missing columns:")
            for col in missing_columns:
                print(f"ALTER TABLE recipes ADD COLUMN {col} TEXT;" if col != "user_id" else "ALTER TABLE recipes ADD COLUMN user_id INTEGER;")
            conn.close()
            return

        # Fetch all recipes
        cursor.execute("SELECT id, title, category, food_type, ingredients, instructions, image_path, user_id FROM recipes")
        rows = cursor.fetchall()

        # Debugging: Print fetched recipes
        if rows:
            print(f"\n=== Recipes Found ({len(rows)}) ===")
            print(f"Columns: {', '.join(required_columns)}")
            for row in rows:
                print(f"ID: {row[0]}, Title: {row[1]}, Category: {row[2]}, Food Type: {row[3]}, Image: {row[6]}")
                print(f"Ingredients: {row[4]}")
                print(f"Instructions: {row[5]}")
                print(f"User ID: {row[7]}\n")
        else:
            print("No recipes found in the database.")

    except Exception as e:
        print(f"Error fetching recipes: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    view_recipes()