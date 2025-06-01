import sqlite3

# Database File
DATABASE = "recipes.db"

def setup_database():
    # Establish connection
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ✅ Create the 'users' table with bio, social media, and image path
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            facebook TEXT,
            instagram TEXT,
            image_path TEXT,  -- Profile picture path
            last_online TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ✅ Create the 'categories' table for recipe categories
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')

    # ✅ Create the 'food_types' table for food types
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS food_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')

    # ✅ Create the 'recipes' table with updated fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,               -- Recipe title
            category TEXT,                     -- Category (Appetizer, Main Dish, etc.)
            food_type TEXT,                    -- Food type (Chicken, Seafood, etc.)
            ingredients TEXT NOT NULL,         -- Ingredients (comma-separated)
            instructions TEXT NOT NULL,        -- Instructions (comma-separated)
            image_path TEXT,                   -- Image path for the recipe
            user_id INTEGER,                   -- Link to the user who created the recipe
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ✅ Create the 'favorites' table to store user's favorite recipes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,          -- The user who favorited the recipe
            recipe_id INTEGER NOT NULL,        -- The recipe they favorited
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (recipe_id) REFERENCES recipes(id)
        )
    ''')

    # ✅ Ensure recipes table has all necessary fields (auto-update columns if missing)
    cursor.execute("PRAGMA table_info(recipes);")
    columns = cursor.fetchall()
    column_names = [column[1] for column in columns]

    missing_columns = {
        "title": "TEXT NOT NULL",
        "category": "TEXT",
        "food_type": "TEXT",
        "cuisine": "TEXT",
        "ingredients": "TEXT NOT NULL",
        "instructions": "TEXT NOT NULL",
        "image_path": "TEXT",
        "prep_time": "TEXT",
        "cook_time": "TEXT",
        "total_time": "TEXT"
    }

    for column, column_type in missing_columns.items():
        if column not in column_names:
            print(f"Adding `{column}` column to `recipes` table...")
            try:
                cursor.execute(f"ALTER TABLE recipes ADD COLUMN {column} {column_type}")
                conn.commit()
                print(f"Added `{column}` column successfully.")
            except sqlite3.Error as e:
                print(f"Error adding column `{column}`: {e}")

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print("Database schema updated successfully!")

# Run the database setup
if __name__ == "__main__":
    setup_database()