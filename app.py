from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import re

# Flask App Setup
app = Flask(__name__)
app.secret_key = "your_secret_key_here"
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Session configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_COOKIE_NAME'] = "recipe_session"

# Database setup
DATABASE = "recipes.db"

def get_db():
    """Establish and return a connection to the database."""
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# List of bad words and sexuality-related words to block
BAD_WORDS = [
    "badword1", "badword2", "badword3",  # placeholder bad words (SORRY FOR THIS....ETO PA ANG ALAM KONG PARAAN)
    "sex", "sexual", "porn", "xxx", "nude", "naked", "erotic", "fetish", "adult", "xxx",
    "fuck", "shit", "bitch", "asshole", "tangina", "putangina", "pakshet", "gago", "tarantado",
    "ulol", "tanga", "bobo", "loko", "hayop", "leche", "pucha", "pwet", "kantot", "shet", "shit",
    "motherfucker", "fucker", "fuck", "fuckyou"
]

def contains_bad_words(text):
    """Check if the given text contains any bad or sexuality-related words."""
    if not text:
        return False
    text = text.lower()
    for word in BAD_WORDS:
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, text):
            return True
    return False

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role='user'):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    if user_id == "0":
        # Return fixed admin user
        return User(id=0, username="shanaiPuray", email="puray@gmail.com", role="admin")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        role = user["role"] if "role" in user.keys() else "user"
        return User(id=user["id"], username=user["username"], email=user["email"], role=role)
    return None

# Decorator to restrict access to admin users only
from functools import wraps
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Admin routes for category management
@app.route('/admin/categories')
@login_required
@admin_required
def admin_categories():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    conn.close()
    return render_template('admin_categories.html', categories=categories)

@app.route('/admin/categories/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_category():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash("Category name cannot be empty.", "danger")
            return redirect(url_for('add_category'))
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            conn.commit()
            flash("Category added successfully.", "success")
            return redirect(url_for('admin_categories'))
        except sqlite3.IntegrityError:
            flash("Category already exists.", "danger")
        finally:
            conn.close()
    return render_template('add_category.html')

@app.route('/admin/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_category(category_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
    category = cursor.fetchone()
    if not category:
        conn.close()
        flash("Category not found.", "danger")
        return redirect(url_for('admin_categories'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash("Category name cannot be empty.", "danger")
            return redirect(url_for('edit_category', category_id=category_id))
        try:
            cursor.execute("UPDATE categories SET name = ? WHERE id = ?", (name, category_id))
            conn.commit()
            flash("Category updated successfully.", "success")
            return redirect(url_for('admin_categories'))
        except sqlite3.IntegrityError:
            flash("Category name already exists.", "danger")
        finally:
            conn.close()
    else:
        conn.close()
        return render_template('edit_category.html', category=category)

@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
@login_required
@admin_required
def delete_category(category_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        flash("Category deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error deleting category: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('admin_categories'))

# Admin routes for food type management
@app.route('/admin/food_types')
@login_required
@admin_required
def admin_food_types():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM food_types ORDER BY name")
    food_types = cursor.fetchall()
    conn.close()
    return render_template('admin_food_types.html', food_types=food_types)

@app.route('/admin/food_types/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_food_type():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash("Food type name cannot be empty.", "danger")
            return redirect(url_for('add_food_type'))
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO food_types (name) VALUES (?)", (name,))
            conn.commit()
            flash("Food type added successfully.", "success")
            return redirect(url_for('admin_food_types'))
        except sqlite3.IntegrityError:
            flash("Food type already exists.", "danger")
        finally:
            conn.close()
    return render_template('add_food_type.html')

@app.route('/admin/food_types/edit/<int:food_type_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_food_type(food_type_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM food_types WHERE id = ?", (food_type_id,))
    food_type = cursor.fetchone()
    if not food_type:
        conn.close()
        flash("Food type not found.", "danger")
        return redirect(url_for('admin_food_types'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash("Food type name cannot be empty.", "danger")
            return redirect(url_for('edit_food_type', food_type_id=food_type_id))
        try:
            cursor.execute("UPDATE food_types SET name = ? WHERE id = ?", (name, food_type_id))
            conn.commit()
            flash("Food type updated successfully.", "success")
            return redirect(url_for('admin_food_types'))
        except sqlite3.IntegrityError:
            flash("Food type name already exists.", "danger")
        finally:
            conn.close()
    else:
        conn.close()
        return render_template('edit_food_type.html', food_type=food_type)

@app.route('/admin/food_types/delete/<int:food_type_id>', methods=['POST'])
@login_required
@admin_required
def delete_food_type(food_type_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM food_types WHERE id = ?", (food_type_id,))
        conn.commit()
        flash("Food type deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error deleting food type: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('admin_food_types'))

# Update recipe add/edit routes to use categories and food types from DB
# Removed duplicate or conflicting add_recipe route definitions to fix the AssertionError

# Removed duplicate or conflicting edit_recipe route definitions to fix the AssertionError

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()

    search_query = None
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        if search_query:
            cursor.execute("""
                SELECT recipes.id, recipes.title, recipes.image_path, recipes.category, recipes.food_type, recipes.cuisine
                FROM recipes
                JOIN users ON recipes.user_id = users.id
                WHERE recipes.title LIKE ?
            """, ('%' + search_query + '%',))
        else:
            cursor.execute("""
                SELECT recipes.id, recipes.title, recipes.image_path, recipes.category, recipes.food_type, recipes.cuisine
                FROM recipes
                JOIN users ON recipes.user_id = users.id
            """)
    else:
        cursor.execute("""
            SELECT recipes.id, recipes.title, recipes.image_path, recipes.category, recipes.food_type, recipes.cuisine
            FROM recipes
            JOIN users ON recipes.user_id = users.id
        """)

    recipes = cursor.fetchall()
    conn.close()

    # Convert recipes into a list of dictionaries for template rendering
    recipes_list = []
    for recipe in recipes:
        recipe_dict = {
            "id": recipe[0],
            "title": recipe[1],
            "image_path": recipe[2] if recipe[2] else "uploads/default-recipe.png",
            "category": recipe[3],
            "food_type": recipe[4],
            "cuisine": recipe[5] or "Not specified"
        }
        recipes_list.append(recipe_dict)

    return render_template('admin_dashboard.html', recipes=recipes_list, search_query=search_query)

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT reports.id, reports.recipe_id, reports.reported_user_id, reports.reporting_user_id, reports.reason, reports.timestamp, reports.status,
               recipes.title, users.username as reported_username
        FROM reports
        JOIN recipes ON reports.recipe_id = recipes.id
        JOIN users ON reports.reported_user_id = users.id
        WHERE reports.status = 'pending'
        ORDER BY reports.timestamp DESC
    """)
    reports = cursor.fetchall()
    conn.close()
    return render_template('admin_reports.html', reports=reports)

# Removed duplicate view_recipe function to fix AssertionError

@app.route('/admin/delete_recipe/<int:recipe_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_recipe(recipe_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Delete the recipe
        cursor.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
        # Update related reports to 'resolved' or delete them
        cursor.execute("UPDATE reports SET status = 'resolved' WHERE recipe_id = ?", (recipe_id,))
        conn.commit()
        flash("Recipe deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error deleting recipe: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('admin_reports'))

@app.route('/admin/manage_users')
@login_required
@admin_required
def admin_manage_users():
    import datetime
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, last_online FROM users")
    users_raw = cursor.fetchall()
    conn.close()

    users = []
    now = datetime.datetime.utcnow()
    for user in users_raw:
        last_online = user['last_online']
        if last_online:
            last_online_dt = datetime.datetime.strptime(last_online, '%Y-%m-%d %H:%M:%S')
            delta = now - last_online_dt
            status = 'Active' if delta.days <= 30 else 'Inactive'
        else:
            status = 'Inactive'
        users.append({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'status': status
        })

    return render_template('admin_manage_users.html', users=users)

@app.route('/admin/menu_settings')
@login_required
@admin_required
def admin_menu_settings():
    return render_template('admin_menusetting.html')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Delete recipes associated with the user
        cursor.execute("DELETE FROM recipes WHERE user_id = ?", (user_id,))
        # Delete the user
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        # Removed cleanup query for orphaned recipes as it is redundant
        conn.commit()
        flash("User and their recipes deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error deleting user and recipes: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('admin_manage_users'))

from flask import redirect
from flask_login import current_user

@app.route('/')
def root():
    if current_user.is_authenticated:
        if hasattr(current_user, 'role') and current_user.role == 'admin':
            return redirect('/admin/dashboard')
        else:
            return redirect('/home')
    else:
        return redirect('/login')

@app.route('/home')
@login_required
def home():
    session.clear()
    conn = get_db()
    cursor = conn.cursor()

    # Fetch all recipes with existing users only
    cursor.execute("""
        SELECT recipes.id, recipes.title, recipes.image_path, recipes.category, recipes.food_type, recipes.cuisine
        FROM recipes
        JOIN users ON recipes.user_id = users.id
    """)
    recipes = cursor.fetchall()

    # Fetch favorite recipe IDs for the logged-in user
    cursor.execute("SELECT recipe_id FROM favorites WHERE user_id = ?", (current_user.id,))
    favorite_recipe_ids = [row[0] for row in cursor.fetchall()]

    # Fetch categories and food types for dropdown menus
    cursor.execute("SELECT name FROM categories ORDER BY name")
    categories = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT name FROM food_types ORDER BY name")
    food_types = [row[0] for row in cursor.fetchall()]

    conn.close()

    # Convert recipes into a list of dictionaries and mark favorites
    recipes_list = []
    for recipe in recipes:
        recipe_dict = {
            "id": recipe[0],
            "title": recipe[1],
            "image_path": recipe[2] if recipe[2] else "uploads/default-recipe.png",
            "category": recipe[3],
            "food_type": recipe[4],
            "cuisine": recipe[5] or "Not specified",
            "is_favorite": recipe[0] in favorite_recipe_ids  # ✅ Mark favorite status
        }
        recipes_list.append(recipe_dict)

    return render_template("base.html", user=current_user, recipes=recipes_list, categories=categories, food_types=food_types)

@app.route('/signup', methods=["GET", "POST"])
def signup():
    # Clear any lingering flash messages
    session.pop('_flashes', None)

    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check for bad words in username and email
        if contains_bad_words(username) or contains_bad_words(email):
            flash("Your username or email contains inappropriate language. Please remove bad words and try again.", "danger")
            return redirect(url_for('signup'))

        conn = get_db()
        cursor = conn.cursor()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            flash("Sign-up successful! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
        finally:
            conn.close()

    return render_template("signup.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        # Check for bad words in email
        if contains_bad_words(email):
            flash("Your email contains inappropriate language. Please remove bad words and try again.", "danger")
            return redirect(url_for('login'))

        # Check for fixed admin account
        if email == "puray@gmail.com" and password == "puray":
            admin_user = User(id=0, username="shanaiPuray", email="puray@gmail.com", role="admin")
            login_user(admin_user, remember=True)
            return redirect(url_for("admin_dashboard"))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user["password"], password):
            # Update last_online timestamp on successful login
            cursor.execute("UPDATE users SET last_online = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
            conn.commit()

            role = user["role"] if "role" in user.keys() else "user"
            login_user(User(id=user["id"], username=user["username"], email=user["email"], role=role), remember=True)
            conn.close()
            next_page = request.args.get('next')
            return redirect(next_page or url_for("home"))
        else:
            conn.close()
            flash("Invalid credentials.", "danger")

    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch user data, including image path
    cursor.execute("SELECT username, email, bio, facebook, instagram, image_path FROM users WHERE id = ?", (current_user.id,))
    user_data = cursor.fetchone()

    # Fetch recipes created by the current user
    cursor.execute("SELECT * FROM recipes WHERE user_id = ?", (current_user.id,))
    user_recipes = cursor.fetchall()

    conn.close()

    # Debugging - Print fetched user data
    print("DEBUG - Fetched User Data:", user_data)

    # Convert user data into a dictionary
    user = {
        "username": user_data[0],
        "email": user_data[1],
        "bio": user_data[2],
        "facebook": user_data[3],
        "instagram": user_data[4],
        "image_path": user_data[5] if user_data[5] else "uploads/profile.png"
    }

    return render_template("profiles/profile.html", user=user, recipes=user_recipes)

@app.context_processor
def inject_cuisines():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch distinct cuisines from the recipes table
    cursor.execute("SELECT DISTINCT cuisine FROM recipes WHERE cuisine IS NOT NULL AND cuisine != ''")
    cuisines = [row[0] for row in cursor.fetchall()]

    conn.close()
    return {'cuisines': cuisines}

@app.route('/filter')
def filter_recipes():
    filter_type = request.args.get('type')  # e.g., category
    selection = request.args.get('selection')  # e.g., Drinks

    conn = get_db()
    cursor = conn.cursor()

    # Fetch filtered recipes
    cursor.execute(f"SELECT * FROM recipes WHERE LOWER({filter_type}) = LOWER(?)", (selection,))
    recipes = cursor.fetchall()

    # Convert sqlite3.Row objects into dictionaries
    recipes = [dict(row) for row in recipes]

    conn.close()

    # Debugging: Confirm the conversion to dictionaries
    print(f"Fetched recipes as dictionaries: {recipes}")

    # Render the new filtered recipes page
    return render_template('filtered_recipes.html', recipes=recipes, filter_type=filter_type, selection=selection)

@app.route('/profile_settings', methods=["GET", "POST"])
@login_required
def update_profile():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        bio = request.form.get("bio")
        facebook = request.form.get("facebook")
        instagram = request.form.get("instagram")
        image = request.files.get("image")  # Get the uploaded image

        # Check for bad words in all text inputs
        if (contains_bad_words(username) or contains_bad_words(email) or contains_bad_words(bio) or
            contains_bad_words(facebook) or contains_bad_words(instagram)):
            flash("Your profile contains inappropriate language. Please remove bad words and try again.", "danger")
            return redirect(url_for("update_profile"))

        conn = get_db()
        cursor = conn.cursor()

        if username:
            cursor.execute("UPDATE users SET username = ? WHERE id = ?", (username, current_user.id))
        if email:
            cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, current_user.id))
        if password:
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, current_user.id))
        if bio:
            cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, current_user.id))
        if facebook:
            cursor.execute("UPDATE users SET facebook = ? WHERE id = ?", (facebook, current_user.id))
        if instagram:
            cursor.execute("UPDATE users SET instagram = ? WHERE id = ?", (instagram, current_user.id))
        if image:
            # Save the uploaded image to the static/uploads folder
            image_filename = secure_filename(image.filename)  # Sanitize filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)  # Save to static/uploads/
            image.save(image_path)

            # Store the relative path (e.g., 'uploads/filename.png')
            image_path = os.path.join('uploads', image_filename)
            cursor.execute("UPDATE users SET image_path = ? WHERE id = ?", (image_path, current_user.id))

        conn.commit()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("profiles/profile_setting.html", user=current_user)

@app.route('/favorites')
@login_required
def favorites():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch user's favorite recipes
    cursor.execute("""
        SELECT recipes.id, recipes.title, recipes.image_path, recipes.category, recipes.food_type, recipes.cuisine
        FROM recipes
        JOIN favorites ON recipes.id = favorites.recipe_id
        WHERE favorites.user_id = ?""",
        (current_user.id,))
    
    favorite_recipes = cursor.fetchall()

    # Fetch only favorite recipe IDs (to persist checkbox state)
    cursor.execute("SELECT recipe_id FROM favorites WHERE user_id = ?", (current_user.id,))
    favorite_recipe_ids = [row[0] for row in cursor.fetchall()]

    conn.close()

    return render_template("profiles/favorites.html", recipes=favorite_recipes, favorite_recipe_ids=favorite_recipe_ids)

@app.route('/add_favorite', methods=['POST'])
@login_required
def add_favorite():
    data = request.get_json()  # Get JSON data from the request
    recipe_id = data.get("recipe_id")  # Extract recipe ID
    is_favorited = data.get("favorite")  # Extract favorite status

    conn = get_db()
    cursor = conn.cursor()

    # Check if the recipe is already a favorite
    cursor.execute("SELECT * FROM favorites WHERE user_id = ? AND recipe_id = ?", (current_user.id, recipe_id))
    existing_favorite = cursor.fetchone()

    try:
        if is_favorited == "on" and not existing_favorite:
            # Add to favorites
            cursor.execute("INSERT INTO favorites (user_id, recipe_id) VALUES (?, ?)", (current_user.id, recipe_id))
            conn.commit()
        elif is_favorited is None and existing_favorite:
            # Remove from favorites
            cursor.execute("DELETE FROM favorites WHERE user_id = ? AND recipe_id = ?", (current_user.id, recipe_id))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

    return '', 204  # Return empty response with status code 204 (No Content)

@app.route('/own_recipes', methods=["GET", "POST"])
@login_required
def own_recipes():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        # Retrieve form inputs
        title = request.form["title"]
        category = request.form["category"]
        food_type = request.form["food_type"]
        cuisine = request.form["cuisine"]  # ✅ Added Cuisine field
        ingredient_names = request.form.getlist("ingredient_names[]")
        ingredient_quantities = request.form.getlist("ingredient_quantities[]")
        ingredient_units = request.form.getlist("ingredient_units[]")
        instructions = request.form.getlist("instructions[]")
        prep_time_value = int(request.form["prep_time_value"])  # Prep Time Value
        prep_time_unit = request.form["prep_time_unit"]  # Prep Time Unit
        cook_time_value = int(request.form["cook_time_value"])  # Cook Time Value
        cook_time_unit = request.form["cook_time_unit"]  # Cook Time Unit
        image = request.files.get("image")

        # Combine ingredient details correctly
        ingredients = [f"{quantity} {unit} {name}" for name, quantity, unit in zip(ingredient_names, ingredient_quantities, ingredient_units)]
        ingredients_str = ",".join(ingredients)
        instructions_str = ",".join(instructions)

        # Convert all times to minutes
        prep_time_value = int(request.form["prep_time_value"])  # Prep Time Value
        prep_time_unit = request.form["prep_time_unit"]  # Prep Time Unit
        cook_time_value = int(request.form["cook_time_value"])  # Cook Time Value
        cook_time_unit = request.form["cook_time_unit"]  # Cook Time Unit

# Convert all times to minutes
        prep_time_in_minutes = prep_time_value * 60 if prep_time_unit == "hours" else prep_time_value
        cook_time_in_minutes = cook_time_value * 60 if cook_time_unit == "hours" else cook_time_value

# Calculate total time in minutes
        total_time_in_minutes = prep_time_in_minutes + cook_time_in_minutes

# Save total time with appropriate units
        if total_time_in_minutes < 60:
            total_time = f"{total_time_in_minutes} minutes"
        else:
            total_time = f"{total_time_in_minutes // 60} hours {total_time_in_minutes % 60} minutes" if total_time_in_minutes % 60 != 0 else f"{total_time_in_minutes // 60} hours"

        # Validate required fields
        if not title or not category or not food_type or not cuisine or not ingredients or not instructions:
            flash("All fields are required!", "danger")
            return redirect(url_for("own_recipes"))

        # Initialize image path
        image_path = None

        # Save image if uploaded
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            image_path = f"uploads/{image_filename}"

        # Insert the recipe into the database with cuisine included
        try:
            cursor.execute(
                '''INSERT INTO recipes (title, category, food_type, cuisine, ingredients, instructions, prep_time, cook_time, total_time, image_path, user_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (title, category, food_type, cuisine, ingredients_str, instructions_str,
                  f"{prep_time_value} {prep_time_unit}", f"{cook_time_value} {cook_time_unit}", total_time, image_path, current_user.id)
            )
            conn.commit()
            flash("Recipe added successfully!", "success")
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash("An error occurred while saving the recipe. Please try again.", "danger")
        finally:
            conn.close()

        return redirect(url_for("own_recipes"))

    # Fetch recipes created by the logged-in user, including cuisine
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, category, food_type, cuisine, rating, ingredients, instructions, prep_time, cook_time, total_time, image_path FROM recipes WHERE user_id = ?", (current_user.id,))
    recipes_raw = cursor.fetchall()
    conn.close()

    # Debugging: Print fetched recipes to verify correctness
    print("Recipe Data Sent to Own Recipes Page:", recipes_raw)

    # Convert raw recipes to structured format with correctly assigned fields
    recipes = []
    for recipe in recipes_raw:
        recipes.append({
            "id": recipe[0],  
            "title": recipe[1],
            "category": recipe[2],
            "food_type": recipe[3],
            "cuisine": recipe[4],
            "rating": recipe[5],  # Added rating field
            "ingredients": recipe[6].split(","),
            "instructions": recipe[7].split(","),
            "prep_time": recipe[8],
            "cook_time": recipe[9],
            "total_time": recipe[10],
            "image_path": recipe[11] if recipe[11] else "uploads/default-recipe.png"
        })

    return render_template("profiles/own_recipes.html", recipes=recipes)

@app.route('/edit_recipe/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def edit_recipe(recipe_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM categories ORDER BY name")
    categories = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT name FROM food_types ORDER BY name")
    food_types = [row[0] for row in cursor.fetchall()]

    if request.method == 'POST':
        # Handle form submission
        title = request.form['title']
        category = request.form['category']
        food_type = request.form['food_type']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        image_path = request.form['image_path']  # Current image path
        image = request.files.get('image')  # Retrieve the uploaded image file

        # Check for bad words in inputs
        if contains_bad_words(title) or contains_bad_words(ingredients) or contains_bad_words(instructions):
            flash("Your recipe contains inappropriate language. Please remove bad words and try again.", "danger")
            return redirect(url_for('edit_recipe', recipe_id=recipe_id))

        # Process the uploaded image if provided
        if image and image.filename != '':
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            image_path = f"uploads/{image_filename}"  # Update the image path

        # Update the recipe with or without a new image
        cursor.execute('''
            UPDATE recipes
            SET title = ?, category = ?, food_type = ?, ingredients = ?, instructions = ?, image_path = ?
            WHERE id = ?
        ''', (title, category, food_type, ingredients, instructions, image_path, recipe_id))

        conn.commit()
        conn.close()

        # Redirect back to the Own Recipe page
        return redirect(url_for('own_recipes'))

    # Fetch the existing recipe details for the GET request
    cursor.execute('SELECT * FROM recipes WHERE id = ?', (recipe_id,))
    recipe = cursor.fetchone()
    conn.close()

    # Pass recipe details to the edit_recipe.html template
    return render_template('profiles/edit_recipe.html', recipe=dict(recipe), categories=categories, food_types=food_types)

@app.route('/search')
def search():
    query = request.args.get('query')  # Get the search query from the request

    # Check for bad words in the search query
    if contains_bad_words(query):
        flash("Your search query contains inappropriate language. Please remove bad words and try again.", "danger")
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Search for recipes by title and fetch the corresponding username from the users table
    cursor.execute("""
        SELECT recipes.id, recipes.title, users.username AS author, recipes.image_path
        FROM recipes
        JOIN users ON recipes.user_id = users.id
        WHERE recipes.title LIKE ? OR users.username LIKE ?
    """, ('%' + query + '%', '%' + query + '%'))
    results = cursor.fetchall()

    conn.close()

    # Convert results to a list of dictionaries for template rendering
    recipes = []
    for row in results:
        recipes.append({
            "id": row[0],          # Recipe ID
            "title": row[1],       # Recipe Title
            "author": row[2],      # Author (username)
            "image_path": row[3]   # Recipe Image Path
        })

    # Render search results or display "No Recipe Found" if there are no results
    if recipes:
        return render_template("search_results.html", results=recipes, query=query)
    else:
        return render_template("search_results.html", results=None, query=query)

@app.route('/recipe/<int:recipe_id>')
@login_required
def view_recipe(recipe_id):
    """Retrieve and display a single recipe by its ID."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT recipes.*, users.username AS author
        FROM recipes
        JOIN users ON recipes.user_id = users.id
        WHERE recipes.id = ?
    """, (recipe_id,))
    recipe = cursor.fetchone()
    
    # Check if 'report' query parameter is present and true
    report_context = request.args.get('report', 'false').lower() == 'true'
    
    conn.close()

    if recipe:
        if current_user.is_authenticated and current_user.role == 'admin':
            return render_template("admin_public_recipe.html", recipe=recipe, report_context=report_context)
        else:
            return render_template("public_recipe.html", recipe=recipe)
    else:
        flash("Recipe not found.", "danger")
        return redirect(url_for("home"))

@app.route('/report_recipe/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def report_recipe(recipe_id):
    if request.method == 'POST':
        reason = request.form.get('reason')
        if not reason:
            flash("Please select a reason for reporting.", "danger")
            return redirect(url_for('view_recipe', recipe_id=recipe_id))

        conn = get_db()
        cursor = conn.cursor()

        # Get the user_id of the recipe owner
        cursor.execute("SELECT user_id FROM recipes WHERE id = ?", (recipe_id,))
        recipe_owner = cursor.fetchone()
        if not recipe_owner:
            flash("Recipe not found.", "danger")
            conn.close()
            return redirect(url_for('home'))

        try:
            cursor.execute("""
                INSERT INTO reports (recipe_id, reported_user_id, reporting_user_id, reason)
                VALUES (?, ?, ?, ?)
            """, (recipe_id, recipe_owner[0], current_user.id, reason))
            conn.commit()
            flash("Report submitted successfully.", "success")
        except sqlite3.Error as e:
            flash(f"An error occurred while submitting the report: {e}", "danger")
        finally:
            conn.close()

        return redirect(url_for('view_recipe', recipe_id=recipe_id))
    else:
        return render_template('report_recipe.html', recipe_id=recipe_id)

@app.route('/about_us')
@login_required
def about_us():
    return render_template("about_us.html")

@app.route('/add_recipe', methods=["GET", "POST"])
@login_required
def add_recipe():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM categories ORDER BY name")
    categories = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT name FROM food_types ORDER BY name")
    food_types = [row[0] for row in cursor.fetchall()]
    conn.close()

    if request.method == "POST":
        # Fetch form data
        title = request.form['title']
        category = request.form['category']
        food_type = request.form['food_type']
        cuisine = request.form.get('cuisine')
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        image_path = request.form.get('image_path')  # Optional image path
        recipe_by = current_user.email  # Use the logged-in user's email as the recipe creator

        # Check for bad words in all relevant inputs
        if (contains_bad_words(title) or contains_bad_words(category) or contains_bad_words(food_type) or
            contains_bad_words(cuisine) or contains_bad_words(ingredients) or contains_bad_words(instructions)):
            flash("Your recipe contains inappropriate language. Please remove bad words and try again.", "danger")
            return redirect(url_for('add_recipe'))

        conn = get_db()
        cursor = conn.cursor()

        # Insert into the database
        cursor.execute("""
            INSERT INTO recipes (title, category, food_type, cuisine, ingredients, instructions, image_path, recipe_by) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (title, category, food_type, cuisine, ingredients, instructions, image_path, recipe_by))
        conn.commit()
        conn.close()

        flash("Recipe added successfully!", "success")
        return redirect(url_for('own_recipes'))

    return render_template("profiles/add_recipe.html", categories=categories, food_types=food_types)

@app.route('/delete_recipe/<int:recipe_id>', methods=["POST"])
@login_required
def delete_recipe(recipe_id):
    conn = get_db()
    cursor = conn.cursor()

    # Delete the recipe with the given ID
    try:
        cursor.execute("DELETE FROM recipes WHERE id = ? AND user_id = ?", (recipe_id, current_user.id))
        conn.commit()
        flash("Recipe deleted successfully!", "success")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash("An error occurred while deleting the recipe. Please try again.", "danger")
    finally:
        conn.close()

    return redirect(url_for('own_recipes'))

@app.route('/public_recipe/<int:recipe_id>')
def public_view_recipe(recipe_id):
    """Retrieve and display a public view of a recipe by its ID."""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch the recipe details and dynamically retrieve the author's username
        cursor.execute("""
            SELECT recipes.*, users.username AS author
            FROM recipes
            JOIN users ON recipes.user_id = users.id
            WHERE recipes.id = ?
        """, (recipe_id,))
        recipe = cursor.fetchone()

        if recipe:
            # Convert the fetched recipe to a dictionary for template rendering
            return render_template("public_recipe.html", recipe=dict(recipe))
        else:
            flash("Recipe not found.", "danger")
            return redirect(url_for("home"))
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash("An error occurred while fetching the recipe.", "danger")
        return redirect(url_for("home"))
    finally:
        conn.close()
    
@app.route('/rate_recipe/<int:recipe_id>', methods=["POST"])
@login_required
def rate_recipe(recipe_id):
    rating = float(request.form["rating"])  # Retrieve the rating from the form
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Insert new rating into the ratings table
        cursor.execute("INSERT INTO ratings (recipe_id, user_id, rating) VALUES (?, ?, ?)", (recipe_id, current_user.id, rating))

        # Calculate the average rating for the recipe
        cursor.execute("SELECT AVG(rating) FROM ratings WHERE recipe_id = ?", (recipe_id,))
        avg_rating = cursor.fetchone()[0]

        # Update the recipe's average rating in the recipes table
        cursor.execute("UPDATE recipes SET rating = ? WHERE id = ?", (avg_rating, recipe_id))
        conn.commit()
        flash("Rating submitted successfully!", "success")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash("An error occurred while submitting your rating. Please try again.", "danger")
    finally:
        conn.close()

    # Redirect back to the public recipe page after rating
    return redirect(url_for("public_view_recipe", recipe_id=recipe_id))  # Updated to match public recipe view

if __name__ == '__main__':
    app.run(debug=True)