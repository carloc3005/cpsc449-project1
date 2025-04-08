from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import re

# Configure Flask to use custom folders:
app = Flask(
    __name__,
    template_folder='pages',    # HTML pages are in the 'pages' folder
    static_folder='images',     # Static files (e.g., images) are in the 'images' folder
    static_url_path='/images'   # Access static files via /images URL
)
app.secret_key = 'server_secret_key'

# In-memory storage for user credentials and inventory items.
users = {}       # Format: { username: {"password": ..., "email": ..., "role": ...} }
inventory = {}
next_item_id = 1

# -----------------------------------
# Helper Functions for Verification
# -----------------------------------
def verifyJWT():
    if not session.get('username'):
        raise ValueError("Unauthorized")

def verifyVarFromSession(varName: str, varType: type):
    if request.json and varName in request.json and isinstance(request.json[varName], varType):
        return request.json[varName]
    raise ValueError(f"Invalid or missing {varName}")

def verifyIsJsonResponse():
    if not request.json:
        raise ValueError("Missing JSON payload")

# -----------------------------------
# Registration Endpoints (API + HTML)
# -----------------------------------

# JSON-based registration (for Postman or API testing)
@app.route('/register', methods=['POST'])
def register():
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
        email = verifyVarFromSession('email', str)
    except ValueError as e:
        return jsonify({"error": f"{str(e)}. JSON must include username, password, and email."}), 400

    role = request.json.get('role', 'user')   # Default to 'user' if not provided.
    if role not in ['user', 'admin']:
        return jsonify({"error": "Role must be either 'user' or 'admin'"}), 400

    # Validate username and password with regex.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
        return jsonify({"error": "Username must only consist of letters, numbers, and '-'."}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
        return jsonify({"error": "Password must only consist of letters, numbers, and '-'."}), 400

    users[username] = {"password": password, "email": email, "role": role}
    return jsonify("User registered successfully."), 201

# HTML-based registration for regular users.
@app.route('/signup_user', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'GET':
        return render_template("signup_user.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = "user"  # Force the role to 'user'
        if not username or not password or not email:
            return render_template("signup_user.html", error="All fields are required.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
            return render_template("signup_user.html", error="Invalid username format.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
            return render_template("signup_user.html", error="Invalid password format.")
        if username in users:
            return render_template("signup_user.html", error="Username already exists.")
        users[username] = {"password": password, "email": email, "role": role}
        return redirect(url_for('login'))

# HTML-based registration for admin accounts.
@app.route('/signup_admin', methods=['GET', 'POST'])
def signup_admin():
    if request.method == 'GET':
        return render_template("signup_admin.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = "admin"  # Force the role to 'admin'
        if not username or not password or not email:
            return render_template("signup_admin.html", error="All fields are required.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
            return render_template("signup_admin.html", error="Invalid username format.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
            return render_template("signup_admin.html", error="Invalid password format.")
        if username in users:
            return render_template("signup_admin.html", error="Username already exists.")
        users[username] = {"password": password, "email": email, "role": role}
        return redirect(url_for('login'))

# -----------------------------------
# Login and Logout Endpoints
# -----------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    else:
        if request.is_json:
            try:
                verifyIsJsonResponse()
                username = verifyVarFromSession('username', str)
                password = verifyVarFromSession('password', str)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
        else:
            username = request.form.get("username")
            password = request.form.get("password")
            if not username or not password:
                return render_template("login.html", error="Missing username or password")
        if username not in users or users[username]["password"] != password:
            if request.is_json:
                return jsonify({"error": "Invalid credentials"}), 401
            else:
                return render_template("login.html", error="Invalid credentials")
        session['username'] = username
        session['role'] = users[username]['role']
        if request.is_json:
            return jsonify("Logged in.")
        else:
            return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    if request.is_json:
        return jsonify("Logged out.")
    else:
        return redirect(url_for('login'))

# -----------------------------------
# Inventory CRUD Endpoints
# -----------------------------------
def can_access(item):
    # Admins can access any item; others only their own.
    if session.get('role') == 'admin':
        return True
    return item.get('owner') == session.get('username')

@app.route('/inventory', methods=['POST'])
def createInventory():
    try:
        verifyJWT()
        verifyIsJsonResponse()
        required_fields = ['name', 'description', 'quantity', 'price']
        for field in required_fields:
            if field not in request.json:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        if not isinstance(request.json['name'], str):
            return jsonify({"error": "name must be a string"}), 400
        if not isinstance(request.json['description'], str):
            return jsonify({"error": "description must be a string"}), 400
        if not isinstance(request.json['quantity'], int):
            return jsonify({"error": "quantity must be an integer"}), 400
        if not isinstance(request.json['price'], (int, float)):
            return jsonify({"error": "price must be a number"}), 400

        global next_item_id
        new_item = {
            'id': next_item_id,
            'name': request.json['name'],
            'description': request.json['description'],
            'quantity': request.json['quantity'],
            'price': request.json['price'],
            'owner': session['username']
        }
        inventory[next_item_id] = new_item
        next_item_id += 1

        return jsonify(new_item), 201

    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/inventory', methods=['GET'])
def getAllInventory():
    try:
        verifyJWT()
        if session.get('role') == 'admin':
            return jsonify(list(inventory.values()))
        else:
            user_items = [item for item in inventory.values() if item.get('owner') == session['username']]
            return jsonify(user_items)
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/inventory/<int:item_id>', methods=['GET'])
def getInventoryItem(item_id):
    try:
        verifyJWT()
        if item_id not in inventory:
            return jsonify({"error": "Item not found"}), 404
        item = inventory[item_id]
        if not can_access(item):
            return jsonify({"error": "Forbidden"}), 403
        return jsonify(item)
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/inventory/<int:item_id>', methods=['PATCH'])
def updateInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    if item_id not in inventory:
        return jsonify({"error": "Item not found"}), 404

    item = inventory[item_id]
    if not can_access(item):
        return jsonify({"error": "Forbidden"}), 403

    if not request.json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    if 'name' in request.json:
        if not isinstance(request.json['name'], str):
            return jsonify({"error": "name must be a string"}), 400
        item['name'] = request.json['name']
    if 'description' in request.json:
        if not isinstance(request.json['description'], str):
            return jsonify({"error": "description must be a string"}), 400
        item['description'] = request.json['description']
    if 'quantity' in request.json:
        if not isinstance(request.json['quantity'], int):
            return jsonify({"error": "quantity must be an integer"}), 400
        item['quantity'] = request.json['quantity']
    if 'price' in request.json:
        if not isinstance(request.json['price'], (int, float)):
            return jsonify({"error": "price must be a number"}), 400
        item['price'] = request.json['price']

    return jsonify(item), 200

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def deleteInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    if item_id not in inventory:
        return jsonify({"error": "Item not found"}), 404

    item = inventory[item_id]
    if not can_access(item):
        return jsonify({"error": "Forbidden"}), 403

    deleted_item = inventory.pop(item_id)
    return jsonify({
        "message": "Item deleted successfully",
        "item": deleted_item
    }), 200

# -----------------------------------
# Dashboard (HTML Interface)
# -----------------------------------
@app.route('/dashboard')
def dashboard():
    try:
        verifyJWT()
        if session.get('role') == 'admin':
            items = list(inventory.values())
        else:
            items = [item for item in inventory.values() if item.get('owner') == session['username']]
        return render_template("dashboard.html", items=items, username=session.get('username'))
    except ValueError:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
