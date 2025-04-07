from flask import Flask, request, jsonify, session
import re

app = Flask(__name__)
app.secret_key = 'server_secret_key'

# In-memory storage for user credentials and inventory items.
users = {}
inventory = {}
next_item_id = 1

# Helper functions for verification.
def verifyJWT():
    username = session.get('username')
    if username is None:
        raise ValueError("Unauthorized")

def verifyVarFromSession(varName: str, varType: type):
    if varName in request.json and isinstance(request.json[varName], varType):
        return request.json[varName]
    raise ValueError(f"Invalid or missing {varName}")

def verifyIsJsonResponse():
    if not request.json:
        raise ValueError("Missing JSON payload")

# SESSION MANAGEMENT ROUTES
@app.route('/register', methods=['POST'])
def register():
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
    except ValueError as e:
        return jsonify({"error": str(e) + ". JSON request must include username (string) and password (string)"}), 400

    # Validate username and password with regex.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
        return jsonify({"error": "Username must only consist of letters, numbers, and '-'."}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
        return jsonify({"error": "Password must only consist of letters, numbers, and '-'."}), 400

    # Save login credentials.
    users[username] = password
    return jsonify("Login credentials created.")

@app.route('/login', methods=['POST'])
def login():
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
    except ValueError as e:
        return jsonify({"error": str(e) + ". JSON request must include username (string) and password (string)"}), 400

    # Check if credentials are valid.
    if username not in users or users[username] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    # Create user session.
    session['username'] = username
    return jsonify("Logged in.")

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify("Logged out.")

# INVENTORY CRUD ROUTES

# Create Inventory Item
@app.route('/inventory', methods=['POST'])
def createInventory():
    try:
        verifyJWT()
        verifyIsJsonResponse()
        required_fields = ['name', 'description', 'quantity', 'price']
        for field in required_fields:
            if field not in request.json:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Validate field types.
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
            'price': request.json['price']
        }
        inventory[next_item_id] = new_item
        next_item_id += 1

        return jsonify(new_item), 201

    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# Read all Inventory Items
@app.route('/inventory', methods=['GET'])
def getAllInventory():
    try:
        verifyJWT()
        return jsonify(list(inventory.values()))
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# Read an Inventory Item by ID
@app.route('/inventory/<int:item_id>', methods=['GET'])
def getInventoryItem(item_id):
    try:
        verifyJWT()
        if item_id not in inventory:
            return jsonify({"error": "Item not found"}), 404
        return jsonify(inventory[item_id])
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# Update an Inventory Item
@app.route('/inventory/<int:item_id>', methods=['PATCH'])
def updateInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    if item_id not in inventory:
        return jsonify({"error": "Item not found"}), 404

    if not request.json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    item = inventory[item_id]

    # Update allowed fields if provided.
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

# Delete an Inventory Item
@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def deleteInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    if item_id not in inventory:
        return jsonify({"error": "Item not found"}), 404

    deleted_item = inventory.pop(item_id)
    return jsonify({
        "message": "Item deleted successfully",
        "item": deleted_item
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
