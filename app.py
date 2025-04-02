from flask import Flask, request, jsonify, session
import re

app = Flask(__name__)
app.secret_key = 'server_secret_key'

def dummyRoute():
    return jsonify('Route not implemented yet...')

# database in memory
# each record in data should be a different users data.
data = {}
users = {}

# inventory data structure
inventory = {}
# global variable for next item id ( Not sure if we should change this to something else)
next_item_id = 1

# helper functions
def verifyJWT():
    username = session.get('username')
    if username is None:
        raise ValueError

def verifyVarFromSession(varName: str, varType: type):
    if varName in request.json and isinstance(request.json[varName], varType):
        return request.json[varName]
    raise ValueError

def verifyIsJsonResponse():
    if not request.json:
        raise ValueError

# SESSION MANAGEMENT ROUTES
@app.route('/register', methods=['POST'])
def regiester():
    # verify json response, presence of vars, and var types
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
    except ValueError:
        return jsonify({"error": "JSON request must include username (string) and password (string)"}), 400
    
    # Validate user / password requirements with regex.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
        print(username)
        return jsonify({"error": "Username must only consist of letters (lower or upper), numbers (0-9), and '-'."}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
        print(password)
        return jsonify({"error": "Password must only consist of letters (lower or upper), numbers (0-9), and '-'."}), 400
    
    # Save login credentials
    users[username] = password
    return jsonify("Login credentials created.")

@app.route('/login', methods=['POST'])
def login():
    # verify request and var types
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
    except ValueError:
        return jsonify({"error": "JSON request must include username (string) and password (string)"}), 400
    
    # check if credentials valid
    if not username in users or not users[username] == password:
        return jsonify({"error": 'Invalid credentials'}), 401
    
    # create session
    session['username'] = username
    
    return jsonify("Logged in.")

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify("Logged out.")

# CRUD ROUTES

# ------------------------------------------------------------
# Create Route for inventory
@app.route('/inventory', methods=['POST'])
def createInventory():
    try:
        verifyJWT()
        verifyIsJsonResponse()
        
        # Verifing that all fields are present
        required_fields = ['name', 'description', 'quantity', 'price']
        for field in required_fields:
            if field not in request.json:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Validate all field types here
        if not isinstance(request.json['name'], str):
            return jsonify({"error": "name must be a string"}), 400
        if not isinstance(request.json['description'], str):
            return jsonify({"error": "description must be a string"}), 400
        if not isinstance(request.json['quantity'], int):
            return jsonify({"error": "quantity must be an integer"}), 400
        if not isinstance(request.json['price'], (int, float)):
            return jsonify({"error": "price must be a number"}), 400
        
        # Create new inventory item
        global next_item_id
        new_item = {
            'id': next_item_id,
            'name': request.json['name'],
            'description': request.json['description'],
            'quantity': request.json['quantity'],
            'price': request.json['price']
        }
        
        # Updating Item ID for next item
        inventory[next_item_id] = new_item
        next_item_id += 1
        
        return jsonify(new_item), 201
        
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# Read Route for inventory
@app.route('/inventory', methods=['GET'])
def getAllInventory():
    try:
        verifyJWT()
        return jsonify(list(inventory.values()))
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# Read Route for Inventory Item by ID
@app.route('/inventory/<int:item_id>', methods=['GET'])
def getInventoryItem(item_id):
    try:
        verifyJWT()
        if item_id not in inventory:
            return jsonify({"error": "Item not found"}), 404
        return jsonify(inventory[item_id])
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

# ------------------------------------------------------------




@app.route('/inventory/<int:item_id>', methods=['PATCH'])
def updateInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify('error', 'Unauthorized'), 401
    print("item id:", item_id)
    return dummyRoute()

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def deleteInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify('error', 'Unauthorized'), 401
    print("item id:", item_id)
    return dummyRoute()

if __name__ == '__main__':
    app.run(debug=True)
