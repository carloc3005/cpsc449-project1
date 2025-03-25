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
@app.route('/inventory', methods=['POST'])
def createInventory():
    try:
        verifyJWT()
    except ValueError:
        return jsonify('error', 'Unauthorized'), 401
    return dummyRoute()

@app.route('/inventory', methods=['GET'])
def getAllInventory():
    try:
        verifyJWT()
    except ValueError:
        return jsonify('error', 'Unauthorized'), 401
    return dummyRoute()

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
