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

# Session helper functions
def verifyJWT():
    if session['email']:
        return True
    return False

# SESSION MANAGEMENT ROUTES
@app.route('/register', methods=['POST'])
def regiester():
    return dummyRoute()

@app.route('/login', methods=['POST'])
def login():
    return dummyRoute()

@app.route('/logout', methods=['POST'])
def logout():
    return dummyRoute()

# CRUD ROUTES
@app.route('/inventory', methods=['POST'])
def createInventory():
    return dummyRoute()

@app.route('/inventory', methods=['GET'])
def getAllInventory():
    return dummyRoute()

@app.route('/inventory/<int:item_id>', methods=['PATCH'])
def updateInventory(item_id):
    print("item id:", item_id)
    return dummyRoute()

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def deleteInventory(item_id):
    print("item id:", item_id)
    return dummyRoute()
