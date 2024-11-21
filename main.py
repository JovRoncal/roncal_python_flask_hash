from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

# Dictionary to store hash values
user_data = {}


# Route for GET /gethash
@app.route('/gethash', methods=['GET'])
def get_hash():
    username = request.args.get('username')  # Get the username from the query string
    if username in user_data:
        return jsonify({"username": username, "hash": user_data[username]})
    return jsonify({"error": "User not found"}), 404


# Route for POST /sethash
@app.route('/sethash', methods=['POST'])
def set_hash():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Hash the password using SHA-256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store the hashed password
        user_data[username] = hashed_password
        return jsonify({"message": "Hash stored successfully"}), 201
    return jsonify({"error": "Username and password required"}), 400


# Route for GET /login
@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    if username and password:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if user_data.get(username) == hashed_password:
            return jsonify({"message": "Login successful"})
        return jsonify({"error": "Invalid username or password"}), 401
    return jsonify({"error": "Username and password required"}), 400


# Route for GET /register
@app.route('/register', methods=['GET'])
def register():
    return jsonify({"message": "Please use POST /sethash to register a user."})


if __name__ == '__main__':
    app.run(debug=True)