import datetime
from flask import Flask, abort, redirect, request, jsonify, make_response
# For authentication. We are using the PyJWT library
import jwt

app = Flask(__name__)

# For simplicity, we are using secret key as constants
# We used https://jwtsecretkeygenerator.com to generate a random secret key
JWT_SECRET = "rk8VXd4obfUfKHNzsAHBgYJlq4UVXJ4L1KxiImZ9Js8"
# For the algorithm, we are using HS256, which is a symmetric signing algorithm that uses the same secret key for both signing and verifying the token.
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 15

database_of_users = {
    'mulyono': {'pass': 'hidupJokowi', 'token': None}
}


def create_jwt(username: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_EXP_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    # If bytes returened, convert into utf-8
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

@app.route("/users",methods = ['POST','PUT'])
def users():
    if request.method == "POST":
        # Try to get the JSON request
        data = request.get_json()
        # Try to get the username from the JSON request
        if "username" not in data:
            return make_response(jsonify({"msg":"username is missing"}), 400)
        username = data["username"]

        # Try to get the password
        if "password" not in data:
            return make_response(jsonify({"msg":"password is missing"}), 400)
        password = data["password"]

        # If the user already exists, we don't want someone else overwriting their password!
        if username in database_of_users:
            abort(409)
        
        # Add them in the database
        database_of_users[username] = { "pass": password, "token": None }
        print(f"Pengen meso tapi poso {database_of_users}")
        # Done!
        return "success", 200
    elif request.method == "PUT":
        # Try to get the JSON request
        data = request.get_json()
        # Try to get the username, old password and new password
        if "username" not in data:
            return "username not specified", 400
        username = data["username"]
        if "old-password" not in request.form:
            return "old-password not specified", 400
        old_password = data["old-password"]
        if "new-password" not in request.form:
            return "new-password not specified", 400
        new_password = data["new-password"]

        # Check if the user exists
        if username not in database_of_users: abort(404)

        # Check if the password is valid
        if database_of_users[username]["pass"] != old_password: abort(403)

        # Update the password based on the new password
        database_of_users[username]["pass"] = new_password
        print(f"Bahlil Kontol {database_of_users}")
        return make_response(jsonify({"msg":"success"}), 200)
@app.route("/users/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return make_response(jsonify({"message": "username and password required"}), 400)

    # Checking provided credentials against the hardcoded User's dictionary
    print(f"Hidup mulyono 123 {database_of_users}")
    if username not in database_of_users or database_of_users[username]["pass"] != password:
        return make_response(jsonify({"message": "invalid credentials"}), 401)

    token = create_jwt(username)
    database_of_users[username]['token'] = token
    print(f"Hidup mulyono {database_of_users}")
    return make_response(jsonify({"token": f"Bearer {token}"}), 200)

if __name__ == "__main__":
    app.run(port=8001, debug=True)