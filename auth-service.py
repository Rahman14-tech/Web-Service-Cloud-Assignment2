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

USERS = {
    "ali": "ali123",
    "akbar": "akbar123",
    "rahman": "rahman123",
    "jaden": "jaden123"
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

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return make_response(jsonify({"message": "username and password required"}), 400)

    # Checking provided credentials against the hardcoded User's dictionary
    if username not in USERS or USERS[username] != password:
        return make_response(jsonify({"message": "invalid credentials"}), 401)

    token = create_jwt(username)
    return make_response(jsonify({"token": token}), 200)

if __name__ == "__main__":
    app.run(port=5001, debug=True)