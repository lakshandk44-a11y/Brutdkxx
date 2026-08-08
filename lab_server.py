#!/usr/bin/env python3
"""Lab login target - rate limiting + lockout simulate කරනවා."""
import time
from flask import Flask, request

app = Flask(__name__)
USERS = {"alice": "Summer2024!", "admin": "P@ssw0rd123", "bob": "charlie#99"}
LOCKOUT_AFTER = 8
LOCKOUT_SECONDS = 60
_rate = {}

@app.route("/")
def index():
    return ("<h1>Lab Login</h1><form method='post' action='/login'>"
            "<input name='username'><input name='password' type='password'>"
            "<button>Login</button></form>")

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    now = time.time()
    cnt, until = _rate.get(u, [0, 0.0])
    if now < until:
        return "Account locked. Too many attempts. Try again later.", 429
    if u in USERS and USERS[u] == p:
        _rate.pop(u, None)
        return "Welcome to the dashboard!", 200
    cnt += 1
    if cnt >= LOCKOUT_AFTER:
        until = now + LOCKOUT_SECONDS
        cnt = 0
    _rate[u] = [cnt, until]
    return "Invalid credentials.", 401

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
