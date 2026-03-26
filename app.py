from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required
import sqlite3
import bcrypt
import jwt
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# JWT Secret
JWT_SECRET = "jwtsecretkey"

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

#Database
def get_db():
    return sqlite3.connect("database.db")

def create_table():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT
                    )""")
    conn.close()

create_table()

# USER CLASS
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# REGISTER 
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"].encode()

    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    try:
        conn = get_db()
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered"})
    except:
        return jsonify({"error": "User already exists"})

#LOGIN
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"].encode()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password, user[2]):
        user_obj = User(user[0])
        login_user(user_obj)

        # Generate JWT
        token = jwt.encode({
            "user_id": user[0],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"})

#  PROTECTED ROUTE 
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return jsonify({"message": "Welcome to secure dashboard"})

#JWT PROTECTED ROUTE
@app.route("/api", methods=["GET"])
def api():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token missing"})

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({"message": f"Hello user {data['user_id']}"})
    except:
        return jsonify({"error": "Invalid or expired token"})


# Get all users 

@app.route("/api/users", methods=["GET"])
def get_all_users():
    token = request.headers.get("Authorization")

    
    if not token:
        return jsonify({"error": "Token missing"}), 401

    # Verify JWT token
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return jsonify({"error": "Invalid or expired token"}), 401

    # Fetch users from database
    conn = get_db()
    cursor = conn.execute("SELECT id, username FROM users")
    users = [{"id": row[0], "username": row[1]} for row in cursor.fetchall()]
    conn.close()

    return jsonify({"users": users})


if __name__ == "__main__":
    app.run(debug=True)