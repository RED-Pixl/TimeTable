import os
from sql import SQL
# Use werkzeug to generate and check passwords hashes
from werkzeug.security import generate_password_hash, check_password_hash
from password_strength import PasswordPolicy
from flask_bcrypt import Bcrypt
# Possible if needed anywhere
from datetime import datetime, timedelta
# Use to generate unique ids for users => 16 bytes, uuid.uuid4()
import uuid
from flask import Flask, send_file, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

# Use get_jwt_identity to retrieve user identity

app = Flask(__name__)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=364)
# Add BCrypt
bcrypt = Bcrypt(app)

# JWT
jwt = JWTManager(app)

policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=2,  # need min. 2 uppercase letters
    numbers=2,  # need min. 2 digits
    special=2,  # need min. 2 special characters
)

policy_dict = {
    "length" : 8,  # min length: 8
    "uppercase" : 2,  # need min. 2 uppercase letters
    "numbers" : 2,  # need min. 2 digits
    "special" : 2,  # need min. 2 special characters
} 

# Use db.execute to execute queries
db = SQL("./school.db")

@app.route("/")
def index():
    return send_file('index.html')

def main():
    app.run(port=int(os.environ.get('PORT', 80)))

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    required_fields = ["username", "role", "password", "email", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if len(db.execute("SELECT * FROM users WHERE email = ?", data["email"])):
        return jsonify({'message': "Email already registered"}), 422
    if len(db.execute("SELECT * FROM users WHERE username = ?", data["username"])) != 0:
        return jsonify({'message': 'Username already exists'}), 422
    
    # Check if password aligns with policy
    psw_problems = policy.test(data["password"])
    if not len(psw_problems) == 0:
        problems = {prob[:-3] : policy_dict[prob[:-3].lower()] for prob in psw_problems}
        return jsonify({'message': 'Password does not align with policy',
                        "problems" : problems}), 400
    
    new_user_id = str(uuid.uuid4())
    db.execute("INSERT INTO users (id, username, role, password_hash, email) VALUES (?, ?, ?, ?, ?)", new_user_id, data["username"], data["role"], bcrypt.generate_password_hash(data["password"]).decode('utf-8'), data["email"])
    
    if data["role"] == "student":
        table = "students"
    elif data["role"] == "teacher":
        table = "teachers"
    else:
        return jsonify({"message": "Invalid role"}), 400
    
    db.execute(f"INSERT INTO { table } (student_id, name, last_name, birth_date) VALUES (?, ?, ?, ?)",
               new_user_id, data["name"], data["last_name"], data["birth_date"])
    
    return jsonify({"message": "Registration successful"}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    required_fields = ["username", "password"]
    if not all(key in data for key in required_fields):
        return jsonify({"message": "Fill in all the required fields"}), 400
    
    user_info = db.execute("SELECT * FROM users WHERE username = ?", data["username"])
    if len(user_info) != 1:
        return jsonify({"message": "User does not exist"}), 400
    
    user_info = user_info[0]
    if bcrypt.check_password_hash(user_info["password"], data["password"]):        # Create access token
        access_token = create_access_token(identity=data["username"])
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Wrong username or password"}), 400
    
# Endpoints for students

@app.route("/students", methods=["GET"])
def get_students():
    # Code to get all students
    return jsonify(db.execute("SELECT * FROM students")), 200

@app.route("/students/<studentId>", methods=["GET"])
def get_student(studentId):
    # Code to get a specific student
    student = db.execute("SELECT * FROM students WHERE student_id = ?", studentId)
    if len(student) == 0:
        return jsonify({"message" : "Student not found"}), 404
    return jsonify(student[0]), 200

@app.route("/students", methods=["POST"])
def create_student():
    # Code to create a new student
    data = request.get_json()
    required_fields = ["username", "role", "password", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({"message": "Please fill in the required fields",
                        "error": "Not all required fields were filled"}), 422
    # Check if the username already exists
    if len(db.execute("SELECT * FROM users WHERE username = ?", data["username"])) != 0:
        return jsonify({"message": "Username already exists", "error" : "User could not be added"}), 422
    
    student_id = str(uuid.uuid4())
    db.execute("INSERT INTO users (id, username, role, password_hash)", student_id, data["username"], "student", bcrypt.generate_password_hash(data["password"]).decode('utf-8'))
    db.execute("INSERT INTO students (student_id, name, last_name, birth_date)", student_id, data["name"], data["last_name"], data["birth_date"])
    return jsonify({"message" : "Student has been added"}), 200

@app.route("/students/<studentId>", methods=["PUT"])
def update_student(studentId):
    # Code to update a student
    return

@app.route("/students/<studentId>", methods=["DELETE"])
def delete_student(studentId):
    # Code to delete a student
    return

# Endpoints for classes

@app.route("/classes", methods=["GET"])
def get_classes():
    # Code to get all classes
    return

@app.route("/classes/<classId>", methods=["GET"])
def get_class(classId):
    # Code to get a specific class
    return

@app.route("/classes", methods=["POST"])
def create_class():
    # Code to create a new class
    return

@app.route("/classes/<classId>", methods=["PUT"])
def update_class(classId):
    # Code to update a class
    return

@app.route("/classes/<classId>", methods=["DELETE"])
def delete_class(classId):
    # Code to delete a class
    return

# Endpoints for teachers

@app.route("/teachers", methods=["GET"])
def get_teachers():
    # Code to get all teachers
    return

@app.route("/teachers/<teacherId>", methods=["GET"])
def get_teacher(teacherId):
    # Code to get a specific teacher
    return

@app.route("/teachers", methods=["POST"])
def create_teacher():
    # Code to create a new teacher
    return

@app.route("/teachers/<teacherId>", methods=["PUT"])
def update_teacher(teacherId):
    # Code to update a teacher
    return

@app.route("/teachers/<teacherId>", methods=["DELETE"])
def delete_teacher(teacherId):
    # Code to delete a teacher
    return

# Endpoints for rooms

@app.route("/rooms", methods=["GET"])
def get_rooms():
    # Code to get all rooms
    return

@app.route("/rooms/<roomId>", methods=["GET"])
def get_room(roomId):
    # Code to get a specific room
    return

@app.route("/rooms", methods=["POST"])
def create_room():
    # Code to create a new room
    return

@app.route("/rooms/<roomId>", methods=["PUT"])
def update_room(roomId):
    # Code to update a room
    # Update room state [free, used]

    return

@app.route("/rooms/<roomId>", methods=["DELETE"])
def delete_room(roomId):
    # Code to delete a room
    return


if __name__ == "__main__":
    main()
