import os
from sql import SQL
# Use werkzeug to generate and check passwords hashes
from werkzeug.security import generate_password_hash, check_password_hash
# Possible if needed anywhere
from datetime import datetime, timedelta
# Use to generate unique ids for users => 16 bytes, uuid.uuid4()
import uuid
from flask import Flask, send_file, jsonify, request

app = Flask(__name__)

# Use db.execute to execute queries
db = SQL("./school.db")

@app.route("/")
def index():
    return send_file('index.html')

def main():
    app.run(port=int(os.environ.get('PORT', 80)))

if __name__ == "__main__":
    main()


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    # Contains fields: username, role, password, email, name, last_name, birth_date
    # Check if not already in system

    if not data["username"] or not data["role"] or not data["password"] or not data["email"] or not data["name"] or not data["last_name"] or not data["birth_date"]:
        return jsonify({'message': "Missing required fields"}), 400 # Should return an error
    
    # Check if user already exists
    if len(db.execute("SELECT * FROM users WHERE username = ?"), data["username"]) != 0:
        return jsonify({'message': 'Username already exists'}), 422 # Should return user already exists error
    
    # Process User information
    new_user_id = uuid.uuid4()
    db.execute("INSERT INTO users (id, username, role, email) VALUES (?, ?, ?, ?)", new_user_id, data["username"], data["role"], data["email"])
    if data["role"] == "student":
        table = "students"
    elif data["role"] == "teacher":
        table = "teachers"
    else:
        return jsonify({"message": "Invalid role"}), 400
    db.execute(f"INSERT INTO { table } (student_id, name, last_name, birth_date) VALUES (?, ?, ?, ?)", new_user_id, data["name"], data["last_name"], data["birth_date"])
    return jsonify({"message": "Registration successful"}), 200

# Endpoints for students

@app.route("/students", methods=["GET"])
def get_students():
    # Code to get all students
    return

@app.route("/students/<studentId>", methods=["GET"])
def get_student(studentId):
    # Code to get a specific student
    return

@app.route("/students", methods=["POST"])
def create_student():
    # Code to create a new student
    return

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