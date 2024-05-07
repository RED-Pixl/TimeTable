import os
from sql import SQL

from flask import Flask, send_file

app = Flask(__name__)

@app.route("/")
def index():
    return send_file('index.html')

def main():
    app.run(port=int(os.environ.get('PORT', 80)))

if __name__ == "__main__":
    main()

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
    return

@app.route("/rooms/<roomId>", methods=["DELETE"])
def delete_room(roomId):
    # Code to delete a room
    return