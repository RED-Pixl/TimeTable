import os
from sql import SQL
from password_strength import PasswordPolicy
from flask_bcrypt import Bcrypt
# Possible if needed anywhere
from datetime import datetime, timedelta
# Use to generate unique ids for users => 16 bytes, uuid.uuid4()
import uuid
from flask import Flask, send_file, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from functools import wraps
import logging


# Use get_jwt_identity to retrieve user identity

app = Flask(__name__)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=364)
app.config["SECRET_KEY"] = "THIS IS A SECRET_KEY"

# Add BCrypt
bcrypt = Bcrypt(app)

# JWT
jwt = JWTManager(app)

# Logger
logging.basicConfig(filename='flask.log', level=logging.INFO)

policy_dict = {
    "Length" : 8,  # min length: 8
    "Uppercase" : 1,  # need min. 2 uppercase letters
    "Numbers" : 2,  # need min. 2 digits
    "Special" : 1,  # need min. 2 special characters
} 

policy = PasswordPolicy.from_names(
    length= policy_dict["Length"],  # min length: 8
    uppercase= policy_dict["Uppercase"],  # need min. 2 uppercase letters
    numbers=policy_dict["Numbers"],  # need min. 2 digits
    special=policy_dict["Special"],  # need min. 2 special characters
)

ADMIN_ROLE = "admin"
TEACHER_ROLE = "teacher"
STUDENT_ROLE = "student"

# Use db.execute to execute queries
db = SQL("./school.db")

@app.route("/")
def index():
    return send_file('index.html')

def main():
    app.run(port=int(os.environ.get('PORT', 80)))

"""
These Decorators have a hierarchical structure. 
Admins are allowed to do anything and access all the routes.
Teachers have special permissions and can do anything students can do as well.
Students have restricted access to routes.
"""

# Custom decorator for admin-only routes
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        # Check if user has admin role
        if db.execute("SELECT role FROM users WHERE username = ?", current_user)[0]["role"] != ADMIN_ROLE:
            return jsonify({"message": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# Custom decorator for teacher-only routes
def teacher_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        # Check if user has teacher role
        user_role = db.execute("SELECT role FROM users WHERE username = ?", current_user)[0]["role"]
        if user_role == ADMIN_ROLE or user_role == TEACHER_ROLE:
            return fn(*args, **kwargs)
        return jsonify({"message": "Teacher access required"}), 403
    return wrapper

# Custom decorator for student-only routes
def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        # Check if user has student role
        user_role = db.execute("SELECT role FROM users WHERE username = ?", current_user)[0]["role"]
        if user_role == ADMIN_ROLE or user_role == TEACHER_ROLE or user_role == STUDENT_ROLE:
            return fn(*args, **kwargs)
        return jsonify({"message": "Student access required"}), 403
    return wrapper

# ================================================================= # ================================================================= #

"""
Routes coming up are for the authentication and registration process.
When editing the functions, please add logging information to the log file "server.log".
"""

@app.route("/api/register", methods=["POST"])
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
        problems = {}
        for problem in psw_problems:
            # "< class 'password_strength.tests.Problem'>"
            problem = str(type(problem)).split("'")[-2].split(".")[-1]
            problems[problem] = policy_dict[problem]
        return jsonify({'message': 'Password does not align with policy',
                        "problems" : problems}), 400
    
    # Check Role
    if data["role"] == "student":
        table = "students"
    elif data["role"] == "teacher":
        table = "teachers"
    else:
        return jsonify({"message": "Invalid role"}), 400
    
    new_user_id = str(uuid.uuid4())
    db.execute("INSERT INTO users (id, username, role, password_hash, email) VALUES (?, ?, ?, ?, ?)", new_user_id, data["username"], data["role"], bcrypt.generate_password_hash(data["password"]).decode('utf-8'), data["email"])
    
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
    if bcrypt.check_password_hash(user_info["password_hash"], data["password"]):        # Create access token
        access_token = create_access_token(identity=data["username"])
        return jsonify(access_token=access_token, message="Login Successful"), 200
    else:
        return jsonify({"message": "Wrong username or password"}), 400

# ================================================================= # ================================================================= #
"""
Function for getting all known schools and information
"""

@app.route("/api/schools", methods=["GET"])
def get_schools():
    return jsonify(db.execute("SELECT * FROM schools")), 200
# Endpoints for students

# ================================================================= # ================================================================= #
@jwt_required()
@admin_required()
@app.route("/api/student", methods=["GET"])
def get_students():
    # Code to get all students
    return jsonify(db.execute("SELECT * FROM students")), 200

@jwt_required()
@teacher_required()
@app.route("/api/student/<studentId>", methods=["GET"])
def get_student(studentId):
    # Code to get a specific student
    user_info = db.execute("SELECT * FROM users WHERE username = ?", studentId)
    if not any(user_info):
        return jsonify({"error": "Student not found"}), 404
    
    personal_info = db.execute("SELECT * FROM students WHERE id = ?", user_info["id"])
    class_id = db.execute("SELECT * FROM student_to_class WHERE student_id = ?", user_info["id"])["class_id"]
    schedule = db.execute("SELECT * FROM schedule_table WHERE class_id = ?", class_id)

    whole_info = {
        "personalInformation": personal_info,
        "schoolInformation": {
            "class": class_id,
            "schedule": schedule
        }
    }

    return jsonify(whole_info), 200

# /api/register is better 
@jwt_required()
@admin_required
@app.route("/api/student", methods=["POST"])
def create_student():
    return jsonify({"msg": "This path is not in use anymore. Use /api/register instead."}), 404

#TODO: FIGURE OUT WHAT THE UPDATES ARE
@app.route("/api/student/<studentId>", methods=["PUT"])
def update_student_personal(studentId):
    # Code to update a student
    return

# ================================================================= # ================================================================= #
"""
Delete helper function for student and teacher
"""
def delete(username):
    # FIND ALL indormation about id
    user_info = db.execute("SELECT * FROM users WHERE username = ?", id)
    if user_info["role"] == "student":
        classId = db.execute("SELECT id FROM classes WHERE class_id = (SELECT class_id FROM student_to_class WHERE student_id = ?)", user_info["id"])["id"]
        db.execute("UPDATE class SET student_count = student_count - ? WHERE id = ?", 1, classId)
    elif user_info["role"] == "teacher":
        role_info = db.execute("SELECT * FROM teachers WHERE teacher_id = ?", user_info["id"])
        if any(db.execute("SELECT * FROM teacher_to_class WHERE teacher_id = ?)", role_info["teacher_id"])) or any(db.execute("SELECT * FROM subjects WHERE head_teacher_id = ?", user_info["id"])) or any(db.execute("SELECT * FROM schedule_table WHERE teacher_id = ?", user_info["id"])):
            return False
        db.execute("DELETE FROM teacher_to_subject WHERE teacher_id = ?", user_info["id"])
    else: 
        return False
        
    # DELETING FUNCTIONS DANGER!!!!!!!
    db.execute(f"DELETE FROM {user_info["role"]}_to_class WHERE student_id = ?", user_info["id"])
    db.execute(f"DELETE FROM {user_info["role"]}s WHERE {user_info["role"]}_id = ?", user_info["id"])
    return True

# ================================================================= # =================================================================
@jwt_required()
@teacher_required()
@app.route("/student/<studentId>", methods=["DELETE"])
def delete_student(studentId):
    # Code to delete a student
    if not delete(studentId):
        return jsonify({
            "msg": "Something went wrong, could not delete student",
            "studentId": studentId,
        }), 400
    return jsonify({
        "msg": "Student has been deleted",
        "studentId": studentId
    }), 200

# ================================================================= # =================================================================
# Endpoints for classes

@jwt_required
@teacher_required
@app.route("/classes", methods=["GET"])
def get_classes():
    # Code to get all classes
    return jsonify(db.execute("SELECT * FROM classes")), 200

@jwt_required
@teacher_required
@app.route("/classes/<classId>", methods=["GET"])
def get_class(classId):
    # Code to get a specific class
    return jsonify(db.execute("SELECT * FROM classes WHERE id = ?", classId)), 200

#TODO: IMLEMENTATION
@jwt_required
@admin_required
@app.route("/classes", methods=["POST"])
def create_class():
    # Code to create a new class
    data = request.get_json()

@jwt_required
@admin_required
@app.route("/classes/<classId>", methods=["PUT"])
def update_class(classId):
    # Code to update a class
    if any(db.execute("SELECT * FROM student_to_class WHERE class_id = ?", classId)) or any(db.execute("SELECT * FROM schedule_table WHERE class_id = ?", classId)) or any("SELECT * FROM teacher_to_class WHERE class_id = ?", classId):
        return jsonify({
            "msg": "Could not update a class. This classId is still in use. Please remove usage first.",
            "classId": classId
        }), 400
    data = request.get_json()
    student_count = data["studentCount"]
    class_room = data["classRoom"]
    db.execute("UPDATE classes SET student_count = ?, class_room = ? WHERE id = ?", student_count, class_room, classId)
    return jsonify({
        "msg": "Successfully updated class!",
        "classId": classId
    }), 200

@jwt_required()
@admin_required
@app.route("/classes/<classId>", methods=["DELETE"])
def delete_class(classId):
    # Code to delete a class
    if any(db.execute("SELECT * FROM student_to_class WHERE classId = ?", classId)):
        return jsonify({
            "msg": "Could not delete a class",
            "classId": classId
        }), 400
    db.execute("DELETE FROM classes WHERE id  = ?", classId)
    return jsonify({
        "msg": "Class was deleted",
        "classId": classId
    }), 200

# ================================================================= # =================================================================
# Endpoints for teachers

@jwt_required()
@teacher_required
@app.route("/teachers", methods=["GET"])
def get_teachers():
    # Code to get all teachers
    return jsonify(db.execute("SELECT * FROM teachers")), 200

@jwt_required()
@admin_required
@app.route("/teachers/<teacherId>", methods=["GET"])
def get_teacher(teacherId):
    # Code to get a specific teacher
    user_info = db.execute("SELECT * FROM users WHERE username = ?", teacherId)
    if not any(user_info):
        return jsonify({"error": "Teacher not found"}), 404
    
    personal_info = db.execute("SELECT * FROM teachers WHERE id = ?", user_info["id"])
    class_id = db.execute("SELECT * FROM teacher_to_class WHERE student_id = ?", user_info["id"])["class_id"]
    schedule = db.execute("SELECT * FROM schedule_table WHERE class_id = ?", class_id)

    whole_info = {
        "personalInformation": personal_info,
        "schoolInformation": {
            "class": class_id,
            "schedule": schedule
        }
    }

    return jsonify(whole_info), 200

@jwt_required()
@admin_required
@app.route("/teachers", methods=["POST"])
def create_teacher():
    # Code to create a new teacher
    return jsonify({
        "msg": "This route is not supported anymore. Please use the /api/register route instead.",
    }), 404

@jwt_required()
@admin_required
@app.route("/teachers/<teacherId>", methods=["PUT"])
def update_teacher_personal(teacherId):
    # Code to update a teacher
    data = request.get_json()

    required_fields = ["username", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    teacher_info = db.execute("SELECT * FROM users WHERE username = ?", teacherId)
    db.execute("UPDATE teachers SET name = ?, last_name = ?, birth_date = ? WHERE teacher_id = ?", data["name"], data["last_name"], data["birth_date"], teacher_info["id"])
    return jsonify({
        "msg": "Updated teacher information",
        "teacher_id": teacherId,
    }), 200

@jwt_required()
@admin_required
@app.route("/teachers/<teacherId>", methods=["DELETE"])
def delete_teacher(teacherId):
    # Code to delete a teacher
    if not delete(teacherId):
        return jsonify({
            "msg": "Could not delete teacher",
            "teacherId": teacherId
        }), 400
    return jsonify({
        "msg": "Successfully deleted teacher",
        "teacherId": teacherId
    }), 200

@app.route("/rooms", methods=["GET"])
def get_rooms():
    # Code to get all rooms
    return jsonify(db.execute("SELECT * FROM rooms")), 200

@app.route("/rooms/<roomId>", methods=["GET"])
def get_room(roomId):
    # Code to get a specific room
    return jsonify(db.execute("SELECT * FROM rooms WHERE room_number = ?", roomId)), 200

@app.route("/rooms", methods=["POST"])
def create_room():
    # Code to create a new room
    data = request.get_json()
    required_fields = ["room_number"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if db.execute("DELETE FROM rooms WHERE room_number = ?", data["room_number"]) != 0:
        return jsonify({
            "msg": "Room already exists",
            "room_number": data["room_number"]
        }), 400
    db.execute("INSERT INTO rooms (room_number, status) VALUES (?, ?)", data["room_number"], "free")
    return jsonify({'msg': "Created room",
                    "room_number" : data["room_number"]
    }), 200

@app.route("/rooms/<roomId>", methods=["PUT"])
def update_room(roomId):
    # Code to update a room
    # Update room state [free, used]
    data = request.get_json()
    required_fields = ["room_number", "status"]
    
    if not all(data.get(key) for key in required_fields):
        return jsonify({'msg': "Missing required fields"}), 400
    
    room_info = db.execute("SELECT * FROM rooms WHERE room_number = ?", roomId)
    if not any(room_info):
        return jsonify({'msg': "Room not found", 
                        "room_number": room_info['room_number']}), 404
    db.execute("UPDATE roomes SET status = ? WHERE room_number = ?", data['status'], room_info['room_number'])
    return jsonify({
        "msg": "Room status changed",
        "status": data['status'],
        "room_number": room_info['room_number']
    }), 200

@app.route("/rooms/<roomId>", methods=["DELETE"])
def delete_room(roomId):
    # Code to delete a room
    if not any(db.execute("SELECT * FROM class WHERE class_room = ?", roomId)) or not any(db.execute("SELECT * FROM schedule_table WHERE room = ?", roomId)):
        return jsonify({
            "msg": "Room could not be deleted",
            "room_id": roomId
        }), 400
    
    if db.execute("DELETE FROM rooms WHERE room_number = ?", roomId) == 0:
        return jsonify({
            "msg": "Room not found",
            "room_id": roomId
        }), 404
    return jsonify({
        "msg": "Successfully deleted room",
        "room_id": roomId
    }), 200

# ================================================================= # =================================================================
# Assignments for students and teachers

@app.route("/api/assignments/class/<username>", methods=["POST"])
def assign_student_to_class():
    data = request.get_json()

    required_fields = ["username", "classId"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    role = data["role"]
    user_id = db.execute("SELECT id FROM users WHER username = ?", data["username"])["id"]
    if role == "student":
        table = "student_to_class"
    elif role == "teacher":
        table == "teacher_to_class"
    else:
        return jsonify({"msg": "Invalid role", "role": role}), 400
    id_type = f"{role}_id"
    db.execute("DELETE FROM ? WHERE ? = ?", table, id_type, user_id)
    db.execute("INSERT INTO ? (?, class_id) VALUES (?, ?)", table, id_type, user_id, data["classId"])
    return jsonify({
        "msg": f"Assigned {role} to class",
        "classId": data["classId"],
        "username": data["username"]
    }), 200

@app.route("/api/assignments/subject/", methods=["POST"])
def assign_subject_to_teacher():
    data = request.get_json()

    required_fields = ["username", "subject"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if not any(db.execute("SELECT subject_name FROM subjects WHERE subject_name = ?", data["subject"])):
        return jsonify({
            "msg": "Subject does not exist in database",
            "subject": data["subject"]
        }), 404
    
    user_info = db.execute("SELECT * FROM users WHERE username = ?", data["username"])
    db.execute("INSERT INTO teacher_to_subject (teacher_id, subject_id) VALUES (?, ?)", user_info["id"], data["subject"])
    return jsonify({"msg": "Assigned teacher to subject",
                    "subject": data["subject"],
                    "username": data["username"]}), 200

# ================================================================= # =================================================================
#SCHEDULER
@app.route("/api/scheduler", methods=["POST"])
def create_schedule():
    data = request.get_json()

    required_fields = ["subject", "classId", "teacherId", "weekDay", "period", "room"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({
            "message": "Missing required fields",
        }), 400
    
    new_schedule_id = str(uuid.uuid4())
    db.execute(db.execute("INSERT INTO schedule_table (id, subject, class_id, teacher_id, week_day, room, period) VALUES (?,?,?,?,?,?,?)", new_schedule_id, data["subject"], data["classId"], data["teacherId"], data["weekDay"], data["room"], data["period"]))
    return jsonify({
        "msg": "Added schedule",
        "schedule": data
    }), 200

# Get all schedules
@app.route("/api/scheduler", methods=["GET"])
def get_schedules():
    return jsonify(db.execute("SELECT * FROM schedule_table")), 200

# Get all schedule for a given class
@app.route("/api/scheduler/<classId>", methods=["GET"])
def get_schedule_class(classId):
    return jsonify(db.execute("SELECT * FROM schedule_table WHERE class_id = ?", classId)), 200    

@app.route("/api/scheduler/<classId>", methods=["DELETE"])
def delete_schedule(classId):
    return


# ================================================================= # =================================================================#
@app.route("/api/constraints/", methods=["POST"])
def create_constraint():
    return

@app.route("/api/constraints/", methods=["GET"])
def get_constraints():
    return
if __name__ == "__main__":
    main()
