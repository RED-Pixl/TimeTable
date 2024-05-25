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
        
        result = db.execute("SELECT role FROM users WHERE username = ?", (current_user,))
        
        # Check if the result is empty
        if not result:
            return jsonify({"message": "User not found"}), 404
        
        # Check if the user has admin role
        if result[0]["role"] != ADMIN_ROLE:
            return jsonify({"message": "Admin access required"}), 403
        
        return fn(*args, **kwargs)
    
    return wrapper
# Custom decorator for teacher-only routes
def teacher_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        # Check if user has teacher role
        result = db.execute("SELECT role FROM users WHERE username = ?", current_user)
        # Check if the result is empty
        if not result:
            return jsonify({"message": "User not found"}), 404
        
        # Check if the user has teacher or admin role
        if result[0]["role"] != ADMIN_ROLE or result[0]["role"] != TEACHER_ROLE:
            return jsonify({"message": "Teacher access required"}), 403
        
        return fn(*args, **kwargs)
    return wrapper

# Custom decorator for student-only routes
def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        # Check if user has student role
        result = db.execute("SELECT role FROM users WHERE username = ?", current_user)

        # Check if the result is empty
        if not result:
            return jsonify({"message": "User not found"}), 404
        
        # Check for student role
        if result[0]["role"] == ADMIN_ROLE or result[0]["role"] == TEACHER_ROLE or result[0]["role"] == STUDENT_ROLE:
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

    required_fields = ["username", "role", "password", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
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
        id_type = "student_id"
    elif data["role"] == "teacher":
        table = "teachers"
        id_type = "teacher_id"
    else:
        return jsonify({"message": "Invalid role"}), 400
    
    new_user_id = str(uuid.uuid4())
    db.execute("INSERT INTO users (id, username, role, password_hash, email) VALUES (?, ?, ?, ?, ?)", new_user_id, data["username"], data["role"], bcrypt.generate_password_hash(data["password"]).decode('utf-8'), None)
    db.execute(f"INSERT INTO { table } ({id_type} , name, last_name, birth_date) VALUES (?, ?, ?, ?)", new_user_id, data["name"], data["last_name"], data["birth_date"])
    
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
    if bcrypt.check_password_hash(user_info["password_hash"], data["password"]):       
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
    query = request.args.get("q", "")
    if not query:
        return jsonify(db.execute("SELECT * FROM schools")), 200
    else:
        return jsonify(db.execute("SELECT * FROM schools WHERE school LIKE ? COLLATE NOCASE", f"%{query}%")), 200
# Endpoints for students

# ================================================================= # ================================================================= #

def check_assignment_class(id_, role):
    if role == TEACHER_ROLE:
        table = "teacher_to_class"
        id_type = "teacher_id"
    elif role == STUDENT_ROLE:
        table = "student_to_class"
        id_type = "student_id"
    else:
        return False
    
    if not any(db.execute(f"SELECT * FROM {table} WHERE {id_type} = ?", id_)):
        return False
    return True

def capitalize_and_clean(s: str):
    words = s.split()
    capitalized_words = ' '.join(word.lower().capitalize() for word in words)
    return capitalized_words

@app.route("/api/student", methods=["GET"])
def get_student():
    search_term = request.args.get("s", "")
    if not search_term:
        # Code to get all students
        results = []
        students = db.execute("SELECT * FROM students")

        for student in students:
            class_id = db.execute("SELECT class_id FROM student_to_class WHERE student_id = ?", student["student_id"])
            if not class_id:
                class_id = None
            else:
                class_id = class_id[0]["class_id"]
            
            results.append({
                "personalInformation": student,
                "classId": class_id
            })

        return jsonify(results), 200
    else: 
        search_term = capitalize_and_clean(search_term)
        # Code to get a specific students from name
        pattern = f"%{search_term}%"
        students = db.execute("""
        SELECT student_id, name, last_name 
        FROM students 
        WHERE name LIKE ? 
        OR last_name LIKE ? 
        OR (name || ' ' || last_name) LIKE ?
        """, pattern, pattern, pattern)

        results = []
        for student in students:
            class_id = db.execute("SELECT class_id FROM student_to_class WHERE student_id = ?", student["student_id"])
            if not class_id:
                class_id = None
                schedule = None
            else:
                class_id = class_id[0]
                schedule = db.execute("SELECT * FROM schedules WHERE class_id = ?", class_id)
                if not schedule:
                    schedule = None
            results.append({
                "personalInformation": student,
                "schoolInformation": {
                    "class": class_id,
                    "schedule": schedule
                }
            })

        return jsonify(results), 200

# /api/register is better 


@app.route("/api/student", methods=["POST"])
def create_student():
    return jsonify({"message": "This path is not in use anymore. Use /api/register instead."}), 404

#TODO: FIGURE OUT WHAT THE UPDATES ARE
@app.route("/api/student", methods=["PUT"])
def update_student_personal():
    # Code to update a student
    data = request.get_json()

    required_fields = ["studentId", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if db.execute("UPDATE students SET name = ?, last_name = ?, birth_date = ? WHERE student_id = ?", data["name"], data["last_name"], data["birth_date"], data["studentId"]) == 0:
        return jsonify({"message": "Teacher not found"}), 404
    
    return jsonify({
        "message": "Successfully updated teacher information",
        "teacherId": data["teacher_id"],
        "personalInformation": db.execute("SELECT * FROM students WHERE student_id = ?", data["teacherId"])[0]
    }) 

# ================================================================= # ================================================================= #
"""
Delete helper function for student and teacher
"""
def delete_student(id: str):
    # Code to get a specific students from name
    student = db.execute("SELECT * FROM students WHERE student_id = ?", id)
    if not student:
        return False
    student = student[0]

    # Update the classes
    class_id = db.execute("SELECT * FROM student_to_class WHERE student_id = ?", student["student_id"])
    if class_id:
        class_id = class_id[0]
        db.execute("UPDATE classes SET student_count = student_count - 1 WHERE id = ?", class_id)


    # DELETE FUNCTIONS DANGER!!!!!
    db.execute("DELETE FROM student WHERE student_id = ?", student["student_id"])
    db.execute("DELETE FROM student_to_class WHERE student_id = ?", student["student_id"])
    db.execute("DELETE FROM users WHERE id = ?", student["student_id"])
    return True

def delete_teacher(id: str):
    teacher = db.execute("DELETE FROM teachers WHERE teacher_id = ?", id)
    if not teacher:
        return False
    teacher = teacher[0]
    has_assosiation = (
        db.execute("SELECT * FROM teacher_to_class WHERE teacher_id = ?", teacher["teacher_id"]) or
        db.execute("SELECT * FROM subjects WHERE head_teacher_id = ?", teacher["teacher_id"]) or
        db.execute("SELECT * FROM schedules WHERE teacher_id = ?", teacher["teacher_id"])
    )

    if has_assosiation:
        return False
    
    # DELETE FUNCTIONS DANGER!!!!
    db.execute("DELETE FROM teacher_to_subject WHERE teacher_id = ?", teacher["teacher_id"])
    db.execute("DELETE FROM teacher_to_class WHERE teacher_id = ?", teacher["teacher"])
    db.execute("DELETE FROM taechers WHERE teacher_id = ?", teacher["teacher"])
    db.execute("DELETE FROM users WHERE id = ?", teacher["teacher_id"])
    return True
# ================================================================= # =================================================================


@app.route("/api/student", methods=["DELETE"])
def delete_student():
    # Code to delete a student
    studentId = request.args.get("s", "")
    if not studentId:
        return jsonify({
            "message": "Student not found, Query has to be specified"
        }), 404
    
    if not delete_student(studentId):
        return jsonify({
            "message": "Something went wrong, could not delete student",
            "studentId": studentId,
        }), 400
    return jsonify({
        "message": "Student has been deleted",
        "studentId": studentId
    }), 200

# ================================================================= # =================================================================
# Endpoints for classes

@app.route("/api/classes", methods=["GET"])
def get_class():
    # Code to get a specific class
    # class information and student list (name, last name)
    query = request.args.get("q", "")
    if not query:
        # Code to get all classes
        results = []
        classes = db.execute("SELECT * FROM classes")
        for class_sg in classes:
            head_teacher = db.execute("SELECT * FROM teacher_to_class WHERE class_id = ?", class_sg["id"])
            if not head_teacher:
                head_teacher = None
            else:
                head_teacher = head_teacher[0]
            
            results.append({
                "classId": class_sg["id"],
                "headTeacher": head_teacher,
                "studentCount": class_sg["student_count"],
                "classRoom": class_sg["class_room"],
            })
        return jsonify(results), 200
    else: 
        class_information = db.execute("SELECT * FROM classes WHERE id = ?", query)
        student_list = db.execute("SELECT name, last_name FROM students WHERE student_id = (SELECT student_id FROM student_to_class WHERE class_id = ?)", query)

        information = {
            "class_information": class_information,
            "student_list": student_list
        }
        return jsonify(information)

# ================================================================= # ================================================================= #
def check_uniqueness_class(id_, class_room, head_teacher_id):
    id_result = db.execute("SELECT * FROM classes WHERE id = ?", id_)
    class_result = db.execute("SELECT * FROM classes WHERE class_room = ?", class_room)
    rooms_result = db.execute("SELECT * FROM rooms WHERE room_number = ?", class_room)
    teacher_result = db.execute("SELECT * FROM teacher_to_class WHERe teacher_id = ?", head_teacher_id)
    if not id_result or not class_result or not rooms_result or not teacher_result:
        return True
    else:
        return False

# ================================================================= # ================================================================== #

@app.route("/api/classes", methods=["POST"])
def create_class():
    # Code to create a new class
    data = request.get_json()

    required_fields = ["classId", "classRoom", "headTeacherId"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if not check_uniqueness_class(data["classId"], data["classRoom"], head):
        return jsonify({
        "message": "Could not create class because class already exists or classroom is already in use or head_teacher already in use.",
            "classId": data["classId"],
            "classRoom": data["classRoom"]
        }), 400
    
    # Insert the class into the database
    db.execute("INSERT INTO classes (id, student_count, class_room) VALUES (?, ?, ?)",
               data["classId"], 0, data["classRoom"])
    
    return jsonify({
        "message": "Successfully created a new class.",
        "classId": data["classId"],
        "classRoom": data["classRoom"],
        "studentCount": 0
    }), 200

@app.route("/api/classes", methods=["PUT"])
def update_class():
    # Code to update a class
    # You can only update a class' classroom. Student Count gets updated automatically every time a student is added
    data = request.get_json()
    required_fields = ["classId", "classRoom"]

    if not all(data.get(key) for key in required_fields):
        return jsonify({"message": "Missing required fields"}), 400
    
    classId = data["classId"]
    class_room = data["classRoom"]

    has_association = (
        db.execute("SELECT * FROM classes WHERE class_room = ?", class_room)
        )
    if has_association:
        return jsonify({"message": "Could not update classroom. Please remove associations first."}), 400
    
    return jsonify({
        "message": "Successfully updated class!",
        "classId": classId
    }), 200



@app.route("/api/classes", methods=["DELETE"])
def delete_class():
    # Code to delete a class
    query = request.args.get("q", "")
    if not query:
        return jsonify({"message": "Class not found, Query has to be given"}), 404
    else: 
        if any(db.execute("SELECT * FROM student_to_class WHERE class_id = ?", query)):
            return jsonify({
                "message": "Could not delete a class. Class still in use. Please try again",
                "classId": query
            }), 400
        db.execute("DELETE FROM classes WHERE id  = ?", query)
        return jsonify({
            "message": "Class was deleted",
            "classId": query
        }), 200

# ================================================================= # =================================================================
# Endpoints for teachers
@app.route("/api/teacher", methods=["GET"])
def get_teacher():
    teacherId = request.args.get("q", "")
    if not teacherId:    
        # Code to get all teachers
        return jsonify(db.execute("SELECT * FROM teachers")), 200
    else:
        # Code to get a specific teacher        
        search_term = capitalize_and_clean(teacherId)
        pattern = f"%{search_term}%"
        teachers = db.execute("""
        SELECT teacher_id, name, last_name 
        FROM teachers 
        WHERE name LIKE ? 
        OR last_name LIKE ? 
        OR (name || ' ' || last_name) LIKE ?
        """, pattern, pattern, pattern)

        results = []
        for teacher in teachers:
            schedule = db.execute("SELECT * FROM schedules WHERE teacher_id = ?", teacher["teacher_id"])
            if not schedule:
                schedule = None
            head_teacher_of = db.execute("SELECT * FROM teacher_to_class WHERE teacher_id = ?", teacher["teacher_id"])
            if not head_teacher_of:
                head_teacher_of = None
            else:
                head_teacher_of = head_teacher_of[0]["id"]
            subjects = db.execute("SELECT * FROM teacher_to_subject WHERE teacher_id = ?", teacher["teacher_id"])
            if not subjects:
                subjects = None
            
            results.append({
                "personalInformation": teacher,
                "schoolInformation": {
                    "subjects": subjects,
                    "headTeacherOf": head_teacher_of,
                    "schedule": schedule
                }
            })

        return jsonify(results), 200



@app.route("/api/teacher", methods=["POST"])
def create_teacher():
    # Code to create a new teacher
    return jsonify({
        "message": "This route is not supported anymore. Please use the /api/register route instead.",
    }), 404

@app.route("/api/teacher", methods=["PUT"])
def update_teacher_personal():
    # Code to update a teacher
    data = request.get_json()

    required_fields = ["teacherId", "name", "last_name", "birth_date"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if db.execute("UPDATE teachers SET name = ?, last_name = ?, birth_date = ? WHERE teacher_id = ?", data["name"], data["last_name"], data["birth_date"], data["teacherId"]) == 0:
        return jsonify({"message": "Teacher not found"}), 404
    
    return jsonify({
        "message": "Successfully updated teacher information",
        "teacherId": data["teacherId"],
        "personalInformation": db.execute("SELECT * FROM teachers WHERE teacher_id = ?", data["teacherId"])[0]
    }) 

@app.route("/api/teacher", methods=["DELETE"])
def delete_teacher():
    # Code to delete a teacher
    teacherId = request.args.get("q", "")
    if not teacherId:
        return jsonify({
            "message": "Teacher has to be specified"
        }), 400
    if not delete_teacher(teacherId):
        return jsonify({
            "message": "Could not delete teacher",
            "teacherId": teacherId
        }), 400
    return jsonify({
        "message": "Successfully deleted teacher",
        "teacherId": teacherId
    }), 200

@app.route("/api/rooms", methods=["GET"])
def get_rooms():
    # Code to get all rooms
    return jsonify(db.execute("SELECT * FROM rooms")), 200

@app.route("/api/rooms", methods=["GET"])
def get_room(roomId):
    roomId = request.args.get("q", "")
    if not roomId:
        # Code to get all rooms
        return jsonify(db.execute("SELECT * FROM rooms")), 200
    # Code to get a specific room
    return jsonify(db.execute("SELECT * FROM rooms WHERE room_number = ?", roomId)), 200

@app.route("/api/rooms", methods=["POST"])
def create_room():
    # Code to create a new room
    data = request.get_json()
    required_fields = ["roomNumber"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if db.execute("DELETE FROM rooms WHERE room_number = ?", data["roomNumber"]) != 0:
        return jsonify({
            "message": "Room already exists",
            "room_number": data["roomNumber"]
        }), 400
    db.execute("INSERT INTO rooms (room_number, status) VALUES (?, ?)", data["roomNumber"], "free")
    return jsonify({'message': "Created room",
                    "room_number" : data["roomNumber"],
                    "status": "free"
    }), 200

@app.route("/api/rooms", methods=["PUT"])
def update_room():
    # Code to update a room
    # Update room state [free, used]
    roomId = request.args.get("q", "")
    if not roomId:
        return jsonify({"message": "'roomNumber' has to be specified", "roomId": roomId})
    
    room_info = db.execute("SELECT * FROM rooms WHERE room_number = ?", roomId)
    if not room_info:
        return jsonify({'message': "Room not found", "roomNumber": roomId}), 404
    
    if not room_info:
        return jsonify({'message': "Room not found", 
                        "room_number": roomId}), 404
    
    room_info = room_info[0]
    if room_info["status"] == "free":
        status = "used"
        db.execute("UPDATE rooms SET status = ? WHERE room_number = ?", status, room_info['room_number'])
    elif room_info["status"] == "used":
        status = "free"
        db.execute("UPDATE rooms SET status = ? WHERE room_number = ?", status, room_info["room_number"])
    return jsonify({
        "message": "Room status changed",
        "status": status,
        "room_number": room_info['room_number']
    }), 200

@app.route("/api/rooms", methods=["DELETE"])
def delete_room():
    # Code to delete a room
    roomId = request.args.get("q", "")
    if not roomId:
        return jsonify({
            "message": "Room must be specified",
            "roomId": roomId
        }), 400
    if any(db.execute("SELECT * FROM classes WHERE class_room = ?", roomId)) or any(db.execute("SELECT * FROM schedules WHERE room = ?", roomId)):
        return jsonify({
            "message": "Room could not be deleted",
            "room_id": roomId
        }), 400
    
    if db.execute("DELETE FROM rooms WHERE room_number = ?", roomId) == 0:
        return jsonify({
            "message": "Room not found",
            "room_id": roomId
        }), 404
    return jsonify({
        "message": "Successfully deleted room",
        "room_id": roomId
    }), 200

# ================================================================= # =================================================================
# Assignments for students and teachers

@app.route("/api/assignments/class", methods=["POST"])
def assign_user_to_class():
    data = request.get_json()

    required_fields = ["userId", "classId"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    # Check if user exists
    user_info = db.execute("SELECT * FROM users WHERE id = ?", data["userId"])
    if not user_info:
        return jsonify({'message': "User not found", "user": data["userId"]}), 404
    
    user_info = user_info[0]

    # Check if class exists
    if not db.execute("SELECT * FROM classes WHERE id = ?", data["classId"]):
        return jsonify({"message": "Class not found", "classId": data["classId"]}), 404
    

    role = user_info["role"]
    if role == "student":
        table = "student_to_class"
    elif role == "teacher":
        table == "teacher_to_class"
    else:
        return jsonify({"message": "Invalid role", "role": role}), 400
    
    id_type = f"{role}_id"
    user_before = db.execute(f"SELECT * FROM {table} WHERE {id_type} = ?", data["userId"])
    if user_before:
        db.execute("UPDATE classes SET student_count = student_count - ? WHERE id = ?", 1, user_before[0]["class_id"])
    db.execute(f"DELETE FROM {table} WHERE {id_type} = ?", user_info["id"])
    db.execute(f"INSERT INTO {table} ({id_type}, class_id) VALUES (?, ?)", user_info["id"], data["classId"])
    db.execute(f"UPDATE classes SET student_count = student_count + ? WHERE id = ?", 1, data["classId"])
    return jsonify({
        "message": f"Assigned {role} to class",
        "classId": data["classId"],
        "userId": data["userId"]
    }), 200

@app.route("/api/assignments/subject/", methods=["POST"])
def assign_subject_to_teacher():
    data = request.get_json()

    required_fields = ["teacherId", "subject"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({'message': "Missing required fields"}), 400
    
    if not any(db.execute("SELECT subject_name FROM subjects WHERE subject_name = ?", data["subject"])):
        return jsonify({
            "message": "Subject does not exist in database",
            "subject": data["subject"]
        }), 404
    
    user_info = db.execute("SELECT * FROM teachers WHERE teacher_id = ?", data["teacher"])
    if not user_info:
        return jsonify({'message': "Teacher does not exist"}), 404
    user_info = user_info[0]
    db.execute("INSERT INTO teacher_to_subject (teacher_id, subject_id) VALUES (?, ?)", user_info["teacher_id"], data["subject"])
    return jsonify({"message": "Assigned teacher to subject",
                    "subject": data["subject"],
                    "username": data["teacher_id"]}), 200

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
    
    # Check if the room is free on the given period and if room exists
    if db.execute("SELECT * FROM schedules WHERE room = ? AND period = ?", data["room"], data["period"]) or not db.execute("SELECT * FROM rooms WHERE room_number = ?", data["room"]):
        return jsonify({"message": "Room is not free on the given period or does not exists"}), 404
    
    # check if subject exists and teacher teaches the given subject
    if not db.execute("SELECT * FROM subjects WHERE subject_name = ?", data["subject"]):
        return jsonify({"message": "Subject does not exist"}), 404
    if not db.execute("SELECT * FROM teacher_to_subject WHERE teacher_id = ? AND subject_id = ?", data["teacherId"], data["subject"]):
        return jsonify({"message": "Teacher does not teach the given subject", "subject": data["subject"], "teacherId": data["teacherId"]})
    
    # check if teacher exists and if teacher is free on the given period
    if not db.execute("SELECT * FROM teachers WHERe teacher_id = ?", data["teacherId"]):
        return jsonify({"message": "Teacher does not exist"}), 404
    if db.execute("SELECT * FROM schedules WHERE teacher_id = ? AND period = ?", data["teacherId"], data["period"]):
        return jsonify({"message": "Teacher is not free on the given period", "period": data["period"]}), 400
    
    # check if weekDay is valid
    VALID_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri"]
    if not data["weekDay"] in VALID_WEEKDAYS:
        return jsonify({"message": "Weekday is not valid", "weekDay": data["weekDay"]}), 400
    
    # check if classId exists and if classId is free on the given period
    if db.execute("SELECT * FROM schedules WHERE class_id = ?", data["classId"]):
        return jsonify({"message": "ClassId is not free on the given period", "classId": data["classId"]}), 400
    
    new_schedule_id = str(uuid.uuid4())
    # INSERT NEW SCHEDULE
    db.execute("INSERT INTO schedules (id, subject, class_id, teacher_id, week_day, room, period) VALUES (?, ?, ?, ?, ?, ?, ?)", new_schedule_id, data["subject"], data["classId"], data["teacherId"], data["weekDay"], data["room"], data["period"])
    return jsonify({
        "message": "Added schedule",
        "scheduleData": data
    }), 200

# Get all schedule for a given class
@app.route("/api/scheduler", methods=["GET"])
def get_schedule_class(classId):
    query = request.args.get("q", "")
    if not query:
        return jsonify(db.execute("SELECT * FROM schedules")), 200
    return jsonify(db.execute("SELECT * FROM schedules WHERE class_id = ?", classId)), 200    

@app.route("/api/scheduler", methods=["DELETE"])
def delete_schedule(classId):
    # Check if class is valid in schedule table
    query = request.args.get("q", "")
    if not query:
        return jsonify({"message": "ClassId has to be specified"}), 400
    
    if not db.execute("SELECT * FROM schedules WHERE class_id = ?", classId):
        return jsonify({
            "message": "Class not found",
        }), 404
    
    num_deleted = db.execute("DELETE FROM schedules WHERE class_id = ?", classId)

    return jsonify({
        "message": "Successfully deleted schedule",
        "classId": classId,
        "numDeleted": num_deleted
    }), 200


# ================================================================= # =================================================================#
# Creating constraints
#TODO: Implement WORK IN PROGRESS

def add_constraint_type(data):
    return

def generate_constraints(data):
    return
# generate constraints for all classes on date where specific teacher is not available
@app.route("/api/constraints", methods=["POST"])
def create_constraints():
    return

@app.route("/api/constraints", methods=["GET"])
def get_constraints():
    query = request.args.get("q", "")
    if not query:
        return jsonify(db.execute("SELECT * FROM constraints"))
    else:
        # By date or by title or by teacher. Changing the database would be much easier in this situation
        return
# ================================================================= # ================================================================= #
# Subject paths

@app.route("/api/subjects", methods=["GET"])
def get_subjects():
    query = request.args.get("q", "")
    if query:
        return jsonify(db.execute("SELECT * FROM subjects WHERE subject_name LIKE ?", f"%{query}%"))
    else:
        return jsonify(db.execute("SELECT * FROM subjects"))

@app.route("/api/subjects", methods=["POST"])
def add_subject():
    data = request.get_json()

    required_fields = ["subjectName", "headTeacherId", "color"]
    if not all(data.get(key) for key in required_fields):
        return jsonify({"message": "Missing required fields", "data": data}), 400
    
    # Check if subject already exists
    if db.execute("SELECT * FROM subjects WHERE subject_name = ?", data["subjectName"]):
        return jsonify({"message": "Subject already exists", "data": data}), 400
    
    # Check if headTeacherId exists and not in use yet
    if db.execute("SELECT * FROM subjects WHERE head_teacher_id = ?", data["headTeacherId"]) or db.execute("SELECT * FROM teachers WHERE teacher_id = ?", data["headTeacherId"]):
        return jsonify({"message": "Teacher does not exist or teacher already a head teacher", "data": data}), 400
    
    # Check if color is valid hex code
    try:
        int(data["color"], 16)
    except ValueError:
        return jsonify({"message": "Color is not a valid hex code", "data": data}), 400
    
    db.execute("INSERT INTO subjects (subject_name, color, head_teacher_id) VALUES (?,?,?)", data["subjectName"], data["color"], data["headTeacherId"])
    return jsonify({"message": "Successfully added subject", "data": data}), 200

@app.route("/api/subjects", methods=["DELETE"])
def delete_subject():
    subject_name = request.args.get("q", "")

    if not subject_name:
        return jsonify({"Subject has to be specified"}), 400
    
    has_associations = (
        db.execute("SELECT * FROM schedule_table WHERE subject = ?", subject_name)
    )

    if has_associations:
        return jsonify({"message": "Associations have to be removed before deletion"}), 400
    
    # DELETE FUNCTIONS DANGER!!!!!!!!!!
    db.execute("DELETE FROM teacher_to_subject WHERE subject_id = ?", subject_name)
    db.execute("DELETE FROM subjects WHERE subject_name = ?", subject_name)
    return jsonify({"message": "Successfully deleted subject"})

@app.route("/api/profile", methods=["PUT"])
def update_profile():
    
    return
if __name__ == "__main__":
    main()


