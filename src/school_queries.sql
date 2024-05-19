-- Creating the users table

CREATE TABLE IF NOT EXISTS users_cp (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    email TEXT NULL UNIQUE,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

-- Creating the teachers table

CREATE TABLE IF NOT EXISTS teachers (
    teacher_id TEXT PRIMARY KEY NOT NULL UNIQUE,
    name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    birth_date TEXT NOT NULL,
    FOREIGN KEY (teacher_id) REFERENCES users (id)
);

-- Creating students table

CREATE TABLE IF NOT EXISTS students (
    student_id TEXT PRIMARY KEY NOT NULL UNIQUE,
    name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    birth_date TEXT NOT NULL,
    FOREIGN KEY (student_id) REFERENCES users (id)
);

-- Creating subjects table

CREATE TABLE IF NOT EXISTS subjects (
    subject_name TEXT PRIMARY KEY NOT NULL,
    color TEXT NOT NULL,
    head_teacher_id TEXT NOT NULL,
    FOREIGN KEY (head_teacher_id) REFERENCES teachers (teacher_id)
);

-- Creating rooms table

CREATE TABLE IF NOT EXISTS rooms (
    room_number INTEGER PRIMARY KEY NOT NULL UNIQUE,
    status TEXT NOT NULL
);

-- Creating classes table

CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
    student_count INTEGER NOT NULL,
    class_room INTEGER NOT NULL,
    FOREIGN KEY (class_room) REFERENCES rooms (room_number)
);

-- Creating student_to_class table

CREATE TABLE IF NOT EXISTS student_to_class (
    student_id TEXT NOT NULL,
    class_id TEXT NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students (student_id),
    FOREIGN KEY (class_id) REFERENCES classes (id)
);

-- Creating schedules table

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    class_id TEXT NOT NULL,
    teacher_id TEXT NOT NULL,
    week_day TEXT NOT NULL,
    room INTEGER NOT NULL,
    FOREIGN KEY (room) REFERENCES rooms (room_number),
    FOREIGN KEY (class_id) REFERENCES classes (id),
    FOREIGN KEY (teacher_id) REFERENCES teachers (teacher_id),
    FOREIGN KEY (subject) REFERENCES subjects (subject_name)
);

-- Creating teacher_to_class table

CREATE TABLE IF NOT EXISTS teacher_to_class (
    class_id TEXT NOT NULL,
    teacher_id TEXT NOT NULL,
    FOREIGN KEY (class_id) REFERENCES classes (id),
    FOREIGN KEY (teacher_id) REFERENCES teachers (teacher_id)
);

-- Creating constraint_types

CREATE TABLE IF NOT EXISTS constraint_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    color TEXT NOT NULL,
    title TEXT NOT NULL
);

-- Creating constraints table

CREATE TABLE IF NOT EXISTS constraints (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    type INTEGER NOT NULL,
    FOREIGN KEY (type) REFERENCES constraint_types (id)
);

-- Creating teacher_to_subject table

CREATE TABLE IF NOT EXISTS teacher_to_subject (
    teacher_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    FOREIGN KEY (teacher_id) REFERENCES teachers (teacher_id),
    FOREIGN KEY (subject_id) REFERENCES subjects (subject_name)
);

ALTER TABLE users
ADD CONSTRAINT username_unqiueness UNIQUE (username);

CREATE TABLE IF NOT EXISTS schools (
    id PRIMARY KEY INTEGER UNIQUE AUTOINCREMENTS NOT NULL,
    title TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE
);