from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class Class(BaseModel):
    id: str
    name: str


class Teacher(BaseModel):
    id: str
    name: str
    surename: str
    subjects: {}


class Room(BaseModel):
    id: int
    name: int


class Schedule(BaseModel):
    id: int
    classes: {}


@app.get("/")
# Dient zum Testen.
async def root():
    return {"message": "Hello World"}


@app.get("/classes")
# Liefert eine Liste aller Klassen.
async def list_class():
    return {}


@app.get("/classes/{class_id}")
# Liefert Informationen zu einer bestimmten Klasse.
async def get_class(class_id: str):
    return {"Id": class_id}


@app.post("/classes")
# Erstellt eine neue Klasse.
# Authentifizierung nötig
async def add_class(new_class: Class):
    return {}


@app.put("/classes/{class_id}")
# Aktualisiert eine bestehende Klasse.
# Authentifizierung nötig
async def update_class(class_id: str, new_class: Class):
    return {"Id": class_id}


@app.delete("/classes/{class_id}")
# Löscht eine bestehende Klasse.
# Authentifizierung nötig
async def delete_class(class_id: str):
    return {"Id": class_id}


@app.get("/teachers")
# Liefert eine Liste aller Lehrer.
async def list_teacher():
    return {}


@app.get("/teachers/{teacher_id}")
# Liefert Informationen zu einem bestimmten Lehrer.
async def get_teacher(teacher_id: str):
    return {"Id": teacher_id}


@app.post("/teachers")
# Erstellt einen neuen Lehrer.
# Authentifizierung nötig
async def add_teacher(new_teacher: Teacher):
    return {}


@app.put("/teachers/{teacher_id}")
# Aktualisiert einen bestehenden Lehrer.
# Authentifizierung nötig
async def update_teacher(teacher_id: str, new_teacher: Teacher):
    return {"Id": teacher_id}


@app.delete("/teachers/{teacher_id}")
# Löscht einen bestehenden Lehrer.
# Authentifizierung nötig
async def delete_teacher(teacher_id: str):
    return {"Id": teacher_id}


@app.get("/rooms")
# Liefert eine Liste aller Räume.
async def list_room():
    return {}


@app.get("/rooms/{room_id}")
# Liefert Informationen zu einem bestimmten Raum.
async def get_room(room_id: int):
    return {"Id": room_id}


@app.post("/rooms")
# Erstellt einen neuen Raum.
# Authentifizierung nötig
async def add_room(new_room: Room):
    return {}


@app.put("/rooms/{room_id}")
# Aktualisiert einen bestehenden Raum.
# Authentifizierung nötig
async def update_room(room_id: int, new_room: Room):
    return {"Id": room_id}


@app.delete("/rooms/{room_id}")
# Löscht einen bestehenden Raum.
# Authentifizierung nötig
async def delete_room(room_id: int):
    return {"Id": room_id}


@app.get("/schedules")
# Liefert eine Liste aller Stundenpläne.
async def list_schedule():
    return {}


@app.get("/schedules/{schedule_id}")
# Liefert Informationen zu einem bestimmten Stundenplan.
async def get_schedule(schedule_id: int):
    return {"Id": schedule_id}


@app.post("/schedules")
# Erstellt einen neuen Stundenplan.
# Authentifizierung nötig
async def add_schedule(new_schedule: Schedule):
    return {}


@app.put("/schedules/{schedule_id}")
# Aktualisiert einen bestehenden Stundenplan.
# Authentifizierung nötig
async def update_schedule(schedule_id: int, new_schedule: Schedule):
    return {"Id": schedule_id}


@app.delete("/schedules/{schedule_id}")
# Löscht einen bestehenden Stundenplan.
# Authentifizierung nötig
async def delete_schedule(schedule_id: int):
    return {"Id": schedule_id}
