from fastapi import FastAPI

app = FastAPI()


@app.get("/")
# Dient zum Testen.
async def root():
    return {"message": "Hello World"}


@app.get("/classes")
# Liefert eine Liste aller Klassen.
async def listclasses():
    return {}


@app.get("/classes/{classId}")
# Liefert Informationen zu einer bestimmten Klasse.
async def getclass(classId):
    return {"Id": classId}


@app.post("/classes")
# Erstellt eine neue Klasse.
# Authentifizierung nötig
async def addclass():
    return {}


@app.put("/classes/{classId}")
# Aktualisiert eine bestehende Klasse.
# Authentifizierung nötig
async def updateclass(classId):
    return {"Id": classId}


@app.delete("/classes")
# Löscht eine bestehende Klasse.
# Authentifizierung nötig
async def deleteclass():
    return {}


@app.get("/teachers")
# Liefert eine Liste aller Lehrer.
async def listteacher():
    return {}


@app.get("/teachers/{teacherId}")
# Liefert Informationen zu einem bestimmten Lehrer.
async def getteacher(teacherId):
    return {"Id": teacherId}


@app.post("/teachers")
# Erstellt einen neuen Lehrer.
# Authentifizierung nötig
async def addteacher():
    return {}


@app.put("/teachers/{teacherId}")
# Aktualisiert einen bestehenden Lehrer.
# Authentifizierung nötig
async def updateteacher(teacherId):
    return {"Id": teacherId}


@app.delete("/teachers/{teacherId}")
# Löscht einen bestehenden Lehrer.
# Authentifizierung nötig
async def deleteteacher(teacherId):
    return {"Id": teacherId}


@app.get("/rooms")
# Liefert eine Liste aller Räume.
async def listrooms():
    return {}


@app.get("/rooms/{roomId}")
# Liefert Informationen zu einem bestimmten Raum.
async def getroom(roomId):
    return {"Id": roomId}


@app.post("/rooms")
# Erstellt einen neuen Raum.
# Authentifizierung nötig
async def addroom():
    return {}


@app.put("/rooms/{roomId}")
# Aktualisiert einen bestehenden Raum.
# Authentifizierung nötig
async def updateroom(roomId):
    return {"Id": roomId}


@app.delete("/rooms/{roomId}")
# Löscht einen bestehenden Raum.
# Authentifizierung nötig
async def deleteroom(roomId):
    return {"Id": roomId}


@app.get("/schedules")
# Liefert eine Liste aller Stundenpläne.
async def listschedules():
    return {}


@app.get("/schedules/{scheduleId}")
# Liefert Informationen zu einem bestimmten Stundenplan.
async def getschedule(scheduleId):
    return {"Id": scheduleId}


@app.post("/schedules")
# Erstellt einen neuen Stundenplan.
# Authentifizierung nötig
async def addschedule():
    return {}


@app.put("/schedules/{scheduleId}")
# Aktualisiert einen bestehenden Stundenplan.
# Authentifizierung nötig
async def updateschedule(scheduleId):
    return {"Id": scheduleId}


@app.delete("/schedules/{scheduleId}")
# Löscht einen bestehenden Stundenplan.
# Authentifizierung nötig
async def deleteschedule(scheduleId):
    return {"Id": scheduleId}