import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User, Patient, Doctor, Appointment, Disease, Report, Prescription

app = FastAPI(title="HEALNEX API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Utilities --------------------

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def issue_token(user_id: str, role: str) -> str:
    token = secrets.token_hex(32)
    session = {
        "user_id": user_id,
        "role": role,
        "token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
    db["session"].insert_one(session)
    return token


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return db["user"].find_one({"email": email})


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # patient | doctor | admin
    # Optional profile fields
    age: Optional[int] = None
    gender: Optional[str] = None
    blood_group: Optional[str] = None
    specialization: Optional[str] = None
    license_no: Optional[str] = None


class LoginBody(BaseModel):
    email: EmailStr
    password: str


# -------------------- Health & Root --------------------

@app.get("/")
def read_root():
    return {"message": "HEALNEX Backend is live"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", "✅ Connected")
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:20]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# -------------------- Schemas Endpoint --------------------

@app.get("/schema")
def get_schema_definitions():
    # Return basic metadata about collections
    return {
        "user": User.__annotations__,
        "patient": Patient.__annotations__,
        "doctor": Doctor.__annotations__,
        "appointment": Appointment.__annotations__,
        "disease": Disease.__annotations__,
        "report": Report.__annotations__,
        "prescription": Prescription.__annotations__,
    }


# -------------------- Auth Endpoints --------------------

@app.post("/auth/register")
def register(body: RegisterBody):
    # Enforce unique email
    if get_user_by_email(body.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    role = body.role.lower().strip()
    if role not in {"patient", "doctor", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")

    user_data = User(
        name=body.name,
        email=body.email,
        role=role,
        password_hash=sha256_hash(body.password),
        is_active=True,
    )
    user_id = create_document("user", user_data)

    # Create role profile
    if role == "patient":
        patient = Patient(
            user_id=user_id,
            age=body.age,
            gender=body.gender,
            blood_group=body.blood_group,
            notes=None,
        )
        create_document("patient", patient)
    elif role == "doctor":
        doctor = Doctor(
            user_id=user_id,
            specialization=body.specialization,
            license_no=body.license_no,
            about=None,
        )
        create_document("doctor", doctor)

    token = issue_token(user_id, role)
    return {"token": token, "user_id": user_id, "role": role}


@app.post("/auth/login")
def login(body: LoginBody):
    user = get_user_by_email(body.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("password_hash") != sha256_hash(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = issue_token(str(user["_id"]), user.get("role", "patient"))
    return {"token": token, "user_id": str(user["_id"]), "role": user.get("role")}


def get_current_session(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ")[-1]
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    # Check expiry
    expires_at = session.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except Exception:
            expires_at = None
    if expires_at and datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=401, detail="Token expired")
    return session


@app.get("/auth/me")
def me(session: Dict[str, Any] = Depends(get_current_session)):
    user = get_user_by_id(session["user_id"]) or {}
    if user:
        user["_id"] = str(user["_id"])  # make serializable
        user.pop("password_hash", None)
    return {"session": {"role": session.get("role"), "user_id": session.get("user_id")}, "user": user}


# -------------------- Disease Knowledge Base --------------------

class DiseaseCreate(BaseModel):
    name: str
    symptoms: List[str] = []
    causes: List[str] = []
    prevention: List[str] = []
    treatments: List[str] = []
    severity: Optional[str] = None


@app.post("/diseases")
def create_disease(data: DiseaseCreate, session: Dict[str, Any] = Depends(get_current_session)):
    if session.get("role") not in {"doctor", "admin"}:
        raise HTTPException(status_code=403, detail="Only doctors or admins can add diseases")
    disease_id = create_document("disease", Disease(**data.model_dump()))
    return {"id": disease_id}


@app.get("/diseases")
def list_diseases(q: Optional[str] = None, limit: int = 50):
    flt = {}
    if q:
        # Basic case-insensitive name match
        flt = {"name": {"$regex": q, "$options": "i"}}
    items = get_documents("disease", flt, limit)
    for it in items:
        it["_id"] = str(it["_id"])  # serialize
    return {"items": items}


# -------------------- Appointments --------------------

class AppointmentCreate(BaseModel):
    patient_id: str
    doctor_id: str
    scheduled_at: str
    reason: Optional[str] = None


@app.post("/appointments")
def create_appointment(data: AppointmentCreate, session: Dict[str, Any] = Depends(get_current_session)):
    role = session.get("role")
    if role not in {"patient", "doctor", "admin"}:
        raise HTTPException(status_code=403, detail="Unauthorized")
    appt_id = create_document("appointment", Appointment(**data.model_dump(), status="pending"))
    return {"id": appt_id}


@app.get("/appointments")
def list_appointments(session: Dict[str, Any] = Depends(get_current_session)):
    role = session.get("role")
    user_id = session.get("user_id")
    flt = {}
    if role == "patient":
        flt = {"patient_id": user_id}
    elif role == "doctor":
        flt = {"doctor_id": user_id}
    items = get_documents("appointment", flt)
    for it in items:
        it["_id"] = str(it["_id"])  # serialize
    return {"items": items}


# -------------------- File Uploads (PDF Reports) --------------------

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/uploads/report")
def upload_report(
    patient_id: str = Form(...),
    title: str = Form(...),
    file: UploadFile = File(...),
    session: Dict[str, Any] = Depends(get_current_session),
):
    if session.get("role") not in {"patient", "doctor", "admin"}:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    # Save to disk
    filename = f"report_{secrets.token_hex(8)}.pdf"
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "wb") as f:
        f.write(file.file.read())

    report = Report(patient_id=patient_id, title=title, file_path=dest, mime_type=file.content_type)
    report_id = create_document("report", report)
    return {"id": report_id, "file": filename}


@app.get("/uploads/report/{filename}")
def get_report_file(filename: str):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(filepath, media_type="application/pdf")


# -------------------- Prescriptions --------------------

class PrescriptionCreate(BaseModel):
    patient_id: str
    content: str


@app.post("/prescriptions")
def create_prescription(data: PrescriptionCreate, session: Dict[str, Any] = Depends(get_current_session)):
    if session.get("role") not in {"doctor", "admin"}:
        raise HTTPException(status_code=403, detail="Only doctors or admins can write prescriptions")
    presc = Prescription(patient_id=data.patient_id, doctor_id=session.get("user_id"), content=data.content, file_path=None)
    presc_id = create_document("prescription", presc)
    return {"id": presc_id}


@app.get("/prescriptions")
def list_prescriptions(session: Dict[str, Any] = Depends(get_current_session)):
    role = session.get("role")
    flt = {}
    if role == "doctor":
        flt = {"doctor_id": session.get("user_id")}
    if role == "patient":
        flt = {"patient_id": session.get("user_id")}
    items = get_documents("prescription", flt)
    for it in items:
        it["_id"] = str(it["_id"])  # serialize
    return {"items": items}


# -------------------- AI Chat (simple rules) --------------------

class ChatMessage(BaseModel):
    message: str


@app.post("/ai/chat")
def ai_chat(msg: ChatMessage):
    text = msg.message.lower()
    # very basic matcher using disease collection
    suggestions: List[str] = []
    try:
        cursor = db["disease"].find({"symptoms": {"$elemMatch": {"$regex": text, "$options": "i"}}}).limit(5)
        for d in cursor:
            suggestions.append(d.get("name"))
    except Exception:
        pass

    if "appointment" in text:
        reply = "To schedule an appointment, please go to the Appointments section and choose a doctor and time."
    elif "headache" in text or "fever" in text:
        reply = "Common causes include dehydration or viral infections. Rest, hydrate, and consult a doctor if symptoms persist."
    elif suggestions:
        reply = f"Potential related conditions: {', '.join(suggestions)}. Please consult a doctor for proper diagnosis."
    else:
        reply = "I'm here to help with general guidance. For medical issues, always consult a professional."

    return {"reply": reply}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
