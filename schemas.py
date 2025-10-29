from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

# HEALNEX Core Schemas
# Each class defines a MongoDB collection using the lowercase name

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    role: str = Field(..., description="User role: patient | doctor | admin")
    password_hash: str = Field(..., description="Hashed password using sha256")
    is_active: bool = Field(True, description="Whether the account is active")

class Patient(BaseModel):
    user_id: str = Field(..., description="Reference to user _id as string")
    age: Optional[int] = Field(None, ge=0, le=120)
    gender: Optional[str] = Field(None, description="male | female | other")
    blood_group: Optional[str] = Field(None, description="e.g., A+, O-, etc.")
    notes: Optional[str] = None

class Doctor(BaseModel):
    user_id: str = Field(..., description="Reference to user _id as string")
    specialization: Optional[str] = None
    license_no: Optional[str] = None
    about: Optional[str] = None

class Appointment(BaseModel):
    patient_id: str = Field(..., description="Patient user_id or patient document id")
    doctor_id: str = Field(..., description="Doctor user_id or doctor document id")
    scheduled_at: str = Field(..., description="ISO datetime string")
    reason: Optional[str] = None
    status: str = Field("pending", description="pending | confirmed | completed | cancelled")

class Disease(BaseModel):
    name: str = Field(...)
    symptoms: List[str] = Field(default_factory=list)
    causes: List[str] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    treatments: List[str] = Field(default_factory=list)
    severity: Optional[str] = None

class Report(BaseModel):
    patient_id: str = Field(..., description="Reference to patient user_id")
    title: str = Field(...)
    file_path: str = Field(..., description="Server path to stored PDF")
    mime_type: str = Field("application/pdf")

class Prescription(BaseModel):
    patient_id: str = Field(...)
    doctor_id: str = Field(...)
    content: str = Field(..., description="Prescription text content")
    file_path: Optional[str] = Field(None, description="If exported to a file, store path here")
