"""
Volve: Central Receiving API and Dashboard

This service acts as the central hub for the Seid ecosystem. It exposes a 
secure API to receive structured JSON audit reports from Vardlokk agents, 
persists the findings in a SQLite database, and provides a web dashboard 
for administrators to review and remediate issues.
"""

import json
import os
from datetime import datetime
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --- CONFIGURATION ---
# In a production deployment, these should be set via environment variables.
SQLALCHEMY_DATABASE_URL = os.getenv("VOLVE_DB_URL", "sqlite:///./volve.db")
EXPECTED_TOKEN = os.getenv("VOLVE_API_TOKEN", "superhemmelig-token-123")
# Toggle to allow disabling the static file server (e.g., if hosted behind an Nginx proxy)
SERVE_STATIC = os.getenv("VOLVE_SERVE_STATIC", "true").lower() in ("true", "1", "yes")

# --- DATABASE SETUP ---
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBFinding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    timestamp = Column(DateTime)
    scope = Column(String)
    
    finding_id = Column(String, index=True)
    severity = Column(String)
    category = Column(String)
    title = Column(String)
    description = Column(Text)
    local_evidence = Column(Text)
    # Store the complex remediation dict as a raw JSON string for easy retrieval
    remediation_json = Column(Text) 
    
    # Track the lifecycle of the finding: pending, accepted, or discarded
    status = Column(String, default="pending") 

Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency generator for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- PYDANTIC MODELS (API SCHEMA) ---
class Remediation(BaseModel):
    action_type: str
    commands: List[str]
    requires_reboot: bool
    risk_of_breakage: str

class Finding(BaseModel):
    finding_id: str
    severity: str
    category: str
    title: str
    description: str
    local_evidence: str
    remediation: Remediation

class AuditData(BaseModel):
    findings: List[Finding]

class AgentMetadata(BaseModel):
    hostname: str
    timestamp: datetime
    scope: str

class AuditPayload(BaseModel):
    agent_metadata: AgentMetadata
    audit_data: AuditData

class StatusUpdate(BaseModel):
    status: str

# --- SECURITY ---
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validates the Bearer token sent by Vardlokk agents."""
    if credentials.credentials != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    return credentials.credentials

# --- APP INITIALIZATION ---
app = FastAPI(root_path="/volve", title="Volve Audit Receiver")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files conditionally based on configuration
if SERVE_STATIC:
    if os.path.exists(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    else:
        print(f"⚠ Warning: Static directory not found at {STATIC_DIR}")

# --- WEB INTERFACE (HTML) ---
@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Renders the main administrative dashboard."""
    # Retrieve all findings, ordered by newest first
    findings = db.query(DBFinding).order_by(DBFinding.timestamp.desc()).all()
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={
            "findings": findings,
            "json": json
        }
    )

# --- API ENDPOINTS ---
@app.post("/api/v1/audits", status_code=status.HTTP_201_CREATED)
def receive_audit(payload: AuditPayload, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    """Receives an automated audit report from a Vardlokk agent and persists it."""
    host = payload.agent_metadata.hostname
    scope = payload.agent_metadata.scope
    audit_time = payload.agent_metadata.timestamp
    finding_count = len(payload.audit_data.findings)
    
    print(f"\n{'='*50}")
    print(f"📥 Received {scope.upper()} audit from {host}")
    print(f"🕒 Timestamp: {audit_time}")
    print(f"🚨 New findings: {finding_count}")
    
    for item in payload.audit_data.findings:
        print(f"  [{item.severity.upper()}] {item.finding_id}: {item.title}")
        
        # Translate the Pydantic model into a SQLAlchemy database row
        db_finding = DBFinding(
            hostname=host,
            timestamp=audit_time,
            scope=scope,
            finding_id=item.finding_id,
            severity=item.severity,
            category=item.category,
            title=item.title,
            description=item.description,
            local_evidence=item.local_evidence,
            remediation_json=json.dumps(item.remediation.dict())
        )
        db.add(db_finding)
        
    db.commit()
    print(f"{'='*50}\n")
    
    return {"status": "success", "message": f"Persisted {finding_count} findings to database"}

@app.post("/api/v1/findings/{finding_id}/status")
def update_status(finding_id: int, status_update: StatusUpdate, db: Session = Depends(get_db)):
    """Updates the lifecycle status of a specific finding (e.g., accepted, discarded)."""
    if status_update.status not in ["pending", "accepted", "discarded"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be pending, accepted, or discarded.")
        
    finding = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding.status = status_update.status
    db.commit()
    
    return {"status": "success"}

@app.delete("/api/v1/findings/{finding_id}")
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    """Permanently removes a finding from the database."""
    finding = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    db.delete(finding)
    db.commit()
    
    return {"status": "success", "message": "Finding permanently deleted"}