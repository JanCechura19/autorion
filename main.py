from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
import psycopg2.extras
import hashlib
import secrets
import json
from datetime import datetime

app = FastAPI(title="Autorion API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_CONFIG = {
    "host": "localhost",
    "database": "autorion",
    "user": "autorion_user",
    "password": "Autorion2025"
}

def get_db():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Sessions storage (in-memory for now)
sessions = {}

# ── MODELS ──────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class EventCreate(BaseModel):
    name: str
    date_from: str
    date_to: Optional[str] = None
    location: str
    capacity: int
    registration_type: str = "drives"
    icon: str = "🎯"

class GuestCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    event_id: int
    companion: bool = False
    status: str = "pending"

class GuestUpdate(BaseModel):
    status: Optional[str] = None
    checked_in: Optional[bool] = None
    companion: Optional[bool] = None

# ── INIT DB ─────────────────────────────────────────────

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'viewer',
            checkin_access BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            date_from VARCHAR(50),
            date_to VARCHAR(50),
            location VARCHAR(255),
            capacity INTEGER DEFAULT 100,
            registration_open BOOLEAN DEFAULT TRUE,
            registration_type VARCHAR(50) DEFAULT 'drives',
            icon VARCHAR(10) DEFAULT '🎯',
            status VARCHAR(50) DEFAULT 'active',
            slug VARCHAR(100) UNIQUE,
            time_windows JSONB DEFAULT '[]',
            slot_start VARCHAR(10) DEFAULT '10:00',
            slot_end VARCHAR(10) DEFAULT '18:00',
            slot_duration INTEGER DEFAULT 15,
            consent_cs TEXT DEFAULT '',
            consent_en TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS guests (
            id SERIAL PRIMARY KEY,
            event_id INTEGER REFERENCES events(id),
            first_name VARCHAR(255),
            last_name VARCHAR(255),
            email VARCHAR(255),
            status VARCHAR(50) DEFAULT 'pending',
            checked_in BOOLEAN DEFAULT FALSE,
            companion BOOLEAN DEFAULT FALSE,
            window_id INTEGER,
            bookings JSONB DEFAULT '[]',
            consent_signed BOOLEAN DEFAULT FALSE,
            consent_paper BOOLEAN DEFAULT FALSE,
            walk_in BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Default admin user
    cur.execute("""
        INSERT INTO users (email, password_hash, name, role, checkin_access)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING;
    """, (
        "admin@autorion.net",
        hash_password("Autorion2025!"),
        "Admin",
        "super_admin",
        True
    ))
    cur.close()
    conn.close()

init_db()

# ── AUTH ────────────────────────────────────────────────

@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s",
                (req.email.lower(), hash_password(req.password)))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Nesprávný email nebo heslo")
    token = secrets.token_hex(32)
    sessions[token] = dict(user)
    return {"token": token, "user": {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "checkin_access": user["checkin_access"]
    }}

@app.post("/api/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    if credentials and credentials.credentials in sessions:
        del sessions[credentials.credentials]
    return {"status": "ok"}

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    if not credentials or credentials.credentials not in sessions:
        raise HTTPException(status_code=401, detail="Nejste přihlášeni")
    return sessions[credentials.credentials]

# ── EVENTS ──────────────────────────────────────────────

@app.get("/api/events")
def get_events(user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE status = 'active' ORDER BY created_at DESC")
    events = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(e) for e in events]

@app.get("/api/events/public/{slug}")
def get_event_public(slug: str):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE slug = %s AND registration_open = TRUE", (slug,))
    event = cur.fetchone()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(event)

@app.post("/api/events")
def create_event(event: EventCreate, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    import re
    slug = re.sub(r'[^a-z0-9]+', '-', event.name.lower()).strip('-')
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO events (name, date_from, date_to, location, capacity, registration_type, icon, slug)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (event.name, event.date_from, event.date_to, event.location,
          event.capacity, event.registration_type, event.icon, slug))
    new_event = cur.fetchone()
    cur.close()
    conn.close()
    return dict(new_event)

@app.get("/api/events/{event_id}")
def get_event(event_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE id = %s", (event_id,))
    event = cur.fetchone()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(event)

# ── GUESTS ──────────────────────────────────────────────

@app.get("/api/events/{event_id}/guests")
def get_guests(event_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM guests WHERE event_id = %s ORDER BY last_name", (event_id,))
    guests = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(g) for g in guests]

@app.post("/api/events/{event_id}/guests")
def create_guest(event_id: int, guest: GuestCreate):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO guests (event_id, first_name, last_name, email, companion, status)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (event_id, guest.first_name, guest.last_name,
          guest.email.lower(), guest.companion, guest.status))
    new_guest = cur.fetchone()
    cur.close()
    conn.close()
    return dict(new_guest)

@app.patch("/api/guests/{guest_id}")
def update_guest(guest_id: int, update: GuestUpdate, user=Depends(get_current_user)):
    fields = {k: v for k, v in update.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="Zadna data k aktualizaci")
    set_clause = ", ".join([f"{k} = %s" for k in fields.keys()])
    values = list(fields.values()) + [guest_id]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"UPDATE guests SET {set_clause} WHERE id = %s RETURNING *", values)
    updated = cur.fetchone()
    cur.close()
    conn.close()
    return dict(updated)

@app.get("/api/health")
def health():
    return {"status": "healthy", "time": str(datetime.now())}
