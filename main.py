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
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Autorion API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "autorion"),
    "user": os.environ.get("DB_USER", "autorion_user"),
    "password": os.environ.get("DB_PASSWORD"),
}

if not DB_CONFIG["password"]:
    raise RuntimeError(
        "DB_PASSWORD environment variable is not set. "
        "Create a .env file (see .env.example) with the required secrets."
    )

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@autorion.net")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

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

class EventUpdate(BaseModel):
    name: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    location: Optional[str] = None
    capacity: Optional[int] = None
    registration_type: Optional[str] = None
    icon: Optional[str] = None
    registration_open: Optional[bool] = None
    status: Optional[str] = None
    theme: Optional[dict] = None
    intro_text: Optional[str] = None
    time_windows: Optional[list] = None
    slot_start: Optional[str] = None
    slot_end: Optional[str] = None
    slot_duration: Optional[int] = None
    consent_cs: Optional[str] = None
    consent_en: Optional[str] = None
    vehicles: Optional[list] = None

class BookingItem(BaseModel):
    vehicle_id: Optional[int] = None
    vehicle_name: Optional[str] = None
    time_slot: Optional[str] = None

class GuestCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    event_id: int
    phone: Optional[str] = None
    companion: bool = False
    status: str = "pending"
    salutation: Optional[str] = None
    window_id: Optional[int] = None
    bookings: List[BookingItem] = []
    consent_signed: bool = False

class GuestUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[str] = None
    checked_in: Optional[bool] = None
    companion: Optional[bool] = None
    consent_signed: Optional[bool] = None
    consent_paper: Optional[bool] = None
    consent_license: Optional[str] = None
    walk_in: Optional[bool] = None

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
            theme JSONB DEFAULT '{}',
            intro_text TEXT DEFAULT '',
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
            phone VARCHAR(50) DEFAULT '',
            status VARCHAR(50) DEFAULT 'pending',
            checked_in BOOLEAN DEFAULT FALSE,
            companion BOOLEAN DEFAULT FALSE,
            window_id INTEGER,
            bookings JSONB DEFAULT '[]',
            consent_signed BOOLEAN DEFAULT FALSE,
            consent_paper BOOLEAN DEFAULT FALSE,
            consent_license VARCHAR(50) DEFAULT '',
            walk_in BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Default admin user (only created if ADMIN_PASSWORD is configured)
    if ADMIN_PASSWORD:
        cur.execute("""
            INSERT INTO users (email, password_hash, name, role, checkin_access)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (email) DO NOTHING;
        """, (
            ADMIN_EMAIL.lower(),
            hash_password(ADMIN_PASSWORD),
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

@app.get("/api/events/preview/{event_id}")
def get_event_preview(event_id: int):
    """Used by the Visual Editor preview iframe — no registration_open requirement.
    Read-only, no auth (mirrors the public endpoint's exposure level)."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE id = %s", (event_id,))
    event = cur.fetchone()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(event)

@app.get("/api/events/public/{slug}/availability")
def get_event_availability(slug: str):
    """Vrátí obsazené time_sloty pro každé vozidlo + obsazenost time_windows, podle existujících guests."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE slug = %s", (slug,))
    event = cur.fetchone()
    if not event:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Akce nenalezena")

    cur.execute(
        "SELECT bookings, window_id FROM guests WHERE event_id = %s AND status != 'cancelled'",
        (event["id"],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    booked_by_vehicle = {}
    booked_by_window = {}
    for row in rows:
        bookings = row.get("bookings") or []
        for b in bookings:
            vid = str(b.get("vehicle_id"))
            slot = b.get("time_slot")
            if vid and slot:
                booked_by_vehicle.setdefault(vid, []).append(slot)
        if row.get("window_id") is not None:
            wid = str(row["window_id"])
            booked_by_window[wid] = booked_by_window.get(wid, 0) + 1

    return {
        "booked_by_vehicle": booked_by_vehicle,
        "booked_by_window": booked_by_window
    }

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

@app.patch("/api/events/{event_id}")
def update_event(event_id: int, update: EventUpdate, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    fields = {k: v for k, v in update.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="Zadna data k aktualizaci")
    json_fields = {"theme", "time_windows", "vehicles"}
    set_parts = []
    values = []
    for k, v in fields.items():
        set_parts.append(f"{k} = %s")
        values.append(json.dumps(v) if k in json_fields else v)
    set_clause = ", ".join(set_parts)
    values.append(event_id)
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"UPDATE events SET {set_clause} WHERE id = %s RETURNING *", values)
    updated = cur.fetchone()
    cur.close()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(updated)

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
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Lock guests rows for this event to avoid race conditions on slot booking
        cur.execute("LOCK TABLE guests IN SHARE ROW EXCLUSIVE MODE")

        bookings_list = [b.dict() for b in guest.bookings]

        if bookings_list:
            # Check vehicle+time_slot collisions
            cur.execute(
                "SELECT bookings FROM guests WHERE event_id = %s AND status != 'cancelled'",
                (event_id,)
            )
            existing = cur.fetchall()
            taken = set()
            for row in existing:
                for b in (row["bookings"] or []):
                    if b.get("vehicle_id") is not None and b.get("time_slot"):
                        taken.add((str(b["vehicle_id"]), b["time_slot"]))
            for b in bookings_list:
                key = (str(b.get("vehicle_id")), b.get("time_slot"))
                if key in taken:
                    conn.rollback()
                    cur.close()
                    conn.close()
                    raise HTTPException(
                        status_code=409,
                        detail=f"Termín {b.get('time_slot')} pro toto vozidlo je již obsazen. Obnovte stránku a vyberte jiný."
                    )

        if guest.window_id is not None:
            # Check window capacity
            cur.execute("SELECT time_windows FROM events WHERE id = %s", (event_id,))
            ev = cur.fetchone()
            windows = ev["time_windows"] if ev else []
            window_def = next((w for w in windows if w.get("id") == guest.window_id), None)
            if window_def and window_def.get("capacity", 0) > 0:
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM guests WHERE event_id = %s AND window_id = %s AND status != 'cancelled'",
                    (event_id, guest.window_id)
                )
                cnt = cur.fetchone()["cnt"]
                if cnt >= window_def["capacity"]:
                    conn.rollback()
                    cur.close()
                    conn.close()
                    raise HTTPException(status_code=409, detail="Tento časový blok je již plně obsazen. Obnovte stránku a vyberte jiný.")

        cur.execute("""
            INSERT INTO guests (event_id, first_name, last_name, email, phone, companion, status, window_id, bookings, consent_signed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            event_id, guest.first_name, guest.last_name, guest.email.lower(), guest.phone or '',
            guest.companion, guest.status, guest.window_id,
            json.dumps(bookings_list), guest.consent_signed
        ))
        new_guest = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return dict(new_guest)
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/guests/{guest_id}")
def update_guest(guest_id: int, update: GuestUpdate, user=Depends(get_current_user)):
    fields = {k: v for k, v in update.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="Zadna data k aktualizaci")
    if "email" in fields:
        fields["email"] = fields["email"].lower()
    set_clause = ", ".join([f"{k} = %s" for k in fields.keys()])
    values = list(fields.values()) + [guest_id]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"UPDATE guests SET {set_clause} WHERE id = %s RETURNING *", values)
    updated = cur.fetchone()
    cur.close()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    return dict(updated)

@app.delete("/api/guests/{guest_id}")
def delete_guest(guest_id: int, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("DELETE FROM guests WHERE id = %s RETURNING id", (guest_id,))
    deleted = cur.fetchone()
    cur.close()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    return {"status": "deleted", "id": guest_id}

@app.get("/api/health")
def health():
    return {"status": "healthy", "time": str(datetime.now())}
