from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
import psycopg2.extras
import hashlib
import bcrypt
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
    """Bcrypt hash for NEW passwords (any password being set/changed from now on)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def _is_legacy_sha256_hash(stored_hash: str) -> bool:
    # Old hashes are raw sha256 hexdigests: exactly 64 hex characters.
    # Bcrypt hashes start with $2a$/$2b$/$2y$ and are ~60 chars — never match this.
    return len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash.lower())

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against either a bcrypt hash (current) or a
    legacy unsalted-sha256 hash (pre-migration accounts)."""
    if _is_legacy_sha256_hash(stored_hash):
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ValueError:
        return False  # malformed hash — never authenticate

# Sessions storage (in-memory for now)
sessions = {}

# ── LOGIN RATE LIMITING ─────────────────────────────────
# After too many failed attempts for one account, the account is locked
# PERMANENTLY (persisted in the DB, survives restarts) until a super_admin
# explicitly unlocks it — see POST /api/users/{id}/unlock. Failed-attempt
# counting itself lives in memory (losing the count on a server restart is
# an acceptable, safe-direction failure — worst case someone gets 5 fresh
# attempts, they don't get an already-locked account un-locked).
LOGIN_MAX_ATTEMPTS = 5
failed_login_counts = {}  # email -> int

def _register_failed_login(email: str) -> int:
    failed_login_counts[email] = failed_login_counts.get(email, 0) + 1
    return failed_login_counts[email]

def _reset_failed_logins(email: str):
    failed_login_counts.pop(email, None)

# ── MODELS ──────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "viewer"
    checkin_access: bool = False
    event_access: Optional[List[int]] = None  # None = all events

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    checkin_access: Optional[bool] = None
    event_access: Optional[List[int]] = None
    event_access_all: Optional[bool] = None  # convenience flag from frontend

class EventCreate(BaseModel):
    name: str
    date_from: str
    date_to: Optional[str] = None
    location: str
    capacity: int
    registration_type: str = "drives"
    icon: str = "🎯"
    slug: Optional[str] = None  # admin-chosen public URL slug; auto-generated from name if omitted

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
    landing_page: Optional[dict] = None
    company: Optional[str] = None  # 'albion' | 'cardion' | 'orbion'

class BookingItem(BaseModel):
    vehicle_id: Optional[int] = None
    vehicle_name: Optional[str] = None
    time_slot: Optional[str] = None

class EventArchiveRequest(BaseModel):
    notes: Optional[str] = ""
    vehicles: Optional[list] = None  # snapshot of vehicles at time of archiving

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
    company: Optional[str] = None  # 'albion' | 'cardion' | 'orbion'

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
    company: Optional[str] = None  # 'albion' | 'cardion' | 'orbion'

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
            event_access JSONB DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked BOOLEAN DEFAULT FALSE;")
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
            landing_page JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Migration: archive support (safe on existing tables — no-op if columns already exist)
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP DEFAULT NULL;")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS archive_meta JSONB DEFAULT '{}';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS vehicles JSONB DEFAULT '[]';")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS guests (
            id SERIAL PRIMARY KEY,
            event_id INTEGER REFERENCES events(id),
            first_name VARCHAR(255),
            last_name VARCHAR(255),
            email VARCHAR(255),
            phone VARCHAR(50) DEFAULT '',
            company VARCHAR(50) DEFAULT '',
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
    email = req.email.lower()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user and user["locked"]:
        cur.close()
        conn.close()
        raise HTTPException(
            status_code=423,
            detail="Účet je zamčen kvůli opakovaným neúspěšným pokusům o přihlášení. Požádejte super admina o odemčení."
        )

    if not user or not verify_password(req.password, user["password_hash"]):
        if user:  # only track/lock attempts against real accounts
            attempts = _register_failed_login(email)
            if attempts >= LOGIN_MAX_ATTEMPTS:
                cur.execute("UPDATE users SET locked = TRUE WHERE id = %s", (user["id"],))
                cur.close()
                conn.close()
                _reset_failed_logins(email)
                raise HTTPException(
                    status_code=423,
                    detail="Účet byl po 5 neúspěšných pokusech zamčen. Požádejte super admina o odemčení."
                )
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Nesprávný email nebo heslo")

    _reset_failed_logins(email)
    # Transparent migration: if this account still has a legacy sha256 hash,
    # upgrade it to bcrypt now that we have the plaintext password in hand.
    if _is_legacy_sha256_hash(user["password_hash"]):
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                    (hash_password(req.password), user["id"]))
    cur.close()
    conn.close()
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

@app.post("/api/auth/change-password")
def change_password(req: PasswordChangeRequest, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (user["id"],))
    current = cur.fetchone()
    if not current or not verify_password(req.current_password, current["password_hash"]):
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Současné heslo není správné")
    if len(req.new_password) < 8:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Nové heslo musí mít alespoň 8 znaků")
    new_hash = hash_password(req.new_password)
    cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user["id"]))
    cur.close()
    conn.close()
    # Invalidate all other sessions for this user except the current one, so
    # the password change takes effect everywhere on next request.
    current_token = None
    for token, sess_user in list(sessions.items()):
        if sess_user["id"] == user["id"]:
            del sessions[token]
    return {"status": "ok", "detail": "Heslo bylo změněno. Přihlaste se znovu."}

# ── USER MANAGEMENT ─────────────────────────────────────

def _user_dict(row):
    """Strip password_hash before returning a user row to the client."""
    d = dict(row)
    d.pop("password_hash", None)
    return d

@app.get("/api/users")
def get_users(user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users ORDER BY created_at")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [_user_dict(r) for r in rows]

@app.post("/api/users")
def create_user(req: UserCreate, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Heslo musí mít alespoň 8 znaků")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO users (email, password_hash, name, role, checkin_access, event_access)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            req.email.lower(), hash_password(req.password), req.name,
            req.role, req.checkin_access,
            json.dumps(req.event_access) if req.event_access is not None else None
        ))
        new_user = cur.fetchone()
        cur.close()
        conn.close()
        return _user_dict(new_user)
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Uživatel s tímto e-mailem již existuje")

@app.patch("/api/users/{user_id}")
def update_user(user_id: int, req: UserUpdate, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    if user_id == user["id"] and req.role is not None and req.role != user["role"]:
        raise HTTPException(status_code=400, detail="Nemůžete změnit vlastní roli")

    fields = {}
    if req.name is not None: fields["name"] = req.name
    if req.email is not None: fields["email"] = req.email.lower()
    if req.password:
        if len(req.password) < 8:
            raise HTTPException(status_code=400, detail="Heslo musí mít alespoň 8 znaků")
        fields["password_hash"] = hash_password(req.password)
    if req.role is not None: fields["role"] = req.role
    if req.checkin_access is not None: fields["checkin_access"] = req.checkin_access
    if req.event_access_all:
        fields["event_access"] = None
    elif req.event_access is not None:
        fields["event_access"] = json.dumps(req.event_access)

    if not fields:
        raise HTTPException(status_code=400, detail="Zadna data k aktualizaci")

    set_clause = ", ".join([f"{k} = %s" for k in fields.keys()])
    values = list(fields.values()) + [user_id]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f"UPDATE users SET {set_clause} WHERE id = %s RETURNING *", values)
        updated = cur.fetchone()
        cur.close()
        conn.close()
        if not updated:
            raise HTTPException(status_code=404, detail="Uživatel nenalezen")
        # If the updated user has an active session, invalidate it so role/
        # password changes take effect on next request.
        for token, sess_user in list(sessions.items()):
            if sess_user["id"] == user_id:
                del sessions[token]
        return _user_dict(updated)
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Uživatel s tímto e-mailem již existuje")

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Nemůžete smazat sami sebe")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("DELETE FROM users WHERE id = %s RETURNING id", (user_id,))
    deleted = cur.fetchone()
    cur.close()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Uživatel nenalezen")
    for token, sess_user in list(sessions.items()):
        if sess_user["id"] == user_id:
            del sessions[token]
    return {"status": "deleted", "id": user_id}

@app.post("/api/users/{user_id}/unlock")
def unlock_user(user_id: int, user=Depends(get_current_user)):
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Pouze super admin může odemykat účty")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE users SET locked = FALSE WHERE id = %s RETURNING id, email", (user_id,))
    updated = cur.fetchone()
    cur.close()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Uživatel nenalezen")
    _reset_failed_logins(updated["email"].lower())
    return {"status": "unlocked", "id": user_id}

# ── EVENTS ──────────────────────────────────────────────

@app.get("/api/events")
def get_events(user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT e.*,
            (SELECT COUNT(*) FROM guests g WHERE g.event_id = e.id) AS guest_count,
            (SELECT COUNT(*) FROM guests g WHERE g.event_id = e.id AND g.checked_in = TRUE) AS checked_in_count
        FROM events e
        WHERE e.status = 'active'
        ORDER BY e.created_at DESC
    """)
    events = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(e) for e in events]

@app.get("/api/events/archived")
def get_archived_events(user=Depends(get_current_user)):
    """Must be registered before /api/events/{event_id} so 'archived' isn't
    mistaken for an event_id path parameter."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT e.*,
            (SELECT COUNT(*) FROM guests g WHERE g.event_id = e.id) AS guest_count,
            (SELECT COUNT(*) FROM guests g WHERE g.event_id = e.id AND g.status = 'confirmed') AS confirmed_count,
            (SELECT COALESCE(SUM(jsonb_array_length(g.bookings)), 0) FROM guests g WHERE g.event_id = e.id) AS rides_count
        FROM events e
        WHERE e.status = 'archived'
        ORDER BY e.archived_at DESC NULLS LAST
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

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

@app.get("/api/events/landing/{slug}")
def get_event_landing(slug: str):
    """Public landing page data — does not require registration_open, since
    the info page can exist independently of whether registration is live."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE slug = %s", (slug,))
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

@app.get("/api/events/check-slug/{slug}")
def check_slug_available(slug: str, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM events WHERE slug = %s", (slug,))
    taken = cur.fetchone() is not None
    cur.close()
    conn.close()
    return {"slug": slug, "available": not taken}

@app.post("/api/events")
def create_event(event: EventCreate, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    import re

    # Use the admin-chosen slug if provided, otherwise derive one from the name.
    raw_source = event.slug if (event.slug and event.slug.strip()) else event.name
    base_slug = re.sub(r'[^a-z0-9]+', '-', raw_source.lower()).strip('-')
    if not base_slug:
        base_slug = "akce"

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Fail-safe: if the slug is already taken (active or archived event),
    # append -2, -3, ... until a free one is found. This guarantees event
    # creation never hard-fails on a slug collision, even if the admin didn't
    # notice the collision warning on the frontend.
    final_slug = base_slug
    cur.execute("SELECT 1 FROM events WHERE slug = %s", (final_slug,))
    n = 2
    while cur.fetchone():
        final_slug = f"{base_slug}-{n}"
        cur.execute("SELECT 1 FROM events WHERE slug = %s", (final_slug,))
        n += 1

    cur.execute("""
        INSERT INTO events (name, date_from, date_to, location, capacity, registration_type, icon, slug)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (event.name, event.date_from, event.date_to, event.location,
          event.capacity, event.registration_type, event.icon, final_slug))
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
    json_fields = {"theme", "time_windows", "vehicles", "landing_page"}
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

@app.post("/api/events/{event_id}/archive")
def archive_event(event_id: int, req: EventArchiveRequest, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT status FROM events WHERE id = %s", (event_id,))
    ev = cur.fetchone()
    if not ev:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    if ev["status"] == "archived":
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Akce je již archivována")
    meta = {"notes": req.notes or "", "vehicles": req.vehicles or []}
    cur.execute("""
        UPDATE events
        SET status = 'archived', archived_at = NOW(), archive_meta = %s
        WHERE id = %s
        RETURNING *
    """, (json.dumps(meta), event_id))
    updated = cur.fetchone()
    cur.close()
    conn.close()
    return dict(updated)

@app.post("/api/events/{event_id}/unarchive")
def unarchive_event(event_id: int, user=Depends(get_current_user)):
    if user["role"] not in ["super_admin", "manager"]:
        raise HTTPException(status_code=403, detail="Nedostatecna opravneni")
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        UPDATE events
        SET status = 'active', archived_at = NULL
        WHERE id = %s
        RETURNING *
    """, (event_id,))
    updated = cur.fetchone()
    cur.close()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(updated)

@app.delete("/api/events/{event_id}")
def delete_event(event_id: int, user=Depends(get_current_user)):
    # Deliberately more restrictive than archive/unarchive: this permanently
    # destroys the event AND every guest registered to it. Super admin only.
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Pouze super admin může trvale smazat akci")
    conn = get_db()
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("SELECT id, name FROM events WHERE id = %s", (event_id,))
        ev = cur.fetchone()
        if not ev:
            conn.rollback()
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Akce nenalezena")
        cur.execute("DELETE FROM guests WHERE event_id = %s", (event_id,))
        deleted_guests = cur.rowcount
        cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "deleted", "id": event_id, "name": ev["name"], "deleted_guests": deleted_guests}
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail="Smazání akce se nezdařilo, žádná data nebyla změněna")

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
            INSERT INTO guests (event_id, first_name, last_name, email, phone, companion, status, window_id, bookings, consent_signed, company)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            event_id, guest.first_name, guest.last_name, guest.email.lower(), guest.phone or '',
            guest.companion, guest.status, guest.window_id,
            json.dumps(bookings_list), guest.consent_signed, guest.company or ''
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
