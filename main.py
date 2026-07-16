from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
import psycopg2.extras
import hashlib
import bcrypt
import requests
import re
from cryptography.fernet import Fernet, InvalidToken
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

# ── ECOMAIL TRANSACTIONAL EMAIL ─────────────────────────
# Registration confirmations. Silently disabled until a real API key is
# configured in .env — until then this is a safe no-op, nothing breaks.
ECOMAIL_API_KEY    = os.environ.get("ECOMAIL_API_KEY", "")
ECOMAIL_FROM_EMAIL  = os.environ.get("ECOMAIL_FROM_EMAIL", "event@info.autorion.net")
ECOMAIL_REPLY_TO    = os.environ.get("ECOMAIL_REPLY_TO", "marketing@autorion.cz")
ECOMAIL_SEND_URL    = "https://api2.ecomailapp.cz/transactional/send-message"

# ── CONSENT SIGNATURE ENCRYPTION ────────────────────────
# A handwritten signature is sensitive personal data. It is encrypted at
# rest (Fernet/AES) and NEVER included in bulk guest listings or in the
# response of any endpoint except the dedicated GET .../signature route.
_SIG_KEY = os.environ.get("SIGNATURE_ENCRYPTION_KEY", "")
_signature_cipher = Fernet(_SIG_KEY.encode()) if _SIG_KEY else None

def encrypt_signature(data_url: str) -> str:
    if not _signature_cipher:
        raise HTTPException(
            status_code=503,
            detail="Ukládání podpisů není nakonfigurováno (chybí SIGNATURE_ENCRYPTION_KEY na serveru)."
        )
    return _signature_cipher.encrypt(data_url.encode()).decode()

def decrypt_signature(token: str) -> str:
    if not _signature_cipher:
        raise HTTPException(status_code=503, detail="Ukládání podpisů není nakonfigurováno.")
    try:
        return _signature_cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Podpis se nepodařilo dešifrovat (poškozená data nebo změněný klíč).")

# Columns returned by every "normal" guest endpoint — consent_signature is
# deliberately excluded so it never rides along in list/update responses.
GUEST_SAFE_COLUMNS = """
    id, event_id, first_name, last_name, email, phone, company, status,
    checked_in, companion, window_id, bookings, consent_signed, consent_paper,
    consent_license, consent_signature_at, walk_in, created_at, invite_token,
    last_email_sent_at
"""

DEFAULT_CONFIRMATION_TEMPLATE = {
    "subject": "Potvrzení registrace – {{event_name}}",
    "body": "Dobrý den {{last_name}},\n\nděkujeme za registraci na akci {{event_name}}. Těšíme se na vás!\n\nNa místě se prosím prokažte tímto e-mailem nebo jménem u check-in stánku.",
}

DEFAULT_EMAIL_DESIGN = {
    "bgColor": "#f4f4f4", "containerBg": "#ffffff", "headerBg": "#181612", "headerColor": "#ffffff",
    "accentColor": "#b8924a", "bodyColor": "#181612", "mutedColor": "#8c8577",
    "fontFamily": "Arial, Helvetica, sans-serif", "fontSize": "15px", "borderRadius": "8px",
    "logoUrl": "", "logoHeight": "40", "logoAlign": "center",
    "showButton": False, "btnBg": "#181612", "btnColor": "#ffffff", "btnText": "Potvrdit účast",
    "footerText": "", "showHero": False, "heroUrl": "", "heroHeight": "200",
}

def _format_event_date(event: dict) -> str:
    date_from = event.get("date_from") or ""
    date_to   = event.get("date_to") or ""
    return f"{date_from} – {date_to}" if (date_to and date_to != date_from) else date_from

def _get_registration_url(guest: dict, event: dict) -> str:
    slug = event.get("slug")
    if not slug:
        return "#"
    url = f"https://registration.autorion.net/?event={slug}"
    if guest.get("invite_token"):
        url += f"&invite={guest['invite_token']}"
    return url

def _resolve_merge_tags(text: str, guest: dict, event: dict, registration_url: str) -> str:
    return (
        (text or "")
        .replace("{{last_name}}", guest.get("last_name") or "")
        .replace("{{event_name}}", event.get("name") or "")
        .replace("{{event_date}}", _format_event_date(event))
        .replace("{{event_location}}", event.get("location") or "")
        .replace("{{registration_link}}", f'<a href="{registration_url}">Odkaz na registraci</a>')
    )

def _linkify_markdown(text: str, color: str) -> str:
    """Lets the admin type a plain [odkaz](https://...) in the template body
    and get a real clickable link in the sent e-mail — mirrors the same
    syntax supported in the Editor e-mailů's manual sends."""
    return re.sub(
        r'\[([^\]]+)\]\((https?://[^\s)]+)\)',
        lambda m: f'<a href="{m.group(2)}" style="color:{color}">{m.group(1)}</a>',
        text or ""
    )

def _build_booking_details_html(guest: dict, event: dict) -> str:
    """The 'what you booked' block (time window OR vehicle rides) —
    always shown as a fixed structural section, not editable free text,
    so it can never be accidentally broken by editing the template body."""
    bookings = guest.get("bookings") or []
    if event.get("registration_type") == "windows":
        windows = event.get("time_windows") or []
        window = next((w for w in windows if w.get("id") == guest.get("window_id")), None)
        if window:
            return f'''
            <tr><td colspan="2" style="padding-top:18px;font-weight:600;color:#181612;font-size:14px;">Čas příchodu</td></tr>
            <tr>
              <td style="padding:6px 0;color:#181612;font-size:14px;">{window.get("label") or ""}</td>
              <td style="padding:6px 0;color:#8c8577;font-size:14px;text-align:right;">{window.get("from") or ""}–{window.get("to") or ""}</td>
            </tr>'''
        return ""
    if bookings:
        rows = "".join(
            f'<tr>'
            f'<td style="padding:6px 0;color:#181612;font-size:14px;">{b.get("vehicle_name") or "Vůz"}</td>'
            f'<td style="padding:6px 0;color:#8c8577;font-size:14px;text-align:right;">{b.get("time_slot") or ""}</td>'
            f'</tr>'
            for b in bookings
        )
        return f'''
        <tr><td colspan="2" style="padding-top:18px;font-weight:600;color:#181612;font-size:14px;">Vaše testovací jízdy</td></tr>
        {rows}'''
    return ""

def _build_templated_email_html(guest: dict, event: dict, template: dict, design: dict) -> str:
    """Renders an event-info-table email (used for the automatic registration
    confirmation) using the SAME customizable subject/body/design an admin
    can edit in the Editor e-mailů — instead of a fixed Python-only template."""
    d = {**DEFAULT_EMAIL_DESIGN, **(design or {})}
    # Hero image can be shared across all templates ("unified", default) or
    # be its own independent image just for this template ("custom") — mirrors
    # the same choice available in the Editor e-mailů.
    hero_source = template if (template.get("heroMode") == "custom") else d
    registration_url = _get_registration_url(guest, event)

    body_resolved = _linkify_markdown(
        _resolve_merge_tags(template.get("body") or "", guest, event, registration_url),
        d.get("accentColor") or "#b8924a"
    )
    body_html = "".join(
        f'<p style="margin:0 0 14px 0">{line}</p>' if line.strip() else '<p style="margin:0 0 8px 0">&nbsp;</p>'
        for line in body_resolved.split("\n")
    )

    logo_html = (
        f'<img src="{d["logoUrl"]}" style="height:{d["logoHeight"]}px;" alt="">'
        if d.get("logoUrl") else
        f'<span style="color:{d["headerColor"]};font-size:19px;font-weight:700;letter-spacing:0.02em;">Autorion Events</span>'
    )
    hero_html = (
        f'<tr><td style="padding:0;"><img src="{hero_source.get("heroUrl")}" width="600" style="display:block;width:100%;height:auto;" alt=""></td></tr>'
        if (hero_source.get("showHero") and hero_source.get("heroUrl")) else ""
    )
    booking_html = _build_booking_details_html(guest, event)
    button_html = (
        f'''<div style="text-align:center;margin-top:28px;">
          <a href="{registration_url}" style="display:inline-block;background:{d['btnBg']};color:{d['btnColor']};text-decoration:none;padding:13px 32px;border-radius:{d['borderRadius']};font-size:15px;font-weight:600;letter-spacing:0.02em;">{d.get('btnText') or 'Potvrdit účast'}</a>
        </div>'''
        if d.get("showButton") else ""
    )
    date_label = _format_event_date(event)

    return f"""
    <div style="font-family:{d['fontFamily']};background:{d['bgColor']};padding:24px 0;">
      <div style="max-width:520px;margin:0 auto;background:{d['containerBg']};border-radius:{d['borderRadius']};overflow:hidden;border:1px solid #ddd9d0;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
          {hero_html}
          <tr><td style="background:{d['headerBg']};padding:26px 32px;text-align:{d['logoAlign']};">{logo_html}</td></tr>
          <tr><td style="padding:32px;">
            <div style="font-size:{d['fontSize']};color:{d['bodyColor']};line-height:1.7;">
              {body_html}
            </div>
            <table style="width:100%;border-top:1px solid #ddd9d0;border-bottom:1px solid #ddd9d0;padding:14px 0;border-collapse:collapse;margin-top:12px;">
              <tr><td style="padding:6px 0;color:{d['mutedColor']};font-size:14px;">Akce</td><td style="padding:6px 0;text-align:right;color:{d['bodyColor']};font-weight:500;font-size:14px;">{event.get('name','')}</td></tr>
              <tr><td style="padding:6px 0;color:{d['mutedColor']};font-size:14px;">Datum</td><td style="padding:6px 0;text-align:right;color:{d['bodyColor']};font-weight:500;font-size:14px;">{date_label}</td></tr>
              <tr><td style="padding:6px 0;color:{d['mutedColor']};font-size:14px;">Místo</td><td style="padding:6px 0;text-align:right;color:{d['bodyColor']};font-weight:500;font-size:14px;">{event.get('location','')}</td></tr>
              {booking_html}
            </table>
            {button_html}
          </td></tr>
        </table>
      </div>
    </div>
    """

def send_ecomail_transactional(to_email: str, to_name: str, subject: str, html: str) -> bool:
    """Low-level Ecomail transactional send. Returns True/False, never raises —
    callers decide how to handle/report a failure."""
    if not ECOMAIL_API_KEY or ECOMAIL_API_KEY == "changeme":
        return False
    try:
        payload = {
            "message": {
                "subject": subject,
                "from_name": "Autorion Events",
                "from_email": ECOMAIL_FROM_EMAIL,
                "reply_to": ECOMAIL_REPLY_TO,
                "html": html,
                "to": [{"email": to_email, "name": to_name}],
            }
        }
        res = requests.post(
            ECOMAIL_SEND_URL,
            json=payload,
            headers={"key": ECOMAIL_API_KEY, "Content-Type": "application/json"},
            timeout=10,
        )
        return res.ok
    except Exception as e:
        print(f"[ecomail] Odeslání selhalo ({to_email}): {e}")
        return False

def _mark_guest_emailed(guest_id: int):
    """Persists 'an e-mail was actually sent to this guest' — used by both
    the automatic registration confirmation and manual bulk sends, so the
    admin's 'E-mail odeslán' / 'Dosud nekontaktovaní' views reflect reality
    instead of resetting on every page reload."""
    if not guest_id:
        return
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE guests SET last_email_sent_at = NOW() WHERE id = %s", (guest_id,))
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[ecomail] Nepodařilo se zaznamenat odeslání e-mailu (guest {guest_id}): {e}")

def send_registration_confirmation_email(guest: dict, event: dict):
    """Best-effort send — a failure here must never break guest registration.
    Uses the event's own 'registration_confirmation' template/design if the
    admin has customized it in the Editor e-mailů; otherwise falls back to
    a sensible built-in default so nothing breaks for events that never
    touched this."""
    if not ECOMAIL_API_KEY or ECOMAIL_API_KEY == "changeme":
        return

    templates = event.get("email_templates") or []
    template = next((t for t in templates if t.get("id") == "registration_confirmation"), None) \
        or DEFAULT_CONFIRMATION_TEMPLATE
    design = event.get("email_design") or {}

    guest_name = f"{guest.get('first_name','')} {guest.get('last_name','')}".strip()
    registration_url = _get_registration_url(guest, event)
    subject = _resolve_merge_tags(template.get("subject") or DEFAULT_CONFIRMATION_TEMPLATE["subject"], guest, event, registration_url)
    html = _build_templated_email_html(guest, event, template, design)

    ok = send_ecomail_transactional(guest["email"], guest_name, subject, html)
    if ok:
        _mark_guest_emailed(guest.get("id"))

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
    email_templates: Optional[list] = None
    email_design: Optional[dict] = None
    company: Optional[str] = None  # 'albion' | 'cardion' | 'orbion'

class BookingItem(BaseModel):
    vehicle_id: Optional[int] = None
    vehicle_name: Optional[str] = None
    time_slot: Optional[str] = None

class EventArchiveRequest(BaseModel):
    notes: Optional[str] = ""
    vehicles: Optional[list] = None  # snapshot of vehicles at time of archiving

class EmailItem(BaseModel):
    email: str
    name: str
    subject: str
    html: str
    guest_id: Optional[int] = None

class BulkEmailRequest(BaseModel):
    items: list[EmailItem]

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
    send_confirmation: bool = True  # public registration always wants this; admin "add guest" forms can opt out

class InviteCompleteRequest(BaseModel):
    phone: Optional[str] = None
    companion: bool = False
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
    consent_signature: Optional[str] = None  # base64 PNG data URL from the signature pad
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
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS email_templates JSONB DEFAULT '[]';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS email_design JSONB DEFAULT '{}';")
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
            window_id BIGINT,
            bookings JSONB DEFAULT '[]',
            consent_signed BOOLEAN DEFAULT FALSE,
            consent_paper BOOLEAN DEFAULT FALSE,
            consent_license VARCHAR(50) DEFAULT '',
            consent_signature TEXT DEFAULT NULL,
            consent_signature_at TIMESTAMP DEFAULT NULL,
            walk_in BOOLEAN DEFAULT FALSE,
            invite_token VARCHAR(64) UNIQUE,
            last_email_sent_at TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Migration: signature storage on already-existing guest tables
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS consent_signature TEXT DEFAULT NULL;")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS consent_signature_at TIMESTAMP DEFAULT NULL;")
    # Migration: time-window IDs are generated client-side via JS Date.now()
    # (millisecond timestamps, ~13 digits) which overflow a plain INTEGER
    # (max ~2.1 billion, ~10 digits) — widen to BIGINT to fit them safely.
    cur.execute("ALTER TABLE guests ALTER COLUMN window_id TYPE BIGINT;")
    # Personal invite links: lets us pre-fill + update an admin-added guest's
    # own record instead of creating a duplicate when they use their link.
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS invite_token VARCHAR(64) UNIQUE;")
    # Real, persistent tracking of "was ANY e-mail (auto-confirmation or
    # manual invitation/reminder/...) actually sent to this guest" — the
    # admin UI used to track this only in browser memory, which reset on
    # every page reload/event switch.
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS last_email_sent_at TIMESTAMP DEFAULT NULL;")
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
    json_fields = {"theme", "time_windows", "vehicles", "landing_page", "email_templates", "email_design"}
    # landing_page is edited independently from two different screens (Visual
    # Editor's hero/sections, and the Nastavení "show register button"
    # toggle). A plain overwrite lets whichever one saves last silently wipe
    # out the other's changes if its local copy is stale. A shallow JSONB
    # merge (old || new) keeps existing top-level keys the caller didn't
    # touch, instead of relying on the client to have a fully up-to-date copy.
    shallow_merge_fields = {"landing_page"}
    set_parts = []
    values = []
    for k, v in fields.items():
        if k in shallow_merge_fields:
            set_parts.append(f"{k} = COALESCE({k}, '{{}}'::jsonb) || %s::jsonb")
            values.append(json.dumps(v))
        elif k in json_fields:
            set_parts.append(f"{k} = %s")
            values.append(json.dumps(v))
        else:
            set_parts.append(f"{k} = %s")
            values.append(v)
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
    cur.execute(f"SELECT {GUEST_SAFE_COLUMNS} FROM guests WHERE event_id = %s ORDER BY last_name", (event_id,))
    guests = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(g) for g in guests]

def _check_booking_and_window_availability(cur, event_id, bookings_list, window_id, exclude_guest_id=None):
    """Raises HTTPException(409, ...) on a real conflict. Shared by both the
    'new guest' (create) and 'complete my invite' (update) flows so a guest
    completing their own invite doesn't collide with a slot/window that
    only THEY already provisionally hold."""
    guest_filter = "AND id != %s" if exclude_guest_id is not None else ""
    guest_filter_params = (exclude_guest_id,) if exclude_guest_id is not None else ()

    if bookings_list:
        cur.execute(
            f"SELECT bookings FROM guests WHERE event_id = %s AND status != 'cancelled' {guest_filter}",
            (event_id, *guest_filter_params)
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
                raise HTTPException(
                    status_code=409,
                    detail=f"Termín {b.get('time_slot')} pro toto vozidlo je již obsazen. Obnovte stránku a vyberte jiný."
                )

    if window_id is not None:
        cur.execute("SELECT time_windows FROM events WHERE id = %s", (event_id,))
        ev = cur.fetchone()
        windows = ev["time_windows"] if ev else []
        window_def = next((w for w in windows if w.get("id") == window_id), None)
        if window_def and window_def.get("capacity", 0) > 0:
            cur.execute(
                f"SELECT COUNT(*) AS cnt FROM guests WHERE event_id = %s AND window_id = %s AND status != 'cancelled' {guest_filter}",
                (event_id, window_id, *guest_filter_params)
            )
            cnt = cur.fetchone()["cnt"]
            if cnt >= window_def["capacity"]:
                raise HTTPException(status_code=409, detail="Tento časový blok je již plně obsazen. Obnovte stránku a vyberte jiný.")

@app.post("/api/events/{event_id}/guests")
def create_guest(event_id: int, guest: GuestCreate):
    conn = get_db()
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Lock guests rows for this event to avoid race conditions on slot booking
        cur.execute("LOCK TABLE guests IN SHARE ROW EXCLUSIVE MODE")

        bookings_list = [b.dict() for b in guest.bookings]
        _check_booking_and_window_availability(cur, event_id, bookings_list, guest.window_id)

        invite_token = secrets.token_urlsafe(24)
        cur.execute(f"""
            INSERT INTO guests (event_id, first_name, last_name, email, phone, companion, status, window_id, bookings, consent_signed, company, invite_token)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {GUEST_SAFE_COLUMNS}
        """, (
            event_id, guest.first_name, guest.last_name, guest.email.lower(), guest.phone or '',
            guest.companion, guest.status, guest.window_id,
            json.dumps(bookings_list), guest.consent_signed, guest.company or '', invite_token
        ))
        new_guest = cur.fetchone()
        cur.execute("SELECT name, date_from, date_to, location, registration_type, time_windows, slug, email_templates, email_design FROM events WHERE id = %s", (event_id,))
        event_row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        if event_row and guest.send_confirmation:
            send_registration_confirmation_email(dict(new_guest), dict(event_row))

        return dict(new_guest)
    except HTTPException:
        conn.rollback()
        cur.close()
        conn.close()
        raise
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/events/public/{slug}/invite/{token}")
def get_invite_prefill(slug: str, token: str):
    """Public, unauthenticated: returns just enough to pre-fill the
    registration form for a specific pre-loaded contact. Never exposes
    other guests or anything beyond this one invite."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM events WHERE slug = %s", (slug,))
    ev = cur.fetchone()
    if not ev:
        cur.close(); conn.close()
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    cur.execute(
        "SELECT first_name, last_name, email, phone, company, status FROM guests WHERE event_id = %s AND invite_token = %s",
        (ev["id"], token)
    )
    guest = cur.fetchone()
    cur.close(); conn.close()
    if not guest:
        raise HTTPException(status_code=404, detail="Pozvánka nenalezena nebo již není platná.")
    return dict(guest)

@app.post("/api/events/public/{slug}/invite/{token}/complete")
def complete_invite(slug: str, token: str, req: InviteCompleteRequest):
    """Completes an admin-pre-loaded guest's registration in place — updates
    their existing record instead of creating a duplicate one."""
    conn = get_db()
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("LOCK TABLE guests IN SHARE ROW EXCLUSIVE MODE")

        cur.execute("SELECT id FROM events WHERE slug = %s", (slug,))
        ev = cur.fetchone()
        if not ev:
            conn.rollback(); cur.close(); conn.close()
            raise HTTPException(status_code=404, detail="Akce nenalezena")
        event_id = ev["id"]

        cur.execute("SELECT id FROM guests WHERE event_id = %s AND invite_token = %s", (event_id, token))
        existing_guest = cur.fetchone()
        if not existing_guest:
            conn.rollback(); cur.close(); conn.close()
            raise HTTPException(status_code=404, detail="Pozvánka nenalezena nebo již není platná.")
        guest_id = existing_guest["id"]

        bookings_list = [b.dict() for b in req.bookings]
        _check_booking_and_window_availability(cur, event_id, bookings_list, req.window_id, exclude_guest_id=guest_id)

        cur.execute(f"""
            UPDATE guests
            SET phone = %s, companion = %s, window_id = %s, bookings = %s,
                consent_signed = %s, status = 'confirmed'
            WHERE id = %s
            RETURNING {GUEST_SAFE_COLUMNS}
        """, (req.phone or '', req.companion, req.window_id, json.dumps(bookings_list), req.consent_signed, guest_id))
        updated_guest = cur.fetchone()
        cur.execute("SELECT name, date_from, date_to, location, registration_type, time_windows, slug, email_templates, email_design FROM events WHERE id = %s", (event_id,))
        event_row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        if event_row:
            send_registration_confirmation_email(dict(updated_guest), dict(event_row))

        return dict(updated_guest)
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

    # The signature is encrypted before it ever touches the database, and is
    # timestamped separately. It's popped out of the generic fields loop so
    # it gets special (encrypted) handling instead of being stored raw.
    raw_signature = fields.pop("consent_signature", None)

    set_parts = [f"{k} = %s" for k in fields.keys()]
    values = list(fields.values())
    if raw_signature is not None:
        set_parts.append("consent_signature = %s")
        set_parts.append("consent_signature_at = NOW()")
        values.append(encrypt_signature(raw_signature))

    set_clause = ", ".join(set_parts)
    values.append(guest_id)
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"UPDATE guests SET {set_clause} WHERE id = %s RETURNING {GUEST_SAFE_COLUMNS}", values)
    updated = cur.fetchone()
    cur.close()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    return dict(updated)

@app.get("/api/guests/{guest_id}/signature")
def get_guest_signature(guest_id: int, user=Depends(get_current_user)):
    """Dedicated, explicit-only route for viewing a guest's signed consent
    (e.g. when an inspector asks to see it). Deliberately separate from
    every other guest endpoint so the signature is never fetched by accident."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT consent_signature, consent_signature_at, first_name, last_name FROM guests WHERE id = %s",
        (guest_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    if not row["consent_signature"]:
        raise HTTPException(status_code=404, detail="Tento host nemá uložený digitální podpis.")
    return {
        "guest_id": guest_id,
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "signed_at": row["consent_signature_at"],
        "signature": decrypt_signature(row["consent_signature"]),
    }

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

@app.post("/api/send-bulk-email")
def send_bulk_email(req: BulkEmailRequest, user=Depends(get_current_user)):
    """Each item already has its per-recipient subject/HTML fully resolved
    by the frontend (merge tags substituted) — this endpoint just relays
    each one to Ecomail and reports back how many actually went out."""
    if not ECOMAIL_API_KEY or ECOMAIL_API_KEY == "changeme":
        raise HTTPException(status_code=503, detail="Ecomail není nakonfigurovaný (chybí API klíč na serveru).")
    if not req.items:
        raise HTTPException(status_code=400, detail="Žádní příjemci k odeslání")
    sent = 0
    for item in req.items:
        if send_ecomail_transactional(item.email, item.name, item.subject, item.html):
            sent += 1
            _mark_guest_emailed(item.guest_id)
    return {"sent": sent, "failed": len(req.items) - sent, "total": len(req.items)}

@app.get("/api/health")
def health():
    return {"status": "healthy", "time": str(datetime.now())}
