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
    allow_origins=[
        "https://autorion.net",
        "https://admin.autorion.net",
        "https://registration.autorion.net",
        "https://checkin.autorion.net",
        "https://event.autorion.net",
    ],
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

# Driver's license numbers are sensitive government-ID data too — reuse the
# same cipher/key as signatures rather than standing up a second one.
def encrypt_sensitive(value: str) -> str:
    if not _signature_cipher:
        raise HTTPException(status_code=503, detail="Šifrování není nakonfigurováno (chybí SIGNATURE_ENCRYPTION_KEY na serveru).")
    return _signature_cipher.encrypt(value.encode()).decode()

def decrypt_sensitive(token: str) -> str:
    if not _signature_cipher:
        raise HTTPException(status_code=503, detail="Šifrování není nakonfigurováno.")
    try:
        return _signature_cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Údaj se nepodařilo dešifrovat (poškozená data nebo změněný klíč).")

# Columns returned by every "normal" guest endpoint — consent_signature is
# deliberately excluded so it never rides along in list/update responses.
GUEST_SAFE_COLUMNS = """
    id, event_id, first_name, last_name, email, phone, company, status,
    checked_in, companion, window_id, bookings, consent_signed, consent_paper,
    consent_signature_at, walk_in, created_at, invite_token,
    last_email_sent_at, gdpr_consent, confirmed_at, unsubscribed_at,
    companion_will_drive, companion_first_name, companion_last_name,
    companion_email, companion_consent_signed, companion_consent_signature_at,
    language
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

# Matches SAVE_DATE_DEALERS in admin-v3.html — dealer display names used to
# resolve {{team_name}} based on the guest's own company field.
DEALER_TEAM_NAMES = {"albion": "Albion Cars", "cardion": "Cardion Cars", "orbion": "Orbion Cars"}

def _get_team_name(guest: dict) -> str:
    company = (guest.get("company") or "").strip().lower()
    return DEALER_TEAM_NAMES.get(company, "Autorion Events")

# {{contact_link}} — page with sales contacts, per dealer. Guests without a
# company get the general Autorion site.
DEALER_CONTACT_URLS = {
    "albion":  "https://www.albioncars.cz/showroomy/albion-cars-praha",
    "cardion": "https://www.volvista.cz/kontakt",
    "orbion":  "https://www.lynkac.cz/kontakt",
}
DEFAULT_CONTACT_URL = "https://www.autorion.cz"

# {{social_links}} — "Sledujte nás: Facebook · Instagram · LinkedIn" per dealer.
# Guests without a company (Autorion has no profiles) get nothing.
DEALER_SOCIAL_URLS = {
    "albion": {
        "Facebook":  "https://www.facebook.com/albioncarscz",
        "Instagram": "https://www.instagram.com/albioncarscz/",
        "LinkedIn":  "https://www.linkedin.com/company/albion-cars-s-r-o/",
    },
    "cardion": {
        "Facebook":  "https://www.facebook.com/volvista.cz/",
        "Instagram": "https://www.instagram.com/volvista.cz/",
        "LinkedIn":  "https://www.linkedin.com/company/cardion-cars/",
    },
    "orbion": {
        "Facebook":  "https://www.facebook.com/lynkacczech/",
        "Instagram": "https://www.instagram.com/lynkac_cz/",
        "LinkedIn":  "https://www.linkedin.com/company/orbion-cars/",
    },
}

def _get_social_links(guest: dict) -> str:
    """Whole social-media block: a sentence about photos/videos, then either the
    dealer's own Facebook · Instagram · LinkedIn links, or (guests without a
    company) a sentence naming the three brands."""
    company = (guest.get("company") or "").strip().lower()
    en = (guest.get("language") or "").lower() == "en"
    intro = ("In the coming weeks, we will have photos and videos from the event on our social media."
             if en else
             "V následujících týdnech budeme mít na našich sociálních sítích fotografie a videa z akce.")
    links = DEALER_SOCIAL_URLS.get(company)
    if links:
        label = "Follow us" if en else "Sledujte nás"
        parts = " · ".join(f'<a href="{url}">{name}</a>' for name, url in links.items())
        return f"{intro}<br>{label}: {parts}"
    fb = lambda key: DEALER_SOCIAL_URLS[key]["Facebook"]
    brands = (f'<a href="{fb("albion")}">Albion Cars</a>, '
              f'<a href="{fb("cardion")}">Volvista.cz</a> '
              f'{"and" if en else "a"} '
              f'<a href="{fb("orbion")}">{"Lynkáč" if not en else "Lynkáč"}</a>')
    follow = "Please follow the social media of" if en else "Sledujte prosím sociální sítě"
    return f"{intro}<br>{follow} {brands}."

def _build_event_details_block(event: dict, design: dict) -> str:
    accent = design.get("accentColor") or "#b8924a"
    body   = design.get("bodyColor") or "#1a1816"
    return f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:22px 0;">
      <tr>
        <td width="50%" style="text-align:center;padding:0 16px;">
          <div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:{accent};font-weight:600;margin-bottom:6px;">Datum</div>
          <div style="font-size:16px;color:{body};font-weight:600;">{_format_event_date(event)}</div>
        </td>
        <td width="1" style="border-left:1px solid {accent};opacity:0.5;"></td>
        <td width="50%" style="text-align:center;padding:0 16px;">
          <div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:{accent};font-weight:600;margin-bottom:6px;">Místo</div>
          <div style="font-size:16px;color:{body};font-weight:600;">{event.get("location") or ""}</div>
        </td>
      </tr>
    </table>'''

def _resolve_merge_tags(text: str, guest: dict, event: dict, registration_url: str, design: dict = None) -> str:
    return (
        (text or "")
        .replace("{{last_name}}", guest.get("last_name") or "")
        .replace("{{event_name}}", event.get("name") or "")
        .replace("{{event_date}}", _format_event_date(event))
        .replace("{{event_location}}", event.get("location") or "")
        .replace("{{team_name}}", _get_team_name(guest))
        .replace("{{contact_link}}", _get_contact_link(guest))
        .replace("{{social_links}}", _get_social_links(guest))
        .replace("{{event_details}}", _build_event_details_block(event, design or {}))
        .replace("{{booking_summary}}", _build_booking_summary_block(guest, event))
        .replace("{{registration_link}}", f'<a href="{registration_url}">Odkaz na registraci</a>')
        .replace("{{info_page_link}}", f'<a href="https://event.autorion.net/info.html?event={event.get("slug","")}">Informace pro účastníky</a>')
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

def _build_booking_summary_block(guest: dict, event: dict) -> str:
    """Standalone 'what you booked' block (time window OR vehicle rides),
    used via the {{booking_summary}} merge tag — the admin places it
    wherever they want in the editable text (e.g. before their sign-off),
    instead of it always appearing at a fixed position."""
    bookings = guest.get("bookings") or []
    if event.get("registration_type") == "windows":
        windows = event.get("time_windows") or []
        window = next((w for w in windows if w.get("id") == guest.get("window_id")), None)
        if not window:
            return ""
        return f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0;border-top:1px solid #eeeeee;border-bottom:1px solid #eeeeee;">
          <tr><td colspan="2" style="padding:14px 0 6px;font-weight:600;color:#181612;font-size:14px;">Detail registrace</td></tr>
          <tr>
            <td style="padding:0 0 12px;color:#181612;font-size:14px;">{window.get("label") or ""}</td>
            <td style="padding:0 0 12px;color:#8c8577;font-size:14px;text-align:right;">{window.get("from") or ""}–{window.get("to") or ""}</td>
          </tr>
        </table>'''
    if bookings:
        rows = "".join(
            f'<tr>'
            f'<td style="padding:6px 0;color:#181612;font-size:14px;">{b.get("vehicle_name") or "Vůz"}</td>'
            f'<td style="padding:6px 0;color:#8c8577;font-size:14px;text-align:right;">{b.get("time_slot") or ""}</td>'
            f'</tr>'
            for b in bookings
        )
        return f'''<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0;border-top:1px solid #eeeeee;border-bottom:1px solid #eeeeee;">
          <tr><td colspan="2" style="padding:14px 0 6px;font-weight:600;color:#181612;font-size:14px;">Vaše testovací jízdy</td></tr>
          {rows}
        </table>'''
    return ""

# Matches SAVE_DATE_DEALERS in admin-v3.html — used as a sensible fallback
# color when a dealer's own accent/header color hasn't been explicitly set.
DEALER_DEFAULT_COLORS = {"albion": "#A6916C", "cardion": "#8291A6", "orbion": "#333333"}

def _build_templated_email_html(guest: dict, event: dict, template: dict, design: dict) -> str:
    """Renders an event-info-table email (used for the automatic registration
    confirmation) using the SAME customizable subject/body/design an admin
    can edit in the Editor e-mailů — instead of a fixed Python-only template."""
    d = {**DEFAULT_EMAIL_DESIGN, **(design or {})}
    # Hero image can be shared across all templates ("unified", default) or
    # be its own independent image just for this template ("custom") — mirrors
    # the same choice available in the Editor e-mailů.
    hero_source = template if (template.get("heroMode") == "custom") else d
    hero_link_url = hero_source.get("videoUrl")  # unified/per-template video, may be overridden by dealer below
    registration_url = _get_registration_url(guest, event)

    # Dealer branding: shared colors/logo (design.dealerBranding) plus this
    # template's own video/hero override (template.dealerHero) — same model
    # as the Editor e-mailů, applied here for the one Python-composed e-mail.
    company = (guest.get("company") or "").strip().lower()
    if template.get("dealerBrandingEnabled") is not False and company:
        shared_brand = (design.get("dealerBranding") or {}).get(company, {})
        template_brand = (template.get("dealerHero") or {}).get(company, {})
        default_color = DEALER_DEFAULT_COLORS.get(company)
        if shared_brand.get("logoUrl") or shared_brand.get("headerBg") or shared_brand.get("accentColor") or default_color:
            d = {
                **d,
                "logoUrl":     shared_brand.get("logoUrl")     or d.get("logoUrl"),
                "headerBg":    shared_brand.get("headerBg")    or default_color or d.get("headerBg"),
                "accentColor": shared_brand.get("accentColor") or default_color or d.get("accentColor"),
                "btnBg":       shared_brand.get("headerBg")    or default_color or d.get("btnBg"),
            }
        if template_brand.get("heroUrl") and hero_source.get("showHero") is not False:
            hero_source = {**hero_source, "showHero": True, "heroUrl": template_brand["heroUrl"]}
            hero_link_url = template_brand.get("videoUrl")  # dealer's own video takes over; none = no link

    body_resolved = _linkify_markdown(
        _resolve_merge_tags(template.get("body") or "", guest, event, registration_url, d),
        d.get("accentColor") or "#b8924a"
    )
    body_html = "".join(
        f'<p style="margin:0 0 14px 0">{line}</p>' if line.strip() else '<p style="margin:0 0 8px 0">&nbsp;</p>'
        for line in body_resolved.split("\n")
    )

    logo_img_html = f'<img src="{d["logoUrl"]}" style="height:{d["logoHeight"]}px;" alt="">' if d.get("logoUrl") else ""
    name_html = f'<div style="font-family:{d["fontFamily"]};font-size:19px;font-weight:700;color:{d["headerColor"]};letter-spacing:0.02em;">{event.get("name","")}</div>'
    logo_html = f'{logo_img_html}<div style="margin-top:{"10px" if logo_img_html else "0"};">{name_html}</div>' if logo_img_html else name_html
    hero_img_tag = f'<img src="{hero_source.get("heroUrl")}" width="600" style="display:block;width:100%;height:auto;" alt="">'
    if hero_link_url:
        hero_content = f'<a href="{hero_link_url}" style="display:block;text-decoration:none;">{hero_img_tag}</a>'
    else:
        hero_content = hero_img_tag
    hero_html = (
        f'<tr><td style="padding:0;">{hero_content}</td></tr>'
        if (hero_source.get("showHero") and hero_source.get("heroUrl")) else ""
    )
    video_caption_html = (
        f'<tr><td style="padding:10px 32px 0;text-align:center;"><a href="{hero_link_url}" style="font-size:13px;color:{d["accentColor"]};text-decoration:none;font-weight:600;">&#9654; Přehrát video</a></td></tr>'
        if (hero_source.get("showHero") and hero_source.get("heroUrl") and hero_link_url) else ""
    )
    button_html = (
        f'''<div style="text-align:center;margin-top:28px;">
          <a href="{registration_url}" style="display:inline-block;background:{d['btnBg']};color:{d['btnColor']};text-decoration:none;padding:13px 32px;border-radius:{d['borderRadius']};font-size:15px;font-weight:600;letter-spacing:0.02em;">{d.get('btnText') or 'Potvrdit účast'}</a>
        </div>'''
        if template.get("showButton", d.get("showButton")) else ""
    )

    return f"""
    <div style="font-family:{d['fontFamily']};background:{d['bgColor']};padding:24px 0;">
      <div style="max-width:520px;margin:0 auto;background:{d['containerBg']};border-radius:{d['borderRadius']};overflow:hidden;border:1px solid #ddd9d0;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
          {hero_html}
          {video_caption_html}
          <tr><td style="background:{d['headerBg']};padding:26px 32px;text-align:{d['logoAlign']};">{logo_html}</td></tr>
          <tr><td style="padding:32px;">
            <div style="font-size:{d['fontSize']};color:{d['bodyColor']};line-height:1.7;">
              {body_html}
            </div>
            {button_html}
          </td></tr>
          <tr><td style="padding:20px 32px 24px;border-top:1px solid #eeeeee;text-align:center;">
            <p style="margin:0;font-size:11px;color:#999999;">© {datetime.now().year} Autorion s.r.o. · {f'<a href="https://registration.autorion.net/unsubscribe.html?token={guest["invite_token"]}" style="color:#999999;">Odhlásit odběr</a>' if guest.get("invite_token") else "Odhlásit odběr"}</p>
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
    info_page: Optional[dict] = None
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
    gdpr_consent: bool = False  # GDPR checkbox agreed at registration — separate from the on-site check-in signature (consent_signed)
    company: Optional[str] = None  # 'albion' | 'cardion' | 'orbion'
    send_confirmation: bool = True  # public registration always wants this; admin "add guest" forms can opt out
    walk_in: bool = False  # added on-site by check-in staff, without prior registration
    language: Optional[str] = None  # 'cs' | 'en' — language the registration form was filled in

class InviteCompleteRequest(BaseModel):
    phone: Optional[str] = None
    companion: bool = False
    window_id: Optional[int] = None
    bookings: List[BookingItem] = []
    gdpr_consent: bool = False
    # Only sent when the registration form let the guest fill these in
    # themselves (i.e. they were empty on file — e.g. an e-mail-only
    # import) — the frontend never sends these when the fields were
    # already locked with an existing value.
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    language: Optional[str] = None  # 'cs' | 'en'

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
    companion_will_drive: Optional[bool] = None
    companion_first_name: Optional[str] = None
    companion_last_name: Optional[str] = None
    companion_email: Optional[str] = None
    companion_license: Optional[str] = None
    companion_consent_signed: Optional[bool] = None
    companion_consent_signature: Optional[str] = None  # base64 PNG data URL
    language: Optional[str] = None  # 'cs' | 'en'

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
    # Global e-mail blacklist — applies across ALL events, not just one, so
    # someone who should never be contacted again stays excluded even for
    # future events they might otherwise get imported/invited into.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_blacklist (
            email VARCHAR(255) PRIMARY KEY,
            reason TEXT DEFAULT '',
            added_at TIMESTAMP DEFAULT NOW(),
            added_by VARCHAR(255) DEFAULT NULL
        );
    """)
    # Small global key-value settings store — currently used for the list of
    # test-send e-mail addresses (comma-separated string under key
    # 'test_emails'), shared across admins/devices.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key VARCHAR(100) PRIMARY KEY,
            value TEXT DEFAULT ''
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
            info_page JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    # Migration: archive support (safe on existing tables — no-op if columns already exist)
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP DEFAULT NULL;")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS archive_meta JSONB DEFAULT '{}';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS vehicles JSONB DEFAULT '[]';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS email_templates JSONB DEFAULT '[]';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS email_design JSONB DEFAULT '{}';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS info_page JSONB DEFAULT '{}';")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS landing_page_views INTEGER DEFAULT 0;")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS landing_page_views_noreg INTEGER DEFAULT 0;")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS registration_page_views INTEGER DEFAULT 0;")
    cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS registration_page_views_invite INTEGER DEFAULT 0;")
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
            consent_license TEXT DEFAULT '', -- holds the encrypted (Fernet) value, much longer than the raw number
            consent_signature TEXT DEFAULT NULL,
            consent_signature_at TIMESTAMP DEFAULT NULL,
            walk_in BOOLEAN DEFAULT FALSE,
            invite_token VARCHAR(64) UNIQUE,
            last_email_sent_at TIMESTAMP DEFAULT NULL,
            gdpr_consent BOOLEAN DEFAULT FALSE,
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
    # Separate from consent_signed (the on-site check-in signature) — this
    # tracks the GDPR checkbox agreed to during registration, which used to
    # incorrectly share the same column, making every self-registered guest
    # look like they'd already signed the on-site consent at check-in.
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS gdpr_consent BOOLEAN DEFAULT FALSE;")
    # confirmed_at: when a guest's status became 'confirmed'. Set by a trigger
    # (below) rather than in each individual code path (invite completion,
    # admin edit, walk-in creation, ...) so it can never be missed by a path
    # we forget to update by hand.
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP DEFAULT NULL;")
    # unsubscribed_at: set only by the public unsubscribe link — distinct
    # from status='declined', which can also mean "never wanted to come" or
    # an admin manually marking someone as not attending. This lets the
    # admin tell apart guests who unsubscribed *after* already registering
    # (e.g. had a booking) from those who simply never planned to attend.
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS unsubscribed_at TIMESTAMP DEFAULT NULL;")
    # A companion is only asked for their own details when they'll ALSO be
    # driving — most companions never need this at all. License number and
    # signature are encrypted the same way as the main guest's.
    # Language the guest registered in ('cs' / 'en'; empty = unknown, treated as Czech).
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS language VARCHAR(5) DEFAULT '';")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_will_drive BOOLEAN DEFAULT FALSE;")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_first_name VARCHAR(255) DEFAULT '';")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_last_name VARCHAR(255) DEFAULT '';")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_email VARCHAR(255) DEFAULT '';")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_license TEXT DEFAULT '';")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_consent_signed BOOLEAN DEFAULT FALSE;")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_consent_signature TEXT DEFAULT NULL;")
    cur.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS companion_consent_signature_at TIMESTAMP DEFAULT NULL;")
    # consent_license used to hold the raw (short) licence number as
    # VARCHAR(50) — now that it's encrypted (Fernet), the ciphertext is much
    # longer than the original number and needs a column without that limit.
    cur.execute("ALTER TABLE guests ALTER COLUMN consent_license TYPE TEXT;")
    cur.execute("ALTER TABLE guests ALTER COLUMN companion_license TYPE TEXT;")
    cur.execute("""
        CREATE OR REPLACE FUNCTION set_guest_confirmed_at() RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.status = 'confirmed' AND (OLD IS NULL OR OLD.status IS DISTINCT FROM 'confirmed') THEN
                NEW.confirmed_at := NOW();
            END IF;
            -- Deliberately NOT clearing confirmed_at when status later moves
            -- away from 'confirmed' (e.g. someone unsubscribes afterwards) —
            -- it's a historical record ("they WERE confirmed at some point"),
            -- which is exactly what's needed to tell apart "confirmed, then
            -- unsubscribed" from "declined from the very start".
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    cur.execute("DROP TRIGGER IF EXISTS trg_guest_confirmed_at ON guests;")
    cur.execute("""
        CREATE TRIGGER trg_guest_confirmed_at
        BEFORE INSERT OR UPDATE OF status ON guests
        FOR EACH ROW EXECUTE FUNCTION set_guest_confirmed_at();
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

def get_current_user_optional(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    """Like get_current_user, but returns None instead of raising when not
    logged in — for endpoints that are public but behave differently (or
    restrict certain fields) when the caller IS authenticated."""
    if not credentials or credentials.credentials not in sessions:
        return None
    return sessions[credentials.credentials]

@app.get("/api/auth/me")
def get_me(user=Depends(get_current_user)):
    """Lets the frontend resume a session after a page reload using just the
    stored token, instead of forcing a fresh login every time."""
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "checkin_access": user["checkin_access"],
    }

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
    cur.execute(
        "UPDATE events SET registration_page_views = COALESCE(registration_page_views, 0) + 1 "
        "WHERE slug = %s AND registration_open = TRUE RETURNING *",
        (slug,)
    )
    event = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    return dict(event)

@app.get("/api/events/landing/{slug}")
def get_event_landing(slug: str, reg: str = None, lang: str = None):
    """Public landing page data — does not require registration_open, since
    the info page can exist independently of whether registration is live.
    Tracks visits to the two link variants separately: the generic link
    (with the register button, e.g. for partners) vs. the ?reg=0 link sent
    to people who already have a personal registration link by e-mail."""
    column = "landing_page_views_noreg" if reg == "0" else "landing_page_views"
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        f"UPDATE events SET {column} = COALESCE({column}, 0) + 1 WHERE slug = %s RETURNING *",
        (slug,)
    )
    event = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    event = dict(event)

    # Custom HTML landing pages can have a separate English version — only
    # the language actually being viewed is sent back, not both, so a
    # bilingual page with its own embedded images doesn't double the
    # payload size for every visitor.
    lp = event.get("landing_page") or {}
    if isinstance(lp, dict) and lp.get("useCustomHtml"):
        lp = dict(lp)
        if lang == "en" and lp.get("customHtmlEn"):
            lp["customHtml"] = lp["customHtmlEn"]
        lp.pop("customHtmlEn", None)
        event["landing_page"] = lp

    return event

@app.get("/api/events/info/{slug}")
def get_event_info(slug: str, lang: str = None):
    """Public info page for confirmed guests — venue map, vehicles on-site,
    and other on-the-day details. Linked from e-mails via {{info_page_link}},
    not meant to be discovered on its own, so no visit tracking here."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM events WHERE slug = %s", (slug,))
    event = cur.fetchone()
    cur.close()
    conn.close()
    if not event:
        raise HTTPException(status_code=404, detail="Akce nenalezena")
    event = dict(event)

    # Same language-stripping as the landing page — only the language
    # actually being viewed is sent back, not both.
    ip = event.get("info_page") or {}
    if isinstance(ip, dict) and ip.get("useCustomHtml"):
        ip = dict(ip)
        if lang == "en" and ip.get("customHtmlEn"):
            ip["customHtml"] = ip["customHtmlEn"]
        ip.pop("customHtmlEn", None)
        event["info_page"] = ip

    return event

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
    json_fields = {"theme", "time_windows", "vehicles", "landing_page", "info_page", "email_templates", "email_design"}
    # landing_page (and info_page, same reasoning) is edited independently
    # from two different screens (Visual Editor's hero/sections, and the
    # Nastavení "show register button" toggle). A plain overwrite lets
    # whichever one saves last silently wipe out the other's changes if its
    # local copy is stale. A shallow JSONB merge (old || new) keeps existing
    # top-level keys the caller didn't touch, instead of relying on the
    # client to have a fully up-to-date copy.
    shallow_merge_fields = {"landing_page", "info_page"}
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
def get_guests(event_id: int, status: str = None, checkin: bool = False, user=Depends(get_current_user)):
    """`status` optionally filters server-side (e.g. status=confirmed).
    `checkin=true` is a purpose-built filter for check-in day: confirmed
    guests, PLUS anyone who unsubscribed from e-mails after already having
    a booking/window assigned — unsubscribing only opts them out of further
    e-mails, it doesn't mean they're not coming. A guest who was declined
    any other way (admin-set, or self-declined without ever booking) is
    still excluded, since they're not expected on-site."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if checkin:
        cur.execute(
            f"SELECT {GUEST_SAFE_COLUMNS} FROM guests WHERE event_id = %s AND ("
            f"status = 'confirmed' OR "
            f"(unsubscribed_at IS NOT NULL AND (window_id IS NOT NULL OR bookings != '[]'::jsonb))"
            f") ORDER BY last_name",
            (event_id,)
        )
    elif status:
        cur.execute(f"SELECT {GUEST_SAFE_COLUMNS} FROM guests WHERE event_id = %s AND status = %s ORDER BY last_name", (event_id, status))
    else:
        cur.execute(f"SELECT {GUEST_SAFE_COLUMNS} FROM guests WHERE event_id = %s ORDER BY last_name", (event_id,))
    guests = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(g) for g in guests]

def _check_booking_and_window_availability(cur, event_id, bookings_list, window_id, exclude_guest_id=None, skip_window_capacity=False):
    """Raises HTTPException(409, ...) on a real conflict. Shared by both the
    'new guest' (create) and 'complete my invite' (update) flows so a guest
    completing their own invite doesn't collide with a slot/window that
    only THEY already provisionally hold.

    skip_window_capacity=True lets a walk-in guest added on-site bypass the
    time-window headcount limit — staff has already physically decided to
    let the person in, so the system shouldn't second-guess that with a
    capacity number. The specific-vehicle/time-slot collision check below
    still applies either way, since double-booking the same car at the same
    time is a real scheduling conflict, not just a soft limit."""
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

    if window_id is not None and not skip_window_capacity:
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

def _norm_lang(value):
    """Only 'cs' / 'en' are stored; anything else becomes empty (= unknown)."""
    v = (value or "").strip().lower()
    return v if v in ("cs", "en") else ""

@app.post("/api/events/{event_id}/guests")
def create_guest(event_id: int, guest: GuestCreate, user=Depends(get_current_user_optional)):
    # walk_in=True both bypasses window capacity AND skips the normal
    # confirmation flow — it must only be settable by an authenticated
    # check-in staff member, never by an anonymous call to this otherwise
    # public registration endpoint.
    if guest.walk_in and not user:
        raise HTTPException(status_code=401, detail="Přidání hosta bez registrace vyžaduje přihlášení.")
    conn = get_db()
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Lock guests rows for this event to avoid race conditions on slot booking
        cur.execute("LOCK TABLE guests IN SHARE ROW EXCLUSIVE MODE")

        bookings_list = [b.dict() for b in guest.bookings]
        _check_booking_and_window_availability(cur, event_id, bookings_list, guest.window_id, skip_window_capacity=guest.walk_in)

        invite_token = secrets.token_urlsafe(24)
        cur.execute(f"""
            INSERT INTO guests (event_id, first_name, last_name, email, phone, companion, status, window_id, bookings, gdpr_consent, company, invite_token, walk_in, language)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {GUEST_SAFE_COLUMNS}
        """, (
            event_id, guest.first_name, guest.last_name, guest.email.lower(), guest.phone or '',
            guest.companion, guest.status, guest.window_id,
            json.dumps(bookings_list), guest.gdpr_consent, guest.company or '', invite_token, guest.walk_in,
            _norm_lang(guest.language)
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
    if not guest:
        cur.close(); conn.close()
        raise HTTPException(status_code=404, detail="Pozvánka nenalezena nebo již není platná.")
    cur.execute(
        "UPDATE events SET registration_page_views_invite = COALESCE(registration_page_views_invite, 0) + 1 WHERE id = %s",
        (ev["id"],)
    )
    conn.commit()
    cur.close(); conn.close()
    return dict(guest)

@app.get("/api/guests/unsubscribe/{token}")
def unsubscribe_guest(token: str):
    """Public, unauthenticated: lets a guest opt out of further e-mails by
    marking their RSVP as declined ('Nemůže přijít') — reuses the existing
    status the admin already tracks, and the default recipient group for
    most templates ('Všichni kromě odmítnutých') already excludes it, so no
    separate opt-out flag is needed for sending. unsubscribed_at is set
    alongside it so the admin can still tell apart someone who unsubscribed
    (possibly after already registering) from a plain admin-set decline."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "UPDATE guests SET status = 'declined', unsubscribed_at = NOW() WHERE invite_token = %s RETURNING first_name, last_name, event_id, email",
        (token,)
    )
    guest = cur.fetchone()
    if not guest:
        cur.close(); conn.close()
        raise HTTPException(status_code=404, detail="Odkaz nenalezen nebo již není platný.")
    if guest.get("email"):
        cur.execute(
            "INSERT INTO email_blacklist (email, reason, added_by) VALUES (%s, %s, %s) ON CONFLICT (email) DO NOTHING",
            (guest["email"].strip().lower(), "Odhlásil se z e-mailů přes odkaz v e-mailu", "systém (unsubscribe)")
        )
    cur.execute("SELECT name FROM events WHERE id = %s", (guest["event_id"],))
    ev = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    return {"first_name": guest["first_name"], "last_name": guest["last_name"], "event_name": ev["name"] if ev else ""}

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
                gdpr_consent = %s, status = 'confirmed',
                first_name = COALESCE(NULLIF(%s, ''), first_name),
                last_name  = COALESCE(NULLIF(%s, ''), last_name),
                language   = COALESCE(NULLIF(%s, ''), language)
            WHERE id = %s
            RETURNING {GUEST_SAFE_COLUMNS}
        """, (req.phone or '', req.companion, req.window_id, json.dumps(bookings_list), req.gdpr_consent,
              req.first_name or '', req.last_name or '', _norm_lang(req.language), guest_id))
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
    if "language" in fields:
        fields["language"] = _norm_lang(fields["language"])

    # The signature and the driver's license number are both encrypted
    # before they ever touch the database — popped out of the generic
    # fields loop so they get special (encrypted) handling instead of
    # being stored raw. Same treatment for the companion's own signature
    # and license, when the companion will also be driving.
    raw_signature = fields.pop("consent_signature", None)
    raw_license   = fields.pop("consent_license", None)
    raw_c_signature = fields.pop("companion_consent_signature", None)
    raw_c_license   = fields.pop("companion_license", None)

    set_parts = [f"{k} = %s" for k in fields.keys()]
    values = list(fields.values())
    if raw_signature is not None:
        set_parts.append("consent_signature = %s")
        set_parts.append("consent_signature_at = NOW()")
        values.append(encrypt_signature(raw_signature))
    if raw_license is not None:
        set_parts.append("consent_license = %s")
        values.append(encrypt_sensitive(raw_license) if raw_license else "")
    if raw_c_signature is not None:
        set_parts.append("companion_consent_signature = %s")
        set_parts.append("companion_consent_signature_at = NOW()")
        values.append(encrypt_signature(raw_c_signature))
    if raw_c_license is not None:
        set_parts.append("companion_license = %s")
        values.append(encrypt_sensitive(raw_c_license) if raw_c_license else "")

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

@app.get("/api/guests/{guest_id}/license")
def get_guest_license(guest_id: int, user=Depends(get_current_user)):
    """Dedicated, explicit-only route for viewing a guest's driver's licence
    number — same reasoning as the signature route: kept separate from every
    other guest endpoint so it's never fetched by accident, and deliberately
    left out of GUEST_SAFE_COLUMNS."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT consent_license, first_name, last_name FROM guests WHERE id = %s", (guest_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    if not row["consent_license"]:
        return {"guest_id": guest_id, "first_name": row["first_name"], "last_name": row["last_name"], "license_number": ""}
    return {
        "guest_id": guest_id,
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "license_number": decrypt_sensitive(row["consent_license"]),
    }

@app.get("/api/guests/{guest_id}/companion")
def get_guest_companion(guest_id: int, user=Depends(get_current_user)):
    """Dedicated, explicit-only route for viewing a companion's licence
    number and signed consent — same reasoning as the main guest's routes."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT companion_will_drive, companion_first_name, companion_last_name, companion_email, "
        "companion_license, companion_consent_signed, companion_consent_signature, companion_consent_signature_at "
        "FROM guests WHERE id = %s",
        (guest_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Host nenalezen")
    return {
        "guest_id": guest_id,
        "will_drive": row["companion_will_drive"],
        "first_name": row["companion_first_name"] or "",
        "last_name": row["companion_last_name"] or "",
        "email": row["companion_email"] or "",
        "license_number": decrypt_sensitive(row["companion_license"]) if row["companion_license"] else "",
        "consent_signed": row["companion_consent_signed"],
        "signature": decrypt_signature(row["companion_consent_signature"]) if row["companion_consent_signature"] else None,
        "signed_at": row["companion_consent_signature_at"],
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
    each one to Ecomail and reports back how many actually went out.
    Blacklisted addresses are always excluded here too, as a backend
    safety net independent of whatever the frontend filtered out."""
    if not ECOMAIL_API_KEY or ECOMAIL_API_KEY == "changeme":
        raise HTTPException(status_code=503, detail="Ecomail není nakonfigurovaný (chybí API klíč na serveru).")
    if not req.items:
        raise HTTPException(status_code=400, detail="Žádní příjemci k odeslání")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT email FROM email_blacklist")
    blacklisted = {row[0].lower() for row in cur.fetchall()}
    cur.close(); conn.close()

    sent = 0
    blocked = 0
    for item in req.items:
        if item.email.lower() in blacklisted:
            blocked += 1
            continue
        if send_ecomail_transactional(item.email, item.name, item.subject, item.html):
            sent += 1
            _mark_guest_emailed(item.guest_id)
    return {"sent": sent, "failed": len(req.items) - sent - blocked, "blocked": blocked, "total": len(req.items)}

@app.get("/api/health")
def health():
    return {"status": "healthy", "time": str(datetime.now())}

@app.get("/api/blacklist")
def get_blacklist(user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT email, reason, added_at, added_by FROM email_blacklist ORDER BY added_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return [dict(r) for r in rows]

class BlacklistAddRequest(BaseModel):
    emails: List[str]
    reason: str = ""

@app.post("/api/blacklist")
def add_to_blacklist(req: BlacklistAddRequest, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    added = 0
    for raw in req.emails:
        email = (raw or "").strip().lower()
        if not email:
            continue
        cur.execute(
            "INSERT INTO email_blacklist (email, reason, added_by) VALUES (%s, %s, %s) "
            "ON CONFLICT (email) DO UPDATE SET reason = EXCLUDED.reason",
            (email, req.reason, user.get("email"))
        )
        added += 1
    conn.commit()
    cur.close(); conn.close()
    return {"added": added}

@app.delete("/api/blacklist/{email}")
def remove_from_blacklist(email: str, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM email_blacklist WHERE email = %s", (email.strip().lower(),))
    deleted = cur.rowcount
    conn.commit()
    cur.close(); conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="E-mail není na blacklistu")
    return {"status": "removed", "email": email}

@app.get("/api/settings/test-emails")
def get_test_emails(user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT value FROM app_settings WHERE key = 'test_emails'")
    row = cur.fetchone()
    cur.close(); conn.close()
    return {"emails": row[0] if row else ""}

class TestEmailsRequest(BaseModel):
    emails: str

@app.put("/api/settings/test-emails")
def set_test_emails(req: TestEmailsRequest, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO app_settings (key, value) VALUES ('test_emails', %s) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        (req.emails,)
    )
    conn.commit()
    cur.close(); conn.close()
    return {"status": "saved"}
