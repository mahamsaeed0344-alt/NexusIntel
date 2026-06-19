"""
NEXUS INTEL — Criminal Face Detection & Recognition System v2
All features: threat scoring, email/SMS alerts, video upload, face compare,
network graph, watchlist, theme toggle, user management, scheduled reports.
Run: python app.py
"""
import os, io, csv, json, time, base64, pickle, sqlite3, uuid, smtplib
import threading, datetime as dt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from functools import wraps
from pathlib import Path

import cv2
import numpy as np
import requests
from PIL import Image
from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, send_file, session, flash, abort, Response)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    import face_recognition
    FACE_REC_OK = True
except Exception as e:
    print("[WARN] face_recognition not available:", e)
    FACE_REC_OK = False

# ── Paths & Config ─────────────────────────────────────────────────────────
BASE          = Path(__file__).resolve().parent
CFG           = json.loads((BASE / "config.json").read_text())
DB_PATH       = BASE / "database" / "criminals.db"
MUGSHOT_DIR   = BASE / "criminal_images"
UPLOAD_DIR    = BASE / "uploads"
DETECT_LIVE   = BASE / "detected" / "live"
DETECT_UPLOAD = BASE / "detected" / "uploaded"
DETECT_VIDEO  = BASE / "detected" / "video"
REPORT_DIR    = BASE / "reports"
LOG_DIR       = BASE / "logs"
MODEL_PATH    = BASE / "models" / "encodings.pkl"

for p in [DB_PATH.parent, MUGSHOT_DIR, UPLOAD_DIR, DETECT_LIVE, DETECT_UPLOAD,
          DETECT_VIDEO, REPORT_DIR, LOG_DIR, MODEL_PATH.parent]:
    p.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "detections.txt"

app = Flask(__name__)
app.secret_key = CFG.get("secret_key", "dev-secret")
app.config["MAX_CONTENT_LENGTH"] = CFG.get("max_upload_mb", 64) * 1024 * 1024

# ── CRIME SEVERITY MAP (for threat scoring) ────────────────────────────────
CRIME_SEVERITY = {
    "murder": 10, "homicide": 10, "terrorism": 10, "kidnapping": 9,
    "rape": 9, "sexual assault": 9, "armed robbery": 8, "robbery": 7,
    "arson": 7, "drug trafficking": 7, "human trafficking": 9,
    "assault": 6, "fraud": 5, "theft": 4, "burglary": 5,
    "drug possession": 4, "extortion": 6, "money laundering": 6,
    "cybercrime": 5, "forgery": 4, "other": 3, "unknown": 2,
}

# ── DB ──────────────────────────────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            email TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS criminals(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            cnic TEXT,
            dob TEXT,
            nationality TEXT,
            crime_type TEXT,
            status TEXT DEFAULT 'Wanted',
            priority INTEGER DEFAULT 0,
            threat_score REAL DEFAULT 0,
            notes TEXT,
            arrest_history TEXT,
            created_at TEXT NOT NULL,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS mugshots(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            criminal_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            FOREIGN KEY(criminal_id) REFERENCES criminals(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS detections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_uid TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL,
            criminal_id INTEGER,
            name TEXT NOT NULL,
            confidence REAL,
            snapshot_path TEXT,
            lat REAL, lon REAL,
            city TEXT, address TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(criminal_id) REFERENCES criminals(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT, action TEXT, detail TEXT, timestamp TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts_sent(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            criminal_id INTEGER,
            channel TEXT,
            sent_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS network_links(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            criminal_id_a INTEGER NOT NULL,
            criminal_id_b INTEGER NOT NULL,
            co_detections INTEGER DEFAULT 1,
            last_together TEXT,
            UNIQUE(criminal_id_a, criminal_id_b)
        );
        """)
        # Migrate: add missing columns gracefully
        for col, defn in [
            ("criminals", "priority INTEGER DEFAULT 0"),
            ("criminals", "threat_score REAL DEFAULT 0"),
            ("criminals", "dob TEXT DEFAULT ''"),
            ("criminals", "nationality TEXT DEFAULT ''"),
            ("criminals", "last_seen TEXT"),
            ("users", "role TEXT DEFAULT 'viewer'"),
            ("users", "email TEXT DEFAULT ''"),
            ("users", "active INTEGER DEFAULT 1"),
        ]:
            table, col_def = col, defn
            col_name = col_def.split()[0]
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
            except Exception:
                pass
        # Default admin
        if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            c.execute(
                "INSERT INTO users(username,password_hash,role,email,active,created_at)"
                " VALUES (?,?,?,?,?,?)",
                ("admin", generate_password_hash("admin123"),
                 "admin", "", 1, now_iso())
            )

def now_iso():
    return dt.datetime.now().isoformat(timespec="seconds")

def audit(action, detail=""):
    with db() as c:
        c.execute("INSERT INTO audit(user,action,detail,timestamp) VALUES (?,?,?,?)",
                  (session.get("user", "system"), action, detail, now_iso()))

def log_detection(line):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ── THREAT SCORING ─────────────────────────────────────────────────────────
def compute_threat_score(cid):
    """Score 0-10 based on crime severity + detection frequency + recency."""
    with db() as c:
        row = c.execute("SELECT crime_type, status, last_seen FROM criminals WHERE id=?", (cid,)).fetchone()
        if not row:
            return 0.0
        det_count = c.execute("SELECT COUNT(*) n FROM detections WHERE criminal_id=?", (cid,)).fetchone()["n"]

    crime = (row["crime_type"] or "unknown").lower().strip()
    severity = 2.0
    for k, v in CRIME_SEVERITY.items():
        if k in crime:
            severity = float(v)
            break

    # Frequency factor (0-3 pts): more detections = higher score
    freq = min(3.0, det_count * 0.3)

    # Recency factor (0-2 pts): seen recently = higher score
    recency = 0.0
    if row["last_seen"]:
        try:
            delta = (dt.datetime.now() - dt.datetime.fromisoformat(row["last_seen"])).days
            recency = max(0.0, 2.0 - delta * 0.1)
        except Exception:
            pass

    # Status factor
    status_map = {"wanted": 1.0, "suspect": 0.5, "arrested": -0.5, "released": 0.0}
    status_f = status_map.get((row["status"] or "").lower(), 0.0)

    raw = severity * 0.5 + freq + recency + status_f
    score = round(max(0.0, min(10.0, raw)), 1)

    with db() as c:
        c.execute("UPDATE criminals SET threat_score=? WHERE id=?", (score, cid))
    return score

def recompute_all_threats():
    with db() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM criminals").fetchall()]
    for cid in ids:
        compute_threat_score(cid)

# ── AUTH ────────────────────────────────────────────────────────────────────
def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **k)
    return w

def admin_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required", "error")
            return redirect(url_for("dashboard"))
        return fn(*a, **k)
    return w

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        with db() as c:
            row = c.execute("SELECT * FROM users WHERE username=? AND active=1", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], p):
            session["user"] = u
            session["role"] = row["role"]
            session["theme"] = CFG.get("theme", "dark")
            audit("login")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid credentials or account disabled", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    old = request.form.get("old") or ""
    new = request.form.get("new") or ""
    if len(new) < 6:
        flash("New password must be at least 6 characters", "error")
        return redirect(url_for("dashboard"))
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
        if not row or not check_password_hash(row["password_hash"], old):
            flash("Current password incorrect", "error")
            return redirect(url_for("dashboard"))
        c.execute("UPDATE users SET password_hash=? WHERE id=?",
                  (generate_password_hash(new), row["id"]))
    audit("change_password")
    flash("Password updated", "success")
    return redirect(url_for("dashboard"))

@app.route("/theme/<t>")
@login_required
def set_theme(t):
    if t in ("dark", "light"):
        session["theme"] = t
    return redirect(request.referrer or url_for("dashboard"))

# ── USER MANAGEMENT ─────────────────────────────────────────────────────────
@app.route("/users")
@admin_required
def users_list():
    with db() as c:
        rows = c.execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("users.html", rows=rows)

@app.route("/users/add", methods=["POST"])
@admin_required
def user_add():
    u = (request.form.get("username") or "").strip()
    p = request.form.get("password") or ""
    r = request.form.get("role", "viewer")
    e = (request.form.get("email") or "").strip()
    if not u or len(p) < 6:
        flash("Username required and password min 6 chars", "error")
        return redirect(url_for("users_list"))
    try:
        with db() as c:
            c.execute("INSERT INTO users(username,password_hash,role,email,active,created_at) VALUES (?,?,?,?,1,?)",
                      (u, generate_password_hash(p), r, e, now_iso()))
        audit("add_user", u)
        flash(f"User '{u}' created", "success")
    except Exception:
        flash("Username already exists", "error")
    return redirect(url_for("users_list"))

@app.route("/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def user_toggle(uid):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if row and row["username"] != "admin":
            c.execute("UPDATE users SET active=? WHERE id=?", (0 if row["active"] else 1, uid))
            audit("toggle_user", f"id={uid}")
    return redirect(url_for("users_list"))

@app.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def user_delete(uid):
    with db() as c:
        row = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        if row and row["username"] != "admin":
            c.execute("DELETE FROM users WHERE id=?", (uid,))
            audit("delete_user", f"id={uid}")
    flash("User deleted", "success")
    return redirect(url_for("users_list"))

@app.route("/users/<int:uid>/role", methods=["POST"])
@admin_required
def user_role(uid):
    role = request.form.get("role", "viewer")
    with db() as c:
        row = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        if row and row["username"] != "admin":
            c.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
            audit("change_role", f"id={uid} role={role}")
    return redirect(url_for("users_list"))

# ── FACE MODEL ──────────────────────────────────────────────────────────────
_MODEL_CACHE = {"encodings": [], "meta": [], "loaded_at": 0}

def load_model(force=False):
    if not force and _MODEL_CACHE["loaded_at"] and MODEL_PATH.exists():
        return _MODEL_CACHE
    if MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        _MODEL_CACHE.update(data)
    else:
        _MODEL_CACHE["encodings"] = []
        _MODEL_CACHE["meta"] = []
    _MODEL_CACHE["loaded_at"] = time.time()
    return _MODEL_CACHE

def train_model():
    """
    Recompute face encodings using CNN model for better accuracy.
    Each mugshot uses multiple jitter passes to improve robustness.
    """
    if not FACE_REC_OK:
        return 0, "face_recognition library not installed"
    encs, meta = [], []
    with db() as c:
        rows = c.execute(
            "SELECT m.path, c.id, c.name, c.crime_type, c.status "
            "FROM mugshots m JOIN criminals c ON c.id=m.criminal_id"
        ).fetchall()
    count = 0
    for r in rows:
        p = BASE / r["path"]
        if not p.exists():
            continue
        try:
            img = face_recognition.load_image_file(str(p))
            # Resize large images for speed while preserving accuracy
            h, w = img.shape[:2]
            if max(h, w) > 1000:
                scale = 1000 / max(h, w)
                img = cv2.resize(img, (int(w*scale), int(h*scale)))
            # Use CNN model for training (more accurate than HOG)
            locs = face_recognition.face_locations(img, model="hog")
            if not locs:
                # fallback: try without location hint
                locs = face_recognition.face_locations(img, number_of_times_to_upsample=2, model="hog")
            if not locs:
                print(f"[train] no face found in {p.name}")
                continue
            # num_jitters=3 — good balance of accuracy vs speed (10 was too slow)
            enc_list = face_recognition.face_encodings(img, locs, num_jitters=3)
            for enc in enc_list:
                encs.append(enc)
                meta.append({
                    "criminal_id": r["id"], "name": r["name"],
                    "crime_type": r["crime_type"], "status": r["status"],
                })
                count += 1
        except Exception as e:
            print(f"[train] failed {p}: {e}")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"encodings": encs, "meta": meta}, f)
    _MODEL_CACHE.update({"encodings": encs, "meta": meta, "loaded_at": time.time()})
    return count, f"Trained on {count} face encodings from {len(rows)} mugshots"

def recognize_faces_bgr(bgr, num_jitters=1):
    """
    Improved face detection:
    - Auto-scales images for best detection size
    - Multi-upsample fallback for partial/small faces (e.g. person holding teddy bear)
    - Brightness/contrast normalization
    - Top-N voting across encodings for same criminal
    - Confidence = 1 - (best_distance / 0.55) * 100
    """
    if not FACE_REC_OK:
        return []

    # ── Pre-process for better detection ───────────────────────────────────
    rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
    h, w = rgb.shape[:2]

    # Normalize brightness/contrast (helps with dark or washed-out photos)
    lab = cv2.cvtColor(bgr, cv2.COLOR_BGR2LAB)
    l_ch, a_ch, b_ch = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    l_ch = clahe.apply(l_ch)
    lab = cv2.merge((l_ch, a_ch, b_ch))
    bgr_eq = cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)
    rgb_eq = cv2.cvtColor(bgr_eq, cv2.COLOR_BGR2RGB)

    # Scale to optimal detection size (600-1200px on longest side)
    scale = 1.0
    longest = max(h, w)
    if longest < 300:
        scale = 600 / longest      # upsample tiny images aggressively
    elif longest < 500:
        scale = 2.0                # small images get doubled
    elif longest > 1600:
        scale = 1200 / longest     # downsample huge images for speed

    if scale != 1.0:
        new_w, new_h = int(w * scale), int(h * scale)
        rgb_eq = cv2.resize(rgb_eq, (new_w, new_h),
                            interpolation=cv2.INTER_LANCZOS4 if scale>1 else cv2.INTER_AREA)

    # ── Detection: try multiple upsample levels ────────────────────────────
    locs = []
    for upsample in [1, 2]:
        locs = face_recognition.face_locations(rgb_eq, model="hog",
                                               number_of_times_to_upsample=upsample)
        if locs:
            break

    if not locs:
        # Last resort: try on original image with heavy upsampling
        locs = face_recognition.face_locations(rgb, model="hog",
                                               number_of_times_to_upsample=3)
        if locs:
            rgb_eq = rgb
            scale = 1.0

    if not locs:
        return []

    # Scale bounding boxes back to original image coordinates
    if scale != 1.0:
        locs = [(int(top/scale), int(right/scale), int(bottom/scale), int(left/scale))
                for top, right, bottom, left in locs]
        # Re-encode using original (unscaled) equalized image
        rgb_eq_orig = cv2.cvtColor(bgr_eq, cv2.COLOR_BGR2RGB)
    else:
        rgb_eq_orig = rgb_eq

    encs = face_recognition.face_encodings(rgb_eq_orig, locs, num_jitters=num_jitters)

    m = load_model()
    known = m["encodings"]
    meta  = m["meta"]
    tol   = float(CFG.get("recognition_tolerance", 0.45))
    out   = []

    for (top, right, bottom, left), enc in zip(locs, encs):
        name = "UNKNOWN PERSON"
        confidence = 0.0
        crim_id = None
        crime = None
        status = None
        threat = 0.0
        priority = 0

        if known:
            dists = face_recognition.face_distance(known, enc)
            i = int(np.argmin(dists))
            best = float(dists[i])

            # Better confidence formula: linear between 0-0.55 distance
            # 0.0 dist → 100%, 0.55 dist → 0%
            raw_conf = max(0.0, (1.0 - best / 0.55)) * 100.0
            confidence = round(min(100.0, raw_conf), 2)

            if best <= tol:
                name = meta[i]["name"]
                crim_id = meta[i]["criminal_id"]
                crime = meta[i]["crime_type"]
                status = meta[i]["status"]
                try:
                    with db() as conn:
                        row = conn.execute(
                            "SELECT threat_score, priority FROM criminals WHERE id=?",
                            (crim_id,)).fetchone()
                        if row:
                            threat = row["threat_score"] or 0.0
                            priority = row["priority"] or 0
                except Exception:
                    pass

        out.append({
            "box": [int(left), int(top), int(right), int(bottom)],
            "name": name, "confidence": round(confidence, 2),
            "criminal_id": crim_id, "crime_type": crime,
            "status": status, "threat_score": threat, "priority": priority,
        })
    return out

def draw_overlays(bgr, results):
    for r in results:
        l, t, rt, b = r["box"]
        known = r["name"] != "UNKNOWN PERSON"
        prio  = r.get("priority", 0)
        conf  = r["confidence"]
        # Colors: priority=bright red, known=red, unknown=amber
        color = (0, 20, 255) if prio else ((30, 30, 230) if known else (0, 165, 255))
        cv2.rectangle(bgr, (l, t), (rt, b), color, 3)
        # Confidence bar under box (only for known criminals)
        if known:
            bar_w = rt - l
            conf_w = int(bar_w * conf / 100)
            cv2.rectangle(bgr, (l, b+2), (rt, b+8), (30,30,30), -1)
            cv2.rectangle(bgr, (l, b+2), (l+conf_w, b+8), color, -1)
        # Label: unknown gets no confidence number
        if known:
            label = f'{r["name"]} {conf:.0f}%'
            if r.get("threat_score", 0) > 0:
                label += f' T:{r["threat_score"]:.0f}'
        else:
            label = "UNKNOWN PERSON"
        (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_DUPLEX, 0.55, 1)
        cv2.rectangle(bgr, (l, t-th-10), (l+tw+10, t), color, -1)
        cv2.putText(bgr, label, (l+5, t-5),
                    cv2.FONT_HERSHEY_DUPLEX, 0.55, (255,255,255), 1, cv2.LINE_AA)
    return bgr

# ── HELPERS ─────────────────────────────────────────────────────────────────
def allowed_image(fn):
    return "." in fn and fn.rsplit(".", 1)[1].lower() in CFG["allowed_image_ext"]

def allowed_video(fn):
    return "." in fn and fn.rsplit(".", 1)[1].lower() in CFG.get("allowed_video_ext", ["mp4","avi","mov","mkv"])

def save_snapshot(bgr, source, name, confidence, lat, lon, city, address, criminal_id=None):
    uid = uuid.uuid4().hex[:12]
    folder = DETECT_LIVE if source == "live" else (DETECT_VIDEO if source == "video" else DETECT_UPLOAD)
    fn = f"{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uid}.jpg"
    fp = folder / fn
    cv2.imwrite(str(fp), bgr)
    rel = str(fp.relative_to(BASE)).replace("\\", "/")
    with db() as c:
        c.execute(
            "INSERT INTO detections(detection_uid,source,criminal_id,name,confidence,"
            "snapshot_path,lat,lon,city,address,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, source, criminal_id, name, confidence, rel, lat, lon, city, address, now_iso())
        )
        if criminal_id:
            c.execute("UPDATE criminals SET last_seen=? WHERE id=?", (now_iso(), criminal_id))
    log_detection(f"{now_iso()} | {source} | {name} | {confidence:.1f}% | {city or '-'} | {lat},{lon} | {rel}")
    # Update network graph if multiple criminals in same detection batch
    return uid, rel

def update_network_links(criminal_ids):
    """Record co-detections between multiple criminals in the same image."""
    ids = [x for x in criminal_ids if x is not None]
    if len(ids) < 2:
        return
    for i in range(len(ids)):
        for j in range(i+1, len(ids)):
            a, b = min(ids[i], ids[j]), max(ids[i], ids[j])
            with db() as c:
                existing = c.execute(
                    "SELECT id,co_detections FROM network_links WHERE criminal_id_a=? AND criminal_id_b=?",
                    (a, b)
                ).fetchone()
                if existing:
                    c.execute(
                        "UPDATE network_links SET co_detections=co_detections+1, last_together=? WHERE id=?",
                        (now_iso(), existing["id"])
                    )
                else:
                    c.execute(
                        "INSERT INTO network_links(criminal_id_a,criminal_id_b,co_detections,last_together) VALUES (?,?,1,?)",
                        (a, b, now_iso())
                    )

# ── Cached server-side IP location (resolved once at startup) ──────────────
_ip_loc_cache = None

def ip_location_fallback():
    global _ip_loc_cache
    if _ip_loc_cache and _ip_loc_cache[0]:
        return _ip_loc_cache
    # Try multiple providers for reliability
    providers = [
        ("https://ipapi.co/json/",        lambda j: (j.get("latitude"), j.get("longitude"), j.get("city"), j.get("region"))),
        ("https://ip-api.com/json/",      lambda j: (j.get("lat"),      j.get("lon"),       j.get("city"), j.get("regionName"))),
        ("https://ipwho.is/",             lambda j: (j.get("latitude"), j.get("longitude"), j.get("city"), j.get("region"))),
    ]
    for url, extractor in providers:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "NexusIntel/2.0"})
            if r.ok:
                j = r.json()
                result = extractor(j)
                if result[0] is not None:
                    _ip_loc_cache = result
                    return result
        except Exception:
            continue
    # Pakistan default (Lahore) so map always has a point
    _ip_loc_cache = (31.5204, 74.3587, "Lahore", "Punjab")
    return _ip_loc_cache

def reverse_geocode(lat, lon):
    """Use Nominatim to get human-readable address from GPS coordinates."""
    try:
        url = (f"https://nominatim.openstreetmap.org/reverse"
               f"?format=json&lat={lat}&lon={lon}&zoom=16&addressdetails=1")
        r = requests.get(url, timeout=5, headers={"User-Agent": "NexusIntel/2.0"})
        if r.ok:
            j = r.json()
            addr = j.get("address", {})
            city = (addr.get("city") or addr.get("town") or addr.get("village")
                    or addr.get("county") or addr.get("state") or "Unknown")
            display = j.get("display_name", "")
            short_addr = ", ".join(display.split(", ")[:3]) if display else city
            return city, short_addr
    except Exception:
        pass
    return None, None

# ── EMAIL / SMS ALERTS ──────────────────────────────────────────────────────
_alert_cooldown = {}  # criminal_id -> last_sent timestamp

def should_send_alert(criminal_id):
    last = _alert_cooldown.get(criminal_id, 0)
    if time.time() - last > 300:  # 5 minute cooldown per criminal
        _alert_cooldown[criminal_id] = time.time()
        return True
    return False

def send_email_alert(name, confidence, city, snapshot_path=None):
    if not CFG.get("email_enabled"):
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = CFG["email_user"]
        msg["To"]   = ", ".join(CFG["email_recipients"])
        msg["Subject"] = f"🚨 NEXUS INTEL ALERT: {name} Detected"
        body = f"""
CRIMINAL DETECTION ALERT
========================
Name:       {name}
Confidence: {confidence:.1f}%
Location:   {city or 'Unknown'}
Time:       {now_iso()}
========================
This is an automated alert from NEXUS INTEL Criminal Detection System.
"""
        msg.attach(MIMEText(body, "plain"))
        if snapshot_path:
            sp = BASE / snapshot_path
            if sp.exists():
                with open(sp, "rb") as f:
                    img_data = f.read()
                att = MIMEApplication(img_data, Name="snapshot.jpg")
                att["Content-Disposition"] = 'attachment; filename="snapshot.jpg"'
                msg.attach(att)
        with smtplib.SMTP(CFG["email_host"], CFG["email_port"]) as s:
            s.starttls()
            s.login(CFG["email_user"], CFG["email_pass"])
            s.sendmail(CFG["email_user"], CFG["email_recipients"], msg.as_string())
        with db() as c:
            c.execute("INSERT INTO alerts_sent(criminal_id,channel,sent_at) VALUES (?,?,?)",
                      (None, "email", now_iso()))
        return True
    except Exception as e:
        print(f"[email] error: {e}")
        return False

def send_sms_alert(name, confidence, city):
    if not CFG.get("sms_enabled"):
        return False
    try:
        from twilio.rest import Client
        cl = Client(CFG["twilio_sid"], CFG["twilio_token"])
        body = f"NEXUS ALERT: {name} detected ({confidence:.0f}%) in {city or 'Unknown'} at {now_iso()}"
        for num in CFG.get("sms_recipients", []):
            cl.messages.create(body=body, from_=CFG["twilio_from"], to=num)
        with db() as c:
            c.execute("INSERT INTO alerts_sent(criminal_id,channel,sent_at) VALUES (?,?,?)",
                      (None, "sms", now_iso()))
        return True
    except Exception as e:
        print(f"[sms] error: {e}")
        return False

def trigger_alerts(result, snapshot_path=None):
    """Send email/SMS for a detected criminal if cooldown allows."""
    if not result.get("criminal_id"):
        return
    cid = result["criminal_id"]
    if not should_send_alert(cid):
        return
    name = result["name"]
    conf = result["confidence"]
    city = ""
    threading.Thread(
        target=lambda: (
            send_email_alert(name, conf, city, snapshot_path),
            send_sms_alert(name, conf, city)
        ), daemon=True
    ).start()

# ── SCHEDULED REPORTS ───────────────────────────────────────────────────────
def generate_daily_report_pdf():
    """Generate PDF and email it."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    bio = io.BytesIO()
    doc = SimpleDocTemplate(bio, pagesize=A4, title="Daily Detection Report")
    styles = getSampleStyleSheet()
    today = dt.date.today().isoformat()
    flow = [
        Paragraph(f"NEXUS INTEL — Daily Report ({today})", styles["Title"]),
        Paragraph(f"Generated: {now_iso()}", styles["Normal"]),
        Spacer(1, 12),
    ]
    with db() as c:
        rows = c.execute(
            "SELECT detection_uid,source,name,confidence,city,timestamp "
            "FROM detections WHERE substr(timestamp,1,10)=? ORDER BY id DESC",
            (today,)
        ).fetchall()
        stats = c.execute(
            "SELECT COUNT(*) total, "
            "SUM(CASE WHEN criminal_id IS NOT NULL THEN 1 ELSE 0 END) known,"
            "IFNULL(AVG(confidence),0) avg_conf FROM detections WHERE substr(timestamp,1,10)=?",
            (today,)
        ).fetchone()

    flow.append(Paragraph(
        f"Total: {stats['total']} | Known: {stats['known']} | "
        f"Avg Confidence: {stats['avg_conf']:.1f}%", styles["Normal"]))
    flow.append(Spacer(1, 8))

    data = [["UID", "Source", "Name", "Conf%", "City", "Time"]]
    for r in rows:
        data.append([r["detection_uid"], r["source"], r["name"],
                     f'{r["confidence"]:.1f}', r["city"] or "", r["timestamp"]])
    if len(data) > 1:
        t = Table(data, repeatRows=1, colWidths=[80, 55, 120, 40, 90, 100])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#020409")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor("#eef2f7")]),
        ]))
        flow.append(t)
    else:
        flow.append(Paragraph("No detections today.", styles["Normal"]))

    doc.build(flow)
    bio.seek(0)
    pdf_path = REPORT_DIR / f"daily_{today}.pdf"
    with open(pdf_path, "wb") as f:
        f.write(bio.read())
    bio.seek(0)

    # Email the report
    if CFG.get("email_enabled") and CFG.get("scheduler_enabled"):
        try:
            msg = MIMEMultipart()
            msg["From"] = CFG["email_user"]
            msg["To"]   = ", ".join(CFG["email_recipients"])
            msg["Subject"] = f"NEXUS INTEL Daily Report — {today}"
            msg.attach(MIMEText(f"Daily detection report for {today} is attached.", "plain"))
            bio2 = open(pdf_path, "rb").read()
            att = MIMEApplication(bio2, Name=f"report_{today}.pdf")
            att["Content-Disposition"] = f'attachment; filename="report_{today}.pdf"'
            msg.attach(att)
            with smtplib.SMTP(CFG["email_host"], CFG["email_port"]) as s:
                s.starttls()
                s.login(CFG["email_user"], CFG["email_pass"])
                s.sendmail(CFG["email_user"], CFG["email_recipients"], msg.as_string())
            print(f"[scheduler] Daily report emailed for {today}")
        except Exception as e:
            print(f"[scheduler] email error: {e}")
    return str(pdf_path)

def _scheduler_loop():
    """Background thread: send daily report at configured hour."""
    print("[scheduler] background thread started")
    while True:
        now = dt.datetime.now()
        target_hour = CFG.get("scheduler_report_hour", 7)
        next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
        if now >= next_run:
            next_run += dt.timedelta(days=1)
        wait = (next_run - now).total_seconds()
        time.sleep(wait)
        try:
            generate_daily_report_pdf()
            print(f"[scheduler] Daily report generated at {now_iso()}")
        except Exception as e:
            print(f"[scheduler] error: {e}")

# ── ROUTES ── PAGES ─────────────────────────────────────────────────────────
@app.route("/")
def root():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as c:
        total_crim = c.execute("SELECT COUNT(*) n FROM criminals").fetchone()["n"]
        total_det  = c.execute("SELECT COUNT(*) n FROM detections").fetchone()["n"]
        unknown    = c.execute("SELECT COUNT(*) n FROM detections WHERE criminal_id IS NULL").fetchone()["n"]
        avg_conf   = c.execute("SELECT IFNULL(AVG(confidence),0) a FROM detections").fetchone()["a"]
        recent     = c.execute("SELECT * FROM detections ORDER BY id DESC LIMIT 10").fetchall()
        watchlist  = c.execute(
            "SELECT c.*, COUNT(d.id) det_count FROM criminals c "
            "LEFT JOIN detections d ON d.criminal_id=c.id "
            "WHERE c.priority=1 GROUP BY c.id ORDER BY c.threat_score DESC LIMIT 5"
        ).fetchall()
    return render_template("dashboard.html",
        total_crim=total_crim, total_det=total_det, unknown=unknown,
        accuracy=round(avg_conf, 1), recent=recent, watchlist=watchlist)

@app.route("/live")
@login_required
def live_page():
    return render_template("live.html")

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_page():
    if request.method == "POST":
        files = request.files.getlist("images")
        if not files or (len(files)==1 and files[0].filename == ''):
            single = request.files.get("image")
            files  = [single] if single and single.filename else []
        files = [f for f in files if f and allowed_image(f.filename)]
        if not files:
            flash("Please choose at least one valid image (JPG/PNG/WEBP/BMP)", "error")
            return redirect(url_for("upload_page"))
        # Uploaded images have no real location — never attach fake/IP location
        lat, lon, city, addr = None, None, None, None
        all_results = []
        errors = []
        for f in files:
            try:
                fn = secure_filename(f.filename)
                sp = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{fn}"
                f.save(sp)
                bgr = cv2.imread(str(sp))
                if bgr is None:
                    errors.append(f"{fn}: cannot decode image")
                    continue
                results = recognize_faces_bgr(bgr, num_jitters=2)
                annotated = draw_overlays(bgr.copy(), results)
                cids = []
                for r in results:
                    save_snapshot(annotated, "uploaded", r["name"], r["confidence"],
                                  lat, lon, city, addr, criminal_id=r["criminal_id"])
                    cids.append(r["criminal_id"])
                    if r["criminal_id"]:
                        trigger_alerts(r)
                update_network_links(cids)
                out_name = f"annotated_{uuid.uuid4().hex[:8]}.jpg"
                cv2.imwrite(str(DETECT_UPLOAD / out_name), annotated)
                all_results.append({
                    "image_url": url_for("file_detected_uploaded", filename=out_name),
                    "filename": fn, "results": results,
                })
            except Exception as e:
                errors.append(f"{f.filename}: {str(e)}")
                app.logger.exception("Upload error")
        for err in errors:
            flash(err, "error")
        if not all_results:
            return redirect(url_for("upload_page"))
        return render_template("upload_result.html",
            all_results=all_results, lat=lat, lon=lon, city=city, addr=addr)
    return render_template("upload.html")

@app.route("/video", methods=["GET", "POST"])
@login_required
def video_page():
    if request.method == "POST":
        f = request.files.get("video")
        if not f or not allowed_video(f.filename):
            flash("Please choose a valid video file (MP4/AVI/MOV/MKV)", "error")
            return redirect(url_for("video_page"))
        fn  = secure_filename(f.filename)
        vp  = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{fn}"
        f.save(vp)
        interval  = max(1, int(request.form.get("interval", 30)))
        max_frames = int(request.form.get("max_frames", 200))
        # Uploaded videos have no real location — never attach fake/IP location
        lat, lon, city, addr = None, None, None, None
        cap = cv2.VideoCapture(str(vp))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 25
        detections_found = []
        frame_idx = 0
        processed = 0
        unique_criminals = set()

        while cap.isOpened() and processed < max_frames:
            ret, bgr = cap.read()
            if not ret:
                break
            if frame_idx % interval == 0:
                results = recognize_faces_bgr(bgr, num_jitters=1)
                if results:
                    annotated = draw_overlays(bgr.copy(), results)
                    ts_sec = frame_idx / fps if fps else 0
                    for r in results:
                        uid, rel = save_snapshot(annotated, "video",
                            r["name"], r["confidence"], lat, lon, city, addr,
                            criminal_id=r["criminal_id"])
                        detections_found.append({
                            "frame": frame_idx, "time_sec": round(ts_sec, 1),
                            "name": r["name"], "confidence": r["confidence"],
                            "criminal_id": r["criminal_id"], "uid": uid,
                            "image_url": url_for("file_by_rel", p=rel),
                        })
                        if r["criminal_id"]:
                            unique_criminals.add(r["criminal_id"])
                            trigger_alerts(r)
                processed += 1
            frame_idx += 1
        cap.release()
        update_network_links(list(unique_criminals))
        audit("video_scan", f"file={fn} frames={processed} detections={len(detections_found)}")
        return render_template("video_result.html",
            detections=detections_found, filename=fn,
            total_frames=total_frames, processed=processed)
    return render_template("video.html")

@app.route("/compare", methods=["GET", "POST"])
@login_required
def compare_page():
    result = None
    if request.method == "POST":
        f1 = request.files.get("face1")
        f2 = request.files.get("face2")
        if not f1 or not f2 or not allowed_image(f1.filename) or not allowed_image(f2.filename):
            flash("Please upload two valid images", "error")
            return redirect(url_for("compare_page"))
        if not FACE_REC_OK:
            flash("face_recognition library not installed", "error")
            return redirect(url_for("compare_page"))
        try:
            import io as _io
            img1 = face_recognition.load_image_file(_io.BytesIO(f1.read()))
            img2 = face_recognition.load_image_file(_io.BytesIO(f2.read()))
            enc1 = face_recognition.face_encodings(img1)
            enc2 = face_recognition.face_encodings(img2)
            if not enc1:
                flash("No face detected in Image 1", "error")
                return redirect(url_for("compare_page"))
            if not enc2:
                flash("No face detected in Image 2", "error")
                return redirect(url_for("compare_page"))
            dist = float(face_recognition.face_distance([enc1[0]], enc2[0])[0])
            sim = max(0.0, min(100.0, (1.0 - dist / 0.6) * 100.0))
            match = dist <= float(CFG.get("recognition_tolerance", 0.45))

            # Save thumbnails for display
            def img_to_b64(np_img):
                bgr = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)
                _, buf = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, 80])
                return base64.b64encode(buf).decode()

            result = {
                "distance": round(dist, 4),
                "similarity": round(sim, 1),
                "match": match,
                "img1_b64": img_to_b64(img1),
                "img2_b64": img_to_b64(img2),
                "faces1": len(enc1),
                "faces2": len(enc2),
            }
            audit("face_compare", f"sim={sim:.1f}% match={match}")
        except Exception as e:
            flash(f"Comparison error: {str(e)}", "error")
    return render_template("compare.html", result=result)

@app.route("/network")
@login_required
def network_page():
    with db() as c:
        links = c.execute(
            "SELECT nl.*, ca.name name_a, cb.name name_b, "
            "ca.crime_type crime_a, cb.crime_type crime_b, "
            "ca.threat_score ts_a, cb.threat_score ts_b "
            "FROM network_links nl "
            "JOIN criminals ca ON ca.id=nl.criminal_id_a "
            "JOIN criminals cb ON cb.id=nl.criminal_id_b "
            "ORDER BY nl.co_detections DESC LIMIT 200"
        ).fetchall()
        nodes_raw = c.execute(
            "SELECT c.id, c.name, c.crime_type, c.threat_score, c.status, c.priority, "
            "c.cnic, c.dob, c.nationality, c.last_seen, c.notes, "
            "COUNT(d.id) det_count, "
            "(SELECT path FROM mugshots WHERE criminal_id=c.id LIMIT 1) mugshot "
            "FROM criminals c LEFT JOIN detections d ON d.criminal_id=c.id "
            "GROUP BY c.id"
        ).fetchall()
    return render_template("network.html", links=[dict(l) for l in links],
                           nodes=[dict(n) for n in nodes_raw])

@app.route("/criminals")
@login_required
def criminals_list():
    q = (request.args.get("q") or "").strip()
    priority_only = request.args.get("priority") == "1"
    with db() as c:
        base_q = "SELECT c.*, COUNT(d.id) det_count FROM criminals c LEFT JOIN detections d ON d.criminal_id=c.id"
        if q and priority_only:
            rows = c.execute(base_q + " WHERE c.priority=1 AND (c.name LIKE ? OR c.cnic LIKE ? OR c.crime_type LIKE ?) GROUP BY c.id ORDER BY c.threat_score DESC",
                             (f"%{q}%",)*3).fetchall()
        elif q:
            rows = c.execute(base_q + " WHERE c.name LIKE ? OR c.cnic LIKE ? OR c.crime_type LIKE ? GROUP BY c.id ORDER BY c.id DESC",
                             (f"%{q}%",)*3).fetchall()
        elif priority_only:
            rows = c.execute(base_q + " WHERE c.priority=1 GROUP BY c.id ORDER BY c.threat_score DESC").fetchall()
        else:
            rows = c.execute(base_q + " GROUP BY c.id ORDER BY c.id DESC").fetchall()
        data = []
        for r in rows:
            mug = c.execute("SELECT path FROM mugshots WHERE criminal_id=? LIMIT 1", (r["id"],)).fetchone()
            d = dict(r)
            d["mugshot"] = mug["path"] if mug else None
            data.append(d)
    return render_template("criminals.html", rows=data, q=q, priority_only=priority_only)

@app.route("/criminals/add", methods=["GET", "POST"])
@login_required
def criminal_add():
    if request.method == "POST":
        try:
            name = (request.form.get("name") or "").strip()[:100]
            if not name:
                flash("Name is required", "error")
                return redirect(url_for("criminal_add"))
            cnic    = (request.form.get("cnic") or "").strip()[:50]
            crime   = (request.form.get("crime_type") or "").strip()[:100]
            status  = (request.form.get("status") or "Wanted").strip()[:30]
            notes   = (request.form.get("notes") or "").strip()[:1000]
            history = (request.form.get("arrest_history") or "").strip()[:1000]
            dob     = (request.form.get("dob") or "").strip()[:20]
            nation  = (request.form.get("nationality") or "").strip()[:60]
            priority= 1 if request.form.get("priority") else 0
            cid = None
            with db() as c:
                cur = c.execute(
                    "INSERT INTO criminals(name,cnic,crime_type,status,notes,arrest_history,"
                    "dob,nationality,priority,threat_score,created_at) VALUES (?,?,?,?,?,?,?,?,?,0,?)",
                    (name,cnic,crime,status,notes,history,dob,nation,priority,now_iso())
                )
                cid = cur.lastrowid
            # Save mugshots OUTSIDE the db transaction to avoid locking
            if cid:
                folder = MUGSHOT_DIR / str(cid)
                folder.mkdir(parents=True, exist_ok=True)
                saved_mugs = 0
                for f in request.files.getlist("mugshots"):
                    if not f or not f.filename:
                        continue
                    if allowed_image(f.filename):
                        try:
                            fn = secure_filename(f.filename)
                            if not fn:
                                fn = f"{uuid.uuid4().hex[:8]}.jpg"
                            sp = folder / f"{uuid.uuid4().hex[:6]}_{fn}"
                            f.save(str(sp))
                            rel = str(sp.relative_to(BASE)).replace("\\", "/")
                            with db() as c2:
                                c2.execute("INSERT INTO mugshots(criminal_id,path) VALUES (?,?)", (cid, rel))
                            saved_mugs += 1
                        except Exception as img_err:
                            app.logger.warning(f"[mugshot] could not save {f.filename}: {img_err}")
                    else:
                        flash(f"Skipped '{f.filename}' — unsupported format", "warning")
            audit("add_criminal", f"id={cid} name={name}")
            try:
                compute_threat_score(cid)
            except Exception as tse:
                app.logger.warning(f"[threat] non-fatal: {tse}")
            safe_retrain_background()
            flash(f"Criminal added successfully (id={cid}). Face model is retraining in the background — recognition will be ready in a few seconds.", "success")
            return redirect(url_for("criminals_list"))
        except Exception as e:
            app.logger.exception("criminal_add error")
            flash(f"Error saving criminal: {str(e)}", "error")
            return redirect(url_for("criminal_add"))
    return render_template("criminal_form.html", c=None, mugshots=[])

@app.route("/criminals/<int:cid>/edit", methods=["GET", "POST"])
@login_required
def criminal_edit(cid):
    with db() as c:
        row = c.execute("SELECT * FROM criminals WHERE id=?", (cid,)).fetchone()
        if not row:
            abort(404)
        mugs = c.execute("SELECT * FROM mugshots WHERE criminal_id=?", (cid,)).fetchall()
    if request.method == "POST":
        try:
            name    = (request.form.get("name") or "").strip()[:100]
            cnic    = (request.form.get("cnic") or "").strip()[:50]
            crime   = (request.form.get("crime_type") or "").strip()[:100]
            status  = (request.form.get("status") or "Wanted").strip()[:30]
            notes   = (request.form.get("notes") or "").strip()[:1000]
            hist    = (request.form.get("arrest_history") or "").strip()[:1000]
            dob     = (request.form.get("dob") or "").strip()[:20]
            nation  = (request.form.get("nationality") or "").strip()[:60]
            priority= 1 if request.form.get("priority") else 0
            with db() as c:
                c.execute("UPDATE criminals SET name=?,cnic=?,crime_type=?,status=?,notes=?,"
                          "arrest_history=?,dob=?,nationality=?,priority=? WHERE id=?",
                          (name,cnic,crime,status,notes,hist,dob,nation,priority,cid))
            folder = MUGSHOT_DIR / str(cid)
            folder.mkdir(parents=True, exist_ok=True)
            for f in request.files.getlist("mugshots"):
                if not f or not f.filename:
                    continue
                if allowed_image(f.filename):
                    try:
                        fn = secure_filename(f.filename)
                        if not fn:
                            fn = f"{uuid.uuid4().hex[:8]}.jpg"
                        sp = folder / f"{uuid.uuid4().hex[:6]}_{fn}"
                        f.save(str(sp))
                        rel = str(sp.relative_to(BASE)).replace("\\", "/")
                        with db() as c2:
                            c2.execute("INSERT INTO mugshots(criminal_id,path) VALUES (?,?)", (cid, rel))
                    except Exception as img_err:
                        app.logger.warning(f"[mugshot] could not save {f.filename}: {img_err}")
                else:
                    flash(f"Skipped '{f.filename}' — unsupported format", "warning")
            audit("edit_criminal", f"id={cid}")
            try:
                compute_threat_score(cid)
            except Exception as tse:
                app.logger.warning(f"[threat] non-fatal: {tse}")
            safe_retrain_background()
            flash("Criminal updated. Face model is retraining in the background — recognition will be ready in a few seconds.", "success")
            return redirect(url_for("criminals_list"))
        except Exception as e:
            app.logger.exception("criminal_edit error")
            flash(f"Error updating criminal: {str(e)}", "error")
    return render_template("criminal_form.html", c=row, mugshots=mugs)

def safe_retrain_background():
    """Run train_model() in a background thread without crashing the server."""
    def _run():
        try:
            train_model()
        except Exception as e:
            app.logger.warning(f"[train] background retrain failed: {e}")
    threading.Thread(target=_run, daemon=True).start()

@app.route("/criminals/<int:cid>/delete", methods=["POST"])
@login_required
def criminal_delete(cid):
    try:
        with db() as c:
            c.execute("DELETE FROM criminals WHERE id=?", (cid,))
        audit("delete_criminal", f"id={cid}")
    except Exception as e:
        app.logger.exception("criminal_delete error")
        flash(f"Error deleting criminal: {e}", "error")
        return redirect(url_for("criminals_list"))

    safe_retrain_background()
    flash("Criminal deleted — model retraining in background", "success")
    return redirect(url_for("criminals_list"))

@app.route("/criminals/<int:cid>/toggle_priority", methods=["POST"])
@login_required
def toggle_priority(cid):
    with db() as c:
        row = c.execute("SELECT priority FROM criminals WHERE id=?", (cid,)).fetchone()
        if row:
            c.execute("UPDATE criminals SET priority=? WHERE id=?", (0 if row["priority"] else 1, cid))
    return redirect(request.referrer or url_for("criminals_list"))

@app.route("/mugshot/<int:mid>/delete", methods=["POST"])
@login_required
def mugshot_delete(mid):
    cid = None
    try:
        with db() as c:
            row = c.execute("SELECT * FROM mugshots WHERE id=?", (mid,)).fetchone()
            if row:
                try: (BASE / row["path"]).unlink(missing_ok=True)
                except Exception: pass
                cid = row["criminal_id"]
                c.execute("DELETE FROM mugshots WHERE id=?", (mid,))
    except Exception as e:
        app.logger.exception("mugshot_delete error")
        flash(f"Error deleting mugshot: {e}", "error")
        return redirect(url_for("criminal_edit", cid=cid)) if cid else redirect(url_for("criminals_list"))

    if cid:
        safe_retrain_background()
    return redirect(url_for("criminal_edit", cid=cid))

@app.route("/criminals/retrain", methods=["POST"])
@login_required
def criminals_retrain():
    n, msg = train_model()
    recompute_all_threats()
    audit("retrain", msg)
    flash(msg, "success")
    return redirect(url_for("criminals_list"))

@app.route("/snapshots")
@login_required
def snapshots():
    src = request.args.get("source", "live")
    if src not in ("live", "uploaded", "video"):
        src = "live"
    with db() as c:
        rows = c.execute(
            "SELECT * FROM detections WHERE source=? ORDER BY id DESC LIMIT 500", (src,)
        ).fetchall()
    return render_template("snapshots.html", rows=rows, source=src)

@app.route("/snapshot/<uid>")
@login_required
def snapshot_detail(uid):
    with db() as c:
        r = c.execute("SELECT * FROM detections WHERE detection_uid=?", (uid,)).fetchone()
    if not r:
        abort(404)
    return render_template("snapshot_detail.html", r=r)

@app.route("/snapshot/<uid>/delete", methods=["POST"])
@login_required
def snapshot_delete(uid):
    src = "live"
    try:
        with db() as c:
            r = c.execute("SELECT * FROM detections WHERE detection_uid=?", (uid,)).fetchone()
            if r:
                src = r["source"] or "live"
                try:
                    if r["snapshot_path"]:
                        (BASE / r["snapshot_path"]).unlink(missing_ok=True)
                except Exception:
                    pass
                c.execute("DELETE FROM detections WHERE detection_uid=?", (uid,))
        audit("delete_snapshot", uid)
    except Exception as e:
        app.logger.exception("snapshot_delete error")
    # Never redirect back to the now-deleted detail page (/snapshot/<uid>) —
    # that would 404. Always go to the snapshots list for the same source.
    referrer = request.referrer or ""
    if f"/snapshot/{uid}" in referrer:
        return redirect(url_for("snapshots", source=src))
    return redirect(referrer or url_for("snapshots", source=src))

@app.route("/snapshots/delete_all", methods=["POST"])
@login_required
def snapshots_delete_all():
    src = request.form.get("source", "live")
    if src not in ("live", "uploaded", "video"):
        src = "live"
    try:
        with db() as c:
            rows = c.execute("SELECT snapshot_path FROM detections WHERE source=?", (src,)).fetchall()
            for r in rows:
                try:
                    if r["snapshot_path"]:
                        (BASE / r["snapshot_path"]).unlink(missing_ok=True)
                except Exception:
                    pass
            c.execute("DELETE FROM detections WHERE source=?", (src,))
        audit("delete_all_snapshots", f"source={src}")
        flash(f"All {src} snapshots deleted", "success")
    except Exception as e:
        app.logger.exception("snapshots_delete_all error")
        flash(f"Error deleting snapshots: {e}", "error")
    return redirect(url_for("snapshots", source=src))

@app.route("/map")
@login_required
def map_page():
    return render_template("map.html")

@app.route("/locations")
@login_required
def locations_page():
    return render_template("locations.html")

@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html")

@app.route("/logs")
@login_required
def logs_page():
    txt = ""
    if LOG_FILE.exists():
        txt = "\n".join(LOG_FILE.read_text(encoding="utf-8").splitlines()[-500:])
    with db() as c:
        aud = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("logs.html", log_text=txt, audit=aud)

@app.route("/reports")
@login_required
def reports_page():
    reports = sorted(REPORT_DIR.glob("*.pdf"), reverse=True)
    return render_template("reports.html", reports=[r.name for r in reports[:20]])

@app.route("/reports/generate", methods=["POST"])
@login_required
def generate_report():
    try:
        path = generate_daily_report_pdf()
        fn = Path(path).name
        flash(f"Report generated: {fn}", "success")
    except Exception as e:
        flash(f"Report error: {e}", "error")
    return redirect(url_for("reports_page"))

@app.route("/reports/download/<fn>")
@login_required
def download_report(fn):
    fp = REPORT_DIR / secure_filename(fn)
    if not fp.exists():
        abort(404)
    return send_file(fp, as_attachment=True)

# ── API ─────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    with db() as c:
        total_crim = c.execute("SELECT COUNT(*) n FROM criminals").fetchone()["n"]
        total_det  = c.execute("SELECT COUNT(*) n FROM detections").fetchone()["n"]
        unknown    = c.execute("SELECT COUNT(*) n FROM detections WHERE criminal_id IS NULL").fetchone()["n"]
        known      = total_det - unknown
        avg = c.execute("SELECT IFNULL(AVG(confidence),0) a FROM detections").fetchone()["a"]
        per_day = list(reversed([dict(r) for r in c.execute(
            "SELECT substr(timestamp,1,10) d, COUNT(*) n FROM detections "
            "GROUP BY d ORDER BY d DESC LIMIT 14"
        ).fetchall()]))
        top = [dict(r) for r in c.execute(
            "SELECT name, COUNT(*) n FROM detections WHERE criminal_id IS NOT NULL "
            "GROUP BY name ORDER BY n DESC LIMIT 7"
        ).fetchall()]
        cats = [dict(r) for r in c.execute(
            "SELECT IFNULL(crime_type,'Other') c, COUNT(*) n FROM criminals "
            "GROUP BY c ORDER BY n DESC LIMIT 8"
        ).fetchall()]
        buckets = {"0-50": 0, "50-70": 0, "70-85": 0, "85-100": 0}
        for r in c.execute("SELECT confidence FROM detections"):
            v = r["confidence"] or 0
            if v < 50: buckets["0-50"] += 1
            elif v < 70: buckets["50-70"] += 1
            elif v < 85: buckets["70-85"] += 1
            else: buckets["85-100"] += 1
        # Threat leaderboard
        threats = [dict(r) for r in c.execute(
            "SELECT name, threat_score, crime_type, status FROM criminals "
            "ORDER BY threat_score DESC LIMIT 8"
        ).fetchall()]
    last7 = [x["n"] for x in per_day[-7:]] or [0]
    forecast = round(sum(last7) / max(1, len(last7)), 1)
    return jsonify({
        "total_crim": total_crim, "total_det": total_det,
        "unknown": unknown, "known": known,
        "accuracy": round(avg, 1),
        "per_day": per_day, "top": top, "categories": cats,
        "confidence_buckets": buckets, "forecast_per_day": forecast,
        "threats": threats,
    })

@app.route("/api/map_points")
@login_required
def api_map_points():
    with db() as c:
        rows = c.execute(
            "SELECT detection_uid,name,confidence,lat,lon,city,timestamp,criminal_id "
            "FROM detections WHERE lat IS NOT NULL AND lon IS NOT NULL "
            "ORDER BY id DESC LIMIT 500"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/recent")
@login_required
def api_recent():
    with db() as c:
        rows = c.execute(
            "SELECT detection_uid,name,confidence,source,city,timestamp,criminal_id "
            "FROM detections ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/locations")
@login_required
def api_locations():
    with db() as c:
        rows = c.execute(
            "SELECT detection_uid,name,confidence,source,criminal_id,"
            "lat,lon,city,address,timestamp,snapshot_path "
            "FROM detections "
            "WHERE source='live' AND lat IS NOT NULL AND lon IS NOT NULL "
            "ORDER BY id DESC LIMIT 500"
        ).fetchall()
    # Only real GPS-tagged live camera detections are ever shown on the map.
    # Uploaded images and uploaded videos have no real location and must
    # never appear on the map, even approximately.
    return jsonify([dict(r) for r in rows])

@app.route("/api/network_data")
@login_required
def api_network_data():
    with db() as c:
        links = [dict(r) for r in c.execute(
            "SELECT nl.criminal_id_a, nl.criminal_id_b, nl.co_detections, "
            "ca.name name_a, cb.name name_b, ca.threat_score ts_a, cb.threat_score ts_b "
            "FROM network_links nl "
            "JOIN criminals ca ON ca.id=nl.criminal_id_a "
            "JOIN criminals cb ON cb.id=nl.criminal_id_b"
        ).fetchall()]
        nodes = [dict(r) for r in c.execute(
            "SELECT id, name, crime_type, threat_score, status, priority FROM criminals"
        ).fetchall()]
    return jsonify({"nodes": nodes, "links": links})

@app.route("/api/watchlist")
@login_required
def api_watchlist():
    with db() as c:
        rows = c.execute(
            "SELECT c.id,c.name,c.crime_type,c.status,c.threat_score,c.priority,c.last_seen,"
            "COUNT(d.id) det_count "
            "FROM criminals c LEFT JOIN detections d ON d.criminal_id=c.id "
            "WHERE c.priority=1 GROUP BY c.id ORDER BY c.threat_score DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/criminal/<int:cid>")
@login_required
def api_criminal_detail(cid):
    """Full criminal profile + detection history + mugshot for map popup."""
    with db() as c:
        crim = c.execute("SELECT * FROM criminals WHERE id=?", (cid,)).fetchone()
        if not crim:
            return jsonify({"error": "not found"}), 404
        mugshots = c.execute(
            "SELECT path FROM mugshots WHERE criminal_id=? LIMIT 1", (cid,)
        ).fetchall()
        dets = c.execute(
            "SELECT detection_uid,source,confidence,lat,lon,city,address,timestamp,snapshot_path "
            "FROM detections WHERE criminal_id=? ORDER BY id DESC LIMIT 10", (cid,)
        ).fetchall()
    result = dict(crim)
    result["mugshot"] = dict(mugshots[0])["path"] if mugshots else None
    result["detections"] = [dict(d) for d in dets]
    return jsonify(result)

@app.route("/api/reverse_geocode")
@login_required
def api_reverse_geocode():
    """Proxy reverse geocode request (avoids CORS on client side)."""
    lat = request.args.get("lat"); lon = request.args.get("lon")
    if not lat or not lon:
        return jsonify({"error": "lat/lon required"}), 400
    city, addr = reverse_geocode(float(lat), float(lon))
    return jsonify({"city": city, "address": addr})

@app.route("/api/my_location")
@login_required
def api_my_location():
    """Return best available server-side location (IP-based, cached)."""
    lat, lon, city, region = ip_location_fallback()
    addr = f"{city}, {region}" if region and region != city else city
    return jsonify({"lat": lat, "lon": lon, "city": city, "address": addr, "source": "ip"})

@app.route("/api/scan_frame", methods=["POST"])
@login_required
def api_scan_frame():
    payload = request.get_json(silent=True) or {}
    b64 = payload.get("image", "")
    if "," in b64:
        b64 = b64.split(",", 1)[1]
    try:
        raw = base64.b64decode(b64)
        arr = np.frombuffer(raw, dtype=np.uint8)
        bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception as e:
        return jsonify({"error": f"bad image: {e}"}), 400
    if bgr is None:
        return jsonify({"error": "decode failed"}), 400

    results = recognize_faces_bgr(bgr, num_jitters=1)
    save = bool(payload.get("save"))
    lat = payload.get("lat"); lon = payload.get("lon")
    city = payload.get("city"); addr = payload.get("address")

    # ── Location: use only real GPS sent by browser ──────────────────────────
    # If GPS coords arrived, reverse-geocode them to get a real street address
    if lat is not None and lon is not None:
        if not city or not addr:
            rg_city, rg_addr = reverse_geocode(lat, lon)
            city = city or rg_city
            addr = addr or rg_addr or city
    # If no GPS, lat/lon stay None — we do NOT inject fake IP location
    # The map will show detections without location as "no GPS" entries

    saved = []
    if save and results:
        annotated = draw_overlays(bgr.copy(), results)
        for r in results:
            # Save ALL detected faces (known criminals AND unknown persons)
            uid, rel = save_snapshot(annotated, "live", r["name"], r["confidence"],
                                     lat, lon, city, addr, criminal_id=r["criminal_id"])
            saved.append({"uid": uid, "path": rel, "name": r["name"],
                          "confidence": r["confidence"], "criminal_id": r["criminal_id"],
                          "lat": lat, "lon": lon, "city": city, "address": addr})
            if r["criminal_id"]:
                trigger_alerts(r, rel)
    return jsonify({"results": results, "saved": saved})

# ── FILE SERVING ─────────────────────────────────────────────────────────────
@app.route("/file/criminal_images/<path:filename>")
@login_required
def file_criminal(filename):
    return send_file(MUGSHOT_DIR / filename)

@app.route("/file/detected/live/<path:filename>")
@login_required
def file_detected_live(filename):
    return send_file(DETECT_LIVE / filename)

@app.route("/file/detected/uploaded/<path:filename>")
@login_required
def file_detected_uploaded(filename):
    return send_file(DETECT_UPLOAD / filename)

@app.route("/file/detected/video/<path:filename>")
@login_required
def file_detected_video(filename):
    return send_file(DETECT_VIDEO / filename)

@app.route("/file/by_rel")
@login_required
def file_by_rel():
    rel = request.args.get("p", "")
    p = (BASE / rel).resolve()
    if not str(p).startswith(str(BASE.resolve())):
        abort(403)
    if not p.exists():
        abort(404)
    return send_file(p)

# ── EXPORTS ──────────────────────────────────────────────────────────────────
@app.route("/export/csv")
@login_required
def export_csv():
    with db() as c:
        rows = c.execute("SELECT * FROM detections ORDER BY id DESC").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id","uid","source","name","confidence","city","lat","lon","timestamp","snapshot"])
    for r in rows:
        w.writerow([r["id"],r["detection_uid"],r["source"],r["name"],
                    r["confidence"],r["city"],r["lat"],r["lon"],
                    r["timestamp"],r["snapshot_path"]])
    return send_file(io.BytesIO(out.getvalue().encode("utf-8")),
                     mimetype="text/csv", as_attachment=True, download_name="detections.csv")

@app.route("/export/xlsx")
@login_required
def export_xlsx():
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = "Detections"
    ws.append(["id","uid","source","name","confidence","city","lat","lon","timestamp","snapshot"])
    with db() as c:
        for r in c.execute("SELECT * FROM detections ORDER BY id DESC"):
            ws.append([r["id"],r["detection_uid"],r["source"],r["name"],
                       r["confidence"],r["city"],r["lat"],r["lon"],
                       r["timestamp"],r["snapshot_path"]])
    bio = io.BytesIO(); wb.save(bio); bio.seek(0)
    return send_file(bio,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True, download_name="detections.xlsx")

@app.route("/export/pdf")
@login_required
def export_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    bio = io.BytesIO()
    doc = SimpleDocTemplate(bio, pagesize=A4, title="Detections Report")
    styles = getSampleStyleSheet()
    flow = [Paragraph("NEXUS INTEL — Detection Report", styles["Title"]),
            Paragraph(now_iso(), styles["Normal"]), Spacer(1, 10)]
    data = [["UID","Source","Name","Conf%","City","Time"]]
    with db() as c:
        for r in c.execute("SELECT * FROM detections ORDER BY id DESC LIMIT 300"):
            data.append([r["detection_uid"],r["source"],r["name"],
                         f'{r["confidence"]:.1f}',r["city"] or "",r["timestamp"]])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#020409")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.25,colors.grey),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.whitesmoke,colors.HexColor("#eef2f7")]),
    ]))
    flow.append(t)
    doc.build(flow)
    bio.seek(0)
    return send_file(bio, mimetype="application/pdf",
                     as_attachment=True, download_name="detections.pdf")

@app.route("/export/criminals.json")
@login_required
def export_criminals_json():
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM criminals")]
    return Response(json.dumps(rows, indent=2), mimetype="application/json",
                    headers={"Content-Disposition":"attachment; filename=criminals.json"})

# ── CONTEXT ──────────────────────────────────────────────────────────────────
@app.context_processor
def inject():
    return {
        "app_name": CFG["app_name"],
        "user": session.get("user"),
        "role": session.get("role", "viewer"),
        "theme": session.get("theme", CFG.get("theme", "dark")),
    }


# ── VOICE ASSISTANT ──────────────────────────────────────────────────────────
@app.route("/api/voice_query", methods=["POST"])
@login_required
def api_voice_query():
    """Handle voice assistant queries and return spoken + structured response."""
    payload = request.get_json(silent=True) or {}
    query   = (payload.get("query") or "").strip().lower()
    if not query:
        return jsonify({"reply": "I did not catch that. Please try again.", "data": None})

    reply = ""
    data  = None

    with db() as c:
        # Stats queries
        if any(w in query for w in ["how many criminal", "total criminal", "count criminal"]):
            n = c.execute("SELECT COUNT(*) n FROM criminals").fetchone()["n"]
            reply = f"There are {n} criminals in the database."
            data  = {"type": "stat", "value": n, "label": "Total Criminals"}

        elif any(w in query for w in ["how many detect", "total detect", "detection count"]):
            n = c.execute("SELECT COUNT(*) n FROM detections").fetchone()["n"]
            reply = f"The system has recorded {n} detections in total."
            data  = {"type": "stat", "value": n, "label": "Total Detections"}

        elif any(w in query for w in ["accuracy", "confidence", "how accurate"]):
            avg = c.execute("SELECT IFNULL(AVG(confidence),0) a FROM detections").fetchone()["a"]
            reply = f"The average recognition accuracy is {avg:.1f} percent."
            data  = {"type": "stat", "value": round(avg,1), "label": "Avg Accuracy %"}

        elif any(w in query for w in ["unknown", "unidentified"]):
            n = c.execute("SELECT COUNT(*) n FROM detections WHERE criminal_id IS NULL").fetchone()["n"]
            reply = f"There are {n} unknown or unidentified persons in the detections."
            data  = {"type": "stat", "value": n, "label": "Unknown Persons"}

        elif any(w in query for w in ["wanted", "most wanted", "priority", "watchlist"]):
            rows = c.execute(
                "SELECT name, crime_type, threat_score FROM criminals "
                "WHERE priority=1 OR status='Wanted' ORDER BY threat_score DESC LIMIT 5"
            ).fetchall()
            if rows:
                names = ", ".join(r["name"] for r in rows[:3])
                reply = f"Top wanted criminals are: {names}. There are {len(rows)} in total on the watchlist."
            else:
                reply = "There are no criminals currently marked as wanted or priority."
            data = {"type": "list", "rows": [dict(r) for r in rows]}

        elif any(w in query for w in ["last detect", "recent detect", "latest detect"]):
            row = c.execute(
                "SELECT name, confidence, city, timestamp FROM detections ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                reply = (f"The last detection was {row['name']} with "
                         f"{row['confidence']:.0f} percent confidence, "
                         f"detected in {row['city'] or 'unknown location'} "
                         f"at {row['timestamp'][11:16]}.")
            else:
                reply = "No detections have been recorded yet."
            data = dict(row) if row else None

        elif any(w in query for w in ["highest threat", "most dangerous", "top threat"]):
            rows = c.execute(
                "SELECT name, threat_score, crime_type FROM criminals "
                "ORDER BY threat_score DESC LIMIT 5"
            ).fetchall()
            if rows:
                top = rows[0]
                reply = (f"The most dangerous criminal is {top['name']} "
                         f"with a threat score of {top['threat_score']:.1f} out of 10, "
                         f"charged with {top['crime_type'] or 'unknown crime'}.")
            else:
                reply = "No criminals in the database yet."
            data = {"type": "list", "rows": [dict(r) for r in rows]}

        elif any(w in query for w in ["today", "today's detect", "detect today"]):
            today = dt.date.today().isoformat()
            n = c.execute(
                "SELECT COUNT(*) n FROM detections WHERE substr(timestamp,1,10)=?", (today,)
            ).fetchone()["n"]
            reply = f"There have been {n} detections today, on {today}."
            data  = {"type": "stat", "value": n, "label": "Detections Today"}

        elif any(w in query for w in ["live detect", "camera", "start live"]):
            reply = "To start live detection, go to the Live page and click Start Camera, then enable Auto-Scan."
            data  = {"type": "navigate", "url": "/live"}

        elif any(w in query for w in ["upload", "scan image", "scan photo"]):
            reply = "To scan images, go to the Upload page and drag your photos onto the upload area."
            data  = {"type": "navigate", "url": "/upload"}

        elif any(w in query for w in ["add criminal", "new criminal", "register criminal"]):
            reply = "To add a new criminal, go to the Criminals page and click the plus Add button."
            data  = {"type": "navigate", "url": "/criminals/add"}

        elif any(w in query for w in ["report", "generate report", "daily report"]):
            reply = "You can generate a report from the Reports page. Daily PDF reports can also be scheduled automatically."
            data  = {"type": "navigate", "url": "/reports"}

        elif any(w in query for w in ["network", "graph", "association", "connection"]):
            reply = "The criminal network graph shows associations between criminals detected together. Go to the Network page to view it."
            data  = {"type": "navigate", "url": "/network"}

        elif any(w in query for w in ["map", "location", "where"]):
            n = c.execute("SELECT COUNT(*) n FROM detections WHERE lat IS NOT NULL").fetchone()["n"]
            reply = f"The detection map shows {n} geo-tagged detection locations. Go to the Map or Locations page."
            data  = {"type": "navigate", "url": "/map"}

        elif any(w in query for w in ["compare", "face compare", "similarity"]):
            reply = "The face comparison tool lets you upload two photos and check if they are the same person. Go to the Compare page."
            data  = {"type": "navigate", "url": "/compare"}

        elif any(w in query for w in ["help", "what can you do", "commands", "assist"]):
            reply = ("I can help you with: checking detection counts, accuracy, wanted list, "
                     "latest detections, threat scores, and navigating to any page. "
                     "Just ask me anything about the system.")
            data  = {"type": "help"}

        else:
            # Try to search for a criminal by name in the query
            words = [w for w in query.split() if len(w) > 3]
            found = None
            for word in words:
                row = c.execute(
                    "SELECT name, crime_type, status, threat_score FROM criminals "
                    "WHERE name LIKE ? LIMIT 1", (f"%{word}%",)
                ).fetchone()
                if row:
                    found = row
                    break
            if found:
                det_count = c.execute(
                    "SELECT COUNT(*) n FROM detections WHERE name LIKE ?",
                    (f"%{found['name']}%",)
                ).fetchone()["n"]
                reply = (f"{found['name']} is in the database. Status: {found['status']}. "
                         f"Crime: {found['crime_type'] or 'not specified'}. "
                         f"Threat score: {found['threat_score']:.1f}. "
                         f"Detected {det_count} times.")
                data = dict(found)
            else:
                reply = ("I am not sure about that. You can ask me about detection counts, "
                         "accuracy, wanted criminals, latest detections, or say 'help' for more options.")

    return jsonify({"reply": reply, "data": data})

@app.errorhandler(404)
def not_found(e):
    flash("That item could not be found — it may have already been deleted.", "error")
    referrer = request.referrer or ""
    # Avoid redirecting back into the same dead URL in a loop
    if referrer and request.path not in referrer:
        return redirect(referrer), 302
    return redirect(url_for("dashboard")), 302

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Maximum size is 64MB per file.", "error")
    return redirect(request.referrer or url_for("dashboard")), 413

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Internal server error")
    flash(f"Server error: {str(e)}", "error")
    return redirect(request.referrer or url_for("dashboard")), 500

@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled exception")
    flash(f"Unexpected error: {str(e)}", "error")
    return redirect(request.referrer or url_for("dashboard"))

# ── BOOT ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    load_model(force=True)
    recompute_all_threats()
    # Pre-warm IP location cache in background (non-blocking)
    threading.Thread(target=ip_location_fallback, daemon=True).start()
    if CFG.get("scheduler_enabled"):
        t = threading.Thread(target=_scheduler_loop, daemon=True)
        t.start()
    print("=" * 62)
    print(f"  NEXUS INTEL — Criminal Face Detection System v2")
    print(f"  http://localhost:5000   (admin / admin123)")
    print(f"  Face recognition: {'OK' if FACE_REC_OK else 'NOT INSTALLED'}")
    print("=" * 62)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)