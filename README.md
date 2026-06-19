# NEXUS INTEL — Criminal Face Detection & Recognition System v2

## FULL SETUP GUIDE (Step by Step)

---

## STEP 1 — Install Python

Download Python **3.10 or 3.11** (NOT 3.12+) from https://python.org/downloads

**Why 3.10/3.11?** The `dlib` / `face_recognition` libraries require this version.

During installation on Windows:
- ✅ Check "Add Python to PATH"
- ✅ Check "Install pip"

Verify in terminal:
```
python --version   # should show 3.10.x or 3.11.x
```

---

## STEP 2 — Install CMake and Visual Studio Build Tools (Windows only)

`dlib` needs a C++ compiler.

**Option A — Recommended (easiest)**
Install the prebuilt wheel:
```
pip install cmake
pip install https://github.com/jloh02/dlib/releases/download/v19.22/dlib-19.22.0-cp310-cp310-win_amd64.whl
```
Replace `cp310` with `cp311` if you have Python 3.11.

**Option B — Full build**
1. Install CMake: https://cmake.org/download/
2. Install Visual Studio Build Tools (C++ workload): https://visualstudio.microsoft.com/visual-cpp-build-tools/
3. Then run: `pip install dlib`

**On Linux/Mac:**
```
sudo apt-get install cmake build-essential libopenblas-dev liblapack-dev   # Ubuntu
brew install cmake                                                           # macOS
pip install dlib
```

---

## STEP 3 — Create Virtual Environment

```bash
cd path/to/cfs_v2
python -m venv venv

# Activate:
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

---

## STEP 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

If `face_recognition` fails, install manually:
```bash
pip install dlib
pip install face_recognition
```

If `dlib` still fails on Windows, use the prebuilt wheel from Step 2.

---

## STEP 5 — Run the Application

```bash
python app.py
```

You should see:
```
══════════════════════════════════════════════════════════════
  NEXUS INTEL — Criminal Face Detection System v2
  http://localhost:5000   (admin / admin123)
  Face recognition: OK
══════════════════════════════════════════════════════════════
```

Open browser: **http://localhost:5000**
Login: **admin / admin123** → change password immediately!

---

## STEP 6 — Add Criminals to Database

1. Go to **Criminals → Add Criminal**
2. Fill in: Name, CNIC, Crime Type, Status
3. Upload **3–5 clear, frontal mugshot photos** (different angles = better accuracy)
4. Check "Priority Watchlist" for high-risk criminals
5. Click **Save & Train Model**

**For best recognition accuracy:**
- Use well-lit, clear photos
- Include multiple angles (front, slight left, slight right)
- Minimum 200×200 pixel resolution
- Avoid blurry or partially covered faces

---

## STEP 7 — Configure Email Alerts (Optional)

Edit `config.json`:
```json
{
  "email_enabled": true,
  "email_host": "smtp.gmail.com",
  "email_port": 587,
  "email_user": "your_gmail@gmail.com",
  "email_pass": "your_app_password",
  "email_recipients": ["admin@yourorg.com"]
}
```

**For Gmail:** Enable 2FA, then create an App Password at:
https://myaccount.google.com/apppasswords

---

## STEP 8 — Configure SMS Alerts via Twilio (Optional)

1. Sign up at https://twilio.com (free trial available)
2. Get your Account SID, Auth Token, and a Twilio phone number
3. Edit `config.json`:
```json
{
  "sms_enabled": true,
  "twilio_sid": "ACxxxxxxxxxxx",
  "twilio_token": "your_auth_token",
  "twilio_from": "+1234567890",
  "sms_recipients": ["+923001234567"]
}
```

---

## STEP 9 — Enable Scheduled Daily Reports (Optional)

```json
{
  "scheduler_enabled": true,
  "scheduler_report_hour": 7,
  "email_enabled": true
}
```

A daily PDF report will be generated and emailed every morning at 7:00 AM.

---

## FEATURES OVERVIEW

| Feature | How to Use |
|---------|-----------|
| Live Detection | Live → Start Camera → Auto-Scan |
| Upload Scan | Upload → drag multiple images |
| Video Scan | Video → upload MP4/AVI/MOV |
| Face Compare | Compare → upload 2 photos |
| Network Graph | Network → see criminal associations |
| Watchlist | Mark criminal as ⚑ Priority |
| Threat Score | Auto-calculated 0–10 per criminal |
| Location Tracker | Locations → live map + list |
| User Management | Users (admin only) |
| Reports | Reports → Generate / Download |
| Theme Toggle | ☀️/🌙 button in navbar |
| Export | Reports → CSV / Excel / PDF / JSON |

---

## ACCURACY TIPS

1. **More mugshots = better accuracy** — Upload 5+ photos per criminal
2. **Tolerance setting** — In `config.json`, lower `recognition_tolerance` (e.g. 0.40) = stricter matching, fewer false positives but may miss some
3. **Lighting** — Detection works best in good lighting
4. **Image size** — At least 200×200px faces
5. **Retrain** — After adding new criminals, click Retrain in the Criminals page

---

## TROUBLESHOOTING

**"face_recognition not available"**
→ Install dlib first (see Step 2), then `pip install face_recognition`

**Camera not working in browser**
→ Chrome requires HTTPS for camera. Run with: `flask run --cert=adhoc` or access via `localhost` (not IP)

**500 errors on upload**
→ Check that all folders exist (database/, uploads/, detected/, etc.)
→ Look at terminal for the exact error message

**Low accuracy**
→ Add more mugshot photos (5+ per person)
→ Lower tolerance in config.json: `"recognition_tolerance": 0.40`
→ Click Retrain after adding photos

---

## DEFAULT LOGIN
- Username: `admin`
- Password: `admin123`
- **Change this immediately after first login!**

