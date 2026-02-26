# CyberDrishti — Setup Guide
### CERT-IN National Cyber Exposure Scanner | साइबर दृष्टि

---

## What You Have (Phase 0 — Foundation)

```
cyberdrishti/
├── START.bat                  ← Double-click to start everything
├── STOP.bat                   ← Double-click to stop everything
├── docker-compose.yml         ← Orchestrates all services
├── .env                       ← Your configuration (keep private!)
├── .gitignore                 ← Prevents secrets from being committed
│
├── backend/
│   ├── Dockerfile             ← How to build the Python container
│   ├── requirements.txt       ← Python libraries needed
│   └── app/
│       ├── main.py            ← FastAPI — all API endpoints
│       ├── worker.py          ← Celery — background task queue
│       ├── core/
│       │   ├── config.py      ← Reads settings from .env
│       │   └── logging.py     ← Audit logging
│       ├── db/
│       │   └── database.py    ← PostgreSQL connection
│       ├── models/
│       │   └── models.py      ← Database table definitions
│       └── services/
│           ├── corpus_tasks.py   ← Domain discovery (CT logs)
│           └── scanner_tasks.py  ← Heuristic scanner engine
│
├── docker/
│   └── postgres/
│       └── init.sql           ← Database schema (all tables)
│
└── frontend/
    └── index.html             ← Dashboard (open in browser)
```

---

## How to Start (First Time)

### Step 1 — Make sure Docker Desktop is running
Open Docker Desktop. Wait until you see the green whale icon in your taskbar.
If it says "Starting...", wait for it to finish.

### Step 2 — Open the project folder
Open Windows Explorer and go to your `cyberdrishti` folder.

### Step 3 — Double-click START.bat
This does everything automatically:
- Downloads all required software (Python, PostgreSQL, Redis) inside Docker
- Creates the database with all tables
- Starts the API server
- Starts the scanner worker
- Opens the dashboard in your browser

**First run takes 2-5 minutes** because Docker downloads images. After that, it starts in ~20 seconds.

---

## How to Use the Dashboard

Once START.bat runs successfully, the dashboard opens in your browser automatically.
If it doesn't open, just double-click `frontend/index.html`.

### Step 1 — Refresh the Domain Corpus
Click **"Refresh Corpus"** in the left sidebar.
This queries Certificate Transparency logs and discovers `.gov.in`, `.edu.in`,
`.nic.in`, `.ac.in`, and `.res.in` domains from across India.

This runs as a background task. Wait ~1-2 minutes, then click **Domain Corpus**
in the sidebar to see the discovered domains.

### Step 2 — Trigger a Scan
In the **Domain Corpus** page, click **▶ Scan** next to any domain.
Or click **"Scan All Pending"** in the sidebar to scan everything at once.

The scanner will:
- Check ~25 sensitive file paths (.env, .git, config files, backup files)
- Scan homepage content for PII patterns (Aadhaar, PAN, Voter ID)
- Check for open directory listings
- Check for unauthenticated admin panels
- Store all findings (no raw PII — hashes only)

### Step 3 — View Findings
Click **Findings** in the sidebar to see all detected exposures.
Each finding shows: domain, type, severity, confidence score, and SLA deadline.

---

## API Reference

The API runs at `http://localhost:8000`

| Endpoint | What it does |
|---|---|
| `GET /api/health` | Check if everything is running |
| `GET /api/dashboard` | Dashboard summary stats |
| `GET /api/domains` | List all domains in corpus |
| `POST /api/domains/add?domain=x` | Add a domain manually |
| `POST /api/domains/{id}/scan` | Trigger scan for a domain |
| `GET /api/findings` | List all findings |
| `GET /api/jobs` | List all scan jobs |
| `GET /api/audit` | View audit log |
| `POST /api/scanner/pilot-refresh` | Trigger corpus refresh |
| `POST /api/scanner/scan-all-pending` | Scan all pending domains |

Full interactive docs: `http://localhost:8000/api/docs`

---

## Stopping

Double-click `STOP.bat` — or run `docker compose down` in the folder.

Your data is saved in Docker volumes — it persists between restarts.

---

## Troubleshooting

**"Docker is not running" error**
→ Open Docker Desktop and wait for it to fully start.

**Dashboard shows "Cannot reach API"**
→ Run `docker compose logs api` to see what's wrong.
→ Make sure ports 8000, 5432, 6379 are not used by other apps.

**Corpus refresh finds 0 domains**
→ This means crt.sh (Certificate Transparency API) is unreachable.
→ Check your internet connection. The scanner will use a fallback list of known domains.

**Scan job shows FAILED**
→ Run `docker compose logs worker` to see the error.

---

## What's Coming (Phase 1)

In the next phase, we'll add:
- Full subdomain enumeration
- PII detection in PDFs and image files
- Responsible disclosure email workflow
- Automatic re-scanning after SLA deadlines
- Expanded regex patterns for more Indian PII types

---

*CyberDrishti v1.0 — Phase 0 Foundation*
*CERT-IN | RESTRICTED | February 2026*
