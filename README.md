# Insider Threat Digital Forensic Investigation Tool
An Inider Threat Digital Forensic tool for file and usb activity , Implemented for Windows entreprise environment.

 *"Implementation of an Automated Insider Threat Digital Forensic Investigation Tool for Toronto
Police Force Against USB Activity and File Access Activity"* (Abdulateef-Adoga
& Egwuonwu). 

| Component | Role | Tech |
|---|---|---|
| **Agent** | Runs on each monitored workstation. Watches USB connect/disconnect events and file access (via Windows Security log auditing) and reports them to the central station. | PowerShell (`agent/agent.ps1`) |
| **Central Station** | Receives agent data, stores it as tamper-evident evidence, runs detection rules, serves the dashboard. | Python / Flask (`server/app.py`) |
| **Dashboard** | Live investigator view: events, alerts, USB whitelist, chain-of-custody verification. | HTML/JS, polls the Flask API (`dashboard/index.html`) |

## Quick start (demo, any OS)

```bash
cd server
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000** — that's the dashboard, served directly by
Flask. It's empty until events arrive.

Since the real agent (`agent.ps1`) only runs on Windows, use the simulator
to generate realistic traffic on any platform:

```bash
cd agent
python simulate_agent.py --server http://localhost:5000 --key change-me-agent-key
```

This plays both roles — USB connects/disconnects (some from unregistered
serials) and file access bursts (some off-hours, some touching
"sensitive" paths, occasional bulk-access bursts) — so you can watch
alerts populate in real time.

## Deploying the real agent (Windows endpoints)

1. Copy `agent/agent.ps1` to the workstation.
2. Run once as Administrator to enable auditing on the folders you want
   watched: `powershell -File agent.ps1 -SetupOnly`. You also need to turn
   on **Object Access** auditing in Local Security Policy → Advanced Audit
   Policy Configuration, or the Security log won't emit Event ID 4663.
3. Run it continuously (as a scheduled task or service):
   `powershell -File agent.ps1 -ServerUrl "http://<central-station>:5000" -ApiKey "<key>" -WatchPaths "D:\CaseFiles","D:\Evidence"`

Change `AGENT_API_KEY` on the server (`server/app.py`)  and pass the same
value as `-ApiKey`  before deploying past a demo.

## What it detects

The rule engine (`server/rules.py`) implements the kinds of insider-threat
indicators the research questions ask about:

- **Unauthorized USB device** — a USB device connects whose serial isn't
  on the approved whitelist.
- **Sensitive data access** — a file under a path matching sensitive
  keywords (case files, intel, criminal records, personnel data) is
  touched.
- **High-risk file type modified** — a write/rename/delete on a file type
  commonly used to exfiltrate bulk data (`.csv`, `.xlsx`, `.pdf`, `.zip`, etc.).
- **Off-hours activity** — file access outside normal working hours.
- **Bulk data access** — an unusually high rate of file events from one
  user in a short window, a common exfiltration signature.

Thresholds live at the top of `rules.py` and are meant to be tuned per
deployment.

## Evidence integrity (chain of custody)

Every event is written to SQLite as a hash-chained ledger
(`server/database.py`): each row's hash is computed over its own content
plus the previous row's hash, the same idea as a blockchain. `GET
/api/verify` recomputes the whole chain and reports the first row where it
breaks. This is what the presentation's "Deploying Hash Algorithm" slide
was solving for  investigators need to be able to show the log wasn't
altered after the fact.

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/agent/usb` | POST | Agent reports a USB connect/disconnect (requires `X-Agent-Key` header) |
| `/api/agent/file` | POST | Agent reports a file access event (requires `X-Agent-Key` header) |
| `/api/events?type=usb\|file&limit=` | GET | List recent evidence records |
| `/api/alerts?limit=` | GET | List recent detection-rule alerts |
| `/api/stats` | GET | Summary counters for the dashboard |
| `/api/verify` | GET | Recompute and validate the evidence hash chain |
| `/api/whitelist` | GET / POST | List / register approved USB device serials |

## Limitations (this is a prototype)

- The Flask dev server (`app.run`) isn't for production  front it with
  gunicorn/uWSGI + nginx and TLS for a real deployment.
- Auth is a single shared API key; a real deployment should issue and
  hash per-agent credentials.
- The 4663-based file monitor only sees folders you've explicitly put a
  SACL on (`-SetupOnly`), matching the project's approach to keeping event
  log volume manageable — it does not watch the whole disk.
- Detection thresholds are simple and rule-based, not ML-based, matching
  the "explainable to an investigator" design in the presentation
