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

Skip to content
cyberwhill
Insiderthreat
Repository navigation
Code
Issues
Pull requests
Actions
Projects
Wiki
Security and quality
Insights
Settings
Commit a3a74e0
cyberwhill
cyberwhill
authored
1 minute ago
Verified
Create How To setup
main
1 parent 
d562df1
 commit 
a3a74e0
1 file changed

+101
Lines changed: 101 additions & 0 deletions
File tree
Filter files…
How To setup
Search within code
 
‎How To setup‎
+101
Lines changed: 101 additions & 0 deletions
Original file line number	Diff line number	Diff line change
@@ -0,0 +1,101 @@
Manual Deployment & Troubleshooting Steps (No
Service/Scheduled Task)
Run everything manually first to confirm it works end-to-end. Once confirmed, you can
convert the server to a systemd service and the agent to a scheduled task.
Step 1: Start the server manually
On the Linux machine:
bash
cd server
pip install -r requirements.txt
export AGENT_API_KEY="K7j2mP9xQz3vN8wR5tY1cB6dF4gH0sL2aE7uI9oM3nP="
python app.py
Leave this terminal window open — closing it kills the server. You should see console
output like:
Agent API key (set AGENT_API_KEY env var to change):
K7j2mP9xQz3vN8wR5tY1cB6dF4gH0sL2aE7uI9oM3nP=
* Running on all addresses (0.0.0.0)
* Running on http://127.0.0.1:5000
* Running on http://<server-lan-ip>:5000
Note the last line — the actual LAN IP it's listening on. You'll need it in Step 3.
Step 2: Confirm the server works, from the server itself
Open a second terminal on the same Linux machine (don't close the first one):
bash
curl http://localhost:5000/api/stats
You should get back JSON like 
{"usb_events": 0, "file_events": 0, ...} 
.
If this fails, stop here — the server itself isn't working, and nothing past this point will work
either.
Step 3: Find the server's real IP address
bash
hostname -I
or
bash
ip addr show
Pick the IP on the same network as your Windows workstation (not 
means "this machine," useless from Windows).
127.0.0.1
 — that only
Step 4: Test reachability from the Windows workstation, before touching the
agent at all
On the Windows machine:
powershell
Test-NetConnection-ComputerName <server-ip-from-step-3> -Port 5000
Look for 
TcpTestSucceeded : True 
.
If 
False
 — stop here, this is a network/firewall problem, not an agent problem. Common
cause: Linux firewall blocking port 5000:
bash
sudo ufw allow 5000/tcp
or if using firewalld:
bash
sudo firewall-cmd --add-port=5000/tcp --permanent
sudo firewall-cmd --reload
Step 5: Test the actual HTTP call from Windows
powershell
Invoke-RestMethod-Uri "http://<server-ip>:5000/api/stats"-Method Get
If this returns JSON successfully, the network path is confirmed good end-to-end —
anything after this is purely about how you invoke the agent script.
Step 6: Run the agent manually (foreground, as Administrator)
Open PowerShell as Administrator on the Windows workstation:
powershell
cd C:\ProgramData\TPSForensic
powershell -File agent.ps1 -SetupOnly -WatchPaths "D:\CaseFiles","D:\Evidence"
Confirm it prints 
Auditing enabled on D:\CaseFiles
 etc.
Then enable the OS-level audit policy:
powershell
auditpol /set /subcategory:"File System" /success:enable
Then run the agent continuously, in the foreground so you can watch its log output live:
powershell

powershell -File agent.ps1 -ServerUrl "http://<server-ip>:5000"-ApiKey "K7j2mP
Use the exact IP from Step 3 — no 
localhost 
, no trailing slash after 
5000 
.

Step 7: Generate a test event
While the agent is running in that window, open a file inside 
D:\CaseFiles
 from a different
window, or plug in a USB drive. Watch the agent's own console — you should see something
like:
[21:55:02] File access reported: D:\CaseFiles\somefile.txt
Step 8: Confirm it landed on the server
Back on Linux:
bash
curl http://localhost:5000/api/events?limit=5
You should see the event you just generated.
If something breaks
Run through Steps 1–5 first and check exactly where it breaks (what 
and 
Test-NetConnection
Invoke-RestMethod
 actually return) — that tells you definitively whether the issue is
the server, the firewall, or the URL passed to the agent.
0 commit comments
Comments
0
 (0)
Comment
You're not receiving notifications from this thread.

