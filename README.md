# Agentic Defence System

A multi-agent, AI-powered network threat detection and response system.

## What it does

- Detects threats in real time: brute force, DDoS, port scans, data exfiltration, impossible travel, multi-stage attacks
- Adaptive rule engine: suggests new detection rules from anomaly patterns — admin approves before they apply
- SOC playbooks: generates recommended response steps per threat type (advisory only, no auto-execution)
- Discord alerts with playbook steps on block/alert actions
- FastAPI backend with rate limiting, API key auth, and live dashboard
- Persistent IsolationForest ML model with online learning via feedback loop
- Log collector: tails live auth logs or replays JSON for demos

## Stack

- Python 3.11, FastAPI, Supabase, scikit-learn, slowapi

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Fill in your .env values
uvicorn api:app --reload
```

## Environment variables

| Variable | Description |
|---|---|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Supabase anon key |
| `API_KEY` | Bearer key for `/events` endpoint |
| `DISCORD_WEBHOOK` | Discord webhook URL for alerts |
| `ABUSEIPDB_KEY` | AbuseIPDB API key (optional) |
| `SHODAN_KEY` | Shodan API key (optional) |

## Database setup

Run `supabase_schema.sql` once in your Supabase SQL editor.

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/events` | Submit a log event for analysis |
| GET | `/health` | Health check |
| GET | `/dashboard` | Live threat dashboard |
| GET | `/logs` | Recent threat logs |
| GET | `/rules/suggested` | Pending adaptive rules |
| POST | `/rules/{id}/approve` | Approve a suggested rule |
| POST | `/rules/{id}/reject` | Reject a suggested rule |
| GET | `/export/stix` | Export blocked IPs as STIX bundle |

## Log collector (demo)

```bash
# Replay sample JSON logs
python collector/log_collector.py --mode json --file data/logs.json

# Tail a live auth log
python collector/log_collector.py --mode tail --file /var/log/auth.log
```

## Run tests

```bash
pytest tests/ -v
```

## Architecture

```
Log Source → MonitoringAgent → NormalizerAgent → FilterAgent
    → DetectionAgent (static rules → dynamic rules → ML fallback)
    → CoordinatorAgent → DecisionAgent → ResponseAgent
    → FeedbackAgent (retrains ML every 50 labelled events)
```
