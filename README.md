# echo-prometheus-surveillance

> Advanced location intelligence and active surveillance platform with 6 integrated modules: GPS tracking, cell tower triangulation, carrier intelligence, physical surveillance, active interception, and IP geolocation.

## Overview

Echo Prometheus Surveillance (codename: ARGUS PANOPTES) is a Cloudflare Worker that coordinates location intelligence and surveillance operations across 6 modules. It provides real-time GPS device tracking, cell tower triangulation via multiple providers, carrier-level intelligence (SS7/SIM swap/CDR analysis), physical surveillance management (cameras, ALPR, facial recognition), active interception coordination, and IP geolocation with threat scoring. Interception and physical operations are dispatched to the CHARLIE node (Kali) for execution.

## Endpoints

### Health and Initialization

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with stats across all 6 modules |
| GET | `/init` | Initialize all 20 database tables |

### Module 1: GPS Tracking

| Method | Path | Description |
|--------|------|-------------|
| POST | `/gps/devices` | Register a device for GPS tracking |
| GET | `/gps/devices` | List all tracked devices (filter by status) |
| POST | `/gps/report` | Report a GPS location (manual or webhook) |
| GET | `/gps/traccar` | Traccar/OsmAnd protocol webhook (GET with query params) |
| GET | `/gps/history/:device_id` | Location history for a device (configurable hours/limit) |
| GET | `/gps/live` | Real-time dashboard data for all active devices |
| POST | `/gps/predict` | Predictive movement analysis based on historical patterns |

### Geofencing

| Method | Path | Description |
|--------|------|-------------|
| POST | `/geofence` | Create a geofence (circle or polygon) |
| GET | `/geofence` | List all active geofences |
| GET | `/geofence/alerts` | Recent geofence breach alerts |

### Module 2: Cell Tower Triangulation

| Method | Path | Description |
|--------|------|-------------|
| POST | `/cell/triangulate` | Triangulate location from cell tower data (6 resolvers) |
| GET | `/cell/lookup` | Look up a single cell tower by MCC/MNC/LAC/CellID |
| POST | `/cell/import` | Bulk import cell tower database entries |
| GET | `/cell/history/:device_id` | Cell tower lookup history for a device |

### Module 3: Carrier Intelligence

| Method | Path | Description |
|--------|------|-------------|
| POST | `/carrier/lookup` | HLR/carrier lookup via Twilio or Numverify |
| POST | `/carrier/sim-swap-check` | Detect SIM swap activity on a phone number |
| POST | `/carrier/ss7/analyze` | Analyze SS7 protocol messages for anomalies |
| POST | `/carrier/cdr/import` | Import call detail records (CDR) |
| POST | `/carrier/cdr/analyze` | Analyze CDR patterns (top contacts, hour distribution, locations) |

### Module 4: Physical Surveillance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/surveillance/cameras` | Register an IP camera (RTSP/ONVIF) |
| GET | `/surveillance/cameras` | List all active cameras |
| POST | `/surveillance/alpr/read` | Report a license plate read |
| GET | `/surveillance/alpr/search` | Search ALPR reads by plate number |
| POST | `/surveillance/alpr/watchlist` | Add a plate to the watchlist |
| GET | `/surveillance/alpr/watchlist` | List plate watchlist |
| POST | `/surveillance/face/detect` | Report a facial recognition detection |
| POST | `/surveillance/face/watchlist` | Add a person to the face watchlist |
| GET | `/surveillance/face/watchlist` | List person watchlist |

### Module 5: Active Interception

| Method | Path | Description |
|--------|------|-------------|
| POST | `/intercept/start` | Start an interception session (packet capture, MITM, WiFi, DNS) |
| POST | `/intercept/stop` | Stop an active interception session |
| GET | `/intercept/sessions` | List interception sessions |
| POST | `/intercept/credentials` | Report captured credentials |
| POST | `/intercept/dns` | Log a DNS interception event |
| POST | `/intercept/dns/rules` | Create DNS spoofing rules |
| POST | `/intercept/wifi/networks` | Report discovered WiFi networks |
| POST | `/intercept/wifi/clients` | Report WiFi client devices |
| GET | `/intercept/wifi/scan` | Get latest WiFi scan results |

### Module 6: IP Intelligence

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ip/lookup` | IP geolocation + threat scoring (3 free providers) |
| POST | `/ip/bulk` | Bulk IP lookup (up to 100 per request) |
| GET | `/ip/history` | IP lookup history |
| GET | `/ip/threats` | High-threat IP feed |
| POST | `/ip/geo-search` | Find IPs by geographic area |

### Utilities

| Method | Path | Description |
|--------|------|-------------|
| POST | `/search` | Cross-module search across all data |
| GET | `/log` | Surveillance activity log |
| GET | `/dashboard` | Full dashboard with stats from all modules |

## Configuration

### Secrets (`wrangler secret put`)

- `OPENCELLID_API_KEY` -- OpenCelliD API key for cell tower lookups
- `UNWIREDLABS_API_KEY` -- UnwiredLabs API key for cell tower resolution
- `GOOGLE_API_KEY` -- Google Geolocation API key
- `NUMVERIFY_API_KEY` -- Numverify phone number validation
- `TWILIO_SID` -- Twilio Account SID for carrier lookups
- `TWILIO_AUTH` -- Twilio Auth Token
- `TRACCAR_URL` -- Traccar GPS tracking server URL
- `TRACCAR_TOKEN` -- Traccar API token
- `COMMANDER_API_URL` -- Commander API URL for cross-node operations
- `ECHO_API_KEY` -- Worker authentication key

### D1 Database

| Binding | Database Name | ID |
|---------|---------------|----|
| `DB` | `echo-prometheus-surveillance` | `f565c442-b7cb-4ace-9dea-d481dc51c80d` |

**Tables (20):** `tracked_devices`, `location_history`, `geofences`, `geofence_alerts`, `cell_tower_logs`, `cell_tower_db`, `carrier_intel`, `ss7_analysis`, `cdr_records`, `surveillance_cameras`, `alpr_reads`, `facial_recognition`, `plate_watchlist`, `person_watchlist`, `intercept_sessions`, `captured_credentials`, `dns_intercepts`, `wifi_networks`, `wifi_clients`, `surveillance_log`, `ip_intel`

### KV Namespace

| Binding | ID |
|---------|-----|
| `CACHE` | `f3835556417542848065e1bfa2e8005e` |

### Service Bindings

| Binding | Service |
|---------|---------|
| `BRAIN` | `echo-shared-brain` |
| `ENGINES` | `echo-engine-runtime` |
| `SWARM` | `echo-swarm-brain` |
| `PROMETHEUS` | `echo-prometheus-cloud` |

### Workers AI

| Binding |
|---------|
| `AI` |

### Environment Variables

| Variable | Value |
|----------|-------|
| `PROMETHEUS_URL` | `http://192.168.1.202:8370` |
| `CHARLIE_NODE` | `192.168.1.202` |

### Cron Triggers

| Schedule | Description |
|----------|-------------|
| `*/5 * * * *` | Device status and geofence check every 5 minutes |
| `0 * * * *` | Hourly intelligence aggregation |
| `0 0 * * *` | Daily surveillance report and data cleanup |

## Deployment

```bash
cd O:\ECHO_OMEGA_PRIME\WORKERS\echo-prometheus-surveillance
npx wrangler deploy

# Set secrets
echo "YOUR_KEY" | npx wrangler secret put ECHO_API_KEY
echo "YOUR_KEY" | npx wrangler secret put OPENCELLID_API_KEY
echo "YOUR_KEY" | npx wrangler secret put TWILIO_SID
echo "YOUR_TOKEN" | npx wrangler secret put TWILIO_AUTH
```

## Architecture

The worker uses a Hono router with CORS enabled globally. It operates as a coordination layer:

- **GPS/Cell/IP modules** execute directly on the Cloudflare edge, querying external APIs (OpenCelliD, BeaconDB, Mylnikov, Google Geolocation, ip-api, ipwhois, ipapi) and caching results in D1.
- **Physical surveillance and interception modules** coordinate with the CHARLIE node (Kali Linux at 192.168.1.202) which runs the actual capture tools (tcpdump, aircrack-ng, mitmproxy).
- **Cell tower triangulation** cascades through 6 resolvers in priority order: local cache, OpenCelliD, UnwiredLabs, Google, BeaconDB, and Mylnikov.
- **Geofencing** uses haversine distance calculations with configurable enter/exit/dwell alerts.
- **SS7 analysis** scores risk based on known surveillance-capable operations and query frequency anomalies.
