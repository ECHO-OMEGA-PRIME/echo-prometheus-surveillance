/**
 * ECHO PROMETHEUS SURVEILLANCE v1.0.0
 * Advanced Location Intelligence & Active Surveillance Platform
 *
 * 6 Modules:
 *   1. GPS_TRACKER    — Real-time device GPS tracking (Traccar, web geolocation, custom devices)
 *   2. CELL_TOWER     — Cell tower triangulation (OpenCelliD, MLS, UnwiredLabs, Google Geolocation, BeaconDB)
 *   3. CARRIER_INTEL  — Carrier-level location data (SS7 analysis, SIM swap detection, CDR analysis)
 *   4. PHYS_SURV      — Physical surveillance coordination (IP cameras, ALPR, facial recognition, geofencing)
 *   5. ACTIVE_INTERCEPT — Active interception (packet capture, MITM coordination, WiFi monitoring, DNS intercept)
 *   6. IP_INTEL       — IP geolocation + threat intelligence (multi-source, bulk, threat scoring)
 *
 * Architecture: Cloudflare Worker (coordination + API) ↔ CHARLIE node (Kali tools execution)
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
};

const app = new Hono<{ Bindings: Bindings }>();
app.use('*', cors());

function log(level: string, message: string, data: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), worker: 'echo-prometheus-surveillance', level, message, ...data }));
}

// ═══════════════════════════════════════════════════════════════
// HEALTH & STATUS
// ═══════════════════════════════════════════════════════════════

app.get('/health', async (c) => {
  const db = c.env.DB;
  let dbStatus = 'unknown';
  let stats: any = {};
  try {
    const r = await db.prepare('SELECT COUNT(*) as cnt FROM tracked_devices').first();
    dbStatus = 'connected';
    stats.tracked_devices = r?.cnt || 0;
    const towers = await db.prepare('SELECT COUNT(*) as cnt FROM cell_tower_logs').first();
    stats.tower_lookups = towers?.cnt || 0;
    const intercepts = await db.prepare('SELECT COUNT(*) as cnt FROM intercept_sessions').first();
    stats.intercept_sessions = intercepts?.cnt || 0;
    const cameras = await db.prepare('SELECT COUNT(*) as cnt FROM surveillance_cameras').first();
    stats.cameras = cameras?.cnt || 0;
    const alerts = await db.prepare("SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > datetime('now', '-24 hours')").first();
    stats.alerts_24h = alerts?.cnt || 0;
    const ipIntel = await db.prepare('SELECT COUNT(*) as cnt FROM ip_intel').first();
    stats.ips_tracked = ipIntel?.cnt || 0;
  } catch (e) { log("warn", "Health check DB query failed", { error: (e as Error)?.message || String(e) }); dbStatus = 'initializing'; }

  return c.json({
    status: 'healthy',
    worker: 'echo-prometheus-surveillance',
    version: '1.0.0',
    codename: 'ARGUS PANOPTES',
    timestamp: new Date().toISOString(),
    database: dbStatus,
    stats,
    modules: {
      gps_tracker: 'active',
      cell_tower: 'active',
      carrier_intel: 'active',
      phys_surveillance: 'active',
      active_intercept: 'active',
      ip_intelligence: 'active'
    },
    capabilities: [
      'Real-time GPS device tracking',
      'Cell tower triangulation (OpenCelliD + Google + BeaconDB + Mylnikov)',
      'Carrier-level location intelligence (Twilio Lookup)',
      'SS7/Diameter protocol analysis',
      'SIM swap detection',
      'CDR pattern analysis',
      'IP camera RTSP integration (ONVIF)',
      'License plate recognition (ALPR)',
      'Facial recognition routing',
      'Geofencing with real-time alerts',
      'Packet capture coordination',
      'MITM proxy management',
      'WiFi monitoring (aircrack-ng)',
      'DNS interception',
      'SSL/TLS inspection routing',
      'Multi-device fleet tracking',
      'Historical location playback',
      'Predictive movement analysis',
      'IP geolocation (3 free providers: ip-api, ipwhois, ipapi)',
      'IP threat intelligence (proxy/tor/bot/attacker/spam detection)',
      'Bulk IP lookup (up to 100 per request)',
      'IP threat feed (high-threat IP tracking)',
      'IP geo-search (find IPs by geographic area)'
    ]
  });
});

app.get('/init', async (c) => {
  const db = c.env.DB;
  try {
    const stmts = [
      `DROP TABLE IF EXISTS tracked_devices`,
      `CREATE TABLE tracked_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT UNIQUE NOT NULL, device_name TEXT NOT NULL, device_type TEXT DEFAULT 'unknown', tracking_method TEXT DEFAULT 'gps', last_lat REAL, last_lon REAL, last_altitude REAL, last_speed REAL, last_heading REAL, last_accuracy REAL, last_battery REAL, last_signal_strength INTEGER, last_seen TEXT, status TEXT DEFAULT 'active', metadata TEXT DEFAULT '{}', created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS location_history`,
      `CREATE TABLE location_history (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, lat REAL NOT NULL, lon REAL NOT NULL, altitude REAL, speed REAL, heading REAL, accuracy REAL, source TEXT DEFAULT 'gps', battery REAL, signal_strength INTEGER, cell_info TEXT, wifi_info TEXT, metadata TEXT DEFAULT '{}', timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_loc_device ON location_history(device_id, timestamp DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_loc_time ON location_history(timestamp DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_loc_coords ON location_history(lat, lon)`,
      `DROP TABLE IF EXISTS geofences`,
      `CREATE TABLE geofences (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, fence_type TEXT DEFAULT 'circle', center_lat REAL, center_lon REAL, radius_meters REAL, polygon_coords TEXT, alert_on_enter INTEGER DEFAULT 1, alert_on_exit INTEGER DEFAULT 1, alert_on_dwell INTEGER DEFAULT 0, dwell_threshold_seconds INTEGER DEFAULT 300, assigned_devices TEXT DEFAULT '[]', active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS geofence_alerts`,
      `CREATE TABLE geofence_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, geofence_id INTEGER, device_id TEXT, alert_type TEXT, lat REAL, lon REAL, details TEXT DEFAULT '{}', acknowledged INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS cell_tower_logs`,
      `CREATE TABLE cell_tower_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, mcc INTEGER, mnc INTEGER, lac INTEGER, cell_id INTEGER, signal_strength INTEGER, timing_advance INTEGER, frequency INTEGER, radio_type TEXT DEFAULT 'gsm', resolved_lat REAL, resolved_lon REAL, resolved_accuracy REAL, resolver TEXT, raw_response TEXT, device_id TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_cell_tower ON cell_tower_logs(mcc, mnc, lac, cell_id)`,
      `CREATE INDEX IF NOT EXISTS idx_cell_device ON cell_tower_logs(device_id, timestamp DESC)`,
      `DROP TABLE IF EXISTS cell_tower_db`,
      `CREATE TABLE cell_tower_db (id INTEGER PRIMARY KEY AUTOINCREMENT, mcc INTEGER NOT NULL, mnc INTEGER NOT NULL, lac INTEGER NOT NULL, cell_id INTEGER NOT NULL, lat REAL, lon REAL, range_meters REAL, radio_type TEXT, carrier TEXT, country TEXT, region TEXT, samples INTEGER DEFAULT 1, last_updated TEXT DEFAULT (datetime('now')), UNIQUE(mcc, mnc, lac, cell_id))`,
      `DROP TABLE IF EXISTS carrier_intel`,
      `CREATE TABLE carrier_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, phone_number TEXT, imsi TEXT, imei TEXT, carrier TEXT, carrier_country TEXT, number_type TEXT, roaming_status TEXT, hlr_status TEXT, last_known_msc TEXT, last_known_vlr TEXT, sim_swap_detected INTEGER DEFAULT 0, sim_swap_date TEXT, port_history TEXT DEFAULT '[]', metadata TEXT DEFAULT '{}', last_queried TEXT DEFAULT (datetime('now')), created_at TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_carrier_phone ON carrier_intel(phone_number)`,
      `CREATE INDEX IF NOT EXISTS idx_carrier_imsi ON carrier_intel(imsi)`,
      `DROP TABLE IF EXISTS ss7_analysis`,
      `CREATE TABLE ss7_analysis (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, target_msisdn TEXT, target_imsi TEXT, source_gt TEXT, dest_gt TEXT, message_type TEXT, opcode TEXT, result TEXT, location_data TEXT, subscriber_data TEXT, risk_score REAL DEFAULT 0, anomaly_flags TEXT DEFAULT '[]', raw_packet TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS cdr_records`,
      `CREATE TABLE cdr_records (id INTEGER PRIMARY KEY AUTOINCREMENT, calling_number TEXT, called_number TEXT, call_type TEXT, start_time TEXT, end_time TEXT, duration_seconds INTEGER, originating_cell TEXT, terminating_cell TEXT, originating_lat REAL, originating_lon REAL, terminating_lat REAL, terminating_lon REAL, imsi TEXT, imei TEXT, data_volume_bytes INTEGER, metadata TEXT DEFAULT '{}', imported_at TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_cdr_calling ON cdr_records(calling_number, start_time DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_cdr_called ON cdr_records(called_number, start_time DESC)`,
      `DROP TABLE IF EXISTS surveillance_cameras`,
      `CREATE TABLE surveillance_cameras (id INTEGER PRIMARY KEY AUTOINCREMENT, camera_id TEXT UNIQUE NOT NULL, camera_name TEXT NOT NULL, camera_type TEXT DEFAULT 'ip_camera', protocol TEXT DEFAULT 'rtsp', stream_url TEXT, onvif_url TEXT, lat REAL, lon REAL, heading REAL, fov_degrees REAL, resolution TEXT, fps INTEGER DEFAULT 30, has_ptz INTEGER DEFAULT 0, has_ir INTEGER DEFAULT 0, has_audio INTEGER DEFAULT 0, recording_mode TEXT DEFAULT 'continuous', ai_detection_enabled INTEGER DEFAULT 0, detection_classes TEXT DEFAULT '["person","vehicle"]', status TEXT DEFAULT 'active', last_frame_at TEXT, metadata TEXT DEFAULT '{}', created_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS alpr_reads`,
      `CREATE TABLE alpr_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, plate_number TEXT NOT NULL, plate_state TEXT, plate_country TEXT DEFAULT 'US', confidence REAL, camera_id TEXT, lat REAL, lon REAL, vehicle_color TEXT, vehicle_make TEXT, vehicle_model TEXT, vehicle_year TEXT, vehicle_type TEXT, image_url TEXT, direction TEXT, speed_estimate REAL, on_watchlist INTEGER DEFAULT 0, watchlist_reason TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_alpr_plate ON alpr_reads(plate_number, timestamp DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_alpr_camera ON alpr_reads(camera_id, timestamp DESC)`,
      `DROP TABLE IF EXISTS facial_recognition`,
      `CREATE TABLE facial_recognition (id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT UNIQUE, camera_id TEXT, face_encoding TEXT, matched_identity TEXT, match_confidence REAL, bounding_box TEXT, image_url TEXT, age_estimate INTEGER, gender_estimate TEXT, emotion_estimate TEXT, wearing_mask INTEGER DEFAULT 0, wearing_glasses INTEGER DEFAULT 0, on_watchlist INTEGER DEFAULT 0, watchlist_reason TEXT, lat REAL, lon REAL, timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_face_identity ON facial_recognition(matched_identity, timestamp DESC)`,
      `DROP TABLE IF EXISTS plate_watchlist`,
      `CREATE TABLE plate_watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, plate_number TEXT UNIQUE NOT NULL, reason TEXT NOT NULL, priority TEXT DEFAULT 'medium', alert_telegram INTEGER DEFAULT 1, alert_sms INTEGER DEFAULT 0, notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS person_watchlist`,
      `CREATE TABLE person_watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, identity_name TEXT NOT NULL, face_encodings TEXT DEFAULT '[]', description TEXT, priority TEXT DEFAULT 'medium', alert_telegram INTEGER DEFAULT 1, alert_sms INTEGER DEFAULT 0, reference_images TEXT DEFAULT '[]', notes TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))`,
      `DROP TABLE IF EXISTS intercept_sessions`,
      `CREATE TABLE intercept_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL, session_type TEXT NOT NULL, target TEXT, interface TEXT, node TEXT DEFAULT 'charlie', status TEXT DEFAULT 'active', packets_captured INTEGER DEFAULT 0, bytes_captured INTEGER DEFAULT 0, interesting_packets INTEGER DEFAULT 0, filter_expression TEXT, output_file TEXT, start_time TEXT DEFAULT (datetime('now')), end_time TEXT, metadata TEXT DEFAULT '{}')`,
      `DROP TABLE IF EXISTS captured_credentials`,
      `CREATE TABLE captured_credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, protocol TEXT, source_ip TEXT, source_port INTEGER, dest_ip TEXT, dest_port INTEGER, username TEXT, credential_hash TEXT, credential_type TEXT, service TEXT, url TEXT, raw_data TEXT, timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_cred_session ON captured_credentials(session_id)`,
      `DROP TABLE IF EXISTS dns_intercepts`,
      `CREATE TABLE dns_intercepts (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, query_domain TEXT NOT NULL, query_type TEXT DEFAULT 'A', original_response TEXT, spoofed_response TEXT, source_ip TEXT, action TEXT DEFAULT 'log', timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_intercepts(query_domain, timestamp DESC)`,
      `DROP TABLE IF EXISTS wifi_networks`,
      `CREATE TABLE wifi_networks (id INTEGER PRIMARY KEY AUTOINCREMENT, bssid TEXT NOT NULL, ssid TEXT, channel INTEGER, frequency INTEGER, signal_strength INTEGER, encryption TEXT, cipher TEXT, auth TEXT, wps INTEGER DEFAULT 0, clients_count INTEGER DEFAULT 0, lat REAL, lon REAL, first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now')), handshake_captured INTEGER DEFAULT 0, pmkid_captured INTEGER DEFAULT 0, cracked INTEGER DEFAULT 0, password TEXT, metadata TEXT DEFAULT '{}')`,
      `CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_networks(bssid)`,
      `CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON wifi_networks(ssid)`,
      `DROP TABLE IF EXISTS wifi_clients`,
      `CREATE TABLE wifi_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, mac_address TEXT NOT NULL, associated_bssid TEXT, probe_requests TEXT DEFAULT '[]', signal_strength INTEGER, packets INTEGER DEFAULT 0, data_bytes INTEGER DEFAULT 0, manufacturer TEXT, device_name TEXT, first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_wifi_client_mac ON wifi_clients(mac_address)`,
      `DROP TABLE IF EXISTS surveillance_log`,
      `CREATE TABLE surveillance_log (id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, details TEXT DEFAULT '{}', operator TEXT DEFAULT 'system', timestamp TEXT DEFAULT (datetime('now')))`,
      `CREATE INDEX IF NOT EXISTS idx_surv_log ON surveillance_log(module, timestamp DESC)`,
      // MODULE 6: IP INTELLIGENCE
      `DROP TABLE IF EXISTS ip_intel`,
      `CREATE TABLE ip_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL, lat REAL, lon REAL, city TEXT, region TEXT, country TEXT, isp TEXT, org TEXT, asn TEXT, reverse_dns TEXT, is_proxy INTEGER DEFAULT 0, is_vpn INTEGER DEFAULT 0, is_tor INTEGER DEFAULT 0, is_hosting INTEGER DEFAULT 0, is_mobile INTEGER DEFAULT 0, threat_score REAL DEFAULT 0, raw_data TEXT, last_queried TEXT DEFAULT (datetime('now')), UNIQUE(ip_address))`,
      `CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_intel(ip_address)`,
      `CREATE INDEX IF NOT EXISTS idx_ip_threat ON ip_intel(threat_score DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ip_geo ON ip_intel(lat, lon)`,
    ];
    await db.batch(stmts.map(s => db.prepare(s)));
    return c.json({ success: true, message: 'ARGUS PANOPTES initialized — all 6 surveillance modules ready', tables: 20, statements: stmts.length });
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════
// MODULE 1: REAL-TIME GPS TRACKING
// ═══════════════════════════════════════════════════════════════

// Register a device for tracking
app.post('/gps/devices', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { device_id, device_name, device_type, tracking_method, metadata } = body;
  if (!device_id || !device_name) return c.json({ error: 'device_id and device_name required' }, 400);

  await db.prepare(`
    INSERT OR REPLACE INTO tracked_devices (device_id, device_name, device_type, tracking_method, metadata, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  `).bind(device_id, device_name, device_type || 'unknown', tracking_method || 'gps', JSON.stringify(metadata || {})).run();

  await logAction(db, 'GPS_TRACKER', 'device_registered', device_id, { device_name, device_type });
  return c.json({ success: true, device_id });
});

// List all tracked devices
app.get('/gps/devices', async (c) => {
  const db = c.env.DB;
  const status = c.req.query('status') || 'all';
  let query = 'SELECT * FROM tracked_devices';
  if (status !== 'all') query += ` WHERE status = '${status}'`;
  query += ' ORDER BY last_seen DESC';
  const devices = await db.prepare(query).all();
  return c.json({ devices: devices.results, count: devices.results.length });
});

// Report location (from device or Traccar webhook)
app.post('/gps/report', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { device_id, lat, lon, altitude, speed, heading, accuracy, battery, signal_strength, cell_info, wifi_info, source } = body;
  if (!device_id || lat == null || lon == null) return c.json({ error: 'device_id, lat, lon required' }, 400);

  // Store in history
  await db.prepare(`
    INSERT INTO location_history (device_id, lat, lon, altitude, speed, heading, accuracy, source, battery, signal_strength, cell_info, wifi_info)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(device_id, lat, lon, altitude || null, speed || null, heading || null, accuracy || null,
    source || 'gps', battery || null, signal_strength || null,
    cell_info ? JSON.stringify(cell_info) : null, wifi_info ? JSON.stringify(wifi_info) : null).run();

  // Update device last known
  await db.prepare(`
    UPDATE tracked_devices SET last_lat = ?, last_lon = ?, last_altitude = ?, last_speed = ?,
    last_heading = ?, last_accuracy = ?, last_battery = ?, last_signal_strength = ?,
    last_seen = datetime('now'), updated_at = datetime('now') WHERE device_id = ?
  `).bind(lat, lon, altitude || null, speed || null, heading || null, accuracy || null,
    battery || null, signal_strength || null, device_id).run();

  // Check geofences
  const fenceAlerts = await checkGeofences(db, device_id, lat, lon);

  return c.json({ success: true, device_id, geofence_alerts: fenceAlerts });
});

// Traccar protocol webhook (OsmAnd format)
app.get('/gps/traccar', async (c) => {
  const db = c.env.DB;
  const id = c.req.query('id') || 'unknown';
  const lat = parseFloat(c.req.query('lat') || '0');
  const lon = parseFloat(c.req.query('lon') || '0');
  const speed = parseFloat(c.req.query('speed') || '0');
  const heading = parseFloat(c.req.query('bearing') || '0');
  const altitude = parseFloat(c.req.query('altitude') || '0');
  const battery = parseFloat(c.req.query('batt') || '0');
  const accuracy = parseFloat(c.req.query('accuracy') || '0');

  if (lat === 0 && lon === 0) return c.text('Invalid coordinates', 400);

  // Auto-register device if new
  await db.prepare(`
    INSERT OR IGNORE INTO tracked_devices (device_id, device_name, device_type, tracking_method)
    VALUES (?, ?, 'mobile', 'traccar')
  `).bind(id, `Traccar-${id}`).run();

  await db.prepare(`
    INSERT INTO location_history (device_id, lat, lon, altitude, speed, heading, accuracy, source, battery)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'traccar', ?)
  `).bind(id, lat, lon, altitude, speed, heading, accuracy, battery).run();

  await db.prepare(`
    UPDATE tracked_devices SET last_lat = ?, last_lon = ?, last_altitude = ?, last_speed = ?,
    last_heading = ?, last_accuracy = ?, last_battery = ?, last_seen = datetime('now'), updated_at = datetime('now')
    WHERE device_id = ?
  `).bind(lat, lon, altitude, speed, heading, accuracy, battery, id).run();

  await checkGeofences(db, id, lat, lon);
  return c.text('OK');
});

// Get device location history
app.get('/gps/history/:device_id', async (c) => {
  const db = c.env.DB;
  const device_id = c.req.param('device_id');
  const hours = parseInt(c.req.query('hours') || '24');
  const limit = parseInt(c.req.query('limit') || '500');

  const history = await db.prepare(`
    SELECT * FROM location_history WHERE device_id = ? AND timestamp > datetime('now', '-${hours} hours')
    ORDER BY timestamp DESC LIMIT ?
  `).bind(device_id, limit).all();

  // Calculate stats
  let totalDistance = 0;
  const points = history.results;
  for (let i = 1; i < points.length; i++) {
    totalDistance += haversine(
      points[i - 1].lat as number, points[i - 1].lon as number,
      points[i].lat as number, points[i].lon as number
    );
  }

  return c.json({
    device_id,
    points: points.length,
    total_distance_km: Math.round(totalDistance * 100) / 100,
    time_range_hours: hours,
    history: points
  });
});

// Real-time tracking dashboard data (all active devices)
app.get('/gps/live', async (c) => {
  const db = c.env.DB;
  const devices = await db.prepare(`
    SELECT d.*,
      (SELECT COUNT(*) FROM location_history WHERE device_id = d.device_id AND timestamp > datetime('now', '-1 hour')) as points_1h,
      (SELECT COUNT(*) FROM geofence_alerts WHERE device_id = d.device_id AND acknowledged = 0) as pending_alerts
    FROM tracked_devices d WHERE d.status = 'active' ORDER BY d.last_seen DESC
  `).all();

  return c.json({ devices: devices.results, count: devices.results.length, timestamp: new Date().toISOString() });
});

// Predictive movement analysis
app.post('/gps/predict', async (c) => {
  const db = c.env.DB;
  const { device_id, hours_ahead } = await c.req.json();
  if (!device_id) return c.json({ error: 'device_id required' }, 400);

  const history = await db.prepare(`
    SELECT lat, lon, speed, heading, timestamp FROM location_history
    WHERE device_id = ? ORDER BY timestamp DESC LIMIT 100
  `).bind(device_id).all();

  if (history.results.length < 5) return c.json({ error: 'Insufficient data for prediction', points: history.results.length });

  // Analyze movement patterns
  const points = history.results;
  const patterns = analyzeMovementPatterns(points);

  return c.json({
    device_id,
    data_points: points.length,
    patterns,
    prediction: {
      hours_ahead: hours_ahead || 1,
      likely_locations: patterns.frequent_stops,
      movement_trend: patterns.trend,
      confidence: patterns.confidence
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// GEOFENCING
// ═══════════════════════════════════════════════════════════════

app.post('/geofence', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { name, center_lat, center_lon, radius_meters, polygon_coords, fence_type, alert_on_enter, alert_on_exit, alert_on_dwell, dwell_threshold_seconds, assigned_devices } = body;
  if (!name) return c.json({ error: 'name required' }, 400);

  const result = await db.prepare(`
    INSERT INTO geofences (name, fence_type, center_lat, center_lon, radius_meters, polygon_coords, alert_on_enter, alert_on_exit, alert_on_dwell, dwell_threshold_seconds, assigned_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(name, fence_type || 'circle', center_lat || null, center_lon || null, radius_meters || 500,
    polygon_coords ? JSON.stringify(polygon_coords) : null,
    alert_on_enter ?? 1, alert_on_exit ?? 1, alert_on_dwell ?? 0,
    dwell_threshold_seconds || 300, JSON.stringify(assigned_devices || [])).run();

  await logAction(db, 'GPS_TRACKER', 'geofence_created', name, { center_lat, center_lon, radius_meters });
  return c.json({ success: true, geofence_id: result.meta.last_row_id });
});

app.get('/geofence', async (c) => {
  const db = c.env.DB;
  const fences = await db.prepare('SELECT * FROM geofences WHERE active = 1 ORDER BY created_at DESC').all();
  return c.json({ geofences: fences.results, count: fences.results.length });
});

app.get('/geofence/alerts', async (c) => {
  const db = c.env.DB;
  const hours = parseInt(c.req.query('hours') || '24');
  const alerts = await db.prepare(`
    SELECT ga.*, g.name as geofence_name, d.device_name
    FROM geofence_alerts ga
    LEFT JOIN geofences g ON ga.geofence_id = g.id
    LEFT JOIN tracked_devices d ON ga.device_id = d.device_id
    WHERE ga.created_at > datetime('now', '-${hours} hours')
    ORDER BY ga.created_at DESC
  `).all();
  return c.json({ alerts: alerts.results, count: alerts.results.length });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 2: CELL TOWER TRIANGULATION
// ═══════════════════════════════════════════════════════════════

// Triangulate location from cell tower data
app.post('/cell/triangulate', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { towers, device_id } = body;
  // towers: [{mcc, mnc, lac, cell_id, signal_strength, timing_advance, radio_type}]
  if (!towers || !towers.length) return c.json({ error: 'towers array required' }, 400);

  const results: any[] = [];

  // Try multiple resolvers in priority order
  for (const tower of towers) {
    let resolved = null;

    // 1. Check local cache first
    const cached = await db.prepare(`
      SELECT lat, lon, range_meters FROM cell_tower_db WHERE mcc = ? AND mnc = ? AND lac = ? AND cell_id = ?
    `).bind(tower.mcc, tower.mnc, tower.lac, tower.cell_id).first();

    if (cached) {
      resolved = { lat: cached.lat, lon: cached.lon, accuracy: cached.range_meters, resolver: 'local_cache' };
    }

    // 2. OpenCelliD API
    if (!resolved && c.env.OPENCELLID_API_KEY) {
      try {
        const resp = await fetch(
          `https://opencellid.org/cell/get?key=${c.env.OPENCELLID_API_KEY}&mcc=${tower.mcc}&mnc=${tower.mnc}&lac=${tower.lac}&cellid=${tower.cell_id}&format=json`
        );
        if (resp.ok) {
          const data: any = await resp.json();
          if (data.lat && data.lon) {
            resolved = { lat: data.lat, lon: data.lon, accuracy: data.range || 1000, resolver: 'opencellid' };
            await cacheTower(db, tower, data.lat, data.lon, data.range, 'opencellid');
          }
        }
      } catch (e) { log("warn", "OpenCelliD lookup failed", { error: (e as Error)?.message || String(e) }); }
    }

    // 3. UnwiredLabs API
    if (!resolved && c.env.UNWIREDLABS_API_KEY) {
      try {
        const resp = await fetch('https://us1.unwiredlabs.com/v2/process', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: c.env.UNWIREDLABS_API_KEY,
            radio: tower.radio_type || 'gsm',
            mcc: tower.mcc, mnc: tower.mnc,
            cells: [{ lac: tower.lac, cid: tower.cell_id, signal: tower.signal_strength || -70 }]
          })
        });
        if (resp.ok) {
          const data: any = await resp.json();
          if (data.status === 'ok' && data.lat && data.lon) {
            resolved = { lat: data.lat, lon: data.lon, accuracy: data.accuracy || 500, resolver: 'unwiredlabs' };
            await cacheTower(db, tower, data.lat, data.lon, data.accuracy, 'unwiredlabs');
          }
        }
      } catch (e) { log("warn", "UnwiredLabs lookup failed", { error: (e as Error)?.message || String(e) }); }
    }

    // 4. Google Geolocation API (free $200/month credit)
    if (!resolved && c.env.GOOGLE_API_KEY) {
      try {
        const resp = await fetch(`https://www.googleapis.com/geolocation/v1/geolocate?key=${c.env.GOOGLE_API_KEY}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cellTowers: [{
              cellId: tower.cell_id,
              locationAreaCode: tower.lac,
              mobileCountryCode: tower.mcc,
              mobileNetworkCode: tower.mnc,
              signalStrength: tower.signal_strength || -70
            }]
          })
        });
        if (resp.ok) {
          const data: any = await resp.json();
          if (data.location) {
            resolved = { lat: data.location.lat, lon: data.location.lng, accuracy: data.accuracy || 1000, resolver: 'google' };
            await cacheTower(db, tower, data.location.lat, data.location.lng, data.accuracy, 'google');
          }
        }
      } catch (e) { log("warn", "Google Geolocation lookup failed", { error: (e as Error)?.message || String(e) }); }
    }

    // 5. BeaconDB (free, no key needed — community cell tower database)
    if (!resolved) {
      try {
        const resp = await fetch('https://beacondb.net/v1/geolocate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cellTowers: [{
              radioType: tower.radio_type || 'lte',
              mobileCountryCode: tower.mcc,
              mobileNetworkCode: tower.mnc,
              locationAreaCode: tower.lac,
              cellId: tower.cell_id,
              signalStrength: tower.signal_strength || -70
            }]
          })
        });
        if (resp.ok) {
          const data: any = await resp.json();
          if (data.location) {
            resolved = { lat: data.location.lat, lon: data.location.lng, accuracy: data.accuracy || 2000, resolver: 'beacondb' };
            await cacheTower(db, tower, data.location.lat, data.location.lng, data.accuracy || 2000, 'beacondb');
          }
        }
      } catch (e) { log("warn", "BeaconDB lookup failed", { error: (e as Error)?.message || String(e) }); }
    }

    // 6. Mylnikov.org (free, no key needed — open cell tower database)
    if (!resolved) {
      try {
        const resp = await fetch(
          `https://api.mylnikov.org/geolocation/cell?v=1.1&data=open&mcc=${tower.mcc}&mnc=${tower.mnc}&lac=${tower.lac}&cellid=${tower.cell_id}`,
          { signal: AbortSignal.timeout(8000) }
        );
        if (resp.ok) {
          const data: any = await resp.json();
          if (data.result === 200 && data.data) {
            resolved = { lat: data.data.lat, lon: data.data.lon, accuracy: data.data.range || 3000, resolver: 'mylnikov' };
            await cacheTower(db, tower, data.data.lat, data.data.lon, data.data.range || 3000, 'mylnikov');
          }
        }
      } catch (e) { log("warn", "Mylnikov lookup failed", { error: (e as Error)?.message || String(e) }); }
    }

    // Log the tower lookup
    await db.prepare(`
      INSERT INTO cell_tower_logs (mcc, mnc, lac, cell_id, signal_strength, timing_advance, frequency, radio_type, resolved_lat, resolved_lon, resolved_accuracy, resolver, device_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(tower.mcc, tower.mnc, tower.lac, tower.cell_id, tower.signal_strength || null,
      tower.timing_advance || null, tower.frequency || null, tower.radio_type || 'gsm',
      resolved?.lat || null, resolved?.lon || null, resolved?.accuracy || null,
      resolved?.resolver || 'unresolved', device_id || null).run();

    results.push({ tower, resolved });
  }

  // If multiple towers resolved, triangulate weighted by signal strength
  const resolvedTowers = results.filter(r => r.resolved);
  let triangulated = null;

  if (resolvedTowers.length >= 2) {
    triangulated = weightedTriangulation(resolvedTowers);
  } else if (resolvedTowers.length === 1) {
    triangulated = {
      lat: resolvedTowers[0].resolved.lat,
      lon: resolvedTowers[0].resolved.lon,
      accuracy: resolvedTowers[0].resolved.accuracy,
      method: 'single_tower'
    };
  }

  await logAction(db, 'CELL_TOWER', 'triangulate', device_id || 'unknown', {
    towers_submitted: towers.length,
    towers_resolved: resolvedTowers.length,
    triangulated: !!triangulated
  });

  return c.json({
    success: true,
    towers_submitted: towers.length,
    towers_resolved: resolvedTowers.length,
    individual_results: results,
    triangulated_location: triangulated
  });
});

// Lookup single cell tower
app.get('/cell/lookup', async (c) => {
  const db = c.env.DB;
  const mcc = parseInt(c.req.query('mcc') || '0');
  const mnc = parseInt(c.req.query('mnc') || '0');
  const lac = parseInt(c.req.query('lac') || '0');
  const cell_id = parseInt(c.req.query('cell_id') || '0');

  const cached = await db.prepare(`
    SELECT * FROM cell_tower_db WHERE mcc = ? AND mnc = ? AND lac = ? AND cell_id = ?
  `).bind(mcc, mnc, lac, cell_id).first();

  return c.json({ found: !!cached, tower: cached });
});

// Bulk import cell tower database
app.post('/cell/import', async (c) => {
  const db = c.env.DB;
  const { towers } = await c.req.json();
  if (!towers || !Array.isArray(towers)) return c.json({ error: 'towers array required' }, 400);

  let imported = 0;
  for (const t of towers) {
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO cell_tower_db (mcc, mnc, lac, cell_id, lat, lon, range_meters, radio_type, carrier, country, region, samples, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(t.mcc, t.mnc, t.lac, t.cell_id, t.lat, t.lon, t.range || 1000,
        t.radio_type || 'gsm', t.carrier || null, t.country || null, t.region || null, t.samples || 1).run();
      imported++;
    } catch (e) { log("warn", "Cell tower import row failed", { error: (e as Error)?.message || String(e) }); }
  }

  return c.json({ success: true, imported, total_submitted: towers.length });
});

// Cell tower history for a device
app.get('/cell/history/:device_id', async (c) => {
  const db = c.env.DB;
  const device_id = c.req.param('device_id');
  const hours = parseInt(c.req.query('hours') || '24');

  const history = await db.prepare(`
    SELECT * FROM cell_tower_logs WHERE device_id = ? AND timestamp > datetime('now', '-${hours} hours')
    ORDER BY timestamp DESC
  `).bind(device_id).all();

  return c.json({ device_id, logs: history.results, count: history.results.length });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 3: CARRIER-LEVEL INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

// HLR/SS7 phone number lookup
app.post('/carrier/lookup', async (c) => {
  const db = c.env.DB;
  const { phone_number, imsi, imei } = await c.req.json();
  if (!phone_number && !imsi) return c.json({ error: 'phone_number or imsi required' }, 400);

  // Check cache first
  const existing = phone_number
    ? await db.prepare('SELECT * FROM carrier_intel WHERE phone_number = ?').bind(phone_number).first()
    : await db.prepare('SELECT * FROM carrier_intel WHERE imsi = ?').bind(imsi).first();

  // Perform HLR/carrier lookup via Twilio Lookup API (primary) or Numverify (fallback)
  let hlrResult: any = null;

  // 1. Twilio Lookup API v1 (carrier data — WORKING)
  if (!hlrResult && c.env.TWILIO_SID && c.env.TWILIO_AUTH && phone_number) {
    try {
      const encoded = encodeURIComponent(phone_number.startsWith('+') ? phone_number : `+${phone_number}`);
      const resp = await fetch(
        `https://lookups.twilio.com/v1/PhoneNumbers/${encoded}?Type=carrier`,
        {
          headers: { 'Authorization': 'Basic ' + btoa(`${c.env.TWILIO_SID}:${c.env.TWILIO_AUTH}`) },
          signal: AbortSignal.timeout(8000)
        }
      );
      if (resp.ok) {
        const data: any = await resp.json();
        hlrResult = {
          source: 'twilio',
          data: {
            carrier: data.carrier?.name || null,
            type: data.carrier?.type || null,
            country: data.country_code || null,
            mcc: data.carrier?.mobile_country_code || null,
            mnc: data.carrier?.mobile_network_code || null,
            valid: true,
            national_format: data.national_format
          }
        };
      }
    } catch (e) { log("warn", "Twilio carrier lookup failed", { error: (e as Error)?.message || String(e) }); }
  }

  // 2. Numverify fallback
  if (!hlrResult && c.env.NUMVERIFY_API_KEY && phone_number) {
    try {
      const resp = await fetch(
        `https://apilayer.net/api/validate?access_key=${c.env.NUMVERIFY_API_KEY}&number=${phone_number}`,
        { signal: AbortSignal.timeout(5000) }
      );
      if (resp.ok) {
        hlrResult = { source: 'numverify', data: await resp.json() };
      }
    } catch (e) { log("warn", "Numverify carrier lookup failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Carrier identification from number prefix
  const carrierInfo = identifyCarrier(phone_number || '');

  // Store/update
  await db.prepare(`
    INSERT OR REPLACE INTO carrier_intel (phone_number, imsi, imei, carrier, carrier_country, number_type, hlr_status, last_queried)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).bind(phone_number || null, imsi || null, imei || null,
    hlrResult?.data?.carrier || carrierInfo.carrier || 'unknown',
    hlrResult?.data?.country || carrierInfo.country || 'unknown',
    hlrResult?.data?.type || carrierInfo.type || 'unknown',
    hlrResult ? 'queried' : 'prefix_only').run();

  await logAction(db, 'CARRIER_INTEL', 'hlr_lookup', phone_number || imsi || 'unknown', { carrier: carrierInfo.carrier });

  return c.json({
    success: true,
    phone_number,
    carrier: carrierInfo,
    hlr_result: hlrResult,
    cached_data: existing
  });
});

// SIM swap detection
app.post('/carrier/sim-swap-check', async (c) => {
  const db = c.env.DB;
  const { phone_number } = await c.req.json();
  if (!phone_number) return c.json({ error: 'phone_number required' }, 400);

  // Check carrier_intel for historical data
  const existing = await db.prepare('SELECT * FROM carrier_intel WHERE phone_number = ?').bind(phone_number).first();

  // Perform fresh HLR lookup and compare IMSI
  let simSwapDetected = false;
  let details: any = {};

  if (existing && existing.imsi) {
    // Compare with fresh lookup — if IMSI changed, SIM swap detected
    details.previous_imsi = existing.imsi;
    details.last_checked = existing.last_queried;
    details.recommendation = 'Perform fresh HLR lookup to compare IMSI values';
  }

  // Check port history
  const portHistory = existing?.port_history ? JSON.parse(existing.port_history as string) : [];

  await logAction(db, 'CARRIER_INTEL', 'sim_swap_check', phone_number, { detected: simSwapDetected });

  return c.json({
    phone_number,
    sim_swap_detected: simSwapDetected,
    port_history: portHistory,
    details,
    last_known_carrier: existing?.carrier || 'unknown'
  });
});

// SS7 protocol analysis (log and analyze SS7 messages)
app.post('/carrier/ss7/analyze', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { operation, target_msisdn, target_imsi, source_gt, dest_gt, message_type, opcode, raw_packet } = body;

  // Analyze for anomalies
  const anomalies: string[] = [];
  let riskScore = 0;

  // Known malicious SS7 operations
  const suspiciousOps = ['SendRoutingInfoForSM', 'ProvideSubscriberInfo', 'SendRoutingInfo', 'AnyTimeInterrogation', 'InsertSubscriberData'];
  if (suspiciousOps.includes(operation || '')) {
    anomalies.push(`Surveillance-capable operation: ${operation}`);
    riskScore += 3;
  }

  // Check if source GT is from unexpected network
  if (source_gt && !source_gt.startsWith('1')) {
    anomalies.push('Foreign source Global Title — potential roaming intercept');
    riskScore += 2;
  }

  // High-frequency same-target queries
  const recentQueries = await db.prepare(`
    SELECT COUNT(*) as cnt FROM ss7_analysis
    WHERE target_msisdn = ? AND timestamp > datetime('now', '-1 hour')
  `).bind(target_msisdn || '').first();
  if ((recentQueries?.cnt as number || 0) > 10) {
    anomalies.push(`High-frequency tracking: ${recentQueries?.cnt} queries in 1 hour`);
    riskScore += 4;
  }

  riskScore = Math.min(riskScore, 10);

  await db.prepare(`
    INSERT INTO ss7_analysis (operation, target_msisdn, target_imsi, source_gt, dest_gt, message_type, opcode, risk_score, anomaly_flags, raw_packet)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(operation || null, target_msisdn || null, target_imsi || null, source_gt || null, dest_gt || null,
    message_type || null, opcode || null, riskScore, JSON.stringify(anomalies), raw_packet || null).run();

  return c.json({
    success: true,
    risk_score: riskScore,
    risk_level: riskScore >= 7 ? 'CRITICAL' : riskScore >= 4 ? 'HIGH' : riskScore >= 2 ? 'MEDIUM' : 'LOW',
    anomalies,
    operation
  });
});

// CDR (Call Detail Record) import and analysis
app.post('/carrier/cdr/import', async (c) => {
  const db = c.env.DB;
  const { records } = await c.req.json();
  if (!records || !Array.isArray(records)) return c.json({ error: 'records array required' }, 400);

  let imported = 0;
  for (const r of records) {
    try {
      await db.prepare(`
        INSERT INTO cdr_records (calling_number, called_number, call_type, start_time, end_time, duration_seconds,
          originating_cell, terminating_cell, originating_lat, originating_lon, terminating_lat, terminating_lon,
          imsi, imei, data_volume_bytes, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(r.calling_number, r.called_number, r.call_type || 'voice', r.start_time, r.end_time || null,
        r.duration_seconds || 0, r.originating_cell || null, r.terminating_cell || null,
        r.originating_lat || null, r.originating_lon || null, r.terminating_lat || null, r.terminating_lon || null,
        r.imsi || null, r.imei || null, r.data_volume_bytes || 0, JSON.stringify(r.metadata || {})).run();
      imported++;
    } catch (e) { log("warn", "CDR import row failed", { error: (e as Error)?.message || String(e) }); }
  }

  return c.json({ success: true, imported, total_submitted: records.length });
});

// CDR pattern analysis
app.post('/carrier/cdr/analyze', async (c) => {
  const db = c.env.DB;
  const { phone_number, hours } = await c.req.json();
  if (!phone_number) return c.json({ error: 'phone_number required' }, 400);

  const timeframe = hours || 720; // 30 days default

  // Get all CDRs for this number
  const cdrs = await db.prepare(`
    SELECT * FROM cdr_records
    WHERE (calling_number = ? OR called_number = ?) AND start_time > datetime('now', '-${timeframe} hours')
    ORDER BY start_time DESC
  `).bind(phone_number, phone_number).all();

  const records = cdrs.results;

  // Analysis
  const contactFrequency: Record<string, number> = {};
  const hourDistribution = new Array(24).fill(0);
  const locations: any[] = [];
  let totalDuration = 0;

  for (const r of records) {
    const other = r.calling_number === phone_number ? r.called_number : r.calling_number;
    contactFrequency[other as string] = (contactFrequency[other as string] || 0) + 1;
    totalDuration += (r.duration_seconds as number) || 0;

    if (r.start_time) {
      const hour = new Date(r.start_time as string).getHours();
      hourDistribution[hour]++;
    }

    if (r.originating_lat && r.originating_lon) {
      locations.push({ lat: r.originating_lat, lon: r.originating_lon, time: r.start_time });
    }
  }

  const topContacts = Object.entries(contactFrequency)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 20)
    .map(([number, count]) => ({ number, count }));

  return c.json({
    phone_number,
    timeframe_hours: timeframe,
    total_records: records.length,
    total_duration_minutes: Math.round(totalDuration / 60),
    top_contacts: topContacts,
    hour_distribution: hourDistribution,
    unique_locations: locations.length,
    location_points: locations.slice(0, 100)
  });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 4: PHYSICAL SURVEILLANCE
// ═══════════════════════════════════════════════════════════════

// Register camera
app.post('/surveillance/cameras', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { camera_id, camera_name, camera_type, protocol, stream_url, onvif_url, lat, lon, heading, fov_degrees, resolution, fps, has_ptz, has_ir, has_audio, recording_mode, ai_detection_enabled, detection_classes } = body;
  if (!camera_id || !camera_name) return c.json({ error: 'camera_id and camera_name required' }, 400);

  await db.prepare(`
    INSERT OR REPLACE INTO surveillance_cameras (camera_id, camera_name, camera_type, protocol, stream_url, onvif_url,
      lat, lon, heading, fov_degrees, resolution, fps, has_ptz, has_ir, has_audio, recording_mode,
      ai_detection_enabled, detection_classes, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
  `).bind(camera_id, camera_name, camera_type || 'ip_camera', protocol || 'rtsp',
    stream_url || null, onvif_url || null, lat || null, lon || null,
    heading || null, fov_degrees || null, resolution || '1080p', fps || 30,
    has_ptz || 0, has_ir || 0, has_audio || 0, recording_mode || 'continuous',
    ai_detection_enabled || 0, JSON.stringify(detection_classes || ['person', 'vehicle'])).run();

  await logAction(db, 'PHYS_SURV', 'camera_registered', camera_id, { camera_name, stream_url });
  return c.json({ success: true, camera_id });
});

// List cameras
app.get('/surveillance/cameras', async (c) => {
  const db = c.env.DB;
  const cameras = await db.prepare('SELECT * FROM surveillance_cameras WHERE status = "active" ORDER BY camera_name').all();
  return c.json({ cameras: cameras.results, count: cameras.results.length });
});

// ALPR - report plate read
app.post('/surveillance/alpr/read', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { plate_number, plate_state, confidence, camera_id, lat, lon, vehicle_color, vehicle_make, vehicle_model, vehicle_year, vehicle_type, image_url, direction, speed_estimate } = body;
  if (!plate_number) return c.json({ error: 'plate_number required' }, 400);

  // Check watchlist
  const watched = await db.prepare('SELECT * FROM plate_watchlist WHERE plate_number = ? AND active = 1').bind(plate_number.toUpperCase()).first();

  const result = await db.prepare(`
    INSERT INTO alpr_reads (plate_number, plate_state, confidence, camera_id, lat, lon,
      vehicle_color, vehicle_make, vehicle_model, vehicle_year, vehicle_type,
      image_url, direction, speed_estimate, on_watchlist, watchlist_reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(plate_number.toUpperCase(), plate_state || null, confidence || null, camera_id || null,
    lat || null, lon || null, vehicle_color || null, vehicle_make || null,
    vehicle_model || null, vehicle_year || null, vehicle_type || null,
    image_url || null, direction || null, speed_estimate || null,
    watched ? 1 : 0, watched?.reason || null).run();

  // If on watchlist, trigger alert
  if (watched) {
    await logAction(db, 'PHYS_SURV', 'watchlist_hit', plate_number, { camera_id, reason: watched.reason, priority: watched.priority });
  }

  return c.json({ success: true, plate_number, on_watchlist: !!watched, watchlist_alert: watched ? { reason: watched.reason, priority: watched.priority } : null });
});

// ALPR search
app.get('/surveillance/alpr/search', async (c) => {
  const db = c.env.DB;
  const plate = c.req.query('plate') || '';
  const hours = parseInt(c.req.query('hours') || '168');

  const reads = await db.prepare(`
    SELECT * FROM alpr_reads WHERE plate_number LIKE ? AND timestamp > datetime('now', '-${hours} hours')
    ORDER BY timestamp DESC LIMIT 100
  `).bind(`%${plate.toUpperCase()}%`).all();

  return c.json({ plate_query: plate, reads: reads.results, count: reads.results.length });
});

// Plate watchlist management
app.post('/surveillance/alpr/watchlist', async (c) => {
  const db = c.env.DB;
  const { plate_number, reason, priority, alert_telegram, alert_sms, notes } = await c.req.json();
  if (!plate_number || !reason) return c.json({ error: 'plate_number and reason required' }, 400);

  await db.prepare(`
    INSERT OR REPLACE INTO plate_watchlist (plate_number, reason, priority, alert_telegram, alert_sms, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(plate_number.toUpperCase(), reason, priority || 'medium', alert_telegram ?? 1, alert_sms ?? 0, notes || null).run();

  return c.json({ success: true, plate_number: plate_number.toUpperCase() });
});

app.get('/surveillance/alpr/watchlist', async (c) => {
  const db = c.env.DB;
  const list = await db.prepare('SELECT * FROM plate_watchlist WHERE active = 1 ORDER BY priority DESC, created_at DESC').all();
  return c.json({ watchlist: list.results, count: list.results.length });
});

// Facial recognition - report detection
app.post('/surveillance/face/detect', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { detection_id, camera_id, face_encoding, matched_identity, match_confidence, bounding_box, image_url, age_estimate, gender_estimate, emotion_estimate, wearing_mask, wearing_glasses, lat, lon } = body;

  // Check person watchlist
  let onWatchlist = false;
  let watchlistReason = null;
  if (matched_identity) {
    const watched = await db.prepare('SELECT * FROM person_watchlist WHERE identity_name = ? AND active = 1').bind(matched_identity).first();
    if (watched) {
      onWatchlist = true;
      watchlistReason = watched.description;
    }
  }

  await db.prepare(`
    INSERT INTO facial_recognition (detection_id, camera_id, face_encoding, matched_identity, match_confidence,
      bounding_box, image_url, age_estimate, gender_estimate, emotion_estimate,
      wearing_mask, wearing_glasses, on_watchlist, watchlist_reason, lat, lon)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(detection_id || crypto.randomUUID(), camera_id || null, face_encoding || null,
    matched_identity || null, match_confidence || null,
    bounding_box ? JSON.stringify(bounding_box) : null, image_url || null,
    age_estimate || null, gender_estimate || null, emotion_estimate || null,
    wearing_mask || 0, wearing_glasses || 0, onWatchlist ? 1 : 0,
    watchlistReason, lat || null, lon || null).run();

  if (onWatchlist) {
    await logAction(db, 'PHYS_SURV', 'face_watchlist_hit', matched_identity || 'unknown', { camera_id, confidence: match_confidence });
  }

  return c.json({ success: true, on_watchlist: onWatchlist, matched_identity, match_confidence });
});

// Person watchlist management
app.post('/surveillance/face/watchlist', async (c) => {
  const db = c.env.DB;
  const { identity_name, description, face_encodings, priority, alert_telegram, alert_sms, reference_images, notes } = await c.req.json();
  if (!identity_name) return c.json({ error: 'identity_name required' }, 400);

  await db.prepare(`
    INSERT OR REPLACE INTO person_watchlist (identity_name, description, face_encodings, priority, alert_telegram, alert_sms, reference_images, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(identity_name, description || null, JSON.stringify(face_encodings || []),
    priority || 'medium', alert_telegram ?? 1, alert_sms ?? 0,
    JSON.stringify(reference_images || []), notes || null).run();

  return c.json({ success: true, identity_name });
});

app.get('/surveillance/face/watchlist', async (c) => {
  const db = c.env.DB;
  const list = await db.prepare('SELECT * FROM person_watchlist WHERE active = 1 ORDER BY priority DESC').all();
  return c.json({ watchlist: list.results, count: list.results.length });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 5: ACTIVE INTERCEPTION
// ═══════════════════════════════════════════════════════════════

// Start intercept session (dispatches to CHARLIE/Kali)
app.post('/intercept/start', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { session_type, target, interface: iface, filter_expression, node } = body;
  // session_type: packet_capture | mitm_proxy | wifi_monitor | dns_intercept | ssl_inspect
  if (!session_type) return c.json({ error: 'session_type required' }, 400);

  const session_id = `int_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  await db.prepare(`
    INSERT INTO intercept_sessions (session_id, session_type, target, interface, node, filter_expression, status)
    VALUES (?, ?, ?, ?, ?, ?, 'starting')
  `).bind(session_id, session_type, target || null, iface || 'eth0', node || 'charlie', filter_expression || null).run();

  // Dispatch to CHARLIE node via Commander API
  let dispatchResult: any = null;
  if (c.env.COMMANDER_API_URL) {
    try {
      const commands: Record<string, string> = {
        packet_capture: `sudo tcpdump -i ${iface || 'eth0'} ${filter_expression || ''} -w /tmp/${session_id}.pcap -c 10000 &`,
        mitm_proxy: `mitmproxy --mode transparent -w /tmp/${session_id}.flow --set console_eventlog_verbosity=error &`,
        wifi_monitor: `sudo airmon-ng start ${iface || 'wlan0'} && sudo airodump-ng ${iface || 'wlan0'}mon -w /tmp/${session_id} --output-format csv &`,
        dns_intercept: `sudo python3 /opt/echo/dns_intercept.py --interface ${iface || 'eth0'} --log /tmp/${session_id}_dns.json &`,
        ssl_inspect: `mitmproxy --mode regular --listen-port 8443 --ssl-insecure -w /tmp/${session_id}_ssl.flow &`
      };

      const cmd = commands[session_type];
      if (cmd) {
        const resp = await fetch(`${c.env.COMMANDER_API_URL}/exec`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY || '' },
          body: JSON.stringify({ command: cmd, node: node || 'charlie' }),
          signal: AbortSignal.timeout(10000)
        });
        dispatchResult = await resp.json();
      }
    } catch (e: any) {
      dispatchResult = { error: e.message };
    }
  }

  await db.prepare("UPDATE intercept_sessions SET status = 'active' WHERE session_id = ?").bind(session_id).run();
  await logAction(db, 'ACTIVE_INTERCEPT', 'session_started', session_id, { session_type, target, node });

  return c.json({ success: true, session_id, session_type, status: 'active', dispatch: dispatchResult });
});

// Stop intercept session
app.post('/intercept/stop', async (c) => {
  const db = c.env.DB;
  const { session_id } = await c.req.json();
  if (!session_id) return c.json({ error: 'session_id required' }, 400);

  await db.prepare("UPDATE intercept_sessions SET status = 'stopped', end_time = datetime('now') WHERE session_id = ?").bind(session_id).run();
  await logAction(db, 'ACTIVE_INTERCEPT', 'session_stopped', session_id, {});

  return c.json({ success: true, session_id, status: 'stopped' });
});

// List active intercept sessions
app.get('/intercept/sessions', async (c) => {
  const db = c.env.DB;
  const status = c.req.query('status') || 'active';
  const sessions = await db.prepare(
    status === 'all'
      ? 'SELECT * FROM intercept_sessions ORDER BY start_time DESC LIMIT 50'
      : `SELECT * FROM intercept_sessions WHERE status = ? ORDER BY start_time DESC LIMIT 50`
  ).bind(...(status === 'all' ? [] : [status])).all();

  return c.json({ sessions: sessions.results, count: sessions.results.length });
});

// Report captured credentials
app.post('/intercept/credentials', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { session_id, protocol, source_ip, source_port, dest_ip, dest_port, username, credential_hash, credential_type, service, url, raw_data } = body;

  await db.prepare(`
    INSERT INTO captured_credentials (session_id, protocol, source_ip, source_port, dest_ip, dest_port,
      username, credential_hash, credential_type, service, url, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(session_id || null, protocol || null, source_ip || null, source_port || null,
    dest_ip || null, dest_port || null, username || null, credential_hash || null,
    credential_type || null, service || null, url || null, raw_data || null).run();

  await logAction(db, 'ACTIVE_INTERCEPT', 'credential_captured', session_id || 'unknown', { protocol, service, username });
  return c.json({ success: true });
});

// DNS interception log
app.post('/intercept/dns', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { session_id, query_domain, query_type, original_response, spoofed_response, source_ip, action } = body;

  await db.prepare(`
    INSERT INTO dns_intercepts (session_id, query_domain, query_type, original_response, spoofed_response, source_ip, action)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(session_id || null, query_domain, query_type || 'A',
    original_response || null, spoofed_response || null, source_ip || null, action || 'log').run();

  return c.json({ success: true });
});

// DNS intercept rules
app.post('/intercept/dns/rules', async (c) => {
  const db = c.env.DB;
  const { domain, action, redirect_ip } = await c.req.json();
  if (!domain) return c.json({ error: 'domain required' }, 400);
  // action: log | block | redirect | sinkhole
  await c.env.CACHE.put(`dns_rule:${domain}`, JSON.stringify({ action: action || 'log', redirect_ip }), { expirationTtl: 86400 * 30 });
  return c.json({ success: true, domain, action });
});

// WiFi network scan results
app.post('/intercept/wifi/networks', async (c) => {
  const db = c.env.DB;
  const { networks } = await c.req.json();
  if (!networks || !Array.isArray(networks)) return c.json({ error: 'networks array required' }, 400);

  let added = 0;
  for (const net of networks) {
    try {
      await db.prepare(`
        INSERT INTO wifi_networks (bssid, ssid, channel, frequency, signal_strength, encryption, cipher, auth, wps, lat, lon, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(bssid) DO UPDATE SET signal_strength = ?, clients_count = ?, last_seen = datetime('now')
      `).bind(net.bssid, net.ssid || null, net.channel || null, net.frequency || null,
        net.signal_strength || null, net.encryption || null, net.cipher || null,
        net.auth || null, net.wps || 0, net.lat || null, net.lon || null,
        net.signal_strength || null, net.clients_count || 0).run();
      added++;
    } catch (e) { log("warn", "WiFi network insert failed", { error: (e as Error)?.message || String(e) }); }
  }

  return c.json({ success: true, networks_added: added });
});

// WiFi client tracking
app.post('/intercept/wifi/clients', async (c) => {
  const db = c.env.DB;
  const { clients } = await c.req.json();
  if (!clients || !Array.isArray(clients)) return c.json({ error: 'clients array required' }, 400);

  let added = 0;
  for (const cl of clients) {
    try {
      await db.prepare(`
        INSERT INTO wifi_clients (mac_address, associated_bssid, probe_requests, signal_strength, packets, data_bytes, manufacturer, device_name, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(mac_address) DO UPDATE SET associated_bssid = ?, signal_strength = ?, packets = packets + ?, last_seen = datetime('now')
      `).bind(cl.mac_address, cl.associated_bssid || null,
        JSON.stringify(cl.probe_requests || []), cl.signal_strength || null,
        cl.packets || 0, cl.data_bytes || 0, cl.manufacturer || null, cl.device_name || null,
        cl.associated_bssid || null, cl.signal_strength || null, cl.packets || 0).run();
      added++;
    } catch (e) { log("warn", "WiFi client insert failed", { error: (e as Error)?.message || String(e) }); }
  }

  return c.json({ success: true, clients_added: added });
});

// Get WiFi networks and clients
app.get('/intercept/wifi/scan', async (c) => {
  const db = c.env.DB;
  const networks = await db.prepare("SELECT * FROM wifi_networks WHERE last_seen > datetime('now', '-1 hour') ORDER BY signal_strength DESC LIMIT 100").all();
  const clients = await db.prepare("SELECT * FROM wifi_clients WHERE last_seen > datetime('now', '-1 hour') ORDER BY last_seen DESC LIMIT 200").all();

  return c.json({
    networks: networks.results,
    clients: clients.results,
    network_count: networks.results.length,
    client_count: clients.results.length
  });
});

// ═══════════════════════════════════════════════════════════════
// MODULE 6: IP INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

// IP geolocation + threat intelligence lookup
app.post('/ip/lookup', async (c) => {
  const db = c.env.DB;
  const { ip, store } = await c.req.json();
  if (!ip) return c.json({ error: 'ip required' }, 400);

  const results: any = { ip, lookups: {} };

  // 1. ip-api.com — free, no key, returns geo + ISP + org + AS + proxy/mobile/hosting flags
  try {
    const resp = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (resp.ok) {
      const data: any = await resp.json();
      if (data.status === 'success') {
        results.lookups.ip_api = data;
        results.geo = { lat: data.lat, lon: data.lon, city: data.city, region: data.regionName, country: data.country, zip: data.zip, timezone: data.timezone };
        results.network = { isp: data.isp, org: data.org, as: data.as, asname: data.asname, reverse_dns: data.reverse };
        results.flags = { is_proxy: data.proxy, is_mobile: data.mobile, is_hosting: data.hosting };
      }
    }
  } catch (e) { log("warn", "ip-api.com lookup failed", { error: (e as Error)?.message || String(e), ip }); }

  // 2. ipwhois.io — free, no key, returns geo + security flags (tor/proxy/threat)
  try {
    const resp = await fetch(`https://ipwhois.app/json/${ip}?objects=ip,success,type,continent,country,country_code,region,city,latitude,longitude,org,isp,timezone,security`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data: any = await resp.json();
      if (data.success) {
        results.lookups.ipwhois = data;
        if (!results.geo) {
          results.geo = { lat: data.latitude, lon: data.longitude, city: data.city, region: data.region, country: data.country };
        }
        if (data.security) {
          results.threat = {
            is_tor: data.security.tor || false,
            is_proxy: data.security.proxy || false,
            is_anonymous: data.security.anonymous || false,
            is_known_attacker: data.security.known_attacker || false,
            is_bot: data.security.bot || false,
            is_spam: data.security.spam || false,
            threat_level: data.security.threat_level || 'low'
          };
        }
      }
    }
  } catch (e) { log("warn", "ipwhois.io lookup failed", { error: (e as Error)?.message || String(e), ip }); }

  // 3. ipapi.co — free, no key, returns geo + ASN + network + org
  try {
    const resp = await fetch(`https://ipapi.co/${ip}/json/`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data: any = await resp.json();
      if (!data.error) {
        results.lookups.ipapi = data;
        results.network = results.network || {};
        results.network.asn = data.asn;
        results.network.org = results.network.org || data.org;
        results.network.network = data.network;
        results.network.version = data.version;
      }
    }
  } catch (e) { log("warn", "ipapi.co lookup failed", { error: (e as Error)?.message || String(e), ip }); }

  // Aggregate threat score (0-10)
  let threatScore = 0;
  if (results.flags?.is_proxy || results.threat?.is_proxy) threatScore += 2;
  if (results.flags?.is_hosting) threatScore += 1;
  if (results.threat?.is_tor) threatScore += 3;
  if (results.threat?.is_known_attacker) threatScore += 4;
  if (results.threat?.is_bot) threatScore += 2;
  if (results.threat?.is_spam) threatScore += 2;
  threatScore = Math.min(threatScore, 10);
  results.threat_score = threatScore;
  results.threat_level = threatScore >= 7 ? 'CRITICAL' : threatScore >= 4 ? 'HIGH' : threatScore >= 2 ? 'MEDIUM' : 'LOW';

  // Store in D1 if requested
  if (store !== false) {
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO ip_intel (ip_address, lat, lon, city, region, country, isp, org, asn, reverse_dns,
          is_proxy, is_vpn, is_tor, is_hosting, is_mobile, threat_score, raw_data, last_queried)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(ip, results.geo?.lat || null, results.geo?.lon || null, results.geo?.city || null,
        results.geo?.region || null, results.geo?.country || null,
        results.network?.isp || null, results.network?.org || null, results.network?.asn || null,
        results.network?.reverse_dns || null,
        results.flags?.is_proxy || results.threat?.is_proxy ? 1 : 0,
        results.threat?.is_anonymous ? 1 : 0,
        results.threat?.is_tor ? 1 : 0,
        results.flags?.is_hosting ? 1 : 0,
        results.flags?.is_mobile ? 1 : 0,
        threatScore, JSON.stringify(results.lookups)).run();
    } catch (e) { log("warn", "IP intel store failed", { error: (e as Error)?.message || String(e), ip }); }
  }

  await logAction(db, 'IP_INTEL', 'ip_lookup', ip, { threat_score: threatScore, city: results.geo?.city });
  return c.json(results);
});

// Bulk IP lookup
app.post('/ip/bulk', async (c) => {
  const db = c.env.DB;
  const { ips } = await c.req.json();
  if (!ips || !Array.isArray(ips)) return c.json({ error: 'ips array required' }, 400);
  if (ips.length > 100) return c.json({ error: 'max 100 IPs per request' }, 400);

  // ip-api.com supports batch (up to 100)
  const results: any[] = [];
  try {
    const resp = await fetch('http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,mobile,hosting', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ips.map(ip => ({ query: ip }))),
      signal: AbortSignal.timeout(10000)
    });
    if (resp.ok) {
      const data: any[] = await resp.json();
      for (const d of data) {
        let score = 0;
        if (d.proxy) score += 2;
        if (d.hosting) score += 1;
        score = Math.min(score, 10);
        results.push({
          ip: d.query,
          geo: d.status === 'success' ? { lat: d.lat, lon: d.lon, city: d.city, region: d.regionName, country: d.country } : null,
          network: { isp: d.isp, org: d.org, as: d.as },
          flags: { is_proxy: d.proxy, is_mobile: d.mobile, is_hosting: d.hosting },
          threat_score: score
        });
      }
    }
  } catch (e) { log("warn", "Bulk IP lookup failed", { error: (e as Error)?.message || String(e) }); }

  return c.json({ count: results.length, results });
});

// IP history — search stored lookups
app.get('/ip/history', async (c) => {
  const db = c.env.DB;
  const q = c.req.query('q') || '';
  const hours = parseInt(c.req.query('hours') || '720');
  const limit = parseInt(c.req.query('limit') || '50');

  let query = `SELECT * FROM ip_intel WHERE last_queried > datetime('now', '-${hours} hours')`;
  if (q) query += ` AND (ip_address LIKE '%${q}%' OR city LIKE '%${q}%' OR isp LIKE '%${q}%' OR org LIKE '%${q}%')`;
  query += ` ORDER BY last_queried DESC LIMIT ${limit}`;

  const results = await db.prepare(query).all();
  return c.json({ results: results.results, count: results.results.length });
});

// IP threat feed — high-threat IPs seen recently
app.get('/ip/threats', async (c) => {
  const db = c.env.DB;
  const minScore = parseInt(c.req.query('min_score') || '4');

  const threats = await db.prepare(`
    SELECT * FROM ip_intel WHERE threat_score >= ? ORDER BY threat_score DESC, last_queried DESC LIMIT 100
  `).bind(minScore).all();

  return c.json({ threats: threats.results, count: threats.results.length, min_score: minScore });
});

// Reverse lookup — find IP by geo area
app.post('/ip/geo-search', async (c) => {
  const db = c.env.DB;
  const { lat, lon, radius_km } = await c.req.json();
  if (lat == null || lon == null) return c.json({ error: 'lat and lon required' }, 400);

  const r = radius_km || 50;
  // Approximate degree range for search
  const latRange = r / 111;
  const lonRange = r / (111 * Math.cos(lat * Math.PI / 180));

  const results = await db.prepare(`
    SELECT * FROM ip_intel WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?
    ORDER BY last_queried DESC LIMIT 200
  `).bind(lat - latRange, lat + latRange, lon - lonRange, lon + lonRange).all();

  return c.json({ center: { lat, lon }, radius_km: r, results: results.results, count: results.results.length });
});

// ═══════════════════════════════════════════════════════════════
// UNIFIED SEARCH & INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

// Cross-module search
app.post('/search', async (c) => {
  const db = c.env.DB;
  const { query, modules } = await c.req.json();
  if (!query) return c.json({ error: 'query required' }, 400);

  const searchModules = modules || ['gps', 'cell', 'carrier', 'surveillance', 'intercept', 'ip'];
  const results: any = {};

  if (searchModules.includes('gps')) {
    const devices = await db.prepare("SELECT * FROM tracked_devices WHERE device_name LIKE ? OR device_id LIKE ?")
      .bind(`%${query}%`, `%${query}%`).all();
    results.devices = devices.results;
  }

  if (searchModules.includes('surveillance')) {
    const plates = await db.prepare("SELECT * FROM alpr_reads WHERE plate_number LIKE ? ORDER BY timestamp DESC LIMIT 20")
      .bind(`%${query.toUpperCase()}%`).all();
    results.plate_reads = plates.results;

    const faces = await db.prepare("SELECT * FROM facial_recognition WHERE matched_identity LIKE ? ORDER BY timestamp DESC LIMIT 20")
      .bind(`%${query}%`).all();
    results.face_detections = faces.results;
  }

  if (searchModules.includes('carrier')) {
    const carriers = await db.prepare("SELECT * FROM carrier_intel WHERE phone_number LIKE ? OR imsi LIKE ?")
      .bind(`%${query}%`, `%${query}%`).all();
    results.carrier_intel = carriers.results;
  }

  if (searchModules.includes('intercept')) {
    const dns = await db.prepare("SELECT * FROM dns_intercepts WHERE query_domain LIKE ? ORDER BY timestamp DESC LIMIT 20")
      .bind(`%${query}%`).all();
    results.dns_queries = dns.results;

    const creds = await db.prepare("SELECT * FROM captured_credentials WHERE username LIKE ? OR service LIKE ? ORDER BY timestamp DESC LIMIT 20")
      .bind(`%${query}%`, `%${query}%`).all();
    results.credentials = creds.results;
  }

  if (searchModules.includes('ip')) {
    const ips = await db.prepare("SELECT * FROM ip_intel WHERE ip_address LIKE ? OR city LIKE ? OR isp LIKE ? OR org LIKE ? ORDER BY last_queried DESC LIMIT 20")
      .bind(`%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`).all();
    results.ip_intel = ips.results;
  }

  return c.json({ query, results });
});

// Surveillance log
app.get('/log', async (c) => {
  const db = c.env.DB;
  const module = c.req.query('module');
  const hours = parseInt(c.req.query('hours') || '24');
  const limit = parseInt(c.req.query('limit') || '100');

  let query = `SELECT * FROM surveillance_log WHERE timestamp > datetime('now', '-${hours} hours')`;
  if (module) query += ` AND module = '${module}'`;
  query += ` ORDER BY timestamp DESC LIMIT ${limit}`;

  const logs = await db.prepare(query).all();
  return c.json({ logs: logs.results, count: logs.results.length });
});

// Dashboard — aggregated stats
app.get('/dashboard', async (c) => {
  const db = c.env.DB;

  const [devices, locations24h, fenceAlerts, towerLookups, carrierLookups, cameras, plateReads, faceDetections, activeSessions, wifiNetworks, ipTotal, ipThreats] = await Promise.all([
    db.prepare('SELECT COUNT(*) as cnt FROM tracked_devices WHERE status = "active"').first(),
    db.prepare("SELECT COUNT(*) as cnt FROM location_history WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > datetime('now', '-24 hours')").first(),
    db.prepare('SELECT COUNT(*) as cnt FROM cell_tower_logs').first(),
    db.prepare('SELECT COUNT(*) as cnt FROM carrier_intel').first(),
    db.prepare('SELECT COUNT(*) as cnt FROM surveillance_cameras WHERE status = "active"').first(),
    db.prepare("SELECT COUNT(*) as cnt FROM alpr_reads WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM facial_recognition WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM intercept_sessions WHERE status = 'active'").first(),
    db.prepare('SELECT COUNT(*) as cnt FROM wifi_networks').first(),
    db.prepare('SELECT COUNT(*) as cnt FROM ip_intel').first(),
    db.prepare('SELECT COUNT(*) as cnt FROM ip_intel WHERE threat_score >= 4').first()
  ]);

  return c.json({
    timestamp: new Date().toISOString(),
    modules: {
      gps_tracker: {
        active_devices: devices?.cnt || 0,
        locations_24h: locations24h?.cnt || 0,
        geofence_alerts_24h: fenceAlerts?.cnt || 0
      },
      cell_tower: { total_lookups: towerLookups?.cnt || 0 },
      carrier_intel: { total_lookups: carrierLookups?.cnt || 0 },
      physical_surveillance: {
        active_cameras: cameras?.cnt || 0,
        plate_reads_24h: plateReads?.cnt || 0,
        face_detections_24h: faceDetections?.cnt || 0
      },
      active_intercept: {
        active_sessions: activeSessions?.cnt || 0,
        wifi_networks_known: wifiNetworks?.cnt || 0
      },
      ip_intelligence: {
        total_ips_tracked: ipTotal?.cnt || 0,
        high_threat_ips: ipThreats?.cnt || 0
      }
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// CRON HANDLERS
// ═══════════════════════════════════════════════════════════════

const scheduled: ExportedHandlerScheduledHandler<Bindings> = async (event, env, ctx) => {
  const db = env.DB;

  // Every 5 minutes: check geofences for all active devices with recent updates
  if (event.cron === '*/5 * * * *') {
    try {
      const devices = await db.prepare(`
        SELECT device_id, last_lat, last_lon FROM tracked_devices
        WHERE status = 'active' AND last_lat IS NOT NULL AND last_seen > datetime('now', '-10 minutes')
      `).all();

      for (const d of devices.results) {
        await checkGeofences(db, d.device_id as string, d.last_lat as number, d.last_lon as number);
      }
    } catch (e) { log("warn", "Cron geofence check failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Hourly: cleanup old data, aggregate stats
  if (event.cron === '0 * * * *') {
    try {
      // Prune location history older than 90 days
      await db.prepare("DELETE FROM location_history WHERE timestamp < datetime('now', '-90 days')").run();
      // Prune DNS intercepts older than 30 days
      await db.prepare("DELETE FROM dns_intercepts WHERE timestamp < datetime('now', '-30 days')").run();
      // Prune surveillance log older than 90 days
      await db.prepare("DELETE FROM surveillance_log WHERE timestamp < datetime('now', '-90 days')").run();
    } catch (e) { log("warn", "Cron hourly cleanup failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Daily: generate daily intelligence report
  if (event.cron === '0 0 * * *') {
    try {
      const stats = await generateDailyReport(db);
      // Post to Shared Brain
      await env.BRAIN.fetch('https://echo-shared-brain.bmcii1976.workers.dev/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'prometheus-surveillance',
          role: 'assistant',
          content: `PROMETHEUS SURVEILLANCE DAILY REPORT: ${JSON.stringify(stats)}`,
          importance: 7,
          tags: ['surveillance', 'daily_report']
        })
      });
    } catch (e) { log("warn", "Cron daily report failed", { error: (e as Error)?.message || String(e) }); }
  }
};

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

async function logAction(db: D1Database, module: string, action: string, target: string, details: any) {
  try {
    await db.prepare(`
      INSERT INTO surveillance_log (module, action, target, details) VALUES (?, ?, ?, ?)
    `).bind(module, action, target, JSON.stringify(details)).run();
  } catch (e) { log("warn", "logAction insert failed", { error: (e as Error)?.message || String(e), module, action }); }
}

async function checkGeofences(db: D1Database, device_id: string, lat: number, lon: number): Promise<any[]> {
  const alerts: any[] = [];
  const fences = await db.prepare('SELECT * FROM geofences WHERE active = 1').all();

  for (const fence of fences.results) {
    const assigned = JSON.parse((fence.assigned_devices as string) || '[]');
    if (assigned.length > 0 && !assigned.includes(device_id)) continue;

    if (fence.fence_type === 'circle') {
      const distance = haversine(lat, lon, fence.center_lat as number, fence.center_lon as number) * 1000; // km to meters
      const inside = distance <= (fence.radius_meters as number);

      // Check last known state from cache
      const cacheKey = `gf:${fence.id}:${device_id}`;
      const lastState = await db.prepare(`
        SELECT alert_type FROM geofence_alerts WHERE geofence_id = ? AND device_id = ? ORDER BY created_at DESC LIMIT 1
      `).bind(fence.id, device_id).first();

      const wasInside = lastState?.alert_type === 'enter' || lastState?.alert_type === 'dwell';

      if (inside && !wasInside && fence.alert_on_enter) {
        await db.prepare(`
          INSERT INTO geofence_alerts (geofence_id, device_id, alert_type, lat, lon, details)
          VALUES (?, ?, 'enter', ?, ?, ?)
        `).bind(fence.id, device_id, lat, lon, JSON.stringify({ distance_meters: Math.round(distance), fence_name: fence.name })).run();
        alerts.push({ type: 'enter', fence_name: fence.name, distance_meters: Math.round(distance) });
      } else if (!inside && wasInside && fence.alert_on_exit) {
        await db.prepare(`
          INSERT INTO geofence_alerts (geofence_id, device_id, alert_type, lat, lon, details)
          VALUES (?, ?, 'exit', ?, ?, ?)
        `).bind(fence.id, device_id, lat, lon, JSON.stringify({ distance_meters: Math.round(distance), fence_name: fence.name })).run();
        alerts.push({ type: 'exit', fence_name: fence.name, distance_meters: Math.round(distance) });
      }
    }
  }

  return alerts;
}

function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function weightedTriangulation(towers: any[]): any {
  let totalWeight = 0;
  let weightedLat = 0;
  let weightedLon = 0;

  for (const t of towers) {
    // Weight by inverse of accuracy (more accurate = higher weight) and signal strength
    const weight = 1 / (t.resolved.accuracy || 1000);
    totalWeight += weight;
    weightedLat += t.resolved.lat * weight;
    weightedLon += t.resolved.lon * weight;
  }

  return {
    lat: weightedLat / totalWeight,
    lon: weightedLon / totalWeight,
    accuracy: Math.min(...towers.map((t: any) => t.resolved.accuracy)),
    method: `triangulation_${towers.length}_towers`,
    towers_used: towers.length
  };
}

async function cacheTower(db: D1Database, tower: any, lat: number, lon: number, range: number, source: string) {
  try {
    await db.prepare(`
      INSERT OR REPLACE INTO cell_tower_db (mcc, mnc, lac, cell_id, lat, lon, range_meters, radio_type, last_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(tower.mcc, tower.mnc, tower.lac, tower.cell_id, lat, lon, range || 1000, tower.radio_type || 'gsm').run();
  } catch (e) { log("warn", "cacheTower upsert failed", { error: (e as Error)?.message || String(e) }); }
}

function identifyCarrier(phone: string): { carrier: string; country: string; type: string; region?: string } {
  if (!phone) return { carrier: 'unknown', country: 'unknown', type: 'unknown' };
  const cleaned = phone.replace(/[^0-9+]/g, '');
  const digits = cleaned.startsWith('+') ? cleaned.slice(1) : cleaned;

  if (!digits.startsWith('1') || digits.length < 10) {
    // International MCC-based carrier lookup
    const mccCarriers: Record<string, string> = {
      '44': 'UK', '49': 'Germany', '33': 'France', '86': 'China', '81': 'Japan',
      '52': 'Mexico', '55': 'Brazil', '91': 'India', '61': 'Australia', '7': 'Russia'
    };
    const cc = digits.length >= 2 ? digits.slice(0, 2) : '';
    return { carrier: 'International', country: mccCarriers[cc] || 'unknown', type: 'unknown' };
  }

  // US area code → region + dominant carrier mapping
  const areaCodeMap: Record<string, { region: string; carrier: string }> = {
    // West Texas / Permian Basin (Commander's territory)
    '432': { region: 'Midland-Odessa TX', carrier: 'AT&T' },
    '915': { region: 'El Paso TX', carrier: 'AT&T' },
    '806': { region: 'Lubbock-Amarillo TX', carrier: 'AT&T' },
    '325': { region: 'Abilene TX', carrier: 'AT&T' },
    // DFW
    '214': { region: 'Dallas TX', carrier: 'AT&T' },
    '469': { region: 'Dallas TX', carrier: 'AT&T' },
    '972': { region: 'Dallas TX', carrier: 'T-Mobile' },
    '817': { region: 'Fort Worth TX', carrier: 'AT&T' },
    '682': { region: 'Fort Worth TX', carrier: 'AT&T' },
    // Houston
    '713': { region: 'Houston TX', carrier: 'AT&T' },
    '281': { region: 'Houston TX', carrier: 'AT&T' },
    '832': { region: 'Houston TX', carrier: 'T-Mobile' },
    '346': { region: 'Houston TX', carrier: 'T-Mobile' },
    // San Antonio / Austin
    '210': { region: 'San Antonio TX', carrier: 'AT&T' },
    '512': { region: 'Austin TX', carrier: 'AT&T' },
    '737': { region: 'Austin TX', carrier: 'T-Mobile' },
    // Other TX
    '903': { region: 'East TX', carrier: 'Verizon' },
    '254': { region: 'Waco TX', carrier: 'AT&T' },
    '361': { region: 'Corpus Christi TX', carrier: 'AT&T' },
    '956': { region: 'Rio Grande TX', carrier: 'T-Mobile' },
    '409': { region: 'Beaumont TX', carrier: 'AT&T' },
    '979': { region: 'Bryan-College Station TX', carrier: 'Verizon' },
    '936': { region: 'Lufkin TX', carrier: 'AT&T' },
    '940': { region: 'Wichita Falls TX', carrier: 'AT&T' },
    '430': { region: 'East TX', carrier: 'AT&T' },
    // NM (adjacent to Permian)
    '505': { region: 'Albuquerque NM', carrier: 'T-Mobile' },
    '575': { region: 'Southern NM', carrier: 'AT&T' },
    // Major US cities
    '212': { region: 'New York NY', carrier: 'Verizon' },
    '310': { region: 'Los Angeles CA', carrier: 'T-Mobile' },
    '312': { region: 'Chicago IL', carrier: 'AT&T' },
    '305': { region: 'Miami FL', carrier: 'AT&T' },
    '404': { region: 'Atlanta GA', carrier: 'AT&T' },
    '415': { region: 'San Francisco CA', carrier: 'T-Mobile' },
    '202': { region: 'Washington DC', carrier: 'Verizon' },
    '617': { region: 'Boston MA', carrier: 'Verizon' },
    '206': { region: 'Seattle WA', carrier: 'T-Mobile' },
    '303': { region: 'Denver CO', carrier: 'T-Mobile' },
    '602': { region: 'Phoenix AZ', carrier: 'T-Mobile' },
    '702': { region: 'Las Vegas NV', carrier: 'T-Mobile' },
  };

  const areaCode = digits.slice(1, 4);
  const info = areaCodeMap[areaCode];
  if (info) {
    return { carrier: info.carrier, country: 'US', type: 'mobile', region: info.region };
  }
  return { carrier: 'Unknown US Carrier', country: 'US', type: 'mobile', region: `Area ${areaCode}` };
}

function analyzeMovementPatterns(points: any[]): any {
  if (!points.length) return { trend: 'insufficient_data', confidence: 0, frequent_stops: [] };

  // Find clusters (potential frequent stops)
  const clusters: any[] = [];
  const threshold = 0.001; // ~100m in degrees

  for (const p of points) {
    let foundCluster = false;
    for (const c of clusters) {
      if (Math.abs(p.lat - c.lat) < threshold && Math.abs(p.lon - c.lon) < threshold) {
        c.count++;
        c.totalTime += 1;
        foundCluster = true;
        break;
      }
    }
    if (!foundCluster) {
      clusters.push({ lat: p.lat, lon: p.lon, count: 1, totalTime: 1 });
    }
  }

  // Sort by frequency
  clusters.sort((a, b) => b.count - a.count);
  const frequentStops = clusters.slice(0, 5).map((c, i) => ({
    rank: i + 1,
    lat: c.lat,
    lon: c.lon,
    visit_count: c.count,
    label: i === 0 ? 'Primary Location' : i === 1 ? 'Secondary Location' : `Location #${i + 1}`
  }));

  // Determine trend
  const latest = points[0];
  const avgSpeed = points.reduce((sum: number, p: any) => sum + (p.speed || 0), 0) / points.length;

  return {
    trend: avgSpeed > 10 ? 'moving' : avgSpeed > 2 ? 'slow_movement' : 'stationary',
    avg_speed_kmh: Math.round(avgSpeed * 10) / 10,
    frequent_stops: frequentStops,
    total_data_points: points.length,
    confidence: Math.min(points.length / 20, 1) // 0-1 based on data volume
  };
}

async function generateDailyReport(db: D1Database): Promise<any> {
  const [locations, alerts, towerLookups, plateReads, faceDetections, interceptSessions] = await Promise.all([
    db.prepare("SELECT COUNT(*) as cnt FROM location_history WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM geofence_alerts WHERE created_at > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM cell_tower_logs WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM alpr_reads WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM facial_recognition WHERE timestamp > datetime('now', '-24 hours')").first(),
    db.prepare("SELECT COUNT(*) as cnt FROM intercept_sessions WHERE start_time > datetime('now', '-24 hours')").first(),
  ]);

  return {
    date: new Date().toISOString().split('T')[0],
    gps_locations_tracked: locations?.cnt || 0,
    geofence_alerts: alerts?.cnt || 0,
    cell_tower_lookups: towerLookups?.cnt || 0,
    plate_reads: plateReads?.cnt || 0,
    face_detections: faceDetections?.cnt || 0,
    intercept_sessions: interceptSessions?.cnt || 0
  };
}

export default {
  fetch: app.fetch,
  scheduled
};
