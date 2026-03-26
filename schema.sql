-- ═══════════════════════════════════════════════════════════════
-- echo-prometheus-surveillance | D1 Database: echo-prometheus-surveillance
-- Idempotent schema — safe to run multiple times
-- ARGUS PANOPTES — 6 surveillance modules, 21 tables
-- ═══════════════════════════════════════════════════════════════

-- MODULE 1: REAL-TIME GPS TRACKING

DROP TABLE IF EXISTS tracked_devices;
CREATE TABLE tracked_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT UNIQUE NOT NULL,
  device_name TEXT NOT NULL,
  device_type TEXT DEFAULT 'unknown',
  tracking_method TEXT DEFAULT 'gps',
  last_lat REAL,
  last_lon REAL,
  last_altitude REAL,
  last_speed REAL,
  last_heading REAL,
  last_accuracy REAL,
  last_battery REAL,
  last_signal_strength INTEGER,
  last_seen TEXT,
  status TEXT DEFAULT 'active',
  metadata TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS location_history;
CREATE TABLE location_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  altitude REAL,
  speed REAL,
  heading REAL,
  accuracy REAL,
  source TEXT DEFAULT 'gps',
  battery REAL,
  signal_strength INTEGER,
  cell_info TEXT,
  wifi_info TEXT,
  metadata TEXT DEFAULT '{}',
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_loc_device ON location_history(device_id, timestamp DESC);
CREATE INDEX idx_loc_time ON location_history(timestamp DESC);
CREATE INDEX idx_loc_coords ON location_history(lat, lon);

DROP TABLE IF EXISTS geofences;
CREATE TABLE geofences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  fence_type TEXT DEFAULT 'circle',
  center_lat REAL,
  center_lon REAL,
  radius_meters REAL,
  polygon_coords TEXT,
  alert_on_enter INTEGER DEFAULT 1,
  alert_on_exit INTEGER DEFAULT 1,
  alert_on_dwell INTEGER DEFAULT 0,
  dwell_threshold_seconds INTEGER DEFAULT 300,
  assigned_devices TEXT DEFAULT '[]',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS geofence_alerts;
CREATE TABLE geofence_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  geofence_id INTEGER,
  device_id TEXT,
  alert_type TEXT,
  lat REAL,
  lon REAL,
  details TEXT DEFAULT '{}',
  acknowledged INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- MODULE 2: CELL TOWER TRACKING & CARRIER INTEL

DROP TABLE IF EXISTS cell_tower_logs;
CREATE TABLE cell_tower_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mcc INTEGER,
  mnc INTEGER,
  lac INTEGER,
  cell_id INTEGER,
  signal_strength INTEGER,
  timing_advance INTEGER,
  frequency INTEGER,
  radio_type TEXT DEFAULT 'gsm',
  resolved_lat REAL,
  resolved_lon REAL,
  resolved_accuracy REAL,
  resolver TEXT,
  raw_response TEXT,
  device_id TEXT,
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_cell_tower ON cell_tower_logs(mcc, mnc, lac, cell_id);
CREATE INDEX idx_cell_device ON cell_tower_logs(device_id, timestamp DESC);

DROP TABLE IF EXISTS cell_tower_db;
CREATE TABLE cell_tower_db (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mcc INTEGER NOT NULL,
  mnc INTEGER NOT NULL,
  lac INTEGER NOT NULL,
  cell_id INTEGER NOT NULL,
  lat REAL,
  lon REAL,
  range_meters REAL,
  radio_type TEXT,
  carrier TEXT,
  country TEXT,
  region TEXT,
  samples INTEGER DEFAULT 1,
  last_updated TEXT DEFAULT (datetime('now')),
  UNIQUE(mcc, mnc, lac, cell_id)
);

DROP TABLE IF EXISTS carrier_intel;
CREATE TABLE carrier_intel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone_number TEXT,
  imsi TEXT,
  imei TEXT,
  carrier TEXT,
  carrier_country TEXT,
  number_type TEXT,
  roaming_status TEXT,
  hlr_status TEXT,
  last_known_msc TEXT,
  last_known_vlr TEXT,
  sim_swap_detected INTEGER DEFAULT 0,
  sim_swap_date TEXT,
  port_history TEXT DEFAULT '[]',
  metadata TEXT DEFAULT '{}',
  last_queried TEXT DEFAULT (datetime('now')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_carrier_phone ON carrier_intel(phone_number);
CREATE INDEX idx_carrier_imsi ON carrier_intel(imsi);

DROP TABLE IF EXISTS ss7_analysis;
CREATE TABLE ss7_analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation TEXT NOT NULL,
  target_msisdn TEXT,
  target_imsi TEXT,
  source_gt TEXT,
  dest_gt TEXT,
  message_type TEXT,
  opcode TEXT,
  result TEXT,
  location_data TEXT,
  subscriber_data TEXT,
  risk_score REAL DEFAULT 0,
  anomaly_flags TEXT DEFAULT '[]',
  raw_packet TEXT,
  timestamp TEXT DEFAULT (datetime('now'))
);

-- MODULE 3: CDR ANALYSIS

DROP TABLE IF EXISTS cdr_records;
CREATE TABLE cdr_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  calling_number TEXT,
  called_number TEXT,
  call_type TEXT,
  start_time TEXT,
  end_time TEXT,
  duration_seconds INTEGER,
  originating_cell TEXT,
  terminating_cell TEXT,
  originating_lat REAL,
  originating_lon REAL,
  terminating_lat REAL,
  terminating_lon REAL,
  imsi TEXT,
  imei TEXT,
  data_volume_bytes INTEGER,
  metadata TEXT DEFAULT '{}',
  imported_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_cdr_calling ON cdr_records(calling_number, start_time DESC);
CREATE INDEX idx_cdr_called ON cdr_records(called_number, start_time DESC);

-- MODULE 4: VIDEO SURVEILLANCE & RECOGNITION

DROP TABLE IF EXISTS surveillance_cameras;
CREATE TABLE surveillance_cameras (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  camera_id TEXT UNIQUE NOT NULL,
  camera_name TEXT NOT NULL,
  camera_type TEXT DEFAULT 'ip_camera',
  protocol TEXT DEFAULT 'rtsp',
  stream_url TEXT,
  onvif_url TEXT,
  lat REAL,
  lon REAL,
  heading REAL,
  fov_degrees REAL,
  resolution TEXT,
  fps INTEGER DEFAULT 30,
  has_ptz INTEGER DEFAULT 0,
  has_ir INTEGER DEFAULT 0,
  has_audio INTEGER DEFAULT 0,
  recording_mode TEXT DEFAULT 'continuous',
  ai_detection_enabled INTEGER DEFAULT 0,
  detection_classes TEXT DEFAULT '["person","vehicle"]',
  status TEXT DEFAULT 'active',
  last_frame_at TEXT,
  metadata TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS alpr_reads;
CREATE TABLE alpr_reads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plate_number TEXT NOT NULL,
  plate_state TEXT,
  plate_country TEXT DEFAULT 'US',
  confidence REAL,
  camera_id TEXT,
  lat REAL,
  lon REAL,
  vehicle_color TEXT,
  vehicle_make TEXT,
  vehicle_model TEXT,
  vehicle_year TEXT,
  vehicle_type TEXT,
  image_url TEXT,
  direction TEXT,
  speed_estimate REAL,
  on_watchlist INTEGER DEFAULT 0,
  watchlist_reason TEXT,
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_alpr_plate ON alpr_reads(plate_number, timestamp DESC);
CREATE INDEX idx_alpr_camera ON alpr_reads(camera_id, timestamp DESC);

DROP TABLE IF EXISTS facial_recognition;
CREATE TABLE facial_recognition (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id TEXT UNIQUE,
  camera_id TEXT,
  face_encoding TEXT,
  matched_identity TEXT,
  match_confidence REAL,
  bounding_box TEXT,
  image_url TEXT,
  age_estimate INTEGER,
  gender_estimate TEXT,
  emotion_estimate TEXT,
  wearing_mask INTEGER DEFAULT 0,
  wearing_glasses INTEGER DEFAULT 0,
  on_watchlist INTEGER DEFAULT 0,
  watchlist_reason TEXT,
  lat REAL,
  lon REAL,
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_face_identity ON facial_recognition(matched_identity, timestamp DESC);

-- MODULE 5: WATCHLISTS & INTERCEPTION

DROP TABLE IF EXISTS plate_watchlist;
CREATE TABLE plate_watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plate_number TEXT UNIQUE NOT NULL,
  reason TEXT NOT NULL,
  priority TEXT DEFAULT 'medium',
  alert_telegram INTEGER DEFAULT 1,
  alert_sms INTEGER DEFAULT 0,
  notes TEXT,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS person_watchlist;
CREATE TABLE person_watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_name TEXT NOT NULL,
  face_encodings TEXT DEFAULT '[]',
  description TEXT,
  priority TEXT DEFAULT 'medium',
  alert_telegram INTEGER DEFAULT 1,
  alert_sms INTEGER DEFAULT 0,
  reference_images TEXT DEFAULT '[]',
  notes TEXT,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

DROP TABLE IF EXISTS intercept_sessions;
CREATE TABLE intercept_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT UNIQUE NOT NULL,
  session_type TEXT NOT NULL,
  target TEXT,
  interface TEXT,
  node TEXT DEFAULT 'charlie',
  status TEXT DEFAULT 'active',
  packets_captured INTEGER DEFAULT 0,
  bytes_captured INTEGER DEFAULT 0,
  interesting_packets INTEGER DEFAULT 0,
  filter_expression TEXT,
  output_file TEXT,
  start_time TEXT DEFAULT (datetime('now')),
  end_time TEXT,
  metadata TEXT DEFAULT '{}'
);

DROP TABLE IF EXISTS captured_credentials;
CREATE TABLE captured_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT,
  protocol TEXT,
  source_ip TEXT,
  source_port INTEGER,
  dest_ip TEXT,
  dest_port INTEGER,
  username TEXT,
  credential_hash TEXT,
  credential_type TEXT,
  service TEXT,
  url TEXT,
  raw_data TEXT,
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_cred_session ON captured_credentials(session_id);

DROP TABLE IF EXISTS dns_intercepts;
CREATE TABLE dns_intercepts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT,
  query_domain TEXT NOT NULL,
  query_type TEXT DEFAULT 'A',
  original_response TEXT,
  spoofed_response TEXT,
  source_ip TEXT,
  action TEXT DEFAULT 'log',
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_dns_domain ON dns_intercepts(query_domain, timestamp DESC);

-- MODULE 6: WIFI & NETWORK INTELLIGENCE

DROP TABLE IF EXISTS wifi_networks;
CREATE TABLE wifi_networks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bssid TEXT NOT NULL,
  ssid TEXT,
  channel INTEGER,
  frequency INTEGER,
  signal_strength INTEGER,
  encryption TEXT,
  cipher TEXT,
  auth TEXT,
  wps INTEGER DEFAULT 0,
  clients_count INTEGER DEFAULT 0,
  lat REAL,
  lon REAL,
  first_seen TEXT DEFAULT (datetime('now')),
  last_seen TEXT DEFAULT (datetime('now')),
  handshake_captured INTEGER DEFAULT 0,
  pmkid_captured INTEGER DEFAULT 0,
  cracked INTEGER DEFAULT 0,
  password TEXT,
  metadata TEXT DEFAULT '{}'
);

CREATE INDEX idx_wifi_bssid ON wifi_networks(bssid);
CREATE INDEX idx_wifi_ssid ON wifi_networks(ssid);

DROP TABLE IF EXISTS wifi_clients;
CREATE TABLE wifi_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac_address TEXT NOT NULL,
  associated_bssid TEXT,
  probe_requests TEXT DEFAULT '[]',
  signal_strength INTEGER,
  packets INTEGER DEFAULT 0,
  data_bytes INTEGER DEFAULT 0,
  manufacturer TEXT,
  device_name TEXT,
  first_seen TEXT DEFAULT (datetime('now')),
  last_seen TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_wifi_client_mac ON wifi_clients(mac_address);

DROP TABLE IF EXISTS surveillance_log;
CREATE TABLE surveillance_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  module TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  result TEXT,
  details TEXT DEFAULT '{}',
  operator TEXT DEFAULT 'system',
  timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_surv_log ON surveillance_log(module, timestamp DESC);

-- IP INTELLIGENCE

DROP TABLE IF EXISTS ip_intel;
CREATE TABLE ip_intel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL,
  lat REAL,
  lon REAL,
  city TEXT,
  region TEXT,
  country TEXT,
  isp TEXT,
  org TEXT,
  asn TEXT,
  reverse_dns TEXT,
  is_proxy INTEGER DEFAULT 0,
  is_vpn INTEGER DEFAULT 0,
  is_tor INTEGER DEFAULT 0,
  is_hosting INTEGER DEFAULT 0,
  is_mobile INTEGER DEFAULT 0,
  threat_score REAL DEFAULT 0,
  raw_data TEXT,
  last_queried TEXT DEFAULT (datetime('now')),
  UNIQUE(ip_address)
);

CREATE INDEX idx_ip_address ON ip_intel(ip_address);
CREATE INDEX idx_ip_threat ON ip_intel(threat_score DESC);
CREATE INDEX idx_ip_geo ON ip_intel(lat, lon);
