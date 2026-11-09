import sqlite3
import datetime

DB_NAME = "wifi_scanner.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Devices table with OS and Threat Level
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            vendor TEXT,
            operating_system TEXT DEFAULT 'Unknown',
            threat_level TEXT DEFAULT 'Low',
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            is_new BOOLEAN DEFAULT 1,
            nickname TEXT
        )
    ''')
    
    # Migration for older databases: Add columns if missing
    try:
        c.execute("ALTER TABLE devices ADD COLUMN operating_system TEXT DEFAULT 'Unknown'")
    except: pass
    try:
        c.execute("ALTER TABLE devices ADD COLUMN threat_level TEXT DEFAULT 'Low'")
    except: pass
    try:
        c.execute("ALTER TABLE devices ADD COLUMN is_new BOOLEAN DEFAULT 1")
    except: pass
    try:
        c.execute("ALTER TABLE devices ADD COLUMN is_online BOOLEAN DEFAULT 0")
    except: pass
    
    # Traffic logs for DNS surveillance
    c.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_mac TEXT,
            domain TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY(device_mac) REFERENCES devices(mac_address)
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def update_device(mac, ip, vendor, os='Unknown', threat='Low'):
    conn = get_db_connection()
    c = conn.cursor()
    
    now = datetime.datetime.now()
    
    # Check if device exists
    c.execute('SELECT * FROM devices WHERE mac_address = ?', (mac,))
    device = c.fetchone()
    
    if device:
        # Update existing device
        c.execute('''
            UPDATE devices 
            SET ip_address = ?, last_seen = ?, is_new = 0, operating_system = ?, threat_level = ?, is_online = 1
            WHERE mac_address = ?
        ''', (ip, now, os, threat, mac))
    else:
        # Insert new device
        c.execute('''
            INSERT INTO devices (mac_address, ip_address, vendor, first_seen, last_seen, is_new, operating_system, threat_level, is_online)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, 1)
        ''', (mac, ip, vendor, now, now, os, threat))
        
    conn.commit()
    conn.close()

def reset_online_status():
    conn = get_db_connection()
    conn.execute('UPDATE devices SET is_online = 0')
    conn.commit()
    conn.close()

def log_traffic(mac, domain):
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.datetime.now()
    c.execute('INSERT INTO traffic_logs (device_mac, domain, timestamp) VALUES (?, ?, ?)', (mac, domain, now))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    conn.close()
    return [dict(d) for d in devices]

def get_active_devices():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices WHERE is_online = 1').fetchall()
    conn.close()
    return [dict(d) for d in devices]

def get_recent_traffic(limit=40, mac=None):
    conn = get_db_connection()
    if mac:
        logs = conn.execute('''
            SELECT t.*, d.ip_address 
            FROM traffic_logs t 
            JOIN devices d ON t.device_mac = d.mac_address 
            WHERE t.device_mac = ?
            ORDER BY t.timestamp DESC LIMIT ?
        ''', (mac, limit)).fetchall()
    else:
        logs = conn.execute('''
            SELECT t.*, d.ip_address 
            FROM traffic_logs t 
            JOIN devices d ON t.device_mac = d.mac_address 
            ORDER BY t.timestamp DESC LIMIT ?
        ''', (limit,)).fetchall()
    conn.close()
    return [dict(l) for l in logs]
