from flask import Flask, render_template, jsonify, request
from scapy.all import ARP, Ether, srp, IP, UDP, DNS, DNSQR, sniff
import requests
import models
import threading
import time
import socket
import json

app = Flask(__name__)

# Initialize DB
models.init_db()

def get_mac_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"

def get_os_fingerprint(ip):
    try:
        # Send an ICMP packet to guess OS via TTL
        from scapy.all import IP, ICMP, sr1
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp:
            ttl = resp.ttl
            if ttl <= 64: return "Linux/Android/iOS"
            if ttl <= 128: return "Windows"
            if ttl <= 255: return "Unix/Solaris"
    except Exception as e:
        print(f"OS Fingerprint error for {ip}: {e}")
    return "Unknown"

def dns_sniffer():
    try:
        def process_pkt(pkt):
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                try:
                    ip = pkt[IP].src
                    domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                    # Find MAC for this IP
                    devices = models.get_all_devices()
                    mac = next((d['mac_address'] for d in devices if d['ip_address'] == ip), None)
                    if mac:
                        models.log_traffic(mac, domain)
                        print(f"[SNIFF] {ip} -> {domain}")
                except:
                    pass

        print("Starting background DNS sniffer...")
        sniff(filter="udp port 53", prn=process_pkt, store=0)
    except Exception as e:
        print(f"DNS Sniffer failed (likely permission/interface issue): {e}")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def scan_network_task():
    print("[LIVE] Initializing real-time network scan...")
    local_ip = get_local_ip()
    
    # ... subnet detection code ...
    subnet_base = ".".join(local_ip.split(".")[:-1])
    target_ip = f"{subnet_base}.0/24"
    
    try:
        print(f"Scanning {target_ip}...")
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=5, verbose=0)[0]
        
        # Collect results first
        found_devices = []
        for sent, received in result:
            mac = received.hwsrc
            ip = received.psrc
            vendor = get_mac_vendor(mac)
            os = get_os_fingerprint(ip)
            threat = "Medium" if os == "Unknown" else "Low"
            found_devices.append((mac, ip, vendor, os, threat))

        # Now update DB in one go
        models.reset_online_status()
        for dev in found_devices:
            models.update_device(*dev)
            
        print(f"[LIVE] Scan complete. {len(found_devices)} devices online.")
    except Exception as e:
        print(f"[ERROR] Scan failure: {e}")

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/topology')
def topology():
    return render_template('topology.html')

@app.route('/devices')
def devices():
    return render_template('devices.html')

@app.route('/surveillance')
def surveillance():
    return render_template('surveillance.html')

@app.route('/scan')
def trigger_scan():
    # Run scan in background to not block UI
    thread = threading.Thread(target=scan_network_task)
    thread.start()
    return jsonify({"status": "Scan started", "message": "Scanning network in background..."})

@app.route('/api/devices')
def get_devices():
    # Only return currently online devices for the HUD
    devices = models.get_active_devices()
    return jsonify(devices)

@app.route('/api/traffic')
def get_traffic():
    mac = request.args.get('mac')
    traffic = models.get_recent_traffic(mac=mac)
    return jsonify(traffic)

def auto_scanner():
    print("[LIVE] Background auto-scanner engaged.")
    while True:
        try:
            # Immediate scan then sleep
            scan_network_task()
        except Exception as e:
            print(f"[ERROR] Auto-scan failure: {e}")
        time.sleep(45) # Scan every 45 seconds to avoid network saturation

@app.route('/api/stats')
def get_stats():
    # Stats should only reflect current network state
    active_devices = models.get_active_devices()
    all_devices = models.get_all_devices()
    return jsonify({
        "total": len(active_devices),
        "new": len([d for d in active_devices if d.get('is_new')]),
        "threats": len([d for d in active_devices if d.get('threat_level', 'Low') != 'Low']),
        "history_total": len(all_devices)
    })

if __name__ == '__main__':
    # Start Sniffer in a separate thread
    sniff_thread = threading.Thread(target=dns_sniffer, daemon=True)
    sniff_thread.start()
    
    # Start Auto-Scanner in a separate thread
    scan_thread = threading.Thread(target=auto_scanner, daemon=True)
    scan_thread.start()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
