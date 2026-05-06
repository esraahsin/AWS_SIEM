#!/bin/bash
set -xe

apt-get update -y
apt-get install -y python3 python3-pip

pip3 install "elasticsearch==8.12.0" "faker==20.1.0"

cat > /opt/siem_generator.py << 'PYEOF'
import os, random, time, ipaddress
from datetime import datetime, timezone
from faker import Faker
from elasticsearch import Elasticsearch

fake   = Faker()
ES_HOST = os.getenv("ES_HOST", "localhost")

# ── Connect with retries (ES takes a few minutes to start) ─────────────────
es = None
for attempt in range(30):
    try:
        client = Elasticsearch(f"http://{ES_HOST}:9200", request_timeout=5)
        if client.ping():
            es = client
            print(f"[OK] Connected to Elasticsearch at {ES_HOST}:9200")
            break
    except Exception as e:
        print(f"[{attempt+1}/30] ES not ready: {e}  — retrying in 20s")
        time.sleep(20)

if es is None:
    print("Could not connect to Elasticsearch after 30 attempts. Exiting.")
    raise SystemExit(1)

# ── Severity scorer ────────────────────────────────────────────────────────
BASE     = {"ids": 7, "firewall": 4, "windows": 5, "webserver": 3}
MODS     = {"blocked":1,"deny":1,"drop":1,"reject":1,"failure":2,"allow":-1,"success":-1}
RISKY_HTTP = {401, 403, 404, 500, 503}

def severity(dataset, action="", existing=None, http_status=None):
    s = BASE.get(dataset, 5)
    for kw, m in MODS.items():
        if kw in action.lower():
            s += m
            break
    if existing is not None:
        s = round((s + existing) / 2)
    if http_status in RISKY_HTTP:
        s += 2
    return max(1, min(10, s))

# ── Fake GeoIP (no MaxMind licence needed) ─────────────────────────────────
GEO = [
    {"country_iso_code":"US","country_name":"United States","city_name":"New York",  "location":{"lat":40.71,"lon":-74.00}},
    {"country_iso_code":"CN","country_name":"China",        "city_name":"Beijing",   "location":{"lat":39.91,"lon":116.39}},
    {"country_iso_code":"RU","country_name":"Russia",       "city_name":"Moscow",    "location":{"lat":55.75,"lon": 37.62}},
    {"country_iso_code":"DE","country_name":"Germany",      "city_name":"Berlin",    "location":{"lat":52.52,"lon": 13.40}},
    {"country_iso_code":"BR","country_name":"Brazil",       "city_name":"Sao Paulo", "location":{"lat":-23.5,"lon":-46.63}},
    {"country_iso_code":"FR","country_name":"France",       "city_name":"Paris",     "location":{"lat":48.85,"lon":  2.35}},
    {"country_iso_code":"IN","country_name":"India",        "city_name":"Mumbai",    "location":{"lat":19.08,"lon": 72.88}},
    {"country_iso_code":"KP","country_name":"North Korea",  "city_name":"Pyongyang", "location":{"lat":39.02,"lon":125.75}},
    {"country_iso_code":"IR","country_name":"Iran",         "city_name":"Tehran",    "location":{"lat":35.69,"lon": 51.39}},
    {"country_iso_code":"GB","country_name":"United Kingdom","city_name":"London",   "location":{"lat":51.51,"lon": -0.13}},
    {"country_iso_code":"JP","country_name":"Japan",        "city_name":"Tokyo",     "location":{"lat":35.68,"lon":139.69}},
    {"country_iso_code":"NG","country_name":"Nigeria",      "city_name":"Lagos",     "location":{"lat": 6.52,"lon":  3.38}},
]

def geo(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except Exception:
        return None
    return random.choice(GEO)

# ── Index helper ───────────────────────────────────────────────────────────
def send(event, source_type):
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    try:
        es.index(index=f"siem-{source_type}-{today}", document=event)
    except Exception as e:
        print(f"[ES ERROR] {e}")

# ── Firewall generator ─────────────────────────────────────────────────────
FW_ACTIONS = ["ALLOW","DENY","DROP","REJECT"]
FW_PROTO   = ["tcp","udp","icmp"]
FW_PORTS   = [22,23,25,53,80,443,3389,8080,8443]

def gen_firewall():
    src = fake.ipv4_public()
    act = random.choice(FW_ACTIONS)
    ev  = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "firewall",
        "event": {
            "kind": "event", "category": "network", "type": "connection",
            "action": act.lower(), "dataset": "firewall",
            "outcome": "success" if act == "ALLOW" else "failure",
            "severity": severity("firewall", act),
        },
        "source":      {"ip": src, "port": random.randint(1024,65535)},
        "destination": {"ip": fake.ipv4_public(), "port": random.choice(FW_PORTS)},
        "network":     {"transport": random.choice(FW_PROTO)},
        "observer":    {"vendor":"FW-Vendor","product":"NGFW","type":"firewall"},
        "tags": ["firewall"],
    }
    g = geo(src)
    if g:
        ev["source"]["geo"] = g
    return ev

# ── Web server generator ───────────────────────────────────────────────────
WEB_METHODS  = ["GET","POST","PUT","DELETE","HEAD"]
WEB_STATUSES = [200,200,200,201,301,400,401,403,404,500,503]
WEB_URIS     = ["/","/login","/api/users","/admin","/wp-admin",
                "/.env","/api/data","/logout","/phpmyadmin","/api/v1/auth"]
WEB_AGENTS   = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0","python-requests/2.28.0","sqlmap/1.7.8","Nmap Scripting Engine",
]

def gen_webserver():
    src    = fake.ipv4_public()
    method = random.choice(WEB_METHODS)
    status = random.choice(WEB_STATUSES)
    uri    = random.choice(WEB_URIS)
    ev = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "webserver",
        "event": {
            "kind": "event", "category": "web", "type": "access",
            "action": method.lower(), "dataset": "webserver",
            "outcome": "success" if status < 400 else "failure",
            "severity": severity("webserver", method, http_status=status),
        },
        "source": {"ip": src},
        "http": {
            "request":  {"method": method},
            "response": {"status_code": status, "bytes": random.randint(100,50000)},
        },
        "url":        {"path": uri, "original": uri},
        "user_agent": {"original": random.choice(WEB_AGENTS)},
        "tags": ["webserver"],
    }
    g = geo(src)
    if g:
        ev["source"]["geo"] = g
    return ev

# ── Windows Event generator ────────────────────────────────────────────────
WIN_EVENTS = {
    4624: ("successful logon",          2, "success"),
    4625: ("failed logon",              6, "failure"),
    4648: ("explicit credential logon", 4, "failure"),
    4672: ("special privileges assigned",5,"success"),
    4688: ("new process created",       3, "success"),
    4720: ("user account created",      5, "success"),
    4726: ("user account deleted",      7, "failure"),
    4740: ("user account locked out",   6, "failure"),
}

def gen_windows():
    eid, (desc, base_sev, outcome) = random.choice(list(WIN_EVENTS.items()))
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "windows",
        "event": {
            "kind": "event", "category": "authentication", "type": "start",
            "code": str(eid), "action": desc, "dataset": "windows",
            "outcome": outcome,
            "severity": severity("windows", desc, base_sev),
        },
        "host":   {"hostname": fake.hostname(), "domain": fake.domain_name()},
        "user":   {"name": fake.user_name(), "domain": fake.domain_word().upper()},
        "source": {"ip": fake.ipv4()},
        "winlog": {"event_id": eid, "channel": "Security"},
        "tags":   ["windows","security-event"],
    }

# ── IDS / Suricata generator ───────────────────────────────────────────────
IDS_SIGS = [
    {"sid":2001219,"msg":"ET SCAN Potential SSH Scan",          "category":"Attempted Information Leak",          "severity":2},
    {"sid":2008578,"msg":"ET EXPLOIT MS17-010 EternalBlue",     "category":"Attempted Admin Privilege Gain",      "severity":1},
    {"sid":2019284,"msg":"ET MALWARE Mirai Botnet Checkin",     "category":"Trojan Activity",                     "severity":1},
    {"sid":2024897,"msg":"ET WEB_SERVER SQL Injection Attempt", "category":"Web Application Attack",              "severity":2},
    {"sid":2100498,"msg":"GPL ATTACK id check returned root",   "category":"Potentially Bad Traffic",             "severity":2},
    {"sid":2013028,"msg":"ET POLICY PE EXE download",          "category":"Potential Corporate Privacy Violation","severity":3},
    {"sid":2016922,"msg":"ET INFO Suspicious POST no referer",  "category":"Potentially Bad Traffic",             "severity":3},
]

def gen_ids():
    sig = random.choice(IDS_SIGS)
    src = fake.ipv4_public()
    act = random.choice(["allowed","blocked"])
    ev  = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "ids",
        "event": {
            "kind": "alert", "category": "intrusion_detection",
            "action": act, "dataset": "ids",
            "outcome": "success" if act == "blocked" else "failure",
            "severity": severity("ids", act, sig["severity"]),
        },
        "source":      {"ip": src, "port": random.randint(1024,65535)},
        "destination": {"ip": fake.ipv4_public(), "port": random.choice([22,80,443,445,3389])},
        "network":     {"transport": "tcp"},
        "observer":    {"product": "Suricata", "type": "ids"},
        "rule":        {"id": str(sig["sid"]), "name": sig["msg"], "category": sig["category"]},
        "tags":        ["ids","suricata"],
    }
    g = geo(src)
    if g:
        ev["source"]["geo"] = g
    return ev

# ── Main loop ──────────────────────────────────────────────────────────────
GENS = [
    (gen_firewall,  "firewall"),
    (gen_webserver, "webserver"),
    (gen_windows,   "windows"),
    (gen_ids,       "ids"),
]

print("SIEM generator running...")
batch = 0
while True:
    batch += 1
    counts = {}
    for fn, src in GENS:
        n = random.randint(3, 8)
        for _ in range(n):
            send(fn(), src)
        counts[src] = n
    print(f"[Batch {batch}] {datetime.now().isoformat()} {counts}")
    time.sleep(2)
PYEOF

# ── systemd service — inlines the ELK IP directly from Terraform ──────────
cat > /etc/systemd/system/siem-generator.service << EOF
[Unit]
Description=SIEM Log Generator
After=network.target

[Service]
Environment="ES_HOST=${elk_private_ip}"
ExecStart=/usr/bin/python3 /opt/siem_generator.py
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable siem-generator
systemctl start siem-generator

echo "Generator service started. ES_HOST=${elk_private_ip}"