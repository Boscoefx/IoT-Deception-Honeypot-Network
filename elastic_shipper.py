import sqlite3, json, time, argparse, os, hashlib, uuid, datetime, urllib.request, urllib.error

INDEX = "honeypot-events"

class SimpleES:
    def __init__(self, url):
        self.url = url.rstrip("/")
    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body else None
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())
    def ping(self):
        try:
            self._req("GET", "/"); return True
        except: return False
    def create_index(self, index, mapping):
        r = self._req("PUT", f"/{index}", mapping)
        return r.get("acknowledged") or "already_exists" in str(r)
    def bulk(self, actions):
        lines = []
        for a in actions:
            lines.append(json.dumps({"index": {"_index": a["_index"], "_id": a.get("_id")}}))
            lines.append(json.dumps(a["_source"]))
        body = ("\n".join(lines) + "\n").encode()
        req = urllib.request.Request(self.url + "/_bulk", data=body,
            headers={"Content-Type": "application/x-ndjson"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                result = json.loads(r.read())
                errors = [i for i in result.get("items",[]) if "error" in i.get("index",{})]
                return len(actions)-len(errors), errors
        except Exception as e:
            return 0, [str(e)]

MAPPING = {"mappings":{"properties":{"timestamp":{"type":"date"},"event_type":{"type":"keyword"},"src_ip":{"type":"ip"},"src_port":{"type":"integer"},"username":{"type":"keyword"},"password":{"type":"keyword"},"command":{"type":"text","fields":{"raw":{"type":"keyword"}}},"session_id":{"type":"keyword"},"sensor":{"type":"keyword"},"country":{"type":"keyword"},"org":{"type":"keyword"},"location":{"type":"geo_point"},"threat_score":{"type":"float"}}},"settings":{"number_of_shards":1,"number_of_replicas":0}}
LOGIN_MAPPING = {"mappings":{"properties":{"timestamp":{"type":"date"},"src_ip":{"type":"ip"},"username":{"type":"keyword"},"password":{"type":"keyword"},"success":{"type":"boolean"},"country":{"type":"keyword"},"location":{"type":"geo_point"}}},"settings":{"number_of_shards":1,"number_of_replicas":0}}
PAYLOAD_MAPPING = {"mappings":{"properties":{"timestamp":{"type":"date"},"src_ip":{"type":"ip"},"filename":{"type":"keyword"},"sha256":{"type":"keyword"},"url":{"type":"keyword"},"country":{"type":"keyword"}}},"settings":{"number_of_shards":1,"number_of_replicas":0}}

SCORES = {"login_success":9.0,"payload_download":9.5,"command":7.0,"login_fail":3.0,"connect":1.0}

def get_geo(conn, ip):
    try:
        r = conn.execute("SELECT country,city,latitude,longitude,org FROM enriched_ips WHERE ip=?",(ip,)).fetchone()
        if r:
            d = {"country":r[0],"city":r[1],"org":r[4]}
            if r[2]: d["location"] = {"lat":r[2],"lon":r[3]}
            return d
    except: pass
    return {}

def bulk_ship(es, conn, state):
    now = datetime.datetime.utcnow()
    shipped = 0

    # events
    rows = conn.execute("SELECT id,timestamp,event_type,src_ip,src_port,username,password,command,session_id,sensor FROM events WHERE id>? ORDER BY id LIMIT 500",(state["last_event_id"],)).fetchall()
    if rows:
        actions = []
        for r in rows:
            geo = get_geo(conn, r[3])
            doc = {"timestamp":r[1],"event_type":r[2],"src_ip":r[3],"src_port":r[4],"username":r[5],"password":r[6],"command":r[7],"session_id":r[8],"sensor":r[9],"threat_score":SCORES.get(r[2],2.0),**geo}
            actions.append({"_index":"honeypot-events","_id":f"ev-{r[0]}","_source":{k:v for k,v in doc.items() if v is not None}})
        n, _ = es.bulk(actions)
        shipped += n
        state["last_event_id"] = rows[-1][0]

    # logins
    rows = conn.execute("SELECT id,timestamp,src_ip,username,password,success FROM login_attempts WHERE id>? ORDER BY id LIMIT 500",(state["last_login_id"],)).fetchall()
    if rows:
        actions = []
        for r in rows:
            geo = get_geo(conn, r[2])
            doc = {"timestamp":r[1],"src_ip":r[2],"username":r[3],"password":r[4],"success":bool(r[5]),**geo}
            actions.append({"_index":"honeypot-logins","_id":f"lg-{r[0]}","_source":{k:v for k,v in doc.items() if v is not None}})
        n, _ = es.bulk(actions)
        shipped += n
        state["last_login_id"] = rows[-1][0]

    # payloads
    rows = conn.execute("SELECT id,timestamp,src_ip,filename,sha256,url FROM payloads WHERE id>? ORDER BY id LIMIT 200",(state["last_payload_id"],)).fetchall()
    if rows:
        actions = []
        for r in rows:
            geo = get_geo(conn, r[2])
            doc = {"timestamp":r[1],"src_ip":r[2],"filename":r[3],"sha256":r[4],"url":r[5],**geo}
            actions.append({"_index":"honeypot-payloads","_id":f"pl-{r[0]}","_source":{k:v for k,v in doc.items() if v is not None}})
        n, _ = es.bulk(actions)
        shipped += n
        state["last_payload_id"] = rows[-1][0]

    return shipped, state

STATE_FILE = "honeypot.db.state"

def load_state():
    if os.path.exists(STATE_FILE):
        return json.load(open(STATE_FILE))
    return {"last_event_id":0,"last_login_id":0,"last_payload_id":0}

def save_state(s):
    json.dump(s, open(STATE_FILE,"w"))

def setup_kibana(url="http://localhost:5601"):
    for title in ["honeypot-events","honeypot-logins","honeypot-payloads"]:
        body = json.dumps({"attributes":{"title":title,"timeFieldName":"timestamp"}}).encode()
        req = urllib.request.Request(f"{url}/api/saved_objects/index-pattern", data=body,
            headers={"Content-Type":"application/json","kbn-xsrf":"true"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            print(f"[+] Kibana pattern created: {title}")
        except Exception as e:
            print(f"[!] {title}: {e}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="honeypot.db")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--watch", action="store_true")
    p.add_argument("--kibana", action="store_true")
    p.add_argument("--reset", action="store_true")
    p.add_argument("--interval", type=int, default=15)
    args = p.parse_args()

    if args.kibana:
        setup_kibana(); exit()

    es = SimpleES(args.es_url)
    if not es.ping():
        print(f"[!] Cannot reach Elasticsearch at {args.es_url}")
        print("    Start it first: sudo docker-compose -f docker-compose-elastic.yml up -d")
        exit(1)
    print(f"[+] Connected to Elasticsearch at {args.es_url}")

    for idx, mapping in [("honeypot-events",MAPPING),("honeypot-logins",LOGIN_MAPPING),("honeypot-payloads",PAYLOAD_MAPPING)]:
        es.create_index(idx, mapping)
        print(f"[+] Index ready: {idx}")

    if args.watch:
        print(f"[+] Watch mode — polling every {args.interval}s. Ctrl+C to stop.")
        while True:
            state = load_state() if not args.reset else {"last_event_id":0,"last_login_id":0,"last_payload_id":0}
            conn = sqlite3.connect(args.db)
            n, state = bulk_ship(es, conn, state)
            conn.close()
            save_state(state)
            if n: print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Shipped {n} docs")
            time.sleep(args.interval)
    else:
        state = {"last_event_id":0,"last_login_id":0,"last_payload_id":0} if args.reset else load_state()
        conn = sqlite3.connect(args.db)
        n, state = bulk_ship(es, conn, state)
        conn.close()
        save_state(state)
        print(f"[+] Shipped {n} documents to Elasticsearch")
        print("[+] Open Kibana: http://localhost:5601")
