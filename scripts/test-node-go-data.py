"""node-go -> node-rs: node-rs runs on a node-go data folder as it is.

    python3 scripts/test-node-go-data.py NODE_GO_BINARY NODE_RS_BINARY

node-go sets up a node, creates a retailer with an API key and imports the
MAISON NOOR fixtures; then node-rs starts on the same folder and must accept
node-go's access token, client secret, /changes cursor and admin password,
and serve the same products.
"""
import base64, http.cookiejar, json, os, subprocess, sys, tempfile, time, urllib.parse, urllib.request, urllib.error

GO, RS = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "obx-conformance", "fixtures", "maison-noor")
PORT = 18433
BASE = f"http://127.0.0.1:{PORT}"
D = tempfile.mkdtemp()
ENV = dict(os.environ, OBX_DATA_DIR=D, PORT=str(PORT), OBX_PUBLIC_URL=BASE, OBX_SETUP_CODE="COMPAT-CODE-1234", OBX_LOG_LEVEL="warn")

def start(binary):
    p = subprocess.Popen([binary, "serve"], env=ENV, stdout=open(os.path.join(D, os.path.basename(binary) + ".log"), "ab"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=1); return p
        except Exception: time.sleep(0.2)
    raise SystemExit(f"{binary} did not start")

jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = {"t": ""}
def call(method, path, body=None, headers=None, raw=False, opener=op):
    h = {"X-CSRF-Token": csrf["t"]}
    h.update(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (bytes, str)):
            data = body.encode() if isinstance(body, str) else body
        else:
            data = json.dumps(body).encode(); h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        r = opener.open(req, timeout=60); b = r.read()
        return r.status, (b if raw else (json.loads(b) if b else None))
    except urllib.error.HTTPError as e:
        b = e.read(); return e.code, (b if raw else (json.loads(b) if b else None))

go = start(GO)
st, s = call("GET", "/admin/api/session"); csrf["t"] = s["csrf_token"]
st, s = call("POST", "/admin/api/setup", {"setup_code": "COMPAT-CODE-1234", "company": {"name": "MAISON NOOR Group", "first_brand_name": "MAISON NOOR", "default_language": "nl", "languages": ["nl", "en"]}, "admin": {"name": "Admin", "email": "admin@maison-noor.example", "password": "compat-check-password-1"}})
assert st == 201, (st, s); csrf["t"] = s["csrf_token"]
st, ret = call("POST", "/admin/api/retailers", {"name": "Compat retailer"}); assert st == 201, ret
st, cl = call("POST", "/admin/api/api-clients", {"retailer_id": ret["id"], "name": "compat", "scopes": ["catalog:read", "media:read", "media:original"]}); assert st == 201, cl
cid, secret = cl["client"]["client_id"], cl["client_secret"]
go.terminate(); go.wait()
subprocess.run([GO, "import", "--csv", f"{FIX}/products.csv", "--assets", f"{FIX}/assets.csv", "--images", f"{FIX}/images"], env=ENV, check=True, capture_output=True)
go = start(GO)
time.sleep(2)

def token():
    auth = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    st, t = call("POST", "/obx/v1/oauth/token", "grant_type=client_credentials", {"Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded"}, opener=urllib.request.build_opener())
    assert st == 200, (st, t); return t["access_token"]

def snapshot(tok):
    cur, n, phase = "", 0, ""
    while True:
        st, p = call("GET", "/obx/v1/changes?limit=500" + (f"&cursor={urllib.parse.quote(cur)}" if cur else ""), headers={"Authorization": "Bearer " + tok}, opener=urllib.request.build_opener())
        assert st == 200, (st, p)
        n += len(p["changes"]) if p["phase"] == "snapshot" else 0
        cur = p["next_cursor"]
        if p["phase"] == "live" and not p["has_more"]:
            return n, cur
tok_go = token()
n_go, cursor_go = snapshot(tok_go)
st, prod_go = call("GET", "/obx/v1/products?limit=100", headers={"Authorization": "Bearer " + tok_go}, opener=urllib.request.build_opener())
go.terminate(); go.wait()

rs = start(RS)
try:
    res = {}
    # 1. the API key from node-go works; its access token too (same keys).
    st, b = call("GET", "/obx/v1/grant", headers={"Authorization": "Bearer " + tok_go}, opener=urllib.request.build_opener())
    res["node-go access token accepted"] = st == 200
    tok = token(); res["node-go client secret accepted"] = True
    # 2. the cursor issued by node-go continues
    st, p = call("GET", "/obx/v1/changes?cursor=" + urllib.parse.quote(cursor_go), headers={"Authorization": "Bearer " + tok}, opener=urllib.request.build_opener())
    res["node-go cursor continues (200, live, no entries)"] = st == 200 and p["phase"] == "live" and p["changes"] == []
    # 3. same snapshot size and same products
    n_rs, _ = snapshot(tok)
    res[f"snapshot size equal ({n_go} vs {n_rs})"] = n_go == n_rs
    st, prod_rs = call("GET", "/obx/v1/products?limit=100", headers={"Authorization": "Bearer " + tok}, opener=urllib.request.build_opener())
    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items() if k not in ("url", "url_expires_at")}
        if isinstance(v, list): return [strip(x) for x in v]
        return v
    res["products identical (without signed URLs)"] = strip(prod_go["items"]) == strip(prod_rs["items"])
    if strip(prod_go["items"]) != strip(prod_rs["items"]):
        a, b2 = json.dumps(strip(prod_go["items"][0]), sort_keys=True), json.dumps(strip(prod_rs["items"][0]), sort_keys=True)
        print("first product differs:\n", a[:1500], "\n", b2[:1500])
    # 4. a rendition downloads with its signed URL
    url = prod_rs["items"][0]["assets"][0]["renditions"]["web"]["url"]
    r = urllib.request.urlopen(url, timeout=30); res["signed rendition downloads"] = r.status == 200 and len(r.read()) > 1000
    # 5. the admin password from node-go logs in
    jar.clear(); csrf["t"] = ""
    st, s = call("GET", "/admin/api/session"); csrf["t"] = s["csrf_token"]
    st, s = call("POST", "/admin/api/session/login", {"email": "admin@maison-noor.example", "password": "compat-check-password-1"})
    res["node-go admin password logs in"] = st == 200
finally:
    rs.terminate(); rs.wait()
for k, v in res.items():
    print(("PASS " if v else "FAIL ") + k)
sys.exit(0 if all(res.values()) else 1)
