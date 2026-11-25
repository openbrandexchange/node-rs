"""Scheduled imports end to end: https, SFTP and S3 sources.

    python3 -I scripts/test-sources.py NODE_RS_BINARY

Starts node-rs with OBX_ALLOW_PRIVATE_URLS=true (the sources are local
servers) and checks, per kind: the test endpoint, a run that imports the
MAISON NOOR fixtures, a second run that is skipped as unchanged, a forced
run, and that credentials are never returned. The https source is a local
HTTP server, the SFTP source a throw-away sshd (/usr/sbin/sshd, skipped
with a note when it is missing), the S3 source a minimal S3 API
(ListObjectsV2 and GetObject) in this script.
"""
import http.cookiejar, http.server, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request
from xml.sax.saxutils import escape

RS = os.path.abspath(sys.argv[1])
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "fixtures")
MN = os.path.join(FIX, "maison-noor")
PORT = 18471
BASE = f"http://127.0.0.1:{PORT}"
D = tempfile.mkdtemp()
ENV = dict(os.environ, OBX_DATA_DIR=os.path.join(D, "data"), PORT=str(PORT), OBX_PUBLIC_URL=BASE, OBX_SETUP_CODE="SRC-TEST-CODE-1",
           OBX_LOG_LEVEL="warn", OBX_ALLOW_PRIVATE_URLS="true")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = {"t": ""}


def call(method, path, body=None):
    h = {"X-CSRF-Token": csrf["t"]}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        r = op.open(req, timeout=120); b = r.read()
        return r.status, (json.loads(b) if b else None), b
    except urllib.error.HTTPError as e:
        b = e.read(); return e.code, (json.loads(b) if b else None), b


def must(status, method, path, body=None):
    st, j, raw = call(method, path, body)
    assert st == status, f"{method} {path}: {st} {raw[:500]!r}"
    return j, raw


def wait_run(run_id):
    for _ in range(600):
        j, _ = must(200, "GET", f"/admin/api/imports/{run_id}")
        if j["status"] in ("succeeded", "failed"):
            return j
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} did not finish")


def check_source(name, kind, config, creds, expect_files, secret=None, extra=None):
    src, raw = must(201, "POST", "/admin/api/import-sources", {"name": name, "kind": kind, "schedule": {"frequency": "manual"}, "config": config, "credentials": creds})
    if secret:
        assert secret.encode() not in raw, f"{name}: the create answer contains a credential"
    sid = src["id"]
    t, _ = must(200, "POST", f"/admin/api/import-sources/{sid}/test")
    assert t["ok"] is True, f"{name}: test {t}"
    assert len(t["files"]) == expect_files, f"{name}: test lists {len(t['files'])} files, want {expect_files}: {t['files'][:5]}"
    if extra:
        extra(t, sid)
    run, _ = must(202, "POST", f"/admin/api/import-sources/{sid}/run", {})
    assert run["source_id"] == sid and run["trigger"] == "manual_run", run
    done = wait_run(run["id"])
    assert done["status"] == "succeeded" and done["counts"]["errors"] == 0, f"{name}: {json.dumps(done)[:800]}"
    again = wait_run(must(202, "POST", f"/admin/api/import-sources/{sid}/run", {})[0]["id"])
    assert again["status"] == "succeeded" and again.get("x-node-rs-unchanged") is True, f"{name}: second run {again}"
    forced = wait_run(must(202, "POST", f"/admin/api/import-sources/{sid}/run", {"force": True})[0]["id"])
    assert forced["status"] == "succeeded" and not forced.get("x-node-rs-unchanged"), f"{name}: forced run {forced}"
    got, raw = must(200, "GET", f"/admin/api/import-sources/{sid}")
    if secret:
        assert secret.encode() not in raw, f"{name}: GET contains a credential"
    assert got["last_run"]["id"] == forced["id"], got["last_run"]
    print(f"ok   {name}: test, run ({done['counts']['created']} created), unchanged rerun, forced run")
    return sid, got


# ---- local servers ---------------------------------------------------------------

web = os.path.join(D, "web"); os.makedirs(web)
shutil.copy(os.path.join(MN, "products.csv"), web)
shutil.copy(os.path.join(FIX, "imports", "xlsx", "products-template.xlsx"), os.path.join(web, "export.xlsx"))
seen_auth = []


class Web(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=web, **k)

    def do_GET(self):
        seen_auth.append(self.headers.get("Authorization"))
        return super().do_GET()

    def log_message(self, *a):
        pass


bucket_root = os.path.join(D, "bucket")
os.makedirs(os.path.join(bucket_root, "export", "images"))
shutil.copy(os.path.join(MN, "products.csv"), os.path.join(bucket_root, "export"))
shutil.copy(os.path.join(MN, "assets.csv"), os.path.join(bucket_root, "export"))
for f in os.listdir(os.path.join(MN, "images")):
    shutil.copy(os.path.join(MN, "images", f), os.path.join(bucket_root, "export", "images"))


class S3(http.server.BaseHTTPRequestHandler):
    """ListObjectsV2 and GetObject of one bucket "obx-source" (path style)."""

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        parts = u.path.lstrip("/").split("/", 1)
        if parts[0] != "obx-source":
            self.send_error(404); return
        if len(parts) == 1 or parts[1] == "":
            prefix = q.get("prefix", [""])[0]
            keys = []
            for dp, _, fs in os.walk(bucket_root):
                for f in fs:
                    k = os.path.relpath(os.path.join(dp, f), bucket_root).replace(os.sep, "/")
                    if k.startswith(prefix):
                        keys.append(k)
            items = "".join(f"<Contents><Key>{escape(k)}</Key><LastModified>2026-11-01T10:00:00.000Z</LastModified><ETag>&quot;{os.path.getsize(os.path.join(bucket_root, k))}&quot;</ETag><Size>{os.path.getsize(os.path.join(bucket_root, k))}</Size></Contents>" for k in sorted(keys))
            body = f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>obx-source</Name><Prefix>{escape(prefix)}</Prefix><KeyCount>{len(keys)}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{items}</ListBucketResult>'.encode()
            self.send_response(200); self.send_header("Content-Type", "application/xml"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        p = os.path.join(bucket_root, urllib.parse.unquote(parts[1]))
        if not os.path.isfile(p):
            self.send_error(404); return
        data = open(p, "rb").read()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.send_header("ETag", f'"{len(data)}"')
        self.send_header("Last-Modified", "Sun, 01 Nov 2026 10:00:00 GMT"); self.end_headers(); self.wfile.write(data)

    def do_HEAD(self):
        self.send_response(200); self.end_headers()

    def log_message(self, *a):
        pass


def serve(handler):
    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return port


web_port, s3_port = serve(Web), serve(S3)

sshd = None
sftp_port = free_port()
if os.path.exists("/usr/sbin/sshd") and shutil.which("ssh-keygen"):
    sd = os.path.join(D, "sshd"); os.makedirs(sd)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(sd, "host")], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(sd, "client")], check=True)
    shutil.copy(os.path.join(sd, "client.pub"), os.path.join(sd, "authorized_keys"))
    sftp_server = next((p for p in ["/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/lib/ssh/sftp-server"] if os.path.exists(p)), "internal-sftp")
    with open(os.path.join(sd, "sshd_config"), "w") as f:
        f.write(f"Port {sftp_port}\nListenAddress 127.0.0.1\nHostKey {sd}/host\nPidFile {sd}/pid\nAuthorizedKeysFile {sd}/authorized_keys\n"
                f"PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nSubsystem sftp {sftp_server}\n")
    sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", os.path.join(sd, "sshd_config")], stdout=open(os.path.join(sd, "log"), "wb"), stderr=subprocess.STDOUT)
    sftp_dir = os.path.join(D, "sftp-export"); os.makedirs(os.path.join(sftp_dir, "images"))
    shutil.copy(os.path.join(MN, "products.csv"), sftp_dir)
    for f in os.listdir(os.path.join(MN, "images")):
        shutil.copy(os.path.join(MN, "images", f), os.path.join(sftp_dir, "images"))
    host_fp = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", os.path.join(sd, "host.pub")], capture_output=True, text=True, check=True).stdout.split()[1]
    time.sleep(0.5)

# ---- the node --------------------------------------------------------------------

node = subprocess.Popen([RS, "serve"], env=ENV, stdout=open(os.path.join(D, "node.log"), "wb"), stderr=subprocess.STDOUT)
failed = False
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=1); break
        except Exception:
            time.sleep(0.1)
    s, _ = must(200, "GET", "/admin/api/session"); csrf["t"] = s["csrf_token"]
    s, _ = must(201, "POST", "/admin/api/setup", {"setup_code": "SRC-TEST-CODE-1", "company": {"name": "MAISON NOOR Group", "first_brand_name": "MAISON NOOR", "default_language": "nl", "languages": ["nl", "en"]},
                                                 "admin": {"name": "Admin", "email": "admin@maison-noor.example", "password": "source-test-password-1"}})
    csrf["t"] = s["csrf_token"]

    # https: a CSV with a secret header; then a workbook (.xlsx by name).
    secret = "Bearer source-test-secret"
    check_source("https csv", "https_url", {"url": f"http://127.0.0.1:{web_port}/products.csv"}, {"headers": {"Authorization": secret}}, 1, secret=secret)
    assert secret in seen_auth, "the Authorization header was not sent"
    check_source("https xlsx", "https_url", {"url": f"http://127.0.0.1:{web_port}/export.xlsx"}, {}, 1)

    # S3 (anonymous, path style).
    check_source("s3", "s3", {"endpoint": f"http://127.0.0.1:{s3_port}", "region": "us-east-1", "bucket": "obx-source", "prefix": "export/", "path_style": True}, {}, 2 + len(os.listdir(os.path.join(MN, "images"))))

    # SFTP: key login, host key pinned on first use, a wrong pin refused.
    if sshd:
        key = open(os.path.join(D, "sshd", "client")).read()
        user = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()

        def pinned(t, sid):
            assert t["host_key_fingerprint"] == host_fp, (t["host_key_fingerprint"], host_fp)

        sid, got = check_source("sftp", "sftp", {"host": "127.0.0.1", "port": sftp_port, "username": user, "path": sftp_dir}, {"private_key": key}, 1 + len(os.listdir(os.path.join(MN, "images"))), secret="PRIVATE KEY", extra=pinned)
        assert got["config"]["host_key_fingerprint"] == host_fp and got["credentials_set"]["private_key"] is True, got
        must(200, "PATCH", f"/admin/api/import-sources/{sid}", {"config": {"host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})
        t, _ = must(200, "POST", f"/admin/api/import-sources/{sid}/test")
        assert t["ok"] is False and "does not match" in (t["message"] or ""), t
        print("ok   sftp: a changed host key is refused")
    else:
        print("note sftp: /usr/sbin/sshd not found; skipped")

    # The URL policy still applies to everything but private addresses.
    st, j, _ = call("POST", "/admin/api/import-sources", {"name": "metadata", "kind": "https_url", "config": {"url": "https://169.254.169.254/latest/"}})
    assert st == 422 and j["obx_error"] == "unsafe_url", (st, j)
    st, j, _ = call("POST", "/admin/api/import-sources", {"name": "x", "kind": "sftp", "config": {"host": "169.254.169.254", "username": "u", "path": "/"}})
    assert st == 422 and j["obx_error"] == "unsafe_url", (st, j)
    items, _ = must(200, "GET", "/admin/api/import-sources")
    assert len(items["items"]) >= 3
    print("ok   unsafe hosts refused; list")
except AssertionError as e:
    failed = True
    print("FAIL", e)
    print(open(os.path.join(D, "node.log")).read()[-3000:])
finally:
    node.terminate(); node.wait()
    if sshd:
        sshd.terminate(); sshd.wait()
    shutil.rmtree(D, ignore_errors=True)
sys.exit(1 if failed else 0)
